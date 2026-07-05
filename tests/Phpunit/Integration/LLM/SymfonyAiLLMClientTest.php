<?php

/*
 * This file is part of the vinceamstoutz/symfony-security-auditor package.
 *
 * (c) Vincent Amstoutz <vincent.amstoutz.dev@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

declare(strict_types=1);

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Integration\LLM;

use Closure;
use DateTimeImmutable;
use Override;
use PHPUnit\Framework\TestCase;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;
use RuntimeException;
use Symfony\AI\Platform\Exception\RateLimitExceededException;
use Symfony\AI\Platform\Message\AssistantMessage;
use Symfony\AI\Platform\Message\MessageBag;
use Symfony\AI\Platform\Message\ToolCallMessage;
use Symfony\AI\Platform\Model;
use Symfony\AI\Platform\ModelCatalog\FallbackModelCatalog;
use Symfony\AI\Platform\ModelCatalog\ModelCatalogInterface;
use Symfony\AI\Platform\PlainConverter;
use Symfony\AI\Platform\PlatformInterface;
use Symfony\AI\Platform\Result\BaseResult;
use Symfony\AI\Platform\Result\DeferredResult;
use Symfony\AI\Platform\Result\InMemoryRawResult;
use Symfony\AI\Platform\Result\MultiPartResult;
use Symfony\AI\Platform\Result\RawResultInterface;
use Symfony\AI\Platform\Result\ResultInterface;
use Symfony\AI\Platform\Result\TextResult;
use Symfony\AI\Platform\Result\ToolCall;
use Symfony\AI\Platform\Result\ToolCallResult;
use Symfony\AI\Platform\ResultConverterInterface;
use Symfony\AI\Platform\Test\InMemoryPlatform;
use Symfony\AI\Platform\TokenUsage\TokenUsage;
use Symfony\AI\Platform\TokenUsage\TokenUsageExtractorInterface;
use Symfony\AI\Platform\Tool\Tool;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Budget\BudgetTracker;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Budget\CostCalculator;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Budget\Exception\BudgetExceededException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Telemetry\TokenUsageRecorder;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\AuditBudget;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\PricingProviderInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\RateLimiterInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\Tool\ToolDefinition;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\Tool\ToolInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\Tool\ToolRegistry;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\BackoffSchedule;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\Exception\InvalidRetryConfigurationException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\Exception\MissingAiPlatformException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\Exception\NonTransientLLMFailureException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\Exception\TransientLLMFailureException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\PlatformAccountingConfig;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\PlatformBinding;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\PlatformRequestConfig;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\PlatformResilienceConfig;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\RateLimitBackoff;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\RetryPolicy;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\SymfonyAiLLMClient;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\TransientFailureClassifier;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Integration\LLM\Fixture\FakeRateLimiter;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Integration\LLM\Fixture\FakeSleeper;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Integration\LLM\Fixture\FixedTokenEstimator;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Integration\LLM\Fixture\InvocationOptionsCapture;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Integration\LLM\Fixture\PlatformInvocationLog;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Integration\LLM\Fixture\ThrowingConverter;

final class SymfonyAiLLMClientTest extends TestCase
{
    /**
     * @throws BudgetExceededException
     * @throws MissingAiPlatformException
     * @throws TransientLLMFailureException
     * @throws NonTransientLLMFailureException
     */
    public function test_complete_returns_text_from_platform_invoke(): void
    {
        $platform = $this->scriptedPlatform([new TextResult('Hello from LLM')]);
        $symfonyAiLLMClient = new SymfonyAiLLMClient(new PlatformBinding($platform, 'test-model', new NullLogger()));

        $llmResponse = $symfonyAiLLMClient->complete('You are a helper.', 'Tell me a joke.');

        self::assertSame('Hello from LLM', $llmResponse->content());
        self::assertSame('test-model', $llmResponse->model());
        self::assertSame('end_turn', $llmResponse->stopReason());
        self::assertSame(0, $llmResponse->inputTokens());
        self::assertSame(0, $llmResponse->outputTokens());
    }

    /**
     * @throws BudgetExceededException
     * @throws MissingAiPlatformException
     * @throws TransientLLMFailureException
     * @throws NonTransientLLMFailureException
     */
    public function test_complete_logs_debug_with_prompt_lengths_and_temperature(): void
    {
        $platform = $this->scriptedPlatform([new TextResult('ok')]);
        /** @var list<array{string, array<string, mixed>}> $logs */
        $logs = [];
        $logger = self::createStub(LoggerInterface::class);
        $logger->method('debug')->willReturnCallback(
            static function (string $msg, array $ctx = []) use (&$logs): void {
                $logs[] = [$msg, $ctx];
            },
        );

        $symfonyAiLLMClient = new SymfonyAiLLMClient(new PlatformBinding($platform, 'test-model', $logger), new PlatformRequestConfig(temperature: 0.42));
        $symfonyAiLLMClient->complete('sys', 'usr-message');

        $startLog = $logs[0];
        self::assertSame('Invoking symfony/ai platform', $startLog[0]);
        self::assertSame(3, $startLog[1]['system_length']);
        self::assertSame(11, $startLog[1]['user_length']);
        self::assertSame(0.42, $startLog[1]['temperature']);
    }

    /**
     * @throws BudgetExceededException
     * @throws MissingAiPlatformException
     * @throws TransientLLMFailureException
     * @throws NonTransientLLMFailureException
     */
    public function test_complete_logs_debug_response_with_content_length(): void
    {
        $platform = $this->scriptedPlatform([new TextResult('twelve-chars')]);
        /** @var list<array{string, array<string, mixed>}> $logs */
        $logs = [];
        $logger = self::createStub(LoggerInterface::class);
        $logger->method('debug')->willReturnCallback(
            static function (string $msg, array $ctx = []) use (&$logs): void {
                $logs[] = [$msg, $ctx];
            },
        );

        $symfonyAiLLMClient = new SymfonyAiLLMClient(new PlatformBinding($platform, 'test-model', $logger));
        $symfonyAiLLMClient->complete('s', 'u');

        $respondedLogs = array_values(array_filter(
            $logs,
            static fn (array $entry): bool => 'symfony/ai platform responded' === $entry[0],
        ));

        self::assertCount(1, $respondedLogs);
        self::assertSame(12, $respondedLogs[0][1]['content_length']);
    }

    /**
     * @throws BudgetExceededException
     * @throws MissingAiPlatformException
     * @throws TransientLLMFailureException
     * @throws NonTransientLLMFailureException
     */
    public function test_complete_passes_temperature_via_options(): void
    {
        $invocationOptionsCapture = new InvocationOptionsCapture();
        $platform = $this->scriptedPlatformCapturingOptions(new TextResult('out'), $invocationOptionsCapture);

        $symfonyAiLLMClient = new SymfonyAiLLMClient(new PlatformBinding($platform, 'test-model', new NullLogger()), new PlatformRequestConfig(temperature: 0.7));
        $symfonyAiLLMClient->complete('s', 'u');

        self::assertNotNull($invocationOptionsCapture->options);
        self::assertSame(0.7, $invocationOptionsCapture->options['temperature']);
        self::assertArrayNotHasKey('cache_control', $invocationOptionsCapture->options);
    }

    /**
     * @throws BudgetExceededException
     * @throws MissingAiPlatformException
     * @throws TransientLLMFailureException
     * @throws NonTransientLLMFailureException
     */
    public function test_complete_omits_temperature_when_left_at_default(): void
    {
        $invocationOptionsCapture = new InvocationOptionsCapture();
        $platform = $this->scriptedPlatformCapturingOptions(new TextResult('out'), $invocationOptionsCapture);

        $symfonyAiLLMClient = new SymfonyAiLLMClient(new PlatformBinding($platform, 'test-model', new NullLogger()));
        $symfonyAiLLMClient->complete('s', 'u');

        self::assertNotNull($invocationOptionsCapture->options);
        self::assertArrayNotHasKey('temperature', $invocationOptionsCapture->options);
    }

    /**
     * @throws BudgetExceededException
     * @throws MissingAiPlatformException
     * @throws TransientLLMFailureException
     * @throws NonTransientLLMFailureException
     */
    public function test_complete_never_sends_cache_control_even_for_anthropic_model(): void
    {
        $invocationOptionsCapture = new InvocationOptionsCapture();
        $platform = $this->scriptedPlatformCapturingOptions(new TextResult('out'), $invocationOptionsCapture);

        $symfonyAiLLMClient = new SymfonyAiLLMClient(new PlatformBinding($platform, 'claude-opus-4-8', new NullLogger()));
        $symfonyAiLLMClient->complete('s', 'u');

        self::assertNotNull($invocationOptionsCapture->options);
        self::assertArrayNotHasKey('cache_control', $invocationOptionsCapture->options);
    }

    /**
     * @throws BudgetExceededException
     * @throws MissingAiPlatformException
     * @throws TransientLLMFailureException
     * @throws NonTransientLLMFailureException
     */
    public function test_complete_passes_provider_json_mode_response_format_for_anthropic_model(): void
    {
        $invocationOptionsCapture = new InvocationOptionsCapture();
        $platform = $this->scriptedPlatformCapturingOptions(new TextResult('out'), $invocationOptionsCapture);

        $symfonyAiLLMClient = new SymfonyAiLLMClient(new PlatformBinding($platform, 'claude-opus-4-8', new NullLogger()), new PlatformRequestConfig(providerJsonMode: true));
        $symfonyAiLLMClient->complete('s', 'u');

        self::assertNotNull($invocationOptionsCapture->options);
        self::assertSame(['type' => 'json_object'], $invocationOptionsCapture->options['response_format']);
    }

    /**
     * @throws BudgetExceededException
     * @throws MissingAiPlatformException
     * @throws TransientLLMFailureException
     * @throws NonTransientLLMFailureException
     */
    public function test_complete_omits_response_format_for_non_anthropic_model_even_when_json_mode_enabled(): void
    {
        $invocationOptionsCapture = new InvocationOptionsCapture();
        $platform = $this->scriptedPlatformCapturingOptions(new TextResult('out'), $invocationOptionsCapture);

        $symfonyAiLLMClient = new SymfonyAiLLMClient(new PlatformBinding($platform, 'gemini-3.1-pro-preview', new NullLogger()), new PlatformRequestConfig(providerJsonMode: true));
        $symfonyAiLLMClient->complete('s', 'u');

        self::assertNotNull($invocationOptionsCapture->options);
        self::assertArrayNotHasKey('response_format', $invocationOptionsCapture->options);
    }

    /**
     * @throws BudgetExceededException
     * @throws MissingAiPlatformException
     * @throws TransientLLMFailureException
     * @throws NonTransientLLMFailureException
     */
    public function test_complete_passes_all_anthropic_options_together_when_multiple_flags_enabled(): void
    {
        $invocationOptionsCapture = new InvocationOptionsCapture();
        $platform = $this->scriptedPlatformCapturingOptions(new TextResult('out'), $invocationOptionsCapture);

        $symfonyAiLLMClient = new SymfonyAiLLMClient(
            new PlatformBinding($platform, 'claude-opus-4-8', new NullLogger(), maxOutputTokens: 4096),
            new PlatformRequestConfig(temperature: 0.5, providerJsonMode: true),
        );
        $symfonyAiLLMClient->complete('s', 'u');

        self::assertNotNull($invocationOptionsCapture->options);
        self::assertSame(0.5, $invocationOptionsCapture->options['temperature']);
        self::assertSame(['type' => 'json_object'], $invocationOptionsCapture->options['response_format']);
        self::assertSame(4096, $invocationOptionsCapture->options['max_tokens']);
        self::assertArrayNotHasKey('cache_control', $invocationOptionsCapture->options);
    }

    /**
     * @throws BudgetExceededException
     * @throws MissingAiPlatformException
     * @throws TransientLLMFailureException
     * @throws NonTransientLLMFailureException
     */
    public function test_complete_omits_response_format_when_provider_json_mode_disabled(): void
    {
        $invocationOptionsCapture = new InvocationOptionsCapture();
        $platform = $this->scriptedPlatformCapturingOptions(new TextResult('out'), $invocationOptionsCapture);

        $symfonyAiLLMClient = new SymfonyAiLLMClient(new PlatformBinding($platform, 'claude-opus-4-8', new NullLogger()));
        $symfonyAiLLMClient->complete('s', 'u');

        self::assertNotNull($invocationOptionsCapture->options);
        self::assertArrayNotHasKey('response_format', $invocationOptionsCapture->options);
    }

    /**
     * @throws BudgetExceededException
     * @throws MissingAiPlatformException
     * @throws TransientLLMFailureException
     * @throws NonTransientLLMFailureException
     */
    public function test_complete_passes_max_output_tokens_via_options_for_anthropic_model(): void
    {
        $invocationOptionsCapture = new InvocationOptionsCapture();
        $platform = $this->scriptedPlatformCapturingOptions(new TextResult('out'), $invocationOptionsCapture);

        $symfonyAiLLMClient = new SymfonyAiLLMClient(
            new PlatformBinding($platform, 'claude-opus-4-8', new NullLogger(), maxOutputTokens: 4096),
        );
        $symfonyAiLLMClient->complete('s', 'u');

        self::assertNotNull($invocationOptionsCapture->options);
        self::assertSame(4096, $invocationOptionsCapture->options['max_tokens']);
    }

    /**
     * @throws BudgetExceededException
     * @throws MissingAiPlatformException
     * @throws TransientLLMFailureException
     * @throws NonTransientLLMFailureException
     */
    public function test_complete_omits_max_output_tokens_for_non_anthropic_model_even_when_configured(): void
    {
        $invocationOptionsCapture = new InvocationOptionsCapture();
        $platform = $this->scriptedPlatformCapturingOptions(new TextResult('out'), $invocationOptionsCapture);

        $symfonyAiLLMClient = new SymfonyAiLLMClient(
            new PlatformBinding($platform, 'gemini-3.1-pro-preview', new NullLogger(), maxOutputTokens: 4096),
        );
        $symfonyAiLLMClient->complete('s', 'u');

        self::assertNotNull($invocationOptionsCapture->options);
        self::assertArrayNotHasKey('max_tokens', $invocationOptionsCapture->options);
    }

    /**
     * @throws BudgetExceededException
     * @throws MissingAiPlatformException
     * @throws TransientLLMFailureException
     * @throws NonTransientLLMFailureException
     */
    public function test_complete_still_sends_temperature_for_non_anthropic_model(): void
    {
        $invocationOptionsCapture = new InvocationOptionsCapture();
        $platform = $this->scriptedPlatformCapturingOptions(new TextResult('out'), $invocationOptionsCapture);

        $symfonyAiLLMClient = new SymfonyAiLLMClient(new PlatformBinding($platform, 'gemini-3.1-pro-preview', new NullLogger()), new PlatformRequestConfig(temperature: 0.7));
        $symfonyAiLLMClient->complete('s', 'u');

        self::assertNotNull($invocationOptionsCapture->options);
        self::assertSame(0.7, $invocationOptionsCapture->options['temperature']);
    }

    /**
     * @throws BudgetExceededException
     * @throws MissingAiPlatformException
     * @throws TransientLLMFailureException
     * @throws NonTransientLLMFailureException
     */
    public function test_complete_omits_max_output_tokens_when_left_at_default(): void
    {
        $invocationOptionsCapture = new InvocationOptionsCapture();
        $platform = $this->scriptedPlatformCapturingOptions(new TextResult('out'), $invocationOptionsCapture);

        $symfonyAiLLMClient = new SymfonyAiLLMClient(new PlatformBinding($platform, 'claude-opus-4-8', new NullLogger()));
        $symfonyAiLLMClient->complete('s', 'u');

        self::assertNotNull($invocationOptionsCapture->options);
        self::assertArrayNotHasKey('max_tokens', $invocationOptionsCapture->options);
    }

    /**
     * @throws BudgetExceededException
     * @throws MissingAiPlatformException
     * @throws TransientLLMFailureException
     * @throws NonTransientLLMFailureException
     */
    public function test_complete_with_tools_passes_max_output_tokens_via_options_for_anthropic_model(): void
    {
        $invocationOptionsCapture = new InvocationOptionsCapture();
        $platform = $this->scriptedPlatformCapturingOptions(
            new MultiPartResult([new TextResult('done')]),
            $invocationOptionsCapture,
        );
        $toolRegistry = new ToolRegistry([$this->makeTool('lookup', 'lookup')], new NullLogger());

        $symfonyAiLLMClient = new SymfonyAiLLMClient(
            new PlatformBinding($platform, 'claude-opus-4-8', new NullLogger(), maxOutputTokens: 8192),
        );
        $symfonyAiLLMClient->completeWithTools('sys', 'usr', $toolRegistry, 3);

        self::assertNotNull($invocationOptionsCapture->options);
        self::assertSame(8192, $invocationOptionsCapture->options['max_tokens']);
    }

    public function test_model_returns_configured_model_name(): void
    {
        $symfonyAiLLMClient = new SymfonyAiLLMClient(new PlatformBinding(new InMemoryPlatform(''), 'claude-test', new NullLogger()));

        self::assertSame('claude-test', $symfonyAiLLMClient->model());
    }

    /**
     * @throws BudgetExceededException
     * @throws MissingAiPlatformException
     * @throws TransientLLMFailureException
     * @throws NonTransientLLMFailureException
     */
    public function test_complete_throws_when_no_ai_platform_is_configured(): void
    {
        $symfonyAiLLMClient = new SymfonyAiLLMClient(new PlatformBinding(null, 'test-model', new NullLogger()));

        $this->expectException(MissingAiPlatformException::class);
        $this->expectExceptionMessage('No AI platform is configured');

        $symfonyAiLLMClient->complete('sys', 'usr');
    }

    /**
     * @throws BudgetExceededException
     * @throws MissingAiPlatformException
     * @throws TransientLLMFailureException
     * @throws NonTransientLLMFailureException
     */
    public function test_complete_with_tools_throws_when_no_ai_platform_is_configured(): void
    {
        $symfonyAiLLMClient = new SymfonyAiLLMClient(new PlatformBinding(null, 'test-model', new NullLogger()));
        $toolRegistry = new ToolRegistry([$this->makeTool('lookup', 'lookup')], new NullLogger());

        $this->expectException(MissingAiPlatformException::class);
        $this->expectExceptionMessage('config/packages/ai.yaml');

        $symfonyAiLLMClient->completeWithTools('sys', 'usr', $toolRegistry, 3);
    }

    /**
     * @throws MissingAiPlatformException
     * @throws BudgetExceededException
     */
    public function test_complete_batch_throws_when_no_ai_platform_is_configured(): void
    {
        $symfonyAiLLMClient = new SymfonyAiLLMClient(new PlatformBinding(null, 'test-model', new NullLogger()));

        $this->expectException(MissingAiPlatformException::class);
        $this->expectExceptionMessage('No AI platform is configured');

        $symfonyAiLLMClient->completeBatch([['system' => 's', 'user' => 'u']], 2);
    }

    /**
     * @throws MissingAiPlatformException
     * @throws BudgetExceededException
     */
    public function test_complete_batch_returns_empty_for_no_requests(): void
    {
        $symfonyAiLLMClient = new SymfonyAiLLMClient(new PlatformBinding(new InMemoryPlatform('x'), 'm', new NullLogger()));

        self::assertSame([], $symfonyAiLLMClient->completeBatch([], 4));
    }

    /**
     * @throws MissingAiPlatformException
     * @throws BudgetExceededException
     */
    public function test_complete_batch_returns_one_response_per_request_in_order(): void
    {
        $symfonyAiLLMClient = new SymfonyAiLLMClient(new PlatformBinding(new InMemoryPlatform('batched'), 'm', new NullLogger()));

        $responses = $symfonyAiLLMClient->completeBatch([
            ['system' => 's1', 'user' => 'u1'],
            ['system' => 's2', 'user' => 'u2'],
            ['system' => 's3', 'user' => 'u3'],
        ], 2);

        self::assertCount(3, $responses);
        self::assertSame('batched', $responses[0]->content());
        self::assertSame('batched', $responses[1]->content());
        self::assertSame('batched', $responses[2]->content());
    }

    /**
     * @throws MissingAiPlatformException
     * @throws BudgetExceededException
     */
    public function test_complete_batch_processes_more_requests_than_window_size(): void
    {
        $symfonyAiLLMClient = new SymfonyAiLLMClient(new PlatformBinding(new InMemoryPlatform('ok'), 'm', new NullLogger()));

        $requests = [];
        for ($i = 0; $i < 5; ++$i) {
            $requests[] = ['system' => 'sys'.$i, 'user' => 'usr'.$i];
        }

        $responses = $symfonyAiLLMClient->completeBatch($requests, 2);

        self::assertCount(5, $responses);
    }

    /**
     * @throws MissingAiPlatformException
     * @throws BudgetExceededException
     */
    public function test_complete_batch_clamps_non_positive_window_to_one(): void
    {
        $symfonyAiLLMClient = new SymfonyAiLLMClient(new PlatformBinding(new InMemoryPlatform('ok'), 'm', new NullLogger()));

        $responses = $symfonyAiLLMClient->completeBatch([
            ['system' => 's', 'user' => 'u'],
            ['system' => 's', 'user' => 'u'],
        ], 0);

        self::assertCount(2, $responses);
    }

    /**
     * @throws MissingAiPlatformException
     * @throws BudgetExceededException
     */
    public function test_complete_batch_records_token_usage_per_response(): void
    {
        $platform = $this->scriptedPlatformWithTokenUsage(
            [new TextResult('one'), new TextResult('two')],
            [new TokenUsage(promptTokens: 11, completionTokens: 7), new TokenUsage(promptTokens: 11, completionTokens: 7)],
        );

        $tokenUsageRecorder = new TokenUsageRecorder();
        $symfonyAiLLMClient = new SymfonyAiLLMClient(
            new PlatformBinding($platform, 'm', new NullLogger()),
            platformAccountingConfig: new PlatformAccountingConfig(tokenUsageRecorder: $tokenUsageRecorder),
        );

        $responses = $symfonyAiLLMClient->completeBatch([
            ['system' => 's1', 'user' => 'u1'],
            ['system' => 's2', 'user' => 'u2'],
        ], 2);

        self::assertSame(11, $responses[0]->inputTokens());
        self::assertSame(7, $responses[0]->outputTokens());
        self::assertSame(11, $responses[1]->inputTokens());
        self::assertSame(7, $responses[1]->outputTokens());
    }

    /**
     * @throws MissingAiPlatformException
     * @throws BudgetExceededException
     */
    public function test_complete_batch_acquires_rate_limit_for_each_request(): void
    {
        $fakeRateLimiter = new FakeRateLimiter();
        $symfonyAiLLMClient = new SymfonyAiLLMClient(
            new PlatformBinding(new InMemoryPlatform('ok'), 'm', new NullLogger()),
            new PlatformRequestConfig(tokenEstimator: new FixedTokenEstimator(123)),
            new PlatformResilienceConfig(rateLimiter: $fakeRateLimiter),
        );

        $symfonyAiLLMClient->completeBatch([
            ['system' => 's1', 'user' => 'u1'],
            ['system' => 's2', 'user' => 'u2'],
            ['system' => 's3', 'user' => 'u3'],
        ], 2);

        self::assertSame([246, 246, 246], $fakeRateLimiter->acquired);
    }

    /**
     * @throws MissingAiPlatformException
     * @throws BudgetExceededException
     */
    public function test_complete_batch_falls_back_to_the_sequential_complete_path_when_dispatch_throws(): void
    {
        $platform = $this->flakyPlatform([
            new RuntimeException('dispatch exploded'),
            new TextResult('recovered-sequentially'),
        ]);

        $symfonyAiLLMClient = new SymfonyAiLLMClient(new PlatformBinding($platform, 'm', new NullLogger()));

        $responses = $symfonyAiLLMClient->completeBatch([
            ['system' => 's', 'user' => 'u'],
        ], 4);

        self::assertCount(1, $responses);
        self::assertSame('recovered-sequentially', $responses[0]->content());
    }

    /**
     * @throws MissingAiPlatformException
     * @throws BudgetExceededException
     */
    public function test_complete_batch_releases_the_rate_limiter_reservation_when_dispatch_fails(): void
    {
        $fakeRateLimiter = new FakeRateLimiter();
        $platform = $this->flakyPlatform([
            new RuntimeException('dispatch exploded'),
            new TextResult('recovered-sequentially'),
        ]);

        $symfonyAiLLMClient = new SymfonyAiLLMClient(
            new PlatformBinding($platform, 'm', new NullLogger()),
            platformResilienceConfig: new PlatformResilienceConfig(rateLimiter: $fakeRateLimiter),
        );

        $symfonyAiLLMClient->completeBatch([
            ['system' => 's', 'user' => 'u'],
        ], 4);

        // The dispatch-loop acquire() for the request whose dispatch failed
        // must be released (0,0) before falling back to the sequential
        // path — otherwise it sits unreconciled in the limiter forever.
        self::assertCount(2, $fakeRateLimiter->recorded);
        self::assertSame([0, 0], $fakeRateLimiter->recorded[0]);
    }

    /**
     * @throws MissingAiPlatformException
     * @throws BudgetExceededException
     */
    public function test_complete_batch_releases_exactly_the_failed_reservation_before_falling_back_to_complete(): void
    {
        $fakeRateLimiter = new FakeRateLimiter();
        $platform = new class implements PlatformInterface {
            private int $calls = 0;

            #[Override]
            public function invoke(Model|string $model, array|string|object $input, array $options = []): DeferredResult
            {
                if (0 === $this->calls) {
                    ++$this->calls;

                    return new DeferredResult(new ThrowingConverter(new RuntimeException('boom')), new InMemoryRawResult(['text' => ''], [], (object) []), $options);
                }

                $deferredResult = new DeferredResult(new PlainConverter(new TextResult('recovered')), new InMemoryRawResult(['text' => ''], [], (object) []), $options);
                $deferredResult->getMetadata()->add('token_usage', new TokenUsage(promptTokens: 9, completionTokens: 4));

                return $deferredResult;
            }

            #[Override]
            public function getModelCatalog(): ModelCatalogInterface
            {
                return new FallbackModelCatalog();
            }
        };

        $symfonyAiLLMClient = new SymfonyAiLLMClient(
            new PlatformBinding($platform, 'm', new NullLogger()),
            platformResilienceConfig: new PlatformResilienceConfig(rateLimiter: $fakeRateLimiter),
        );

        $responses = $symfonyAiLLMClient->completeBatch([['system' => 's', 'user' => 'u']], 4);

        self::assertSame('recovered', $responses[0]->content());
        self::assertSame([[0, 0], [9, 4]], $fakeRateLimiter->recorded);
    }

    /**
     * @throws MissingAiPlatformException
     * @throws BudgetExceededException
     */
    public function test_complete_batch_does_not_release_an_already_reconciled_reservation_when_a_later_step_fails(): void
    {
        $fakeRateLimiter = new FakeRateLimiter();
        $platform = $this->scriptedPlatformWithTokenUsage(
            [new TextResult('ignored'), new TextResult('recovered')],
            [new TokenUsage(promptTokens: -1, completionTokens: 0), new TokenUsage(promptTokens: 5, completionTokens: 2)],
        );

        $symfonyAiLLMClient = new SymfonyAiLLMClient(
            new PlatformBinding($platform, 'm', new NullLogger()),
            platformResilienceConfig: new PlatformResilienceConfig(rateLimiter: $fakeRateLimiter),
        );

        $responses = $symfonyAiLLMClient->completeBatch([['system' => 's', 'user' => 'u']], 4);

        self::assertSame('recovered', $responses[0]->content());
        self::assertSame([[-1, 0], [5, 2]], $fakeRateLimiter->recorded);
    }

    /**
     * @throws MissingAiPlatformException
     * @throws BudgetExceededException
     */
    public function test_complete_batch_with_tools_resolves_each_conversation_against_its_own_registry(): void
    {
        $firstToolCalls = 0;
        $secondToolCalls = 0;
        $firstRegistry = new ToolRegistry([$this->makeTool('record', 'd', static function (array $arguments) use (&$firstToolCalls): string {
            ++$firstToolCalls;

            return 'ok';
        })], new NullLogger());
        $secondRegistry = new ToolRegistry([$this->makeTool('record', 'd', static function (array $arguments) use (&$secondToolCalls): string {
            ++$secondToolCalls;

            return 'ok';
        })], new NullLogger());

        $platform = $this->scriptedPlatform([
            new MultiPartResult([new ToolCallResult([new ToolCall('1', 'record')])]),
            new TextResult('answer-1'),
            new TextResult('answer-0'),
        ]);

        $symfonyAiLLMClient = new SymfonyAiLLMClient(new PlatformBinding($platform, 'm', new NullLogger()));

        $responses = $symfonyAiLLMClient->completeBatchWithTools([
            ['system' => 's0', 'user' => 'u0', 'tools' => $firstRegistry],
            ['system' => 's1', 'user' => 'u1', 'tools' => $secondRegistry],
        ], 4, 3);

        self::assertCount(2, $responses);
        self::assertSame('answer-0', $responses[0]->content());
        self::assertSame('end_turn', $responses[0]->stopReason());
        self::assertSame('answer-1', $responses[1]->content());
        self::assertSame(1, $firstToolCalls);
        self::assertSame(0, $secondToolCalls);
    }

    /**
     * @throws MissingAiPlatformException
     * @throws BudgetExceededException
     */
    public function test_complete_batch_with_tools_returns_empty_list_for_empty_requests(): void
    {
        $symfonyAiLLMClient = new SymfonyAiLLMClient(new PlatformBinding(new InMemoryPlatform('ok'), 'm', new NullLogger()));

        self::assertSame([], $symfonyAiLLMClient->completeBatchWithTools([], 4, 3));
    }

    /**
     * @throws MissingAiPlatformException
     * @throws BudgetExceededException
     */
    public function test_complete_batch_with_tools_caps_iterations_and_warns(): void
    {
        $toolRegistry = new ToolRegistry([$this->makeTool('record', 'd')], new NullLogger());

        /** @var list<array{string, array<string, mixed>}> $warnings */
        $warnings = [];
        $logger = self::createStub(LoggerInterface::class);
        $logger->method('debug');
        $logger->method('warning')->willReturnCallback(
            static function (string $msg, array $ctx = []) use (&$warnings): void {
                $warnings[] = [$msg, $ctx];
            },
        );

        $platformInvocationLog = new PlatformInvocationLog();
        $platform = $this->scriptedPlatform([
            new MultiPartResult([new ToolCallResult([new ToolCall('1', 'record')])]),
            new MultiPartResult([new ToolCallResult([new ToolCall('2', 'record')])]),
            new MultiPartResult([new ToolCallResult([new ToolCall('3', 'record')])]),
        ], $platformInvocationLog);

        $symfonyAiLLMClient = new SymfonyAiLLMClient(new PlatformBinding($platform, 'm', $logger));

        $responses = $symfonyAiLLMClient->completeBatchWithTools([
            ['system' => 's', 'user' => 'u', 'tools' => $toolRegistry],
        ], 4, 2);

        self::assertSame('max_tool_iterations', $responses[0]->stopReason());
        self::assertSame('', $responses[0]->content());
        self::assertSame(2, $platformInvocationLog->invocations);

        $capLogs = array_values(array_filter(
            $warnings,
            static fn (array $entry): bool => 'Tool-using loop hit iteration cap' === $entry[0],
        ));
        self::assertCount(1, $capLogs);
        self::assertSame(2, $capLogs[0][1]['max_iterations']);
    }

    /**
     * @throws InvalidRetryConfigurationException
     * @throws MissingAiPlatformException
     * @throws BudgetExceededException
     */
    public function test_complete_batch_with_tools_falls_back_to_the_sequential_path_when_dispatch_fails_before_tools_ran(): void
    {
        $toolRegistry = new ToolRegistry([$this->makeTool('record', 'd')], new NullLogger());
        $platform = $this->flakyPlatform([
            new RuntimeException('HTTP 503 Service Unavailable'),
            new TextResult('recovered'),
        ]);

        $symfonyAiLLMClient = new SymfonyAiLLMClient(
            new PlatformBinding($platform, 'm', new NullLogger()),
            platformResilienceConfig: new PlatformResilienceConfig(retryPolicy: new RetryPolicy(new BackoffSchedule(maxAttempts: 3, initialDelayMs: 10, backoffMultiplier: 2.0, jitterRatio: 0.0), jitterSource: static fn (): float => 0.5), transientFailureClassifier: new TransientFailureClassifier(), sleeper: new FakeSleeper()),
        );

        $responses = $symfonyAiLLMClient->completeBatchWithTools([
            ['system' => 's', 'user' => 'u', 'tools' => $toolRegistry],
        ], 4, 3);

        self::assertSame('recovered', $responses[0]->content());
        self::assertSame('end_turn', $responses[0]->stopReason());
    }

    /**
     * @throws InvalidRetryConfigurationException
     * @throws MissingAiPlatformException
     * @throws BudgetExceededException
     */
    public function test_complete_batch_with_tools_falls_back_to_the_sequential_path_when_the_retry_itself_fails_before_tools_ran(): void
    {
        $toolRegistry = new ToolRegistry([$this->makeTool('record', 'd')], new NullLogger());
        $platform = $this->flakyPlatform([
            new RuntimeException('HTTP 503 Service Unavailable'),
            new RuntimeException('HTTP 401 Unauthorized'),
            new TextResult('recovered-via-full-restart'),
        ]);

        $symfonyAiLLMClient = new SymfonyAiLLMClient(
            new PlatformBinding($platform, 'm', new NullLogger()),
            platformResilienceConfig: new PlatformResilienceConfig(retryPolicy: new RetryPolicy(new BackoffSchedule(maxAttempts: 3, initialDelayMs: 10, backoffMultiplier: 2.0, jitterRatio: 0.0), jitterSource: static fn (): float => 0.5), transientFailureClassifier: new TransientFailureClassifier(), sleeper: new FakeSleeper()),
        );

        $responses = $symfonyAiLLMClient->completeBatchWithTools([
            ['system' => 's', 'user' => 'u', 'tools' => $toolRegistry],
        ], 4, 3);

        self::assertSame('recovered-via-full-restart', $responses[0]->content());
        self::assertSame('end_turn', $responses[0]->stopReason());
    }

    /**
     * @throws InvalidRetryConfigurationException
     * @throws MissingAiPlatformException
     * @throws BudgetExceededException
     */
    public function test_complete_batch_with_tools_releases_the_rate_limiter_reservation_when_dispatch_fails_before_tools_ran(): void
    {
        $fakeRateLimiter = new FakeRateLimiter();
        $toolRegistry = new ToolRegistry([$this->makeTool('record', 'd')], new NullLogger());
        $platform = $this->flakyPlatform([
            new RuntimeException('HTTP 503 Service Unavailable'),
            new TextResult('recovered'),
        ]);

        $symfonyAiLLMClient = new SymfonyAiLLMClient(
            new PlatformBinding($platform, 'm', new NullLogger()),
            platformResilienceConfig: new PlatformResilienceConfig(retryPolicy: new RetryPolicy(new BackoffSchedule(maxAttempts: 3, initialDelayMs: 10, backoffMultiplier: 2.0, jitterRatio: 0.0), jitterSource: static fn (): float => 0.5), transientFailureClassifier: new TransientFailureClassifier(), sleeper: new FakeSleeper(), rateLimiter: $fakeRateLimiter),
        );

        $symfonyAiLLMClient->completeBatchWithTools([
            ['system' => 's', 'user' => 'u', 'tools' => $toolRegistry],
        ], 4, 3);

        self::assertCount(2, $fakeRateLimiter->recorded);
        self::assertSame([0, 0], $fakeRateLimiter->recorded[0]);
    }

    /**
     * @throws MissingAiPlatformException
     * @throws BudgetExceededException
     */
    public function test_complete_batch_with_tools_releases_exactly_the_failed_reservation_before_falling_back(): void
    {
        $fakeRateLimiter = new FakeRateLimiter();
        $toolRegistry = new ToolRegistry([$this->makeTool('record', 'd')], new NullLogger());
        $platform = new class implements PlatformInterface {
            private int $calls = 0;

            #[Override]
            public function invoke(Model|string $model, array|string|object $input, array $options = []): DeferredResult
            {
                if (0 === $this->calls) {
                    ++$this->calls;

                    return new DeferredResult(new ThrowingConverter(new RuntimeException('boom')), new InMemoryRawResult(['text' => ''], [], (object) []), $options);
                }

                $deferredResult = new DeferredResult(new PlainConverter(new TextResult('recovered')), new InMemoryRawResult(['text' => ''], [], (object) []), $options);
                $deferredResult->getMetadata()->add('token_usage', new TokenUsage(promptTokens: 9, completionTokens: 4));

                return $deferredResult;
            }

            #[Override]
            public function getModelCatalog(): ModelCatalogInterface
            {
                return new FallbackModelCatalog();
            }
        };

        $symfonyAiLLMClient = new SymfonyAiLLMClient(
            new PlatformBinding($platform, 'm', new NullLogger()),
            platformResilienceConfig: new PlatformResilienceConfig(rateLimiter: $fakeRateLimiter),
        );

        $responses = $symfonyAiLLMClient->completeBatchWithTools([
            ['system' => 's', 'user' => 'u', 'tools' => $toolRegistry],
        ], 4, 3);

        self::assertSame('recovered', $responses[0]->content());
        self::assertSame([[0, 0], [9, 4]], $fakeRateLimiter->recorded);
    }

    /**
     * @throws MissingAiPlatformException
     * @throws BudgetExceededException
     */
    public function test_complete_batch_with_tools_does_not_release_an_already_reconciled_reservation_when_a_later_step_fails(): void
    {
        $fakeRateLimiter = new FakeRateLimiter();
        $toolRegistry = new ToolRegistry([$this->makeTool('record', 'd')], new NullLogger());
        $platform = $this->scriptedPlatformWithTokenUsage(
            [new TextResult('ignored'), new TextResult('recovered')],
            [new TokenUsage(promptTokens: -1, completionTokens: 0), new TokenUsage(promptTokens: 5, completionTokens: 2)],
        );

        $symfonyAiLLMClient = new SymfonyAiLLMClient(
            new PlatformBinding($platform, 'm', new NullLogger()),
            platformResilienceConfig: new PlatformResilienceConfig(rateLimiter: $fakeRateLimiter),
        );

        $responses = $symfonyAiLLMClient->completeBatchWithTools([
            ['system' => 's', 'user' => 'u', 'tools' => $toolRegistry],
        ], 4, 3);

        self::assertSame('recovered', $responses[0]->content());
        self::assertSame([[-1, 0], [5, 2]], $fakeRateLimiter->recorded);
    }

    /**
     * @throws MissingAiPlatformException
     * @throws BudgetExceededException
     */
    public function test_complete_batch_with_tools_falls_back_to_the_sequential_path_when_resolution_fails_before_tools_ran(): void
    {
        $toolRegistry = new ToolRegistry([$this->makeTool('record', 'd')], new NullLogger());

        $platform = new class implements PlatformInterface {
            private int $invocations = 0;

            #[Override]
            public function invoke(Model|string $model, array|string|object $input, array $options = []): DeferredResult
            {
                ++$this->invocations;
                $converter = 1 === $this->invocations
                    ? new class implements ResultConverterInterface {
                        #[Override]
                        public function supports(Model $model): bool
                        {
                            return true;
                        }

                        /**
                         * @throws RuntimeException
                         */
                        #[Override]
                        public function convert(RawResultInterface $result, array $options = []): ResultInterface
                        {
                            throw new RuntimeException('resolution exploded');
                        }

                        #[Override]
                        public function getTokenUsageExtractor(): ?TokenUsageExtractorInterface
                        {
                            return null;
                        }
                    }
                : new PlainConverter(new TextResult('recovered'));

                return new DeferredResult($converter, new InMemoryRawResult(['text' => ''], [], (object) []), $options);
            }

            #[Override]
            public function getModelCatalog(): ModelCatalogInterface
            {
                return new FallbackModelCatalog();
            }
        };

        $symfonyAiLLMClient = new SymfonyAiLLMClient(new PlatformBinding($platform, 'm', new NullLogger()));

        $responses = $symfonyAiLLMClient->completeBatchWithTools([
            ['system' => 's', 'user' => 'u', 'tools' => $toolRegistry],
        ], 4, 3);

        self::assertSame('recovered', $responses[0]->content());
        self::assertSame('end_turn', $responses[0]->stopReason());
    }

    /**
     * @throws MissingAiPlatformException
     * @throws BudgetExceededException
     */
    public function test_complete_batch_with_tools_finalizes_as_empty_content_when_failing_after_tools_ran(): void
    {
        $toolCalls = 0;
        $toolRegistry = new ToolRegistry([$this->makeTool('record', 'd', static function (array $arguments) use (&$toolCalls): string {
            ++$toolCalls;

            return 'ok';
        })], new NullLogger());

        /** @var list<array{string, array<string, mixed>}> $warnings */
        $warnings = [];
        $logger = self::createStub(LoggerInterface::class);
        $logger->method('debug');
        $logger->method('warning')->willReturnCallback(
            static function (string $msg, array $ctx = []) use (&$warnings): void {
                $warnings[] = [$msg, $ctx];
            },
        );

        $platform = $this->flakyPlatform([
            new MultiPartResult([new ToolCallResult([new ToolCall('1', 'record')])]),
            new RuntimeException('HTTP 503 Service Unavailable'),
        ]);

        $symfonyAiLLMClient = new SymfonyAiLLMClient(new PlatformBinding($platform, 'm', $logger));

        $responses = $symfonyAiLLMClient->completeBatchWithTools([
            ['system' => 's', 'user' => 'u', 'tools' => $toolRegistry],
        ], 4, 3);

        self::assertSame('empty_content', $responses[0]->stopReason());
        self::assertSame('', $responses[0]->content());
        self::assertSame(1, $toolCalls);

        $failureLogs = array_values(array_filter(
            $warnings,
            static fn (array $entry): bool => 'Concurrent tool-using conversation failed after tool execution; keeping recorded tool results' === $entry[0],
        ));
        self::assertCount(1, $failureLogs);
        self::assertArrayHasKey('input_tokens', $failureLogs[0][1]);
        self::assertArrayHasKey('output_tokens', $failureLogs[0][1]);
    }

    /**
     * @throws InvalidRetryConfigurationException
     * @throws MissingAiPlatformException
     * @throws BudgetExceededException
     */
    public function test_complete_batch_with_tools_retries_through_the_seam_and_recovers_when_failing_after_tools_ran(): void
    {
        $toolCalls = 0;
        $toolRegistry = new ToolRegistry([$this->makeTool('record', 'd', static function (array $arguments) use (&$toolCalls): string {
            ++$toolCalls;

            return 'ok';
        })], new NullLogger());

        $fakeSleeper = new FakeSleeper();
        $platform = $this->flakyPlatform([
            new MultiPartResult([new ToolCallResult([new ToolCall('1', 'record')])]),
            new RuntimeException('HTTP 503 Service Unavailable'),
            new RuntimeException('HTTP 503 Service Unavailable'),
            new TextResult('recovered-through-retry'),
        ]);

        $symfonyAiLLMClient = new SymfonyAiLLMClient(
            new PlatformBinding($platform, 'm', new NullLogger()),
            platformResilienceConfig: new PlatformResilienceConfig(retryPolicy: new RetryPolicy(new BackoffSchedule(maxAttempts: 3, initialDelayMs: 10, backoffMultiplier: 2.0, jitterRatio: 0.0), jitterSource: static fn (): float => 0.5), transientFailureClassifier: new TransientFailureClassifier(), sleeper: $fakeSleeper),
        );

        $responses = $symfonyAiLLMClient->completeBatchWithTools([
            ['system' => 's', 'user' => 'u', 'tools' => $toolRegistry],
        ], 4, 3);

        self::assertSame('recovered-through-retry', $responses[0]->content());
        self::assertSame('end_turn', $responses[0]->stopReason());
        self::assertSame(1, $toolCalls);
        self::assertSame([10], $fakeSleeper->durations);
    }

    /**
     * @throws MissingAiPlatformException
     * @throws BudgetExceededException
     */
    public function test_complete_batch_with_tools_propagates_budget_exceeded_when_a_post_tool_retry_exceeds_it(): void
    {
        $toolRegistry = new ToolRegistry([$this->makeTool('record', 'd')], new NullLogger());

        $platform = new class implements PlatformInterface {
            private int $invocations = 0;

            #[Override]
            public function invoke(Model|string $model, array|string|object $input, array $options = []): DeferredResult
            {
                ++$this->invocations;

                if (1 === $this->invocations) {
                    return new DeferredResult(
                        new PlainConverter(new MultiPartResult([new ToolCallResult([new ToolCall('1', 'record')])])),
                        new InMemoryRawResult(['text' => ''], [], (object) []),
                        $options,
                    );
                }

                if (2 === $this->invocations) {
                    throw new RuntimeException('HTTP 503 Service Unavailable');
                }

                if ($this->invocations > 3) {
                    throw new RuntimeException('platform invoked more times than scripted — invokeWithRetry never returned (a mutation removed a loop-exit branch).');
                }

                $deferredResult = new DeferredResult(
                    new PlainConverter(new TextResult('too-expensive')),
                    new InMemoryRawResult(['text' => ''], [], (object) []),
                    $options,
                );
                $deferredResult->getMetadata()->add('token_usage', new TokenUsage(promptTokens: 500, completionTokens: 0));

                return $deferredResult;
            }

            #[Override]
            public function getModelCatalog(): ModelCatalogInterface
            {
                return new FallbackModelCatalog();
            }
        };

        $budgetTracker = new BudgetTracker(
            AuditBudget::forTokens(100),
            new CostCalculator($this->stubPricing(0.0, 0.0)),
        );
        $symfonyAiLLMClient = new SymfonyAiLLMClient(
            new PlatformBinding($platform, 'm', new NullLogger()),
            platformAccountingConfig: new PlatformAccountingConfig(tokenUsageRecorder: new TokenUsageRecorder(), budgetTracker: $budgetTracker),
        );

        $this->expectException(BudgetExceededException::class);

        $symfonyAiLLMClient->completeBatchWithTools([
            ['system' => 's', 'user' => 'u', 'tools' => $toolRegistry],
        ], 4, 3);
    }

    /**
     * @throws MissingAiPlatformException
     * @throws BudgetExceededException
     */
    public function test_complete_batch_with_tools_accumulates_tokens_across_rounds(): void
    {
        $toolRegistry = new ToolRegistry([$this->makeTool('record', 'd')], new NullLogger());
        $platform = $this->scriptedPlatformWithTokenUsage(
            [
                new MultiPartResult([new ToolCallResult([new ToolCall('1', 'record')])]),
                new TextResult('done'),
            ],
            [
                new TokenUsage(promptTokens: 10, completionTokens: 5, cacheCreationTokens: 2, cacheReadTokens: 3),
                new TokenUsage(promptTokens: 20, completionTokens: 7, cacheCreationTokens: 1, cacheReadTokens: 4),
            ],
        );

        $symfonyAiLLMClient = new SymfonyAiLLMClient(new PlatformBinding($platform, 'm', new NullLogger()));

        $responses = $symfonyAiLLMClient->completeBatchWithTools([
            ['system' => 's', 'user' => 'u', 'tools' => $toolRegistry],
        ], 4, 3);

        self::assertSame('done', $responses[0]->content());
        self::assertSame(30, $responses[0]->inputTokens());
        self::assertSame(12, $responses[0]->outputTokens());
        self::assertSame(7, $responses[0]->cacheReadTokens());
        self::assertSame(3, $responses[0]->cacheCreationTokens());
    }

    /**
     * @throws MissingAiPlatformException
     * @throws BudgetExceededException
     */
    public function test_complete_batch_with_tools_records_rate_limit_for_each_round(): void
    {
        $fakeRateLimiter = new FakeRateLimiter();
        $toolRegistry = new ToolRegistry([$this->makeTool('record', 'd')], new NullLogger());
        $platform = $this->scriptedPlatform([
            new MultiPartResult([new ToolCallResult([new ToolCall('1', 'record')])]),
            new TextResult('done'),
        ]);

        $symfonyAiLLMClient = new SymfonyAiLLMClient(
            new PlatformBinding($platform, 'm', new NullLogger()),
            platformResilienceConfig: new PlatformResilienceConfig(rateLimiter: $fakeRateLimiter),
        );

        $symfonyAiLLMClient->completeBatchWithTools([
            ['system' => 's', 'user' => 'u', 'tools' => $toolRegistry],
        ], 4, 3);

        self::assertCount(2, $fakeRateLimiter->recorded);
    }

    /**
     * @throws MissingAiPlatformException
     * @throws BudgetExceededException
     */
    public function test_complete_batch_with_tools_appends_assistant_then_tool_call_message_between_rounds(): void
    {
        $tool = $this->makeTool('record', 'd', static fn (array $args): string => 'tool-output');
        $toolRegistry = new ToolRegistry([$tool], new NullLogger());

        $platformInvocationLog = new PlatformInvocationLog();
        $platform = $this->scriptedPlatform([
            new MultiPartResult([new ToolCallResult([new ToolCall('call-1', 'record', ['q' => 'v'])])]),
            new MultiPartResult([new TextResult('done')]),
        ], $platformInvocationLog);

        $symfonyAiLLMClient = new SymfonyAiLLMClient(new PlatformBinding($platform, 'm', new NullLogger()));
        $symfonyAiLLMClient->completeBatchWithTools([
            ['system' => 's', 'user' => 'u', 'tools' => $toolRegistry],
        ], 4, 3);

        self::assertSame(2, $platformInvocationLog->invocations);
        $secondInvocationMessages = $platformInvocationLog->messageSnapshots[1];

        $hasAssistant = false;
        $hasToolCall = false;
        foreach ($secondInvocationMessages as $secondInvocationMessage) {
            if ($secondInvocationMessage instanceof AssistantMessage) {
                $hasAssistant = true;
            }

            if ($secondInvocationMessage instanceof ToolCallMessage) {
                $hasToolCall = true;
            }
        }

        self::assertTrue($hasAssistant, 'Second round should receive an AssistantMessage carrying the prior tool calls');
        self::assertTrue($hasToolCall, 'Second round should receive a ToolCallMessage carrying the tool execution result');
    }

    /**
     * @throws MissingAiPlatformException
     * @throws BudgetExceededException
     */
    public function test_complete_batch_with_tools_dispatches_one_window_at_a_time_when_concurrency_is_one(): void
    {
        $rateLimiter = new class implements RateLimiterInterface {
            /** @var list<string> */
            public array $events = [];

            #[Override]
            public function acquire(int $estimatedInputTokens): void
            {
                $this->events[] = 'acquire';
            }

            #[Override]
            public function record(int $inputTokens, int $outputTokens): void
            {
                $this->events[] = 'record';
            }

            #[Override]
            public function pauseUntil(DateTimeImmutable $until): void {}
        };

        $toolRegistry = new ToolRegistry([$this->makeTool('record', 'd')], new NullLogger());
        $platform = $this->scriptedPlatform([new TextResult('a'), new TextResult('b')]);

        $symfonyAiLLMClient = new SymfonyAiLLMClient(new PlatformBinding($platform, 'm', new NullLogger()), platformResilienceConfig: new PlatformResilienceConfig(rateLimiter: $rateLimiter));

        $symfonyAiLLMClient->completeBatchWithTools([
            ['system' => 's0', 'user' => 'u0', 'tools' => $toolRegistry],
            ['system' => 's1', 'user' => 'u1', 'tools' => $toolRegistry],
        ], 1, 3);

        self::assertSame(['acquire', 'record', 'acquire', 'record'], $rateLimiter->events);
    }

    /**
     * @throws MissingAiPlatformException
     * @throws BudgetExceededException
     */
    public function test_complete_batch_with_tools_keeps_dispatching_later_conversations_after_an_earlier_one_finishes(): void
    {
        $firstRegistry = new ToolRegistry([$this->makeTool('record', 'd')], new NullLogger());
        $secondRegistry = new ToolRegistry([$this->makeTool('record', 'd')], new NullLogger());

        $platform = $this->scriptedPlatform([
            new TextResult('answer-0'),
            new MultiPartResult([new ToolCallResult([new ToolCall('1', 'record')])]),
            new TextResult('answer-1'),
        ]);

        $symfonyAiLLMClient = new SymfonyAiLLMClient(new PlatformBinding($platform, 'm', new NullLogger()));

        $responses = $symfonyAiLLMClient->completeBatchWithTools([
            ['system' => 's0', 'user' => 'u0', 'tools' => $firstRegistry],
            ['system' => 's1', 'user' => 'u1', 'tools' => $secondRegistry],
        ], 4, 3);

        self::assertCount(2, $responses);
        self::assertSame('answer-0', $responses[0]->content());
        self::assertSame('answer-1', $responses[1]->content());
        self::assertSame('end_turn', $responses[1]->stopReason());
    }

    /**
     * @throws MissingAiPlatformException
     * @throws BudgetExceededException
     */
    public function test_complete_batch_with_tools_records_budget_and_aborts_when_a_response_exceeds_it(): void
    {
        $toolRegistry = new ToolRegistry([$this->makeTool('record', 'd')], new NullLogger());
        $platform = $this->scriptedPlatformWithTokenUsage(
            new TextResult('done'),
            new TokenUsage(promptTokens: 500, completionTokens: 0),
        );
        $budgetTracker = new BudgetTracker(
            AuditBudget::forTokens(100),
            new CostCalculator($this->stubPricing(0.0, 0.0)),
        );
        $symfonyAiLLMClient = new SymfonyAiLLMClient(
            new PlatformBinding($platform, 'm', new NullLogger()),
            platformAccountingConfig: new PlatformAccountingConfig(tokenUsageRecorder: new TokenUsageRecorder(), budgetTracker: $budgetTracker),
        );

        $this->expectException(BudgetExceededException::class);

        $symfonyAiLLMClient->completeBatchWithTools([
            ['system' => 's', 'user' => 'u', 'tools' => $toolRegistry],
        ], 4, 3);
    }

    /**
     * @throws MissingAiPlatformException
     * @throws BudgetExceededException
     */
    public function test_complete_batch_with_tools_acquires_rate_limit_for_each_dispatch(): void
    {
        $fakeRateLimiter = new FakeRateLimiter();
        $toolRegistry = new ToolRegistry([$this->makeTool('record', 'd')], new NullLogger());
        $symfonyAiLLMClient = new SymfonyAiLLMClient(
            new PlatformBinding(new InMemoryPlatform('ok'), 'm', new NullLogger()),
            new PlatformRequestConfig(tokenEstimator: new FixedTokenEstimator(123)),
            new PlatformResilienceConfig(rateLimiter: $fakeRateLimiter),
        );

        $symfonyAiLLMClient->completeBatchWithTools([
            ['system' => 's1', 'user' => 'u1', 'tools' => $toolRegistry],
            ['system' => 's2', 'user' => 'u2', 'tools' => $toolRegistry],
        ], 4, 3);

        self::assertSame([246, 246], $fakeRateLimiter->acquired);
    }

    /**
     * @throws MissingAiPlatformException
     * @throws BudgetExceededException
     */
    public function test_complete_batch_records_budget_and_aborts_when_a_response_exceeds_it(): void
    {
        $platform = $this->scriptedPlatformWithTokenUsage(
            new TextResult('done'),
            new TokenUsage(promptTokens: 500, completionTokens: 0),
        );
        $budgetTracker = new BudgetTracker(
            AuditBudget::forTokens(100),
            new CostCalculator($this->stubPricing(0.0, 0.0)),
        );
        $symfonyAiLLMClient = new SymfonyAiLLMClient(
            new PlatformBinding($platform, 'm', new NullLogger()),
            platformAccountingConfig: new PlatformAccountingConfig(tokenUsageRecorder: new TokenUsageRecorder(), budgetTracker: $budgetTracker),
        );

        $this->expectException(BudgetExceededException::class);

        $symfonyAiLLMClient->completeBatch([['system' => 's', 'user' => 'u']], 4);
    }

    /**
     * @throws MissingAiPlatformException
     * @throws BudgetExceededException
     */
    public function test_complete_batch_dispatches_one_request_per_window_when_concurrency_is_one(): void
    {
        $rateLimiter = new class implements RateLimiterInterface {
            /** @var list<string> */
            public array $events = [];

            #[Override]
            public function acquire(int $estimatedInputTokens): void
            {
                $this->events[] = 'acquire';
            }

            #[Override]
            public function record(int $inputTokens, int $outputTokens): void
            {
                $this->events[] = 'record';
            }

            #[Override]
            public function pauseUntil(DateTimeImmutable $until): void {}
        };

        $symfonyAiLLMClient = new SymfonyAiLLMClient(
            new PlatformBinding(new InMemoryPlatform('ok'), 'm', new NullLogger()),
            platformResilienceConfig: new PlatformResilienceConfig(rateLimiter: $rateLimiter),
        );

        $symfonyAiLLMClient->completeBatch([
            ['system' => 's1', 'user' => 'u1'],
            ['system' => 's2', 'user' => 'u2'],
        ], 1);

        // window size 1 ⇒ acquire+resolve one request before the next; a larger
        // window would acquire both before resolving either.
        self::assertSame(['acquire', 'record', 'acquire', 'record'], $rateLimiter->events);
    }

    /**
     * @throws MissingAiPlatformException
     * @throws BudgetExceededException
     */
    public function test_complete_batch_falls_back_to_complete_when_resolving_a_response_throws(): void
    {
        $platform = new class implements PlatformInterface {
            private int $calls = 0;

            #[Override]
            public function invoke(Model|string $model, array|string|object $input, array $options = []): DeferredResult
            {
                if ($this->calls >= 2) {
                    throw new RuntimeException('batch-fallback platform invoked more than twice — invokeWithRetry never returned (a mutation removed a loop-exit branch).');
                }

                $converter = 0 === $this->calls++
                    ? new ThrowingConverter(new RuntimeException('boom'))
                    : new PlainConverter(new TextResult('recovered'));

                return new DeferredResult($converter, new InMemoryRawResult(['text' => ''], [], (object) []), $options);
            }

            #[Override]
            public function getModelCatalog(): ModelCatalogInterface
            {
                return new FallbackModelCatalog();
            }
        };

        $symfonyAiLLMClient = new SymfonyAiLLMClient(new PlatformBinding($platform, 'm', new NullLogger()));

        $responses = $symfonyAiLLMClient->completeBatch([['system' => 's', 'user' => 'u']], 4);

        self::assertSame('recovered', $responses[0]->content());
    }

    /**
     * @throws MissingAiPlatformException
     */
    public function test_complete_batch_rethrows_budget_exceeded_without_falling_back_to_complete(): void
    {
        $platformInvocationLog = new PlatformInvocationLog();
        $platform = new class($platformInvocationLog) implements PlatformInterface {
            public function __construct(private readonly PlatformInvocationLog $platformInvocationLog) {}

            #[Override]
            public function invoke(Model|string $model, array|string|object $input, array $options = []): DeferredResult
            {
                ++$this->platformInvocationLog->invocations;
                $deferredResult = new DeferredResult(
                    new PlainConverter(new TextResult('x')),
                    new InMemoryRawResult(['text' => ''], [], (object) []),
                    $options,
                );
                $deferredResult->getMetadata()->add('token_usage', new TokenUsage(promptTokens: 500, completionTokens: 0));

                return $deferredResult;
            }

            #[Override]
            public function getModelCatalog(): ModelCatalogInterface
            {
                return new FallbackModelCatalog();
            }
        };

        $budgetTracker = new BudgetTracker(
            AuditBudget::forTokens(100),
            new CostCalculator($this->stubPricing(0.0, 0.0)),
        );
        $symfonyAiLLMClient = new SymfonyAiLLMClient(
            new PlatformBinding($platform, 'm', new NullLogger()),
            platformAccountingConfig: new PlatformAccountingConfig(tokenUsageRecorder: new TokenUsageRecorder(), budgetTracker: $budgetTracker),
        );

        $budgetExceeded = false;
        try {
            $symfonyAiLLMClient->completeBatch([['system' => 's', 'user' => 'u']], 4);
        } catch (BudgetExceededException) {
            $budgetExceeded = true;
        }

        self::assertTrue($budgetExceeded, 'completeBatch must abort rather than retry via complete().');
        self::assertSame(1, $platformInvocationLog->invocations);
    }

    /**
     * @throws BudgetExceededException
     * @throws MissingAiPlatformException
     * @throws TransientLLMFailureException
     * @throws NonTransientLLMFailureException
     */
    public function test_complete_with_tools_returns_text_when_platform_emits_no_tool_calls(): void
    {
        $platform = $this->scriptedPlatform([
            new MultiPartResult([new TextResult('done')]),
        ]);
        $symfonyAiLLMClient = new SymfonyAiLLMClient(new PlatformBinding($platform, 'm', new NullLogger()));

        $toolRegistry = new ToolRegistry([$this->makeTool('lookup', 'description here')], new NullLogger());

        $llmResponse = $symfonyAiLLMClient->completeWithTools('sys', 'usr', $toolRegistry, 3);

        self::assertSame('done', $llmResponse->content());
        self::assertSame('end_turn', $llmResponse->stopReason());
        self::assertSame(0, $llmResponse->inputTokens());
        self::assertSame(0, $llmResponse->outputTokens());
    }

    /**
     * @throws BudgetExceededException
     * @throws MissingAiPlatformException
     * @throws TransientLLMFailureException
     * @throws NonTransientLLMFailureException
     */
    public function test_complete_with_tools_executes_tool_calls_then_returns_final_text(): void
    {
        $tool = $this->makeTool('lookup', 'looks things up', static fn (array $args): string => 'tool-result');
        $toolRegistry = new ToolRegistry([$tool], new NullLogger());

        $platform = $this->scriptedPlatform([
            new MultiPartResult([new ToolCallResult([new ToolCall('call-1', 'lookup', ['q' => 'test'])])]),
            new MultiPartResult([new TextResult('final answer')]),
        ]);

        $symfonyAiLLMClient = new SymfonyAiLLMClient(new PlatformBinding($platform, 'm', new NullLogger()));
        $llmResponse = $symfonyAiLLMClient->completeWithTools('sys', 'usr', $toolRegistry, 5);

        self::assertSame('final answer', $llmResponse->content());
        self::assertSame('end_turn', $llmResponse->stopReason());
    }

    /**
     * @throws BudgetExceededException
     * @throws MissingAiPlatformException
     * @throws TransientLLMFailureException
     * @throws NonTransientLLMFailureException
     */
    public function test_complete_with_tools_stops_at_iteration_cap_and_warns(): void
    {
        $tool = $this->makeTool('lookup', 'lookup');
        $toolRegistry = new ToolRegistry([$tool], new NullLogger());

        /** @var list<array{string, array<string, mixed>}> $warnings */
        $warnings = [];
        $logger = self::createStub(LoggerInterface::class);
        $logger->method('debug');
        $logger->method('warning')->willReturnCallback(
            static function (string $msg, array $ctx = []) use (&$warnings): void {
                $warnings[] = [$msg, $ctx];
            },
        );

        $platform = $this->scriptedPlatform([
            new MultiPartResult([new ToolCallResult([new ToolCall('1', 'lookup')])]),
            new MultiPartResult([new ToolCallResult([new ToolCall('2', 'lookup')])]),
            new MultiPartResult([new ToolCallResult([new ToolCall('3', 'lookup')])]),
        ]);

        $symfonyAiLLMClient = new SymfonyAiLLMClient(new PlatformBinding($platform, 'm', $logger));
        $llmResponse = $symfonyAiLLMClient->completeWithTools('sys', 'usr', $toolRegistry, 2);

        self::assertSame('', $llmResponse->content());
        self::assertSame('max_tool_iterations', $llmResponse->stopReason());
        self::assertSame(0, $llmResponse->inputTokens());
        self::assertSame(0, $llmResponse->outputTokens());

        $capLogs = array_values(array_filter(
            $warnings,
            static fn (array $entry): bool => 'Tool-using loop hit iteration cap' === $entry[0],
        ));
        self::assertCount(1, $capLogs);
        self::assertSame(2, $capLogs[0][1]['max_iterations']);
    }

    /**
     * @throws BudgetExceededException
     * @throws MissingAiPlatformException
     * @throws TransientLLMFailureException
     * @throws NonTransientLLMFailureException
     */
    public function test_complete_with_tools_invokes_platform_exact_max_iterations_times_when_all_iterations_return_tool_calls(): void
    {
        $tool = $this->makeTool('lookup', 'lookup');
        $toolRegistry = new ToolRegistry([$tool], new NullLogger());

        $platformInvocationLog = new PlatformInvocationLog();
        $platform = $this->scriptedPlatform(
            [
                new MultiPartResult([new ToolCallResult([new ToolCall('1', 'lookup')])]),
                new MultiPartResult([new ToolCallResult([new ToolCall('2', 'lookup')])]),
                new MultiPartResult([new ToolCallResult([new ToolCall('3', 'lookup')])]),
            ],
            $platformInvocationLog,
        );

        $symfonyAiLLMClient = new SymfonyAiLLMClient(new PlatformBinding($platform, 'm', new NullLogger()));
        $symfonyAiLLMClient->completeWithTools('sys', 'usr', $toolRegistry, 2);

        self::assertSame(2, $platformInvocationLog->invocations);
    }

    /**
     * @throws BudgetExceededException
     * @throws MissingAiPlatformException
     * @throws TransientLLMFailureException
     * @throws NonTransientLLMFailureException
     */
    public function test_complete_with_tools_logs_loop_ended_debug_with_iterations_count_and_content_length(): void
    {
        $toolRegistry = new ToolRegistry([$this->makeTool('lookup', 'lookup')], new NullLogger());

        /** @var list<array{string, array<string, mixed>}> $logs */
        $logs = [];
        $logger = self::createStub(LoggerInterface::class);
        $logger->method('debug')->willReturnCallback(
            static function (string $msg, array $ctx = []) use (&$logs): void {
                $logs[] = [$msg, $ctx];
            },
        );

        $platform = $this->scriptedPlatform([
            new MultiPartResult([new ToolCallResult([new ToolCall('1', 'lookup')])]),
            new MultiPartResult([new TextResult('finished-12c')]),
        ]);

        $symfonyAiLLMClient = new SymfonyAiLLMClient(new PlatformBinding($platform, 'm', $logger));
        $symfonyAiLLMClient->completeWithTools('sys', 'usr', $toolRegistry, 5);

        $endedLogs = array_values(array_filter(
            $logs,
            static fn (array $entry): bool => 'Tool-using loop ended with text response' === $entry[0],
        ));

        self::assertCount(1, $endedLogs);
        self::assertSame(1, $endedLogs[0][1]['iterations']);
        self::assertSame(12, $endedLogs[0][1]['content_length']);
    }

    /**
     * @throws BudgetExceededException
     * @throws MissingAiPlatformException
     * @throws TransientLLMFailureException
     * @throws NonTransientLLMFailureException
     */
    public function test_complete_with_tools_appends_assistant_message_then_tool_call_message_between_iterations(): void
    {
        $tool = $this->makeTool('lookup', 'lookup', static fn (array $args): string => 'tool-output');
        $toolRegistry = new ToolRegistry([$tool], new NullLogger());

        $platformInvocationLog = new PlatformInvocationLog();
        $platform = $this->scriptedPlatform(
            [
                new MultiPartResult([new ToolCallResult([new ToolCall('call-1', 'lookup', ['q' => 'v'])])]),
                new MultiPartResult([new TextResult('done')]),
            ],
            $platformInvocationLog,
        );

        $symfonyAiLLMClient = new SymfonyAiLLMClient(new PlatformBinding($platform, 'm', new NullLogger()));
        $symfonyAiLLMClient->completeWithTools('sys', 'usr', $toolRegistry, 5);

        self::assertSame(2, $platformInvocationLog->invocations);
        $secondInvocationMessages = $platformInvocationLog->messageSnapshots[1];

        $hasAssistant = false;
        $hasToolCall = false;
        foreach ($secondInvocationMessages as $secondInvocationMessage) {
            if ($secondInvocationMessage instanceof AssistantMessage) {
                $hasAssistant = true;
            }

            if ($secondInvocationMessage instanceof ToolCallMessage) {
                $hasToolCall = true;
            }
        }

        self::assertTrue($hasAssistant, 'Second invoke should receive an AssistantMessage carrying the prior tool calls');
        self::assertTrue($hasToolCall, 'Second invoke should receive a ToolCallMessage carrying the tool execution result');
    }

    /**
     * @throws BudgetExceededException
     * @throws MissingAiPlatformException
     * @throws TransientLLMFailureException
     * @throws NonTransientLLMFailureException
     */
    public function test_complete_with_tools_logs_tool_invocation_with_tool_name_and_iteration_number(): void
    {
        $tool = $this->makeTool('lookup', 'lookup', static fn (array $args): string => 'ok');
        $toolRegistry = new ToolRegistry([$tool], new NullLogger());

        /** @var list<array{string, array<string, mixed>}> $logs */
        $logs = [];
        $logger = self::createStub(LoggerInterface::class);
        $logger->method('debug')->willReturnCallback(
            static function (string $msg, array $ctx = []) use (&$logs): void {
                $logs[] = [$msg, $ctx];
            },
        );

        $platform = $this->scriptedPlatform([
            new MultiPartResult([new ToolCallResult([new ToolCall('1', 'lookup')])]),
            new MultiPartResult([new TextResult('done')]),
        ]);

        $symfonyAiLLMClient = new SymfonyAiLLMClient(new PlatformBinding($platform, 'm', $logger));
        $symfonyAiLLMClient->completeWithTools('sys', 'usr', $toolRegistry, 5);

        $toolInvokedLogs = array_values(array_filter(
            $logs,
            static fn (array $entry): bool => 'Tool invoked' === $entry[0],
        ));

        self::assertCount(1, $toolInvokedLogs);
        self::assertSame('lookup', $toolInvokedLogs[0][1]['tool']);
        self::assertSame(1, $toolInvokedLogs[0][1]['iteration']);
    }

    /**
     * @throws BudgetExceededException
     * @throws MissingAiPlatformException
     * @throws TransientLLMFailureException
     * @throws NonTransientLLMFailureException
     */
    public function test_complete_with_tools_passes_tool_definitions_in_options(): void
    {
        $invocationOptionsCapture = new InvocationOptionsCapture();
        $platform = $this->scriptedPlatformCapturingOptions(
            new MultiPartResult([new TextResult('done')]),
            $invocationOptionsCapture,
        );

        $tool = $this->makeTool(
            'fetch_file',
            'reads a file from disk',
            parametersSchema: [
                'type' => 'object',
                'properties' => [
                    'path' => ['type' => 'string', 'description' => 'file path'],
                    123 => ['type' => 'string', 'description' => 'ignored — non-string key'],
                    'bogus_spec' => 'not-an-array',
                    'malformed_type' => ['type' => 42, 'description' => null],
                ],
                'required' => ['path', 456, 'mode'],
            ],
        );

        $symfonyAiLLMClient = new SymfonyAiLLMClient(new PlatformBinding($platform, 'm', new NullLogger()));
        $symfonyAiLLMClient->completeWithTools('sys', 'usr', new ToolRegistry([$tool], new NullLogger()), 3);

        self::assertNotNull($invocationOptionsCapture->options);
        self::assertArrayHasKey('tools', $invocationOptionsCapture->options);
        $tools = $invocationOptionsCapture->options['tools'];
        self::assertIsArray($tools);
        self::assertCount(1, $tools);

        $platformTool = $tools[0];
        self::assertInstanceOf(Tool::class, $platformTool);
        self::assertSame('fetch_file', $platformTool->getName());
        self::assertSame('reads a file from disk', $platformTool->getDescription());

        $parameters = $platformTool->getParameters();
        self::assertNotNull($parameters);
        self::assertSame(['path', 'mode'], $parameters['required']);
        $properties = $parameters['properties'];
        self::assertArrayHasKey('path', $properties);
        self::assertSame('string', $properties['path']['type']);
        self::assertSame('file path', $properties['path']['description']);
        self::assertSame('string', $properties['malformed_type']['type']);
        self::assertSame('', $properties['malformed_type']['description']);
    }

    /**
     * @throws BudgetExceededException
     * @throws MissingAiPlatformException
     * @throws TransientLLMFailureException
     * @throws NonTransientLLMFailureException
     */
    public function test_complete_with_tools_handles_bare_tool_call_result_not_wrapped_in_multipart(): void
    {
        $tool = $this->makeTool('lookup', 'lookup', static fn (array $args): string => 'ok');
        $toolRegistry = new ToolRegistry([$tool], new NullLogger());

        $platform = $this->scriptedPlatform([
            new ToolCallResult([new ToolCall('1', 'lookup')]),
            new MultiPartResult([new TextResult('final')]),
        ]);

        $symfonyAiLLMClient = new SymfonyAiLLMClient(new PlatformBinding($platform, 'm', new NullLogger()));
        $llmResponse = $symfonyAiLLMClient->completeWithTools('sys', 'usr', $toolRegistry, 5);

        self::assertSame('final', $llmResponse->content());
    }

    /**
     * @throws BudgetExceededException
     * @throws MissingAiPlatformException
     * @throws TransientLLMFailureException
     * @throws NonTransientLLMFailureException
     */
    public function test_complete_with_tools_handles_bare_text_result_not_wrapped_in_multipart(): void
    {
        $tool = $this->makeTool('lookup', 'lookup');
        $toolRegistry = new ToolRegistry([$tool], new NullLogger());

        $platform = $this->scriptedPlatform([new TextResult('plain text')]);

        $symfonyAiLLMClient = new SymfonyAiLLMClient(new PlatformBinding($platform, 'm', new NullLogger()));
        $llmResponse = $symfonyAiLLMClient->completeWithTools('sys', 'usr', $toolRegistry, 3);

        self::assertSame('plain text', $llmResponse->content());
    }

    /**
     * @throws BudgetExceededException
     * @throws MissingAiPlatformException
     * @throws TransientLLMFailureException
     * @throws NonTransientLLMFailureException
     */
    public function test_complete_with_tools_falls_back_to_empty_text_when_platform_returns_unknown_result_type(): void
    {
        $tool = $this->makeTool('lookup', 'lookup');
        $toolRegistry = new ToolRegistry([$tool], new NullLogger());

        $unknownResult = new class extends BaseResult {
            /** @return list<never> */
            #[Override]
            public function getContent(): array
            {
                return [];
            }
        };

        $platform = $this->scriptedPlatform([$unknownResult]);

        $symfonyAiLLMClient = new SymfonyAiLLMClient(new PlatformBinding($platform, 'm', new NullLogger()));
        $llmResponse = $symfonyAiLLMClient->completeWithTools('sys', 'usr', $toolRegistry, 3);

        self::assertSame('', $llmResponse->content());
        self::assertSame('end_turn', $llmResponse->stopReason());
    }

    /**
     * @throws BudgetExceededException
     * @throws MissingAiPlatformException
     * @throws TransientLLMFailureException
     * @throws NonTransientLLMFailureException
     */
    public function test_complete_with_tools_normalize_schema_tolerates_missing_properties_and_required(): void
    {
        $invocationOptionsCapture = new InvocationOptionsCapture();
        $platform = $this->scriptedPlatformCapturingOptions(
            new MultiPartResult([new TextResult('done')]),
            $invocationOptionsCapture,
        );

        $tool = $this->makeTool(
            'no_schema',
            'no schema',
            parametersSchema: [
                'properties' => 'not-an-array',
                'required' => 'not-a-list',
            ],
        );

        $symfonyAiLLMClient = new SymfonyAiLLMClient(new PlatformBinding($platform, 'm', new NullLogger()));
        $symfonyAiLLMClient->completeWithTools('sys', 'usr', new ToolRegistry([$tool], new NullLogger()), 1);

        self::assertNotNull($invocationOptionsCapture->options);
        $tools = $invocationOptionsCapture->options['tools'];
        self::assertIsArray($tools);
        $platformTool = $tools[0];
        self::assertInstanceOf(Tool::class, $platformTool);
        $parameters = $platformTool->getParameters();
        self::assertNotNull($parameters);
        self::assertSame([], $parameters['properties']);
        self::assertSame([], $parameters['required']);
    }

    /**
     * @throws BudgetExceededException
     * @throws MissingAiPlatformException
     * @throws TransientLLMFailureException
     * @throws NonTransientLLMFailureException
     */
    public function test_complete_populates_input_and_output_tokens_from_platform_metadata(): void
    {
        $tokenUsageRecorder = new TokenUsageRecorder();
        $platform = $this->scriptedPlatformWithTokenUsage(
            new TextResult('done'),
            new TokenUsage(promptTokens: 120, completionTokens: 30),
        );
        $symfonyAiLLMClient = new SymfonyAiLLMClient(
            new PlatformBinding($platform, 'm', new NullLogger()),
            platformAccountingConfig: new PlatformAccountingConfig(tokenUsageRecorder: $tokenUsageRecorder),
        );

        $llmResponse = $symfonyAiLLMClient->complete('sys', 'usr');

        self::assertSame(120, $llmResponse->inputTokens());
        self::assertSame(30, $llmResponse->outputTokens());
        self::assertSame(150, $llmResponse->totalTokens());
        self::assertSame(120, $tokenUsageRecorder->snapshot()->inputTokens());
        self::assertSame(30, $tokenUsageRecorder->snapshot()->outputTokens());
    }

    /**
     * @throws BudgetExceededException
     * @throws MissingAiPlatformException
     * @throws TransientLLMFailureException
     * @throws NonTransientLLMFailureException
     */
    public function test_complete_populates_cache_tokens_from_platform_metadata(): void
    {
        $tokenUsageRecorder = new TokenUsageRecorder();
        $platform = $this->scriptedPlatformWithTokenUsage(
            new TextResult('done'),
            new TokenUsage(promptTokens: 120, completionTokens: 30, cacheCreationTokens: 40, cacheReadTokens: 200),
        );
        $symfonyAiLLMClient = new SymfonyAiLLMClient(
            new PlatformBinding($platform, 'm', new NullLogger()),
            platformAccountingConfig: new PlatformAccountingConfig(tokenUsageRecorder: $tokenUsageRecorder),
        );

        $llmResponse = $symfonyAiLLMClient->complete('sys', 'usr');

        self::assertSame(200, $llmResponse->cacheReadTokens());
        self::assertSame(40, $llmResponse->cacheCreationTokens());
        self::assertSame(200, $tokenUsageRecorder->snapshot()->cacheReadTokens());
        self::assertSame(40, $tokenUsageRecorder->snapshot()->cacheCreationTokens());
    }

    /**
     * @throws BudgetExceededException
     * @throws MissingAiPlatformException
     * @throws TransientLLMFailureException
     * @throws NonTransientLLMFailureException
     */
    public function test_complete_defaults_cache_tokens_to_zero_when_token_usage_omits_them(): void
    {
        $platform = $this->scriptedPlatformWithTokenUsage(
            new TextResult('done'),
            new TokenUsage(promptTokens: 120, completionTokens: 30),
        );
        $symfonyAiLLMClient = new SymfonyAiLLMClient(new PlatformBinding($platform, 'm', new NullLogger()));

        $llmResponse = $symfonyAiLLMClient->complete('sys', 'usr');

        self::assertSame(0, $llmResponse->cacheReadTokens());
        self::assertSame(0, $llmResponse->cacheCreationTokens());
    }

    /**
     * @throws BudgetExceededException
     * @throws MissingAiPlatformException
     * @throws TransientLLMFailureException
     * @throws NonTransientLLMFailureException
     */
    public function test_complete_returns_zero_tokens_when_platform_metadata_omits_token_usage(): void
    {
        $tokenUsageRecorder = new TokenUsageRecorder();
        $platform = $this->scriptedPlatform([new TextResult('done')]);
        $symfonyAiLLMClient = new SymfonyAiLLMClient(
            new PlatformBinding($platform, 'm', new NullLogger()),
            platformAccountingConfig: new PlatformAccountingConfig(tokenUsageRecorder: $tokenUsageRecorder),
        );

        $llmResponse = $symfonyAiLLMClient->complete('sys', 'usr');

        self::assertSame(0, $llmResponse->inputTokens());
        self::assertSame(0, $llmResponse->outputTokens());
        self::assertSame(0, $llmResponse->cacheReadTokens());
        self::assertSame(0, $llmResponse->cacheCreationTokens());
        self::assertSame(0, $tokenUsageRecorder->snapshot()->totalTokens());
    }

    /**
     * @throws BudgetExceededException
     * @throws MissingAiPlatformException
     * @throws TransientLLMFailureException
     * @throws NonTransientLLMFailureException
     */
    public function test_complete_returns_zero_tokens_when_token_usage_prompt_and_completion_are_null(): void
    {
        $tokenUsageRecorder = new TokenUsageRecorder();
        $platform = $this->scriptedPlatformWithTokenUsage(
            new TextResult('done'),
            new TokenUsage(),
        );
        $symfonyAiLLMClient = new SymfonyAiLLMClient(
            new PlatformBinding($platform, 'm', new NullLogger()),
            platformAccountingConfig: new PlatformAccountingConfig(tokenUsageRecorder: $tokenUsageRecorder),
        );

        $llmResponse = $symfonyAiLLMClient->complete('sys', 'usr');

        self::assertSame(0, $llmResponse->inputTokens());
        self::assertSame(0, $llmResponse->outputTokens());
        self::assertSame(0, $tokenUsageRecorder->snapshot()->totalTokens());
    }

    /**
     * @throws BudgetExceededException
     * @throws MissingAiPlatformException
     * @throws TransientLLMFailureException
     * @throws NonTransientLLMFailureException
     */
    public function test_consecutive_complete_calls_accumulate_in_shared_recorder(): void
    {
        $tokenUsageRecorder = new TokenUsageRecorder();
        $attackerPlatform = $this->scriptedPlatformWithTokenUsage(
            new TextResult('one'),
            new TokenUsage(promptTokens: 50, completionTokens: 10),
        );
        $reviewerPlatform = $this->scriptedPlatformWithTokenUsage(
            new TextResult('two'),
            new TokenUsage(promptTokens: 30, completionTokens: 5),
        );
        $clientOne = new SymfonyAiLLMClient(new PlatformBinding($attackerPlatform, 'attacker', new NullLogger()), platformAccountingConfig: new PlatformAccountingConfig(tokenUsageRecorder: $tokenUsageRecorder));
        $clientTwo = new SymfonyAiLLMClient(new PlatformBinding($reviewerPlatform, 'reviewer', new NullLogger()), platformAccountingConfig: new PlatformAccountingConfig(tokenUsageRecorder: $tokenUsageRecorder));

        $clientOne->complete('sys', 'usr');
        $clientTwo->complete('sys', 'usr');

        $snapshot = $tokenUsageRecorder->snapshot();
        self::assertSame(80, $snapshot->inputTokens());
        self::assertSame(15, $snapshot->outputTokens());
    }

    /**
     * @throws BudgetExceededException
     * @throws MissingAiPlatformException
     * @throws TransientLLMFailureException
     * @throws NonTransientLLMFailureException
     */
    public function test_complete_with_tools_aborts_mid_loop_when_budget_exceeded(): void
    {
        $tokenUsageRecorder = new TokenUsageRecorder();
        $tool = $this->makeTool('echo', 'echo', static fn (): string => 'echoed');
        $toolCall = new ToolCall('call-1', 'echo', []);
        $platform = $this->scriptedPlatformWithTokenUsage(
            results: [new ToolCallResult([$toolCall]), new TextResult('should-not-reach')],
            tokenUsages: [
                new TokenUsage(promptTokens: 200, completionTokens: 0),
                new TokenUsage(promptTokens: 200, completionTokens: 0),
            ],
        );
        $budgetTracker = new BudgetTracker(
            AuditBudget::forTokens(100),
            new CostCalculator($this->stubPricing(0.0, 0.0)),
        );
        $symfonyAiLLMClient = new SymfonyAiLLMClient(
            new PlatformBinding($platform, 'm', new NullLogger()),
            platformAccountingConfig: new PlatformAccountingConfig(tokenUsageRecorder: $tokenUsageRecorder, budgetTracker: $budgetTracker),
        );

        $this->expectException(BudgetExceededException::class);
        $this->expectExceptionMessage('token budget exceeded (200 / 100 tokens)');

        $symfonyAiLLMClient->completeWithTools(
            'sys',
            'usr',
            new ToolRegistry([$tool], new NullLogger()),
            5,
        );
    }

    /**
     * @throws BudgetExceededException
     * @throws MissingAiPlatformException
     * @throws TransientLLMFailureException
     * @throws NonTransientLLMFailureException
     */
    public function test_complete_records_budget_call_and_aborts_when_exceeded(): void
    {
        $tokenUsageRecorder = new TokenUsageRecorder();
        $platform = $this->scriptedPlatformWithTokenUsage(
            new TextResult('done'),
            new TokenUsage(promptTokens: 500, completionTokens: 0),
        );
        $budgetTracker = new BudgetTracker(
            AuditBudget::forTokens(100),
            new CostCalculator($this->stubPricing(0.0, 0.0)),
        );
        $symfonyAiLLMClient = new SymfonyAiLLMClient(
            new PlatformBinding($platform, 'm', new NullLogger()),
            platformAccountingConfig: new PlatformAccountingConfig(tokenUsageRecorder: $tokenUsageRecorder, budgetTracker: $budgetTracker),
        );

        $this->expectException(BudgetExceededException::class);

        $symfonyAiLLMClient->complete('sys', 'usr');
    }

    private function stubPricing(float $inputPrice, float $outputPrice): PricingProviderInterface
    {
        return new class($inputPrice, $outputPrice) implements PricingProviderInterface {
            public function __construct(
                private readonly float $inputPrice,
                private readonly float $outputPrice,
            ) {}

            #[Override]
            public function pricePerMillionInputTokens(string $model): float
            {
                return $this->inputPrice;
            }

            #[Override]
            public function pricePerMillionOutputTokens(string $model): float
            {
                return $this->outputPrice;
            }

            #[Override]
            public function hasModel(string $model): bool
            {
                return true;
            }
        };
    }

    /**
     * @throws BudgetExceededException
     * @throws MissingAiPlatformException
     * @throws TransientLLMFailureException
     * @throws NonTransientLLMFailureException
     */
    public function test_complete_with_tools_accumulates_tokens_across_iterations(): void
    {
        $tokenUsageRecorder = new TokenUsageRecorder();
        $toolCall = new ToolCall('call-1', 'echo', []);
        $platform = $this->scriptedPlatformWithTokenUsage(
            results: [new ToolCallResult([$toolCall]), new TextResult('finished')],
            tokenUsages: [
                new TokenUsage(promptTokens: 40, completionTokens: 10, cacheCreationTokens: 7, cacheReadTokens: 100),
                new TokenUsage(promptTokens: 60, completionTokens: 5, cacheCreationTokens: 3, cacheReadTokens: 200),
            ],
        );
        $tool = $this->makeTool('echo', 'echo', static fn (): string => 'echoed');
        $symfonyAiLLMClient = new SymfonyAiLLMClient(
            new PlatformBinding($platform, 'm', new NullLogger()),
            platformAccountingConfig: new PlatformAccountingConfig(tokenUsageRecorder: $tokenUsageRecorder),
        );

        $llmResponse = $symfonyAiLLMClient->completeWithTools(
            'sys',
            'usr',
            new ToolRegistry([$tool], new NullLogger()),
            5,
        );

        self::assertSame(100, $llmResponse->inputTokens());
        self::assertSame(15, $llmResponse->outputTokens());
        self::assertSame(300, $llmResponse->cacheReadTokens());
        self::assertSame(10, $llmResponse->cacheCreationTokens());
        self::assertSame(100, $tokenUsageRecorder->snapshot()->inputTokens());
        self::assertSame(15, $tokenUsageRecorder->snapshot()->outputTokens());
        self::assertSame(300, $tokenUsageRecorder->snapshot()->cacheReadTokens());
        self::assertSame(10, $tokenUsageRecorder->snapshot()->cacheCreationTokens());
    }

    /**
     * @param ResultInterface|list<ResultInterface> $results
     * @param TokenUsage|list<TokenUsage>           $tokenUsages
     */
    private function scriptedPlatformWithTokenUsage(
        ResultInterface|array $results = new TextResult(''),
        TokenUsage|array $tokenUsages = new TokenUsage(),
    ): PlatformInterface {
        $resultList = $results instanceof ResultInterface ? [$results] : $results;
        $tokenUsageList = $tokenUsages instanceof TokenUsage ? [$tokenUsages] : $tokenUsages;

        return new class($resultList, $tokenUsageList) implements PlatformInterface {
            /**
             * @param list<ResultInterface> $results
             * @param list<TokenUsage>      $tokenUsages
             */
            public function __construct(
                private array $results,
                private array $tokenUsages,
            ) {}

            #[Override]
            public function invoke(Model|string $model, array|string|object $input, array $options = []): DeferredResult
            {
                $result = array_shift($this->results);
                if (!$result instanceof ResultInterface) {
                    throw new RuntimeException('scriptedPlatformWithTokenUsage invoked more times than scripted — invokeWithRetry never returned (a mutation removed a loop-exit branch).');
                }

                $tokenUsage = array_shift($this->tokenUsages);
                $deferredResult = new DeferredResult(
                    new PlainConverter($result),
                    new InMemoryRawResult(['text' => ''], [], (object) []),
                    $options,
                );
                if ($tokenUsage instanceof TokenUsage) {
                    $deferredResult->getMetadata()->add('token_usage', $tokenUsage);
                }

                return $deferredResult;
            }

            #[Override]
            public function getModelCatalog(): ModelCatalogInterface
            {
                return new FallbackModelCatalog();
            }
        };
    }

    /**
     * @throws InvalidRetryConfigurationException
     * @throws BudgetExceededException
     * @throws MissingAiPlatformException
     * @throws TransientLLMFailureException
     * @throws NonTransientLLMFailureException
     */
    public function test_complete_retries_transient_failures_and_succeeds(): void
    {
        $fakeSleeper = new FakeSleeper();
        $platform = $this->flakyPlatform([
            new RuntimeException('HTTP 503 Service Unavailable'),
            new RuntimeException('HTTP 503 Service Unavailable'),
            new TextResult('finally ok'),
        ]);
        $symfonyAiLLMClient = new SymfonyAiLLMClient(
            new PlatformBinding($platform, 'm', new NullLogger()),
            platformResilienceConfig: new PlatformResilienceConfig(retryPolicy: new RetryPolicy(new BackoffSchedule(maxAttempts: 3, initialDelayMs: 10, backoffMultiplier: 2.0, jitterRatio: 0.0), jitterSource: static fn (): float => 0.5), transientFailureClassifier: new TransientFailureClassifier(), sleeper: $fakeSleeper),
        );

        $llmResponse = $symfonyAiLLMClient->complete('sys', 'usr');

        self::assertSame('finally ok', $llmResponse->content());
        self::assertSame([10, 20], $fakeSleeper->durations);
    }

    /**
     * @throws InvalidRetryConfigurationException
     * @throws BudgetExceededException
     * @throws MissingAiPlatformException
     * @throws TransientLLMFailureException
     * @throws NonTransientLLMFailureException
     */
    public function test_complete_releases_the_rate_limiter_reservation_for_each_failed_retry_attempt(): void
    {
        $fakeRateLimiter = new FakeRateLimiter();
        $platform = $this->flakyPlatform([
            new RuntimeException('HTTP 503 Service Unavailable'),
            new TextResult('recovered'),
        ]);
        $symfonyAiLLMClient = new SymfonyAiLLMClient(
            new PlatformBinding($platform, 'm', new NullLogger()),
            platformResilienceConfig: new PlatformResilienceConfig(retryPolicy: new RetryPolicy(new BackoffSchedule(maxAttempts: 3, initialDelayMs: 10, backoffMultiplier: 2.0, jitterRatio: 0.0), jitterSource: static fn (): float => 0.5), transientFailureClassifier: new TransientFailureClassifier(), sleeper: new FakeSleeper(), rateLimiter: $fakeRateLimiter),
        );

        $symfonyAiLLMClient->complete('sys', 'usr');

        // The failed first attempt's acquire() must be released (0,0)
        // before retrying — otherwise it sits unreconciled in the limiter
        // for the rest of the window, since only the eventual success
        // triggers a real record() call.
        self::assertCount(2, $fakeRateLimiter->recorded);
        self::assertSame([0, 0], $fakeRateLimiter->recorded[0]);
    }

    /**
     * @throws InvalidRetryConfigurationException
     * @throws BudgetExceededException
     * @throws MissingAiPlatformException
     * @throws TransientLLMFailureException
     * @throws NonTransientLLMFailureException
     */
    public function test_complete_throws_transient_failure_after_exhausting_attempts(): void
    {
        $fakeSleeper = new FakeSleeper();
        $platform = $this->flakyPlatform([
            new RuntimeException('HTTP 503 Service Unavailable'),
            new RuntimeException('HTTP 503 Service Unavailable'),
            new RuntimeException('HTTP 503 Service Unavailable'),
        ]);
        $symfonyAiLLMClient = new SymfonyAiLLMClient(
            new PlatformBinding($platform, 'm', new NullLogger()),
            platformResilienceConfig: new PlatformResilienceConfig(retryPolicy: new RetryPolicy(new BackoffSchedule(maxAttempts: 3, initialDelayMs: 10, backoffMultiplier: 2.0, jitterRatio: 0.0), jitterSource: static fn (): float => 0.5), transientFailureClassifier: new TransientFailureClassifier(), sleeper: $fakeSleeper),
        );

        $this->expectException(TransientLLMFailureException::class);
        $this->expectExceptionMessage('LLM call failed after 3 transient retries');

        try {
            $symfonyAiLLMClient->complete('sys', 'usr');
        } finally {
            // Final attempt does not sleep — only retries-before-attempts do.
            self::assertSame([10, 20], $fakeSleeper->durations);
        }
    }

    /**
     * @throws InvalidRetryConfigurationException
     * @throws BudgetExceededException
     * @throws MissingAiPlatformException
     * @throws TransientLLMFailureException
     * @throws NonTransientLLMFailureException
     */
    public function test_complete_logs_warning_with_full_context_when_retrying_transient_failure(): void
    {
        /** @var list<array{string, array<string, mixed>}> $warnings */
        $warnings = [];
        $logger = self::createStub(LoggerInterface::class);
        $logger->method('warning')->willReturnCallback(
            static function (string $msg, array $ctx = []) use (&$warnings): void {
                $warnings[] = [$msg, $ctx];
            },
        );

        $platform = $this->flakyPlatform([
            new RuntimeException('HTTP 503 first failure message'),
            new TextResult('recovered'),
        ]);
        $symfonyAiLLMClient = new SymfonyAiLLMClient(
            new PlatformBinding($platform, 'm', $logger),
            platformResilienceConfig: new PlatformResilienceConfig(retryPolicy: new RetryPolicy(new BackoffSchedule(maxAttempts: 3, initialDelayMs: 50, backoffMultiplier: 2.0, jitterRatio: 0.0), jitterSource: static fn (): float => 0.5), transientFailureClassifier: new TransientFailureClassifier(), sleeper: new FakeSleeper()),
        );

        $symfonyAiLLMClient->complete('sys', 'usr');

        self::assertCount(1, $warnings);
        self::assertSame('LLM call failed, retrying after backoff', $warnings[0][0]);
        $context = $warnings[0][1];
        self::assertSame(1, $context['attempt']);
        self::assertSame(3, $context['max_attempts']);
        self::assertSame(50, $context['delay_ms']);
        self::assertSame('HTTP 503 first failure message', $context['error']);
    }

    /**
     * @throws InvalidRetryConfigurationException
     * @throws BudgetExceededException
     * @throws MissingAiPlatformException
     * @throws NonTransientLLMFailureException
     */
    public function test_complete_logs_one_warning_per_intermediate_attempt_no_warning_on_last(): void
    {
        /** @var list<array{string, array<string, mixed>}> $warnings */
        $warnings = [];
        $logger = self::createStub(LoggerInterface::class);
        $logger->method('warning')->willReturnCallback(
            static function (string $msg, array $ctx = []) use (&$warnings): void {
                $warnings[] = [$msg, $ctx];
            },
        );

        $platform = $this->flakyPlatform([
            new RuntimeException('HTTP 503'),
            new RuntimeException('HTTP 503'),
            new RuntimeException('HTTP 503'),
        ]);
        $symfonyAiLLMClient = new SymfonyAiLLMClient(
            new PlatformBinding($platform, 'm', $logger),
            platformResilienceConfig: new PlatformResilienceConfig(retryPolicy: new RetryPolicy(new BackoffSchedule(maxAttempts: 3, initialDelayMs: 10, backoffMultiplier: 2.0, jitterRatio: 0.0), jitterSource: static fn (): float => 0.5), transientFailureClassifier: new TransientFailureClassifier(), sleeper: new FakeSleeper()),
        );

        try {
            $symfonyAiLLMClient->complete('sys', 'usr');
            self::fail('Expected TransientLLMFailureException');
        } catch (TransientLLMFailureException) {
            self::assertCount(2, $warnings);
            self::assertSame(1, $warnings[0][1]['attempt']);
            self::assertSame(2, $warnings[1][1]['attempt']);
        }
    }

    /**
     * @throws InvalidRetryConfigurationException
     * @throws BudgetExceededException
     * @throws MissingAiPlatformException
     * @throws TransientLLMFailureException
     * @throws NonTransientLLMFailureException
     */
    public function test_complete_does_not_retry_non_transient_failures(): void
    {
        $fakeSleeper = new FakeSleeper();
        $platform = $this->flakyPlatform([
            new RuntimeException('HTTP 401 Unauthorized: invalid api key'),
            new TextResult('should-not-reach'),
        ]);
        $symfonyAiLLMClient = new SymfonyAiLLMClient(
            new PlatformBinding($platform, 'm', new NullLogger()),
            platformResilienceConfig: new PlatformResilienceConfig(retryPolicy: new RetryPolicy(new BackoffSchedule(maxAttempts: 5), jitterSource: static fn (): float => 0.5), transientFailureClassifier: new TransientFailureClassifier(), sleeper: $fakeSleeper),
        );

        $this->expectException(NonTransientLLMFailureException::class);
        $this->expectExceptionMessage('LLM call failed with non-transient error');

        try {
            $symfonyAiLLMClient->complete('sys', 'usr');
        } finally {
            self::assertSame([], $fakeSleeper->durations);
        }
    }

    /**
     * @throws InvalidRetryConfigurationException
     * @throws BudgetExceededException
     * @throws MissingAiPlatformException
     * @throws TransientLLMFailureException
     * @throws NonTransientLLMFailureException
     */
    public function test_complete_returns_empty_response_when_platform_reports_empty_content(): void
    {
        $fakeSleeper = new FakeSleeper();
        $platform = $this->emptyContentPlatform('Response does not contain any content.');
        $symfonyAiLLMClient = new SymfonyAiLLMClient(
            new PlatformBinding($platform, 'm', new NullLogger()),
            platformResilienceConfig: new PlatformResilienceConfig(retryPolicy: new RetryPolicy(new BackoffSchedule(maxAttempts: 5), jitterSource: static fn (): float => 0.5), transientFailureClassifier: new TransientFailureClassifier(), sleeper: $fakeSleeper),
        );

        $llmResponse = $symfonyAiLLMClient->complete('sys', 'usr');

        self::assertSame('', $llmResponse->content());
        self::assertSame('empty_content', $llmResponse->stopReason());
        self::assertTrue($llmResponse->isEmpty());
        self::assertSame(0, $llmResponse->inputTokens());
        self::assertSame(0, $llmResponse->outputTokens());
        self::assertSame([], $fakeSleeper->durations);
    }

    /**
     * @throws BudgetExceededException
     * @throws MissingAiPlatformException
     * @throws TransientLLMFailureException
     * @throws NonTransientLLMFailureException
     */
    public function test_complete_logs_warning_when_platform_reports_empty_content(): void
    {
        /** @var list<array{string, array<string, mixed>}> $warnings */
        $warnings = [];
        $logger = self::createStub(LoggerInterface::class);
        $logger->method('warning')->willReturnCallback(
            static function (string $msg, array $ctx = []) use (&$warnings): void {
                $warnings[] = [$msg, $ctx];
            },
        );

        $symfonyAiLLMClient = new SymfonyAiLLMClient(
            new PlatformBinding($this->emptyContentPlatform('Response does not contain any content.'), 'm', $logger),
            platformResilienceConfig: new PlatformResilienceConfig(transientFailureClassifier: new TransientFailureClassifier()),
        );

        $symfonyAiLLMClient->complete('sys', 'usr');

        $emptyLogs = array_values(array_filter(
            $warnings,
            static fn (array $entry): bool => 'LLM returned a response with no content blocks' === $entry[0],
        ));
        self::assertCount(1, $emptyLogs);
        self::assertSame(
            'LLM returned a response with no content: Response does not contain any content.',
            $emptyLogs[0][1]['error'],
        );
    }

    /**
     * @throws BudgetExceededException
     * @throws MissingAiPlatformException
     * @throws TransientLLMFailureException
     * @throws NonTransientLLMFailureException
     */
    public function test_complete_with_tools_returns_empty_response_when_platform_reports_empty_content_on_first_iteration(): void
    {
        $tool = $this->makeTool('lookup', 'lookup');
        $toolRegistry = new ToolRegistry([$tool], new NullLogger());

        $symfonyAiLLMClient = new SymfonyAiLLMClient(
            new PlatformBinding($this->emptyContentPlatform('Response does not contain any content.'), 'm', new NullLogger()),
            platformResilienceConfig: new PlatformResilienceConfig(transientFailureClassifier: new TransientFailureClassifier()),
        );

        $llmResponse = $symfonyAiLLMClient->completeWithTools('sys', 'usr', $toolRegistry, 5);

        self::assertSame('', $llmResponse->content());
        self::assertSame('empty_content', $llmResponse->stopReason());
        self::assertSame(0, $llmResponse->inputTokens());
        self::assertSame(0, $llmResponse->outputTokens());
    }

    /**
     * @throws BudgetExceededException
     * @throws MissingAiPlatformException
     * @throws TransientLLMFailureException
     * @throws NonTransientLLMFailureException
     */
    public function test_complete_with_tools_logs_warning_when_platform_reports_empty_content(): void
    {
        $tool = $this->makeTool('lookup', 'lookup');
        $toolRegistry = new ToolRegistry([$tool], new NullLogger());

        /** @var list<array{string, array<string, mixed>}> $warnings */
        $warnings = [];
        $logger = self::createStub(LoggerInterface::class);
        $logger->method('warning')->willReturnCallback(
            static function (string $msg, array $ctx = []) use (&$warnings): void {
                $warnings[] = [$msg, $ctx];
            },
        );

        $symfonyAiLLMClient = new SymfonyAiLLMClient(
            new PlatformBinding($this->emptyContentPlatform('Response does not contain any content.'), 'm', $logger),
            platformResilienceConfig: new PlatformResilienceConfig(transientFailureClassifier: new TransientFailureClassifier()),
        );

        $symfonyAiLLMClient->completeWithTools('sys', 'usr', $toolRegistry, 5);

        $emptyLogs = array_values(array_filter(
            $warnings,
            static fn (array $entry): bool => 'Tool-using loop ended with empty content response' === $entry[0],
        ));
        self::assertCount(1, $emptyLogs);
        self::assertSame(0, $emptyLogs[0][1]['iterations']);
        self::assertSame(
            'LLM returned a response with no content: Response does not contain any content.',
            $emptyLogs[0][1]['error'],
        );
    }

    /**
     * @throws BudgetExceededException
     * @throws MissingAiPlatformException
     * @throws TransientLLMFailureException
     * @throws NonTransientLLMFailureException
     */
    public function test_complete_with_tools_demotes_empty_content_to_debug_after_at_least_one_tool_iteration(): void
    {
        $tool = $this->makeTool('lookup', 'lookup');
        $toolRegistry = new ToolRegistry([$tool], new NullLogger());

        /** @var list<array{string, array<string, mixed>}> $warnings */
        $warnings = [];
        /** @var list<array{string, array<string, mixed>}> $debugs */
        $debugs = [];
        $logger = self::createStub(LoggerInterface::class);
        $logger->method('warning')->willReturnCallback(
            static function (string $msg, array $ctx = []) use (&$warnings): void {
                $warnings[] = [$msg, $ctx];
            },
        );
        $logger->method('debug')->willReturnCallback(
            static function (string $msg, array $ctx = []) use (&$debugs): void {
                $debugs[] = [$msg, $ctx];
            },
        );

        $platform = $this->lazilyFailingPlatform([
            new MultiPartResult([new ToolCallResult([new ToolCall('1', 'lookup')])]),
            new RuntimeException('Response does not contain any content.'),
        ]);

        $symfonyAiLLMClient = new SymfonyAiLLMClient(
            new PlatformBinding($platform, 'm', $logger),
            platformResilienceConfig: new PlatformResilienceConfig(transientFailureClassifier: new TransientFailureClassifier()),
        );

        $symfonyAiLLMClient->completeWithTools('sys', 'usr', $toolRegistry, 5);

        $matchesMessage = static fn (array $entry): bool => 'Tool-using loop ended with empty content response' === $entry[0];

        self::assertCount(0, array_filter($warnings, $matchesMessage));
        $emptyDebugs = array_values(array_filter($debugs, $matchesMessage));
        self::assertCount(1, $emptyDebugs);
        self::assertSame(1, $emptyDebugs[0][1]['iterations']);
    }

    /**
     * @throws InvalidRetryConfigurationException
     * @throws BudgetExceededException
     * @throws MissingAiPlatformException
     * @throws TransientLLMFailureException
     * @throws NonTransientLLMFailureException
     */
    public function test_complete_does_not_retry_empty_content_failures(): void
    {
        $fakeSleeper = new FakeSleeper();
        $platformInvocationLog = new PlatformInvocationLog();
        $platform = $this->emptyContentPlatform('Response does not contain any content.', $platformInvocationLog);
        $symfonyAiLLMClient = new SymfonyAiLLMClient(
            new PlatformBinding($platform, 'm', new NullLogger()),
            platformResilienceConfig: new PlatformResilienceConfig(retryPolicy: new RetryPolicy(new BackoffSchedule(maxAttempts: 5), jitterSource: static fn (): float => 0.5), transientFailureClassifier: new TransientFailureClassifier(), sleeper: $fakeSleeper),
        );

        $symfonyAiLLMClient->complete('sys', 'usr');

        self::assertSame(1, $platformInvocationLog->invocations);
        self::assertSame([], $fakeSleeper->durations);
    }

    /**
     * @throws InvalidRetryConfigurationException
     * @throws BudgetExceededException
     * @throws MissingAiPlatformException
     * @throws TransientLLMFailureException
     * @throws NonTransientLLMFailureException
     */
    public function test_complete_uses_rate_limit_delay_for_429_errors(): void
    {
        $fakeSleeper = new FakeSleeper();
        $platform = $this->flakyPlatform([
            new RuntimeException('HTTP 429 Rate limit exceeded'),
            new TextResult('recovered after rate limit'),
        ]);
        $symfonyAiLLMClient = new SymfonyAiLLMClient(
            new PlatformBinding($platform, 'm', new NullLogger()),
            platformResilienceConfig: new PlatformResilienceConfig(retryPolicy: new RetryPolicy(new BackoffSchedule(maxAttempts: 3, initialDelayMs: 500, jitterRatio: 0.0), new RateLimitBackoff(initialDelayMs: 60_000), jitterSource: static fn (): float => 0.5), transientFailureClassifier: new TransientFailureClassifier(), sleeper: $fakeSleeper),
        );

        $symfonyAiLLMClient->complete('sys', 'usr');

        self::assertSame([60_000], $fakeSleeper->durations);
    }

    /**
     * @throws InvalidRetryConfigurationException
     * @throws BudgetExceededException
     * @throws MissingAiPlatformException
     * @throws TransientLLMFailureException
     * @throws NonTransientLLMFailureException
     */
    public function test_complete_uses_regular_delay_for_non_rate_limit_transient_errors(): void
    {
        $fakeSleeper = new FakeSleeper();
        $platform = $this->flakyPlatform([
            new RuntimeException('HTTP 503 Service Unavailable'),
            new TextResult('recovered'),
        ]);
        $symfonyAiLLMClient = new SymfonyAiLLMClient(
            new PlatformBinding($platform, 'm', new NullLogger()),
            platformResilienceConfig: new PlatformResilienceConfig(retryPolicy: new RetryPolicy(new BackoffSchedule(maxAttempts: 3, initialDelayMs: 500, jitterRatio: 0.0), new RateLimitBackoff(initialDelayMs: 60_000), jitterSource: static fn (): float => 0.5), transientFailureClassifier: new TransientFailureClassifier(), sleeper: $fakeSleeper),
        );

        $symfonyAiLLMClient->complete('sys', 'usr');

        self::assertSame([500], $fakeSleeper->durations);
    }

    /**
     * @throws InvalidRetryConfigurationException
     * @throws BudgetExceededException
     * @throws MissingAiPlatformException
     * @throws TransientLLMFailureException
     * @throws NonTransientLLMFailureException
     */
    public function test_non_rate_limit_transient_error_never_pauses_the_rate_limiter(): void
    {
        $fakeRateLimiter = new FakeRateLimiter();
        $platform = $this->flakyPlatform([
            new RuntimeException('HTTP 503 Service Unavailable retry-after: 30'),
            new TextResult('recovered'),
        ]);
        $symfonyAiLLMClient = new SymfonyAiLLMClient(
            new PlatformBinding($platform, 'm', new NullLogger()),
            platformResilienceConfig: new PlatformResilienceConfig(retryPolicy: new RetryPolicy(new BackoffSchedule(maxAttempts: 3, initialDelayMs: 500, jitterRatio: 0.0), new RateLimitBackoff(initialDelayMs: 60_000), jitterSource: static fn (): float => 0.5), transientFailureClassifier: new TransientFailureClassifier(), sleeper: new FakeSleeper(), rateLimiter: $fakeRateLimiter),
        );

        $symfonyAiLLMClient->complete('sys', 'usr');

        self::assertSame([], $fakeRateLimiter->paused, 'A non-429 transient failure must not honor a Retry-After hint.');
    }

    /**
     * @throws InvalidRetryConfigurationException
     * @throws BudgetExceededException
     * @throws MissingAiPlatformException
     * @throws TransientLLMFailureException
     * @throws NonTransientLLMFailureException
     */
    public function test_eager_resolution_catches_transient_failure_thrown_from_deferred_result(): void
    {
        $fakeSleeper = new FakeSleeper();
        $platform = $this->lazilyFailingPlatform([
            new RuntimeException('HTTP 503 Service Unavailable'),
            new TextResult('recovered after lazy 503'),
        ]);
        $symfonyAiLLMClient = new SymfonyAiLLMClient(
            new PlatformBinding($platform, 'm', new NullLogger()),
            platformResilienceConfig: new PlatformResilienceConfig(retryPolicy: new RetryPolicy(new BackoffSchedule(maxAttempts: 3, initialDelayMs: 10, jitterRatio: 0.0), jitterSource: static fn (): float => 0.5), transientFailureClassifier: new TransientFailureClassifier(), sleeper: $fakeSleeper),
        );

        $llmResponse = $symfonyAiLLMClient->complete('sys', 'usr');

        self::assertSame('recovered after lazy 503', $llmResponse->content());
        self::assertSame([10], $fakeSleeper->durations);
    }

    /**
     * @throws BudgetExceededException
     * @throws MissingAiPlatformException
     * @throws TransientLLMFailureException
     * @throws NonTransientLLMFailureException
     */
    public function test_acquire_runs_before_invoke_with_estimated_input_tokens(): void
    {
        $fakeRateLimiter = new FakeRateLimiter();
        $platform = $this->scriptedPlatform([new TextResult('ok')]);
        $symfonyAiLLMClient = new SymfonyAiLLMClient(
            new PlatformBinding($platform, 'm', new NullLogger()),
            new PlatformRequestConfig(tokenEstimator: new FixedTokenEstimator(123)),
            new PlatformResilienceConfig(rateLimiter: $fakeRateLimiter),
        );

        $symfonyAiLLMClient->complete('sys', 'usr');

        self::assertSame([246], $fakeRateLimiter->acquired, 'system + user prompts → 2 × 123 = 246');
    }

    /**
     * @throws BudgetExceededException
     * @throws MissingAiPlatformException
     * @throws TransientLLMFailureException
     * @throws NonTransientLLMFailureException
     */
    public function test_record_runs_after_success_with_actual_tokens(): void
    {
        $fakeRateLimiter = new FakeRateLimiter();
        $platform = $this->scriptedPlatformWithTokenUsage(
            new TextResult('ok'),
            new TokenUsage(promptTokens: 250, completionTokens: 75),
        );
        $symfonyAiLLMClient = new SymfonyAiLLMClient(
            new PlatformBinding($platform, 'm', new NullLogger()),
            platformResilienceConfig: new PlatformResilienceConfig(rateLimiter: $fakeRateLimiter),
        );

        $symfonyAiLLMClient->complete('sys', 'usr');

        self::assertSame([[250, 75]], $fakeRateLimiter->recorded);
    }

    /**
     * @throws BudgetExceededException
     * @throws MissingAiPlatformException
     * @throws TransientLLMFailureException
     * @throws NonTransientLLMFailureException
     */
    public function test_complete_with_tools_records_actual_tokens_after_each_iteration(): void
    {
        $fakeRateLimiter = new FakeRateLimiter();
        $tool = $this->makeTool('echo', 'echo', static fn (): string => 'echoed');
        $toolRegistry = new ToolRegistry([$tool], new NullLogger());

        $platform = $this->scriptedPlatformWithTokenUsage(
            results: [
                new MultiPartResult([new ToolCallResult([new ToolCall('call-1', 'echo', [])])]),
                new MultiPartResult([new TextResult('finished')]),
            ],
            tokenUsages: [
                new TokenUsage(promptTokens: 40, completionTokens: 10),
                new TokenUsage(promptTokens: 60, completionTokens: 5),
            ],
        );
        $symfonyAiLLMClient = new SymfonyAiLLMClient(
            new PlatformBinding($platform, 'm', new NullLogger()),
            platformResilienceConfig: new PlatformResilienceConfig(rateLimiter: $fakeRateLimiter),
        );

        $symfonyAiLLMClient->completeWithTools('sys', 'usr', $toolRegistry, 5);

        self::assertSame([[40, 10], [60, 5]], $fakeRateLimiter->recorded);
    }

    /**
     * @throws InvalidRetryConfigurationException
     * @throws BudgetExceededException
     * @throws MissingAiPlatformException
     * @throws TransientLLMFailureException
     * @throws NonTransientLLMFailureException
     */
    public function test_429_with_retry_after_uses_server_hint_and_pauses_rate_limiter(): void
    {
        $fakeSleeper = new FakeSleeper();
        $fakeRateLimiter = new FakeRateLimiter();
        $platform = $this->flakyPlatform([
            new RateLimitExceededException(retryAfter: 7),
            new TextResult('recovered'),
        ]);
        $symfonyAiLLMClient = new SymfonyAiLLMClient(
            new PlatformBinding($platform, 'm', new NullLogger()),
            platformResilienceConfig: new PlatformResilienceConfig(retryPolicy: new RetryPolicy(new BackoffSchedule(maxAttempts: 3, jitterRatio: 0.0), new RateLimitBackoff(initialDelayMs: 60_000), jitterSource: static fn (): float => 0.5), transientFailureClassifier: new TransientFailureClassifier(), sleeper: $fakeSleeper, rateLimiter: $fakeRateLimiter),
        );

        $symfonyAiLLMClient->complete('sys', 'usr');

        self::assertSame([7_000], $fakeSleeper->durations, 'must honor server-provided 7s, not the default 60s');
        self::assertCount(1, $fakeRateLimiter->paused);
    }

    /**
     * @throws InvalidRetryConfigurationException
     * @throws BudgetExceededException
     * @throws MissingAiPlatformException
     * @throws TransientLLMFailureException
     * @throws NonTransientLLMFailureException
     */
    public function test_429_without_retry_after_falls_back_to_exponential_delay(): void
    {
        $fakeSleeper = new FakeSleeper();
        $fakeRateLimiter = new FakeRateLimiter();
        $platform = $this->flakyPlatform([
            new RateLimitExceededException(),
            new TextResult('recovered'),
        ]);
        $symfonyAiLLMClient = new SymfonyAiLLMClient(
            new PlatformBinding($platform, 'm', new NullLogger()),
            platformResilienceConfig: new PlatformResilienceConfig(retryPolicy: new RetryPolicy(new BackoffSchedule(maxAttempts: 3, jitterRatio: 0.0), new RateLimitBackoff(initialDelayMs: 60_000), jitterSource: static fn (): float => 0.5), transientFailureClassifier: new TransientFailureClassifier(), sleeper: $fakeSleeper, rateLimiter: $fakeRateLimiter),
        );

        $symfonyAiLLMClient->complete('sys', 'usr');

        self::assertSame([60_000], $fakeSleeper->durations);
        self::assertSame([], $fakeRateLimiter->paused, 'no server hint means no pauseUntil call');
    }

    /**
     * @param list<ResultInterface|RuntimeException> $scriptedResultsOrErrors
     */
    private function lazilyFailingPlatform(array $scriptedResultsOrErrors): PlatformInterface
    {
        return new class($scriptedResultsOrErrors) implements PlatformInterface {
            /** @var list<ResultInterface|RuntimeException> */
            private array $remaining;

            /** @param list<ResultInterface|RuntimeException> $scriptedResultsOrErrors */
            public function __construct(array $scriptedResultsOrErrors)
            {
                $this->remaining = $scriptedResultsOrErrors;
            }

            #[Override]
            public function invoke(Model|string $model, array|string|object $input, array $options = []): DeferredResult
            {
                $next = array_shift($this->remaining);
                if (null === $next) {
                    throw new RuntimeException('lazilyFailingPlatform invoked more times than scripted — invokeWithRetry never returned (a mutation removed a loop-exit branch).');
                }

                $converter = $next instanceof RuntimeException
                    ? new ThrowingConverter($next)
                    : new PlainConverter($next);

                return new DeferredResult(
                    $converter,
                    new InMemoryRawResult(['text' => ''], [], (object) []),
                    $options,
                );
            }

            #[Override]
            public function getModelCatalog(): ModelCatalogInterface
            {
                return new FallbackModelCatalog();
            }
        };
    }

    private function emptyContentPlatform(string $message, ?PlatformInvocationLog $platformInvocationLog = null): PlatformInterface
    {
        return new class($message, $platformInvocationLog) implements PlatformInterface {
            public function __construct(
                private readonly string $message,
                private readonly ?PlatformInvocationLog $platformInvocationLog,
            ) {}

            #[Override]
            public function invoke(Model|string $model, array|string|object $input, array $options = []): DeferredResult
            {
                if ($this->platformInvocationLog instanceof PlatformInvocationLog) {
                    ++$this->platformInvocationLog->invocations;
                }

                return new DeferredResult(
                    new ThrowingConverter(new RuntimeException($this->message)),
                    new InMemoryRawResult(['text' => ''], [], (object) []),
                    $options,
                );
            }

            #[Override]
            public function getModelCatalog(): ModelCatalogInterface
            {
                return new FallbackModelCatalog();
            }
        };
    }

    /**
     * @param list<ResultInterface|RuntimeException> $scriptedResultsOrErrors
     */
    private function flakyPlatform(array $scriptedResultsOrErrors): PlatformInterface
    {
        return new class($scriptedResultsOrErrors) implements PlatformInterface {
            /** @var list<ResultInterface|RuntimeException> */
            private array $remaining;

            /** @param list<ResultInterface|RuntimeException> $scriptedResultsOrErrors */
            public function __construct(array $scriptedResultsOrErrors)
            {
                $this->remaining = $scriptedResultsOrErrors;
            }

            #[Override]
            public function invoke(Model|string $model, array|string|object $input, array $options = []): DeferredResult
            {
                $next = array_shift($this->remaining);
                if ($next instanceof RuntimeException) {
                    throw $next;
                }

                if (!$next instanceof ResultInterface) {
                    throw new RuntimeException('flakyPlatform invoked more times than scripted — invokeWithRetry never returned (a mutation removed a loop-exit branch).');
                }

                $result = $next;

                return new DeferredResult(
                    new PlainConverter($result),
                    new InMemoryRawResult(['text' => ''], [], (object) []),
                    $options,
                );
            }

            #[Override]
            public function getModelCatalog(): ModelCatalogInterface
            {
                return new FallbackModelCatalog();
            }
        };
    }

    /**
     * @param list<ResultInterface> $scriptedResults
     */
    private function scriptedPlatform(array $scriptedResults, ?PlatformInvocationLog $platformInvocationLog = null): PlatformInterface
    {
        return new class($scriptedResults, $platformInvocationLog) implements PlatformInterface {
            /** @var list<ResultInterface> */
            private array $remaining;

            /**
             * @param list<ResultInterface> $scriptedResults
             */
            public function __construct(
                array $scriptedResults,
                private readonly ?PlatformInvocationLog $platformInvocationLog,
            ) {
                $this->remaining = $scriptedResults;
            }

            #[Override]
            public function invoke(Model|string $model, array|string|object $input, array $options = []): DeferredResult
            {
                if ($this->platformInvocationLog instanceof PlatformInvocationLog) {
                    ++$this->platformInvocationLog->invocations;
                    if ($input instanceof MessageBag) {
                        $this->platformInvocationLog->messageSnapshots[] = $input->getMessages();
                    }
                }

                $result = array_shift($this->remaining);
                if (!$result instanceof ResultInterface) {
                    throw new RuntimeException('scriptedPlatform invoked more times than scripted — invokeWithRetry never returned (a mutation removed a loop-exit branch).');
                }

                return new DeferredResult(
                    new PlainConverter($result),
                    new InMemoryRawResult(['text' => ''], [], (object) []),
                    $options,
                );
            }

            #[Override]
            public function getModelCatalog(): ModelCatalogInterface
            {
                return new FallbackModelCatalog();
            }
        };
    }

    private function scriptedPlatformCapturingOptions(
        ResultInterface $result,
        InvocationOptionsCapture $invocationOptionsCapture,
    ): PlatformInterface {
        return new class($result, $invocationOptionsCapture) implements PlatformInterface {
            private int $invocations = 0;

            public function __construct(
                private readonly ResultInterface $result,
                private readonly InvocationOptionsCapture $invocationOptionsCapture,
            ) {}

            #[Override]
            public function invoke(Model|string $model, array|string|object $input, array $options = []): DeferredResult
            {
                if (++$this->invocations > 1) {
                    throw new RuntimeException('scriptedPlatformCapturingOptions invoked more than once — invokeWithRetry never returned (a mutation removed a loop-exit branch).');
                }

                $this->invocationOptionsCapture->options ??= $options;

                return new DeferredResult(
                    new PlainConverter($this->result),
                    new InMemoryRawResult(['text' => ''], [], (object) []),
                    $options,
                );
            }

            #[Override]
            public function getModelCatalog(): ModelCatalogInterface
            {
                return new FallbackModelCatalog();
            }
        };
    }

    /**
     * @param ?Closure(array<string, mixed>): string $executor
     * @param array<string, mixed>                   $parametersSchema
     */
    private function makeTool(
        string $name,
        string $description,
        ?Closure $executor = null,
        array $parametersSchema = ['type' => 'object', 'properties' => [], 'required' => []],
    ): ToolInterface {
        return new class($name, $description, $executor, $parametersSchema) implements ToolInterface {
            /**
             * @param ?Closure(array<string, mixed>): string $executor
             * @param array<string, mixed>                   $parametersSchema
             */
            public function __construct(
                private readonly string $name,
                private readonly string $description,
                private readonly ?Closure $executor,
                private readonly array $parametersSchema,
            ) {}

            #[Override]
            public function definition(): ToolDefinition
            {
                return new ToolDefinition($this->name, $this->description, $this->parametersSchema);
            }

            #[Override]
            public function execute(array $arguments): string
            {
                return $this->executor instanceof Closure ? ($this->executor)($arguments) : 'ok';
            }
        };
    }
}
