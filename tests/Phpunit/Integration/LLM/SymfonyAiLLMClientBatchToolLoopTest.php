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
use Symfony\AI\Platform\Message\AssistantMessage;
use Symfony\AI\Platform\Message\SystemMessage;
use Symfony\AI\Platform\Message\ToolCallMessage;
use Symfony\AI\Platform\Message\UserMessage;
use Symfony\AI\Platform\Model;
use Symfony\AI\Platform\ModelCatalog\FallbackModelCatalog;
use Symfony\AI\Platform\ModelCatalog\ModelCatalogInterface;
use Symfony\AI\Platform\PlainConverter;
use Symfony\AI\Platform\PlatformInterface;
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
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Budget\BudgetTracker;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Budget\CostCalculator;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Budget\Exception\BudgetExceededException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Exception\NegativeTokenCountException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Telemetry\TokenUsageRecorder;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidAuditBudgetException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidTokenUsageException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidToolRegistryException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\AuditBudget;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\PricingProviderInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\RateLimiterInterface;
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
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\RetryPolicy;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\SymfonyAiLLMClient;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\TransientFailureClassifier;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Integration\LLM\Fixture\CallbackTool;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Integration\LLM\Fixture\FakeRateLimiter;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Integration\LLM\Fixture\FakeSleeper;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Integration\LLM\Fixture\FixedPricingProvider;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Integration\LLM\Fixture\FixedTokenEstimator;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Integration\LLM\Fixture\FlakyPlatform;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Integration\LLM\Fixture\MessageCollectingLogger;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Integration\LLM\Fixture\PlatformInvocationLog;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Integration\LLM\Fixture\ScriptedPlatform;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Integration\LLM\Fixture\ScriptedTokenUsagePlatform;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Integration\LLM\Fixture\ThrowingConverter;

final class SymfonyAiLLMClientBatchToolLoopTest extends TestCase
{
    /**
     * @throws MissingAiPlatformException
     * @throws BudgetExceededException
     * @throws InvalidToolRegistryException
     * @throws InvalidTokenUsageException
     * @throws NonTransientLLMFailureException
     * @throws NegativeTokenCountException
     * @throws InvalidRetryConfigurationException
     * @throws TransientLLMFailureException
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
     * @throws InvalidTokenUsageException
     * @throws NonTransientLLMFailureException
     * @throws NegativeTokenCountException
     * @throws InvalidRetryConfigurationException
     * @throws TransientLLMFailureException
     */
    public function test_complete_batch_with_tools_returns_empty_list_for_empty_requests(): void
    {
        $symfonyAiLLMClient = new SymfonyAiLLMClient(new PlatformBinding(new InMemoryPlatform('ok'), 'm', new NullLogger()));

        self::assertSame([], $symfonyAiLLMClient->completeBatchWithTools([], 4, 3));
    }

    /**
     * @throws MissingAiPlatformException
     * @throws BudgetExceededException
     * @throws InvalidTokenUsageException
     * @throws NonTransientLLMFailureException
     * @throws InvalidToolRegistryException
     * @throws NegativeTokenCountException
     * @throws InvalidRetryConfigurationException
     * @throws TransientLLMFailureException
     */
    public function test_complete_batch_with_tools_grows_the_rate_limiter_estimate_as_tool_results_accumulate_in_the_conversation(): void
    {
        $tool = $this->makeTool('lookup', 'looks things up', static fn (array $args): string => 'tool-result');
        $toolRegistry = new ToolRegistry([$tool], new NullLogger());

        $platform = $this->scriptedPlatform([
            new MultiPartResult([new ToolCallResult([new ToolCall('call-1', 'lookup', ['q' => 'test'])])]),
            new MultiPartResult([new TextResult('final answer')]),
        ]);

        $fakeRateLimiter = new FakeRateLimiter();
        $symfonyAiLLMClient = new SymfonyAiLLMClient(
            new PlatformBinding($platform, 'm', new NullLogger()),
            new PlatformRequestConfig(tokenEstimator: new FixedTokenEstimator(10)),
            new PlatformResilienceConfig(rateLimiter: $fakeRateLimiter),
        );

        $symfonyAiLLMClient->completeBatchWithTools([
            ['system' => 'sys', 'user' => 'usr', 'tools' => $toolRegistry],
        ], 1, 5);

        self::assertSame([20, 30], $fakeRateLimiter->acquired);
    }

    /**
     * @throws MissingAiPlatformException
     * @throws BudgetExceededException
     * @throws InvalidToolRegistryException
     * @throws InvalidTokenUsageException
     * @throws NonTransientLLMFailureException
     * @throws NegativeTokenCountException
     * @throws InvalidRetryConfigurationException
     * @throws TransientLLMFailureException
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
     * @throws MissingAiPlatformException
     * @throws BudgetExceededException
     * @throws InvalidToolRegistryException
     * @throws InvalidTokenUsageException
     * @throws NonTransientLLMFailureException
     * @throws NegativeTokenCountException
     * @throws InvalidRetryConfigurationException
     * @throws TransientLLMFailureException
     */
    public function test_complete_batch_with_tools_sends_each_prompt_under_its_own_role(): void
    {
        $toolRegistry = new ToolRegistry([$this->makeTool('record', 'd')], new NullLogger());
        $platformInvocationLog = new PlatformInvocationLog();
        $platform = $this->scriptedPlatform([new TextResult('ok')], $platformInvocationLog);

        $symfonyAiLLMClient = new SymfonyAiLLMClient(new PlatformBinding($platform, 'm', new NullLogger()));

        $symfonyAiLLMClient->completeBatchWithTools([
            ['system' => 'sys-prompt', 'user' => 'usr-prompt', 'tools' => $toolRegistry],
        ], 4, 2);

        $messages = $platformInvocationLog->messageSnapshots[0];
        self::assertInstanceOf(SystemMessage::class, $messages[0]);
        self::assertSame('sys-prompt', $messages[0]->getContent());
        self::assertInstanceOf(UserMessage::class, $messages[1]);
    }

    /**
     * @throws MissingAiPlatformException
     * @throws BudgetExceededException
     * @throws InvalidToolRegistryException
     * @throws InvalidTokenUsageException
     * @throws NonTransientLLMFailureException
     * @throws NegativeTokenCountException
     * @throws InvalidRetryConfigurationException
     * @throws TransientLLMFailureException
     */
    public function test_complete_batch_with_tools_reports_tokens_accumulated_across_rounds_when_capping(): void
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

        $platform = $this->scriptedPlatformWithTokenUsage(
            [
                new MultiPartResult([new ToolCallResult([new ToolCall('1', 'record')])]),
                new MultiPartResult([new ToolCallResult([new ToolCall('2', 'record')])]),
            ],
            [
                new TokenUsage(promptTokens: 7, completionTokens: 3),
                new TokenUsage(promptTokens: 11, completionTokens: 5),
            ],
        );

        $symfonyAiLLMClient = new SymfonyAiLLMClient(new PlatformBinding($platform, 'm', $logger));

        $symfonyAiLLMClient->completeBatchWithTools([
            ['system' => 's', 'user' => 'u', 'tools' => $toolRegistry],
        ], 4, 2);

        $capContexts = array_values(array_map(
            static fn (array $entry): array => $entry[1],
            array_filter($warnings, static fn (array $entry): bool => 'Tool-using loop hit iteration cap' === $entry[0]),
        ));
        self::assertSame([['max_iterations' => 2, 'input_tokens' => 18, 'output_tokens' => 8]], $capContexts);
    }

    /**
     * @throws InvalidRetryConfigurationException
     * @throws MissingAiPlatformException
     * @throws BudgetExceededException
     * @throws InvalidToolRegistryException
     * @throws InvalidTokenUsageException
     * @throws NonTransientLLMFailureException
     * @throws NegativeTokenCountException
     * @throws TransientLLMFailureException
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
     * @throws InvalidToolRegistryException
     * @throws InvalidTokenUsageException
     * @throws NonTransientLLMFailureException
     * @throws NegativeTokenCountException
     * @throws TransientLLMFailureException
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
     * @throws InvalidToolRegistryException
     * @throws InvalidTokenUsageException
     * @throws NonTransientLLMFailureException
     * @throws NegativeTokenCountException
     * @throws TransientLLMFailureException
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
     * @throws InvalidToolRegistryException
     * @throws InvalidTokenUsageException
     * @throws NonTransientLLMFailureException
     * @throws NegativeTokenCountException
     * @throws InvalidRetryConfigurationException
     * @throws TransientLLMFailureException
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
     * A dispatch whose token extraction fails must release its own
     * reservation as `[0, 0]` — not the poisoned value that failed to
     * extract — and the fallback conversation's own reservation must still
     * be recorded correctly and independently alongside it.
     *
     * @throws MissingAiPlatformException
     * @throws BudgetExceededException
     * @throws InvalidToolRegistryException
     * @throws InvalidTokenUsageException
     * @throws NonTransientLLMFailureException
     * @throws NegativeTokenCountException
     * @throws InvalidRetryConfigurationException
     * @throws TransientLLMFailureException
     */
    public function test_complete_batch_with_tools_releases_a_clean_reservation_when_extraction_fails_then_records_the_fallbacks_reservation_independently(): void
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
        self::assertSame([[0, 0], [5, 2]], $fakeRateLimiter->recorded);
    }

    /**
     * @throws MissingAiPlatformException
     * @throws BudgetExceededException
     * @throws InvalidToolRegistryException
     * @throws InvalidTokenUsageException
     * @throws NonTransientLLMFailureException
     * @throws NegativeTokenCountException
     * @throws InvalidRetryConfigurationException
     * @throws TransientLLMFailureException
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
     * @throws InvalidRetryConfigurationException
     * @throws MissingAiPlatformException
     * @throws BudgetExceededException
     * @throws InvalidToolRegistryException
     * @throws InvalidTokenUsageException
     * @throws NonTransientLLMFailureException
     * @throws NegativeTokenCountException
     * @throws TransientLLMFailureException
     */
    public function test_complete_batch_with_tools_aborts_like_the_sequential_path_when_the_retry_after_a_tool_ran_is_exhausted(): void
    {
        $toolCalls = 0;
        $toolRegistry = new ToolRegistry([$this->makeTool('record', 'd', static function (array $arguments) use (&$toolCalls): string {
            ++$toolCalls;

            return 'ok';
        })], new NullLogger());

        $platform = $this->flakyPlatform([
            new MultiPartResult([new ToolCallResult([new ToolCall('1', 'record')])]),
            new RuntimeException('HTTP 503 Service Unavailable'),
            new RuntimeException('HTTP 503 Service Unavailable'),
        ]);

        $symfonyAiLLMClient = new SymfonyAiLLMClient(
            new PlatformBinding($platform, 'm', new NullLogger()),
            platformResilienceConfig: new PlatformResilienceConfig(retryPolicy: new RetryPolicy(new BackoffSchedule(maxAttempts: 1))),
        );

        $caught = null;
        try {
            $symfonyAiLLMClient->completeBatchWithTools([
                ['system' => 's', 'user' => 'u', 'tools' => $toolRegistry],
            ], 4, 3);
        } catch (TransientLLMFailureException $transientllmFailureException) {
            $caught = $transientllmFailureException;
        }

        self::assertInstanceOf(TransientLLMFailureException::class, $caught);
        self::assertSame('LLM call failed after 2 attempts: HTTP 503 Service Unavailable', $caught->getMessage());
        self::assertSame(1, $toolCalls);
    }

    /**
     * @throws MissingAiPlatformException
     * @throws BudgetExceededException
     * @throws InvalidToolRegistryException
     * @throws InvalidTokenUsageException
     * @throws NonTransientLLMFailureException
     * @throws NegativeTokenCountException
     * @throws InvalidRetryConfigurationException
     * @throws TransientLLMFailureException
     */
    public function test_complete_batch_with_tools_rethrows_a_non_transient_failure_instead_of_finalizing_as_empty_content_after_tools_ran(): void
    {
        $toolCalls = 0;
        $toolRegistry = new ToolRegistry([$this->makeTool('record', 'd', static function (array $arguments) use (&$toolCalls): string {
            ++$toolCalls;

            return 'ok';
        })], new NullLogger());

        $platform = $this->flakyPlatform([
            new MultiPartResult([new ToolCallResult([new ToolCall('1', 'record')])]),
            new RuntimeException('dispatch blip'),
            new RuntimeException('HTTP 401 Unauthorized'),
        ]);

        $symfonyAiLLMClient = new SymfonyAiLLMClient(new PlatformBinding($platform, 'm', new NullLogger()));

        $this->expectException(NonTransientLLMFailureException::class);

        $symfonyAiLLMClient->completeBatchWithTools([
            ['system' => 's', 'user' => 'u', 'tools' => $toolRegistry],
        ], 4, 3);
    }

    /**
     * @throws InvalidRetryConfigurationException
     * @throws MissingAiPlatformException
     * @throws BudgetExceededException
     * @throws InvalidToolRegistryException
     * @throws InvalidTokenUsageException
     * @throws NonTransientLLMFailureException
     * @throws NegativeTokenCountException
     * @throws TransientLLMFailureException
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
     * @throws InvalidToolRegistryException
     * @throws InvalidAuditBudgetException
     * @throws InvalidTokenUsageException
     * @throws NonTransientLLMFailureException
     * @throws NegativeTokenCountException
     * @throws InvalidRetryConfigurationException
     * @throws TransientLLMFailureException
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
     * @throws InvalidToolRegistryException
     * @throws InvalidTokenUsageException
     * @throws NonTransientLLMFailureException
     * @throws NegativeTokenCountException
     * @throws InvalidRetryConfigurationException
     * @throws TransientLLMFailureException
     */
    public function test_complete_batch_with_tools_finalizes_as_empty_content_when_the_retry_itself_fails_after_tools_ran(): void
    {
        $toolRegistry = new ToolRegistry([$this->makeTool('record', 'd')], new NullLogger());

        $platform = new class implements PlatformInterface {
            private int $invocations = 0;

            #[Override]
            public function invoke(Model|string $model, array|string|object $input, array $options = []): DeferredResult
            {
                ++$this->invocations;

                if (1 === $this->invocations) {
                    $toolCallResult = new DeferredResult(
                        new PlainConverter(new MultiPartResult([new ToolCallResult([new ToolCall('1', 'record')])])),
                        new InMemoryRawResult(['text' => ''], [], (object) []),
                        $options,
                    );
                    $toolCallResult->getMetadata()->add('token_usage', new TokenUsage(promptTokens: 120, completionTokens: 30));

                    return $toolCallResult;
                }

                if (2 === $this->invocations) {
                    throw new RuntimeException('HTTP 503 Service Unavailable');
                }

                $deferredResult = new DeferredResult(
                    new PlainConverter(new TextResult('should never surface')),
                    new InMemoryRawResult(['text' => ''], [], (object) []),
                    $options,
                );
                $deferredResult->getMetadata()->add('token_usage', new TokenUsage(promptTokens: -1, completionTokens: 0));

                return $deferredResult;
            }

            #[Override]
            public function getModelCatalog(): ModelCatalogInterface
            {
                return new FallbackModelCatalog();
            }
        };
        $messageCollectingLogger = new MessageCollectingLogger();

        $symfonyAiLLMClient = new SymfonyAiLLMClient(
            new PlatformBinding($platform, 'm', $messageCollectingLogger),
            platformAccountingConfig: new PlatformAccountingConfig(tokenUsageRecorder: new TokenUsageRecorder()),
        );

        $responses = $symfonyAiLLMClient->completeBatchWithTools([
            ['system' => 's', 'user' => 'u', 'tools' => $toolRegistry],
        ], 4, 3);

        self::assertSame('empty_content', $responses[0]->stopReason());
        self::assertSame('', $responses[0]->content());
        self::assertContains(['Concurrent tool-using conversation failed after tool execution; keeping recorded tool results', ['input_tokens' => 120, 'output_tokens' => 30]], $messageCollectingLogger->records);
    }

    /**
     * @throws MissingAiPlatformException
     * @throws BudgetExceededException
     * @throws InvalidToolRegistryException
     * @throws InvalidTokenUsageException
     * @throws NonTransientLLMFailureException
     * @throws NegativeTokenCountException
     * @throws InvalidRetryConfigurationException
     * @throws TransientLLMFailureException
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
     * @throws InvalidToolRegistryException
     * @throws InvalidTokenUsageException
     * @throws NonTransientLLMFailureException
     * @throws NegativeTokenCountException
     * @throws InvalidRetryConfigurationException
     * @throws TransientLLMFailureException
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
     * @throws InvalidToolRegistryException
     * @throws InvalidTokenUsageException
     * @throws NonTransientLLMFailureException
     * @throws NegativeTokenCountException
     * @throws InvalidRetryConfigurationException
     * @throws TransientLLMFailureException
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
     * @throws InvalidToolRegistryException
     * @throws InvalidTokenUsageException
     * @throws NonTransientLLMFailureException
     * @throws NegativeTokenCountException
     * @throws InvalidRetryConfigurationException
     * @throws TransientLLMFailureException
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
     * @throws InvalidToolRegistryException
     * @throws InvalidTokenUsageException
     * @throws NonTransientLLMFailureException
     * @throws NegativeTokenCountException
     * @throws InvalidRetryConfigurationException
     * @throws TransientLLMFailureException
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
     * @throws InvalidToolRegistryException
     * @throws InvalidAuditBudgetException
     * @throws InvalidTokenUsageException
     * @throws NonTransientLLMFailureException
     * @throws NegativeTokenCountException
     * @throws InvalidRetryConfigurationException
     * @throws TransientLLMFailureException
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
     * @throws InvalidToolRegistryException
     * @throws InvalidTokenUsageException
     * @throws NonTransientLLMFailureException
     * @throws NegativeTokenCountException
     * @throws InvalidRetryConfigurationException
     * @throws TransientLLMFailureException
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

    private function stubPricing(float $inputPrice, float $outputPrice): PricingProviderInterface
    {
        return new FixedPricingProvider($inputPrice, $outputPrice);
    }

    /**
     * @param ResultInterface|list<ResultInterface> $results
     * @param TokenUsage|list<TokenUsage>           $tokenUsages
     */
    private function scriptedPlatformWithTokenUsage(
        ResultInterface|array $results = new TextResult(''),
        TokenUsage|array $tokenUsages = new TokenUsage(),
    ): PlatformInterface {
        return ScriptedTokenUsagePlatform::scripted($results, $tokenUsages);
    }

    /**
     * @throws InvalidRetryConfigurationException
     * @throws BudgetExceededException
     * @throws MissingAiPlatformException
     * @throws TransientLLMFailureException
     * @throws NonTransientLLMFailureException
     * @throws InvalidTokenUsageException
     * @throws NegativeTokenCountException
     * @throws InvalidToolRegistryException
     */
    public function test_complete_batch_with_tools_aborts_without_a_restart_and_counts_every_attempt_when_the_retry_before_any_tool_ran_is_exhausted(): void
    {
        $symfonyAiLLMClient = new SymfonyAiLLMClient(
            new PlatformBinding($this->flakyPlatform(array_fill(0, 10, new RuntimeException('HTTP 503 Service Unavailable'))), 'm', new NullLogger()),
            platformResilienceConfig: new PlatformResilienceConfig(retryPolicy: new RetryPolicy(new BackoffSchedule(maxAttempts: 3, initialDelayMs: 10, backoffMultiplier: 2.0, jitterRatio: 0.0), jitterSource: static fn (): float => 0.5), transientFailureClassifier: new TransientFailureClassifier(), sleeper: new FakeSleeper()),
        );

        $this->expectException(TransientLLMFailureException::class);
        $this->expectExceptionMessage('LLM call failed after 4 attempts: HTTP 503 Service Unavailable');

        $symfonyAiLLMClient->completeBatchWithTools([
            ['system' => 's', 'user' => 'u', 'tools' => new ToolRegistry([$this->makeTool('record', 'd')], new NullLogger())],
        ], 2, 3);
    }

    /**
     * @param list<ResultInterface|RuntimeException> $scriptedResultsOrErrors
     */
    private function flakyPlatform(array $scriptedResultsOrErrors): PlatformInterface
    {
        return new FlakyPlatform($scriptedResultsOrErrors);
    }

    /**
     * @param list<ResultInterface> $scriptedResults
     */
    private function scriptedPlatform(array $scriptedResults, ?PlatformInvocationLog $platformInvocationLog = null): PlatformInterface
    {
        return new ScriptedPlatform($scriptedResults, $platformInvocationLog);
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
        return new CallbackTool($name, $description, $executor, $parametersSchema);
    }
}
