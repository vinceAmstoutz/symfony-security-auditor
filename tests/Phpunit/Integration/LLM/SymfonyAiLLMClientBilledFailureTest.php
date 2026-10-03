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

use Override;
use PHPUnit\Framework\TestCase;
use Psr\Log\NullLogger;
use Symfony\AI\Platform\Exception\MalformedToolCallException;
use Symfony\AI\Platform\Exception\MaxOutputTokensException;
use Symfony\AI\Platform\Exception\RuntimeException as PlatformRuntimeException;
use Symfony\AI\Platform\PlainConverter;
use Symfony\AI\Platform\PlatformInterface;
use Symfony\AI\Platform\Result\DeferredResult;
use Symfony\AI\Platform\Result\InMemoryRawResult;
use Symfony\AI\Platform\Result\TextResult;
use Symfony\AI\Platform\TokenUsage\TokenUsage;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\Chunk\StructuredVulnerabilityCollectionSession;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Budget\BudgetTracker;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Budget\CostCalculator;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Budget\Exception\BudgetExceededException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Exception\NegativeTokenCountException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Telemetry\TokenUsageRecorder;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidAuditBudgetException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidTokenUsageException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidToolRegistryException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\LLMProviderException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\AuditBudget;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\PricingProviderInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\TokenEstimatorInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\Exception\InvalidRetryConfigurationException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\Exception\MissingAiPlatformException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\Exception\NonTransientLLMFailureException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\Exception\TransientLLMFailureException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\PlatformAccountingConfig;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\PlatformBinding;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\PlatformRequestConfig;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\PlatformResilienceConfig;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\SymfonyAiLLMClient;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Tool\RecordVulnerabilityToolFactory;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Integration\LLM\Fixture\FakeRateLimiter;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Integration\LLM\Fixture\FakeSleeper;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Integration\LLM\Fixture\MessageCollectingLogger;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Integration\LLM\Fixture\RawUsageExtractor;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Integration\LLM\Fixture\ScriptedDeferredPlatform;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Integration\LLM\Fixture\ScriptedTokenUsagePlatform;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Integration\LLM\Fixture\ThrowingConverter;

/**
 * A provider bills a call it answered even when its bridge cannot turn the
 * answer into a result: a tool call the output token limit cut off mid-way
 * through its arguments, a tool call whose arguments the model garbled, an
 * answer the bridge reports as an error. The cut-off is a degraded `length`
 * answer, never retried — every attempt would hit the same cap — and every
 * attempt that was billed is booked against the budget, the report's token
 * totals and the rate-limit window, at the usage the provider reported when
 * its raw answer carries one.
 */
final class SymfonyAiLLMClientBilledFailureTest extends TestCase
{
    private const string MALFORMED_ARGUMENTS = 'Model returned malformed JSON arguments for the "record_vulnerability" tool: "Control character error, possibly incorrectly encoded"';

    private const string REPORTED_USAGE_DEBUG = 'An answer the provider delivered as an error is booked at the usage it reported, since the provider bills the request it accepted';

    private const string ESTIMATED_INPUT_DEBUG = 'An answer the provider delivered as an error is booked at its estimated input tokens, since the provider bills the request it accepted';

    private BudgetTracker $budgetTracker;

    private TokenUsageRecorder $tokenUsageRecorder;

    private FakeRateLimiter $fakeRateLimiter;

    private MessageCollectingLogger $messageCollectingLogger;

    /**
     * @throws InvalidAuditBudgetException
     */
    #[Override]
    protected function setUp(): void
    {
        $this->budgetTracker = new BudgetTracker(AuditBudget::forTokens(1_000_000), new CostCalculator($this->freePricing()));
        $this->tokenUsageRecorder = new TokenUsageRecorder();
        $this->fakeRateLimiter = new FakeRateLimiter();
        $this->messageCollectingLogger = new MessageCollectingLogger();
    }

    /**
     * @throws BudgetExceededException
     * @throws InvalidTokenUsageException
     * @throws LLMProviderException
     * @throws NegativeTokenCountException
     * @throws InvalidRetryConfigurationException
     * @throws InvalidToolRegistryException
     */
    public function test_complete_with_tools_ends_a_tool_call_the_output_limit_cut_off_as_a_length_response_without_retrying_it(): void
    {
        $scriptedDeferredPlatform = new ScriptedDeferredPlatform([$this->toolCallCutOffByTheOutputLimit()]);

        $llmResponse = $this->client($scriptedDeferredPlatform)->completeWithTools('sys', 'user', StructuredVulnerabilityCollectionSession::begin(new RecordVulnerabilityToolFactory(), new NullLogger(), [])->toolRegistry, 3);

        self::assertSame('length', $llmResponse->stopReason());
        self::assertSame(1, $scriptedDeferredPlatform->invocations);
    }

    /**
     * @throws BudgetExceededException
     * @throws InvalidTokenUsageException
     * @throws LLMProviderException
     * @throws NegativeTokenCountException
     * @throws InvalidRetryConfigurationException
     * @throws InvalidToolRegistryException
     */
    public function test_complete_with_tools_books_a_tool_call_the_output_limit_cut_off_at_the_usage_the_provider_reported(): void
    {
        $this->client(new ScriptedDeferredPlatform([$this->toolCallCutOffByTheOutputLimit()]))->completeWithTools('sys', 'user', StructuredVulnerabilityCollectionSession::begin(new RecordVulnerabilityToolFactory(), new NullLogger(), [])->toolRegistry, 3);

        self::assertSame(54096, $this->budgetTracker->tokensUsed());
        self::assertSame([50000, 4096], [$this->tokenUsageRecorder->snapshot()->inputTokens(), $this->tokenUsageRecorder->snapshot()->outputTokens()]);
        self::assertSame([[50000, 4096]], $this->fakeRateLimiter->recorded);
        self::assertContains([self::REPORTED_USAGE_DEBUG, ['stop_reason' => 'length', 'input_tokens' => 50000, 'output_tokens' => 4096]], $this->messageCollectingLogger->records);
        self::assertNotContains(self::ESTIMATED_INPUT_DEBUG, array_column($this->messageCollectingLogger->records, 0));
    }

    /**
     * @throws BudgetExceededException
     * @throws InvalidTokenUsageException
     * @throws LLMProviderException
     * @throws NegativeTokenCountException
     * @throws InvalidRetryConfigurationException
     * @throws InvalidToolRegistryException
     */
    public function test_complete_batch_with_tools_ends_a_tool_call_the_output_limit_cut_off_as_a_length_response_booked_at_its_reported_usage(): void
    {
        $scriptedDeferredPlatform = new ScriptedDeferredPlatform([$this->toolCallCutOffByTheOutputLimit()]);

        $responses = $this->client($scriptedDeferredPlatform)->completeBatchWithTools([['system' => 'sys', 'user' => 'user', 'tools' => StructuredVulnerabilityCollectionSession::begin(new RecordVulnerabilityToolFactory(), new NullLogger(), [])->toolRegistry]], 2, 3);

        self::assertSame('length', $responses[0]->stopReason());
        self::assertSame(1, $scriptedDeferredPlatform->invocations);
        self::assertSame(54096, $this->budgetTracker->tokensUsed());
    }

    /**
     * @throws BudgetExceededException
     * @throws InvalidTokenUsageException
     * @throws LLMProviderException
     * @throws NegativeTokenCountException
     * @throws InvalidRetryConfigurationException
     * @throws InvalidToolRegistryException
     */
    public function test_complete_with_tools_retries_a_tool_call_the_model_garbled_and_books_each_billed_attempt_at_its_reported_usage(): void
    {
        $scriptedDeferredPlatform = new ScriptedDeferredPlatform([$this->garbledToolCall(), $this->answer('[]', new TokenUsage(promptTokens: 200, completionTokens: 10))]);

        $llmResponse = $this->client($scriptedDeferredPlatform)->completeWithTools('sys', 'user', StructuredVulnerabilityCollectionSession::begin(new RecordVulnerabilityToolFactory(), new NullLogger(), [])->toolRegistry, 3);

        self::assertSame('[]', $llmResponse->content());
        self::assertSame(2, $scriptedDeferredPlatform->invocations);
        self::assertSame(550, $this->budgetTracker->tokensUsed());
        self::assertSame([[300, 40], [200, 10]], $this->fakeRateLimiter->recorded);
    }

    /**
     * @throws BudgetExceededException
     * @throws InvalidTokenUsageException
     * @throws LLMProviderException
     * @throws NegativeTokenCountException
     * @throws InvalidRetryConfigurationException
     * @throws InvalidToolRegistryException
     */
    public function test_complete_with_tools_books_a_garbled_tool_call_that_reports_no_usage_at_its_estimated_input_tokens(): void
    {
        $scriptedTokenUsagePlatform = new ScriptedTokenUsagePlatform(
            [new MalformedToolCallException(self::MALFORMED_ARGUMENTS), new TextResult('[]')],
            [new TokenUsage(), new TokenUsage(promptTokens: 20, completionTokens: 5)],
        );

        $this->client($scriptedTokenUsagePlatform)->completeWithTools('sys', 'user', StructuredVulnerabilityCollectionSession::begin(new RecordVulnerabilityToolFactory(), new NullLogger(), [])->toolRegistry, 3);

        self::assertSame(32, $this->budgetTracker->tokensUsed());
        self::assertSame([[7, 0], [20, 5]], $this->fakeRateLimiter->recorded);
        self::assertContains([self::ESTIMATED_INPUT_DEBUG, ['stop_reason' => 'malformed_tool_call', 'estimated_input_tokens' => 7]], $this->messageCollectingLogger->records);
    }

    /**
     * @throws BudgetExceededException
     * @throws InvalidTokenUsageException
     * @throws LLMProviderException
     * @throws NegativeTokenCountException
     * @throws InvalidRetryConfigurationException
     * @throws InvalidToolRegistryException
     */
    public function test_an_attempt_that_failed_before_any_answer_came_back_is_not_booked_at_the_usage_of_the_attempt_before_it(): void
    {
        $scriptedDeferredPlatform = new ScriptedDeferredPlatform([$this->garbledToolCall(), new MaxOutputTokensException('cut off')]);

        $llmResponse = $this->client($scriptedDeferredPlatform)->completeWithTools('sys', 'user', StructuredVulnerabilityCollectionSession::begin(new RecordVulnerabilityToolFactory(), new NullLogger(), [])->toolRegistry, 3);

        self::assertSame('length', $llmResponse->stopReason());
        self::assertSame(347, $this->budgetTracker->tokensUsed());
    }

    /**
     * @throws BudgetExceededException
     * @throws InvalidTokenUsageException
     * @throws LLMProviderException
     * @throws NegativeTokenCountException
     * @throws InvalidRetryConfigurationException
     */
    public function test_complete_books_an_answer_the_bridge_reports_as_an_error_at_the_usage_the_provider_reported(): void
    {
        $this->client(new ScriptedDeferredPlatform([$this->contentFilterFinishReason()]))->complete('sys', 'user');

        self::assertSame(1250, $this->budgetTracker->tokensUsed());
        self::assertSame([[1200, 50]], $this->fakeRateLimiter->recorded);
    }

    /**
     * @throws BudgetExceededException
     * @throws MissingAiPlatformException
     * @throws InvalidTokenUsageException
     * @throws NegativeTokenCountException
     * @throws InvalidRetryConfigurationException
     * @throws NonTransientLLMFailureException
     * @throws TransientLLMFailureException
     */
    public function test_complete_batch_books_an_answer_the_bridge_reports_as_an_error_at_the_usage_the_provider_reported(): void
    {
        $llmResponses = $this->client(new ScriptedDeferredPlatform([$this->contentFilterFinishReason()]))->completeBatch([['system' => 'sys', 'user' => 'user']], 2);

        self::assertSame('content-filter', $llmResponses[0]->stopReason());
        self::assertSame(1250, $this->budgetTracker->tokensUsed());
        self::assertSame([[1200, 50]], $this->fakeRateLimiter->recorded);
    }

    private function toolCallCutOffByTheOutputLimit(): DeferredResult
    {
        return new DeferredResult(
            new ThrowingConverter(new MalformedToolCallException(self::MALFORMED_ARGUMENTS), new RawUsageExtractor()),
            new InMemoryRawResult($this->chatCompletion('length', '{"type":"sql_injection","title":"SQL inj', 50000, 4096)),
            [],
        );
    }

    private function garbledToolCall(): DeferredResult
    {
        return new DeferredResult(
            new ThrowingConverter(new MalformedToolCallException(self::MALFORMED_ARGUMENTS), new RawUsageExtractor()),
            new InMemoryRawResult($this->chatCompletion('tool_calls', "{'type': 'sql_injection'}", 300, 40)),
            [],
        );
    }

    private function contentFilterFinishReason(): DeferredResult
    {
        return new DeferredResult(
            new ThrowingConverter(new PlatformRuntimeException('Unsupported finish reason "content_filter".'), new RawUsageExtractor()),
            new InMemoryRawResult(['choices' => [['index' => 0, 'message' => ['role' => 'assistant', 'content' => null], 'finish_reason' => 'content_filter']], 'usage' => ['prompt_tokens' => 1200, 'completion_tokens' => 50]]),
            [],
        );
    }

    private function answer(string $content, TokenUsage $tokenUsage): DeferredResult
    {
        $deferredResult = new DeferredResult(new PlainConverter(new TextResult($content)), new InMemoryRawResult(), []);
        $deferredResult->getMetadata()->add('token_usage', $tokenUsage);

        return $deferredResult;
    }

    /**
     * @return array<string, mixed>
     */
    private function chatCompletion(string $finishReason, string $arguments, int $promptTokens, int $completionTokens): array
    {
        return [
            'id' => 'chatcmpl-1',
            'object' => 'chat.completion',
            'model' => 'm',
            'choices' => [[
                'index' => 0,
                'message' => ['role' => 'assistant', 'content' => null, 'tool_calls' => [['id' => 'call_1', 'type' => 'function', 'function' => ['name' => 'record_vulnerability', 'arguments' => $arguments]]]],
                'finish_reason' => $finishReason,
            ]],
            'usage' => ['prompt_tokens' => $promptTokens, 'completion_tokens' => $completionTokens, 'total_tokens' => $promptTokens + $completionTokens],
        ];
    }

    private function client(PlatformInterface $platform): SymfonyAiLLMClient
    {
        return new SymfonyAiLLMClient(
            new PlatformBinding($platform, 'm', $this->messageCollectingLogger),
            new PlatformRequestConfig(tokenEstimator: $this->tokenEstimatorByLength()),
            new PlatformResilienceConfig(sleeper: new FakeSleeper(), rateLimiter: $this->fakeRateLimiter),
            new PlatformAccountingConfig($this->tokenUsageRecorder, $this->budgetTracker),
        );
    }

    private function tokenEstimatorByLength(): TokenEstimatorInterface
    {
        return new class implements TokenEstimatorInterface {
            #[Override]
            public function estimateTokens(string $text, string $model): int
            {
                return \strlen($text);
            }
        };
    }

    private function freePricing(): PricingProviderInterface
    {
        return new class implements PricingProviderInterface {
            #[Override]
            public function pricePerMillionInputTokens(string $model): float
            {
                return 0.0;
            }

            #[Override]
            public function pricePerMillionOutputTokens(string $model): float
            {
                return 0.0;
            }

            #[Override]
            public function hasModel(string $model): bool
            {
                return true;
            }
        };
    }
}
