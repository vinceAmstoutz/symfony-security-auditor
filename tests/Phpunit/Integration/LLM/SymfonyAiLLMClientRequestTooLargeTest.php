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
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;
use RuntimeException;
use Symfony\AI\Platform\Exception\BadRequestException;
use Symfony\AI\Platform\PlainConverter;
use Symfony\AI\Platform\Result\DeferredResult;
use Symfony\AI\Platform\Result\RawHttpResult;
use Symfony\AI\Platform\Result\TextResult;
use Symfony\AI\Platform\Result\ToolCall;
use Symfony\AI\Platform\Result\ToolCallResult;
use Symfony\Contracts\HttpClient\ResponseInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\Chunk\StructuredVulnerabilityCollectionSession;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Budget\BudgetTracker;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Budget\CostCalculator;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Budget\Exception\BudgetExceededException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Exception\NegativeTokenCountException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidAuditBudgetException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidTokenUsageException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidToolRegistryException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\LLMProviderException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\LLMRequestTooLargeException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\AuditBudget;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\PricingProviderInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\RateLimiterInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\TokenEstimatorInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\Tool\ToolRegistry;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\Exception\InvalidRetryConfigurationException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\Exception\NonTransientLLMFailureException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\Exception\RateLimitRequestTooLargeException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\PlatformAccountingConfig;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\PlatformBinding;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\PlatformRequestConfig;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\PlatformResilienceConfig;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\SymfonyAiLLMClient;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Tool\RecordVulnerabilityToolFactory;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Integration\LLM\Fixture\FakeRateLimiter;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Integration\LLM\Fixture\FakeSleeper;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Integration\LLM\Fixture\FixedResultTool;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Integration\LLM\Fixture\MessageCollectingLogger;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Integration\LLM\Fixture\ScriptedDeferredPlatform;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Integration\LLM\Fixture\ScriptedTokenUsagePlatform;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Integration\LLM\Fixture\ThrowingConverter;

/**
 * A prompt the model cannot take in is refused before anything is generated:
 * a single call surfaces it under its own type, without retrying, and a batch
 * answers it per request as a `request_too_large` response, so the chunk
 * analyzers can split the chunk while the other requests of the window keep
 * their answers. A conversation that only outgrows the model once tool results
 * were appended ends as an empty response instead.
 */
final class SymfonyAiLLMClientRequestTooLargeTest extends TestCase
{
    private const string PROMPT_TOO_LONG = 'prompt is too long: 213462 tokens > 200000 maximum';

    private const string OUTGROWN_WARNING = 'Tool-using conversation outgrew the model input limit after tool results were appended; it ends as an empty response and keeps the tool results already recorded';

    private const string CONCURRENT_OUTGROWN_WARNING = 'Concurrent tool-using conversation outgrew the model input limit after tool results were appended; it ends as an empty response and keeps the tool results already recorded';

    /**
     * @throws BudgetExceededException
     * @throws InvalidTokenUsageException
     * @throws LLMProviderException
     * @throws NegativeTokenCountException
     * @throws InvalidRetryConfigurationException
     */
    public function test_complete_surfaces_a_prompt_the_model_cannot_fit_under_its_own_exception_without_retrying(): void
    {
        $scriptedTokenUsagePlatform = new ScriptedTokenUsagePlatform([new BadRequestException(self::PROMPT_TOO_LONG)], []);
        $symfonyAiLLMClient = $this->client($scriptedTokenUsagePlatform, new NullLogger());

        $caught = null;
        try {
            $symfonyAiLLMClient->complete('sys', 'usr');
        } catch (LLMRequestTooLargeException $llmRequestTooLargeException) {
            $caught = $llmRequestTooLargeException;
        }

        self::assertInstanceOf(LLMRequestTooLargeException::class, $caught);
        self::assertSame('The model cannot fit the request: '.self::PROMPT_TOO_LONG, $caught->getMessage());
        self::assertSame(1, $scriptedTokenUsagePlatform->invocations);
    }

    /**
     * @throws BudgetExceededException
     * @throws InvalidTokenUsageException
     * @throws LLMProviderException
     * @throws NegativeTokenCountException
     * @throws InvalidRetryConfigurationException
     * @throws InvalidToolRegistryException
     */
    public function test_complete_with_tools_surfaces_a_prompt_the_model_cannot_fit_before_any_tool_ran(): void
    {
        $symfonyAiLLMClient = $this->client(new ScriptedTokenUsagePlatform([new BadRequestException(self::PROMPT_TOO_LONG)], []), new NullLogger());

        $this->expectException(LLMRequestTooLargeException::class);

        $symfonyAiLLMClient->completeWithTools('sys', 'usr', StructuredVulnerabilityCollectionSession::begin(new RecordVulnerabilityToolFactory(), new NullLogger(), [])->toolRegistry, 3);
    }

    /**
     * @throws BudgetExceededException
     * @throws InvalidTokenUsageException
     * @throws LLMProviderException
     * @throws NegativeTokenCountException
     * @throws InvalidRetryConfigurationException
     * @throws InvalidToolRegistryException
     */
    public function test_complete_with_tools_ends_a_conversation_that_outgrew_the_model_after_a_tool_ran_as_an_empty_response(): void
    {
        $scriptedTokenUsagePlatform = new ScriptedTokenUsagePlatform([
            new ToolCallResult([new ToolCall('call-1', 'record_vulnerability', $this->finding())]),
            new BadRequestException(self::PROMPT_TOO_LONG),
        ], []);
        $messageCollectingLogger = new MessageCollectingLogger();
        $symfonyAiLLMClient = $this->client($scriptedTokenUsagePlatform, $messageCollectingLogger);

        $llmResponse = $symfonyAiLLMClient->completeWithTools('sys', 'usr', StructuredVulnerabilityCollectionSession::begin(new RecordVulnerabilityToolFactory(), new NullLogger(), [])->toolRegistry, 3);

        self::assertSame('empty_content', $llmResponse->stopReason());
        self::assertSame(2, $scriptedTokenUsagePlatform->invocations);
        self::assertContains(
            [self::OUTGROWN_WARNING, ['iterations' => 1, 'input_tokens' => 0, 'output_tokens' => 0, 'error' => 'The model cannot fit the request: '.self::PROMPT_TOO_LONG]],
            $messageCollectingLogger->records,
        );
    }

    /**
     * @throws BudgetExceededException
     * @throws InvalidTokenUsageException
     * @throws LLMProviderException
     * @throws InvalidToolRegistryException
     * @throws NegativeTokenCountException
     * @throws InvalidRetryConfigurationException
     */
    public function test_complete_batch_with_tools_answers_a_prompt_the_model_cannot_fit_with_a_request_too_large_response_and_keeps_its_siblings(): void
    {
        $scriptedTokenUsagePlatform = new ScriptedTokenUsagePlatform([
            new TextResult('ok'),
            new BadRequestException(self::PROMPT_TOO_LONG),
        ], []);
        $messageCollectingLogger = new MessageCollectingLogger();
        $symfonyAiLLMClient = $this->client($scriptedTokenUsagePlatform, $messageCollectingLogger);

        $responses = $symfonyAiLLMClient->completeBatchWithTools([
            ['system' => 's', 'user' => 'fits', 'tools' => StructuredVulnerabilityCollectionSession::begin(new RecordVulnerabilityToolFactory(), new NullLogger(), [])->toolRegistry],
            ['system' => 's', 'user' => 'does not fit', 'tools' => StructuredVulnerabilityCollectionSession::begin(new RecordVulnerabilityToolFactory(), new NullLogger(), [])->toolRegistry],
        ], 2, 3);

        self::assertSame('ok', $responses[0]->content());
        self::assertTrue($responses[1]->isRequestTooLarge());
        self::assertTrue($responses[1]->isDegraded());
        self::assertSame(self::PROMPT_TOO_LONG, $responses[1]->content());
        self::assertSame(2, $scriptedTokenUsagePlatform->invocations);
        self::assertContains(
            ['Concurrent tool-using conversation refused as too large for the model before any tool ran; its chunk is handed back to be split', ['error' => self::PROMPT_TOO_LONG]],
            $messageCollectingLogger->records,
        );
    }

    /**
     * @throws BudgetExceededException
     * @throws InvalidTokenUsageException
     * @throws LLMProviderException
     * @throws InvalidToolRegistryException
     * @throws NegativeTokenCountException
     * @throws InvalidRetryConfigurationException
     */
    public function test_complete_batch_with_tools_answers_a_refusal_read_from_the_provider_answer_with_a_request_too_large_response(): void
    {
        $scriptedDeferredPlatform = new ScriptedDeferredPlatform([
            new DeferredResult(new PlainConverter(new TextResult('ok')), new RawHttpResult(self::createStub(ResponseInterface::class)), []),
            new DeferredResult(new ThrowingConverter(new BadRequestException(self::PROMPT_TOO_LONG)), new RawHttpResult(self::createStub(ResponseInterface::class)), []),
        ]);
        $symfonyAiLLMClient = new SymfonyAiLLMClient(
            new PlatformBinding($scriptedDeferredPlatform, 'm', new NullLogger()),
            platformResilienceConfig: new PlatformResilienceConfig(sleeper: new FakeSleeper()),
        );

        $responses = $symfonyAiLLMClient->completeBatchWithTools([
            ['system' => 's', 'user' => 'fits', 'tools' => StructuredVulnerabilityCollectionSession::begin(new RecordVulnerabilityToolFactory(), new NullLogger(), [])->toolRegistry],
            ['system' => 's', 'user' => 'does not fit', 'tools' => StructuredVulnerabilityCollectionSession::begin(new RecordVulnerabilityToolFactory(), new NullLogger(), [])->toolRegistry],
        ], 2, 3);

        self::assertSame('ok', $responses[0]->content());
        self::assertTrue($responses[1]->isRequestTooLarge());
        self::assertSame(self::PROMPT_TOO_LONG, $responses[1]->content());
        self::assertSame(2, $scriptedDeferredPlatform->invocations);
    }

    /**
     * @throws BudgetExceededException
     * @throws InvalidTokenUsageException
     * @throws LLMProviderException
     * @throws InvalidToolRegistryException
     * @throws NegativeTokenCountException
     * @throws InvalidRetryConfigurationException
     */
    public function test_complete_batch_with_tools_ends_a_conversation_that_outgrew_the_model_after_a_tool_ran_as_an_empty_response(): void
    {
        $scriptedTokenUsagePlatform = new ScriptedTokenUsagePlatform([
            new ToolCallResult([new ToolCall('call-1', 'record_vulnerability', $this->finding())]),
            new BadRequestException(self::PROMPT_TOO_LONG),
        ], []);
        $messageCollectingLogger = new MessageCollectingLogger();
        $symfonyAiLLMClient = $this->client($scriptedTokenUsagePlatform, $messageCollectingLogger);

        $responses = $symfonyAiLLMClient->completeBatchWithTools([['system' => 's', 'user' => 'u', 'tools' => StructuredVulnerabilityCollectionSession::begin(new RecordVulnerabilityToolFactory(), new NullLogger(), [])->toolRegistry]], 2, 3);

        self::assertSame('empty_content', $responses[0]->stopReason());
        self::assertSame(2, $scriptedTokenUsagePlatform->invocations);
        self::assertContains(
            [self::CONCURRENT_OUTGROWN_WARNING, ['input_tokens' => 0, 'output_tokens' => 0, 'error' => self::PROMPT_TOO_LONG]],
            $messageCollectingLogger->records,
        );
    }

    /**
     * @throws BudgetExceededException
     * @throws InvalidTokenUsageException
     * @throws LLMProviderException
     * @throws InvalidToolRegistryException
     * @throws NegativeTokenCountException
     * @throws InvalidRetryConfigurationException
     */
    public function test_complete_batch_with_tools_ends_a_conversation_the_rate_limit_window_cannot_fit_before_any_tool_ran_without_calling_the_provider(): void
    {
        $scriptedTokenUsagePlatform = new ScriptedTokenUsagePlatform([new TextResult('ok')], []);
        $symfonyAiLLMClient = $this->clientRefusingEstimatesAbove(100, $scriptedTokenUsagePlatform, new NullLogger());

        $responses = $symfonyAiLLMClient->completeBatchWithTools([
            ['system' => 's', 'user' => str_repeat('x', 4000), 'tools' => StructuredVulnerabilityCollectionSession::begin(new RecordVulnerabilityToolFactory(), new NullLogger(), [])->toolRegistry],
            ['system' => 's', 'user' => 'fits', 'tools' => StructuredVulnerabilityCollectionSession::begin(new RecordVulnerabilityToolFactory(), new NullLogger(), [])->toolRegistry],
        ], 2, 1);

        self::assertTrue($responses[0]->isRequestTooLarge());
        self::assertStringContainsString('exceed window capacity (100)', $responses[0]->content());
        self::assertSame('ok', $responses[1]->content());
        self::assertSame(1, $scriptedTokenUsagePlatform->invocations);
    }

    /**
     * @throws BudgetExceededException
     * @throws InvalidTokenUsageException
     * @throws LLMProviderException
     * @throws InvalidToolRegistryException
     * @throws NegativeTokenCountException
     * @throws InvalidRetryConfigurationException
     */
    public function test_complete_batch_with_tools_ends_a_conversation_the_rate_limit_window_cannot_fit_after_a_tool_ran_as_an_empty_response(): void
    {
        $scriptedTokenUsagePlatform = new ScriptedTokenUsagePlatform([
            new ToolCallResult([new ToolCall('call-1', 'read_big', [])]),
            new TextResult('never reached'),
        ], []);
        $messageCollectingLogger = new MessageCollectingLogger();
        $symfonyAiLLMClient = $this->clientRefusingEstimatesAbove(100, $scriptedTokenUsagePlatform, $messageCollectingLogger);
        $toolRegistry = new ToolRegistry([new FixedResultTool('read_big', str_repeat('x', 8000))], new NullLogger());

        $responses = $symfonyAiLLMClient->completeBatchWithTools([['system' => 's', 'user' => 'u', 'tools' => $toolRegistry]], 2, 3);

        self::assertSame('empty_content', $responses[0]->stopReason());
        self::assertSame(1, $scriptedTokenUsagePlatform->invocations);
        self::assertCount(1, array_filter($messageCollectingLogger->records, static fn (array $record): bool => self::CONCURRENT_OUTGROWN_WARNING === $record[0]));
    }

    /**
     * @throws BudgetExceededException
     * @throws InvalidTokenUsageException
     * @throws LLMProviderException
     * @throws InvalidToolRegistryException
     * @throws NegativeTokenCountException
     * @throws InvalidRetryConfigurationException
     */
    public function test_complete_batch_with_tools_ends_a_conversation_whose_retry_the_model_refuses_as_too_large_without_restarting_it(): void
    {
        $scriptedTokenUsagePlatform = new ScriptedTokenUsagePlatform([
            new RuntimeException('HTTP 503 Service Unavailable'),
            new BadRequestException(self::PROMPT_TOO_LONG),
        ], []);
        $symfonyAiLLMClient = $this->client($scriptedTokenUsagePlatform, new NullLogger());

        $responses = $symfonyAiLLMClient->completeBatchWithTools([['system' => 's', 'user' => 'u', 'tools' => StructuredVulnerabilityCollectionSession::begin(new RecordVulnerabilityToolFactory(), new NullLogger(), [])->toolRegistry]], 2, 3);

        self::assertTrue($responses[0]->isRequestTooLarge());
        self::assertSame(2, $scriptedTokenUsagePlatform->invocations);
    }

    /**
     * @throws BudgetExceededException
     * @throws InvalidTokenUsageException
     * @throws LLMProviderException
     * @throws InvalidToolRegistryException
     * @throws NegativeTokenCountException
     * @throws InvalidRetryConfigurationException
     */
    public function test_complete_batch_with_tools_ends_a_conversation_whose_restart_the_model_refuses_as_too_large(): void
    {
        $scriptedTokenUsagePlatform = new ScriptedTokenUsagePlatform([
            new RuntimeException('HTTP 503 Service Unavailable'),
            new RuntimeException('HTTP 503 Service Unavailable'),
            new RuntimeException('HTTP 503 Service Unavailable'),
            new RuntimeException('HTTP 503 Service Unavailable'),
            new BadRequestException(self::PROMPT_TOO_LONG),
        ], []);
        $symfonyAiLLMClient = $this->client($scriptedTokenUsagePlatform, new NullLogger());

        $responses = $symfonyAiLLMClient->completeBatchWithTools([['system' => 's', 'user' => 'u', 'tools' => StructuredVulnerabilityCollectionSession::begin(new RecordVulnerabilityToolFactory(), new NullLogger(), [])->toolRegistry]], 2, 3);

        self::assertTrue($responses[0]->isRequestTooLarge());
        self::assertSame(5, $scriptedTokenUsagePlatform->invocations);
    }

    /**
     * @throws BudgetExceededException
     * @throws InvalidTokenUsageException
     * @throws LLMProviderException
     * @throws InvalidToolRegistryException
     * @throws NegativeTokenCountException
     * @throws InvalidRetryConfigurationException
     */
    public function test_a_failure_that_ends_the_window_cancels_the_requests_still_in_flight_and_only_those(): void
    {
        $cancelled = [];
        $consumed = self::createStub(ResponseInterface::class);
        $consumed->method('cancel')->willReturnCallback(static function () use (&$cancelled): void {
            $cancelled[] = 'consumed';
        });
        $refused = self::createStub(ResponseInterface::class);
        $refused->method('cancel')->willReturnCallback(static function () use (&$cancelled): void {
            $cancelled[] = 'refused';
        });
        $abandoned = self::createStub(ResponseInterface::class);
        $abandoned->method('cancel')->willReturnCallback(static function () use (&$cancelled): void {
            $cancelled[] = 'abandoned';
        });
        $scriptedDeferredPlatform = new ScriptedDeferredPlatform([
            new DeferredResult(new PlainConverter(new TextResult('ok')), new RawHttpResult($consumed), []),
            new DeferredResult(new ThrowingConverter(new RuntimeException('HTTP 401 Unauthorized')), new RawHttpResult($refused), []),
            new RuntimeException('dispatch blip'),
            new DeferredResult(new PlainConverter(new TextResult('never read')), new RawHttpResult($abandoned), []),
            new RuntimeException('HTTP 401 Unauthorized'),
            new RuntimeException('HTTP 401 Unauthorized'),
        ]);
        $symfonyAiLLMClient = new SymfonyAiLLMClient(
            new PlatformBinding($scriptedDeferredPlatform, 'm', new NullLogger()),
            platformResilienceConfig: new PlatformResilienceConfig(sleeper: new FakeSleeper()),
        );

        $caught = null;
        try {
            $symfonyAiLLMClient->completeBatchWithTools([
                ['system' => 's', 'user' => 'answered', 'tools' => StructuredVulnerabilityCollectionSession::begin(new RecordVulnerabilityToolFactory(), new NullLogger(), [])->toolRegistry],
                ['system' => 's', 'user' => 'refused', 'tools' => StructuredVulnerabilityCollectionSession::begin(new RecordVulnerabilityToolFactory(), new NullLogger(), [])->toolRegistry],
                ['system' => 's', 'user' => 'never dispatched', 'tools' => StructuredVulnerabilityCollectionSession::begin(new RecordVulnerabilityToolFactory(), new NullLogger(), [])->toolRegistry],
                ['system' => 's', 'user' => 'in flight', 'tools' => StructuredVulnerabilityCollectionSession::begin(new RecordVulnerabilityToolFactory(), new NullLogger(), [])->toolRegistry],
            ], 4, 3);
        } catch (NonTransientLLMFailureException $nonTransientLLMFailureException) {
            $caught = $nonTransientLLMFailureException;
        }

        self::assertInstanceOf(NonTransientLLMFailureException::class, $caught);
        self::assertSame(['refused', 'abandoned'], $cancelled);
    }

    /**
     * @throws BudgetExceededException
     * @throws InvalidAuditBudgetException
     * @throws InvalidTokenUsageException
     * @throws InvalidToolRegistryException
     * @throws LLMProviderException
     * @throws NegativeTokenCountException
     * @throws InvalidRetryConfigurationException
     */
    public function test_a_cancelled_request_still_in_flight_is_booked_at_its_estimated_input_tokens(): void
    {
        $abandoned = self::createStub(ResponseInterface::class);
        $scriptedDeferredPlatform = new ScriptedDeferredPlatform([
            new DeferredResult(new ThrowingConverter(new RuntimeException('HTTP 401 Unauthorized')), new RawHttpResult(self::createStub(ResponseInterface::class)), []),
            new DeferredResult(new PlainConverter(new TextResult('never read')), new RawHttpResult($abandoned), []),
            new RuntimeException('HTTP 401 Unauthorized'),
            new RuntimeException('HTTP 401 Unauthorized'),
        ]);
        $fakeRateLimiter = new FakeRateLimiter();
        $budgetTracker = new BudgetTracker(AuditBudget::forTokens(1000), new CostCalculator($this->freePricing()));
        $messageCollectingLogger = new MessageCollectingLogger();
        $symfonyAiLLMClient = new SymfonyAiLLMClient(
            new PlatformBinding($scriptedDeferredPlatform, 'm', $messageCollectingLogger),
            new PlatformRequestConfig(tokenEstimator: $this->tokenEstimatorByLength()),
            new PlatformResilienceConfig(sleeper: new FakeSleeper(), rateLimiter: $fakeRateLimiter),
            new PlatformAccountingConfig(budgetTracker: $budgetTracker),
        );

        $caught = null;
        try {
            $symfonyAiLLMClient->completeBatchWithTools([
                ['system' => 's', 'user' => 'refused', 'tools' => StructuredVulnerabilityCollectionSession::begin(new RecordVulnerabilityToolFactory(), new NullLogger(), [])->toolRegistry],
                ['system' => 's', 'user' => 'in flight', 'tools' => StructuredVulnerabilityCollectionSession::begin(new RecordVulnerabilityToolFactory(), new NullLogger(), [])->toolRegistry],
            ], 2, 3);
        } catch (NonTransientLLMFailureException $nonTransientLLMFailureException) {
            $caught = $nonTransientLLMFailureException;
        }

        self::assertInstanceOf(NonTransientLLMFailureException::class, $caught);
        self::assertSame([10, 0], end($fakeRateLimiter->recorded));
        self::assertSame(10, $budgetTracker->tokensUsed());
        self::assertSame(10, $budgetTracker->usageByModel()['m']['input_tokens']);
        self::assertContains(
            ['Cancelled a request still in flight; its estimated input tokens are booked as spent since the provider bills a request it accepted', ['estimated_input_tokens' => 10]],
            $messageCollectingLogger->records,
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

    private function client(ScriptedTokenUsagePlatform $scriptedTokenUsagePlatform, LoggerInterface $logger): SymfonyAiLLMClient
    {
        return new SymfonyAiLLMClient(
            new PlatformBinding($scriptedTokenUsagePlatform, 'm', $logger),
            platformResilienceConfig: new PlatformResilienceConfig(sleeper: new FakeSleeper()),
        );
    }

    private function clientRefusingEstimatesAbove(int $windowCapacity, ScriptedTokenUsagePlatform $scriptedTokenUsagePlatform, LoggerInterface $logger): SymfonyAiLLMClient
    {
        $rateLimiter = self::createStub(RateLimiterInterface::class);
        $rateLimiter->method('acquire')->willReturnCallback(static function (int $estimatedInputTokens) use ($windowCapacity): void {
            if ($estimatedInputTokens > $windowCapacity) {
                throw RateLimitRequestTooLargeException::from($estimatedInputTokens, $windowCapacity);
            }
        });

        return new SymfonyAiLLMClient(
            new PlatformBinding($scriptedTokenUsagePlatform, 'm', $logger),
            platformResilienceConfig: new PlatformResilienceConfig(sleeper: new FakeSleeper(), rateLimiter: $rateLimiter),
        );
    }

    /**
     * @return array<string, mixed>
     */
    private function finding(): array
    {
        return [
            'type' => 'broken_access_control',
            'severity' => 'high',
            'title' => 'recorded before the conversation outgrew the model',
            'description' => 'desc',
            'file_path' => 'src/A.php',
            'line_start' => 1,
            'line_end' => 2,
            'vulnerable_code' => 'x',
            'attack_vector' => 'x',
            'proof' => 'x',
            'remediation' => 'x',
            'confidence' => 0.9,
        ];
    }
}
