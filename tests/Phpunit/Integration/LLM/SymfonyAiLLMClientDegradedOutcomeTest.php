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
use Symfony\AI\Platform\Exception\ContentFilterException;
use Symfony\AI\Platform\Exception\MalformedToolCallException;
use Symfony\AI\Platform\Exception\MaxOutputTokensException;
use Symfony\AI\Platform\Exception\RuntimeException as PlatformRuntimeException;
use Symfony\AI\Platform\FinishReason\FinishReason;
use Symfony\AI\Platform\FinishReason\FinishReasonCase;
use Symfony\AI\Platform\PlainConverter;
use Symfony\AI\Platform\PlatformInterface;
use Symfony\AI\Platform\Result\DeferredResult;
use Symfony\AI\Platform\Result\InMemoryRawResult;
use Symfony\AI\Platform\Result\RawHttpResult;
use Symfony\AI\Platform\Result\TextResult;
use Symfony\AI\Platform\Result\ThinkingResult;
use Symfony\AI\Platform\Result\ToolCall;
use Symfony\AI\Platform\Result\ToolCallResult;
use Symfony\AI\Platform\TokenUsage\TokenUsage;
use Symfony\Contracts\HttpClient\ResponseInterface;
use Throwable;
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
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\RateLimiterInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\TokenEstimatorInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\Exception\InvalidRetryConfigurationException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\Exception\MissingAiPlatformException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\Exception\NonTransientLLMFailureException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\Exception\RateLimitRequestTooLargeException;
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
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Integration\LLM\Fixture\ScriptedDeferredPlatform;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Integration\LLM\Fixture\ScriptedTokenUsagePlatform;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Integration\LLM\Fixture\ThrowingConverter;

/**
 * Some providers deliver "the model answered with nothing usable" as a typed
 * failure instead of a stop reason: the output-limit cut-off, the content
 * filter. Every call path answers those with the degraded response a stop
 * reason would have produced, without retrying the same prompt, while a
 * malformed tool call — a sampling glitch — is retried. The JSON batch window
 * answers a request the model or the rate-limit window cannot fit on its own,
 * and a failure that ends it cancels the requests still in flight.
 */
final class SymfonyAiLLMClientDegradedOutcomeTest extends TestCase
{
    private const string PROMPT_TOO_LONG = 'prompt is too long: 213462 tokens > 200000 maximum';

    private const string CONCURRENT_DEGRADED_WARNING = 'Concurrent tool-using conversation ended without usable content; it is answered as a degraded response and keeps the tool results already recorded';

    private const string TOO_LARGE_DEBUG = 'Batch request refused as too large for the model; it is answered as request_too_large so the caller can act on that request alone';

    private const string BOOKED_DEBUG = 'An answer the provider delivered as an error is booked at its estimated input tokens, since the provider bills the request it accepted';

    private const string AZURE_FILTERED = "The response was filtered due to the prompt triggering Azure OpenAI's content management policy.";

    /**
     * @throws BudgetExceededException
     * @throws InvalidTokenUsageException
     * @throws LLMProviderException
     * @throws NegativeTokenCountException
     * @throws InvalidRetryConfigurationException
     */
    public function test_complete_answers_an_output_limit_failure_as_a_length_response_without_retrying(): void
    {
        $scriptedTokenUsagePlatform = new ScriptedTokenUsagePlatform([new MaxOutputTokensException('The response hit the output token limit')], []);
        $messageCollectingLogger = new MessageCollectingLogger();

        $llmResponse = $this->client($scriptedTokenUsagePlatform, $messageCollectingLogger)->complete('sys', 'usr');

        self::assertSame('length', $llmResponse->stopReason());
        self::assertSame('', $llmResponse->content());
        self::assertTrue($llmResponse->isDegraded());
        self::assertSame(1, $scriptedTokenUsagePlatform->invocations);
        self::assertContains(
            ['LLM returned a response with no content blocks', ['stop_reason' => 'length', 'error' => 'LLM returned a response with no content: The response hit the output token limit']],
            $messageCollectingLogger->records,
        );
    }

    /**
     * @throws BudgetExceededException
     * @throws InvalidAuditBudgetException
     * @throws InvalidTokenUsageException
     * @throws LLMProviderException
     * @throws NegativeTokenCountException
     * @throws InvalidRetryConfigurationException
     */
    public function test_complete_answers_a_thinking_only_answer_cut_off_by_the_output_limit_as_a_length_response_and_books_it(): void
    {
        $scriptedTokenUsagePlatform = new ScriptedTokenUsagePlatform([$this->thinkingCutOffByTheOutputLimit()], [new TokenUsage(promptTokens: 20000, completionTokens: 8192)]);
        $fakeRateLimiter = new FakeRateLimiter();
        $budgetTracker = new BudgetTracker(AuditBudget::unlimited(), new CostCalculator($this->freePricing()));
        $tokenUsageRecorder = new TokenUsageRecorder();
        $symfonyAiLLMClient = new SymfonyAiLLMClient(
            new PlatformBinding($scriptedTokenUsagePlatform, 'm', new NullLogger()),
            platformResilienceConfig: new PlatformResilienceConfig(sleeper: new FakeSleeper(), rateLimiter: $fakeRateLimiter),
            platformAccountingConfig: new PlatformAccountingConfig($tokenUsageRecorder, $budgetTracker),
        );

        $llmResponse = $symfonyAiLLMClient->complete('sys', 'usr');

        self::assertSame('length', $llmResponse->stopReason());
        self::assertSame('', $llmResponse->content());
        self::assertTrue($llmResponse->isDegraded());
        self::assertSame([20000, 8192], [$llmResponse->inputTokens(), $llmResponse->outputTokens()]);
        self::assertSame(1, $scriptedTokenUsagePlatform->invocations);
        self::assertSame(28192, $budgetTracker->tokensUsed());
        self::assertSame([20000, 8192], [$tokenUsageRecorder->snapshot()->inputTokens(), $tokenUsageRecorder->snapshot()->outputTokens()]);
        self::assertSame([[20000, 8192]], $fakeRateLimiter->recorded);
    }

    /**
     * @throws BudgetExceededException
     * @throws InvalidAuditBudgetException
     * @throws InvalidTokenUsageException
     * @throws LLMProviderException
     * @throws NegativeTokenCountException
     * @throws InvalidRetryConfigurationException
     */
    public function test_complete_batch_answers_a_thinking_only_answer_cut_off_by_the_output_limit_without_sending_it_again_or_losing_its_sibling(): void
    {
        $scriptedTokenUsagePlatform = new ScriptedTokenUsagePlatform(
            [$this->thinkingCutOffByTheOutputLimit(), new TextResult('sibling answer')],
            [new TokenUsage(promptTokens: 20000, completionTokens: 8192), new TokenUsage(promptTokens: 10, completionTokens: 5)],
        );
        $budgetTracker = new BudgetTracker(AuditBudget::unlimited(), new CostCalculator($this->freePricing()));
        $symfonyAiLLMClient = new SymfonyAiLLMClient(
            new PlatformBinding($scriptedTokenUsagePlatform, 'm', new NullLogger()),
            platformResilienceConfig: new PlatformResilienceConfig(sleeper: new FakeSleeper()),
            platformAccountingConfig: new PlatformAccountingConfig(budgetTracker: $budgetTracker),
        );

        $responses = $symfonyAiLLMClient->completeBatch([['system' => 's', 'user' => 'thinking'], ['system' => 's', 'user' => 'sibling']], 2);

        self::assertCount(2, $responses);
        self::assertSame(['length', ''], [$responses[0]->stopReason(), $responses[0]->content()]);
        self::assertSame([20000, 8192], [$responses[0]->inputTokens(), $responses[0]->outputTokens()]);
        self::assertSame(['end_turn', 'sibling answer'], [$responses[1]->stopReason(), $responses[1]->content()]);
        self::assertSame([10, 5], [$responses[1]->inputTokens(), $responses[1]->outputTokens()]);
        self::assertSame(2, $scriptedTokenUsagePlatform->invocations);
        self::assertSame(28207, $budgetTracker->tokensUsed());
    }

    /**
     * @throws BudgetExceededException
     * @throws InvalidTokenUsageException
     * @throws LLMProviderException
     * @throws NegativeTokenCountException
     * @throws InvalidRetryConfigurationException
     */
    public function test_complete_answers_a_content_filter_failure_as_a_content_filter_response_without_retrying(): void
    {
        $scriptedTokenUsagePlatform = new ScriptedTokenUsagePlatform([$this->contentFiltered()], []);

        $llmResponse = $this->client($scriptedTokenUsagePlatform, new NullLogger())->complete('sys', 'usr');

        self::assertSame('content-filter', $llmResponse->stopReason());
        self::assertTrue($llmResponse->isDegraded());
        self::assertSame(1, $scriptedTokenUsagePlatform->invocations);
    }

    /**
     * @throws BudgetExceededException
     * @throws InvalidTokenUsageException
     * @throws LLMProviderException
     * @throws NegativeTokenCountException
     * @throws InvalidRetryConfigurationException
     */
    public function test_complete_answers_the_generic_bridge_reporting_a_content_filter_finish_reason_as_an_error_as_a_content_filter_response(): void
    {
        $scriptedDeferredPlatform = new ScriptedDeferredPlatform([
            new DeferredResult(new ThrowingConverter(new PlatformRuntimeException('Unsupported finish reason "content_filter".')), new InMemoryRawResult(), []),
        ]);

        $llmResponse = $this->client($scriptedDeferredPlatform, new NullLogger())->complete('sys', 'usr');

        self::assertSame('content-filter', $llmResponse->stopReason());
        self::assertSame(1, $scriptedDeferredPlatform->invocations);
    }

    /**
     * @throws BudgetExceededException
     * @throws InvalidTokenUsageException
     * @throws LLMProviderException
     * @throws NegativeTokenCountException
     * @throws InvalidRetryConfigurationException
     */
    public function test_complete_answers_a_prompt_the_content_filter_refused_with_an_http_400_as_a_content_filter_response(): void
    {
        $scriptedDeferredPlatform = new ScriptedDeferredPlatform([$this->contentFilterRefusal()]);

        $llmResponse = $this->client($scriptedDeferredPlatform, new NullLogger())->complete('sys', 'usr');

        self::assertSame('content-filter', $llmResponse->stopReason());
        self::assertSame(1, $scriptedDeferredPlatform->invocations);
    }

    /**
     * @throws BudgetExceededException
     * @throws InvalidTokenUsageException
     * @throws LLMProviderException
     * @throws InvalidToolRegistryException
     * @throws NegativeTokenCountException
     * @throws InvalidRetryConfigurationException
     */
    public function test_complete_batch_with_tools_answers_a_prompt_the_content_filter_refused_with_an_http_400_as_a_content_filter_response(): void
    {
        $scriptedDeferredPlatform = new ScriptedDeferredPlatform([$this->contentFilterRefusal()]);

        $responses = $this->client($scriptedDeferredPlatform, new NullLogger())->completeBatchWithTools([['system' => 's', 'user' => 'u', 'tools' => StructuredVulnerabilityCollectionSession::begin(new RecordVulnerabilityToolFactory(), new NullLogger(), [])->toolRegistry]], 2, 3);

        self::assertSame('content-filter', $responses[0]->stopReason());
        self::assertSame(1, $scriptedDeferredPlatform->invocations);
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
    public function test_complete_batch_answers_a_prompt_the_content_filter_refused_with_an_http_400_as_a_content_filter_response(): void
    {
        $scriptedDeferredPlatform = new ScriptedDeferredPlatform([$this->contentFilterRefusal()]);

        $responses = $this->client($scriptedDeferredPlatform, new NullLogger())->completeBatch([['system' => 's', 'user' => 'u']], 2);

        self::assertSame('content-filter', $responses[0]->stopReason());
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
    public function test_complete_with_tools_retries_a_malformed_tool_call(): void
    {
        $scriptedTokenUsagePlatform = new ScriptedTokenUsagePlatform([
            new MalformedToolCallException('Tool call arguments are not valid JSON'),
            new TextResult('[]'),
        ], []);

        $llmResponse = $this->client($scriptedTokenUsagePlatform, new NullLogger())->completeWithTools('sys', 'usr', StructuredVulnerabilityCollectionSession::begin(new RecordVulnerabilityToolFactory(), new NullLogger(), [])->toolRegistry, 3);

        self::assertSame('[]', $llmResponse->content());
        self::assertSame(2, $scriptedTokenUsagePlatform->invocations);
    }

    /**
     * @throws BudgetExceededException
     * @throws InvalidTokenUsageException
     * @throws LLMProviderException
     * @throws NegativeTokenCountException
     * @throws InvalidRetryConfigurationException
     * @throws InvalidToolRegistryException
     */
    public function test_complete_with_tools_ends_a_conversation_cut_off_by_the_output_limit_as_a_length_response(): void
    {
        $scriptedTokenUsagePlatform = new ScriptedTokenUsagePlatform([
            new ToolCallResult([new ToolCall('call-1', 'record_vulnerability', $this->finding())]),
            new MaxOutputTokensException('cut off'),
        ], []);
        $messageCollectingLogger = new MessageCollectingLogger();

        $llmResponse = $this->client($scriptedTokenUsagePlatform, $messageCollectingLogger)->completeWithTools('sys', 'usr', StructuredVulnerabilityCollectionSession::begin(new RecordVulnerabilityToolFactory(), new NullLogger(), [])->toolRegistry, 3);

        self::assertSame('length', $llmResponse->stopReason());
        self::assertSame(2, $scriptedTokenUsagePlatform->invocations);
        self::assertContains(
            ['Tool-using loop ended with empty content response', ['iterations' => 1, 'stop_reason' => 'length', 'input_tokens' => 0, 'output_tokens' => 0, 'error' => 'LLM returned a response with no content: cut off']],
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
    public function test_complete_batch_with_tools_ends_a_conversation_the_provider_answered_with_nothing_usable_without_retrying_it(): void
    {
        $scriptedTokenUsagePlatform = new ScriptedTokenUsagePlatform([new MaxOutputTokensException('cut off')], []);
        $messageCollectingLogger = new MessageCollectingLogger();

        $responses = $this->client($scriptedTokenUsagePlatform, $messageCollectingLogger)->completeBatchWithTools([['system' => 's', 'user' => 'u', 'tools' => StructuredVulnerabilityCollectionSession::begin(new RecordVulnerabilityToolFactory(), new NullLogger(), [])->toolRegistry]], 2, 3);

        self::assertSame('length', $responses[0]->stopReason());
        self::assertSame(1, $scriptedTokenUsagePlatform->invocations);
        self::assertContains(
            [self::CONCURRENT_DEGRADED_WARNING, ['stop_reason' => 'length', 'input_tokens' => 0, 'output_tokens' => 0, 'error' => 'cut off']],
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
    public function test_complete_batch_with_tools_ends_a_conversation_whose_answer_the_content_filter_withheld_while_it_resolved(): void
    {
        $scriptedDeferredPlatform = new ScriptedDeferredPlatform([
            new DeferredResult(new ThrowingConverter($this->contentFiltered()), new RawHttpResult(self::createStub(ResponseInterface::class)), []),
        ]);

        $responses = $this->client($scriptedDeferredPlatform, new NullLogger())->completeBatchWithTools([['system' => 's', 'user' => 'u', 'tools' => StructuredVulnerabilityCollectionSession::begin(new RecordVulnerabilityToolFactory(), new NullLogger(), [])->toolRegistry]], 2, 3);

        self::assertSame('content-filter', $responses[0]->stopReason());
        self::assertSame(1, $scriptedDeferredPlatform->invocations);
    }

    /**
     * @throws BudgetExceededException
     * @throws InvalidTokenUsageException
     * @throws LLMProviderException
     * @throws InvalidToolRegistryException
     * @throws NegativeTokenCountException
     * @throws InvalidRetryConfigurationException
     */
    public function test_complete_batch_with_tools_ends_a_conversation_whose_retry_the_content_filter_withheld_without_restarting_it(): void
    {
        $scriptedTokenUsagePlatform = new ScriptedTokenUsagePlatform([
            new RuntimeException('HTTP 503 Service Unavailable'),
            $this->contentFiltered(),
        ], []);
        $messageCollectingLogger = new MessageCollectingLogger();

        $responses = $this->client($scriptedTokenUsagePlatform, $messageCollectingLogger)->completeBatchWithTools([['system' => 's', 'user' => 'u', 'tools' => StructuredVulnerabilityCollectionSession::begin(new RecordVulnerabilityToolFactory(), new NullLogger(), [])->toolRegistry]], 2, 3);

        self::assertSame('content-filter', $responses[0]->stopReason());
        self::assertSame(2, $scriptedTokenUsagePlatform->invocations);
        self::assertContains(
            [self::CONCURRENT_DEGRADED_WARNING, ['stop_reason' => 'content-filter', 'input_tokens' => 0, 'output_tokens' => 0, 'error' => 'LLM returned a response with no content: filtered']],
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
    public function test_complete_batch_with_tools_retries_a_malformed_tool_call(): void
    {
        $scriptedTokenUsagePlatform = new ScriptedTokenUsagePlatform([
            new MalformedToolCallException('Tool call arguments are not valid JSON'),
            new TextResult('[]'),
        ], []);

        $responses = $this->client($scriptedTokenUsagePlatform, new NullLogger())->completeBatchWithTools([['system' => 's', 'user' => 'u', 'tools' => StructuredVulnerabilityCollectionSession::begin(new RecordVulnerabilityToolFactory(), new NullLogger(), [])->toolRegistry]], 2, 3);

        self::assertSame('[]', $responses[0]->content());
        self::assertSame(2, $scriptedTokenUsagePlatform->invocations);
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
    public function test_complete_batch_answers_a_response_cut_off_by_the_output_limit_without_a_fallback_call(): void
    {
        $scriptedDeferredPlatform = new ScriptedDeferredPlatform([
            new DeferredResult(new PlainConverter(new TextResult('ok')), new RawHttpResult(self::createStub(ResponseInterface::class)), []),
            new DeferredResult(new ThrowingConverter(new MaxOutputTokensException('cut off')), new RawHttpResult(self::createStub(ResponseInterface::class)), []),
        ]);
        $messageCollectingLogger = new MessageCollectingLogger();

        $responses = $this->client($scriptedDeferredPlatform, $messageCollectingLogger)->completeBatch([['system' => 's', 'user' => 'fits'], ['system' => 's', 'user' => 'cut off']], 2);

        self::assertSame('ok', $responses[0]->content());
        self::assertSame('length', $responses[1]->stopReason());
        self::assertSame('', $responses[1]->content());
        self::assertSame([0, 0], [$responses[1]->inputTokens(), $responses[1]->outputTokens()]);
        self::assertSame(2, $scriptedDeferredPlatform->invocations);
        self::assertNotContains(['Batch-window response failed to resolve after dispatch; falling back to a fresh complete() call that may duplicate provider billing for the already-dispatched request', []], $messageCollectingLogger->records);
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
    public function test_complete_batch_answers_a_response_withheld_by_the_content_filter_without_a_fallback_call(): void
    {
        $scriptedDeferredPlatform = new ScriptedDeferredPlatform([
            new DeferredResult(new ThrowingConverter($this->contentFiltered()), new RawHttpResult(self::createStub(ResponseInterface::class)), []),
        ]);

        $responses = $this->client($scriptedDeferredPlatform, new NullLogger())->completeBatch([['system' => 's', 'user' => 'u']], 2);

        self::assertSame('content-filter', $responses[0]->stopReason());
        self::assertSame(1, $scriptedDeferredPlatform->invocations);
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
    public function test_complete_batch_answers_a_prompt_the_model_refused_while_it_resolved_as_request_too_large_and_keeps_its_siblings(): void
    {
        $scriptedDeferredPlatform = new ScriptedDeferredPlatform([
            new DeferredResult(new ThrowingConverter(new BadRequestException(self::PROMPT_TOO_LONG)), new RawHttpResult(self::createStub(ResponseInterface::class)), []),
            new DeferredResult(new PlainConverter(new TextResult('ok')), new RawHttpResult(self::createStub(ResponseInterface::class)), []),
        ]);
        $messageCollectingLogger = new MessageCollectingLogger();

        $responses = $this->client($scriptedDeferredPlatform, $messageCollectingLogger)->completeBatch([['system' => 's', 'user' => 'does not fit'], ['system' => 's', 'user' => 'fits']], 2);

        self::assertTrue($responses[0]->isRequestTooLarge());
        self::assertSame(self::PROMPT_TOO_LONG, $responses[0]->content());
        self::assertSame([0, 0], [$responses[0]->inputTokens(), $responses[0]->outputTokens()]);
        self::assertSame('ok', $responses[1]->content());
        self::assertSame(2, $scriptedDeferredPlatform->invocations);
        self::assertContains([self::TOO_LARGE_DEBUG, ['error' => self::PROMPT_TOO_LONG]], $messageCollectingLogger->records);
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
    public function test_complete_batch_answers_a_prompt_the_model_refuses_on_the_fallback_call_as_request_too_large(): void
    {
        $scriptedDeferredPlatform = new ScriptedDeferredPlatform([
            new RuntimeException('dispatch blip'),
            new BadRequestException(self::PROMPT_TOO_LONG),
        ]);

        $responses = $this->client($scriptedDeferredPlatform, new NullLogger())->completeBatch([['system' => 's', 'user' => 'u']], 2);

        self::assertTrue($responses[0]->isRequestTooLarge());
        self::assertSame('The model cannot fit the request: '.self::PROMPT_TOO_LONG, $responses[0]->content());
        self::assertSame(2, $scriptedDeferredPlatform->invocations);
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
    public function test_complete_batch_answers_a_request_the_rate_limit_window_cannot_fit_without_calling_the_provider(): void
    {
        $scriptedDeferredPlatform = new ScriptedDeferredPlatform([
            new DeferredResult(new PlainConverter(new TextResult('ok')), new RawHttpResult(self::createStub(ResponseInterface::class)), []),
        ]);
        $rateLimiter = self::createStub(RateLimiterInterface::class);
        $rateLimiter->method('acquire')->willReturnCallback(static function (int $estimatedInputTokens): void {
            if ($estimatedInputTokens > 100) {
                throw RateLimitRequestTooLargeException::from($estimatedInputTokens, 100);
            }
        });
        $messageCollectingLogger = new MessageCollectingLogger();
        $symfonyAiLLMClient = new SymfonyAiLLMClient(
            new PlatformBinding($scriptedDeferredPlatform, 'm', $messageCollectingLogger),
            platformResilienceConfig: new PlatformResilienceConfig(sleeper: new FakeSleeper(), rateLimiter: $rateLimiter),
        );

        $responses = $symfonyAiLLMClient->completeBatch([['system' => 's', 'user' => str_repeat('x', 4000)], ['system' => 's', 'user' => 'fits']], 2);

        self::assertCount(1, array_filter($messageCollectingLogger->records, static fn (array $record): bool => self::TOO_LARGE_DEBUG === $record[0]));
        self::assertTrue($responses[0]->isRequestTooLarge());
        self::assertStringContainsString('exceed window capacity (100)', $responses[0]->content());
        self::assertSame('ok', $responses[1]->content());
        self::assertSame(1, $scriptedDeferredPlatform->invocations);
    }

    /**
     * @throws BudgetExceededException
     * @throws MissingAiPlatformException
     * @throws InvalidAuditBudgetException
     * @throws InvalidTokenUsageException
     */
    public function test_a_failure_that_ends_a_batch_window_cancels_the_requests_still_in_flight_and_books_only_the_unread_ones(): void
    {
        $cancelled = [];
        $refused = self::createStub(ResponseInterface::class);
        $refused->method('cancel')->willReturnCallback(static function () use (&$cancelled): void {
            $cancelled[] = 'refused';
        });
        $abandoned = self::createStub(ResponseInterface::class);
        $abandoned->method('cancel')->willReturnCallback(static function () use (&$cancelled): void {
            $cancelled[] = 'abandoned';
        });
        $consumed = self::createStub(ResponseInterface::class);
        $consumed->method('cancel')->willReturnCallback(static function () use (&$cancelled): void {
            $cancelled[] = 'consumed';
        });
        $scriptedDeferredPlatform = new ScriptedDeferredPlatform([
            new DeferredResult(new PlainConverter(new TextResult('ok')), new RawHttpResult($consumed), []),
            new DeferredResult(new ThrowingConverter(new RuntimeException('HTTP 401 Unauthorized')), new RawHttpResult($refused), []),
            new RuntimeException('dispatch blip'),
            new DeferredResult(new PlainConverter(new TextResult('never read')), new RawHttpResult($abandoned), []),
            new RuntimeException('HTTP 401 Unauthorized'),
        ]);
        $fakeRateLimiter = new FakeRateLimiter();
        $budgetTracker = new BudgetTracker(AuditBudget::forTokens(1000), new CostCalculator($this->freePricing()));
        $tokenUsageRecorder = new TokenUsageRecorder();
        $messageCollectingLogger = new MessageCollectingLogger();
        $symfonyAiLLMClient = new SymfonyAiLLMClient(
            new PlatformBinding($scriptedDeferredPlatform, 'm', $messageCollectingLogger),
            new PlatformRequestConfig(tokenEstimator: $this->tokenEstimatorByLength()),
            new PlatformResilienceConfig(sleeper: new FakeSleeper(), rateLimiter: $fakeRateLimiter),
            new PlatformAccountingConfig($tokenUsageRecorder, $budgetTracker),
        );

        $caught = null;
        try {
            $symfonyAiLLMClient->completeBatch([
                ['system' => 's', 'user' => 'answered'],
                ['system' => 's', 'user' => 'refused'],
                ['system' => 's', 'user' => 'never dispatched'],
                ['system' => 's', 'user' => 'in flight'],
            ], 4);
        } catch (Throwable $throwable) {
            $caught = $throwable;
        }

        self::assertInstanceOf(NonTransientLLMFailureException::class, $caught);
        self::assertSame(['refused', 'abandoned'], $cancelled);
        self::assertSame([10, 0], end($fakeRateLimiter->recorded));
        self::assertSame(10, $budgetTracker->tokensUsed());
        self::assertSame(10, $tokenUsageRecorder->snapshot()->inputTokens());
        self::assertSame(0, $tokenUsageRecorder->snapshot()->outputTokens());
        self::assertContains(
            ['Cancelled a request still in flight; its estimated input tokens are booked as spent since the provider bills a request it accepted', ['estimated_input_tokens' => 10]],
            $messageCollectingLogger->records,
        );
    }

    /**
     * @throws BudgetExceededException
     * @throws InvalidAuditBudgetException
     * @throws InvalidTokenUsageException
     * @throws LLMProviderException
     * @throws NegativeTokenCountException
     * @throws InvalidRetryConfigurationException
     */
    public function test_complete_books_an_answer_delivered_as_an_error_at_its_estimated_input_tokens(): void
    {
        [$symfonyAiLLMClient, $budgetTracker, $messageCollectingLogger, $tokenUsageRecorder] = $this->accountingClient(new ScriptedTokenUsagePlatform([new MaxOutputTokensException('cut off')], []));

        $symfonyAiLLMClient->complete('sys', 'user');

        self::assertSame(7, $budgetTracker->tokensUsed());
        self::assertSame(7, $tokenUsageRecorder->snapshot()->inputTokens());
        self::assertSame(0, $tokenUsageRecorder->snapshot()->outputTokens());
        self::assertContains([self::BOOKED_DEBUG, ['stop_reason' => 'length', 'estimated_input_tokens' => 7]], $messageCollectingLogger->records);
    }

    /**
     * @throws BudgetExceededException
     * @throws InvalidAuditBudgetException
     * @throws InvalidTokenUsageException
     * @throws LLMProviderException
     * @throws NegativeTokenCountException
     * @throws InvalidRetryConfigurationException
     * @throws InvalidToolRegistryException
     */
    public function test_complete_with_tools_books_an_answer_delivered_as_an_error_at_its_estimated_input_tokens(): void
    {
        [$symfonyAiLLMClient, $budgetTracker, , $tokenUsageRecorder] = $this->accountingClient(new ScriptedTokenUsagePlatform([$this->contentFiltered()], []));

        $symfonyAiLLMClient->completeWithTools('sys', 'user', StructuredVulnerabilityCollectionSession::begin(new RecordVulnerabilityToolFactory(), new NullLogger(), [])->toolRegistry, 3);

        self::assertSame(7, $budgetTracker->tokensUsed());
        self::assertSame(7, $tokenUsageRecorder->snapshot()->inputTokens());
        self::assertSame(0, $tokenUsageRecorder->snapshot()->outputTokens());
    }

    /**
     * @throws BudgetExceededException
     * @throws InvalidAuditBudgetException
     * @throws InvalidTokenUsageException
     * @throws LLMProviderException
     * @throws InvalidToolRegistryException
     * @throws NegativeTokenCountException
     * @throws InvalidRetryConfigurationException
     */
    public function test_complete_batch_with_tools_books_an_answer_delivered_as_an_error_at_its_estimated_input_tokens(): void
    {
        [$symfonyAiLLMClient, $budgetTracker, , $tokenUsageRecorder] = $this->accountingClient(new ScriptedTokenUsagePlatform([new MaxOutputTokensException('cut off')], []));

        $symfonyAiLLMClient->completeBatchWithTools([['system' => 'sys', 'user' => 'user', 'tools' => StructuredVulnerabilityCollectionSession::begin(new RecordVulnerabilityToolFactory(), new NullLogger(), [])->toolRegistry]], 2, 3);

        self::assertSame(7, $budgetTracker->tokensUsed());
        self::assertSame(7, $tokenUsageRecorder->snapshot()->inputTokens());
        self::assertSame(0, $tokenUsageRecorder->snapshot()->outputTokens());
    }

    /**
     * @throws BudgetExceededException
     * @throws InvalidAuditBudgetException
     * @throws InvalidTokenUsageException
     * @throws MissingAiPlatformException
     * @throws NegativeTokenCountException
     * @throws InvalidRetryConfigurationException
     * @throws NonTransientLLMFailureException
     * @throws TransientLLMFailureException
     */
    public function test_complete_batch_books_an_answer_delivered_as_an_error_at_its_estimated_input_tokens(): void
    {
        [$symfonyAiLLMClient, $budgetTracker, , $tokenUsageRecorder] = $this->accountingClient(new ScriptedDeferredPlatform([
            new DeferredResult(new ThrowingConverter(new MaxOutputTokensException('cut off')), new RawHttpResult(self::createStub(ResponseInterface::class)), []),
        ]));

        $symfonyAiLLMClient->completeBatch([['system' => 'sys', 'user' => 'user']], 2);

        self::assertSame(7, $budgetTracker->tokensUsed());
        self::assertSame(7, $tokenUsageRecorder->snapshot()->inputTokens());
        self::assertSame(0, $tokenUsageRecorder->snapshot()->outputTokens());
    }

    /**
     * @throws BudgetExceededException
     * @throws InvalidAuditBudgetException
     * @throws InvalidTokenUsageException
     * @throws MissingAiPlatformException
     */
    public function test_a_failed_batch_window_releases_the_reservation_of_a_request_it_never_dispatched(): void
    {
        $fakeRateLimiter = new FakeRateLimiter();
        $symfonyAiLLMClient = new SymfonyAiLLMClient(
            new PlatformBinding(new ScriptedDeferredPlatform([
                new DeferredResult(new ThrowingConverter(new RuntimeException('HTTP 401 Unauthorized')), new RawHttpResult(self::createStub(ResponseInterface::class)), []),
                new RuntimeException('dispatch blip'),
                new RuntimeException('HTTP 401 Unauthorized'),
            ]), 'm', new NullLogger()),
            platformResilienceConfig: new PlatformResilienceConfig(sleeper: new FakeSleeper(), rateLimiter: $fakeRateLimiter),
        );

        $caught = null;
        try {
            $symfonyAiLLMClient->completeBatch([['system' => 's', 'user' => 'refused'], ['system' => 's', 'user' => 'never dispatched']], 2);
        } catch (Throwable $throwable) {
            $caught = $throwable;
        }

        self::assertInstanceOf(NonTransientLLMFailureException::class, $caught);
        self::assertSame(array_fill(0, \count($fakeRateLimiter->acquired), [0, 0]), $fakeRateLimiter->recorded);
    }

    /**
     * @throws BudgetExceededException
     * @throws InvalidTokenUsageException
     * @throws InvalidToolRegistryException
     */
    public function test_a_failed_tool_window_releases_the_reservation_of_a_conversation_it_never_dispatched(): void
    {
        $fakeRateLimiter = new FakeRateLimiter();
        $symfonyAiLLMClient = new SymfonyAiLLMClient(
            new PlatformBinding(new ScriptedDeferredPlatform([
                new DeferredResult(new ThrowingConverter(new RuntimeException('HTTP 401 Unauthorized')), new RawHttpResult(self::createStub(ResponseInterface::class)), []),
                new RuntimeException('dispatch blip'),
                new RuntimeException('HTTP 401 Unauthorized'),
                new RuntimeException('HTTP 401 Unauthorized'),
            ]), 'm', new NullLogger()),
            platformResilienceConfig: new PlatformResilienceConfig(sleeper: new FakeSleeper(), rateLimiter: $fakeRateLimiter),
        );

        $caught = null;
        try {
            $symfonyAiLLMClient->completeBatchWithTools([
                ['system' => 's', 'user' => 'refused', 'tools' => StructuredVulnerabilityCollectionSession::begin(new RecordVulnerabilityToolFactory(), new NullLogger(), [])->toolRegistry],
                ['system' => 's', 'user' => 'never dispatched', 'tools' => StructuredVulnerabilityCollectionSession::begin(new RecordVulnerabilityToolFactory(), new NullLogger(), [])->toolRegistry],
            ], 2, 3);
        } catch (Throwable $throwable) {
            $caught = $throwable;
        }

        self::assertInstanceOf(NonTransientLLMFailureException::class, $caught);
        self::assertSame(array_fill(0, \count($fakeRateLimiter->acquired), [0, 0]), $fakeRateLimiter->recorded);
    }

    /**
     * @return array{SymfonyAiLLMClient, BudgetTracker, MessageCollectingLogger, TokenUsageRecorder}
     *
     * @throws InvalidAuditBudgetException
     */
    private function accountingClient(PlatformInterface $platform): array
    {
        $budgetTracker = new BudgetTracker(AuditBudget::forTokens(1000), new CostCalculator($this->freePricing()));
        $messageCollectingLogger = new MessageCollectingLogger();
        $tokenUsageRecorder = new TokenUsageRecorder();

        return [
            new SymfonyAiLLMClient(
                new PlatformBinding($platform, 'm', $messageCollectingLogger),
                new PlatformRequestConfig(tokenEstimator: $this->tokenEstimatorByLength()),
                new PlatformResilienceConfig(sleeper: new FakeSleeper()),
                new PlatformAccountingConfig($tokenUsageRecorder, $budgetTracker),
            ),
            $budgetTracker,
            $messageCollectingLogger,
            $tokenUsageRecorder,
        ];
    }

    /**
     * @throws BudgetExceededException
     * @throws InvalidTokenUsageException
     * @throws LLMProviderException
     * @throws NegativeTokenCountException
     * @throws InvalidRetryConfigurationException
     */
    public function test_complete_releases_the_rate_limit_reservation_of_a_cut_off_answer_at_the_input_it_took_in(): void
    {
        $fakeRateLimiter = new FakeRateLimiter();

        $this->clientLimitedBy(new ScriptedTokenUsagePlatform([new MaxOutputTokensException('cut off')], []), $fakeRateLimiter)->complete('sys', 'usr');

        self::assertGreaterThan(0, $fakeRateLimiter->acquired[0]);
        self::assertSame([[$fakeRateLimiter->acquired[0], 0]], $fakeRateLimiter->recorded);
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
    public function test_complete_batch_releases_the_rate_limit_reservation_of_a_cut_off_answer_at_the_input_it_took_in(): void
    {
        $fakeRateLimiter = new FakeRateLimiter();

        $this->clientLimitedBy(new ScriptedDeferredPlatform([
            new DeferredResult(new ThrowingConverter(new MaxOutputTokensException('cut off')), new RawHttpResult(self::createStub(ResponseInterface::class)), []),
        ]), $fakeRateLimiter)->completeBatch([['system' => 's', 'user' => 'cut off']], 2);

        self::assertGreaterThan(0, $fakeRateLimiter->acquired[0]);
        self::assertSame([[$fakeRateLimiter->acquired[0], 0]], $fakeRateLimiter->recorded);
    }

    /**
     * @throws BudgetExceededException
     * @throws InvalidTokenUsageException
     * @throws LLMProviderException
     * @throws InvalidToolRegistryException
     * @throws NegativeTokenCountException
     * @throws InvalidRetryConfigurationException
     */
    public function test_a_tool_window_releases_the_reservation_of_an_answer_withheld_while_it_resolved_at_the_input_it_took_in(): void
    {
        $fakeRateLimiter = new FakeRateLimiter();

        $this->clientLimitedBy(new ScriptedDeferredPlatform([
            new DeferredResult(new ThrowingConverter($this->contentFiltered()), new RawHttpResult(self::createStub(ResponseInterface::class)), []),
        ]), $fakeRateLimiter)->completeBatchWithTools([['system' => 's', 'user' => 'u', 'tools' => StructuredVulnerabilityCollectionSession::begin(new RecordVulnerabilityToolFactory(), new NullLogger(), [])->toolRegistry]], 2, 3);

        self::assertGreaterThan(0, $fakeRateLimiter->acquired[0]);
        self::assertSame([[$fakeRateLimiter->acquired[0], 0]], $fakeRateLimiter->recorded);
    }

    /**
     * @throws BudgetExceededException
     * @throws InvalidTokenUsageException
     * @throws LLMProviderException
     * @throws InvalidToolRegistryException
     * @throws NegativeTokenCountException
     * @throws InvalidRetryConfigurationException
     */
    public function test_a_tool_window_releases_the_reservation_of_an_answer_withheld_at_dispatch_at_the_input_it_took_in(): void
    {
        $fakeRateLimiter = new FakeRateLimiter();

        $this->clientLimitedBy(new ScriptedDeferredPlatform([
            $this->contentFiltered(),
        ]), $fakeRateLimiter)->completeBatchWithTools([['system' => 's', 'user' => 'u', 'tools' => StructuredVulnerabilityCollectionSession::begin(new RecordVulnerabilityToolFactory(), new NullLogger(), [])->toolRegistry]], 2, 3);

        self::assertGreaterThan(0, $fakeRateLimiter->acquired[0]);
        self::assertSame([[$fakeRateLimiter->acquired[0], 0]], $fakeRateLimiter->recorded);
    }

    private function clientLimitedBy(PlatformInterface $platform, FakeRateLimiter $fakeRateLimiter): SymfonyAiLLMClient
    {
        return new SymfonyAiLLMClient(
            new PlatformBinding($platform, 'm', new NullLogger()),
            platformResilienceConfig: new PlatformResilienceConfig(sleeper: new FakeSleeper(), rateLimiter: $fakeRateLimiter),
        );
    }

    private function contentFilterRefusal(): DeferredResult
    {
        return new DeferredResult(
            new ThrowingConverter(new BadRequestException(self::AZURE_FILTERED)),
            new InMemoryRawResult(['error' => ['message' => self::AZURE_FILTERED, 'type' => null, 'param' => 'prompt', 'code' => 'content_filter', 'status' => 400]]),
            [],
        );
    }

    private function contentFiltered(): RuntimeException
    {
        return new RuntimeException('filtered', previous: new ContentFilterException('Blocked by the safety system'));
    }

    private function client(PlatformInterface $platform, LoggerInterface $logger): SymfonyAiLLMClient
    {
        return new SymfonyAiLLMClient(
            new PlatformBinding($platform, 'm', $logger),
            platformResilienceConfig: new PlatformResilienceConfig(sleeper: new FakeSleeper()),
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

    private function thinkingCutOffByTheOutputLimit(): ThinkingResult
    {
        $thinkingResult = new ThinkingResult('let me think about this controller', 'signature');
        $thinkingResult->getMetadata()->add('finish_reason', new FinishReason(FinishReasonCase::LENGTH, 'max_tokens'));

        return $thinkingResult;
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

    /**
     * @return array<string, mixed>
     */
    private function finding(): array
    {
        return [
            'type' => 'broken_access_control',
            'severity' => 'high',
            'title' => 'recorded before the answer was cut off',
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
