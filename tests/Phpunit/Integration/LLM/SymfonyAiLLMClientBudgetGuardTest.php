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

use PHPUnit\Framework\TestCase;
use Psr\Log\NullLogger;
use RuntimeException;
use Symfony\AI\Platform\Result\TextResult;
use Symfony\AI\Platform\Result\ToolCall;
use Symfony\AI\Platform\Result\ToolCallResult;
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
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\TokenUsageSnapshot;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\LLMResponse;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\PricingProviderInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\BackoffSchedule;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\Exception\InvalidRetryConfigurationException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\PlatformAccountingConfig;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\PlatformBinding;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\PlatformResilienceConfig;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\RetryPolicy;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\SymfonyAiLLMClient;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Tool\RecordVulnerabilityToolFactory;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Integration\LLM\Fixture\FakeSleeper;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Integration\LLM\Fixture\MessageCollectingLogger;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Integration\LLM\Fixture\ScriptedTokenUsagePlatform;

/**
 * The budget is checked before every provider call, and a window that blows
 * it is aborted only once every request it already dispatched has been
 * recorded.
 */
final class SymfonyAiLLMClientBudgetGuardTest extends TestCase
{
    private const string BUDGET_EXCEEDED_MESSAGE_FORMAT = 'Audit aborted: token budget exceeded (%d / 100 tokens)';

    private const string BATCH_WINDOW_DEBUG_MESSAGE = 'Budget exceeded while resolving a batch window; the remaining dispatched requests are still resolved so their spend is recorded';

    private const string WAVEFRONT_DEBUG_MESSAGE = 'Budget exceeded while advancing a concurrent conversation; the remaining dispatched conversations of the round are still resolved so their spend is recorded';

    /**
     * @throws InvalidAuditBudgetException
     * @throws InvalidTokenUsageException
     * @throws LLMProviderException
     * @throws NegativeTokenCountException
     * @throws InvalidRetryConfigurationException
     */
    public function test_complete_refuses_to_call_the_provider_once_the_budget_is_spent(): void
    {
        $scriptedTokenUsagePlatform = new ScriptedTokenUsagePlatform([], []);
        $symfonyAiLLMClient = $this->clientWithSpentBudget($scriptedTokenUsagePlatform);

        $aborted = false;
        try {
            $symfonyAiLLMClient->complete('sys', 'usr');
        } catch (BudgetExceededException) {
            $aborted = true;
        }

        self::assertTrue($aborted);
        self::assertSame(0, $scriptedTokenUsagePlatform->invocations);
    }

    /**
     * @throws InvalidAuditBudgetException
     * @throws InvalidTokenUsageException
     * @throws LLMProviderException
     * @throws NegativeTokenCountException
     * @throws InvalidRetryConfigurationException
     * @throws InvalidToolRegistryException
     */
    public function test_complete_with_tools_refuses_to_start_a_conversation_once_the_budget_is_spent(): void
    {
        $scriptedTokenUsagePlatform = new ScriptedTokenUsagePlatform([], []);
        $symfonyAiLLMClient = $this->clientWithSpentBudget($scriptedTokenUsagePlatform);

        $aborted = false;
        try {
            $symfonyAiLLMClient->completeWithTools('sys', 'usr', StructuredVulnerabilityCollectionSession::begin(new RecordVulnerabilityToolFactory(), new NullLogger(), [])->toolRegistry, 3);
        } catch (BudgetExceededException) {
            $aborted = true;
        }

        self::assertTrue($aborted);
        self::assertSame(0, $scriptedTokenUsagePlatform->invocations);
    }

    /**
     * @throws InvalidAuditBudgetException
     * @throws InvalidTokenUsageException
     * @throws LLMProviderException
     * @throws NegativeTokenCountException
     * @throws InvalidRetryConfigurationException
     */
    public function test_complete_batch_refuses_to_dispatch_a_window_once_the_budget_is_spent(): void
    {
        $scriptedTokenUsagePlatform = new ScriptedTokenUsagePlatform([], []);
        $symfonyAiLLMClient = $this->clientWithSpentBudget($scriptedTokenUsagePlatform);

        $aborted = false;
        try {
            $symfonyAiLLMClient->completeBatch([['system' => 's', 'user' => 'u'], ['system' => 's', 'user' => 'u']], 4);
        } catch (BudgetExceededException) {
            $aborted = true;
        }

        self::assertTrue($aborted);
        self::assertSame(0, $scriptedTokenUsagePlatform->invocations);
    }

    /**
     * @throws InvalidAuditBudgetException
     * @throws InvalidTokenUsageException
     * @throws LLMProviderException
     * @throws InvalidToolRegistryException
     * @throws NegativeTokenCountException
     * @throws InvalidRetryConfigurationException
     */
    public function test_complete_batch_with_tools_refuses_to_dispatch_a_round_once_the_budget_is_spent(): void
    {
        $scriptedTokenUsagePlatform = new ScriptedTokenUsagePlatform([], []);
        $symfonyAiLLMClient = $this->clientWithSpentBudget($scriptedTokenUsagePlatform);

        $aborted = false;
        try {
            $symfonyAiLLMClient->completeBatchWithTools([
                ['system' => 's', 'user' => 'u', 'tools' => StructuredVulnerabilityCollectionSession::begin(new RecordVulnerabilityToolFactory(), new NullLogger(), [])->toolRegistry],
                ['system' => 's', 'user' => 'u', 'tools' => StructuredVulnerabilityCollectionSession::begin(new RecordVulnerabilityToolFactory(), new NullLogger(), [])->toolRegistry],
            ], 4, 3);
        } catch (BudgetExceededException) {
            $aborted = true;
        }

        self::assertTrue($aborted);
        self::assertSame(0, $scriptedTokenUsagePlatform->invocations);
    }

    /**
     * @throws InvalidAuditBudgetException
     * @throws InvalidTokenUsageException
     * @throws LLMProviderException
     * @throws NegativeTokenCountException
     * @throws InvalidRetryConfigurationException
     * @throws InvalidToolRegistryException
     * @throws BudgetExceededException
     */
    public function test_complete_with_tools_aborts_when_its_final_round_exceeds_the_budget(): void
    {
        $symfonyAiLLMClient = new SymfonyAiLLMClient(
            new PlatformBinding($this->platformAnswering(['done']), 'm', new NullLogger()),
            platformAccountingConfig: new PlatformAccountingConfig(budgetTracker: $this->tokenBudget()),
        );

        $this->expectException(BudgetExceededException::class);
        $this->expectExceptionMessage(\sprintf(self::BUDGET_EXCEEDED_MESSAGE_FORMAT, 500));

        $symfonyAiLLMClient->completeWithTools('sys', 'usr', StructuredVulnerabilityCollectionSession::begin(new RecordVulnerabilityToolFactory(), new NullLogger(), [])->toolRegistry, 1);
    }

    /**
     * @throws InvalidAuditBudgetException
     * @throws InvalidTokenUsageException
     * @throws LLMProviderException
     * @throws InvalidRetryConfigurationException
     * @throws NegativeTokenCountException
     */
    public function test_complete_books_the_thinking_tokens_a_provider_counts_apart_from_the_completion_against_the_budget(): void
    {
        $budgetTracker = $this->tokenBudget();
        $symfonyAiLLMClient = new SymfonyAiLLMClient(
            new PlatformBinding(new ScriptedTokenUsagePlatform([new TextResult('answer')], [new TokenUsage(promptTokens: 20, completionTokens: 10, thinkingTokens: 80, totalTokens: 110)]), 'm', new NullLogger()),
            platformAccountingConfig: new PlatformAccountingConfig(budgetTracker: $budgetTracker),
        );

        $message = null;
        try {
            $symfonyAiLLMClient->complete('sys', 'usr');
        } catch (BudgetExceededException $budgetExceededException) {
            $message = $budgetExceededException->getMessage();
        }

        self::assertSame(\sprintf(self::BUDGET_EXCEEDED_MESSAGE_FORMAT, 110), $message);
        self::assertSame(110, $budgetTracker->tokensUsed());
    }

    /**
     * @throws InvalidAuditBudgetException
     * @throws InvalidTokenUsageException
     * @throws LLMProviderException
     * @throws InvalidRetryConfigurationException
     * @throws NegativeTokenCountException
     */
    public function test_complete_batch_records_every_dispatched_response_before_aborting_on_the_budget(): void
    {
        $tokenUsageRecorder = new TokenUsageRecorder();
        $budgetTracker = $this->tokenBudget();
        $scriptedTokenUsagePlatform = $this->platformAnswering(['a', 'b', 'c']);
        $symfonyAiLLMClient = $this->clientWithoutRetries($scriptedTokenUsagePlatform, $budgetTracker, new MessageCollectingLogger(), $tokenUsageRecorder);

        $message = null;
        try {
            $symfonyAiLLMClient->completeBatch(array_fill(0, 3, ['system' => 's', 'user' => 'u']), 4);
        } catch (BudgetExceededException $budgetExceededException) {
            $message = $budgetExceededException->getMessage();
        }

        self::assertSame(\sprintf(self::BUDGET_EXCEEDED_MESSAGE_FORMAT, 1500), $message);
        self::assertSame(1500, $budgetTracker->tokensUsed());
        self::assertSame(1500, $tokenUsageRecorder->snapshot()->inputTokens());
        self::assertSame(3, $scriptedTokenUsagePlatform->invocations);
    }

    /**
     * @throws InvalidAuditBudgetException
     * @throws InvalidTokenUsageException
     * @throws LLMProviderException
     * @throws InvalidRetryConfigurationException
     * @throws NegativeTokenCountException
     */
    public function test_complete_batch_keeps_recording_its_siblings_when_a_fallback_call_spends_the_budget(): void
    {
        $messageCollectingLogger = new MessageCollectingLogger();
        $scriptedTokenUsagePlatform = new ScriptedTokenUsagePlatform(
            [new RuntimeException('HTTP 503 Service Unavailable'), new TextResult('sibling'), new TextResult('fallback')],
            [new TokenUsage(), $this->fiveHundredTokens(), $this->fiveHundredTokens()],
        );
        $symfonyAiLLMClient = $this->clientWithoutRetries($scriptedTokenUsagePlatform, $this->tokenBudget(), $messageCollectingLogger);

        $message = null;
        try {
            $symfonyAiLLMClient->completeBatch([['system' => 's', 'user' => 'u'], ['system' => 's', 'user' => 'u']], 4);
        } catch (BudgetExceededException $budgetExceededException) {
            $message = $budgetExceededException->getMessage();
        }

        self::assertSame(\sprintf(self::BUDGET_EXCEEDED_MESSAGE_FORMAT, 1000), $message);
        self::assertContains([self::BATCH_WINDOW_DEBUG_MESSAGE, ['error' => \sprintf(self::BUDGET_EXCEEDED_MESSAGE_FORMAT, 500)]], $messageCollectingLogger->records);
        self::assertSame(3, $scriptedTokenUsagePlatform->invocations);
    }

    /**
     * @throws InvalidAuditBudgetException
     * @throws InvalidTokenUsageException
     * @throws LLMProviderException
     * @throws InvalidToolRegistryException
     * @throws InvalidRetryConfigurationException
     * @throws NegativeTokenCountException
     */
    public function test_complete_batch_with_tools_records_every_conversation_of_the_round_before_aborting_on_the_budget(): void
    {
        $budgetTracker = $this->tokenBudget();
        $scriptedTokenUsagePlatform = $this->platformAnswering(['a', 'b', 'c']);
        $symfonyAiLLMClient = $this->clientWithoutRetries($scriptedTokenUsagePlatform, $budgetTracker, new MessageCollectingLogger());

        $message = null;
        try {
            $symfonyAiLLMClient->completeBatchWithTools(array_fill(0, 3, ['system' => 's', 'user' => 'u', 'tools' => StructuredVulnerabilityCollectionSession::begin(new RecordVulnerabilityToolFactory(), new NullLogger(), [])->toolRegistry]), 4, 1);
        } catch (BudgetExceededException $budgetExceededException) {
            $message = $budgetExceededException->getMessage();
        }

        self::assertSame(\sprintf(self::BUDGET_EXCEEDED_MESSAGE_FORMAT, 1500), $message);
        self::assertSame(1500, $budgetTracker->tokensUsed());
        self::assertSame(3, $scriptedTokenUsagePlatform->invocations);
    }

    /**
     * @throws InvalidAuditBudgetException
     * @throws InvalidTokenUsageException
     * @throws LLMProviderException
     * @throws InvalidToolRegistryException
     * @throws InvalidRetryConfigurationException
     * @throws NegativeTokenCountException
     */
    public function test_complete_batch_with_tools_keeps_recording_its_siblings_when_a_restarted_conversation_spends_the_budget(): void
    {
        $messageCollectingLogger = new MessageCollectingLogger();
        $scriptedTokenUsagePlatform = new ScriptedTokenUsagePlatform(
            [new RuntimeException('HTTP 503 Service Unavailable'), new TextResult('sibling'), new RuntimeException('HTTP 401 Unauthorized'), new TextResult('restarted')],
            [new TokenUsage(), $this->fiveHundredTokens(), new TokenUsage(), $this->fiveHundredTokens()],
        );
        $symfonyAiLLMClient = $this->clientWithoutRetries($scriptedTokenUsagePlatform, $this->tokenBudget(), $messageCollectingLogger);

        $message = null;
        try {
            $symfonyAiLLMClient->completeBatchWithTools([
                ['system' => 's', 'user' => 'u', 'tools' => StructuredVulnerabilityCollectionSession::begin(new RecordVulnerabilityToolFactory(), new NullLogger(), [])->toolRegistry],
                ['system' => 's', 'user' => 'u', 'tools' => StructuredVulnerabilityCollectionSession::begin(new RecordVulnerabilityToolFactory(), new NullLogger(), [])->toolRegistry],
            ], 4, 1);
        } catch (BudgetExceededException $budgetExceededException) {
            $message = $budgetExceededException->getMessage();
        }

        self::assertSame(\sprintf(self::BUDGET_EXCEEDED_MESSAGE_FORMAT, 1000), $message);
        self::assertContains([self::WAVEFRONT_DEBUG_MESSAGE, ['error' => \sprintf(self::BUDGET_EXCEEDED_MESSAGE_FORMAT, 500)]], $messageCollectingLogger->records);
        self::assertSame(4, $scriptedTokenUsagePlatform->invocations);
    }

    /**
     * @throws InvalidAuditBudgetException
     * @throws InvalidTokenUsageException
     * @throws LLMProviderException
     * @throws InvalidToolRegistryException
     * @throws NegativeTokenCountException
     * @throws InvalidRetryConfigurationException
     */
    public function test_complete_batch_with_tools_stops_a_conversation_that_exceeded_the_budget_before_running_its_tool_calls(): void
    {
        $structuredVulnerabilityCollectionSession = StructuredVulnerabilityCollectionSession::begin(new RecordVulnerabilityToolFactory(), new NullLogger(), []);
        $scriptedTokenUsagePlatform = new ScriptedTokenUsagePlatform(
            [new ToolCallResult([new ToolCall('call-1', 'record_vulnerability', $this->finding())])],
            [$this->fiveHundredTokens()],
        );
        $symfonyAiLLMClient = new SymfonyAiLLMClient(
            new PlatformBinding($scriptedTokenUsagePlatform, 'm', new NullLogger()),
            platformAccountingConfig: new PlatformAccountingConfig(budgetTracker: $this->tokenBudget()),
        );

        $message = null;
        try {
            $symfonyAiLLMClient->completeBatchWithTools([['system' => 's', 'user' => 'u', 'tools' => $structuredVulnerabilityCollectionSession->toolRegistry]], 4, 2);
        } catch (BudgetExceededException $budgetExceededException) {
            $message = $budgetExceededException->getMessage();
        }

        self::assertSame(\sprintf(self::BUDGET_EXCEEDED_MESSAGE_FORMAT, 500), $message);
        self::assertSame([], $structuredVulnerabilityCollectionSession->drain());
        self::assertSame(1, $scriptedTokenUsagePlatform->invocations);
    }

    /**
     * @throws InvalidAuditBudgetException
     * @throws InvalidTokenUsageException
     * @throws LLMProviderException
     * @throws NegativeTokenCountException
     * @throws InvalidRetryConfigurationException
     * @throws InvalidToolRegistryException
     */
    public function test_complete_batch_with_tools_refuses_to_retry_a_conversation_once_a_sibling_spent_the_budget(): void
    {
        $scriptedTokenUsagePlatform = new ScriptedTokenUsagePlatform(
            [new TextResult('spends the budget'), new RuntimeException('HTTP 503 Service Unavailable'), new TextResult('retried after the budget was spent')],
            [$this->fiveHundredTokens(), new TokenUsage(), $this->fiveHundredTokens()],
        );
        $symfonyAiLLMClient = $this->clientWithoutRetries($scriptedTokenUsagePlatform, $this->tokenBudget(), new MessageCollectingLogger());

        $aborted = false;
        try {
            $symfonyAiLLMClient->completeBatchWithTools([
                ['system' => 's', 'user' => 'u', 'tools' => StructuredVulnerabilityCollectionSession::begin(new RecordVulnerabilityToolFactory(), new NullLogger(), [])->toolRegistry],
                ['system' => 's', 'user' => 'u', 'tools' => StructuredVulnerabilityCollectionSession::begin(new RecordVulnerabilityToolFactory(), new NullLogger(), [])->toolRegistry],
            ], 4, 1);
        } catch (BudgetExceededException) {
            $aborted = true;
        }

        self::assertTrue($aborted);
        self::assertSame(2, $scriptedTokenUsagePlatform->invocations);
    }

    /**
     * @throws InvalidAuditBudgetException
     * @throws InvalidTokenUsageException
     * @throws LLMProviderException
     * @throws NegativeTokenCountException
     * @throws InvalidRetryConfigurationException
     * @throws InvalidToolRegistryException
     */
    public function test_complete_batch_with_tools_aborts_on_the_budget_a_retried_answer_spent_after_a_tool_ran(): void
    {
        $scriptedTokenUsagePlatform = new ScriptedTokenUsagePlatform(
            [new ToolCallResult([new ToolCall('call-1', 'record_vulnerability', $this->finding())]), new RuntimeException('HTTP 503 Service Unavailable'), new TextResult('retried answer that spends the budget')],
            [new TokenUsage(), new TokenUsage(), $this->fiveHundredTokens()],
        );
        $messageCollectingLogger = new MessageCollectingLogger();
        $symfonyAiLLMClient = $this->clientWithoutRetries($scriptedTokenUsagePlatform, $this->tokenBudget(), $messageCollectingLogger);

        $aborted = false;
        try {
            $symfonyAiLLMClient->completeBatchWithTools([
                ['system' => 's', 'user' => 'u', 'tools' => StructuredVulnerabilityCollectionSession::begin(new RecordVulnerabilityToolFactory(), new NullLogger(), [])->toolRegistry],
            ], 4, 3);
        } catch (BudgetExceededException) {
            $aborted = true;
        }

        self::assertTrue($aborted);
        self::assertSame(3, $scriptedTokenUsagePlatform->invocations);
        self::assertNotContains('Concurrent tool-using conversation failed after tool execution; keeping recorded tool results', array_column($messageCollectingLogger->records, 0));
    }

    /**
     * A client whose budget is already spent, over a platform scripted with no
     * answer at all: a call that reaches it fails the test with the fixture's
     * own "invoked more times than scripted" error instead of the expected
     * budget abort, and its invocation count says so too.
     *
     * @throws InvalidAuditBudgetException
     * @throws InvalidTokenUsageException
     */
    private function clientWithSpentBudget(ScriptedTokenUsagePlatform $scriptedTokenUsagePlatform): SymfonyAiLLMClient
    {
        $budgetTracker = $this->tokenBudget();
        $budgetTracker->recordCall(LLMResponse::of('', 'm', 'end_turn', TokenUsageSnapshot::of(500, 0)));

        return new SymfonyAiLLMClient(
            new PlatformBinding($scriptedTokenUsagePlatform, 'm', new NullLogger()),
            platformAccountingConfig: new PlatformAccountingConfig(budgetTracker: $budgetTracker),
        );
    }

    /**
     * @throws InvalidRetryConfigurationException
     */
    private function clientWithoutRetries(ScriptedTokenUsagePlatform $scriptedTokenUsagePlatform, BudgetTracker $budgetTracker, MessageCollectingLogger $messageCollectingLogger, ?TokenUsageRecorder $tokenUsageRecorder = null): SymfonyAiLLMClient
    {
        return new SymfonyAiLLMClient(
            new PlatformBinding($scriptedTokenUsagePlatform, 'm', $messageCollectingLogger),
            platformResilienceConfig: new PlatformResilienceConfig(
                retryPolicy: new RetryPolicy(new BackoffSchedule(maxAttempts: 1, initialDelayMs: 1, backoffMultiplier: 2.0, jitterRatio: 0.0), jitterSource: static fn (): float => 0.5),
                sleeper: new FakeSleeper(),
            ),
            platformAccountingConfig: new PlatformAccountingConfig(tokenUsageRecorder: $tokenUsageRecorder ?? new TokenUsageRecorder(), budgetTracker: $budgetTracker),
        );
    }

    /**
     * @param list<string> $answers
     */
    private function platformAnswering(array $answers): ScriptedTokenUsagePlatform
    {
        return new ScriptedTokenUsagePlatform(
            array_map(static fn (string $answer): TextResult => new TextResult($answer), $answers),
            array_map(fn (): TokenUsage => $this->fiveHundredTokens(), $answers),
        );
    }

    private function fiveHundredTokens(): TokenUsage
    {
        return new TokenUsage(promptTokens: 500, completionTokens: 0);
    }

    /**
     * @throws InvalidAuditBudgetException
     */
    private function tokenBudget(): BudgetTracker
    {
        return new BudgetTracker(AuditBudget::forTokens(100), new CostCalculator(self::createStub(PricingProviderInterface::class)));
    }

    /**
     * @return array<string, mixed>
     */
    private function finding(): array
    {
        return [
            'type' => 'broken_access_control',
            'severity' => 'high',
            'title' => 'recorded after the budget was spent',
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
