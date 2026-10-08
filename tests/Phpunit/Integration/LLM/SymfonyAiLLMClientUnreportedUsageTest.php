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
use Symfony\AI\Platform\Result\TextResult;
use Symfony\AI\Platform\Result\ToolCall;
use Symfony\AI\Platform\Result\ToolCallResult;
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
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\Tool\ToolRegistry;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\Exception\InvalidRetryConfigurationException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\PlatformAccountingConfig;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\PlatformBinding;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\PlatformRequestConfig;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\PlatformResilienceConfig;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\SymfonyAiLLMClient;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Integration\LLM\Fixture\FakeRateLimiter;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Integration\LLM\Fixture\FixedResultTool;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Integration\LLM\Fixture\FixedTokenEstimator;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Integration\LLM\Fixture\ScriptedPlatform;

/**
 * A provider that reports no token usage with its answers (Bedrock's
 * InvokeModel route, a gateway that omits `usage`) is booked at the estimated
 * input tokens of every call it answered, on every call path, so the budget
 * and the rate-limit window still see its spend. The estimator here counts
 * 100 tokens per prompt text and per tool result.
 */
final class SymfonyAiLLMClientUnreportedUsageTest extends TestCase
{
    private const int TOKENS_PER_TEXT = 100;

    private const string BUDGET_EXCEEDED_MESSAGE_FORMAT = 'Audit aborted: token budget exceeded (%d / 100 tokens)';

    private FakeRateLimiter $fakeRateLimiter;

    private TokenUsageRecorder $tokenUsageRecorder;

    private BudgetTracker $budgetTracker;

    /**
     * @throws InvalidAuditBudgetException
     */
    #[Override]
    protected function setUp(): void
    {
        $this->fakeRateLimiter = new FakeRateLimiter();
        $this->tokenUsageRecorder = new TokenUsageRecorder();
        $this->budgetTracker = $this->budgetOf(100);
    }

    /**
     * @throws InvalidTokenUsageException
     * @throws LLMProviderException
     * @throws NegativeTokenCountException
     * @throws InvalidRetryConfigurationException
     */
    public function test_complete_aborts_on_the_budget_an_answer_that_reports_no_usage_spent(): void
    {
        $symfonyAiLLMClient = $this->client(new ScriptedPlatform([new TextResult('done')]));

        $message = null;
        try {
            $symfonyAiLLMClient->complete('sys', 'usr');
        } catch (BudgetExceededException $budgetExceededException) {
            $message = $budgetExceededException->getMessage();
        }

        self::assertSame(\sprintf(self::BUDGET_EXCEEDED_MESSAGE_FORMAT, 200), $message);
        self::assertSame(200, $this->budgetTracker->tokensUsed());
        self::assertSame([200], $this->fakeRateLimiter->acquired);
        self::assertSame([[200, 0]], $this->fakeRateLimiter->recorded);
        self::assertSame(200, $this->tokenUsageRecorder->snapshot()->inputTokens());
        self::assertSame(0, $this->tokenUsageRecorder->snapshot()->outputTokens());
    }

    /**
     * @throws InvalidTokenUsageException
     * @throws LLMProviderException
     * @throws NegativeTokenCountException
     * @throws InvalidRetryConfigurationException
     */
    public function test_complete_batch_books_the_estimated_input_tokens_of_every_answer_that_reports_no_usage(): void
    {
        $symfonyAiLLMClient = $this->client(new ScriptedPlatform([new TextResult('a'), new TextResult('b')]));

        $message = null;
        try {
            $symfonyAiLLMClient->completeBatch([['system' => 's', 'user' => 'u'], ['system' => 's', 'user' => 'u']], 2);
        } catch (BudgetExceededException $budgetExceededException) {
            $message = $budgetExceededException->getMessage();
        }

        self::assertSame(\sprintf(self::BUDGET_EXCEEDED_MESSAGE_FORMAT, 400), $message);
        self::assertSame(400, $this->budgetTracker->tokensUsed());
        self::assertSame([200, 200], $this->fakeRateLimiter->acquired);
        self::assertSame([[200, 0], [200, 0]], $this->fakeRateLimiter->recorded);
        self::assertSame(400, $this->tokenUsageRecorder->snapshot()->inputTokens());
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
    public function test_complete_with_tools_books_the_conversation_it_sent_at_each_round_of_an_answer_that_reports_no_usage(): void
    {
        $this->budgetTracker = $this->budgetOf(1000);
        $symfonyAiLLMClient = $this->client(new ScriptedPlatform([
            new ToolCallResult([new ToolCall('call-1', 'lookup', [])]),
            new TextResult('done'),
        ]));

        $llmResponse = $symfonyAiLLMClient->completeWithTools('sys', 'usr', $this->toolRegistry(), 3);

        self::assertSame([500, 0], [$llmResponse->inputTokens(), $llmResponse->outputTokens()]);
        self::assertSame(500, $this->budgetTracker->tokensUsed());
        self::assertSame([200, 300], $this->fakeRateLimiter->acquired);
        self::assertSame([[200, 0], [300, 0]], $this->fakeRateLimiter->recorded);
        self::assertSame(500, $this->tokenUsageRecorder->snapshot()->inputTokens());
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
    public function test_complete_batch_with_tools_books_the_conversation_it_sent_at_each_round_of_an_answer_that_reports_no_usage(): void
    {
        $this->budgetTracker = $this->budgetOf(1000);
        $symfonyAiLLMClient = $this->client(new ScriptedPlatform([
            new ToolCallResult([new ToolCall('call-1', 'lookup', [])]),
            new TextResult('done'),
        ]));

        $responses = $symfonyAiLLMClient->completeBatchWithTools([['system' => 's', 'user' => 'u', 'tools' => $this->toolRegistry()]], 2, 3);

        self::assertSame([500, 0], [$responses[0]->inputTokens(), $responses[0]->outputTokens()]);
        self::assertSame(500, $this->budgetTracker->tokensUsed());
        self::assertSame([200, 300], $this->fakeRateLimiter->acquired);
        self::assertSame([[200, 0], [300, 0]], $this->fakeRateLimiter->recorded);
        self::assertSame(500, $this->tokenUsageRecorder->snapshot()->inputTokens());
    }

    private function client(ScriptedPlatform $scriptedPlatform): SymfonyAiLLMClient
    {
        return new SymfonyAiLLMClient(
            new PlatformBinding($scriptedPlatform, 'm', new NullLogger()),
            new PlatformRequestConfig(tokenEstimator: new FixedTokenEstimator(self::TOKENS_PER_TEXT)),
            new PlatformResilienceConfig(rateLimiter: $this->fakeRateLimiter),
            new PlatformAccountingConfig($this->tokenUsageRecorder, $this->budgetTracker),
        );
    }

    /**
     * @throws InvalidAuditBudgetException
     */
    private function budgetOf(int $maxTokens): BudgetTracker
    {
        return new BudgetTracker(AuditBudget::forTokens($maxTokens), new CostCalculator(self::createStub(PricingProviderInterface::class)));
    }

    /**
     * @throws InvalidToolRegistryException
     */
    private function toolRegistry(): ToolRegistry
    {
        return new ToolRegistry([new FixedResultTool('lookup', 'a file')], new NullLogger());
    }
}
