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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Infrastructure\LLM;

use Override;
use PHPUnit\Framework\TestCase;
use Psr\Log\NullLogger;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Budget\BudgetTracker;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Budget\CostCalculator;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Budget\Exception\BudgetExceededException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Exception\NegativeTokenCountException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Telemetry\TokenUsageRecorder;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidAuditBudgetException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidTokenUsageException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidToolRegistryException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\AuditBudget;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\TokenUsageSnapshot;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\BatchCapableLLMClientInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\LLMClientInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\LLMResponse;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\PricingProviderInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\Tool\ToolRegistry;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\ToolBatchCapableLLMClientInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\PlatformBinding;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\SymfonyAiLLMClient;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\UnpricedCostCapWarning;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\LLM\UsageBookingClientFactory;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Application\Agent\Fixture\WarningCollectingLogger;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Infrastructure\LLM\Fixture\UnpricedCostCapWarnings;

final class UsageBookingClientFactoryTest extends TestCase
{
    private TokenUsageRecorder $tokenUsageRecorder;

    #[Override]
    protected function setUp(): void
    {
        $this->tokenUsageRecorder = new TokenUsageRecorder();
    }

    public function test_the_bundled_client_is_handed_over_as_it_is_since_it_books_its_own_usage(): void
    {
        $symfonyAiLLMClient = new SymfonyAiLLMClient(new PlatformBinding(null, 'm', new NullLogger()));

        self::assertSame($symfonyAiLLMClient, $this->around($symfonyAiLLMClient, $this->budgetTracker(AuditBudget::unlimited())));
    }

    /**
     * @throws BudgetExceededException
     * @throws NegativeTokenCountException
     * @throws InvalidTokenUsageException
     * @throws InvalidToolRegistryException
     */
    public function test_a_client_answering_one_call_at_a_time_has_the_usage_of_each_answer_booked(): void
    {
        $toolRegistry = new ToolRegistry([], new NullLogger());
        [$first, $second] = [$this->answer(100, 20, 3, 4), $this->answer(7, 1)];
        $llmClient = $this->createMock(LLMClientInterface::class);
        $llmClient->expects(self::once())->method('complete')->with('system', 'user')->willReturn($first);
        $llmClient->expects(self::once())->method('completeWithTools')->with('system', 'user', $toolRegistry, 6)->willReturn($second);
        $llmClient->method('model')->willReturn('acme-secure-v2');
        $budgetTracker = $this->budgetTracker(AuditBudget::unlimited());

        $wrapped = $this->around($llmClient, $budgetTracker);

        self::assertNotInstanceOf(BatchCapableLLMClientInterface::class, $wrapped);
        self::assertSame($first, $wrapped->complete('system', 'user'));
        self::assertSame($second, $wrapped->completeWithTools('system', 'user', $toolRegistry, 6));
        self::assertSame('acme-secure-v2', $wrapped->model());
        self::assertSame([107, 21, 3, 4], $this->bookedTotals());
        self::assertSame(135, $budgetTracker->tokensUsed());
        self::assertSame(['acme-secure-v2'], array_keys($budgetTracker->usageByModel()));
    }

    /**
     * @throws BudgetExceededException
     * @throws NegativeTokenCountException
     * @throws InvalidTokenUsageException
     */
    public function test_a_batch_capable_client_stays_one_and_has_every_answer_of_a_batch_booked(): void
    {
        $requests = [['system' => 's', 'user' => 'a'], ['system' => 's', 'user' => 'b']];
        $answers = [$this->answer(10, 2), $this->answer(30, 4)];
        $llmClient = $this->createMock(BatchCapableLLMClientInterface::class);
        $llmClient->expects(self::once())->method('completeBatch')->with($requests, 3)->willReturn($answers);
        $llmClient->method('model')->willReturn('acme-batch');

        $wrapped = $this->around($llmClient, $this->budgetTracker(AuditBudget::unlimited()));

        self::assertInstanceOf(BatchCapableLLMClientInterface::class, $wrapped);
        self::assertNotInstanceOf(ToolBatchCapableLLMClientInterface::class, $wrapped);
        self::assertSame($answers, $wrapped->completeBatch($requests, 3));
        self::assertSame('acme-batch', $wrapped->model());
        self::assertSame([40, 6, 0, 0], $this->bookedTotals());
    }

    /**
     * @throws BudgetExceededException
     * @throws NegativeTokenCountException
     * @throws InvalidTokenUsageException
     * @throws InvalidToolRegistryException
     */
    public function test_a_tool_batch_capable_client_stays_one_and_has_every_answer_it_gives_booked(): void
    {
        $toolRegistry = new ToolRegistry([], new NullLogger());
        $toolRequests = [['system' => 's', 'user' => 'a', 'tools' => $toolRegistry]];
        $requests = [['system' => 's', 'user' => 'b']];
        $llmClient = $this->createMock(ToolBatchCapableLLMClientInterface::class);
        $llmClient->expects(self::once())->method('completeBatchWithTools')->with($toolRequests, 2, 5)->willReturn([$this->answer(1000, 0)]);
        $llmClient->expects(self::once())->method('completeBatch')->with($requests, 2)->willReturn([$this->answer(200, 0)]);
        $llmClient->expects(self::once())->method('completeWithTools')->with('system', 'user', $toolRegistry, 5)->willReturn($this->answer(30, 0));
        $llmClient->expects(self::once())->method('complete')->with('system', 'user')->willReturn($this->answer(4, 0));
        $llmClient->method('model')->willReturn('acme-tools');

        $wrapped = $this->around($llmClient, $this->budgetTracker(AuditBudget::unlimited()));

        self::assertInstanceOf(ToolBatchCapableLLMClientInterface::class, $wrapped);
        $wrapped->completeBatchWithTools($toolRequests, 2, 5);
        $wrapped->completeBatch($requests, 2);
        $wrapped->completeWithTools('system', 'user', $toolRegistry, 5);
        $wrapped->complete('system', 'user');
        self::assertSame('acme-tools', $wrapped->model());
        self::assertSame([1234, 0, 0, 0], $this->bookedTotals());
    }

    /**
     * @throws BudgetExceededException
     * @throws NegativeTokenCountException
     * @throws InvalidTokenUsageException
     * @throws InvalidAuditBudgetException
     */
    public function test_the_answer_that_spends_the_budget_is_booked_before_the_run_is_stopped(): void
    {
        $llmClient = self::createStub(BatchCapableLLMClientInterface::class);
        $llmClient->method('completeBatch')->willReturn([$this->answer(6, 0), $this->answer(5, 0)]);

        $wrapped = $this->around($llmClient, $this->budgetTracker(AuditBudget::forTokens(10)));
        self::assertInstanceOf(BatchCapableLLMClientInterface::class, $wrapped);

        try {
            $wrapped->completeBatch([], 2);
            self::fail('The answers spending the budget should stop the run.');
        } catch (BudgetExceededException) {
            self::assertSame([11, 0, 0, 0], $this->bookedTotals());
        }
    }

    /**
     * @throws BudgetExceededException
     * @throws NegativeTokenCountException
     * @throws InvalidTokenUsageException
     * @throws InvalidToolRegistryException
     * @throws InvalidAuditBudgetException
     */
    public function test_no_call_is_made_once_the_budget_is_spent(): void
    {
        $toolRegistry = new ToolRegistry([], new NullLogger());
        $llmClient = $this->createMock(ToolBatchCapableLLMClientInterface::class);
        $llmClient->expects(self::never())->method('complete');
        $llmClient->expects(self::never())->method('completeWithTools');
        $llmClient->expects(self::never())->method('completeBatch');
        $llmClient->expects(self::never())->method('completeBatchWithTools');
        $budgetTracker = $this->budgetTracker(AuditBudget::forTokens(1));
        $budgetTracker->recordCall($this->answer(2, 0));

        $wrapped = $this->around($llmClient, $budgetTracker);
        self::assertInstanceOf(ToolBatchCapableLLMClientInterface::class, $wrapped);

        $refusals = 0;
        foreach ([
            static fn (): LLMResponse => $wrapped->complete('system', 'user'),
            static fn (): LLMResponse => $wrapped->completeWithTools('system', 'user', $toolRegistry, 5),
            static fn (): array => $wrapped->completeBatch([], 2),
            static fn (): array => $wrapped->completeBatchWithTools([], 2, 5),
        ] as $call) {
            try {
                $call();
            } catch (BudgetExceededException) {
                ++$refusals;
            }
        }

        self::assertSame(4, $refusals);
        self::assertSame([0, 0, 0, 0], $this->bookedTotals());
    }

    /**
     * @throws BudgetExceededException
     * @throws NegativeTokenCountException
     * @throws InvalidTokenUsageException
     * @throws InvalidAuditBudgetException
     */
    public function test_a_client_answering_one_call_at_a_time_is_stopped_once_its_answer_spends_the_budget(): void
    {
        $llmClient = self::createStub(LLMClientInterface::class);
        $llmClient->method('complete')->willReturn($this->answer(100, 20));

        $wrapped = $this->around($llmClient, $this->budgetTracker(AuditBudget::forTokens(100)));

        $this->expectException(BudgetExceededException::class);

        $wrapped->complete('system', 'user');
    }

    /**
     * @throws InvalidTokenUsageException
     */
    public function test_a_client_already_wrapped_is_handed_over_as_it_is_so_its_usage_is_not_booked_twice(): void
    {
        $budgetTracker = $this->budgetTracker(AuditBudget::unlimited());

        foreach ([LLMClientInterface::class, BatchCapableLLMClientInterface::class, ToolBatchCapableLLMClientInterface::class] as $clientInterface) {
            $wrapped = $this->around(self::createStub($clientInterface), $budgetTracker);

            self::assertSame($wrapped, $this->around($wrapped, $budgetTracker));
        }
    }

    /**
     * @throws BudgetExceededException
     * @throws NegativeTokenCountException
     * @throws InvalidTokenUsageException
     * @throws InvalidAuditBudgetException
     */
    public function test_an_answer_under_a_model_without_a_price_is_warned_about_when_a_cost_cap_is_set(): void
    {
        $llmClient = self::createStub(LLMClientInterface::class);
        $llmClient->method('complete')->willReturn($this->answer(10, 1));
        $warningCollectingLogger = new WarningCollectingLogger();

        $wrapped = $this->around($llmClient, $this->budgetTracker(AuditBudget::forCost(5.0)), UnpricedCostCapWarnings::of(AuditBudget::forCost(5.0), $warningCollectingLogger));
        $wrapped->complete('system', 'user');

        self::assertSame([UnpricedCostCapWarnings::messageFor('acme-secure-v2')], array_column($warningCollectingLogger->warnings, 0));
    }

    private function around(LLMClientInterface $llmClient, BudgetTracker $budgetTracker, ?UnpricedCostCapWarning $unpricedCostCapWarning = null): LLMClientInterface
    {
        return UsageBookingClientFactory::around($llmClient, $this->tokenUsageRecorder, $budgetTracker, $unpricedCostCapWarning ?? UnpricedCostCapWarnings::of(AuditBudget::unlimited(), new NullLogger()));
    }

    private function budgetTracker(AuditBudget $auditBudget): BudgetTracker
    {
        return new BudgetTracker($auditBudget, new CostCalculator(self::createStub(PricingProviderInterface::class)));
    }

    /**
     * @return list<int>
     *
     * @throws InvalidTokenUsageException
     */
    private function bookedTotals(): array
    {
        $tokenUsageSnapshot = $this->tokenUsageRecorder->snapshot();

        return [$tokenUsageSnapshot->inputTokens(), $tokenUsageSnapshot->outputTokens(), $tokenUsageSnapshot->cacheReadTokens(), $tokenUsageSnapshot->cacheCreationTokens()];
    }

    /**
     * @throws InvalidTokenUsageException
     */
    private function answer(int $inputTokens, int $outputTokens, int $cacheReadTokens = 0, int $cacheCreationTokens = 0): LLMResponse
    {
        return LLMResponse::of('[]', 'acme-secure-v2', 'end_turn', TokenUsageSnapshot::of($inputTokens, $outputTokens, $cacheReadTokens, $cacheCreationTokens));
    }
}
