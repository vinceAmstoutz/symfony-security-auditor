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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Application\Budget;

use PHPUnit\Framework\TestCase;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Budget\BudgetTracker;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Budget\CostCalculator;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Budget\Exception\BudgetExceededException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\AuditBudget;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\LLMResponse;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\PricingProviderInterface;

final class BudgetTrackerTest extends TestCase
{
    public function test_unlimited_budget_never_throws(): void
    {
        $budgetTracker = $this->budgetTracker(AuditBudget::unlimited());

        $budgetTracker->recordCall(LLMResponse::create('x', 1_000_000, 1_000_000, 'gpt-4o', 'end_turn'));
        $budgetTracker->assertWithinBudget();

        self::expectNotToPerformAssertions();
    }

    public function test_token_budget_passes_at_cap(): void
    {
        $budgetTracker = $this->budgetTracker(AuditBudget::forTokens(150));

        $budgetTracker->recordCall(LLMResponse::create('x', 100, 50, 'gpt-4o', 'end_turn'));
        $budgetTracker->assertWithinBudget();

        self::assertSame(150, $budgetTracker->tokensUsed());
    }

    public function test_token_budget_exceeded_throws(): void
    {
        $budgetTracker = $this->budgetTracker(AuditBudget::forTokens(100));

        $budgetTracker->recordCall(LLMResponse::create('x', 80, 30, 'gpt-4o', 'end_turn'));

        $this->expectException(BudgetExceededException::class);
        $this->expectExceptionMessage('token budget exceeded (110 / 100 tokens)');

        $budgetTracker->assertWithinBudget();
    }

    public function test_cost_budget_exceeded_throws(): void
    {
        $budgetTracker = $this->budgetTracker(AuditBudget::forCost(0.01), inputPrice: 100.0, outputPrice: 100.0);

        $budgetTracker->recordCall(LLMResponse::create('x', 1_000, 0, 'gpt-4o', 'end_turn'));

        $this->expectException(BudgetExceededException::class);
        $this->expectExceptionMessage('cost budget exceeded');

        $budgetTracker->assertWithinBudget();
    }

    public function test_for_both_enforces_whichever_cap_is_hit_first(): void
    {
        $budgetTracker = $this->budgetTracker(AuditBudget::forBoth(maxTokens: 1_000_000, maxCostUsd: 0.001), inputPrice: 100.0, outputPrice: 0.0);

        $budgetTracker->recordCall(LLMResponse::create('x', 100, 0, 'gpt-4o', 'end_turn'));

        $this->expectException(BudgetExceededException::class);
        $this->expectExceptionMessage('cost budget exceeded');

        $budgetTracker->assertWithinBudget();
    }

    public function test_multiple_record_calls_accumulate(): void
    {
        $budgetTracker = $this->budgetTracker(AuditBudget::forTokens(500));

        $budgetTracker->recordCall(LLMResponse::create('a', 100, 50, 'gpt-4o', 'end_turn'));
        $budgetTracker->recordCall(LLMResponse::create('b', 100, 50, 'gpt-4o', 'end_turn'));

        self::assertSame(300, $budgetTracker->tokensUsed());
        $budgetTracker->assertWithinBudget();
    }

    public function test_at_cap_call_completes_next_call_aborts(): void
    {
        $budgetTracker = $this->budgetTracker(AuditBudget::forTokens(100));

        $budgetTracker->recordCall(LLMResponse::create('a', 60, 40, 'gpt-4o', 'end_turn'));
        $budgetTracker->assertWithinBudget();

        $budgetTracker->recordCall(LLMResponse::create('b', 1, 0, 'gpt-4o', 'end_turn'));

        $this->expectException(BudgetExceededException::class);

        $budgetTracker->assertWithinBudget();
    }

    private function budgetTracker(
        AuditBudget $auditBudget,
        float $inputPrice = 0.0,
        float $outputPrice = 0.0,
    ): BudgetTracker {
        $pricingProvider = new class($inputPrice, $outputPrice) implements PricingProviderInterface {
            public function __construct(
                private readonly float $inputPrice,
                private readonly float $outputPrice,
            ) {}

            public function pricePerMillionInputTokens(string $model): float
            {
                return $this->inputPrice;
            }

            public function pricePerMillionOutputTokens(string $model): float
            {
                return $this->outputPrice;
            }

            public function hasModel(string $model): bool
            {
                return true;
            }
        };

        return new BudgetTracker($auditBudget, new CostCalculator($pricingProvider));
    }
}
