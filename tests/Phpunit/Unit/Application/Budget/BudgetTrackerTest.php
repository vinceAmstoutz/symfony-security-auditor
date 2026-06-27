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

use Override;
use PHPUnit\Framework\TestCase;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Budget\BudgetTracker;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Budget\CostCalculator;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Budget\Exception\BudgetExceededException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\AuditBudget;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\TokenUsageSnapshot;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\CacheAwarePricingProviderInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\LLMResponse;

final class BudgetTrackerTest extends TestCase
{
    /**
     * @throws BudgetExceededException
     */
    public function test_unlimited_budget_never_throws(): void
    {
        $budgetTracker = $this->budgetTracker(AuditBudget::unlimited());

        $budgetTracker->recordCall(LLMResponse::of('x', 'gpt-4o', 'end_turn', TokenUsageSnapshot::of(1_000_000, 1_000_000)));
        $budgetTracker->assertWithinBudget();

        self::expectNotToPerformAssertions();
    }

    /**
     * @throws BudgetExceededException
     */
    public function test_token_budget_passes_at_cap(): void
    {
        $budgetTracker = $this->budgetTracker(AuditBudget::forTokens(150));

        $budgetTracker->recordCall(LLMResponse::of('x', 'gpt-4o', 'end_turn', TokenUsageSnapshot::of(100, 50)));
        $budgetTracker->assertWithinBudget();

        self::assertSame(150, $budgetTracker->tokensUsed());
    }

    /**
     * @throws BudgetExceededException
     */
    public function test_token_budget_exceeded_throws(): void
    {
        $budgetTracker = $this->budgetTracker(AuditBudget::forTokens(100));

        $budgetTracker->recordCall(LLMResponse::of('x', 'gpt-4o', 'end_turn', TokenUsageSnapshot::of(80, 30)));

        $this->expectException(BudgetExceededException::class);
        $this->expectExceptionMessage('token budget exceeded (110 / 100 tokens)');

        $budgetTracker->assertWithinBudget();
    }

    /**
     * @throws BudgetExceededException
     */
    public function test_cost_budget_exceeded_throws(): void
    {
        $budgetTracker = $this->budgetTracker(AuditBudget::forCost(0.01), inputPrice: 100.0, outputPrice: 100.0);

        $budgetTracker->recordCall(LLMResponse::of('x', 'gpt-4o', 'end_turn', TokenUsageSnapshot::of(1_000, 0)));

        $this->expectException(BudgetExceededException::class);
        $this->expectExceptionMessage('cost budget exceeded');

        $budgetTracker->assertWithinBudget();
    }

    /**
     * @throws BudgetExceededException
     */
    public function test_for_both_enforces_whichever_cap_is_hit_first(): void
    {
        $budgetTracker = $this->budgetTracker(AuditBudget::forBoth(maxTokens: 1_000_000, maxCostUsd: 0.001), inputPrice: 100.0, outputPrice: 0.0);

        $budgetTracker->recordCall(LLMResponse::of('x', 'gpt-4o', 'end_turn', TokenUsageSnapshot::of(100, 0)));

        $this->expectException(BudgetExceededException::class);
        $this->expectExceptionMessage('cost budget exceeded');

        $budgetTracker->assertWithinBudget();
    }

    /**
     * @throws BudgetExceededException
     */
    public function test_multiple_record_calls_accumulate(): void
    {
        $budgetTracker = $this->budgetTracker(AuditBudget::forTokens(500));

        $budgetTracker->recordCall(LLMResponse::of('a', 'gpt-4o', 'end_turn', TokenUsageSnapshot::of(100, 50)));
        $budgetTracker->recordCall(LLMResponse::of('b', 'gpt-4o', 'end_turn', TokenUsageSnapshot::of(100, 50)));

        self::assertSame(300, $budgetTracker->tokensUsed());
        $budgetTracker->assertWithinBudget();
    }

    public function test_cost_used_accumulates_from_recorded_calls(): void
    {
        $budgetTracker = $this->budgetTracker(AuditBudget::unlimited(), inputPrice: 10.0, outputPrice: 20.0);

        // 1M input @ $10 = $10; 0 output @ $20 = $0; total $10
        $budgetTracker->recordCall(LLMResponse::of('x', 'gpt-4o', 'end_turn', TokenUsageSnapshot::of(1_000_000, 0)));

        self::assertSame(10.0, $budgetTracker->costUsdUsed());
    }

    public function test_cost_used_accumulates_across_multiple_calls(): void
    {
        // Pins: `$this->costUsdUsed += ...` — if mutated to `=`, the second call
        // would overwrite the first, and the total would be $5 (not $15).
        $budgetTracker = $this->budgetTracker(AuditBudget::unlimited(), inputPrice: 10.0);

        $budgetTracker->recordCall(LLMResponse::of('a', 'gpt-4o', 'end_turn', TokenUsageSnapshot::of(1_000_000, 0)));
        $budgetTracker->recordCall(LLMResponse::of('b', 'gpt-4o', 'end_turn', TokenUsageSnapshot::of(500_000, 0)));

        self::assertSame(15.0, $budgetTracker->costUsdUsed());
    }

    /**
     * @throws BudgetExceededException
     */
    public function test_cost_budget_passes_at_exact_cap_and_aborts_above(): void
    {
        $budgetTracker = $this->budgetTracker(AuditBudget::forCost(5.0), inputPrice: 10.0);

        $budgetTracker->recordCall(LLMResponse::of('a', 'gpt-4o', 'end_turn', TokenUsageSnapshot::of(500_000, 0))); // $5.00
        $budgetTracker->assertWithinBudget();
        self::assertSame(5.0, $budgetTracker->costUsdUsed());

        $budgetTracker->recordCall(LLMResponse::of('b', 'gpt-4o', 'end_turn', TokenUsageSnapshot::of(1_000, 0))); // +$0.01 → $5.01

        $this->expectException(BudgetExceededException::class);
        $budgetTracker->assertWithinBudget();
    }

    public function test_cost_used_is_rounded_to_six_decimal_places(): void
    {
        $budgetTracker = $this->budgetTracker(AuditBudget::unlimited(), inputPrice: 0.7);

        $budgetTracker->recordCall(LLMResponse::of('x', 'gpt-4o', 'end_turn', TokenUsageSnapshot::of(1, 0)));

        self::assertSame(0.000001, $budgetTracker->costUsdUsed());
    }

    /**
     * @throws BudgetExceededException
     */
    public function test_at_cap_call_completes_next_call_aborts(): void
    {
        $budgetTracker = $this->budgetTracker(AuditBudget::forTokens(100));

        $budgetTracker->recordCall(LLMResponse::of('a', 'gpt-4o', 'end_turn', TokenUsageSnapshot::of(60, 40)));
        $budgetTracker->assertWithinBudget();

        $budgetTracker->recordCall(LLMResponse::of('b', 'gpt-4o', 'end_turn', TokenUsageSnapshot::of(1, 0)));

        $this->expectException(BudgetExceededException::class);

        $budgetTracker->assertWithinBudget();
    }

    public function test_cache_read_tokens_contribute_to_cost_at_the_cache_read_rate(): void
    {
        $budgetTracker = $this->budgetTracker(AuditBudget::unlimited(), cacheReadPrice: 1.0);

        $budgetTracker->recordCall(LLMResponse::of('x', 'claude-opus-4-7', 'end_turn', TokenUsageSnapshot::of(0, 0, 1_000_000, 0)));

        self::assertSame(1.0, $budgetTracker->costUsdUsed());
    }

    public function test_cache_creation_tokens_contribute_to_cost_at_the_cache_creation_rate(): void
    {
        $budgetTracker = $this->budgetTracker(AuditBudget::unlimited(), cacheCreationPrice: 12.5);

        $budgetTracker->recordCall(LLMResponse::of('x', 'claude-opus-4-7', 'end_turn', TokenUsageSnapshot::of(0, 0, 0, 1_000_000)));

        self::assertSame(12.5, $budgetTracker->costUsdUsed());
    }

    private function budgetTracker(
        AuditBudget $auditBudget,
        float $inputPrice = 0.0,
        float $outputPrice = 0.0,
        float $cacheReadPrice = 0.0,
        float $cacheCreationPrice = 0.0,
    ): BudgetTracker {
        $pricingProvider = new class($inputPrice, $outputPrice, $cacheReadPrice, $cacheCreationPrice) implements CacheAwarePricingProviderInterface {
            public function __construct(
                private readonly float $inputPrice,
                private readonly float $outputPrice,
                private readonly float $cacheReadPrice,
                private readonly float $cacheCreationPrice,
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
            public function cacheReadPricePerMillionTokens(string $model): float
            {
                return $this->cacheReadPrice;
            }

            #[Override]
            public function cacheCreationPricePerMillionTokens(string $model): float
            {
                return $this->cacheCreationPrice;
            }

            #[Override]
            public function hasModel(string $model): bool
            {
                return true;
            }
        };

        return new BudgetTracker($auditBudget, new CostCalculator($pricingProvider));
    }
}
