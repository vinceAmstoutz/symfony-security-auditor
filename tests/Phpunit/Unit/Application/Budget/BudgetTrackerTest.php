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
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidAuditBudgetException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidTokenUsageException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\AuditBudget;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\TokenUsageSnapshot;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\CacheAwarePricingProviderInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\LLMResponse;

final class BudgetTrackerTest extends TestCase
{
    /**
     * @throws BudgetExceededException
     * @throws InvalidTokenUsageException
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
     * @throws InvalidAuditBudgetException
     * @throws InvalidTokenUsageException
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
     * @throws InvalidAuditBudgetException
     * @throws InvalidTokenUsageException
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
     * @throws InvalidAuditBudgetException
     * @throws InvalidTokenUsageException
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
     * @throws InvalidAuditBudgetException
     * @throws InvalidTokenUsageException
     */
    public function test_cost_budget_exceeded_message_formats_amounts_with_a_period_regardless_of_the_process_numeric_locale(): void
    {
        $budgetTracker = $this->budgetTracker(AuditBudget::forCost(0.01), inputPrice: 100.0, outputPrice: 100.0);

        $budgetTracker->recordCall(LLMResponse::of('x', 'gpt-4o', 'end_turn', TokenUsageSnapshot::of(1_000, 0)));

        $previousLocale = setlocale(\LC_NUMERIC, '0');
        setlocale(\LC_NUMERIC, 'de_DE.UTF-8');

        try {
            $message = '';
            try {
                $budgetTracker->assertWithinBudget();
            } catch (BudgetExceededException $budgetExceededException) {
                $message = $budgetExceededException->getMessage();
            }
        } finally {
            setlocale(\LC_NUMERIC, false !== $previousLocale ? $previousLocale : 'C');
        }

        self::assertStringContainsString('$0.1000 / $0.0100 USD', $message);
    }

    /**
     * @throws BudgetExceededException
     * @throws InvalidAuditBudgetException
     * @throws InvalidTokenUsageException
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
     * @throws InvalidAuditBudgetException
     * @throws InvalidTokenUsageException
     */
    public function test_multiple_record_calls_accumulate(): void
    {
        $budgetTracker = $this->budgetTracker(AuditBudget::forTokens(500));

        $budgetTracker->recordCall(LLMResponse::of('a', 'gpt-4o', 'end_turn', TokenUsageSnapshot::of(100, 50)));
        $budgetTracker->recordCall(LLMResponse::of('b', 'gpt-4o', 'end_turn', TokenUsageSnapshot::of(100, 50)));

        self::assertSame(300, $budgetTracker->tokensUsed());
        $budgetTracker->assertWithinBudget();
    }

    /**
     * @throws InvalidTokenUsageException
     */
    public function test_cost_used_accumulates_from_recorded_calls(): void
    {
        $budgetTracker = $this->budgetTracker(AuditBudget::unlimited(), inputPrice: 10.0, outputPrice: 20.0);

        // 1M input @ $10 = $10; 0 output @ $20 = $0; total $10
        $budgetTracker->recordCall(LLMResponse::of('x', 'gpt-4o', 'end_turn', TokenUsageSnapshot::of(1_000_000, 0)));

        self::assertSame(10.0, $budgetTracker->costUsdUsed());
    }

    /**
     * @throws InvalidTokenUsageException
     */
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
     * @throws InvalidAuditBudgetException
     * @throws InvalidTokenUsageException
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

    /**
     * @throws BudgetExceededException
     * @throws InvalidAuditBudgetException
     * @throws InvalidTokenUsageException
     */
    public function test_cost_budget_is_not_falsely_exceeded_by_floating_point_accumulation_error(): void
    {
        $budgetTracker = $this->budgetTracker(AuditBudget::forCost(0.3), inputPrice: 10.0);

        for ($i = 0; $i < 3; ++$i) {
            $budgetTracker->recordCall(LLMResponse::of('x', 'gpt-4o', 'end_turn', TokenUsageSnapshot::of(10_000, 0)));
        }

        $budgetTracker->assertWithinBudget();

        self::assertSame(0.3, $budgetTracker->costUsdUsed());
    }

    /**
     * @throws BudgetExceededException
     * @throws InvalidAuditBudgetException
     * @throws InvalidTokenUsageException
     */
    public function test_cost_budget_is_not_falsely_exceeded_by_a_cap_with_finer_precision_than_the_rounding_grid(): void
    {
        $budgetTracker = $this->budgetTracker(AuditBudget::forCost(0.1234567), inputPrice: 0.1);

        $budgetTracker->recordCall(LLMResponse::of('x', 'gpt-4o', 'end_turn', TokenUsageSnapshot::of(1_234_566, 0)));
        $budgetTracker->assertWithinBudget();

        self::assertSame(0.123457, $budgetTracker->costUsdUsed());
    }

    /**
     * @throws BudgetExceededException
     * @throws InvalidAuditBudgetException
     * @throws InvalidTokenUsageException
     */
    public function test_cost_budget_threshold_is_rounded_to_six_decimals_not_five(): void
    {
        $budgetTracker = $this->budgetTracker(AuditBudget::forCost(0.1234567), inputPrice: 0.123459);

        $budgetTracker->recordCall(LLMResponse::of('x', 'gpt-4o', 'end_turn', TokenUsageSnapshot::of(1_000_000, 0)));
        self::assertSame(0.123459, $budgetTracker->costUsdUsed());

        $this->expectException(BudgetExceededException::class);
        $budgetTracker->assertWithinBudget();
    }

    /**
     * @throws InvalidTokenUsageException
     */
    public function test_cost_used_is_rounded_to_six_decimal_places(): void
    {
        $budgetTracker = $this->budgetTracker(AuditBudget::unlimited(), inputPrice: 0.7);

        $budgetTracker->recordCall(LLMResponse::of('x', 'gpt-4o', 'end_turn', TokenUsageSnapshot::of(1, 0)));

        self::assertSame(0.000001, $budgetTracker->costUsdUsed());
    }

    /**
     * @throws BudgetExceededException
     * @throws InvalidAuditBudgetException
     * @throws InvalidTokenUsageException
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

    /**
     * @throws InvalidTokenUsageException
     */
    public function test_cache_read_tokens_contribute_to_cost_at_the_cache_read_rate(): void
    {
        $budgetTracker = $this->budgetTracker(AuditBudget::unlimited(), cacheReadPrice: 1.0);

        $budgetTracker->recordCall(LLMResponse::of('x', 'claude-opus-4-7', 'end_turn', TokenUsageSnapshot::of(0, 0, 1_000_000, 0)));

        self::assertSame(1.0, $budgetTracker->costUsdUsed());
    }

    /**
     * @throws InvalidTokenUsageException
     */
    public function test_cache_creation_tokens_contribute_to_cost_at_the_cache_creation_rate(): void
    {
        $budgetTracker = $this->budgetTracker(AuditBudget::unlimited(), cacheCreationPrice: 12.5);

        $budgetTracker->recordCall(LLMResponse::of('x', 'claude-opus-4-7', 'end_turn', TokenUsageSnapshot::of(0, 0, 0, 1_000_000)));

        self::assertSame(12.5, $budgetTracker->costUsdUsed());
    }

    /**
     * @throws BudgetExceededException
     * @throws InvalidAuditBudgetException
     * @throws InvalidTokenUsageException
     */
    public function test_reset_clears_accumulated_tokens_and_cost(): void
    {
        $budgetTracker = $this->budgetTracker(AuditBudget::forTokens(100), inputPrice: 10.0);

        $budgetTracker->recordCall(LLMResponse::of('a', 'gpt-4o', 'end_turn', TokenUsageSnapshot::of(80, 10)));

        $budgetTracker->reset();

        self::assertSame(0, $budgetTracker->tokensUsed());
        self::assertSame(0.0, $budgetTracker->costUsdUsed());
        $budgetTracker->assertWithinBudget();
    }

    /**
     * @throws BudgetExceededException
     * @throws InvalidTokenUsageException
     */
    public function test_it_attributes_usage_to_the_model_of_each_call(): void
    {
        $budgetTracker = $this->splitModelBudgetTracker();

        $budgetTracker->recordCall(LLMResponse::of('x', 'claude-opus-5', 'end_turn', TokenUsageSnapshot::of(1_000_000, 200_000)));
        $budgetTracker->recordCall(LLMResponse::of('x', 'ollama/llama3.2', 'end_turn', TokenUsageSnapshot::of(500_000, 100_000)));

        self::assertSame([
            'claude-opus-5' => ['model' => 'claude-opus-5', 'input_tokens' => 1_000_000, 'output_tokens' => 200_000, 'cache_read_tokens' => 0, 'cache_creation_tokens' => 0, 'estimated_cost_usd' => 6.0],
            'ollama/llama3.2' => ['model' => 'ollama/llama3.2', 'input_tokens' => 500_000, 'output_tokens' => 100_000, 'cache_read_tokens' => 0, 'cache_creation_tokens' => 0, 'estimated_cost_usd' => 0.0],
        ], $budgetTracker->usageByModel());
    }

    /**
     * Cached prompt traffic accumulates the same way fresh input does: two
     * calls to one model must report the sum of both, not the last one and
     * not their difference.
     *
     * @throws BudgetExceededException
     * @throws InvalidTokenUsageException
     */
    public function test_it_sums_cached_prompt_tokens_across_repeated_calls(): void
    {
        $budgetTracker = $this->splitModelBudgetTracker();

        $budgetTracker->recordCall(LLMResponse::of('x', 'claude-opus-5', 'end_turn', TokenUsageSnapshot::of(0, 0, 300_000, 40_000)));
        $budgetTracker->recordCall(LLMResponse::of('x', 'claude-opus-5', 'end_turn', TokenUsageSnapshot::of(0, 0, 100_000, 10_000)));

        $usage = $budgetTracker->usageByModel()['claude-opus-5'];

        self::assertSame(400_000, $usage['cache_read_tokens']);
        self::assertSame(50_000, $usage['cache_creation_tokens']);
    }

    /**
     * @throws BudgetExceededException
     * @throws InvalidTokenUsageException
     */
    public function test_it_sums_repeated_calls_to_the_same_model(): void
    {
        $budgetTracker = $this->splitModelBudgetTracker();

        $budgetTracker->recordCall(LLMResponse::of('x', 'claude-opus-5', 'end_turn', TokenUsageSnapshot::of(1_000_000, 200_000)));
        $budgetTracker->recordCall(LLMResponse::of('x', 'claude-opus-5', 'end_turn', TokenUsageSnapshot::of(400_000, 50_000)));

        self::assertSame(
            ['model' => 'claude-opus-5', 'input_tokens' => 1_400_000, 'output_tokens' => 250_000, 'cache_read_tokens' => 0, 'cache_creation_tokens' => 0, 'estimated_cost_usd' => 7.95],
            $budgetTracker->usageByModel()['claude-opus-5'],
        );
    }

    /**
     * @throws BudgetExceededException
     * @throws InvalidTokenUsageException
     */
    public function test_reset_clears_the_per_model_attribution(): void
    {
        $budgetTracker = $this->splitModelBudgetTracker();
        $budgetTracker->recordCall(LLMResponse::of('x', 'claude-opus-5', 'end_turn', TokenUsageSnapshot::of(1_000_000, 0)));

        $budgetTracker->reset();

        self::assertSame([], $budgetTracker->usageByModel());
    }

    /** A tracker whose pricing provider knows `claude-opus-5` and prices everything else at zero, as an unlisted or self-hosted model does. */
    private function splitModelBudgetTracker(): BudgetTracker
    {
        $pricingProvider = new class implements CacheAwarePricingProviderInterface {
            #[Override]
            public function pricePerMillionInputTokens(string $model): float
            {
                return 'claude-opus-5' === $model ? 3.0 : 0.0;
            }

            #[Override]
            public function pricePerMillionOutputTokens(string $model): float
            {
                return 'claude-opus-5' === $model ? 15.0 : 0.0;
            }

            #[Override]
            public function cacheReadPricePerMillionTokens(string $model): float
            {
                return 0.0;
            }

            #[Override]
            public function cacheCreationPricePerMillionTokens(string $model): float
            {
                return 0.0;
            }

            #[Override]
            public function hasModel(string $model): bool
            {
                return 'claude-opus-5' === $model;
            }
        };

        return new BudgetTracker(AuditBudget::unlimited(), new CostCalculator($pricingProvider));
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
