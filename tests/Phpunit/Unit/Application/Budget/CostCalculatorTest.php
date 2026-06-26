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
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Budget\CostCalculator;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\CacheAwarePricingProviderInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\PricingProviderInterface;

final class CostCalculatorTest extends TestCase
{
    public function test_cost_of_one_million_input_tokens_at_three_dollars_is_three_dollars(): void
    {
        $costCalculator = new CostCalculator($this->fixedPricing(3.0, 15.0));

        self::assertSame(3.000000, $costCalculator->costForCall(1_000_000, 0, 'model'));
    }

    public function test_cost_of_one_million_output_tokens_at_fifteen_dollars_is_fifteen_dollars(): void
    {
        $costCalculator = new CostCalculator($this->fixedPricing(3.0, 15.0));

        self::assertSame(15.000000, $costCalculator->costForCall(0, 1_000_000, 'model'));
    }

    public function test_cost_sums_input_and_output_components(): void
    {
        $costCalculator = new CostCalculator($this->fixedPricing(3.0, 15.0));

        self::assertSame(0.018, $costCalculator->costForCall(1_000, 1_000, 'model'));
    }

    public function test_zero_tokens_costs_zero(): void
    {
        $costCalculator = new CostCalculator($this->fixedPricing(3.0, 15.0));

        self::assertSame(0.0, $costCalculator->costForCall(0, 0, 'model'));
    }

    public function test_unknown_model_with_zero_pricing_costs_zero(): void
    {
        $costCalculator = new CostCalculator($this->fixedPricing(0.0, 0.0));

        self::assertSame(0.0, $costCalculator->costForCall(1_000_000, 1_000_000, 'unknown'));
    }

    public function test_cost_returns_raw_unrounded_value(): void
    {
        $costCalculator = new CostCalculator($this->fixedPricing(0.1, 0.4));

        // 7 input tokens @ 0.1/1M = 7e-7 = 0.0000007 (unrounded mathematically;
        // ~7.000000000000001e-7 due to float representation).
        self::assertEqualsWithDelta(7.0e-7, $costCalculator->costForCall(7, 0, 'model'), 1e-15);
    }

    public function test_cache_read_tokens_use_the_providers_cache_read_rate_when_cache_aware(): void
    {
        $costCalculator = new CostCalculator($this->cacheAwarePricing(3.0, 15.0, 0.5, 6.25));

        self::assertEqualsWithDelta(0.5, $costCalculator->costForCall(0, 0, 'model', 1_000_000, 0), 1e-12);
    }

    public function test_cache_creation_tokens_use_the_providers_cache_creation_rate_when_cache_aware(): void
    {
        $costCalculator = new CostCalculator($this->cacheAwarePricing(3.0, 15.0, 0.5, 6.25));

        self::assertEqualsWithDelta(6.25, $costCalculator->costForCall(0, 0, 'model', 0, 1_000_000), 1e-12);
    }

    public function test_cache_read_tokens_fall_back_to_the_input_rate_without_a_cache_aware_provider(): void
    {
        $costCalculator = new CostCalculator($this->fixedPricing(3.0, 15.0));

        self::assertEqualsWithDelta(3.0, $costCalculator->costForCall(0, 0, 'model', 1_000_000, 0), 1e-12);
    }

    public function test_cache_creation_tokens_fall_back_to_the_input_rate_without_a_cache_aware_provider(): void
    {
        $costCalculator = new CostCalculator($this->fixedPricing(3.0, 15.0));

        self::assertEqualsWithDelta(3.0, $costCalculator->costForCall(0, 0, 'model', 0, 1_000_000), 1e-12);
    }

    public function test_cost_sums_input_output_and_both_cache_components_with_cache_aware_rates(): void
    {
        $costCalculator = new CostCalculator($this->cacheAwarePricing(3.0, 15.0, 0.5, 6.25));

        self::assertEqualsWithDelta(0.02475, $costCalculator->costForCall(1_000, 1_000, 'model', 1_000, 1_000), 1e-12);
    }

    public function test_cache_tokens_default_to_zero_cost(): void
    {
        $costCalculator = new CostCalculator($this->fixedPricing(3.0, 15.0));

        self::assertEqualsWithDelta(0.003, $costCalculator->costForCall(1_000, 0, 'model'), 1e-12);
    }

    private function fixedPricing(float $inputPrice, float $outputPrice): PricingProviderInterface
    {
        return new class($inputPrice, $outputPrice) implements PricingProviderInterface {
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
    }

    private function cacheAwarePricing(
        float $inputPrice,
        float $outputPrice,
        float $cacheReadPrice,
        float $cacheCreationPrice,
    ): CacheAwarePricingProviderInterface {
        return new class($inputPrice, $outputPrice, $cacheReadPrice, $cacheCreationPrice) implements CacheAwarePricingProviderInterface {
            public function __construct(
                private readonly float $inputPrice,
                private readonly float $outputPrice,
                private readonly float $cacheReadPrice,
                private readonly float $cacheCreationPrice,
            ) {}

            public function pricePerMillionInputTokens(string $model): float
            {
                return $this->inputPrice;
            }

            public function pricePerMillionOutputTokens(string $model): float
            {
                return $this->outputPrice;
            }

            public function cacheReadPricePerMillionTokens(string $model): float
            {
                return $this->cacheReadPrice;
            }

            public function cacheCreationPricePerMillionTokens(string $model): float
            {
                return $this->cacheCreationPrice;
            }

            public function hasModel(string $model): bool
            {
                return true;
            }
        };
    }
}
