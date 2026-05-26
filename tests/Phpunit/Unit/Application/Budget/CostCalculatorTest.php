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
}
