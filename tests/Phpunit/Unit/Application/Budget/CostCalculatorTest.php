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
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Budget\CostCalculator;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\CacheAwarePricingProviderInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\PricingProviderInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\ServingPlatformPricingProviderInterface;

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

    public function test_cache_read_tokens_fall_back_to_the_anthropic_discount_for_claude_models_without_a_cache_aware_provider(): void
    {
        $costCalculator = new CostCalculator($this->fixedPricing(3.0, 15.0));

        self::assertEqualsWithDelta(0.3, $costCalculator->costForCall(0, 0, 'claude-opus-4-8', 1_000_000, 0), 1e-12);
    }

    public function test_cache_creation_tokens_fall_back_to_the_anthropic_surcharge_for_claude_models_without_a_cache_aware_provider(): void
    {
        $costCalculator = new CostCalculator($this->fixedPricing(3.0, 15.0));

        self::assertEqualsWithDelta(3.75, $costCalculator->costForCall(0, 0, 'claude-opus-4-8', 0, 1_000_000), 1e-12);
    }

    public function test_cache_aware_rates_win_over_the_claude_heuristic(): void
    {
        $costCalculator = new CostCalculator($this->cacheAwarePricing(3.0, 15.0, 0.5, 6.25));

        self::assertEqualsWithDelta(0.5, $costCalculator->costForCall(0, 0, 'claude-opus-4-8', 1_000_000, 0), 1e-12);
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

    #[DataProvider('billedModelCases')]
    public function test_it_bills_the_reported_model_only_when_the_pricing_source_knows_it(?string $reportedModel, string $expectedBilledModel): void
    {
        $costCalculator = new CostCalculator($this->pricingKnowing('listed-model'));

        self::assertSame($expectedBilledModel, $costCalculator->billedModel('configured-model', $reportedModel));
    }

    /** @return iterable<string, array{?string, string}> */
    public static function billedModelCases(): iterable
    {
        yield 'a listed reported model' => ['listed-model', 'listed-model'];
        yield 'an unlisted reported model' => ['gateway-internal-id', 'configured-model'];
        yield 'no reported model' => [null, 'configured-model'];
    }

    #[DataProvider('servingPlatformBilledModelCases')]
    public function test_it_bills_the_reported_model_only_when_the_serving_platform_prices_it(string $reportedModel, string $expectedBilledModel): void
    {
        $costCalculator = new CostCalculator($this->pricingServing('served-model'));

        self::assertSame($expectedBilledModel, $costCalculator->billedModel('configured-model', $reportedModel));
    }

    /** @return iterable<string, array{string, string}> */
    public static function servingPlatformBilledModelCases(): iterable
    {
        yield 'a reported model the serving platform prices' => ['served-model', 'served-model'];
        yield 'a reported model only another provider prices' => ['relisted-model', 'configured-model'];
    }

    private function pricingServing(string $servedModel): ServingPlatformPricingProviderInterface
    {
        return new class($servedModel) implements ServingPlatformPricingProviderInterface {
            public function __construct(private readonly string $servedModel) {}

            #[Override]
            public function pricePerMillionInputTokens(string $model): float
            {
                return 1.0;
            }

            #[Override]
            public function pricePerMillionOutputTokens(string $model): float
            {
                return 1.0;
            }

            #[Override]
            public function hasModel(string $model): bool
            {
                return true;
            }

            #[Override]
            public function hasServingPlatformPrice(string $model): bool
            {
                return $this->servedModel === $model;
            }
        };
    }

    private function pricingKnowing(string $knownModel): PricingProviderInterface
    {
        return new class($knownModel) implements PricingProviderInterface {
            public function __construct(private readonly string $knownModel) {}

            #[Override]
            public function pricePerMillionInputTokens(string $model): float
            {
                return 1.0;
            }

            #[Override]
            public function pricePerMillionOutputTokens(string $model): float
            {
                return 1.0;
            }

            #[Override]
            public function hasModel(string $model): bool
            {
                return $this->knownModel === $model;
            }
        };
    }

    private function fixedPricing(float $inputPrice, float $outputPrice): PricingProviderInterface
    {
        return new class($inputPrice, $outputPrice) implements PricingProviderInterface {
            public function __construct(
                private readonly float $inputPrice,
                private readonly float $outputPrice,
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
    }
}
