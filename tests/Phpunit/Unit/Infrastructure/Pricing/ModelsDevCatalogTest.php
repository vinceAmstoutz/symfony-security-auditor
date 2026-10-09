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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Infrastructure\Pricing;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Pricing\ModelsDevCatalog;

final class ModelsDevCatalogTest extends TestCase
{
    #[DataProvider('pricedCosts')]
    public function test_it_accepts_a_cost_with_finite_non_negative_rates_and_an_input_rate(mixed $cost): void
    {
        self::assertTrue(ModelsDevCatalog::isPricedCost($cost));
    }

    /** @return iterable<string, array{array<string, mixed>}> */
    public static function pricedCosts(): iterable
    {
        yield 'integer rates' => [['input' => 5, 'output' => 25]];
        yield 'fractional rates' => [['input' => 0.132, 'output' => 1.254, 'cache_read' => 0.01, 'cache_write' => 0.165]];
        yield 'a free model' => [['input' => 0, 'output' => 0]];
        yield 'an input rate alone' => [['input' => 3]];
        yield 'a non-numeric optional rate' => [['input' => 4, 'output' => 8, 'cache_read' => 'free', 'cache_write' => null]];
        yield 'tiered rates the auditor does not read' => [['input' => 5, 'output' => 25, 'tiers' => [['input' => -1]], 'context_over_200k' => ['input' => -1]]];
    }

    #[DataProvider('unpricedCosts')]
    public function test_it_refuses_a_cost_that_is_not_a_finite_non_negative_price_with_an_input_rate(mixed $cost): void
    {
        self::assertFalse(ModelsDevCatalog::isPricedCost($cost));
    }

    /** @return iterable<string, array{mixed}> */
    public static function unpricedCosts(): iterable
    {
        yield 'no cost' => [null];
        yield 'a scalar cost' => [5];
        yield 'an empty cost' => [[]];
        yield 'no input rate' => [['output' => 25]];
        yield 'a null input rate' => [['input' => null, 'output' => 25]];
        yield 'a numeric string input rate' => [['input' => '5', 'output' => 25]];
        yield 'a negative integer input rate' => [['input' => -1]];
        yield 'a slightly negative input rate' => [['input' => -0.01]];
        yield 'an infinite input rate' => [['input' => \INF]];
        yield 'a negative infinite input rate' => [['input' => -\INF]];
        yield 'a NaN input rate' => [['input' => \NAN]];
        yield 'a negative output rate' => [['input' => 5, 'output' => -0.01]];
        yield 'an infinite output rate' => [['input' => 5, 'output' => \INF]];
        yield 'a negative cache read rate' => [['input' => 5, 'cache_read' => -0.01]];
        yield 'an infinite cache read rate' => [['input' => 5, 'cache_read' => \INF]];
        yield 'a negative cache write rate' => [['input' => 5, 'cache_write' => -0.01]];
        yield 'an infinite cache write rate' => [['input' => 5, 'cache_write' => \INF]];
    }

    /** @param array<array-key, mixed> $catalog */
    #[DataProvider('catalogsWithUpdates')]
    public function test_it_reads_the_newest_update_any_model_carries(array $catalog, ?string $expected): void
    {
        self::assertSame($expected, ModelsDevCatalog::newestUpdate($catalog));
    }

    /** @return iterable<string, array{array<array-key, mixed>, ?string}> */
    public static function catalogsWithUpdates(): iterable
    {
        yield 'the last of several in ascending order' => [['p' => ['models' => ['a' => ['last_updated' => '2026-01-01'], 'b' => ['last_updated' => '2026-03-05']]]], '2026-03-05'];
        yield 'the first of several in descending order' => [['p' => ['models' => ['a' => ['last_updated' => '2026-03-05'], 'b' => ['last_updated' => '2026-01-01']]]], '2026-03-05'];
        yield 'the newest of the middle' => [['p' => ['models' => ['a' => ['last_updated' => '2026-01-01'], 'b' => ['last_updated' => '2026-03-05'], 'c' => ['last_updated' => '2026-02-02']]]], '2026-03-05'];
        yield 'one provider after another' => [['p' => ['models' => ['a' => ['last_updated' => '2026-03-05']]], 'q' => ['models' => ['b' => ['last_updated' => '2026-04-01']]], 'r' => ['models' => ['c' => ['last_updated' => '2026-02-02']]]], '2026-04-01'];
        yield 'a day after the same month alone' => [['p' => ['models' => ['a' => ['last_updated' => '2026-06'], 'b' => ['last_updated' => '2026-06-09']]]], '2026-06-09'];
        yield 'a month alone before the same month, a day later' => [['p' => ['models' => ['a' => ['last_updated' => '2026-06-09'], 'b' => ['last_updated' => '2026-06']]]], '2026-06-09'];
        yield 'only a model with a date string counts' => [['p' => ['models' => [
            'none' => ['id' => 'none'],
            'null' => ['last_updated' => null],
            'number' => ['last_updated' => 20261231],
            'list' => ['last_updated' => ['2026-12-31']],
            'text' => 'not a model',
            'dated' => ['last_updated' => '2026-01-01'],
        ]]], '2026-01-01'];
        yield 'providers without models are skipped' => [[
            'notes' => 'not a provider',
            'bare' => ['name' => 'Bare'],
            'listing' => ['models' => 'not a map'],
            'dated' => ['models' => ['a' => ['last_updated' => '2026-01-01']]],
        ], '2026-01-01'];
        yield 'no model carries a date' => [['p' => ['models' => ['a' => ['id' => 'a']]]], null];
        yield 'an empty catalog' => [[], null];
    }

    public function test_it_drops_only_the_costs_that_are_not_priced(): void
    {
        $catalog = [
            'anthropic' => ['name' => 'Anthropic', 'models' => [
                'paid' => ['cost' => ['input' => 5, 'output' => 25]],
                'broken' => ['id' => 'broken', 'cost' => ['input' => -5]],
                'listed' => ['id' => 'listed'],
                'not-a-model' => 'text',
            ]],
            'aggregator' => ['models' => 'not a map'],
            'notes' => 'not a provider',
        ];

        self::assertSame(
            [
                'anthropic' => ['name' => 'Anthropic', 'models' => [
                    'paid' => ['cost' => ['input' => 5, 'output' => 25]],
                    'broken' => ['id' => 'broken'],
                    'listed' => ['id' => 'listed'],
                    'not-a-model' => 'text',
                ]],
                'aggregator' => ['models' => 'not a map'],
                'notes' => 'not a provider',
            ],
            ModelsDevCatalog::withoutInvalidCosts($catalog),
        );
    }

    /** @param array<array-key, mixed> $catalog */
    #[DataProvider('catalogsPricingAModel')]
    public function test_it_tells_a_catalog_that_prices_a_model(array $catalog): void
    {
        self::assertTrue(ModelsDevCatalog::containsPricedModel($catalog));
    }

    /** @return iterable<string, array{array<array-key, mixed>}> */
    public static function catalogsPricingAModel(): iterable
    {
        yield 'a priced model' => [['anthropic' => ['models' => ['m' => ['cost' => ['input' => 1]]]]]];
        yield 'a priced model after unpriced ones' => [[
            'notes' => 'text',
            'empty' => ['models' => 'not a map'],
            'anthropic' => ['models' => ['text', ['cost' => ['input' => -1]], ['id' => 'x'], ['cost' => ['input' => 0]]]],
        ]];
        yield 'a priced model under a later provider' => [[
            'first' => ['models' => ['m' => ['id' => 'm']]],
            'second' => ['models' => ['m' => ['cost' => ['input' => 2]]]],
        ]];
    }

    /** @param array<array-key, mixed> $catalog */
    #[DataProvider('catalogsPricingNoModel')]
    public function test_it_tells_a_catalog_that_prices_no_model(array $catalog): void
    {
        self::assertFalse(ModelsDevCatalog::containsPricedModel($catalog));
    }

    /** @return iterable<string, array{array<array-key, mixed>}> */
    public static function catalogsPricingNoModel(): iterable
    {
        yield 'an empty catalog' => [[]];
        yield 'a document that is not a catalog' => [['message' => 'Not Found']];
        yield 'a provider without models' => [['anthropic' => ['api' => 'https://api.anthropic.com']]];
        yield 'models that are not a map' => [['anthropic' => ['models' => 'none']]];
        yield 'a model without a cost' => [['anthropic' => ['models' => ['m' => ['id' => 'm']]]]];
        yield 'a model whose cost has no input rate' => [['anthropic' => ['models' => ['m' => ['cost' => ['output' => 25]]]]]];
        yield 'a model whose cost is negative' => [['anthropic' => ['models' => ['m' => ['cost' => ['input' => -1]]]]]];
    }
}
