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

use JsonException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Psr\Log\LoggerInterface;
use Stringable;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Pricing\ModelsDevPricingProvider;

final class ModelsDevPricingProviderTest extends TestCase
{
    /** @var list<array{0: string, 1: array<array-key, mixed>}> */
    private array $loggedWarnings = [];

    public function test_it_prices_a_known_first_party_model(): void
    {
        $modelsDevPricingProvider = $this->providerForCatalog('catalog.json');

        self::assertTrue($modelsDevPricingProvider->hasModel('claude-opus-4-8'));
        self::assertSame(5.0, $modelsDevPricingProvider->pricePerMillionInputTokens('claude-opus-4-8'));
        self::assertSame(25.0, $modelsDevPricingProvider->pricePerMillionOutputTokens('claude-opus-4-8'));
    }

    public function test_it_prices_a_model_name_carrying_the_documented_query_string_options_syntax(): void
    {
        $modelsDevPricingProvider = $this->providerForCatalog('catalog.json');

        self::assertTrue($modelsDevPricingProvider->hasModel('claude-opus-4-8?temperature=0.2'));
        self::assertSame(5.0, $modelsDevPricingProvider->pricePerMillionInputTokens('claude-opus-4-8?temperature=0.2'));
        self::assertSame(25.0, $modelsDevPricingProvider->pricePerMillionOutputTokens('claude-opus-4-8?temperature=0.2'));
    }

    public function test_it_prefers_first_party_over_aggregator_for_a_bare_id(): void
    {
        $modelsDevPricingProvider = $this->providerForCatalog('catalog.json');

        self::assertSame(5.0, $modelsDevPricingProvider->pricePerMillionInputTokens('claude-opus-4-8'));
        self::assertSame(25.0, $modelsDevPricingProvider->pricePerMillionOutputTokens('claude-opus-4-8'));
    }

    #[DataProvider('newerFirstPartyCases')]
    public function test_it_prices_a_bare_id_from_every_first_party_provider_in_the_catalog(string $model, float $expectedInputPrice): void
    {
        $modelsDevPricingProvider = $this->providerForCatalog('catalog.json');

        self::assertTrue($modelsDevPricingProvider->hasModel($model));
        self::assertSame($expectedInputPrice, $modelsDevPricingProvider->pricePerMillionInputTokens($model));
    }

    /** @return iterable<string, array{string, float}> */
    public static function newerFirstPartyCases(): iterable
    {
        yield 'xai grok' => ['grok-4', 2.0];
        yield 'moonshot kimi' => ['kimi-k2', 0.6];
    }

    public function test_a_bare_id_found_only_in_an_aggregator_is_not_priced(): void
    {
        $modelsDevPricingProvider = $this->providerForCatalog('catalog.json');

        self::assertFalse($modelsDevPricingProvider->hasModel('aggregator-only-model'));
        self::assertSame(0.0, $modelsDevPricingProvider->pricePerMillionInputTokens('aggregator-only-model'));
    }

    public function test_a_dotted_bare_id_found_only_in_an_aggregator_is_not_priced(): void
    {
        $modelsDevPricingProvider = $this->providerForCatalog('catalog.json');

        self::assertFalse($modelsDevPricingProvider->hasModel('gpt-5.5'));
        self::assertSame(0.0, $modelsDevPricingProvider->pricePerMillionInputTokens('gpt-5.5'));
    }

    public function test_it_returns_real_cache_rates_when_present(): void
    {
        $modelsDevPricingProvider = $this->providerForCatalog('catalog.json');

        self::assertSame(0.5, $modelsDevPricingProvider->cacheReadPricePerMillionTokens('claude-opus-4-8'));
        self::assertSame(6.25, $modelsDevPricingProvider->cacheCreationPricePerMillionTokens('claude-opus-4-8'));
    }

    public function test_it_falls_back_to_the_input_rate_when_cache_rates_are_absent(): void
    {
        $modelsDevPricingProvider = $this->providerForCatalog('catalog.json');

        self::assertSame(3.0, $modelsDevPricingProvider->cacheReadPricePerMillionTokens('claude-no-cache'));
        self::assertSame(3.0, $modelsDevPricingProvider->cacheCreationPricePerMillionTokens('claude-no-cache'));
    }

    public function test_it_falls_back_to_the_input_rate_when_cache_rates_are_present_but_not_numeric(): void
    {
        $modelsDevPricingProvider = $this->providerForCatalog('catalog.json');

        self::assertSame(4.0, $modelsDevPricingProvider->cacheReadPricePerMillionTokens('claude-bad-cache'));
        self::assertSame(4.0, $modelsDevPricingProvider->cacheCreationPricePerMillionTokens('claude-bad-cache'));
    }

    public function test_it_prices_a_model_listing_only_an_input_rate_with_a_free_output_and_cache_rates_at_the_input_rate(): void
    {
        $modelsDevPricingProvider = $this->providerForCatalog('input-only-cost.json');

        self::assertSame(3.0, $modelsDevPricingProvider->pricePerMillionInputTokens('claude-input-only'));
        self::assertSame(0.0, $modelsDevPricingProvider->pricePerMillionOutputTokens('claude-input-only'));
        self::assertSame(3.0, $modelsDevPricingProvider->cacheReadPricePerMillionTokens('claude-input-only'));
        self::assertSame(3.0, $modelsDevPricingProvider->cacheCreationPricePerMillionTokens('claude-input-only'));
    }

    public function test_it_resolves_a_provider_qualified_id_across_providers(): void
    {
        $modelsDevPricingProvider = $this->providerForCatalog('catalog.json');

        self::assertTrue($modelsDevPricingProvider->hasModel('anthropic.claude-opus-4-8'));
        self::assertSame(7.0, $modelsDevPricingProvider->pricePerMillionInputTokens('anthropic.claude-opus-4-8'));
        self::assertSame(28.0, $modelsDevPricingProvider->pricePerMillionOutputTokens('anthropic.claude-opus-4-8'));
        self::assertSame(0.7, $modelsDevPricingProvider->cacheReadPricePerMillionTokens('anthropic.claude-opus-4-8'));
    }

    /**
     * `qualified/free-tier-collision` is priced at $0 by `302ai` (alphabetically
     * first) and at $10/$20 by `zzz-collides-on-qualified-key` (alphabetically
     * last) — an aggregator's stray free-tier listing must never win over a
     * genuinely paid one for the same qualified id, since that would both
     * under-report the real cost and, via `hasModel()` returning `true`,
     * silently bypass `UnpricedModelBudgetGuard`'s "no published pricing"
     * safety net.
     */
    public function test_it_prefers_a_nonzero_price_over_an_alphabetically_earlier_zero_price_for_a_qualified_id(): void
    {
        $modelsDevPricingProvider = $this->providerForCatalog('catalog.json');

        self::assertTrue($modelsDevPricingProvider->hasModel('qualified/free-tier-collision'));
        self::assertSame(10.0, $modelsDevPricingProvider->pricePerMillionInputTokens('qualified/free-tier-collision'));
        self::assertSame(20.0, $modelsDevPricingProvider->pricePerMillionOutputTokens('qualified/free-tier-collision'));
    }

    public function test_a_partial_first_party_price_with_a_nonzero_input_wins_over_a_later_provider(): void
    {
        $modelsDevPricingProvider = $this->providerForCatalog('partial-and-free-collisions.json');

        self::assertSame(3.0, $modelsDevPricingProvider->pricePerMillionInputTokens('partial-price-probe'));
    }

    public function test_a_fully_free_model_keeps_the_first_providers_cache_rate_across_zero_priced_collisions(): void
    {
        $modelsDevPricingProvider = $this->providerForCatalog('partial-and-free-collisions.json');

        self::assertSame(0.25, $modelsDevPricingProvider->cacheReadPricePerMillionTokens('fully-free-probe'));
    }

    public function test_it_ignores_unrecognised_cost_fields(): void
    {
        $modelsDevPricingProvider = $this->providerForCatalog('catalog.json');

        self::assertSame(2.0, $modelsDevPricingProvider->pricePerMillionInputTokens('gpt-extra-fields'));
        self::assertSame(8.0, $modelsDevPricingProvider->pricePerMillionOutputTokens('gpt-extra-fields'));
        self::assertSame(0.2, $modelsDevPricingProvider->cacheReadPricePerMillionTokens('gpt-extra-fields'));
    }

    public function test_a_model_entry_without_a_cost_section_is_unpriced(): void
    {
        $modelsDevPricingProvider = $this->providerForCatalog('catalog.json');

        self::assertFalse($modelsDevPricingProvider->hasModel('llama-local'));
        self::assertSame(0.0, $modelsDevPricingProvider->pricePerMillionInputTokens('llama-local'));
    }

    public function test_a_provider_whose_models_section_is_not_an_object_is_skipped(): void
    {
        $modelsDevPricingProvider = $this->providerForCatalog('catalog.json');

        self::assertFalse($modelsDevPricingProvider->hasModel('gemini-2.5-flash'));
        self::assertSame(0.0, $modelsDevPricingProvider->pricePerMillionInputTokens('gemini-2.5-flash'));
    }

    public function test_a_non_numeric_cost_field_is_priced_as_zero(): void
    {
        $modelsDevPricingProvider = $this->providerForCatalog('catalog.json');

        self::assertSame(0.0, $modelsDevPricingProvider->pricePerMillionInputTokens('claude-weird-cost'));
        self::assertSame(0.0, $modelsDevPricingProvider->pricePerMillionOutputTokens('claude-weird-cost'));
    }

    #[DataProvider('invalidCostCases')]
    public function test_a_cost_that_is_not_a_finite_non_negative_price_with_an_input_rate_is_unpriced(string $model): void
    {
        $modelsDevPricingProvider = $this->providerForCatalog('invalid-costs.json');

        self::assertFalse($modelsDevPricingProvider->hasModel($model));
        self::assertSame(0.0, $modelsDevPricingProvider->pricePerMillionInputTokens($model));
        self::assertSame(0.0, $modelsDevPricingProvider->pricePerMillionOutputTokens($model));
    }

    /** @return iterable<string, array{string}> */
    public static function invalidCostCases(): iterable
    {
        yield 'a negative input rate' => ['negative-input-probe'];
        yield 'a slightly negative input rate' => ['negative-fractional-input-probe'];
        yield 'an infinite input rate' => ['infinite-input-probe'];
        yield 'no input rate' => ['missing-input-probe'];
        yield 'a textual input rate' => ['textual-input-probe'];
        yield 'a negative output rate' => ['negative-output-probe'];
        yield 'an infinite output rate' => ['infinite-output-probe'];
        yield 'a negative cache read rate' => ['negative-cache-read-probe'];
        yield 'a negative cache write rate' => ['negative-cache-write-probe'];
    }

    public function test_a_free_model_and_a_paid_model_stay_priced_beside_invalid_costs(): void
    {
        $modelsDevPricingProvider = $this->providerForCatalog('invalid-costs.json');

        self::assertTrue($modelsDevPricingProvider->hasModel('free-probe'));
        self::assertSame(0.0, $modelsDevPricingProvider->pricePerMillionInputTokens('free-probe'));
        self::assertTrue($modelsDevPricingProvider->hasModel('valid-probe'));
        self::assertSame(5.0, $modelsDevPricingProvider->pricePerMillionInputTokens('valid-probe'));
        self::assertSame(25.0, $modelsDevPricingProvider->pricePerMillionOutputTokens('valid-probe'));
    }

    public function test_an_invalid_cost_does_not_hide_a_valid_one_a_later_provider_lists(): void
    {
        $modelsDevPricingProvider = $this->providerForCatalog('invalid-costs.json');

        self::assertTrue($modelsDevPricingProvider->hasModel('shadowed-probe'));
        self::assertSame(3.0, $modelsDevPricingProvider->pricePerMillionInputTokens('shadowed-probe'));
        self::assertSame(6.0, $modelsDevPricingProvider->pricePerMillionOutputTokens('shadowed-probe'));
    }

    public function test_it_resolves_a_slash_namespaced_qualified_id(): void
    {
        $modelsDevPricingProvider = $this->providerForCatalog('catalog.json');

        self::assertTrue($modelsDevPricingProvider->hasModel('vertex_ai/gemini-flash'));
        self::assertSame(1.0, $modelsDevPricingProvider->pricePerMillionInputTokens('vertex_ai/gemini-flash'));
        self::assertSame(4.0, $modelsDevPricingProvider->pricePerMillionOutputTokens('vertex_ai/gemini-flash'));
    }

    public function test_it_resolves_a_cloud_region_prefixed_qualified_id(): void
    {
        $modelsDevPricingProvider = $this->providerForCatalog('catalog.json');

        self::assertTrue($modelsDevPricingProvider->hasModel('us.anthropic.claude-opus-4-8'));
        self::assertSame(6.0, $modelsDevPricingProvider->pricePerMillionInputTokens('us.anthropic.claude-opus-4-8'));
        self::assertSame(24.0, $modelsDevPricingProvider->pricePerMillionOutputTokens('us.anthropic.claude-opus-4-8'));
    }

    public function test_an_unknown_model_prices_zero(): void
    {
        $modelsDevPricingProvider = $this->providerForCatalog('catalog.json');

        self::assertFalse($modelsDevPricingProvider->hasModel('totally-unknown'));
        self::assertSame(0.0, $modelsDevPricingProvider->pricePerMillionInputTokens('totally-unknown'));
        self::assertSame(0.0, $modelsDevPricingProvider->pricePerMillionOutputTokens('totally-unknown'));
        self::assertSame(0.0, $modelsDevPricingProvider->cacheReadPricePerMillionTokens('totally-unknown'));
        self::assertSame(0.0, $modelsDevPricingProvider->cacheCreationPricePerMillionTokens('totally-unknown'));
    }

    public function test_an_unknown_model_is_warned_once_across_repeated_queries(): void
    {
        $modelsDevPricingProvider = $this->providerForCatalog('catalog.json');

        $modelsDevPricingProvider->pricePerMillionInputTokens('mystery-x');
        $modelsDevPricingProvider->pricePerMillionOutputTokens('mystery-x');
        $modelsDevPricingProvider->cacheReadPricePerMillionTokens('mystery-x');

        $modelWarnings = array_values(array_filter(
            $this->loggedWarnings,
            static fn (array $warning): bool => 'No pricing entry for LLM model — cost reporting will show zero' === $warning[0],
        ));
        self::assertCount(1, $modelWarnings);
        self::assertSame(['model' => 'mystery-x'], $modelWarnings[0][1]);
    }

    public function test_a_missing_catalog_file_disables_pricing_without_throwing(): void
    {
        $modelsDevPricingProvider = $this->providerForCatalog('does-not-exist.json');

        self::assertFalse($modelsDevPricingProvider->hasModel('claude-opus-4-8'));
        self::assertSame(0.0, $modelsDevPricingProvider->pricePerMillionInputTokens('claude-opus-4-8'));

        $context = $this->catalogUnavailableContext();
        self::assertSame('catalog file not found or unreadable', $context['reason']);
        self::assertIsString($context['path']);
        self::assertStringContainsString('does-not-exist.json', $context['path']);
    }

    public function test_a_malformed_catalog_disables_pricing_without_throwing(): void
    {
        $modelsDevPricingProvider = $this->providerForCatalog('malformed.json');

        self::assertFalse($modelsDevPricingProvider->hasModel('claude-opus-4-8'));
        self::assertSame(0.0, $modelsDevPricingProvider->pricePerMillionInputTokens('claude-opus-4-8'));

        $context = $this->catalogUnavailableContext();
        self::assertSame('catalog JSON invalid', $context['reason']);
        self::assertIsString($context['path']);
        self::assertStringContainsString('malformed.json', $context['path']);
    }

    public function test_a_non_object_catalog_root_disables_pricing_without_throwing(): void
    {
        $modelsDevPricingProvider = $this->providerForCatalog('not-object.json');

        self::assertFalse($modelsDevPricingProvider->hasModel('claude-opus-4-8'));
        self::assertSame('catalog root is not an object', $this->catalogUnavailableContext()['reason']);
    }

    /** @return array<array-key, mixed> */
    private function catalogUnavailableContext(): array
    {
        foreach ($this->loggedWarnings as $loggedWarning) {
            if ('models.dev pricing catalog unavailable; cost reporting disabled' === $loggedWarning[0]) {
                return $loggedWarning[1];
            }
        }

        self::fail('Expected a "catalog unavailable" warning but none was logged.');
    }

    public function test_a_missing_override_catalog_path_falls_back_to_the_default_catalog(): void
    {
        $modelsDevPricingProvider = new ModelsDevPricingProvider($this->warningCapturingLogger(), '/does/not/exist/models-dev.json');

        self::assertTrue($modelsDevPricingProvider->hasModel('claude-opus-4-8'));
        self::assertSame([], $this->loggedWarnings);
    }

    #[DataProvider('unusableOverrideCases')]
    public function test_an_unusable_override_falls_back_to_the_packaged_catalog(string $fixture, string $expectedReason): void
    {
        $modelsDevPricingProvider = $this->providerForCatalog($fixture, ModelsDevPricingProvider::CATALOG_PACKAGE);

        self::assertTrue($modelsDevPricingProvider->hasModel('claude-opus-4-8'));
        self::assertSame(5.0, $modelsDevPricingProvider->pricePerMillionInputTokens('claude-opus-4-8'));
        self::assertSame(
            [['Ignoring the unusable pricing catalog override; falling back to the packaged catalog', ['reason' => $expectedReason, 'path' => __DIR__.'/Fixture/'.$fixture]]],
            $this->loggedWarnings,
        );
    }

    /** @return iterable<string, array{string, string}> */
    public static function unusableOverrideCases(): iterable
    {
        yield 'malformed JSON' => ['malformed.json', 'catalog JSON invalid'];
        yield 'a root that is not an object' => ['not-object.json', 'catalog root is not an object'];
        yield 'a document that prices no model' => ['no-pricing.json', 'catalog carries no model pricing'];
    }

    public function test_it_names_the_packaged_catalog_as_the_one_in_use_when_the_override_is_unusable(): void
    {
        $modelsDevPricingProvider = $this->providerForCatalog('malformed.json', ModelsDevPricingProvider::CATALOG_PACKAGE);

        self::assertNotNull($modelsDevPricingProvider->packagedCatalogPath());
        self::assertSame($modelsDevPricingProvider->packagedCatalogPath(), $modelsDevPricingProvider->effectiveCatalogPath());
    }

    public function test_it_names_a_usable_override_as_the_one_in_use(): void
    {
        $modelsDevPricingProvider = $this->providerForCatalog('catalog.json', ModelsDevPricingProvider::CATALOG_PACKAGE);

        self::assertSame(__DIR__.'/Fixture/catalog.json', $modelsDevPricingProvider->effectiveCatalogPath());
        self::assertSame([], $this->loggedWarnings);
    }

    public function test_it_names_the_override_when_neither_catalog_can_be_read(): void
    {
        $modelsDevPricingProvider = $this->providerForCatalog('does-not-exist.json');

        self::assertSame(__DIR__.'/Fixture/does-not-exist.json', $modelsDevPricingProvider->effectiveCatalogPath());
    }

    public function test_an_unusable_override_and_an_unusable_packaged_catalog_disable_pricing_naming_the_packaged_one(): void
    {
        $modelsDevPricingProvider = $this->providerForCatalog('malformed.json', 'vinceamstoutz/symfony-security-auditor');

        self::assertFalse($modelsDevPricingProvider->hasModel('claude-opus-4-8'));
        self::assertCount(2, $this->loggedWarnings);
        self::assertSame('Ignoring the unusable pricing catalog override; falling back to the packaged catalog', $this->loggedWarnings[0][0]);
        self::assertSame(['reason' => 'catalog JSON invalid', 'path' => __DIR__.'/Fixture/malformed.json'], $this->loggedWarnings[0][1]);
        self::assertSame('models.dev pricing catalog unavailable; cost reporting disabled', $this->loggedWarnings[1][0]);
        self::assertSame(['reason' => 'catalog file not found or unreadable', 'path' => $modelsDevPricingProvider->packagedCatalogPath()], $this->loggedWarnings[1][1]);
    }

    public function test_an_unusable_packaged_catalog_is_not_read_a_second_time_as_a_fallback(): void
    {
        $modelsDevPricingProvider = $this->providerForCatalog('does-not-exist.json', 'vinceamstoutz/symfony-security-auditor');

        self::assertFalse($modelsDevPricingProvider->hasModel('claude-opus-4-8'));
        self::assertCount(1, $this->loggedWarnings);
        self::assertSame('models.dev pricing catalog unavailable; cost reporting disabled', $this->loggedWarnings[0][0]);
    }

    /**
     * `InstalledVersions::getInstallPath()` answers relative to the Composer
     * directory, so the raw join carries a `vendor/composer/../symfony/...`
     * detour that `doctor` would print verbatim at the user.
     */
    public function test_the_packaged_catalog_path_is_free_of_parent_directory_detours(): void
    {
        $packagedCatalogPath = (new ModelsDevPricingProvider($this->warningCapturingLogger()))->packagedCatalogPath();

        self::assertIsString($packagedCatalogPath);
        self::assertStringNotContainsString('/../', $packagedCatalogPath);
        self::assertStringNotContainsString('/composer/', $packagedCatalogPath);
        self::assertStringEndsWith('/symfony/models-dev/models-dev.json', $packagedCatalogPath);
    }

    public function test_a_missing_catalog_package_disables_pricing_without_throwing(): void
    {
        $modelsDevPricingProvider = new ModelsDevPricingProvider($this->warningCapturingLogger(), null, 'vinceamstoutz/not-a-real-package');

        self::assertFalse($modelsDevPricingProvider->hasModel('claude-opus-4-8'));
        self::assertSame(0.0, $modelsDevPricingProvider->pricePerMillionInputTokens('claude-opus-4-8'));
        self::assertContains('models.dev pricing catalog unavailable; cost reporting disabled', array_column($this->loggedWarnings, 0));
    }

    /**
     * @throws JsonException
     */
    public function test_it_memoizes_the_catalog_and_loads_it_only_once(): void
    {
        $tempFile = sys_get_temp_dir().'/models_dev_test_'.uniqid('', true).'.json';

        file_put_contents($tempFile, json_encode([
            'anthropic' => [
                'models' => [
                    'memoized-model' => [
                        'cost' => ['input' => 10.0, 'output' => 20.0],
                    ],
                ],
            ],
        ], \JSON_THROW_ON_ERROR));

        try {
            $modelsDevPricingProvider = new ModelsDevPricingProvider($this->warningCapturingLogger(), $tempFile);

            self::assertTrue($modelsDevPricingProvider->hasModel('memoized-model'));
            self::assertSame(10.0, $modelsDevPricingProvider->pricePerMillionInputTokens('memoized-model'));

            unlink($tempFile);

            self::assertTrue($modelsDevPricingProvider->hasModel('memoized-model'));
            self::assertSame(10.0, $modelsDevPricingProvider->pricePerMillionInputTokens('memoized-model'));
        } finally {
            if (file_exists($tempFile)) {
                unlink($tempFile);
            }
        }
    }

    #[DataProvider('servingPlatformCases')]
    public function test_it_prices_a_model_at_the_rate_of_the_platform_serving_it(string $platform, string $model, float $expectedInputPrice, float $expectedOutputPrice): void
    {
        $modelsDevPricingProvider = $this->providerServedBy($platform);

        self::assertTrue($modelsDevPricingProvider->hasModel($model));
        self::assertSame($expectedInputPrice, $modelsDevPricingProvider->pricePerMillionInputTokens($model));
        self::assertSame($expectedOutputPrice, $modelsDevPricingProvider->pricePerMillionOutputTokens($model));
    }

    /** @return iterable<string, array{string, string, float, float}> */
    public static function servingPlatformCases(): iterable
    {
        yield 'together over an aggregator listing the same id' => ['together', 'vendor/relisted-model', 2.0, 2.0];
        yield 'venice from its own listing' => ['venice', 'venice-uncensored', 0.5, 2.0];
        yield 'bedrock under the id as configured' => ['bedrock', 'nova-verbatim', 0.01, 0.02];
        yield 'bedrock nova under its versioned id' => ['bedrock', 'nova-micro', 0.035, 0.14];
        yield 'bedrock claude under its versioned id' => ['bedrock', 'claude-haiku-4-5-20251001', 1.0, 5.0];
        yield 'bedrock claude over the first-party rate' => ['bedrock', 'claude-opus-4-8', 7.0, 28.0];
        yield 'bedrock llama under its dashed, versioned id' => ['bedrock', 'llama-3.3-70b-instruct', 0.72, 0.72];
        yield 'a platform not listing the model falls back to first party' => ['azure', 'claude-opus-4-8', 5.0, 25.0];
        yield 'a platform with no listing of its own falls back to first party' => ['generic', 'claude-opus-4-8', 5.0, 25.0];
    }

    public function test_without_a_serving_platform_a_relisted_id_keeps_the_catalog_wide_rate(): void
    {
        self::assertSame(0.2, $this->providerForCatalog('platform-listings.json')->pricePerMillionInputTokens('vendor/relisted-model'));
    }

    public function test_without_a_serving_platform_a_model_only_that_platform_lists_is_unpriced(): void
    {
        self::assertFalse($this->providerForCatalog('platform-listings.json')->hasModel('venice-uncensored'));
    }

    public function test_the_serving_platform_free_listing_is_not_replaced_by_another_provider_paid_one(): void
    {
        $modelsDevPricingProvider = $this->providerServedBy('anthropic');

        self::assertTrue($modelsDevPricingProvider->hasModel('claude-promo'));
        self::assertSame(0.0, $modelsDevPricingProvider->pricePerMillionInputTokens('claude-promo'));
    }

    #[DataProvider('servingPlatformPriceCases')]
    public function test_it_tells_whether_the_serving_platform_prices_a_model(?string $platform, string $model, bool $expected): void
    {
        $modelsDevPricingProvider = null === $platform ? $this->providerForCatalog('platform-listings.json') : $this->providerServedBy($platform);

        self::assertSame($expected, $modelsDevPricingProvider->hasServingPlatformPrice($model));
    }

    /** @return iterable<string, array{?string, string, bool}> */
    public static function servingPlatformPriceCases(): iterable
    {
        yield 'a model the serving platform lists' => ['venice', 'venice-uncensored', true];
        yield 'a model the serving platform lists, with query-string options' => ['venice', 'venice-uncensored?temperature=0.2', true];
        yield 'a model the serving platform lists under another id' => ['bedrock', 'nova-micro', true];
        yield 'a model the serving platform lists for free' => ['anthropic', 'claude-promo', true];
        yield 'a model only another provider lists' => ['venice', 'claude-opus-4-8', false];
        yield 'a model only an aggregator relists' => ['venice', 'vendor/relisted-model', false];
        yield 'a known model on a platform with no listing of its own' => ['generic', 'claude-opus-4-8', true];
        yield 'an unknown model on a platform with no listing of its own' => ['generic', 'nobody-lists-this', false];
        yield 'a known model on a platform the catalog does not list' => ['cerebras', 'claude-opus-4-8', true];
        yield 'a known model with no serving platform' => [null, 'claude-opus-4-8', true];
        yield 'a model only a platform lists, with no serving platform' => [null, 'venice-uncensored', false];
    }

    public function test_a_model_the_serving_platform_does_not_list_keeps_its_catalog_wide_price(): void
    {
        $modelsDevPricingProvider = $this->providerServedBy('venice');

        self::assertFalse($modelsDevPricingProvider->hasServingPlatformPrice('claude-opus-4-8'));
        self::assertSame(5.0, $modelsDevPricingProvider->pricePerMillionInputTokens('claude-opus-4-8'));
    }

    private function providerServedBy(string $platform): ModelsDevPricingProvider
    {
        return new ModelsDevPricingProvider($this->warningCapturingLogger(), __DIR__.'/Fixture/platform-listings.json', 'vinceamstoutz/not-a-real-package', $platform);
    }

    private function providerForCatalog(string $fixture, string $package = 'vinceamstoutz/not-a-real-package'): ModelsDevPricingProvider
    {
        return new ModelsDevPricingProvider($this->warningCapturingLogger(), __DIR__.'/Fixture/'.$fixture, $package);
    }

    private function warningCapturingLogger(): LoggerInterface
    {
        $logger = self::createStub(LoggerInterface::class);
        $logger->method('warning')->willReturnCallback(
            function (string|Stringable $message, array $context = []): void {
                $this->loggedWarnings[] = [(string) $message, $context];
            },
        );

        return $logger;
    }
}
