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

    public function test_a_missing_catalog_package_disables_pricing_without_throwing(): void
    {
        $modelsDevPricingProvider = new ModelsDevPricingProvider($this->warningCapturingLogger(), null, 'vinceamstoutz/not-a-real-package');

        self::assertFalse($modelsDevPricingProvider->hasModel('claude-opus-4-8'));
        self::assertSame(0.0, $modelsDevPricingProvider->pricePerMillionInputTokens('claude-opus-4-8'));
        self::assertContains('models.dev pricing catalog unavailable; cost reporting disabled', array_column($this->loggedWarnings, 0));
    }

    private function providerForCatalog(string $fixture): ModelsDevPricingProvider
    {
        return new ModelsDevPricingProvider($this->warningCapturingLogger(), __DIR__.'/Fixture/'.$fixture);
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
