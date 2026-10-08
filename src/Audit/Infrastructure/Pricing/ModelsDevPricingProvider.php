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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Pricing;

use Composer\InstalledVersions;
use OutOfBoundsException;
use Override;
use Psr\Log\LoggerInterface;
use Symfony\Component\Filesystem\Path;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\CacheAwarePricingProviderInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\ServingPlatformPricingProviderInterface;

/**
 * Sources per-million-token USD pricing (input/output and real prompt-cache
 * rates) from the daily `symfony/models-dev` catalog snapshot, read once from
 * `vendor/` with no network call. Replaces the hand-maintained price table.
 * A model is priced from the listing of the `symfony/ai` platform the audit
 * runs against first, and only then from the catalog at large. Each model's
 * price is resolved once per run and remembered, since every call asks for it
 * several times.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final class ModelsDevPricingProvider implements CacheAwarePricingProviderInterface, ServingPlatformPricingProviderInterface
{
    public const string CATALOG_PACKAGE = 'symfony/models-dev';

    public const string CATALOG_FILENAME = 'models-dev.json';

    /**
     * Official first-party provider keys, in resolution priority order. A bare
     * model id is priced only from these: aggregators and clouds re-list the
     * same id at a marked-up rate, so a bare lookup must never reach them.
     *
     * @var list<string>
     */
    private const array FIRST_PARTY_PROVIDERS = [
        'anthropic', 'openai', 'google', 'mistral', 'cohere', 'deepseek', 'perplexity', 'cerebras',
        'xai', 'moonshotai', 'alibaba', 'zai', 'llama', 'minimax', 'nvidia',
    ];

    /** @var array<string, true> */
    private array $warnedModels = [];

    /** @var array<array-key, mixed>|null */
    private ?array $catalog = null;

    /** @var array<string, ?ModelPrice> */
    private array $pricesByModel = [];

    /** @var array<string, ?ModelPrice> */
    private array $servingPlatformPricesByModel = [];

    private ?string $loadedCatalogPath = null;

    public function __construct(
        private readonly LoggerInterface $logger,
        private readonly ?string $catalogPath = null,
        private readonly string $catalogPackage = self::CATALOG_PACKAGE,
        private readonly ?string $platform = null,
    ) {}

    #[Override]
    public function pricePerMillionInputTokens(string $model): float
    {
        return $this->priced($model)->input;
    }

    #[Override]
    public function pricePerMillionOutputTokens(string $model): float
    {
        return $this->priced($model)->output;
    }

    #[Override]
    public function cacheReadPricePerMillionTokens(string $model): float
    {
        return $this->priced($model)->cacheRead;
    }

    #[Override]
    public function cacheCreationPricePerMillionTokens(string $model): float
    {
        return $this->priced($model)->cacheCreation;
    }

    #[Override]
    public function hasModel(string $model): bool
    {
        return $this->lookup($model) instanceof ModelPrice;
    }

    #[Override]
    public function hasServingPlatformPrice(string $model): bool
    {
        if (!$this->hasServingPlatformListing()) {
            return $this->hasModel($model);
        }

        return $this->servingPlatformPrice($model) instanceof ModelPrice;
    }

    private function priced(string $model): ModelPrice
    {
        $price = $this->lookup($model);
        if (!$price instanceof ModelPrice) {
            $this->warnUnknownModel($model);

            return new ModelPrice(0.0, 0.0, 0.0, 0.0);
        }

        return $price;
    }

    private function lookup(string $model): ?ModelPrice
    {
        if (!\array_key_exists($model, $this->pricesByModel)) {
            $this->pricesByModel[$model] = $this->servingPlatformPrice($model) ?? $this->priceFromCatalog($this->stripOptionsQueryString($model));
        }

        return $this->pricesByModel[$model];
    }

    private function servingPlatformPrice(string $model): ?ModelPrice
    {
        if (!\array_key_exists($model, $this->servingPlatformPricesByModel)) {
            $this->servingPlatformPricesByModel[$model] = $this->priceFromServingPlatform($this->stripOptionsQueryString($model));
        }

        return $this->servingPlatformPricesByModel[$model];
    }

    /**
     * A platform the catalog has no listing for leaves the catalog at large
     * as the only rate there is.
     */
    private function hasServingPlatformListing(): bool
    {
        if (null === $this->platform) {
            return false;
        }

        $provider = PlatformCatalogProviders::providerOf($this->platform);

        return null !== $provider && \array_key_exists($provider, $this->catalog());
    }

    /**
     * The platform the audit runs against bills at its own listed rate, which
     * an aggregator or another cloud re-listing the same id does not share.
     */
    private function priceFromServingPlatform(string $model): ?ModelPrice
    {
        if (null === $this->platform) {
            return null;
        }

        $provider = PlatformCatalogProviders::providerOf($this->platform);
        if (null === $provider) {
            return null;
        }

        foreach (PlatformCatalogProviders::listedIds($this->platform, $model) as $listedId) {
            $cost = $this->costEntry($provider, $listedId);
            if (null !== $cost) {
                return $this->toModelPrice($cost);
            }
        }

        return null;
    }

    private function priceFromCatalog(string $model): ?ModelPrice
    {
        $firstParty = $this->priceFromProviders($model, self::FIRST_PARTY_PROVIDERS);
        if ($firstParty instanceof ModelPrice) {
            return $firstParty;
        }

        if (!$this->isProviderQualified($model)) {
            return null;
        }

        return $this->priceFromProviders($model, $this->sortedProviderKeys());
    }

    /**
     * `docs/configuration.md`'s documented `model: 'name?temperature=0.2'`
     * query-string syntax (per `symfony/ai-bundle`'s own convention) reaches
     * this provider unparsed — `LLMConfiguration` and `ContainerParameterRegistrar`
     * both publish the model name verbatim, only `symfony/ai`'s own platform
     * factory ever splits it. Stripping everything from the first `?` before
     * every catalog lookup keeps a model configured this way priced the same
     * as its bare name.
     */
    private function stripOptionsQueryString(string $model): string
    {
        $withoutOptions = strstr($model, '?', true);

        return false === $withoutOptions ? $model : $withoutOptions;
    }

    /**
     * A qualified id can legitimately appear under several providers at once
     * (aggregators re-listing the same upstream model) with disagreeing
     * prices — an aggregator's stray `$0` free-tier listing must never win
     * over a genuinely paid one just because it sorts first, since that
     * would both under-report the real cost and, via `hasModel()` returning
     * `true`, silently bypass the "no published pricing" budget-guard safety
     * net. The first non-zero match wins; a fully free model (every match
     * genuinely `$0`) still prices at `$0`.
     *
     * @param list<int|string> $providers
     */
    private function priceFromProviders(string $model, array $providers): ?ModelPrice
    {
        $zeroPriceFallback = null;
        foreach ($providers as $provider) {
            $cost = $this->costEntry($provider, $model);
            if (null === $cost) {
                continue;
            }

            $modelPrice = $this->toModelPrice($cost);
            if (0.0 !== $modelPrice->input || 0.0 !== $modelPrice->output) {
                return $modelPrice;
            }

            $zeroPriceFallback ??= $modelPrice;
        }

        return $zeroPriceFallback;
    }

    /** @return array<array-key, mixed>|null */
    private function costEntry(int|string $provider, string $model): ?array
    {
        $providerData = $this->catalog()[$provider] ?? null;
        if (!\is_array($providerData)) {
            return null;
        }

        $models = $providerData['models'] ?? null;
        if (!\is_array($models)) {
            return null;
        }

        $entry = $models[$model] ?? null;
        if (!\is_array($entry)) {
            return null;
        }

        $cost = $entry['cost'] ?? null;

        return ModelsDevCatalog::isPricedCost($cost) ? $cost : null;
    }

    /** @param array<array-key, mixed> $cost */
    private function toModelPrice(array $cost): ModelPrice
    {
        $input = $this->numericOr($cost['input'] ?? null, 0.0);
        $output = $this->numericOr($cost['output'] ?? null, 0.0);
        $cacheRead = $this->numericOr($cost['cache_read'] ?? null, $input);
        $cacheCreation = $this->numericOr($cost['cache_write'] ?? null, $input);

        return new ModelPrice($input, $output, $cacheRead, $cacheCreation);
    }

    private function numericOr(mixed $value, float $fallback): float
    {
        return \is_int($value) || \is_float($value) ? $value : $fallback;
    }

    private function isProviderQualified(string $model): bool
    {
        if (str_contains($model, '/')) {
            return true;
        }

        foreach (explode('.', $model) as $segment) {
            if (\array_key_exists($segment, $this->catalog())) {
                return true;
            }
        }

        return false;
    }

    /** @return list<int|string> */
    private function sortedProviderKeys(): array
    {
        $keys = array_keys($this->catalog());
        sort($keys);

        return $keys;
    }

    /** @return array<array-key, mixed> */
    private function catalog(): array
    {
        return $this->catalog ??= $this->loadCatalog();
    }

    /** @return array<array-key, mixed> */
    private function loadCatalog(): array
    {
        $path = $this->preferredCatalogPath();
        $catalog = ModelsDevCatalog::fromFile($path);
        $packagedPath = $this->packagedCatalogPath();

        if (\is_string($catalog) && null !== $packagedPath && $path !== $packagedPath) {
            $this->logger->warning('Ignoring the unusable pricing catalog override; falling back to the packaged catalog', [
                'reason' => $catalog,
                'path' => $path,
            ]);
            $path = $packagedPath;
            $catalog = ModelsDevCatalog::fromFile($path);
        }

        if (\is_string($catalog)) {
            return $this->disablePricing($catalog, $path);
        }

        $this->loadedCatalogPath = $path;

        return $catalog;
    }

    /**
     * The catalog file this provider actually reads, so `doctor` can name it
     * instead of assuming the packaged one — a `self-update` refresh writes an
     * override that takes precedence, unless it cannot serve as a catalog, in
     * which case the packaged one is read in its place.
     */
    public function effectiveCatalogPath(): ?string
    {
        $this->catalog();

        return $this->loadedCatalogPath ?? $this->preferredCatalogPath();
    }

    /**
     * An override that does not exist yet falls through to the packaged
     * catalog rather than shadowing it, which is what makes the override
     * location safe to point at before anything writes there.
     */
    private function preferredCatalogPath(): ?string
    {
        if (null !== $this->catalogPath && is_file($this->catalogPath)) {
            return $this->catalogPath;
        }

        return $this->packagedCatalogPath() ?? $this->catalogPath;
    }

    /**
     * The catalog shipped with the installed `symfony/models-dev` package —
     * the only file whose contents `InstalledVersions::getPrettyVersion()`
     * actually describes, which is why `doctor` compares against it before
     * naming a version.
     *
     * `InstalledVersions::getInstallPath()` resolves relative to the Composer
     * directory, so it hands back a `vendor/composer/../symfony/...` detour.
     * `Path::canonicalize()` collapses it lexically — `realpath()` cannot, it
     * returns `false` for the `phar://` path a packaged binary reports.
     */
    public function packagedCatalogPath(): ?string
    {
        try {
            $installPath = InstalledVersions::getInstallPath($this->catalogPackage);
        } catch (OutOfBoundsException) {
            return null;
        }

        return null === $installPath ? null : Path::canonicalize(\sprintf('%s/%s', $installPath, self::CATALOG_FILENAME));
    }

    /** @return array<array-key, mixed> */
    private function disablePricing(string $reason, ?string $path): array
    {
        $this->logger->warning('models.dev pricing catalog unavailable; cost reporting disabled', [
            'reason' => $reason,
            'path' => $path,
        ]);

        return [];
    }

    private function warnUnknownModel(string $model): void
    {
        if (\array_key_exists($model, $this->warnedModels)) {
            return;
        }

        $this->warnedModels[$model] = true;
        $this->logger->warning('No pricing entry for LLM model — cost reporting will show zero', [
            'model' => $model,
        ]);
    }
}
