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
 * Prices models in USD per million tokens from the installed
 * `symfony/models-dev` catalog, with no network call: from the serving
 * platform's listing first, then from the catalog at large. Remembers each
 * model's price for the run.
 *
 * @phpstan-import-type PricedCost from ModelsDevCatalog
 *
 * @internal not part of the BC promise, see docs/versioning.md
 */
final class ModelsDevPricingProvider implements CacheAwarePricingProviderInterface, ServingPlatformPricingProviderInterface
{
    public const string CATALOG_PACKAGE = 'symfony/models-dev';

    public const string CATALOG_FILENAME = 'models-dev.json';

    /**
     * First-party provider keys, in priority order. A bare model id is priced
     * only from these, never from an aggregator's marked-up listing.
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

    /**
     * Returns the models the catalog lists under `$platform`'s own provider.
     *
     * @return array<array-key, mixed>
     */
    public function platformListing(string $platform): array
    {
        $provider = PlatformCatalogProviders::providerOf($platform);

        return null === $provider ? [] : $this->arrayAt($this->arrayAt($this->catalog(), $provider), 'models');
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

    private function hasServingPlatformListing(): bool
    {
        if (null === $this->platform) {
            return false;
        }

        $provider = PlatformCatalogProviders::providerOf($this->platform);

        return null !== $provider && \array_key_exists($provider, $this->catalog());
    }

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
     * Drops the `?temperature=0.2` options of a configured model name, so it
     * prices as its bare name.
     */
    private function stripOptionsQueryString(string $model): string
    {
        $withoutOptions = strstr($model, '?', true);

        return false === $withoutOptions ? $model : $withoutOptions;
    }

    /**
     * Returns the first non-zero price, so an aggregator's `$0` listing never
     * hides a paid one nor bypasses the unpriced-model budget guard; `$0` only
     * when every match is free.
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

    /** @return PricedCost|null */
    private function costEntry(int|string $provider, string $model): ?array
    {
        $models = $this->arrayAt($this->arrayAt($this->catalog(), $provider), 'models');
        $cost = $this->arrayAt($models, $model)['cost'] ?? null;

        return ModelsDevCatalog::isPricedCost($cost) ? $cost : null;
    }

    /**
     * @param array<array-key, mixed> $array
     *
     * @return array<array-key, mixed>
     */
    private function arrayAt(array $array, int|string $key): array
    {
        $value = $array[$key] ?? null;

        return \is_array($value) ? $value : [];
    }

    /** @param PricedCost $cost */
    private function toModelPrice(array $cost): ModelPrice
    {
        $input = $cost['input'];
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
     * Returns the catalog file actually read: the `self-update` refresh,
     * unless it is unusable or older than the packaged catalog, which is read
     * then.
     */
    public function effectiveCatalogPath(): ?string
    {
        $this->catalog();

        return $this->loadedCatalogPath ?? $this->preferredCatalogPath();
    }

    private function preferredCatalogPath(): ?string
    {
        if (null !== $this->catalogPath && is_file($this->catalogPath) && !ModelsDevCatalog::isFileNewer($this->packagedCatalogPath(), $this->catalogPath)) {
            return $this->catalogPath;
        }

        return $this->packagedCatalogPath() ?? $this->catalogPath;
    }

    /**
     * Returns the catalog shipped with the installed `symfony/models-dev`
     * package, the one file its installed version describes. The path is
     * canonicalized lexically, since `realpath()` fails on a `phar://` path.
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
