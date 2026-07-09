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
use JsonException;
use OutOfBoundsException;
use Override;
use Psr\Log\LoggerInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\CacheAwarePricingProviderInterface;

/**
 * Sources per-million-token USD pricing (input/output and real prompt-cache
 * rates) from the daily `symfony/models-dev` catalog snapshot, read once from
 * `vendor/` with no network call. Replaces the hand-maintained price table.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final class ModelsDevPricingProvider implements CacheAwarePricingProviderInterface
{
    private const string CATALOG_PACKAGE = 'symfony/models-dev';

    private const string CATALOG_FILENAME = 'models-dev.json';

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

    public function __construct(
        private readonly LoggerInterface $logger,
        private readonly ?string $catalogPath = null,
        private readonly string $catalogPackage = self::CATALOG_PACKAGE,
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
        $model = $this->stripOptionsQueryString($model);

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

    /** @param list<int|string> $providers */
    private function priceFromProviders(string $model, array $providers): ?ModelPrice
    {
        foreach ($providers as $provider) {
            $cost = $this->costEntry($provider, $model);
            if (null !== $cost) {
                return $this->toModelPrice($cost);
            }
        }

        return null;
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

        return \is_array($cost) ? $cost : null;
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
        $path = $this->catalogPath ?? $this->defaultCatalogPath();
        $contents = null !== $path && is_file($path) ? file_get_contents($path) : false;
        if (false === $contents) {
            return $this->disablePricing('catalog file not found or unreadable', $path);
        }

        try {
            $decoded = json_decode($contents, true, flags: \JSON_THROW_ON_ERROR);
        } catch (JsonException) {
            return $this->disablePricing('catalog JSON invalid', $path);
        }

        return \is_array($decoded) ? $decoded : $this->disablePricing('catalog root is not an object', $path);
    }

    private function defaultCatalogPath(): ?string
    {
        try {
            $installPath = InstalledVersions::getInstallPath($this->catalogPackage);
        } catch (OutOfBoundsException) {
            return null;
        }

        return null === $installPath ? null : \sprintf('%s/%s', $installPath, self::CATALOG_FILENAME);
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
