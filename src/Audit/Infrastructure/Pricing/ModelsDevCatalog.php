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

use JsonException;

/**
 * What a decoded `symfony/models-dev` catalog must hold for the auditor to
 * price a call from it: one definition shared by the refresh that writes the
 * override and the provider that reads whichever catalog is in place.
 *
 * @phpstan-type PricedCost array{input: float|int, output?: mixed, cache_read?: mixed, cache_write?: mixed}
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class ModelsDevCatalog
{
    private const array OPTIONAL_RATES = ['output', 'cache_read', 'cache_write'];

    /**
     * @phpstan-assert-if-true PricedCost $cost
     */
    public static function isPricedCost(mixed $cost): bool
    {
        if (!\is_array($cost) || !self::isPrice($cost['input'] ?? null)) {
            return false;
        }

        foreach (self::OPTIONAL_RATES as $rate) {
            $value = $cost[$rate] ?? null;
            if (self::isNumber($value) && !self::isPrice($value)) {
                return false;
            }
        }

        return true;
    }

    /**
     * @return array<array-key, mixed>|string the catalog the file holds, or the reason it cannot serve as one
     */
    public static function fromFile(?string $path): array|string
    {
        $contents = null !== $path && is_file($path) ? file_get_contents($path) : false;
        if (false === $contents) {
            return 'catalog file not found or unreadable';
        }

        try {
            $decoded = json_decode($contents, true, flags: \JSON_THROW_ON_ERROR);
        } catch (JsonException) {
            return 'catalog JSON invalid';
        }

        if (!\is_array($decoded)) {
            return 'catalog root is not an object';
        }

        return self::containsPricedModel($decoded) ? $decoded : 'catalog carries no model pricing';
    }

    /**
     * Whether the catalog in `$path` is a strictly newer snapshot than the one
     * in `$otherPath`. One that cannot be read, or whose models carry no date,
     * is neither newer nor older than anything.
     */
    public static function isFileNewer(?string $path, ?string $otherPath): bool
    {
        $update = self::newestUpdateInFile($path);
        $otherUpdate = self::newestUpdateInFile($otherPath);

        if (null === $update || null === $otherUpdate) {
            return false;
        }

        return 0 < strcmp($update, $otherUpdate);
    }

    /**
     * The newest `last_updated` any model of the catalog carries: how fresh a
     * snapshot is, since the file itself holds no version. A catalog whose
     * models carry none has no date.
     *
     * @param array<array-key, mixed> $catalog
     */
    public static function newestUpdate(array $catalog): ?string
    {
        $updates = [];

        foreach ($catalog as $provider) {
            array_push($updates, ...self::providerUpdates($provider));
        }

        return [] === $updates ? null : max($updates);
    }

    private static function newestUpdateInFile(?string $path): ?string
    {
        $catalog = self::fromFile($path);

        return \is_array($catalog) ? self::newestUpdate($catalog) : null;
    }

    /**
     * A model whose cost is not a priced one keeps its entry but loses the
     * cost, which leaves it unpriced instead of billed at a rate nobody set.
     *
     * @param array<array-key, mixed> $catalog
     *
     * @return array<array-key, mixed>
     */
    public static function withoutInvalidCosts(array $catalog): array
    {
        return array_map(self::providerWithoutInvalidCosts(...), $catalog);
    }

    /**
     * @param array<array-key, mixed> $catalog
     */
    public static function containsPricedModel(array $catalog): bool
    {
        foreach ($catalog as $provider) {
            if (\is_array($provider) && self::providerPricesAnyModel($provider)) {
                return true;
            }
        }

        return false;
    }

    private static function providerWithoutInvalidCosts(mixed $provider): mixed
    {
        if (!\is_array($provider) || !\is_array($provider['models'] ?? null)) {
            return $provider;
        }

        $provider['models'] = array_map(self::modelWithoutInvalidCost(...), $provider['models']);

        return $provider;
    }

    private static function modelWithoutInvalidCost(mixed $model): mixed
    {
        if (\is_array($model) && !self::isPricedCost($model['cost'] ?? null)) {
            unset($model['cost']);
        }

        return $model;
    }

    /**
     * @return list<string>
     */
    private static function providerUpdates(mixed $provider): array
    {
        $models = \is_array($provider) ? ($provider['models'] ?? null) : null;
        if (!\is_array($models)) {
            return [];
        }

        $updates = [];
        foreach ($models as $model) {
            $update = \is_array($model) ? ($model['last_updated'] ?? null) : null;
            if (\is_string($update)) {
                $updates[] = $update;
            }
        }

        return $updates;
    }

    /**
     * @param array<array-key, mixed> $provider
     */
    private static function providerPricesAnyModel(array $provider): bool
    {
        $models = $provider['models'] ?? null;
        if (!\is_array($models)) {
            return false;
        }

        foreach ($models as $model) {
            if (\is_array($model) && self::isPricedCost($model['cost'] ?? null)) {
                return true;
            }
        }

        return false;
    }

    private static function isPrice(mixed $value): bool
    {
        return self::isNumber($value) && is_finite($value) && $value >= 0;
    }

    /**
     * @phpstan-assert-if-true int|float $value
     */
    private static function isNumber(mixed $value): bool
    {
        return \is_int($value) || \is_float($value);
    }
}
