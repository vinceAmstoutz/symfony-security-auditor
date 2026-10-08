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
