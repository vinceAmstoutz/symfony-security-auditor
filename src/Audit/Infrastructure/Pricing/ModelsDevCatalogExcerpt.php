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

/**
 * Keeps only the model fields of a `symfony/models-dev` catalog the auditor
 * reads: cost, family, dates and tool support.
 *
 * @internal not part of the BC promise, see docs/versioning.md
 */
final readonly class ModelsDevCatalogExcerpt
{
    private const array READ_MODEL_FIELDS = ['cost' => true, 'family' => true, 'last_updated' => true, 'release_date' => true, 'tool_call' => true];

    /**
     * @param array<array-key, mixed> $catalog
     *
     * @return array<array-key, mixed>
     */
    public static function of(array $catalog): array
    {
        return array_map(self::provider(...), $catalog);
    }

    private static function provider(mixed $provider): mixed
    {
        if (!\is_array($provider) || !\is_array($provider['models'] ?? null)) {
            return $provider;
        }

        return ['models' => array_map(self::model(...), $provider['models'])];
    }

    private static function model(mixed $model): mixed
    {
        return \is_array($model) ? array_intersect_key($model, self::READ_MODEL_FIELDS) : $model;
    }
}
