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

use Override;

/**
 * Reads the models to offer from the catalog the run would price from: the
 * ten newest a platform's own listing prices and lists as calling tools.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class ModelsDevPricedModelList implements PricedModelListInterface
{
    private const int OFFERED_MODELS = 10;

    public function __construct(
        private ModelsDevPricingProvider $modelsDevPricingProvider,
    ) {}

    #[Override]
    public function pricedModels(string $platform): array
    {
        $releaseDates = [];
        foreach ($this->modelsDevPricingProvider->platformListing($platform) as $model => $listing) {
            if (\is_array($listing) && $this->isOffered($listing)) {
                $releaseDates[(string) $model] = $this->releaseDate($listing);
            }
        }

        arsort($releaseDates);

        return \array_slice(array_map(strval(...), array_keys($releaseDates)), 0, self::OFFERED_MODELS);
    }

    /** @param array<array-key, mixed> $listing */
    private function isOffered(array $listing): bool
    {
        return true === ($listing['tool_call'] ?? null) && ModelsDevCatalog::isPricedCost($listing['cost'] ?? null);
    }

    /** @param array<array-key, mixed> $listing */
    private function releaseDate(array $listing): string
    {
        $releaseDate = $listing['release_date'] ?? null;

        return \is_string($releaseDate) ? $releaseDate : '';
    }
}
