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
 * @internal not part of the BC promise, see docs/versioning.md
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
        $pricedModels = [];
        $families = [];
        foreach ($this->modelsDevPricingProvider->platformListing($platform) as $model => $listing) {
            $pricedModel = \is_array($listing) ? $this->paidModelOffered((string) $model, $listing) : null;
            if ($pricedModel instanceof PricedModel) {
                $releaseDates[$model] = $this->releaseDate($listing);
                $pricedModels[$model] = $pricedModel;
                $families[$model] = $this->family((string) $model, $listing);
            }
        }

        arsort($releaseDates);

        $newestOfEachFamily = [];
        foreach (array_keys($releaseDates) as $model) {
            $newestOfEachFamily[$families[$model]] ??= $pricedModels[$model];
        }

        $offered = \array_slice($newestOfEachFamily, 0, self::OFFERED_MODELS);
        usort($offered, static fn (PricedModel $left, PricedModel $right): int => self::cost($right) <=> self::cost($left));

        return $offered;
    }

    private static function cost(PricedModel $pricedModel): float
    {
        return $pricedModel->inputPrice + ($pricedModel->outputPrice ?? 0.0);
    }

    /** @param array<array-key, mixed> $listing */
    private function family(string $model, array $listing): string
    {
        $family = $listing['family'] ?? null;

        return \is_string($family) ? $family : $model;
    }

    /** @param array<array-key, mixed> $listing */
    private function pricedModel(string $model, array $listing): PricedModel
    {
        $cost = (array) $listing['cost'];

        return new PricedModel($model, (float) $this->price($cost['input'] ?? null), $this->price($cost['output'] ?? null));
    }

    private function price(mixed $rate): ?float
    {
        return \is_int($rate) || \is_float($rate) ? $rate : null;
    }

    /** @param array<array-key, mixed> $listing */
    private function paidModelOffered(string $model, array $listing): ?PricedModel
    {
        if (!$this->isOffered($listing)) {
            return null;
        }

        $pricedModel = $this->pricedModel($model, $listing);

        return 0.0 < self::cost($pricedModel) ? $pricedModel : null;
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
