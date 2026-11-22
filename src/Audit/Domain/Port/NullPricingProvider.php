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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port;

use Override;

/**
 * Prices no model: a run on a subscription is not billed per call, so no API
 * rate may stand in for what it costs.
 *
 * @internal not part of the BC promise, see docs/versioning.md
 */
final readonly class NullPricingProvider implements PricingProviderInterface
{
    #[Override]
    public function pricePerMillionInputTokens(string $model): float
    {
        return 0.0;
    }

    #[Override]
    public function pricePerMillionOutputTokens(string $model): float
    {
        return 0.0;
    }

    #[Override]
    public function hasModel(string $model): bool
    {
        return false;
    }
}
