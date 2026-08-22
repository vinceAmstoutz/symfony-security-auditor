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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\SelfUpdate;

use Override;

/**
 * Used whenever refreshing the pricing catalog is not wanted — `privacy.offline_only`
 * is enabled, or the standalone configuration could not be read confidently
 * enough to know either way (self-update must not depend on a fully
 * resolved provider configuration).
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class NullPricingCatalogRefresher implements PricingCatalogRefresherInterface
{
    #[Override]
    public function refresh(): PricingCatalogRefreshOutcome
    {
        return PricingCatalogRefreshOutcome::Skipped;
    }
}
