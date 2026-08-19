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

/**
 * Refreshes the bundled `symfony/models-dev` pricing catalog after a
 * successful `self-update`. Never throws — a failed refresh must not fail
 * the self-update itself, only leave the pricing catalog as stale as it was.
 * The returned outcome lets `self-update` tell the user that cost figures
 * will keep coming from the catalog frozen into the binary.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
interface PricingCatalogRefresherInterface
{
    public function refresh(): PricingCatalogRefreshOutcome;
}
