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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Integration\Infrastructure\SelfUpdate\Fixture;

use Override;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\SelfUpdate\PricingCatalogRefresherInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\SelfUpdate\PricingCatalogRefreshOutcome;

final class RecordingPricingCatalogRefresher implements PricingCatalogRefresherInterface
{
    public int $refreshCount = 0;

    public function __construct(private readonly PricingCatalogRefreshOutcome $pricingCatalogRefreshOutcome = PricingCatalogRefreshOutcome::Refreshed) {}

    #[Override]
    public function refresh(): PricingCatalogRefreshOutcome
    {
        ++$this->refreshCount;

        return $this->pricingCatalogRefreshOutcome;
    }
}
