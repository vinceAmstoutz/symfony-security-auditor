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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Infrastructure\SelfUpdate;

use PHPUnit\Framework\TestCase;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\SelfUpdate\NullPricingCatalogRefresher;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\SelfUpdate\PricingCatalogRefreshOutcome;

final class NullPricingCatalogRefresherTest extends TestCase
{
    public function test_it_reports_a_skipped_refresh_so_self_update_stays_quiet(): void
    {
        self::assertSame(PricingCatalogRefreshOutcome::Skipped, (new NullPricingCatalogRefresher())->refresh());
    }
}
