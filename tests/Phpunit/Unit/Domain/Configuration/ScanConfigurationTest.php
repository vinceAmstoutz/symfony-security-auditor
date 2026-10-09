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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Domain\Configuration;

use PHPUnit\Framework\TestCase;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Configuration\ScanConfiguration;

final class ScanConfigurationTest extends TestCase
{
    public function test_tracked_files_a_gitignore_matches_stay_out_of_the_scan_unless_asked_for(): void
    {
        $scanConfiguration = new ScanConfiguration(['src'], true, 512, true, []);

        self::assertFalse($scanConfiguration->includeTrackedIgnored);
    }

    public function test_tracked_files_a_gitignore_matches_join_the_scan_when_asked_for(): void
    {
        $scanConfiguration = new ScanConfiguration(['src'], true, 512, true, [], includeTrackedIgnored: true);

        self::assertTrue($scanConfiguration->includeTrackedIgnored);
    }
}
