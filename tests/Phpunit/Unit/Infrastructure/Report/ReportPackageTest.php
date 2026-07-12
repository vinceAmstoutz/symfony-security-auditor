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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Infrastructure\Report;

use PHPUnit\Framework\TestCase;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Report\ReportPackage;

final class ReportPackageTest extends TestCase
{
    public function test_version_falls_back_to_unknown_when_the_package_is_not_registered_with_composer(): void
    {
        $reportPackage = new ReportPackage('vinceamstoutz/not-a-real-package');

        self::assertSame(ReportPackage::UNKNOWN_VERSION, $reportPackage->version());
    }
}
