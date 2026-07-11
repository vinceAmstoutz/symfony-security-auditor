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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Domain\Model;

use DateTimeImmutable;
use PHPUnit\Framework\TestCase;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ReportIdentity;

final class ReportIdentityTest extends TestCase
{
    public function test_duration_sums_days_hours_minutes_seconds_and_microseconds(): void
    {
        $reportIdentity = new ReportIdentity(
            'AUDIT-1',
            '/project',
            new DateTimeImmutable('2020-03-10 08:15:20.250000'),
            new DateTimeImmutable('2020-03-12 12:20:26.750000'),
            3,
        );

        self::assertSame(187_506.5, $reportIdentity->durationSeconds());
    }

    public function test_duration_is_sub_second_when_only_microseconds_elapse(): void
    {
        $reportIdentity = new ReportIdentity(
            'AUDIT-2',
            '/project',
            new DateTimeImmutable('2020-03-10 08:15:20.250000'),
            new DateTimeImmutable('2020-03-10 08:15:20.500000'),
            0,
        );

        self::assertSame(0.25, $reportIdentity->durationSeconds());
    }
}
