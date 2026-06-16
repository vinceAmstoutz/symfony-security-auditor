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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Infrastructure\Progress;

use PHPUnit\Framework\TestCase;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Progress\AuditOverviewLine;

final class AuditOverviewLineTest extends TestCase
{
    public function test_it_lists_every_non_zero_category(): void
    {
        $line = AuditOverviewLine::from(['files' => 21, 'controllers' => 15, 'voters' => 2, 'forms' => 4]);

        self::assertSame('Auditing 21 file(s) — 15 controller(s), 2 voter(s), 4 form(s)', $line);
    }

    public function test_it_omits_zero_count_categories(): void
    {
        $line = AuditOverviewLine::from(['files' => 21, 'controllers' => 15, 'voters' => 0, 'forms' => 0]);

        self::assertSame('Auditing 21 file(s) — 15 controller(s)', $line);
    }

    public function test_it_shows_only_the_file_count_when_no_category_has_a_count(): void
    {
        $line = AuditOverviewLine::from(['files' => 21, 'controllers' => 0, 'voters' => 0, 'forms' => 0]);

        self::assertSame('Auditing 21 file(s)', $line);
    }

    public function test_it_keeps_a_middle_category_when_its_neighbours_are_zero(): void
    {
        $line = AuditOverviewLine::from(['files' => 9, 'controllers' => 0, 'voters' => 3, 'forms' => 0]);

        self::assertSame('Auditing 9 file(s) — 3 voter(s)', $line);
    }
}
