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

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilitySeverity;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Progress\SeverityColor;

final class SeverityColorTest extends TestCase
{
    #[DataProvider('colorCases')]
    public function test_it_maps_each_severity_to_a_console_color(VulnerabilitySeverity $vulnerabilitySeverity, string $expected): void
    {
        self::assertSame($expected, SeverityColor::for($vulnerabilitySeverity));
    }

    /** @return iterable<string, array{VulnerabilitySeverity, string}> */
    public static function colorCases(): iterable
    {
        yield 'critical' => [VulnerabilitySeverity::CRITICAL, 'red'];
        yield 'high' => [VulnerabilitySeverity::HIGH, 'bright-red'];
        yield 'medium' => [VulnerabilitySeverity::MEDIUM, 'yellow'];
        yield 'low' => [VulnerabilitySeverity::LOW, 'green'];
        yield 'info' => [VulnerabilitySeverity::INFO, 'blue'];
    }
}
