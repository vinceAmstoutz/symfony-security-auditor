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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Infrastructure\Config;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\PlatformServiceId;

final class PlatformServiceIdTest extends TestCase
{
    #[DataProvider('instanceCases')]
    public function test_it_rejects_an_instance_the_container_cannot_name_a_service_by(string $instance, bool $expected): void
    {
        self::assertSame($expected, PlatformServiceId::accepts($instance));
    }

    /**
     * @return iterable<string, array{string, bool}>
     */
    public static function instanceCases(): iterable
    {
        yield 'an ordinary name is accepted' => ['my_gateway', true];
        yield 'a dot inside the name is accepted' => ['eu.west', true];
        yield 'a single quote is not allowed in a service id' => ["o'brien", false];
        yield 'a newline is not allowed either' => ["a\nb", false];
        yield 'nor is a carriage return' => ["a\rb", false];
        yield 'nor is a null byte' => ["a\0b", false];
        yield 'a trailing backslash escapes the id' => ['gw\\', false];
        yield 'a backslash elsewhere is fine' => ['gw\\eu', true];
    }
}
