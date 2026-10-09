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
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\PlatformEndpoint;

final class PlatformEndpointTest extends TestCase
{
    #[DataProvider('endpointCases')]
    public function test_it_reads_the_scheme_host_and_port_of_a_url_with_an_authority(string $value, string $scheme, string $host, ?int $port): void
    {
        $platformEndpoint = PlatformEndpoint::tryFrom($value);

        self::assertInstanceOf(PlatformEndpoint::class, $platformEndpoint);
        self::assertSame($scheme, $platformEndpoint->scheme);
        self::assertSame($host, $platformEndpoint->host);
        self::assertSame($port, $platformEndpoint->port);
    }

    /**
     * @return iterable<string, array{string, string, string, ?int}>
     */
    public static function endpointCases(): iterable
    {
        yield 'a name' => ['https://gw.example/v1', 'https', 'gw.example', null];
        yield 'a name and a port' => ['http://localhost:11434', 'http', 'localhost', 11434];
        yield 'a bracketed address' => ['http://[::1]:11434', 'http', '[::1]', 11434];
        yield 'userinfo' => ['https://admin:hunter2@gw.example', 'https', 'gw.example', null];
        yield 'an empty host' => ['file:///etc/passwd', 'file', '', null];
    }

    #[DataProvider('notEndpointCases')]
    public function test_it_reads_nothing_from_a_value_that_is_not_a_url_with_an_authority(string $value): void
    {
        self::assertNotInstanceOf(PlatformEndpoint::class, PlatformEndpoint::tryFrom($value));
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function notEndpointCases(): iterable
    {
        yield 'a plain word' => ['llama3.2'];
        yield 'a scheme and no authority' => ['user:s3cretpassword'];
        yield 'an authority and no scheme' => ['//gw.example/v1'];
        yield 'an unterminated address' => ['http://[::1'];
        yield 'an empty string' => [''];
    }

    #[DataProvider('originCases')]
    public function test_it_quotes_only_the_scheme_host_and_port(string $value, string $origin): void
    {
        $platformEndpoint = PlatformEndpoint::tryFrom($value);

        self::assertInstanceOf(PlatformEndpoint::class, $platformEndpoint);
        self::assertSame($origin, $platformEndpoint->origin());
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function originCases(): iterable
    {
        yield 'without a port' => ['https://admin:hunter2@gw.example/v1?token=abc#frag', 'https://gw.example'];
        yield 'with a port' => ['https://admin:hunter2@gw.example:8443/v1?token=abc#frag', 'https://gw.example:8443'];
        yield 'with a bracketed address' => ['http://[::1]:11434/api', 'http://[::1]:11434'];
        yield 'with an empty host' => ['file:///etc/passwd', 'file://'];
    }
}
