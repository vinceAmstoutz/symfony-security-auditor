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

    #[DataProvider('loopbackCases')]
    public function test_it_tells_a_loopback_host_from_every_other_one(string $value, bool $loopback): void
    {
        $platformEndpoint = PlatformEndpoint::tryFrom($value);

        self::assertInstanceOf(PlatformEndpoint::class, $platformEndpoint);
        self::assertSame($loopback, $platformEndpoint->isLoopback());
    }

    /**
     * @return iterable<string, array{string, bool}>
     */
    public static function loopbackCases(): iterable
    {
        yield 'localhost' => ['http://localhost:11434', true];
        yield 'localhost in capitals' => ['http://LOCALHOST:11434', true];
        yield 'the ipv4 loopback address' => ['http://127.0.0.1:11434', true];
        yield 'the first address of the ipv4 loopback block' => ['http://127.0.0.0:11434', true];
        yield 'the last address of the ipv4 loopback block' => ['http://127.255.255.255:11434', true];
        yield 'the ipv6 loopback address' => ['http://[::1]:11434', true];
        yield 'the ipv6 loopback address in full' => ['http://[0:0:0:0:0:0:0:1]:11434', true];
        yield 'the address below the ipv4 loopback block' => ['http://126.255.255.255:11434', false];
        yield 'the address above the ipv4 loopback block' => ['http://128.0.0.0:11434', false];
        yield 'an ipv6 address starting with the loopback byte' => ['http://[7f00::1]:11434', false];
        yield 'the ipv6 address next to the loopback one' => ['http://[::2]:11434', false];
        yield 'the unspecified ipv4 address' => ['http://0.0.0.0:11434', false];
        yield 'the unspecified ipv6 address' => ['http://[::]:11434', false];
        yield 'a private class a address' => ['http://10.1.2.3:8080', false];
        yield 'a private class b address' => ['http://172.16.4.5:8080', false];
        yield 'a private class c address' => ['http://192.168.1.20:1234', false];
        yield 'a link-local address' => ['http://169.254.10.10:1234', false];
        yield 'a public address' => ['https://8.8.8.8:443', false];
        yield 'an mdns name' => ['http://workstation.local:11434', false];
        yield 'a name under localhost' => ['http://models.localhost:11434', false];
        yield 'a name starting with localhost' => ['http://localhost.example.com:11434', false];
        yield 'a public name' => ['https://gw.example/v1', false];
        yield 'an ipv4-mapped loopback address' => ['http://[::ffff:127.0.0.1]:11434', false];
        yield 'an empty host' => ['file:///etc/passwd', false];
    }
}
