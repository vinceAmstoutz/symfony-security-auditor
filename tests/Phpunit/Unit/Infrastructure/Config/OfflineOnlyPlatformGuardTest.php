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

use Override;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\Exception\NonLocalPlatformEndpointException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\OfflineOnlyPlatformGuard;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\StandalonePlatformConfig;

final class OfflineOnlyPlatformGuardTest extends TestCase
{
    private OfflineOnlyPlatformGuard $offlineOnlyPlatformGuard;

    #[Override]
    protected function setUp(): void
    {
        $this->offlineOnlyPlatformGuard = new OfflineOnlyPlatformGuard();
    }

    /**
     * @throws NonLocalPlatformEndpointException
     */
    #[DataProvider('localEndpointCases')]
    public function test_it_accepts_a_platform_that_stays_on_this_machine(string $endpoint): void
    {
        $standalonePlatformConfig = new StandalonePlatformConfig(['ollama' => ['endpoint' => $endpoint]]);

        $this->offlineOnlyPlatformGuard->assertEveryPlatformIsLocal($standalonePlatformConfig);

        self::assertSame(['ollama' => ['endpoint' => $endpoint]], $standalonePlatformConfig->platform);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function localEndpointCases(): iterable
    {
        yield 'loopback name' => ['http://localhost:11434'];
        yield 'loopback ipv4' => ['http://127.0.0.1:11434'];
        yield 'loopback ipv6' => ['http://[::1]:11434'];
        yield 'private class a' => ['http://10.1.2.3:8080'];
        yield 'private class b' => ['http://172.16.4.5:8080'];
        yield 'private class c' => ['http://192.168.1.20:1234'];
        yield 'link local' => ['http://169.254.10.10:1234'];
        yield 'mdns host' => ['http://workstation.local:11434'];
        yield 'localhost subdomain' => ['http://models.localhost:11434'];
        yield 'uppercase host' => ['http://LOCALHOST:11434'];
        yield 'ipv4-mapped loopback' => ['http://[::ffff:127.0.0.1]:11434'];
        yield 'a percent-encoded path escaped for the container' => ['http://localhost:11434/v1%%2Fx%%3Fy'];
        yield 'credentials in front of a local host' => ['http://user:s3cretpassword@127.0.0.1:11434'];
    }

    /**
     * @throws NonLocalPlatformEndpointException
     */
    #[DataProvider('settingsThatAreNotEndpointsCases')]
    public function test_a_setting_that_is_not_an_endpoint_does_not_make_a_local_platform_remote(string $key, string $value): void
    {
        $standalonePlatformConfig = new StandalonePlatformConfig(['ollama' => ['endpoint' => 'http://localhost:11434', $key => $value]]);

        $this->offlineOnlyPlatformGuard->assertEveryPlatformIsLocal($standalonePlatformConfig);

        self::assertSame(['ollama' => ['endpoint' => 'http://localhost:11434', $key => $value]], $standalonePlatformConfig->platform);
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function settingsThatAreNotEndpointsCases(): iterable
    {
        yield 'an api key shaped like user:password' => ['api_key', 'user:s3cretpassword'];
        yield 'an api key with a dash, a digit and an underscore' => ['api_key', 'team-7:tok_abcdef123456'];
        yield 'an api key that is a secret store reference' => ['api_key', 'vault://kv/team-key'];
        yield 'a model name with a tag' => ['model', 'llama3.2:3b'];
        yield 'a mail address' => ['contact', 'mailto:ops@example.com'];
        yield 'a scheme with a path and no authority' => ['socket', 'unix:/var/run/ollama.sock'];
    }

    /**
     * @throws NonLocalPlatformEndpointException
     */
    #[DataProvider('remoteEndpointCases')]
    public function test_it_refuses_a_platform_that_would_leave_this_machine(string $endpoint): void
    {
        $this->expectException(NonLocalPlatformEndpointException::class);
        $this->expectExceptionMessage($endpoint);

        $this->offlineOnlyPlatformGuard->assertEveryPlatformIsLocal(
            new StandalonePlatformConfig(['azure' => ['base_url' => $endpoint]]),
        );
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function remoteEndpointCases(): iterable
    {
        yield 'public host name' => ['https://my-deployment.openai.azure.com'];
        yield 'public ipv4' => ['https://8.8.8.8:443'];
        yield 'public ipv6' => ['https://[2001:4860:4860::8888]:443'];
        yield 'ipv4-mapped public ipv6' => ['https://[::ffff:8.8.8.8]:443'];
        yield 'ipv4-mapped public ipv6 hex form' => ['https://[::ffff:808:808]:443'];
    }

    /**
     * @throws NonLocalPlatformEndpointException
     */
    #[DataProvider('quotedOriginCases')]
    public function test_a_refusal_quotes_the_origin_of_the_endpoint_and_nothing_else(string $endpoint, string $quotedOrigin): void
    {
        $this->expectException(NonLocalPlatformEndpointException::class);
        $this->expectExceptionMessage(\sprintf('would send your source code to "%s", which is not a loopback or private-range address.', $quotedOrigin));

        $this->offlineOnlyPlatformGuard->assertEveryPlatformIsLocal(
            new StandalonePlatformConfig(['generic' => ['gw' => ['base_url' => $endpoint]]]),
        );
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function quotedOriginCases(): iterable
    {
        yield 'no userinfo, port, path or query' => ['https://gw.example', 'https://gw.example'];
        yield 'userinfo, path, query and fragment' => ['https://admin:hunter2@gw.example/v1?token=abc#frag', 'https://gw.example'];
        yield 'a port' => ['https://gw.example:8443/v1/secret-path', 'https://gw.example:8443'];
        yield 'userinfo and a port on an address' => ['https://u:p@8.8.8.8:8080', 'https://8.8.8.8:8080'];
        yield 'a bracketed address and a port' => ['https://[2001:4860:4860::8888]:443/v1', 'https://[2001:4860:4860::8888]:443'];
        yield 'an authority without a host' => ['file:///etc/passwd', 'file://'];
        yield 'a percent sign escaped for the container' => ['https://gw.example/v1%%2Fx%%3Fy', 'https://gw.example'];
        yield 'a local looking name used as credentials' => ['http://localhost:11434@gw.example', 'http://gw.example'];
    }

    /**
     * @throws NonLocalPlatformEndpointException
     */
    public function test_an_endpoint_below_an_instance_named_like_the_api_key_is_still_inspected(): void
    {
        $this->expectException(NonLocalPlatformEndpointException::class);
        $this->expectExceptionMessage('to "https://remote.example.com"');

        $this->offlineOnlyPlatformGuard->assertEveryPlatformIsLocal(
            new StandalonePlatformConfig(['generic' => ['api_key' => ['base_url' => 'https://remote.example.com']]]),
        );
    }

    /**
     * @throws NonLocalPlatformEndpointException
     */
    public function test_it_refuses_a_hosted_provider_that_carries_no_endpoint_at_all(): void
    {
        $this->expectException(NonLocalPlatformEndpointException::class);
        $this->expectExceptionMessage('the "anthropic" platform is a hosted provider with no local endpoint configured');

        $this->offlineOnlyPlatformGuard->assertEveryPlatformIsLocal(
            new StandalonePlatformConfig(['anthropic' => ['api_key' => 'sk-secret']]),
        );
    }

    /**
     * @throws NonLocalPlatformEndpointException
     */
    public function test_it_refuses_a_provider_whose_configuration_is_not_a_map(): void
    {
        $this->expectException(NonLocalPlatformEndpointException::class);
        $this->expectExceptionMessage('"bedrock"');

        $this->offlineOnlyPlatformGuard->assertEveryPlatformIsLocal(
            new StandalonePlatformConfig(['bedrock' => null]),
        );
    }

    /**
     * @throws NonLocalPlatformEndpointException
     */
    public function test_it_inspects_endpoints_nested_below_the_provider_key(): void
    {
        $this->expectException(NonLocalPlatformEndpointException::class);
        $this->expectExceptionMessage('https://api.example.com');

        $this->offlineOnlyPlatformGuard->assertEveryPlatformIsLocal(
            new StandalonePlatformConfig(['generic' => ['default' => ['base_url' => 'https://api.example.com']]]),
        );
    }

    /**
     * @throws NonLocalPlatformEndpointException
     */
    public function test_it_refuses_as_soon_as_one_of_several_platforms_is_remote(): void
    {
        $this->expectException(NonLocalPlatformEndpointException::class);
        $this->expectExceptionMessage('"openai"');

        $this->offlineOnlyPlatformGuard->assertEveryPlatformIsLocal(
            new StandalonePlatformConfig([
                'ollama' => ['endpoint' => 'http://localhost:11434'],
                'openai' => ['api_key' => 'sk-secret'],
            ]),
        );
    }

    /**
     * @throws NonLocalPlatformEndpointException
     */
    public function test_a_non_url_setting_is_not_mistaken_for_an_endpoint(): void
    {
        $this->expectException(NonLocalPlatformEndpointException::class);
        $this->expectExceptionMessage('no local endpoint configured');

        $this->offlineOnlyPlatformGuard->assertEveryPlatformIsLocal(
            new StandalonePlatformConfig(['ollama' => ['model' => 'llama3.2', 'region' => 'eu-west-3']]),
        );
    }

    /**
     * @throws NonLocalPlatformEndpointException
     */
    public function test_a_setting_that_is_not_a_string_is_not_mistaken_for_an_endpoint(): void
    {
        $this->expectException(NonLocalPlatformEndpointException::class);
        $this->expectExceptionMessage('no local endpoint configured');

        $this->offlineOnlyPlatformGuard->assertEveryPlatformIsLocal(
            new StandalonePlatformConfig(['ollama' => ['timeout' => 30, 'verify' => true, 'proxy' => null]]),
        );
    }

    /**
     * @throws NonLocalPlatformEndpointException
     */
    public function test_every_endpoint_of_a_provider_must_be_local_not_just_the_first(): void
    {
        $this->expectException(NonLocalPlatformEndpointException::class);
        $this->expectExceptionMessage('https://fallback.example.com');

        $this->offlineOnlyPlatformGuard->assertEveryPlatformIsLocal(
            new StandalonePlatformConfig(['generic' => [
                'primary' => ['base_url' => 'http://127.0.0.1:1234'],
                'fallback' => ['base_url' => 'https://fallback.example.com'],
            ]]),
        );
    }

    /**
     * @throws NonLocalPlatformEndpointException
     */
    public function test_an_endpoint_found_before_a_nested_block_is_still_checked(): void
    {
        $this->expectException(NonLocalPlatformEndpointException::class);
        $this->expectExceptionMessage('https://remote.example.com');

        $this->offlineOnlyPlatformGuard->assertEveryPlatformIsLocal(
            new StandalonePlatformConfig(['generic' => [
                'base_url' => 'https://remote.example.com',
                'fallback' => ['base_url' => 'http://127.0.0.1:1234'],
            ]]),
        );
    }

    /**
     * @throws NonLocalPlatformEndpointException
     */
    public function test_every_endpoint_inside_one_nested_block_is_checked(): void
    {
        $this->expectException(NonLocalPlatformEndpointException::class);
        $this->expectExceptionMessage('https://remote.example.com');

        $this->offlineOnlyPlatformGuard->assertEveryPlatformIsLocal(
            new StandalonePlatformConfig(['generic' => ['default' => [
                'base_url' => 'http://127.0.0.1:1234',
                'fallback_url' => 'https://remote.example.com',
            ]]]),
        );
    }

    /**
     * @throws NonLocalPlatformEndpointException
     */
    public function test_an_empty_platform_map_has_nothing_to_refuse(): void
    {
        $standalonePlatformConfig = new StandalonePlatformConfig([]);

        $this->offlineOnlyPlatformGuard->assertEveryPlatformIsLocal($standalonePlatformConfig);

        self::assertSame([], $standalonePlatformConfig->platform);
    }

    /**
     * @param array<array-key, mixed> $platform
     */
    #[DataProvider('loopbackOnlyCases')]
    public function test_it_tells_a_platform_that_stays_on_the_loopback_interface_from_one_that_does_not(array $platform, bool $loopbackOnly): void
    {
        self::assertSame($loopbackOnly, $this->offlineOnlyPlatformGuard->reachesOnlyLoopback(new StandalonePlatformConfig($platform)));
    }

    /**
     * @return iterable<string, array{array<array-key, mixed>, bool}>
     */
    public static function loopbackOnlyCases(): iterable
    {
        yield 'a loopback name' => [['ollama' => ['endpoint' => 'http://localhost:11434']], true];
        yield 'a loopback ipv4 address' => [['ollama' => ['endpoint' => 'http://127.0.0.1:11434']], true];
        yield 'a loopback ipv6 address' => [['ollama' => ['endpoint' => 'http://[::1]:11434']], true];
        yield 'an endpoint below an instance' => [['generic' => ['gw' => ['base_url' => 'http://127.0.0.1:8080']]], true];
        yield 'credentials in front of a loopback host' => [['ollama' => ['endpoint' => 'http://user:s3cretpassword@127.0.0.1:11434']], true];
        yield 'two platforms on the loopback interface' => [['ollama' => ['endpoint' => 'http://localhost:11434'], 'lmstudio' => ['host_url' => 'http://127.0.0.1:1234']], true];
        yield 'a setting that is not an endpoint beside a loopback one' => [['ollama' => ['endpoint' => 'http://localhost:11434', 'api_key' => 'user:s3cretpassword']], true];
        yield 'a private-range address' => [['ollama' => ['endpoint' => 'http://192.168.1.20:11434']], false];
        yield 'a private network name' => [['ollama' => ['endpoint' => 'http://workstation.local:11434']], false];
        yield 'a private-range address below an instance' => [['generic' => ['gw' => ['base_url' => 'http://10.0.0.2:8080']]], false];
        yield 'a private-range address beside a loopback one' => [['ollama' => ['endpoint' => 'http://localhost:11434', 'base_url' => 'http://10.0.0.2:8080']], false];
        yield 'a private-range platform after a loopback one' => [['ollama' => ['endpoint' => 'http://localhost:11434'], 'lmstudio' => ['host_url' => 'http://192.168.1.20:1234']], false];
        yield 'a private-range platform before a loopback one' => [['lmstudio' => ['host_url' => 'http://192.168.1.20:1234'], 'ollama' => ['endpoint' => 'http://localhost:11434']], false];
        yield 'a provider whose configuration is not a map beside a loopback one' => [['bedrock' => null, 'ollama' => ['endpoint' => 'http://localhost:11434']], true];
    }
}
