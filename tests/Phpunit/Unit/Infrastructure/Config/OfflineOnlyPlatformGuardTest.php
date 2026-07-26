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
        yield 'scheme without host' => ['file:///etc/passwd'];
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
}
