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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config;

use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\Exception\NonLocalPlatformEndpointException;

/**
 * Fails a `privacy.offline_only` run before it boots unless every configured
 * platform carries a URL and every URL names a loopback, link-local or
 * private-range host. A platform whose only endpoint a dry run read from an
 * unset variable is not judged.
 *
 * @internal not part of the BC promise, see docs/versioning.md
 */
final readonly class OfflineOnlyPlatformGuard
{
    /**
     * @throws NonLocalPlatformEndpointException
     */
    public function assertEveryPlatformIsLocal(StandalonePlatformConfig $standalonePlatformConfig): void
    {
        foreach ($standalonePlatformConfig->platform as $provider => $providerConfig) {
            $this->assertProviderIsLocal((string) $provider, \is_array($providerConfig) ? $providerConfig : []);
        }
    }

    /**
     * True when every endpoint of every configured platform is on the loopback
     * interface.
     */
    public function reachesOnlyLoopback(StandalonePlatformConfig $standalonePlatformConfig): bool
    {
        foreach ($this->endpointsIn($standalonePlatformConfig->platform) as $platformEndpoint) {
            if (!$platformEndpoint->isLoopback()) {
                return false;
            }
        }

        return true;
    }

    /**
     * @param array<array-key, mixed> $providerConfig
     *
     * @throws NonLocalPlatformEndpointException
     */
    private function assertProviderIsLocal(string $provider, array $providerConfig): void
    {
        $endpoints = $this->endpointsIn($providerConfig);

        if ([] === $endpoints && !$this->holdsAnUnresolvedSetting($providerConfig)) {
            throw NonLocalPlatformEndpointException::forProviderWithoutEndpoint($provider);
        }

        foreach ($endpoints as $endpoint) {
            if (!$this->isLocal($endpoint)) {
                throw NonLocalPlatformEndpointException::forProvider($provider, $endpoint->origin());
            }
        }
    }

    /**
     * @param array<array-key, mixed> $providerConfig
     *
     * @return list<PlatformEndpoint>
     */
    private function endpointsIn(array $providerConfig): array
    {
        $endpoints = [];
        foreach ($providerConfig as $key => $value) {
            if (\is_array($value)) {
                $endpoints = [...$endpoints, ...$this->endpointsIn($value)];

                continue;
            }

            $endpoint = $this->endpointIn($key, $value);
            if ($endpoint instanceof PlatformEndpoint) {
                $endpoints[] = $endpoint;
            }
        }

        return $endpoints;
    }

    /**
     * True when a dry run stood in for a setting whose `%env()%` variable is
     * unset, which only the real run can judge.
     *
     * @param array<array-key, mixed> $providerConfig
     */
    private function holdsAnUnresolvedSetting(array $providerConfig): bool
    {
        foreach ($providerConfig as $key => $value) {
            if ($this->isUnresolved($key, $value)) {
                return true;
            }
        }

        return false;
    }

    private function isUnresolved(int|string $key, mixed $value): bool
    {
        if (\is_array($value)) {
            return $this->holdsAnUnresolvedSetting($value);
        }

        return !PlatformApiKey::names($key) && StandalonePlatformConfigResolver::UNNEEDED_CREDENTIAL === $value;
    }

    private function endpointIn(int|string $key, mixed $value): ?PlatformEndpoint
    {
        if (PlatformApiKey::names($key) || !\is_string($value)) {
            return null;
        }

        return PlatformEndpoint::tryFrom(ContainerParameterSyntax::unescape($value));
    }

    private function isLocal(PlatformEndpoint $platformEndpoint): bool
    {
        $host = trim($platformEndpoint->host, '[]');

        if ('localhost' === $host || str_ends_with($host, '.localhost') || str_ends_with($host, '.local')) {
            return true;
        }

        $host = $this->embeddedIpv4($host);

        if (false === filter_var($host, \FILTER_VALIDATE_IP)) {
            return false;
        }

        return false === filter_var($host, \FILTER_VALIDATE_IP, \FILTER_FLAG_NO_PRIV_RANGE | \FILTER_FLAG_NO_RES_RANGE);
    }

    /**
     * Unwraps an IPv4-mapped IPv6 host (`::ffff:a.b.c.d` or its hex form), so
     * a public target such as `[::ffff:8.8.8.8]` is not taken for a local one.
     */
    private function embeddedIpv4(string $host): string
    {
        $packed = inet_pton($host);
        if (false === $packed || 16 !== \strlen($packed) || !str_starts_with($packed, "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff")) {
            return $host;
        }

        $ipv4 = inet_ntop(substr($packed, 12));

        return false === $ipv4 ? $host : $ipv4;
    }
}
