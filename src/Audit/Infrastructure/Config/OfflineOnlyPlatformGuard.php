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

use Uri\Rfc3986\Uri;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\Exception\NonLocalPlatformEndpointException;

/**
 * Fails a `privacy.offline_only` run before it boots unless every configured
 * platform talks to this machine (or its private network). A provider is
 * accepted only when it carries at least one URL and every URL it carries
 * resolves to a loopback, link-local or private-range host — so a hosted
 * provider (an `api_key` and nothing else) and a cloud endpoint
 * (`base_url: https://…azure.com`) are both rejected.
 *
 * @internal not part of the BC promise — see docs/versioning.md
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
     * @param array<array-key, mixed> $providerConfig
     *
     * @throws NonLocalPlatformEndpointException
     */
    private function assertProviderIsLocal(string $provider, array $providerConfig): void
    {
        $urls = $this->urlsIn($providerConfig);

        if ([] === $urls) {
            throw NonLocalPlatformEndpointException::forProviderWithoutEndpoint($provider);
        }

        foreach ($urls as $url) {
            if (!$this->isLocal($url)) {
                throw NonLocalPlatformEndpointException::forProvider($provider, $url);
            }
        }
    }

    /**
     * @param array<array-key, mixed> $providerConfig
     *
     * @return list<string>
     */
    private function urlsIn(array $providerConfig): array
    {
        $urls = [];
        foreach ($providerConfig as $value) {
            if (\is_array($value)) {
                $urls = [...$urls, ...$this->urlsIn($value)];

                continue;
            }

            if (\is_string($value) && $this->isEndpoint($value)) {
                $urls[] = $value;
            }
        }

        return $urls;
    }

    private function isEndpoint(string $value): bool
    {
        return null !== Uri::parse($value)?->getScheme();
    }

    private function isLocal(string $url): bool
    {
        $host = Uri::parse($url)?->getHost();
        if (null === $host || '' === $host) {
            return false;
        }

        $host = trim($host, '[]');

        if ('localhost' === $host || str_ends_with($host, '.localhost') || str_ends_with($host, '.local')) {
            return true;
        }

        if (false === filter_var($host, \FILTER_VALIDATE_IP)) {
            return false;
        }

        return false === filter_var($host, \FILTER_VALIDATE_IP, \FILTER_FLAG_NO_PRIV_RANGE | \FILTER_FLAG_NO_RES_RANGE);
    }
}
