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

use Override;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Bridge\ProviderKey;

/**
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class StandaloneConfigFactory implements StandaloneConfigFactoryInterface
{
    #[Override]
    public function create(string $provider, string $model, ?string $apiKeyEnvironmentVariable, ?string $baseUrl = null, ?string $endpoint = null): array
    {
        return [
            'provider' => $provider,
            'platform' => $this->platformBlock(ProviderKey::of($provider), $this->connection($apiKeyEnvironmentVariable, $baseUrl, $endpoint)),
            'model' => $model,
        ];
    }

    /**
     * @param array<string, string> $connection
     *
     * @return array<string, mixed>
     */
    private function platformBlock(ProviderKey $providerKey, array $connection): array
    {
        if (null === $providerKey->instance) {
            return [$providerKey->platform => $connection];
        }

        return [$providerKey->platform => [$providerKey->instance => $connection]];
    }

    /**
     * A null variable is the caller saying the platform runs without a
     * credential, so the key is left out rather than written as an
     * `%env()%` placeholder pointing at a variable nobody will ever set.
     *
     * @return array<string, string>
     */
    private function connection(?string $apiKeyEnvironmentVariable, ?string $baseUrl, ?string $endpoint): array
    {
        $connection = null !== $baseUrl ? ['base_url' => $baseUrl] : [];

        if (null !== $endpoint) {
            $connection['endpoint'] = $endpoint;
        }

        if (null !== $apiKeyEnvironmentVariable) {
            $connection['api_key'] = \sprintf('%%env(%s)%%', $apiKeyEnvironmentVariable);
        }

        return $connection;
    }
}
