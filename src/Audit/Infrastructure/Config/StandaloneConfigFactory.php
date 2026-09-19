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
    public function create(string $provider, string $model, string $apiKeyEnvironmentVariable, ?string $baseUrl = null): array
    {
        return [
            'provider' => $provider,
            'platform' => $this->platformBlock(ProviderKey::of($provider), $apiKeyEnvironmentVariable, $baseUrl),
            'model' => $model,
        ];
    }

    /**
     * @return array<string, mixed>
     */
    private function platformBlock(ProviderKey $providerKey, string $apiKeyEnvironmentVariable, ?string $baseUrl): array
    {
        $connection = $this->connection($apiKeyEnvironmentVariable, $baseUrl);

        if (null === $providerKey->instance) {
            return [$providerKey->platform => $connection];
        }

        return [$providerKey->platform => [$providerKey->instance => $connection]];
    }

    /**
     * @return array<string, string>
     */
    private function connection(string $apiKeyEnvironmentVariable, ?string $baseUrl): array
    {
        $connection = null !== $baseUrl ? ['base_url' => $baseUrl] : [];
        $connection['api_key'] = \sprintf('%%env(%s)%%', $apiKeyEnvironmentVariable);

        return $connection;
    }
}
