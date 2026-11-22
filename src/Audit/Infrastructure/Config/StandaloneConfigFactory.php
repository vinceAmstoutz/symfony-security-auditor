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
    public function create(string $provider, string $model, ?string $apiKeyEnvironmentVariable, PlatformConnection $platformConnection = new PlatformConnection(), ?string $reviewerModel = null): array
    {
        $providerKey = ProviderKey::of($provider);
        $connection = $this->connection($apiKeyEnvironmentVariable, $platformConnection);

        if (BedrockMantleRoute::applies($providerKey)) {
            $connection = ['api' => BedrockMantleRoute::of($model), ...$connection];
        }

        return [
            'provider' => $provider,
            'platform' => $this->platformBlock($providerKey, $connection),
            'model' => $model,
            ...null === $reviewerModel ? [] : ['reviewer_model' => $reviewerModel],
            'audit' => ['report_static_findings' => true],
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
    private function connection(?string $apiKeyEnvironmentVariable, PlatformConnection $platformConnection): array
    {
        $connection = null !== $platformConnection->baseUrl ? ['base_url' => ContainerParameterSyntax::literal($platformConnection->baseUrl)] : [];

        if (null !== $platformConnection->endpoint) {
            $connection['endpoint'] = ContainerParameterSyntax::literal($platformConnection->endpoint);
        }

        if (null !== $platformConnection->deployment) {
            $connection['deployment'] = ContainerParameterSyntax::literal($platformConnection->deployment);
        }

        if (null !== $apiKeyEnvironmentVariable) {
            $connection['api_key'] = \sprintf('%%env(%s)%%', $apiKeyEnvironmentVariable);
        }

        return $connection;
    }
}
