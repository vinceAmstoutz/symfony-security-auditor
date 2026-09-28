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

use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Bridge\ProviderKey;

/**
 * The configuration `init` prints instead of writing for a platform it cannot
 * configure: every setting the platform needs, with `<placeholder>` values for
 * what only the user knows, ready to paste into `config.yaml`.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class HandWrittenPlatformBlock
{
    /**
     * @var array<string, array<string, mixed>>
     */
    public const array CONNECTIONS = [
        'azure' => ['base_url' => 'https://<resource>.openai.azure.com', 'deployment' => '<deployment>', 'api_version' => '<api version>', 'api_key' => '%env(AZURE_API_KEY)%'],
        'bedrock' => ['api' => 'messages', 'api_key' => '%env(BEDROCK_API_KEY)%', 'region' => 'us-west-2'],
        'cache' => ['platform' => 'ai.platform.<platform to cache>'],
        'cartesia' => ['api_key' => '%env(CARTESIA_API_KEY)%', 'version' => '<api version>'],
        'dockermodelrunner' => ['host_url' => 'http://127.0.0.1:12434'],
        'failover' => ['platforms' => ['ai.platform.<first choice>', 'ai.platform.<fallback>']],
        'higgsfield' => ['api_key' => '%env(HIGGSFIELD_API_KEY)%', 'api_secret' => '%env(HIGGSFIELD_API_SECRET)%'],
        'lmstudio' => ['host_url' => 'http://127.0.0.1:1234'],
        'transformersphp' => [],
    ];

    private const string DEFAULT_INSTANCE = 'default';

    /**
     * @return array<string, mixed>
     */
    public static function for(ProviderKey $providerKey, string $model): array
    {
        $connection = self::CONNECTIONS[$providerKey->platform] ?? [];

        if (!\in_array($providerKey->platform, InstanceKeyedPlatforms::NAMES, true)) {
            return ['provider' => $providerKey->platform, 'platform' => [$providerKey->platform => $connection], 'model' => $model];
        }

        $instance = $providerKey->instance ?? self::DEFAULT_INSTANCE;

        return [
            'provider' => \sprintf('%s.%s', $providerKey->platform, $instance),
            'platform' => [$providerKey->platform => [$instance => $connection]],
            'model' => $model,
        ];
    }
}
