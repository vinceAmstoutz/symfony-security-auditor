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
 * The block `init` prints for a platform it cannot write, with a
 * `<placeholder>` for each value only the user knows.
 *
 * @internal not part of the BC promise, see docs/versioning.md
 */
final readonly class HandWrittenPlatformBlock
{
    /**
     * @var array<string, array<string, mixed>>
     */
    public const array CONNECTIONS = [
        'cartesia' => ['api_key' => '%env(CARTESIA_API_KEY)%', 'version' => '<api version>'],
        'dockermodelrunner' => ['host_url' => 'http://127.0.0.1:12434'],
        'higgsfield' => ['api_key' => '%env(HIGGSFIELD_API_KEY)%', 'api_secret' => '%env(HIGGSFIELD_API_SECRET)%'],
        'lmstudio' => ['host_url' => 'http://127.0.0.1:1234'],
        'transformersphp' => [],
    ];

    /**
     * @return array<string, mixed>
     */
    public static function for(ProviderKey $providerKey, string $model): array
    {
        return ['provider' => $providerKey->platform, 'platform' => [$providerKey->platform => self::CONNECTIONS[$providerKey->platform] ?? []], 'model' => $model];
    }
}
