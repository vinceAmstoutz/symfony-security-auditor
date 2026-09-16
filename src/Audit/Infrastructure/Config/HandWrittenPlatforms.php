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
 * The `symfony/ai` platforms whose connection block `init` cannot write, mapped
 * to what they need instead. `init` only ever writes an `api_key` plus an
 * optional `base_url`, so a platform that rejects `api_key` or requires a field
 * `init` never asks for ends up with a block the container refuses to compile.
 * Each entry was confirmed by compiling the block `StandaloneConfigFactory`
 * produces for it against `symfony/ai-bundle`'s own definitions.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class HandWrittenPlatforms
{
    /**
     * @var array<string, string>
     */
    public const array REQUIREMENTS = [
        'azure' => 'a "deployment" name beside the api_key',
        'bedrock' => 'a "bedrock_runtime_client" service rather than an api_key',
        'cache' => 'the "platform" it wraps and a cache "service" rather than an api_key',
        'cartesia' => 'a "version" beside the api_key',
        'dockermodelrunner' => 'a "host_url" rather than an api_key',
        'failover' => 'the list of "platforms" it falls back through rather than an api_key',
        'lmstudio' => 'a "host_url" rather than an api_key',
        'transformersphp' => 'no connection options at all',
    ];

    public static function requirementOf(ProviderKey $providerKey): ?string
    {
        return self::REQUIREMENTS[$providerKey->platform] ?? null;
    }
}
