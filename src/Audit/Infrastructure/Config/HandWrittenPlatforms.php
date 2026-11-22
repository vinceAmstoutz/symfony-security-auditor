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
 * The `symfony/ai` platforms whose connection block `init` cannot write, since
 * they reject `api_key` or require a field it never asks for, mapped to what
 * they need.
 *
 * @internal not part of the BC promise, see docs/versioning.md
 */
final readonly class HandWrittenPlatforms
{
    /**
     * @var array<string, string>
     */
    public const array REQUIREMENTS = [
        'cartesia' => 'a "version" beside the api_key',
        'dockermodelrunner' => 'a "host_url" rather than an api_key',
        'higgsfield' => 'an "api_secret" beside the api_key',
        'lmstudio' => 'a "host_url" rather than an api_key',
        'transformersphp' => 'an empty connection block rather than an api_key',
    ];

    public static function requirementOf(ProviderKey $providerKey): ?string
    {
        return self::REQUIREMENTS[$providerKey->platform] ?? null;
    }
}
