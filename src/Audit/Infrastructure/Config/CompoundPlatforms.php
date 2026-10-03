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
 * The `symfony/ai` platforms that wrap other platforms instead of reaching a
 * provider, mapped to the container service `symfony/ai-bundle` wires them to
 * beyond the platforms themselves. Only a Symfony application defines those
 * services: the standalone container has none of them, and its config file
 * cannot declare one, so no block written for these platforms boots there.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class CompoundPlatforms
{
    /**
     * @var array<string, string>
     */
    public const array SERVICES_NEEDED = [
        'cache' => 'the serializer service',
        'failover' => 'a rate limiter service',
    ];

    public static function serviceNeededBy(ProviderKey $providerKey): ?string
    {
        return self::SERVICES_NEEDED[$providerKey->platform] ?? null;
    }
}
