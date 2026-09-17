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
 * The `symfony/ai` platforms declared with `useAttributeAsKey`, which register
 * one service per instance as `ai.platform.<platform>.<instance>`. Their
 * connection block is a prototype nested under an instance name, so a provider
 * naming the platform alone describes no service and compiles to nothing the
 * container accepts.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class InstanceKeyedPlatforms
{
    /**
     * @var list<string>
     */
    public const array NAMES = ['azure', 'bedrock', 'cache', 'failover', 'generic', 'openresponses'];

    public static function needsAnInstance(ProviderKey $providerKey): bool
    {
        return null === $providerKey->instance && self::isInstanceKeyed($providerKey);
    }

    public static function rejectsAnInstance(ProviderKey $providerKey): bool
    {
        return null !== $providerKey->instance && !self::isInstanceKeyed($providerKey);
    }

    private static function isInstanceKeyed(ProviderKey $providerKey): bool
    {
        return \in_array($providerKey->platform, self::NAMES, true);
    }
}
