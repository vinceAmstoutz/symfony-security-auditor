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

/**
 * An instance name as `symfony/config` will store it. `ArrayNode::preNormalize()`
 * rewrites a key holding a hyphen and no underscore, and an instance is a
 * prototyped key like any other, so `generic.my-gateway` registers the service
 * under `my_gateway`. Writing the name the user typed into `provider:` would
 * then point at a service that does not exist, so the name is folded here the
 * same way the framework will fold it.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class ConfigKeyInstanceName
{
    public static function of(string $instance): string
    {
        if (!str_contains($instance, '-') || str_contains($instance, '_')) {
            return $instance;
        }

        return str_replace('-', '_', $instance);
    }

    /**
     * A purely numeric name becomes an integer array key, which turns the
     * instance level into a list and makes the dumped YAML a sequence the
     * prototype cannot take a name from.
     */
    public static function isUsable(string $instance): bool
    {
        return 1 !== preg_match('/^-?\d+$/', $instance);
    }
}
