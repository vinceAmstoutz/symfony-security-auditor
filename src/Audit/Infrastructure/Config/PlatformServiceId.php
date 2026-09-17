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
 * An instance name reaches the container as the tail of
 * `ai.platform.<platform>.<instance>`, and `ContainerBuilder::setDefinition()`
 * refuses an id holding a NUL, a carriage return, a newline or a quote, or
 * ending in a backslash. Such a name survives YAML untouched, so it is only
 * caught here, before `init` writes a config the next run cannot build.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class PlatformServiceId
{
    private const string FORBIDDEN_CHARACTERS = "\0\r\n'";

    public static function accepts(string $instance): bool
    {
        return !str_ends_with($instance, '\\')
            && \strlen($instance) === strcspn($instance, self::FORBIDDEN_CHARACTERS);
    }
}
