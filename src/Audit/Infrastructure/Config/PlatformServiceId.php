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
 * Refuses an instance name `ContainerBuilder::setDefinition()` cannot take as
 * the tail of `ai.platform.<platform>.<instance>`: one holding a NUL, a
 * carriage return, a newline or a quote, or ending in a backslash.
 *
 * @internal not part of the BC promise, see docs/versioning.md
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
