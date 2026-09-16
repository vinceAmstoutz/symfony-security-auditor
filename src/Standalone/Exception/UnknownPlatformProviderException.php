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

namespace VinceAmstoutz\SymfonySecurityAuditor\Standalone\Exception;

use RuntimeException;

/** @internal not part of the BC promise — see docs/versioning.md */
final class UnknownPlatformProviderException extends RuntimeException
{
    public static function forProvider(string $provider): self
    {
        return new self(\sprintf('The selected provider "%s" is not present in the "platform:" block of your config.', $provider));
    }

    /**
     * @param list<string> $instances
     */
    public static function forUnknownInstance(string $platform, string $instance, array $instances): self
    {
        return new self(\sprintf(
            'The "%1$s" platform has no "%2$s" instance. Configured instances: %3$s.',
            $platform,
            $instance,
            implode(', ', $instances),
        ));
    }

    /**
     * @param list<string> $instances
     */
    public static function forInstanceKeyedProvider(string $provider, array $instances): self
    {
        return new self(\sprintf(
            'The "%1$s" platform is configured per instance, so "provider: %1$s" does not select one. Use "%1$s.<instance>" instead. Configured instances: %2$s.',
            $provider,
            implode(', ', $instances),
        ));
    }
}
