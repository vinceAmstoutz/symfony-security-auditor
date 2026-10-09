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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Config\Exception;

use Symfony\Component\Config\Definition\Exception\InvalidConfigurationException;

/** @internal not part of the BC promise — see docs/versioning.md */
final class TypedNodeEnvPlaceholderException extends InvalidConfigurationException
{
    /**
     * @param non-empty-list<string> $paths
     */
    public static function forPaths(array $paths): self
    {
        return new self(\sprintf(
            'Invalid configuration for path %s: an environment variable placeholder ("%%env(...)%%") is not supported on this setting, which the bundle reads while the container is built, before the variable has a value. Set a literal value instead.',
            implode(', ', array_map(static fn (string $path): string => \sprintf('"%s"', $path), $paths)),
        ));
    }
}
