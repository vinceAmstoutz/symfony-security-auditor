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

use RuntimeException;
use Throwable;

/** @internal not part of the BC promise — see docs/versioning.md */
final class CredentialStoreWriteException extends RuntimeException
{
    public static function forPath(string $path, Throwable $throwable): self
    {
        return new self(\sprintf('The credentials at "%s" could not be written.', $path), previous: $throwable);
    }

    public static function forBlankCredential(): self
    {
        return new self('An empty API key cannot be stored.');
    }

    public static function forNonUtf8Credential(): self
    {
        return new self('The API key must be valid UTF-8 text; this one is not, which usually means the paste was truncated or mangled.');
    }

    public static function forUnresolvableLocation(): self
    {
        return new self('No per-user configuration directory could be resolved, so there is nowhere to store the credentials. Set HOME (or XDG_CONFIG_HOME, or SYMFONY_SECURITY_AUDITOR_HOME), or pass the API key through its environment variable instead.');
    }
}
