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

/** @internal not part of the BC promise — see docs/versioning.md */
final class UnreadableCredentialStoreException extends RuntimeException
{
    public static function forInsecurePermissions(string $path, int $mode): self
    {
        return new self(\sprintf(
            'The stored credentials at "%s" are readable by other users on this machine (permissions %04o). Anyone who could read them may already have your API key, so rotate it with your provider, then run "chmod 600 %s".',
            $path,
            $mode,
            $path,
        ));
    }

    public static function forUnreadableFile(string $path): self
    {
        return new self(\sprintf('The stored credentials at "%s" could not be read.', $path));
    }

    public static function forMalformedContent(string $path): self
    {
        return new self(\sprintf('The stored credentials at "%s" are not valid JSON. Run "auth:set" to write them again.', $path));
    }
}
