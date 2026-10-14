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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\FileSystem\Exception;

use RuntimeException;

/** @internal not part of the BC promise — see docs/versioning.md */
final class UnreadableInputFileException extends RuntimeException
{
    public static function forReadError(string $path, string $error): self
    {
        return new self(\sprintf('File "%s" could not be read: %s', $path, $error));
    }

    public static function forOversizedFile(string $path, int $maxBytes): self
    {
        return new self(\sprintf('File "%s" holds more than %d bytes, so it was not read.', $path, $maxBytes));
    }
}
