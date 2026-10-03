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

namespace VinceAmstoutz\SymfonySecurityAuditor\Command\Exception;

use RuntimeException;
use Symfony\Component\Filesystem\Exception\IOException;

/** @internal not part of the BC promise — see docs/versioning.md */
final class BaselineWriteFailedException extends RuntimeException
{
    public static function forDirectoryPath(string $path): self
    {
        return new self(\sprintf('The baseline cannot be written to "%s": the path ends with a directory separator, so it names a directory. Give --generate-baseline a file path before the audit spends anything.', $path));
    }

    public static function forUncreatableDirectory(string $path, IOException $ioException): self
    {
        return new self(\sprintf('The baseline cannot be written to "%s", its directory could not be created (%s): choose another --generate-baseline path before the audit spends anything.', $path, $ioException->getMessage()), previous: $ioException);
    }

    public static function forUnwritablePath(string $path): self
    {
        return new self(\sprintf('The baseline cannot be written to "%s": choose a --generate-baseline path that is a writable file or lies under a writable directory, before the audit spends anything.', $path));
    }
}
