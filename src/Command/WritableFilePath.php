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

namespace VinceAmstoutz\SymfonySecurityAuditor\Command;

use Symfony\Component\Filesystem\Exception\IOException;
use Symfony\Component\Filesystem\Filesystem;

/**
 * Checks that a file can be saved at a path and saves it: `dumpFile()` for a
 * file, a plain write for a character device.
 *
 * @internal not part of the BC promise, see docs/versioning.md
 */
final readonly class WritableFilePath
{
    /**
     * A trailing separator, which `dirname()` drops, names a directory.
     */
    public static function namesADirectory(string $path): bool
    {
        return str_ends_with($path, '/') || str_ends_with($path, '\\');
    }

    /**
     * Expects the directories to exist. Needs a writable directory and, for an
     * existing path, a writable regular file: the rename of `dumpFile()` would
     * replace a pipe, a socket or a block device. A character device needs
     * only to be writable.
     */
    public static function canBeWritten(string $path): bool
    {
        if (self::isCharacterDevice($path)) {
            return is_writable($path);
        }

        return is_writable(\dirname($path)) && (!file_exists($path) || (is_file($path) && is_writable($path)));
    }

    public static function isCharacterDevice(string $path): bool
    {
        return file_exists($path) && 'char' === filetype($path);
    }

    /**
     * Appends to a character device, which the rename of `dumpFile()` would
     * replace with a regular file.
     *
     * @throws IOException
     */
    public static function dump(Filesystem $filesystem, string $path, string $content): void
    {
        if (self::isCharacterDevice($path)) {
            $filesystem->appendToFile($path, $content);

            return;
        }

        $filesystem->dumpFile($path, $content);
    }
}
