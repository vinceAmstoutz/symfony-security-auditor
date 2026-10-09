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
 * What saving a file at a path needs, checked by the report and baseline
 * writers before an audit spends anything on the file, and the saving itself:
 * `Filesystem::dumpFile()` for a file, a plain write for a character device.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class WritableFilePath
{
    /**
     * A path ending with a separator names a directory, yet `dirname()` drops
     * that separator, so every directory check passes and only the write
     * itself fails — once the audit has run. Both separators count, as they do
     * for `Symfony\Component\Filesystem\Path`. The bytes are compared as
     * they are: a path need not be valid UTF-8.
     */
    public static function namesADirectory(string $path): bool
    {
        return str_ends_with($path, '/') || str_ends_with($path, '\\');
    }

    /**
     * Once the directories exist — `dumpFile()` would create them anyway —
     * what remains is what `dumpFile()` needs: a writable directory in every
     * case (it writes a temporary file beside the target and renames it), plus
     * a destination that is a writable regular file when it already exists. A
     * pipe, a socket or a block device is none: the rename would replace it
     * with a regular file. A character device such as `/dev/null` is written
     * to directly, so it needs to be writable and its directory does not.
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
     * A file is replaced through a temporary file and a rename, which would
     * turn a character device into a regular file, so a device is appended to
     * and stays what it is.
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
