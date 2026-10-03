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

/**
 * What `Filesystem::dumpFile()` needs to save a file at a path, checked by the
 * report and baseline writers before an audit spends anything on the file.
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
     * a destination that is not a directory and, when it already exists, is
     * writable itself.
     */
    public static function canBeWritten(string $path): bool
    {
        return is_writable(\dirname($path)) && (!file_exists($path) || (!is_dir($path) && is_writable($path)));
    }
}
