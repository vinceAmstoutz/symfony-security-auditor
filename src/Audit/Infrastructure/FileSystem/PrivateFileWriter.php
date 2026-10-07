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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\FileSystem;

use Symfony\Component\Filesystem\Filesystem;

/**
 * Writes what the audit caches about the audited code — source excerpts,
 * findings, reviewer reasoning — so that only its owner can read it.
 * `Filesystem::dumpFile()` gives a new file the process umask, which leaves it
 * world-readable on a typical host, so the file is created empty and tightened
 * first, and `dumpFile()` keeps the permissions of a file that exists. The
 * directories it has to create are owner-only too; one that exists is left as
 * its owner set it.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class PrivateFileWriter
{
    private const int FILE_MODE = 0o600;

    private const int DIRECTORY_MODE = 0o700;

    public static function write(Filesystem $filesystem, string $path, string $contents): void
    {
        $filesystem->mkdir(\dirname($path), self::DIRECTORY_MODE);
        $filesystem->touch($path);
        $filesystem->chmod($path, self::FILE_MODE);
        $filesystem->dumpFile($path, $contents);
    }
}
