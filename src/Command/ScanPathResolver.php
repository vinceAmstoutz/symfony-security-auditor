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

use Symfony\Component\Filesystem\Path;
use VinceAmstoutz\SymfonySecurityAuditor\Command\Exception\ScanPathOutsideProjectException;

use function Symfony\Component\String\u;

/**
 * Turns the `--path` values into the project-relative form the scan filters
 * by: a relative path is kept, an absolute one inside the project is made
 * relative and one outside it is refused. A Windows path (`C:\Users\…`) is
 * read as one on every platform.
 *
 * @internal not part of the BC promise, see docs/versioning.md
 */
final readonly class ScanPathResolver
{
    /**
     * @param list<string> $scanPaths
     *
     * @return list<string> an empty list scans the whole project
     *
     * @throws ScanPathOutsideProjectException
     */
    public static function resolve(array $scanPaths, string $projectPath): array
    {
        $projectRoot = self::withForwardSlashes($projectPath);

        $resolved = [];
        foreach ($scanPaths as $scanPath) {
            $absolutePath = self::withForwardSlashes($scanPath);
            if (!self::isAbsolute($absolutePath)) {
                $resolved[] = $scanPath;

                continue;
            }

            $relative = self::relativeToProject($absolutePath, $projectRoot);
            if (null === $relative) {
                throw ScanPathOutsideProjectException::forPath($scanPath, $projectPath);
            }

            if ('' !== $relative) {
                $resolved[] = $relative;
            }
        }

        return $resolved;
    }

    /**
     * Null outside the project. Compares the path as typed, then through the
     * folder above it that resolves to the project, since a shell's `$PWD`
     * keeps a symlink `getcwd()` resolves. The rest of the path is read as
     * typed.
     */
    private static function relativeToProject(string $absolutePath, string $projectRoot): ?string
    {
        if (Path::isBasePath($projectRoot, $absolutePath)) {
            return Path::makeRelative($absolutePath, $projectRoot);
        }

        $realProjectRoot = realpath($projectRoot);
        if (false === $realProjectRoot) {
            return null;
        }

        $canonicalPath = Path::canonicalize($absolutePath);
        foreach (self::foldersOf($canonicalPath) as $folder) {
            if (realpath($folder) === $realProjectRoot) {
                return Path::makeRelative($canonicalPath, $folder);
            }
        }

        return null;
    }

    /**
     * @return list<string> the path and each folder above it, nearest first, the root left out
     */
    private static function foldersOf(string $path): array
    {
        $parent = Path::getDirectory($path);

        return $parent === $path ? [] : [$path, ...self::foldersOf($parent)];
    }

    private static function withForwardSlashes(string $path): string
    {
        $slashed = str_replace('\\', '/', mb_check_encoding($path, 'UTF-8') ? u($path)->toString() : $path);

        return 1 === preg_match('#^[a-z]:(?:/|$)#', $slashed) ? ucfirst($slashed) : $slashed;
    }

    private static function isAbsolute(string $path): bool
    {
        return str_starts_with($path, '/') || 1 === preg_match('#^[A-Z]:/#', $path);
    }
}
