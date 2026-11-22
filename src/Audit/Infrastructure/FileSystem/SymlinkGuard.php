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

use Symfony\Component\Filesystem\Path;

/**
 * Refuses a path whose file, directory or any directory between the trusted
 * root (the working directory by default) and the file is a symlink, so a
 * symlink committed to the project cannot redirect a read or a write.
 * Directories above the root are trusted. A relative path or root is read
 * against the working directory and a trailing slash is ignored.
 *
 * @internal not part of the BC promise, see docs/versioning.md
 */
final readonly class SymlinkGuard
{
    public static function isThroughSymlink(string $path, ?string $trustedRoot = null): bool
    {
        $path = rtrim($path, '/');
        if (is_link($path)) {
            return true;
        }

        $workingDirectory = getcwd();
        if (false === $workingDirectory) {
            return is_link(\dirname($path));
        }

        $absolutePath = Path::isAbsolute($path) ? $path : \sprintf('%s/%s', $workingDirectory, $path);
        $canonicalRoot = Path::makeAbsolute($trustedRoot ?? $workingDirectory, $workingDirectory);
        if (self::traversesSymlinkBelowRoot($absolutePath, $canonicalRoot)) {
            return true;
        }

        $directory = \dirname(Path::canonicalize($absolutePath));
        if (!Path::isBasePath($canonicalRoot, $directory)) {
            return is_link($directory);
        }

        return false;
    }

    /**
     * Refuses a symlink below the working directory or below `$projectRoot`.
     */
    public static function isThroughSymlinkIntoProject(string $path, ?string $projectRoot): bool
    {
        return self::isThroughSymlink($path)
            || (null !== $projectRoot && self::isThroughSymlink($path, $projectRoot));
    }

    /**
     * Walks the path as written, not canonicalized: the kernel reads
     * `build/link/../report.sarif` through `build/link`, even when the `..`
     * climbs above the root.
     */
    private static function traversesSymlinkBelowRoot(string $absolutePath, string $canonicalRoot): bool
    {
        $segments = explode('/', Path::normalize(\dirname($absolutePath)));
        foreach (array_keys($segments) as $depth) {
            $ancestor = implode('/', \array_slice($segments, 0, $depth + 1));
            if (self::isStrictlyBelow($canonicalRoot, $ancestor) && is_link($ancestor)) {
                return true;
            }
        }

        return false;
    }

    private static function isStrictlyBelow(string $canonicalRoot, string $ancestor): bool
    {
        $canonicalAncestor = Path::canonicalize($ancestor);

        return $canonicalAncestor !== $canonicalRoot && Path::isBasePath($canonicalRoot, $canonicalAncestor);
    }
}
