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
 * `Filesystem::dumpFile()` and `readFile()` transparently follow a symlink
 * anywhere on the way to their target, so a predictable path committed as a
 * symlink by a malicious change — `report.sarif`, `.security-baseline.json`,
 * a cache shard, or a directory above them such as `build -> /elsewhere` —
 * would redirect the read or write out of the project. A path is refused when
 * its file, its directory or any directory between the trusted root (the
 * process working directory by default) and the file is a symlink. Directories
 * above that root are the user's own, the operating system's included
 * (`/var -> /private/var` on macOS), and are left alone. A relative path or
 * root is read against the working directory, as the filesystem calls read
 * it. A trailing slash is dropped first: `link/` names the directory `link`
 * points to, so `is_link()` would look straight through it.
 *
 * @internal not part of the BC promise — see docs/versioning.md
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
     * The audited checkout is as untrusted below its root as below the
     * working directory, so a path into it given from outside the working
     * directory has every directory between the project root and the file
     * checked too, not only its own directory.
     */
    public static function isThroughSymlinkIntoProject(string $path, ?string $projectRoot): bool
    {
        return self::isThroughSymlink($path)
            || (null !== $projectRoot && self::isThroughSymlink($path, $projectRoot));
    }

    /**
     * Walks the directory prefixes of the path as written rather than as
     * canonicalized: the kernel reads `build/link/../report.sarif` through
     * `build/link` before it climbs back up, so collapsing the `..` first
     * would hide the link. This runs before the `canonicalize()` collapse
     * below precisely because a `..` can climb back ABOVE the root, which
     * would otherwise take the "outside the root" branch and skip the walk
     * that catches the symlinked prefix. Prefixes above the root and the root
     * itself stay unchecked, as before.
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
