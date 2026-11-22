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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Scan;

use Symfony\Component\Filesystem\Path;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFile;

use function Symfony\Component\String\u;

/**
 * Keeps the files under any of the scan paths, comparing normalized paths
 * byte for byte: `apps/api` matches `apps/api/src/X.php`, not
 * `apps/api-shared/X.php`.
 *
 * @internal not part of the BC promise, see docs/versioning.md
 */
final readonly class ScanPathFilter
{
    /**
     * @param list<ProjectFile> $files
     * @param list<string>      $scanPaths empty keeps every file
     *
     * @return list<ProjectFile>
     */
    public static function apply(array $files, array $scanPaths): array
    {
        $normalized = self::normalize($scanPaths);

        if ([] === $normalized) {
            return $files;
        }

        $filtered = [];
        foreach ($files as $file) {
            if (self::matchesAnyPrefix($file->relativePath(), $normalized)) {
                $filtered[] = $file;
            }
        }

        return $filtered;
    }

    /**
     * Tells whether `$relativePath` lies under a scan path, by the rule
     * `apply()` keeps files by.
     *
     * @param list<string> $scanPaths empty list covers every file
     */
    public static function includes(string $relativePath, array $scanPaths): bool
    {
        $normalized = self::normalize($scanPaths);

        return [] === $normalized || self::matchesAnyPrefix($relativePath, $normalized);
    }

    /**
     * Trims each path, writes it with forward slashes and resolves its `.`,
     * `..` and empty segments as the scanner does, so `src/../src`, `./src//`
     * and `src` are one path. Drops blank entries and the project root.
     *
     * @param list<string> $scanPaths
     *
     * @return list<string>
     */
    public static function normalize(array $scanPaths): array
    {
        $normalized = [];
        foreach ($scanPaths as $scanPath) {
            $canonical = self::canonicalize(PathText::of($scanPath)->trim()->replace('\\', '/')->toString());
            if ('' === $canonical) {
                continue;
            }

            $normalized[] = $canonical;
        }

        return $normalized;
    }

    /** Resolved against `./` because `Path::canonicalize()` expands a leading `~` to the home directory. */
    private static function canonicalize(string $scanPath): string
    {
        return Path::canonicalize(\sprintf('./%s', $scanPath));
    }

    /**
     * @param list<string> $prefixes
     */
    private static function matchesAnyPrefix(string $relativePath, array $prefixes): bool
    {
        $relative = u($relativePath)->replace('\\', '/')->toString();
        foreach ($prefixes as $prefix) {
            if ($relative === $prefix || u($relative)->startsWith(\sprintf('%s/', $prefix))) {
                return true;
            }
        }

        return false;
    }
}
