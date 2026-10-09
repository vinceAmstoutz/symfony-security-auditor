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
 * Keeps every `ProjectFile` whose relative path lives under any of the
 * configured scan paths. Used by the `--path` option on the CLI to restrict
 * audits to one or several subdirectories of a monorepo without changing the
 * `ProjectFileScannerInterface` contract.
 *
 * Path comparison is byte-exact on a normalized form (forward slashes, no
 * trailing separator) — a path of `apps/api` matches `apps/api/src/X.php`
 * but not `apps/api-shared/X.php`.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class ScanPathFilter
{
    /**
     * @param list<ProjectFile> $files
     * @param list<string>      $scanPaths empty list returns the input
     *                                     unchanged
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
     * Whether a file at `$relativePath` lies under any of the scan paths, by
     * the same rule {@see apply()} keeps files by — so a report's recorded
     * scope reads back exactly as its scan applied it.
     *
     * @param list<string> $scanPaths empty list covers every file
     */
    public static function includes(string $relativePath, array $scanPaths): bool
    {
        $normalized = self::normalize($scanPaths);

        return [] === $normalized || self::matchesAnyPrefix($relativePath, $normalized);
    }

    /**
     * The scan paths in the one form the filter compares and a scanner scans:
     * trimmed, with forward slashes, and with their `.`, `..` and empty
     * segments resolved, so `src/../src`, `./src//` and `src` are one path —
     * the scanner resolves them through the filesystem, and a spelling the
     * filter read literally would scan a directory while its skipped files
     * went unrecorded. The project root itself and blank entries name no path
     * to narrow to and are dropped.
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
