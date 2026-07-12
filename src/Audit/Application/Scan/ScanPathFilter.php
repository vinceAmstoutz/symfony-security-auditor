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

use Symfony\Component\String\UnicodeString;
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
        $normalized = self::normalizePrefixes($scanPaths);

        if ([] === $normalized) {
            return $files;
        }

        $filtered = [];
        foreach ($files as $file) {
            if (self::matchesAnyPrefix($file, $normalized)) {
                $filtered[] = $file;
            }
        }

        return $filtered;
    }

    /**
     * @param list<string> $scanPaths
     *
     * @return list<string>
     */
    private static function normalizePrefixes(array $scanPaths): array
    {
        $normalized = [];
        foreach ($scanPaths as $scanPath) {
            $trimmed = self::stripLeadingCurrentDirSegment(u($scanPath)->trim()->replace('\\', '/')->trimEnd('/'));
            if ($trimmed->isEmpty()) {
                continue;
            }

            $normalized[] = $trimmed->toString();
        }

        return $normalized;
    }

    /**
     * `Path::makeRelative()` (used to compute every scanned file's relative
     * path) never produces a leading `./` in its output, so a `--path ./src`
     * or bare `--path .` CLI filter could otherwise never match any scanned
     * real relative path — silently scanning zero files instead of the
     * intended subdirectory (or, for a bare `.`, the whole project).
     */
    private static function stripLeadingCurrentDirSegment(UnicodeString $unicodeString): UnicodeString
    {
        while ($unicodeString->startsWith('./')) {
            $unicodeString = $unicodeString->after('/');
        }

        return '.' === $unicodeString->toString() ? u('') : $unicodeString;
    }

    /**
     * @param list<string> $prefixes
     */
    private static function matchesAnyPrefix(ProjectFile $projectFile, array $prefixes): bool
    {
        $relative = u($projectFile->relativePath())->replace('\\', '/')->toString();
        foreach ($prefixes as $prefix) {
            if ($relative === $prefix || u($relative)->startsWith(\sprintf('%s/', $prefix))) {
                return true;
            }
        }

        return false;
    }
}
