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
            $trimmed = u($scanPath)->trim();
            if ($trimmed->isEmpty()) {
                continue;
            }

            $normalized[] = $trimmed->replace('\\', '/')->trimEnd('/')->toString();
        }

        return $normalized;
    }

    /**
     * @param list<string> $prefixes
     */
    private static function matchesAnyPrefix(ProjectFile $projectFile, array $prefixes): bool
    {
        $relative = u($projectFile->relativePath())->replace('\\', '/')->toString();
        foreach ($prefixes as $prefix) {
            if ($relative === $prefix || u($relative)->startsWith($prefix.'/')) {
                return true;
            }
        }

        return false;
    }
}
