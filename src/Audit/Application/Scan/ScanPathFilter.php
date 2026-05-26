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
        $normalized = [];
        foreach ($scanPaths as $scanPath) {
            $trimmed = trim($scanPath);
            if ('' === $trimmed) {
                continue;
            }

            $normalized[] = rtrim(str_replace('\\', '/', $trimmed), '/');
        }

        if ([] === $normalized) {
            return $files;
        }

        $filtered = [];
        foreach ($files as $file) {
            $relative = str_replace('\\', '/', $file->relativePath());
            foreach ($normalized as $prefix) {
                if ($relative === $prefix || str_starts_with($relative, $prefix.'/')) {
                    $filtered[] = $file;

                    break;
                }
            }
        }

        return $filtered;
    }
}
