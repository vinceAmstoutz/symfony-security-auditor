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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port;

use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFile;

/**
 * Opt-in companion of {@see ProjectFileScannerInterface} for a scanner that can
 * be told where to look: the `--path` values of a run replace the configured
 * scan surface (`scan.included_paths`) instead of narrowing it, so a command
 * line flag wins over the configuration. A scanner without it keeps working:
 * its result is narrowed to the paths, as before.
 */
interface ScopedProjectFileScannerInterface extends ProjectFileScannerInterface
{
    /**
     * Scans exactly `$scanPaths` — project-relative directories and files,
     * never empty — in place of the configured ones, under every other rule
     * the scanner applies (file types, size limit, ignored files, symlinks,
     * containment in the project).
     *
     * @param non-empty-list<string> $scanPaths
     *
     * @return list<ProjectFile>
     */
    public function scanWithin(string $projectPath, array $scanPaths): array;
}
