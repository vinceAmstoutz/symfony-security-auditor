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
 * be told where to look: a run whose `--path` values lie under no file of the
 * configured scan surface (`scan.included_paths`) scans them itself, so a
 * monorepo folder the configuration leaves out can still be audited. The
 * files of the configured surface that do lie under the paths are never
 * widened. A scanner without it keeps working: such a run audits no file, as
 * before.
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
