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
 * Optional companion of {@see ProjectFileScannerInterface}: scans a run's
 * `--path` values in place of `scan.included_paths`, so `--path apps/api`
 * reaches a folder the configuration leaves out. Without it, a run audits the
 * files of the configured surface under those paths.
 */
interface ScopedProjectFileScannerInterface extends ProjectFileScannerInterface
{
    /**
     * Scans exactly `$scanPaths`, project-relative directories and files, in
     * place of the configured ones, under every other rule the scanner applies
     * (file types, size limit, ignored files, symlinks, containment in the
     * project).
     *
     * @param non-empty-list<string> $scanPaths
     *
     * @return list<ProjectFile>
     */
    public function scanWithin(string $projectPath, array $scanPaths): array;
}
