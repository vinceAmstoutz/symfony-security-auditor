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

use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFileScan;

/**
 * Opt-in extension of {@see ProjectFileScannerInterface} for scanners that
 * know which files they matched and still left out because they were over the
 * size limit or could not be read. `IngestionStage` checks `instanceof` and
 * records each as a file the run did not analyze, so the report is incomplete
 * instead of passing the file as clean; a scanner that does not implement it
 * keeps working and reports nothing. Files excluded on purpose — gitignored,
 * hidden, outside the included paths — are not among them.
 */
interface SkippedFileReportingProjectFileScannerInterface extends ProjectFileScannerInterface
{
    /**
     * Its `files` are exactly what {@see ProjectFileScannerInterface::scan()}
     * returns for the same project, or what
     * {@see ScopedProjectFileScannerInterface::scanWithin()} returns when
     * `$scanPaths` is given: project-relative paths that replace the
     * configured scan surface, as the `--path` values of a run do.
     *
     * @param list<string> $scanPaths none scans the configured paths
     */
    public function scanReportingSkippedFiles(string $projectPath, array $scanPaths = []): ProjectFileScan;
}
