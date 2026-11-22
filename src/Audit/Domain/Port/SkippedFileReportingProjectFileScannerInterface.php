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
 * Optional extension of {@see ProjectFileScannerInterface}, checked with
 * `instanceof`: also returns the files the scan matched and left out (over the
 * size limit, unreadable or symlinked), which the report lists as `skipped`
 * under the `scan` stage without gating on them. A file whose repaired name or
 * content could read as something else
 * (`SkippedFileReason::leavesTheRunIncomplete()`) is listed as `errored`
 * instead, which leaves the report incomplete. Files excluded on purpose
 * (gitignored, hidden, outside the included paths) are not among them.
 */
interface SkippedFileReportingProjectFileScannerInterface extends ProjectFileScannerInterface
{
    /**
     * Its `files` are exactly what {@see ProjectFileScannerInterface::scan()}
     * returns, or {@see ScopedProjectFileScannerInterface::scanWithin()} when
     * `$scanPaths` is given.
     *
     * @param list<string> $scanPaths none scans the configured paths
     */
    public function scanReportingSkippedFiles(string $projectPath, array $scanPaths = []): ProjectFileScan;
}
