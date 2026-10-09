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

use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFileScan;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\ProjectFileScannerInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\ScopedProjectFileScannerInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\SkippedFileReportingProjectFileScannerInterface;

/**
 * The files a run covers, given its `--path` values. Without a path it is the
 * configured scan surface. With paths, it is the part of that surface under
 * them, and nothing else: a path only narrows what `scan.included_paths`
 * reaches. Only when no file of the configured surface lies under any of the
 * paths — a monorepo folder the configuration leaves out — are the paths
 * scanned themselves, by a scanner that can be told where to look, so a run
 * that would find nothing audits what was asked for.
 * The files the Symfony mapping is read from are a wider set: `--path` only
 * narrows what is audited, so the configured scope still supplies the security
 * configuration, voters and forms that decide how each audited route is guarded.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class ScopedScan
{
    /**
     * @param list<string> $scanPaths as given on the command line
     */
    public static function resolve(ProjectFileScannerInterface $projectFileScanner, string $projectPath, array $scanPaths): ScopedScanResult
    {
        $configured = self::configured($projectFileScanner, $projectPath);
        $paths = ScanPathFilter::normalize($scanPaths);

        if ([] === $paths) {
            return new ScopedScanResult($configured, $configured->files);
        }

        $narrowed = ScanPathFilter::apply($configured->files, $paths);
        if ([] !== $narrowed) {
            return new ScopedScanResult(new ProjectFileScan($narrowed, $configured->skippedFiles), $configured->files);
        }

        $within = self::within($projectFileScanner, $projectPath, $paths);

        return new ScopedScanResult($within, [...$configured->files, ...$within->files]);
    }

    private static function configured(ProjectFileScannerInterface $projectFileScanner, string $projectPath): ProjectFileScan
    {
        if ($projectFileScanner instanceof SkippedFileReportingProjectFileScannerInterface) {
            return $projectFileScanner->scanReportingSkippedFiles($projectPath);
        }

        return new ProjectFileScan($projectFileScanner->scan($projectPath), []);
    }

    /**
     * @param non-empty-list<string> $paths
     */
    private static function within(ProjectFileScannerInterface $projectFileScanner, string $projectPath, array $paths): ProjectFileScan
    {
        if ($projectFileScanner instanceof SkippedFileReportingProjectFileScannerInterface) {
            return $projectFileScanner->scanReportingSkippedFiles($projectPath, $paths);
        }

        if ($projectFileScanner instanceof ScopedProjectFileScannerInterface) {
            return new ProjectFileScan($projectFileScanner->scanWithin($projectPath, $paths), []);
        }

        return new ProjectFileScan([], []);
    }
}
