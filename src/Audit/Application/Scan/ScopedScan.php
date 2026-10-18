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
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFileScan;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\ProjectFileScannerInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\ReadSharingProjectFileScannerInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\ScopedProjectFileScannerInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\SkippedFileReportingProjectFileScannerInterface;

/**
 * The files a run covers, given its `--path` values. Without a path it is the
 * configured scan surface. With paths, the paths replace `scan.included_paths`
 * for the run: a scanner that can be told where to look scans them themselves,
 * under every other rule it applies, so `--path src` audits all of `src` even
 * when the configuration narrows the scope to `src/Controller`. A path equal
 * to the project root names no path and keeps the configured scope. A scanner
 * that cannot be told where to look keeps the part of the configured surface
 * under the paths, as it always did.
 * The files the Symfony mapping is read from are a wider set: the configured
 * scope plus the files the paths reached, each once, so the security
 * configuration, voters and forms that decide how each audited route is
 * guarded are still read when `--path` names a single folder. A scanner that
 * can share its reads scans both through the scanner sharing them, so a file
 * both reach is read and scrubbed once.
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
        $projectFileScanner = $projectFileScanner instanceof ReadSharingProjectFileScannerInterface ? $projectFileScanner->sharingReads() : $projectFileScanner;
        $configured = self::configured($projectFileScanner, $projectPath);
        $paths = ScanPathFilter::normalize($scanPaths);

        if ([] === $paths) {
            return new ScopedScanResult($configured, $configured->files);
        }

        $within = self::within($projectFileScanner, $projectPath, $paths);
        if (!$within instanceof ProjectFileScan) {
            return new ScopedScanResult(new ProjectFileScan(ScanPathFilter::apply($configured->files, $paths), []), $configured->files);
        }

        return new ScopedScanResult($within, self::eachFileOnce([...$configured->files, ...$within->files]));
    }

    /**
     * @param list<ProjectFile> $files
     *
     * @return list<ProjectFile>
     */
    private static function eachFileOnce(array $files): array
    {
        $byRelativePath = [];
        foreach ($files as $file) {
            $byRelativePath[$file->relativePath()] ??= $file;
        }

        return array_values($byRelativePath);
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
    private static function within(ProjectFileScannerInterface $projectFileScanner, string $projectPath, array $paths): ?ProjectFileScan
    {
        if ($projectFileScanner instanceof SkippedFileReportingProjectFileScannerInterface) {
            return $projectFileScanner->scanReportingSkippedFiles($projectPath, $paths);
        }

        if ($projectFileScanner instanceof ScopedProjectFileScannerInterface) {
            return new ProjectFileScan($projectFileScanner->scanWithin($projectPath, $paths), []);
        }

        return null;
    }
}
