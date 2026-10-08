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
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\ProjectFileScannerInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\ScopedProjectFileScannerInterface;

/**
 * The files a run covers, given its `--path` values. Without a path it is the
 * configured scan surface. With paths, a command line flag wins over the
 * configuration: a scanner that can be told where to look scans exactly those
 * paths, and one that cannot has its result narrowed to them, as before.
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
     *
     * @return list<ProjectFile>
     */
    public static function files(ProjectFileScannerInterface $projectFileScanner, string $projectPath, array $scanPaths): array
    {
        $paths = ScanPathFilter::normalize($scanPaths);

        if ([] === $paths) {
            return $projectFileScanner->scan($projectPath);
        }

        if ($projectFileScanner instanceof ScopedProjectFileScannerInterface) {
            return $projectFileScanner->scanWithin($projectPath, $paths);
        }

        return ScanPathFilter::apply($projectFileScanner->scan($projectPath), $paths);
    }

    /**
     * @param list<string>      $scanPaths   as given on the command line
     * @param list<ProjectFile> $scopedFiles what {@see self::files()} returned for the same paths
     *
     * @return list<ProjectFile>
     */
    public static function mappingFiles(ProjectFileScannerInterface $projectFileScanner, string $projectPath, array $scanPaths, array $scopedFiles): array
    {
        if ([] === ScanPathFilter::normalize($scanPaths)) {
            return $scopedFiles;
        }

        $byRelativePath = [];
        foreach ([...$projectFileScanner->scan($projectPath), ...$scopedFiles] as $file) {
            $byRelativePath[$file->relativePath()] ??= $file;
        }

        return array_values($byRelativePath);
    }
}
