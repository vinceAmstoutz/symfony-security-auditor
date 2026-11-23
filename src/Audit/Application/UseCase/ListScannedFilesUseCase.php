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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\UseCase;

use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Scan\ScopedScan;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidAuditContextException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFile;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\GitChangedFilesResolverInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\ProbingProjectFileScannerInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\ProjectFileScannerInterface;

/**
 * Lists the files an audit would ingest, scoped to the `--path` values as a
 * run scopes them, without calling the LLM.
 *
 * @internal not part of the BC promise, see docs/versioning.md
 */
final readonly class ListScannedFilesUseCase
{
    public function __construct(
        private ProjectFileScannerInterface $projectFileScanner,
        private ?GitChangedFilesResolverInterface $gitChangedFilesResolver = null,
        private ?SinceClosurePreview $sinceClosurePreview = null,
    ) {}

    /**
     * @param list<string> $scanPaths    project-relative paths to scope the
     *                                   listing to, empty for every scanned file
     * @param ?string      $diffSinceRef narrows the listing to the files
     *                                   `audit:run --since` would audit against
     *                                   this git ref
     *
     * @return list<ProjectFile>
     *
     * @throws InvalidAuditContextException
     */
    public function execute(string $projectPath, array $scanPaths = [], ?string $diffSinceRef = null): array
    {
        $scopedScanResult = ScopedScan::resolve($this->projectFileScanner, $projectPath, $scanPaths);
        $files = $scopedScanResult->audited->files;
        if (null === $diffSinceRef || !$this->gitChangedFilesResolver instanceof GitChangedFilesResolverInterface) {
            return $files;
        }

        $changedFiles = $this->filterByGitDiff($projectPath, $diffSinceRef, $files);

        return $this->sinceClosurePreview?->auditedFiles($projectPath, $scanPaths, $diffSinceRef, $changedFiles, $scopedScanResult->mappingFiles) ?? $changedFiles;
    }

    /**
     * Tells whether the configured scan reaches a file in the project, without
     * reading one when the scanner can probe.
     *
     * @throws InvalidAuditContextException
     */
    public function holdsAFile(string $projectPath): bool
    {
        return $this->projectFileScanner instanceof ProbingProjectFileScannerInterface
            ? $this->projectFileScanner->reachesAFile($projectPath)
            : [] !== $this->execute($projectPath);
    }

    /**
     * @param list<ProjectFile> $files
     *
     * @return list<ProjectFile>
     */
    private function filterByGitDiff(string $projectPath, string $ref, array $files): array
    {
        $changed = $this->gitChangedFilesResolver?->changedSince($projectPath, $ref) ?? [];
        $changedSet = array_flip($changed);

        return array_values(array_filter(
            $files,
            static fn (ProjectFile $projectFile): bool => \array_key_exists($projectFile->relativePath(), $changedSet),
        ));
    }
}
