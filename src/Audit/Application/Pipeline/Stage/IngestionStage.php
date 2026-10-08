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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Pipeline\Stage;

use Override;
use Psr\Log\LoggerInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Scan\ScopedScan;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\AuditContext;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\BuiltInStageName;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFile;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Pipeline\StageInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\GitChangedFilesResolverInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\ProjectFileScannerInterface;

/** @internal not part of the BC promise — see docs/versioning.md */
final readonly class IngestionStage implements StageInterface
{
    private const string SECRET_SCRUBBING = 'secret_scrubbing';

    public function __construct(
        private ProjectFileScannerInterface $projectFileScanner,
        private LoggerInterface $logger,
        private ?GitChangedFilesResolverInterface $gitChangedFilesResolver = null,
    ) {}

    #[Override]
    public function name(): string
    {
        return BuiltInStageName::Ingestion->value;
    }

    #[Override]
    public function process(AuditContext $auditContext): void
    {
        $this->logger->info('Ingesting project files', [
            'path' => $auditContext->projectPath(),
        ]);

        $scannedFiles = ScopedScan::files($this->projectFileScanner, $auditContext->projectPath(), $auditContext->scanPaths());

        $files = $scannedFiles;
        $diffSinceRef = $auditContext->diffSinceRef();
        if (null !== $diffSinceRef && $this->gitChangedFilesResolver instanceof GitChangedFilesResolverInterface) {
            $files = $this->filterByGitDiff($auditContext->projectPath(), $diffSinceRef, $scannedFiles);
        }

        if ([] === $files) {
            $this->logger->warning('No files found in project', [
                'path' => $auditContext->projectPath(),
            ]);
        }

        $auditContext->setProjectFiles($files);
        $auditContext->setFilesDiscovered(\count($scannedFiles));
        $auditContext->setMappingFiles(ScopedScan::mappingFiles($this->projectFileScanner, $auditContext->projectPath(), $auditContext->scanPaths(), $scannedFiles));
        $this->recordWithheldFiles($files, $auditContext);
        $auditContext->setMeta('ingestion.file_count', \count($files));
        $auditContext->setMeta('ingestion.total_lines', array_sum(
            array_map(static fn (ProjectFile $projectFile): int => $projectFile->linesCount(), $files),
        ));

        $this->logger->info('Ingestion complete', [
            'files' => \count($files),
            'lines' => $auditContext->getMeta('ingestion.total_lines'),
        ]);
    }

    /**
     * The secret scrubber hands over a file it could not vouch for as a
     * placeholder, so nothing in it can be analyzed: the file is recorded as
     * errored, which marks the report incomplete instead of letting the
     * blanked-out file pass as a clean one.
     *
     * @param list<ProjectFile> $files
     */
    private function recordWithheldFiles(array $files, AuditContext $auditContext): void
    {
        foreach ($files as $file) {
            if ($file->isWithheld()) {
                $auditContext->recordCoverage(self::SECRET_SCRUBBING, $file->relativePath(), 'errored');
                $this->logger->warning('Secret scrubbing could not scan a file, so its content was withheld and the file is not analyzed', ['file' => $file->relativePath()]);
            }
        }
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

        $filtered = array_values(array_filter(
            $files,
            static fn (ProjectFile $projectFile): bool => \array_key_exists($projectFile->relativePath(), $changedSet),
        ));

        $this->logger->info('Diff filter applied', [
            'ref' => $ref,
            'changed_in_diff' => \count($changed),
            'kept_after_intersection' => \count($filtered),
            'dropped' => \count($files) - \count($filtered),
        ]);

        return $filtered;
    }
}
