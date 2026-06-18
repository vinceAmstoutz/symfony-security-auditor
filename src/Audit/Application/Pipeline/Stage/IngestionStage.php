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

use Psr\Log\LoggerInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Scan\ScanPathFilter;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\AuditContext;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\BuiltInStageName;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFile;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Pipeline\StageInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\GitChangedFilesResolverInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\ProjectFileScannerInterface;

/** @internal not part of the BC promise — see docs/versioning.md */
final readonly class IngestionStage implements StageInterface
{
    public function __construct(
        private ProjectFileScannerInterface $projectFileScanner,
        private LoggerInterface $logger,
        private ?GitChangedFilesResolverInterface $gitChangedFilesResolver = null,
    ) {}

    public function name(): string
    {
        return BuiltInStageName::Ingestion->value;
    }

    public function process(AuditContext $auditContext): void
    {
        $this->logger->info('Ingesting project files', [
            'path' => $auditContext->projectPath(),
        ]);

        $files = ScanPathFilter::apply(
            $this->projectFileScanner->scan($auditContext->projectPath()),
            $auditContext->scanPaths(),
        );

        $diffSinceRef = $auditContext->diffSinceRef();
        if (null !== $diffSinceRef && $this->gitChangedFilesResolver instanceof GitChangedFilesResolverInterface) {
            $files = $this->filterByGitDiff($auditContext->projectPath(), $diffSinceRef, $files);
        }

        if ([] === $files) {
            $this->logger->warning('No files found in project', [
                'path' => $auditContext->projectPath(),
            ]);
        }

        $auditContext->setProjectFiles($files);
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
            static fn (ProjectFile $projectFile): bool => array_key_exists($projectFile->relativePath(), $changedSet),
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
