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
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\AuditContext;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFile;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Pipeline\StageInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\ProjectFileScannerInterface;

/** @internal not part of the BC promise — see docs/versioning.md */
final readonly class IngestionStage implements StageInterface
{
    public function __construct(
        private ProjectFileScannerInterface $projectFileScanner,
        private LoggerInterface $logger,
    ) {}

    public function name(): string
    {
        return 'ingestion';
    }

    public function process(AuditContext $auditContext): void
    {
        $this->logger->info('Ingesting project files', [
            'path' => $auditContext->projectPath(),
        ]);

        $files = $this->projectFileScanner->scan($auditContext->projectPath());

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
}
