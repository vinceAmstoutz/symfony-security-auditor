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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Integration\Command\Fixture;

use Override;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Pipeline\Stage\IngestionStage;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\AuditContext;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Pipeline\PipelineInterface;

/**
 * Test fake — a run whose scan is the real ingestion and whose attacker
 * analyzed every file that scan returned without finding anything.
 *
 * @internal scoped to AuditCommand skipped-file integration tests
 */
final readonly class IngestedThenAnalyzedPipeline implements PipelineInterface
{
    public function __construct(private IngestionStage $ingestionStage) {}

    #[Override]
    public function process(AuditContext $auditContext): void
    {
        $this->ingestionStage->process($auditContext);

        foreach ($auditContext->projectFiles() as $projectFile) {
            $auditContext->recordCoverage('attacker', $projectFile->relativePath(), 'analyzed');
        }
    }
}
