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

use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\Chunk\ChunkFindingProgress;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\AuditContext;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFile;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\CandidateFindingSourceInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\ProgressReporterInterface;

/**
 * @internal not part of the BC promise, see docs/versioning.md
 */
final readonly class StaticCandidateQueue
{
    /**
     * Queues and announces what the scrubber redacted and the static pre-scan
     * matched in `$files` as candidate findings for the reviewer. A cost
     * estimate queues none.
     *
     * @param list<ProjectFile> $files
     */
    public static function queue(array $files, AuditContext $auditContext, ?CandidateFindingSourceInterface $candidateFindingSource, ?ProgressReporterInterface $progressReporter): void
    {
        if ($auditContext->isCostEstimate() || !$candidateFindingSource instanceof CandidateFindingSourceInterface) {
            return;
        }

        $candidates = $candidateFindingSource->candidatesIn($files);
        foreach ($candidates as $candidate) {
            $auditContext->addStaticCandidate($candidate);
        }

        if ($progressReporter instanceof ProgressReporterInterface) {
            ChunkFindingProgress::report($progressReporter, $candidates);
        }
    }
}
