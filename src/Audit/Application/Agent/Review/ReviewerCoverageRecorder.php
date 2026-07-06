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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\Review;

use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\AgentRole;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProgressEvent;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\Vulnerability;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Pipeline\CoverageRecorderInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\ProgressReporterInterface;

/**
 * Records a finding's reviewer coverage entry and emits the matching
 * `review.finding.reviewed` progress event in one step, so every review
 * outcome — validated, rejected, or errored, on every review path — advances
 * the progress counter exactly once.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class ReviewerCoverageRecorder
{
    public static function record(
        Vulnerability $vulnerability,
        string $status,
        CoverageRecorderInterface $coverageRecorder,
        ProgressReporterInterface $progressReporter,
    ): void {
        $coverageRecorder->recordCoverage(AgentRole::Reviewer->value, $vulnerability->filePath(), $status);
        $progressReporter->report(ProgressEvent::ReviewFindingReviewed->value, [
            'accepted' => 'validated' === $status,
            'type' => $vulnerability->type()->value,
            'file' => $vulnerability->filePath(),
            'line' => $vulnerability->lineStart(),
        ]);
    }
}
