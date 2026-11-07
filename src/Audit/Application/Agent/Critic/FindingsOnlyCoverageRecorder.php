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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\Critic;

use Override;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\Vulnerability;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Pipeline\CoverageRecorderInterface;

/**
 * Hands the analysis of a coverage gap the findings recorder of the run but
 * none of its coverage ledger: the loop already analyzed the gap's files, so
 * how the extra look at them ends never makes the audit incomplete.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class FindingsOnlyCoverageRecorder implements CoverageRecorderInterface
{
    public function __construct(
        private CoverageRecorderInterface $coverageRecorder,
    ) {}

    #[Override]
    public function recordCoverage(string $stage, string $filePath, string $status): void
    {
        // intentionally noop
    }

    #[Override]
    public function recordReviewedFinding(Vulnerability $vulnerability): void
    {
        $this->coverageRecorder->recordReviewedFinding($vulnerability);
    }

    #[Override]
    public function drainReviewedFindings(): array
    {
        return $this->coverageRecorder->drainReviewedFindings();
    }

    #[Override]
    public function recordFoundVulnerability(Vulnerability $vulnerability): void
    {
        $this->coverageRecorder->recordFoundVulnerability($vulnerability);
    }

    #[Override]
    public function drainFoundVulnerabilities(): array
    {
        return $this->coverageRecorder->drainFoundVulnerabilities();
    }
}
