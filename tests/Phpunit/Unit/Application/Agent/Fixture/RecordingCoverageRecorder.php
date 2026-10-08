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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Application\Agent\Fixture;

use Override;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\Vulnerability;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Pipeline\CoverageRecorderInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Pipeline\FailureReasonRecorderInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Pipeline\RejectedFindingRecorderInterface;

/**
 * Test fake: a real coverage recorder that keeps everything it is told in
 * public buffers, so a test can assert which coverage statuses were recorded
 * and which findings/candidates were pushed through the drain side channels
 * without mocking the port. Drain semantics mirror the production recorder
 * (return-and-clear).
 */
final class RecordingCoverageRecorder implements CoverageRecorderInterface, RejectedFindingRecorderInterface, FailureReasonRecorderInterface
{
    /** @var list<array{stage: string, filePath: string, status: string}> */
    public array $coverage = [];

    /** @var list<array{stage: string, filePath: string, reason: string}> */
    public array $failureReasons = [];

    /** @var list<Vulnerability> */
    public array $reviewed = [];

    /** @var list<Vulnerability> */
    public array $found = [];

    /** @var list<Vulnerability> */
    public array $rejected = [];

    #[Override]
    public function recordCoverage(string $stage, string $filePath, string $status): void
    {
        $this->coverage[] = ['stage' => $stage, 'filePath' => $filePath, 'status' => $status];
    }

    #[Override]
    public function recordFailureReason(string $stage, string $filePath, string $reason): void
    {
        $this->failureReasons[] = ['stage' => $stage, 'filePath' => $filePath, 'reason' => $reason];
    }

    #[Override]
    public function recordReviewedFinding(Vulnerability $vulnerability): void
    {
        $this->reviewed[] = $vulnerability;
    }

    #[Override]
    public function recordRejectedFinding(Vulnerability $vulnerability): void
    {
        $this->rejected[] = $vulnerability;
    }

    #[Override]
    public function drainReviewedFindings(): array
    {
        $drained = $this->reviewed;
        $this->reviewed = [];

        return $drained;
    }

    #[Override]
    public function recordFoundVulnerability(Vulnerability $vulnerability): void
    {
        $this->found[] = $vulnerability;
    }

    #[Override]
    public function drainFoundVulnerabilities(): array
    {
        $drained = $this->found;
        $this->found = [];

        return $drained;
    }
}
