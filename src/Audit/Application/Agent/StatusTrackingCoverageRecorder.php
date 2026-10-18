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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent;

use Override;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\AgentRole;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFile;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\Vulnerability;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Pipeline\CoverageRecorderInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Pipeline\FailureReasonRecorderInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Pipeline\InconclusiveAnalysisRecorderInterface;

/**
 * Forwards everything to the recorder it wraps and remembers the attacker's
 * last status per file, so the escalating agent can tell which files the
 * expensive pass actually judged once that pass returns, why a file that
 * ended errored did, and which analyzed files were judged on a partial look.
 *
 * Mutable by design: it accumulates the pass's coverage while the pass runs,
 * so it opts out of the final readonly rule as a per-run accumulator (see
 * .claude/rules/php-classes.md: documented context carriers).
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final class StatusTrackingCoverageRecorder implements CoverageRecorderInterface, FailureReasonRecorderInterface, InconclusiveAnalysisRecorderInterface
{
    private const string INCONCLUSIVE = 'inconclusive';

    private const array CONCLUSIVE_STATUSES = ['analyzed', 'cached'];

    private const array ANALYZED_STATUSES = [...self::CONCLUSIVE_STATUSES, self::INCONCLUSIVE];

    /** @var array<string, string> */
    private array $lastAttackerStatus = [];

    /** @var array<string, string> */
    private array $failureReasons = [];

    public function __construct(
        private readonly CoverageRecorderInterface $coverageRecorder,
    ) {}

    #[Override]
    public function recordCoverage(string $stage, string $filePath, string $status): void
    {
        $this->coverageRecorder->recordCoverage($stage, $filePath, $status);

        if (AgentRole::Attacker->value === $stage) {
            $this->lastAttackerStatus[$filePath] = $status;
            unset($this->failureReasons[$filePath]);
        }
    }

    #[Override]
    public function recordInconclusiveAnalysis(string $stage, string $filePath): void
    {
        if ($this->coverageRecorder instanceof InconclusiveAnalysisRecorderInterface) {
            $this->coverageRecorder->recordInconclusiveAnalysis($stage, $filePath);
        }

        if (AgentRole::Attacker->value === $stage) {
            $this->lastAttackerStatus[$filePath] = self::INCONCLUSIVE;
        }
    }

    #[Override]
    public function recordFailureReason(string $stage, string $filePath, string $reason): void
    {
        if ($this->coverageRecorder instanceof FailureReasonRecorderInterface) {
            $this->coverageRecorder->recordFailureReason($stage, $filePath, $reason);
        }

        if (AgentRole::Attacker->value === $stage) {
            $this->failureReasons[$filePath] = $reason;
        }
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

    /**
     * How the attacker left a chunk: `analyzed` when its last word on every
     * file is that it analyzed the file or served it from its cache, `errored`
     * otherwise.
     *
     * @param list<ProjectFile> $chunk
     */
    public function chunkStatus(array $chunk): string
    {
        $analyzed = array_flip($this->analyzedFiles());

        foreach ($chunk as $projectFile) {
            if (!\array_key_exists($projectFile->relativePath(), $analyzed)) {
                return 'errored';
            }
        }

        return 'analyzed';
    }

    /**
     * Why the chunk ended errored, as the first of its files left unanalyzed
     * that has a recorded reason says; null for a chunk that was analyzed or
     * whose failure named no reason.
     *
     * @param list<ProjectFile> $chunk
     */
    public function chunkFailureReason(array $chunk): ?string
    {
        foreach ($chunk as $projectFile) {
            if (\array_key_exists($projectFile->relativePath(), $this->failureReasons)) {
                return $this->failureReasons[$projectFile->relativePath()];
            }
        }

        return null;
    }

    /**
     * @return list<string>
     */
    public function analyzedFiles(): array
    {
        return $this->filesLastLeft(self::ANALYZED_STATUSES);
    }

    /**
     * The analyzed files whose answer is a verdict: every file in
     * {@see analyzedFiles()} but those the model judged on a partial look.
     *
     * @return list<string>
     */
    public function conclusiveFiles(): array
    {
        return $this->filesLastLeft(self::CONCLUSIVE_STATUSES);
    }

    /**
     * @param list<string> $statuses
     *
     * @return list<string>
     */
    private function filesLastLeft(array $statuses): array
    {
        return array_keys(array_filter(
            $this->lastAttackerStatus,
            static fn (string $status): bool => \in_array($status, $statuses, true),
        ));
    }
}
