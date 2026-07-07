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
use Throwable;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\AttackerAgentInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\AttackerAnalysisRequest;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFile;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\Vulnerability;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Pipeline\CoverageRecorderInterface;

/**
 * Test fake: a real AttackerAgentInterface implementation that returns a fixed
 * finding set on every call and records what it was invoked with, so tests can
 * assert on call count, the files passed, and the previousFindings context
 * without mocking an internal Application collaborator. Like a real attacker,
 * every returned finding is pushed through the coverage recorder's
 * `recordFoundVulnerability()` side channel before the call resolves; an
 * optional `$throwsBeforeReturning` lets a test simulate a mid-run abort after
 * those findings were already recorded.
 */
final class RecordingAttackerAgent implements AttackerAgentInterface
{
    public int $callCount = 0;

    /** @var list<ProjectFile> */
    public array $lastFiles = [];

    /** @var list<Vulnerability> */
    public array $lastPreviousFindings = [];

    /** @var list<int> */
    public array $previousFindingsCountPerCall = [];

    /** @var list<Vulnerability> */
    public array $lastRejectedFindings = [];

    /** @var list<int> */
    public array $rejectedFindingsCountPerCall = [];

    /**
     * @param list<Vulnerability> $returnFindings findings returned on every call
     */
    public function __construct(
        private readonly array $returnFindings = [],
        private readonly ?Throwable $throwable = null,
    ) {}

    #[Override]
    public function analyze(AttackerAnalysisRequest $attackerAnalysisRequest, CoverageRecorderInterface $coverageRecorder): array
    {
        ++$this->callCount;
        $this->lastFiles = $attackerAnalysisRequest->files;
        $this->lastPreviousFindings = $attackerAnalysisRequest->previousFindings;
        $this->previousFindingsCountPerCall[] = \count($attackerAnalysisRequest->previousFindings);
        $this->lastRejectedFindings = $attackerAnalysisRequest->rejectedFindings;
        $this->rejectedFindingsCountPerCall[] = \count($attackerAnalysisRequest->rejectedFindings);

        foreach ($this->returnFindings as $returnFinding) {
            $coverageRecorder->recordFoundVulnerability($returnFinding);
        }

        if ($this->throwable instanceof Throwable) {
            throw $this->throwable;
        }

        return $this->returnFindings;
    }
}
