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
use VinceAmstoutz\SecurityAuditor\Audit\Application\Agent\AttackerAgentInterface;
use VinceAmstoutz\SecurityAuditor\Audit\Application\Agent\AttackerAnalysisRequest;
use VinceAmstoutz\SecurityAuditor\Audit\Domain\Model\ProjectFile;
use VinceAmstoutz\SecurityAuditor\Audit\Domain\Model\Vulnerability;
use VinceAmstoutz\SecurityAuditor\Audit\Domain\Pipeline\CoverageRecorderInterface;

/**
 * Test fake returning a fixed finding set and recording what it was invoked
 * with, so tests can assert on call count, files and previous-findings context
 * without mocking an internal collaborator. Like a real attacker, every returned
 * finding goes through the coverage recorder before the call resolves;
 * `$throwsBeforeReturning` simulates a mid-run abort after that.
 * `$hiddenRecordedFindings` simulates a chunk that swallowed a generic
 * `Throwable` after a partial success: recorded via the coverage recorder but
 * absent from the returned list, as a real chunk analyzer leaves it.
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
     * @param list<Vulnerability> $returnFindings         findings returned on every call
     * @param list<Vulnerability> $hiddenRecordedFindings findings recorded via the coverage recorder but omitted from the returned list
     */
    public function __construct(
        private readonly array $returnFindings = [],
        private readonly ?Throwable $throwable = null,
        private readonly array $hiddenRecordedFindings = [],
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

        foreach ([...$this->returnFindings, ...$this->hiddenRecordedFindings] as $returnFinding) {
            $coverageRecorder->recordFoundVulnerability($returnFinding);
        }

        if ($this->throwable instanceof Throwable) {
            throw $this->throwable;
        }

        return $this->returnFindings;
    }
}
