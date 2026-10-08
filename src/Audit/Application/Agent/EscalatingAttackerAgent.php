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
use Psr\Log\LoggerInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFile;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\Vulnerability;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Pipeline\CoverageRecorderInterface;

/**
 * @internal not part of the BC promise — see docs/versioning.md
 *
 * Two-pass attacker for cost-sensitive audits.
 *
 *   1. A cheap-model attacker (e.g. claude-haiku-4-5) sweeps every chunk.
 *      In typical Symfony projects most files are inert — the cheap sweep
 *      converges quickly with no findings.
 *
 *   2. If the cheap pass found anything, an expensive-model attacker
 *      (e.g. claude-opus-4-7) re-analyses ONLY the files the cheap pass
 *      flagged. Those re-runs receive the cheap findings as
 *      candidateFindings — leads to confirm, refine or discard, never
 *      reviewer-validated context — so the deeper model re-reports what
 *      it confirms instead of treating them as settled, and still hunts
 *      for what the first pass missed.
 *
 *   3. The two result sets are merged: every expensive finding is kept; a
 *      cheap finding on a file the expensive pass analyzed (`analyzed` or
 *      `cached`) is dropped, since the deep pass re-reports what it confirms
 *      and its silence is a discard — so a refined location or type never
 *      reaches the reviewer twice; cheap findings on files it did not judge
 *      (cold files, or hot files it errored on) pass through, deduplicated
 *      by Vulnerability::id(). A discarded cheap finding also leaves the
 *      coverage recorder's recoverable findings, so draining them after the
 *      pass cannot bring it back.
 *
 * Net effect: full-project coverage at roughly 1/3 to 1/5 of running the
 * expensive model on every chunk, with detection quality close to the
 * pure expensive baseline because hot zones still get the deep treatment.
 */
final readonly class EscalatingAttackerAgent implements AttackerAgentInterface
{
    public function __construct(
        private AttackerAgentInterface $cheapAttacker,
        private AttackerAgentInterface $expensiveAttacker,
        private LoggerInterface $logger,
    ) {}

    #[Override]
    public function analyze(AttackerAnalysisRequest $attackerAnalysisRequest, CoverageRecorderInterface $coverageRecorder): array
    {
        $files = $attackerAnalysisRequest->files;

        $this->logger->info('Escalation: running cheap-model first pass', [
            'files' => \count($files),
        ]);

        $cheapFindings = $this->cheapAttacker->analyze($attackerAnalysisRequest, $coverageRecorder);

        if ([] === $cheapFindings) {
            $this->logger->info('Escalation: cheap pass found nothing, skipping expensive pass');

            return [];
        }

        $hotFiles = $this->filterToHotFiles($files, $cheapFindings);

        $this->logger->info('Escalation: running expensive-model deep pass on hot files', [
            'cheap_findings' => \count($cheapFindings),
            'hot_files' => \count($hotFiles),
            'cold_files_skipped' => \count($files) - \count($hotFiles),
        ]);

        $statusTrackingCoverageRecorder = new StatusTrackingCoverageRecorder($coverageRecorder);
        $expensiveFindings = $this->expensiveAttacker->analyze(
            $attackerAnalysisRequest->withFilesAndCandidateFindings($hotFiles, $cheapFindings),
            $statusTrackingCoverageRecorder,
        );

        $analyzedByExpensive = $statusTrackingCoverageRecorder->analyzedFiles();
        $this->withdrawFromRecovery($coverageRecorder, array_filter(
            $cheapFindings,
            fn (Vulnerability $vulnerability): bool => $this->isJudged($vulnerability, $analyzedByExpensive),
        ));

        return $this->merge($cheapFindings, $expensiveFindings, $analyzedByExpensive);
    }

    /**
     * A cheap finding the deep pass judged and dropped was recorded for
     * recovery while the cheap pass ran. Left there, the orchestrator's drain
     * of recovered findings would bring it back and undo the discard, so it
     * leaves the buffer and only a finding this pass keeps, or one a chunk
     * recorded but could not return, stays recoverable.
     *
     * @param array<Vulnerability> $discarded
     */
    private function withdrawFromRecovery(CoverageRecorderInterface $coverageRecorder, array $discarded): void
    {
        foreach ($coverageRecorder->drainFoundVulnerabilities() as $vulnerability) {
            if (!\in_array($vulnerability, $discarded, true)) {
                $coverageRecorder->recordFoundVulnerability($vulnerability);
            }
        }
    }

    /**
     * @param list<string> $analyzedByExpensive
     */
    private function isJudged(Vulnerability $vulnerability, array $analyzedByExpensive): bool
    {
        return \in_array(EchoedFilePath::normalize($vulnerability->filePath()), $analyzedByExpensive, true);
    }

    /**
     * `Vulnerability::filePath()` is free text echoed back by the LLM — the
     * `record_vulnerability` schema only constrains it to a non-blank
     * string, with no cross-check against the chunk's real file list. A
     * cheap-model quirk like a leading `./` must not make a real cheap
     * finding's file silently excluded from the expensive pass, so both
     * sides are normalized before comparing.
     *
     * @param ProjectFile[]   $files
     * @param Vulnerability[] $cheapFindings
     *
     * @return list<ProjectFile>
     */
    private function filterToHotFiles(array $files, array $cheapFindings): array
    {
        $hotPaths = array_map(
            static fn (Vulnerability $vulnerability): string => EchoedFilePath::normalize($vulnerability->filePath()),
            $cheapFindings,
        );

        return array_values(array_filter(
            $files,
            static fn (ProjectFile $projectFile): bool => \in_array(EchoedFilePath::normalize($projectFile->relativePath()), $hotPaths, true),
        ));
    }

    /**
     * @param Vulnerability[] $cheap
     * @param Vulnerability[] $expensive
     * @param list<string>    $analyzedByExpensive
     *
     * @return list<Vulnerability>
     */
    private function merge(array $cheap, array $expensive, array $analyzedByExpensive): array
    {
        $byId = [];

        foreach ($expensive as $vulnerability) {
            $byId[$vulnerability->id()] = $vulnerability;
        }

        foreach ($cheap as $vulnerability) {
            if ($this->isJudged($vulnerability, $analyzedByExpensive) || \array_key_exists($vulnerability->id(), $byId)) {
                continue;
            }

            $byId[$vulnerability->id()] = $vulnerability;
        }

        return array_values($byId);
    }
}
