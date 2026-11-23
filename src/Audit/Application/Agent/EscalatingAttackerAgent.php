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
 * Runs a cheap-model attacker over every chunk, then the expensive model over
 * only the files it flagged, with the cheap findings on each chunk's files as
 * unverified `candidateFindings` to confirm, refine or discard.
 *
 * Keeps every expensive finding and drops a cheap one on a file the expensive
 * pass judged: `analyzed` or `cached`, unless answered at the tool-call limit
 * without a finding. Passes the other cheap findings through, deduplicated by
 * `Vulnerability::id()`.
 *
 * @internal not part of the BC promise, see docs/versioning.md
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

        try {
            $expensiveFindings = $this->expensiveAttacker->analyze(
                $attackerAnalysisRequest->withFilesAndCandidateFindings($hotFiles, $cheapFindings),
                $statusTrackingCoverageRecorder,
            );
        } finally {
            $analyzedByExpensive = $statusTrackingCoverageRecorder->conclusiveFiles();
            $this->withdrawFromRecovery($coverageRecorder, array_filter(
                $cheapFindings,
                fn (Vulnerability $vulnerability): bool => $this->isJudged($vulnerability, $analyzedByExpensive),
            ));
        }

        return $this->merge($cheapFindings, $expensiveFindings, $analyzedByExpensive);
    }

    /**
     * Removes the discarded cheap findings from the recoverable ones, so
     * draining them cannot undo the discard, even after a budget cap or a
     * provider failure stopped the deep pass.
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
     * Compares normalized paths, since a finding's file path is free text the
     * LLM echoes: a leading `./` must not keep a flagged file out of the
     * expensive pass.
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
