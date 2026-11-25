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
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\Review\ReviewerCoverageRecorder;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Budget\Exception\BudgetExceededException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Scan\ScanPathFilter;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\LLMProviderException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\AuditContext;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProgressEvent;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFile;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\SymfonyMapping;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\Vulnerability;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\ProgressReporterInterface;

/**
 * @internal not part of the BC promise, see docs/versioning.md
 */
final readonly class AuditOrchestrator implements AuditOrchestratorInterface
{
    public const int DEFAULT_MAX_ITERATIONS = 3;

    public const float DEFAULT_MIN_CONFIDENCE = 0.6;

    public function __construct(
        private AttackerAgentInterface $attackerAgent,
        private ReviewerAgentInterface $reviewerAgent,
        private LoggerInterface $logger,
        private AuditLoopSettings $auditLoopSettings,
        private ProgressReporterInterface $progressReporter,
    ) {}

    /**
     * @throws BudgetExceededException
     * @throws LLMProviderException
     */
    #[Override]
    public function orchestrate(AuditContext $auditContext): void
    {
        $mapping = $auditContext->mapping();

        if (!$mapping instanceof SymfonyMapping) {
            $this->logger->warning('No mapping available, skipping audit');

            return;
        }

        $files = $auditContext->projectFiles();
        $iteration = 0;

        $this->logger->info('Starting attacker vs reviewer loop', [
            'max_iterations' => $this->auditLoopSettings->maxIterations,
        ]);

        $scanPaths = $auditContext->scanPaths();
        $this->progressReporter->report(ProgressEvent::AuditStarted->value, [
            'files' => \count($files),
            'controllers' => \count(ScanPathFilter::apply($mapping->controllers(), $scanPaths)),
            'voters' => \count(ScanPathFilter::apply($mapping->voters(), $scanPaths)),
            'forms' => \count(ScanPathFilter::apply($mapping->forms(), $scanPaths)),
        ]);

        do {
            ++$iteration;
            $newFindings = $this->runIteration($mapping, $files, $auditContext, $iteration);
        } while (0 !== $newFindings && $iteration < $this->auditLoopSettings->maxIterations);

        $auditContext->setMeta('audit.baseline_skipped', \count(array_unique(array_map(
            static fn (Vulnerability $vulnerability): string => $vulnerability->fingerprint(),
            $auditContext->baselineSkippedFindings(),
        ))));
        $auditContext->setMeta('audit.iterations', $iteration);
        $auditContext->setMeta('audit.total_findings', \count($auditContext->vulnerabilities()));
        $auditContext->setMeta('audit.validated', \count($auditContext->validatedVulnerabilities()));
        $auditContext->setMeta('audit.risk_score', $auditContext->riskScore());
    }

    /**
     * @param list<ProjectFile> $files
     *
     * @throws BudgetExceededException
     * @throws LLMProviderException
     */
    private function runIteration(SymfonyMapping $symfonyMapping, array $files, AuditContext $auditContext, int $iteration): int
    {
        $this->logger->info(\sprintf('Audit iteration %d/%d', $iteration, $this->auditLoopSettings->maxIterations));
        $this->progressReporter->report(ProgressEvent::AuditIterationStarted->value, [
            'iteration' => $iteration,
            'max_iterations' => $this->auditLoopSettings->maxIterations,
        ]);

        $previousFindings = array_values($auditContext->validatedVulnerabilities());
        $rejectedFindings = $this->rejectedFindings($auditContext);
        $knownFindings = [...$previousFindings, ...$auditContext->baselineSkippedFindings()];
        $staticCandidates = FindingPrecedence::collapseById($auditContext->drainStaticCandidates());
        $attackerAnalysisRequest = new AttackerAnalysisRequest(
            files: $files,
            symfonyMapping: $symfonyMapping,
            bypassCache: $auditContext->isCacheBypassed(),
            previousFindings: $knownFindings,
            rejectedFindings: $rejectedFindings,
            toolFiles: $this->auditLoopSettings->toolFiles($auditContext),
        );
        $attackerFindings = $this->analyzeWithRecovery($attackerAnalysisRequest, $auditContext, $staticCandidates);

        if ([] === $staticCandidates && [] === $attackerFindings) {
            $this->logger->info('Attacker found no new findings, stopping');
            $this->progressReporter->report(ProgressEvent::ReviewSkipped->value, ['reason' => 'no_new_findings']);

            return 0;
        }

        $reviewCandidates = $this->reviewCandidates($staticCandidates, $attackerFindings, $auditContext);

        if ([] === $reviewCandidates) {
            $this->logger->info('Every remaining finding is baseline-accepted, stopping');
            $this->progressReporter->report(ProgressEvent::ReviewSkipped->value, ['reason' => 'all_baseline_accepted']);

            return 0;
        }

        $this->progressReporter->report(ProgressEvent::ReviewStarted->value, [
            'findings' => \count($reviewCandidates),
        ]);

        $staticCandidatesById = $this->byId($staticCandidates);
        $reviewed = $this->reviewPersistingOnAbort($reviewCandidates, $staticCandidatesById, $files, $auditContext);
        $newFindings = $this->persistReviewedFindings($this->mergeRecoveredFindings($reviewed, $auditContext->drainReviewedFindings()), $auditContext, $staticCandidatesById);

        $acceptedCount = \count(array_filter(
            $reviewed,
            static fn (Vulnerability $vulnerability): bool => $vulnerability->isReviewerValidated(),
        ));
        $this->reportReviewCompleted($reviewed, $acceptedCount, $auditContext);

        $this->logger->info('Iteration complete', [
            'iteration' => $iteration,
            'attacker_found' => \count($staticCandidates) + \count($attackerFindings),
            'reviewer_accepted' => $acceptedCount,
            'new_unique' => $newFindings,
            'total' => \count($auditContext->vulnerabilities()),
            'previous_validated_passed_back' => \count($previousFindings),
        ]);

        return $newFindings;
    }

    /**
     * Returns the findings to review: the static candidates no attacker finding
     * replaces and the attacker findings, each without those the baseline
     * accepts. An attacker finding that would replace a baseline-accepted
     * static candidate is left out with it.
     *
     * @param list<Vulnerability> $staticCandidates one per id
     * @param list<Vulnerability> $attackerFindings
     *
     * @return list<Vulnerability>
     */
    private function reviewCandidates(array $staticCandidates, array $attackerFindings, AuditContext $auditContext): array
    {
        $pendingStaticCandidates = $this->withoutBaselineAccepted($staticCandidates, $auditContext);
        $acceptedStaticCandidates = array_values(array_diff_key($this->byId($staticCandidates), $this->byId($pendingStaticCandidates)));

        return [
            ...FindingOverlap::outside($pendingStaticCandidates, $attackerFindings),
            ...$this->withoutBaselineAccepted(FindingOverlap::outside($attackerFindings, $acceptedStaticCandidates), $auditContext),
        ];
    }

    /**
     * @param list<Vulnerability> $findings
     *
     * @return array<string, Vulnerability>
     */
    private function byId(array $findings): array
    {
        return array_combine(array_map(static fn (Vulnerability $finding): string => $finding->id(), $findings), $findings);
    }

    /**
     * @param list<Vulnerability>          $findings
     * @param array<string, Vulnerability> $staticCandidatesById
     * @param list<ProjectFile>            $files
     *
     * @return list<Vulnerability>
     *
     * @throws BudgetExceededException
     * @throws LLMProviderException
     */
    private function reviewPersistingOnAbort(array $findings, array $staticCandidatesById, array $files, AuditContext $auditContext): array
    {
        try {
            return $this->review($findings, $staticCandidatesById, $files, $auditContext);
        } catch (BudgetExceededException|LLMProviderException $exception) {
            $this->persistReviewedFindings($auditContext->drainReviewedFindings(), $auditContext);

            throw $exception;
        }
    }

    /**
     * Reviews the static candidates among `$findings` with the others of
     * their file, so each file is sent once.
     *
     * @param list<Vulnerability>          $findings
     * @param array<string, Vulnerability> $staticCandidatesById
     * @param list<ProjectFile>            $files
     *
     * @return list<Vulnerability>
     *
     * @throws BudgetExceededException
     * @throws LLMProviderException
     */
    private function review(array $findings, array $staticCandidatesById, array $files, AuditContext $auditContext): array
    {
        $isStaticCandidate = static fn (Vulnerability $vulnerability): bool => \array_key_exists($vulnerability->id(), $staticCandidatesById);
        $staticCandidates = array_values(array_filter($findings, $isStaticCandidate));
        $toolFiles = $this->auditLoopSettings->toolFiles($auditContext);

        try {
            $reviewed = $this->reviewerAgent->review(
                array_values(array_filter($findings, static fn (Vulnerability $vulnerability): bool => !$isStaticCandidate($vulnerability))),
                $files,
                $auditContext,
                $auditContext->isCacheBypassed(),
                $toolFiles,
            );
        } catch (BudgetExceededException $budgetExceededException) {
            ReviewerCoverageRecorder::recordEach($staticCandidates, 'aborted', $auditContext, $this->progressReporter);

            throw $budgetExceededException;
        } catch (LLMProviderException $llmProviderException) {
            ReviewerCoverageRecorder::recordEach($staticCandidates, 'errored', $auditContext, $this->progressReporter);

            throw $llmProviderException;
        }

        return [...$reviewed, ...$this->reviewerAgent->reviewByFile($staticCandidates, $files, $auditContext, $auditContext->isCacheBypassed(), $toolFiles)];
    }

    /**
     * @param list<Vulnerability> $reviewed
     */
    private function reportReviewCompleted(array $reviewed, int $acceptedCount, AuditContext $auditContext): void
    {
        $rejectedCount = \count(array_filter(
            $reviewed,
            static fn (Vulnerability $vulnerability): bool => self::wasRejected($vulnerability, $auditContext),
        ));
        $this->progressReporter->report(ProgressEvent::ReviewCompleted->value, [
            'accepted' => $acceptedCount,
            'rejected' => $rejectedCount,
            'failed' => \count($reviewed) - $acceptedCount - $rejectedCount,
        ]);
    }

    /**
     * @param list<Vulnerability> $staticCandidates reviewed with the recovered findings when the attacker aborts
     *
     * @return list<Vulnerability> the findings at or above the confidence floor, one per id, copies below it dropped before collapsing
     *
     * @throws BudgetExceededException
     * @throws LLMProviderException
     */
    private function analyzeWithRecovery(AttackerAnalysisRequest $attackerAnalysisRequest, AuditContext $auditContext, array $staticCandidates): array
    {
        try {
            $rawFindings = $this->attackerAgent->analyze($attackerAnalysisRequest, $auditContext);
        } catch (BudgetExceededException|LLMProviderException $attackerException) {
            $this->reviewRecoveredFindings($staticCandidates, $auditContext->drainFoundVulnerabilities(), $attackerAnalysisRequest->files, $auditContext);

            throw $attackerException;
        }

        return $this->mergeRecoveredFindings(
            $this->filterByConfidence($rawFindings),
            $this->filterByConfidence($auditContext->drainFoundVulnerabilities()),
        );
    }

    /**
     * Merges by id the findings drained from the coverage recorder, which a
     * swallowed failure may have kept out of the agent's return value.
     * Findings sharing an id collapse to the one `FindingPrecedence` keeps.
     *
     * @param list<Vulnerability> $rawFindings
     * @param list<Vulnerability> $recoveredFindings
     *
     * @return list<Vulnerability>
     */
    private function mergeRecoveredFindings(array $rawFindings, array $recoveredFindings): array
    {
        return FindingPrecedence::collapseById([...$rawFindings, ...$recoveredFindings]);
    }

    /**
     * Filters and reviews the attacker candidates found before a mid-run abort
     * as a completed iteration would. Persists the verdicts reached before a
     * further abort and swallows it, so the caller sees the original abort.
     *
     * @param list<Vulnerability> $staticCandidates one per id
     * @param list<Vulnerability> $rawFindings
     * @param list<ProjectFile>   $files
     */
    private function reviewRecoveredFindings(array $staticCandidates, array $rawFindings, array $files, AuditContext $auditContext): void
    {
        $filtered = $this->reviewCandidates($staticCandidates, $this->filterByConfidence($rawFindings), $auditContext);

        if ([] === $filtered) {
            $this->progressReporter->report(ProgressEvent::ReviewSkipped->value, ['reason' => 'nothing_recovered']);

            return;
        }

        $this->progressReporter->report(ProgressEvent::ReviewStarted->value, [
            'findings' => \count($filtered),
        ]);

        try {
            $reviewed = $this->review($filtered, $this->byId($staticCandidates), $files, $auditContext);
        } catch (BudgetExceededException|LLMProviderException) {
            $this->persistReviewedFindings($auditContext->drainReviewedFindings(), $auditContext);

            return;
        }

        $this->persistReviewedFindings($reviewed, $auditContext);
    }

    /**
     * Returns the findings the reviewer rejected in earlier iterations, for the
     * attacker to stop re-reporting. A finding whose review failed is left out.
     *
     * @return list<Vulnerability>
     */
    private function rejectedFindings(AuditContext $auditContext): array
    {
        return array_values(array_filter(
            $auditContext->vulnerabilities(),
            static fn (Vulnerability $vulnerability): bool => self::wasRejected($vulnerability, $auditContext),
        ));
    }

    /**
     * Returns false for a failed review, which reached no verdict.
     */
    private static function wasRejected(Vulnerability $vulnerability, AuditContext $auditContext): bool
    {
        return !$vulnerability->isReviewerValidated() && $auditContext->wasRejectedByReviewer($vulnerability);
    }

    /**
     * Skips at most as many findings per fingerprint as the baseline accepts
     * occurrences of it, from credits spent once across all iterations. A
     * re-report of a skipped finding (same fingerprint, overlapping lines)
     * stays skipped without a credit.
     *
     * @param list<Vulnerability> $findings
     *
     * @return list<Vulnerability>
     */
    private function withoutBaselineAccepted(array $findings, AuditContext $auditContext): array
    {
        $remaining = [];
        foreach ($findings as $finding) {
            if ($this->isReReportedBaselineSkip($finding, $auditContext)) {
                continue;
            }

            if ($auditContext->consumeBaselineCreditFor($finding)) {
                $auditContext->recordBaselineSkippedFinding($finding);
                $this->recordBaselineSkip($finding, $auditContext);

                continue;
            }

            $remaining[] = $finding;
        }

        return $remaining;
    }

    private function isReReportedBaselineSkip(Vulnerability $vulnerability, AuditContext $auditContext): bool
    {
        foreach ($auditContext->baselineSkippedFindingsWith($vulnerability->fingerprint()) as $skippedFinding) {
            if ($this->linesOverlap($skippedFinding->lineStart(), $skippedFinding->lineEnd(), $vulnerability->lineStart(), $vulnerability->lineEnd())) {
                return true;
            }
        }

        return false;
    }

    private function recordBaselineSkip(Vulnerability $vulnerability, AuditContext $auditContext): void
    {
        if (1 < \count($auditContext->baselineSkippedFindingsWith($vulnerability->fingerprint()))) {
            return;
        }

        $this->logger->info('Baseline-accepted finding skipped before review', [
            'fingerprint' => $vulnerability->fingerprint(),
            'type' => $vulnerability->type()->value,
            'file' => $vulnerability->filePath(),
        ]);
        $this->progressReporter->report(ProgressEvent::BaselineFindingSkipped->value, [
            'type' => $vulnerability->type()->value,
            'file' => $vulnerability->filePath(),
            'line' => $vulnerability->lineStart(),
            'title' => $vulnerability->title(),
        ]);
    }

    /**
     * @param list<Vulnerability> $vulnerabilities
     *
     * @return list<Vulnerability>
     */
    private function filterByConfidence(array $vulnerabilities): array
    {
        return array_values(array_filter($vulnerabilities, $this->passesConfidenceFloor(...)));
    }

    private function passesConfidenceFloor(Vulnerability $vulnerability): bool
    {
        if ($vulnerability->confidence() >= $this->auditLoopSettings->minConfidence) {
            return true;
        }

        $this->logger->warning('Dropping finding below the confidence floor', [
            'type' => $vulnerability->type()->value,
            'file' => $vulnerability->filePath(),
            'confidence' => $vulnerability->confidence(),
            'min_confidence' => $this->auditLoopSettings->minConfidence,
        ]);

        return false;
    }

    /**
     * Returns how many admitted findings are new, leaving out the static
     * candidates: only what the attacker discovers calls for another iteration.
     *
     * @param list<Vulnerability>          $reviewed
     * @param array<string, Vulnerability> $staticCandidatesById
     */
    private function persistReviewedFindings(array $reviewed, AuditContext $auditContext, array $staticCandidatesById = []): int
    {
        $newFindings = 0;

        foreach ($reviewed as $vulnerability) {
            $replaced = $this->admit($vulnerability, $auditContext);
            if (null === $replaced) {
                continue;
            }

            $auditContext->addVulnerability($vulnerability);
            if (!\array_key_exists($vulnerability->id(), $staticCandidatesById) && !FindingPrecedence::onlyOutranksOnConfidence($vulnerability, $replaced)) {
                ++$newFindings;
            }
        }

        return $newFindings;
    }

    /**
     * Admits a same-id repeat only when it corrects the earlier verdict: an
     * accept replaces a reject and a validated verdict replaces a validated one
     * when it raises the severity or changes the type. A rejection never
     * displaces a validated entry and no verdict lowers a reported severity.
     * A finding overlapping validated findings of the same file and type is
     * admitted only when it outranks them all. It then replaces them.
     *
     * @return list<Vulnerability>|null the validated findings the admitted one replaces, null when it is a duplicate
     */
    private function admit(Vulnerability $vulnerability, AuditContext $auditContext): ?array
    {
        $existingById = $auditContext->vulnerabilities()[$vulnerability->id()] ?? null;
        if ($existingById instanceof Vulnerability && $this->isSameIdDuplicate($existingById, $vulnerability)) {
            return null;
        }

        $overlapped = $this->overlappingValidated($vulnerability, $auditContext);
        if (!FindingPrecedence::prevailsOverAll($vulnerability, $overlapped)) {
            return null;
        }

        foreach ($overlapped as $existing) {
            $auditContext->removeVulnerability($existing->id());
        }

        return $overlapped;
    }

    /**
     * @return list<Vulnerability>
     */
    private function overlappingValidated(Vulnerability $vulnerability, AuditContext $auditContext): array
    {
        return array_values(array_filter(
            $auditContext->vulnerabilitiesIn($vulnerability->filePath()),
            fn (Vulnerability $existing): bool => $existing->isReviewerValidated()
                && $existing->type() === $vulnerability->type()
                && $this->linesOverlap(
                    $existing->lineStart(),
                    $existing->lineEnd(),
                    $vulnerability->lineStart(),
                    $vulnerability->lineEnd(),
                ),
        ));
    }

    private function isSameIdDuplicate(Vulnerability $existingById, Vulnerability $vulnerability): bool
    {
        if ($existingById->isReviewerValidated()) {
            if (!$vulnerability->isReviewerValidated()) {
                return true;
            }

            return !FindingPrecedence::prevails($vulnerability, $existingById)
                && !$this->isReclassification($existingById, $vulnerability);
        }

        return !$vulnerability->isReviewerValidated();
    }

    private function isReclassification(Vulnerability $existingById, Vulnerability $vulnerability): bool
    {
        return $existingById->severity() === $vulnerability->severity()
            && $existingById->type() !== $vulnerability->type();
    }

    private function linesOverlap(int $start1, int $end1, int $start2, int $end2): bool
    {
        return $start1 <= $end2 && $start2 <= $end1;
    }
}
