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
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Budget\Exception\BudgetExceededException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\LLMProviderException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\AuditContext;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProgressEvent;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFile;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\SymfonyMapping;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\Vulnerability;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\ProgressReporterInterface;

/**
 * `config/services.php` always aliases `ProgressReporterInterface` to
 * `ProgressReporterHolder`, so it is required here rather than falling back to
 * `NullProgressReporter`.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class AuditOrchestrator implements AuditOrchestratorInterface
{
    private const string SKIPPED_FINGERPRINTS_META = 'audit.baseline_skipped_fingerprints';

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

        $this->progressReporter->report(ProgressEvent::AuditStarted->value, [
            'files' => \count($files),
            'controllers' => \count($mapping->controllers()),
            'voters' => \count($mapping->voters()),
            'forms' => \count($mapping->forms()),
        ]);

        do {
            ++$iteration;
            $this->logger->info(\sprintf('Audit iteration %d/%d', $iteration, $this->auditLoopSettings->maxIterations));
            $this->progressReporter->report(ProgressEvent::AuditIterationStarted->value, [
                'iteration' => $iteration,
                'max_iterations' => $this->auditLoopSettings->maxIterations,
            ]);

            $previousFindings = array_values($auditContext->validatedVulnerabilities());
            $rejectedFindings = $this->rejectedFindings($auditContext);
            $rawFindings = $this->analyzeWithRecovery($mapping, $files, $previousFindings, $rejectedFindings, $auditContext);
            $filtered = $this->filterByConfidence($rawFindings);

            if ([] === $filtered) {
                $this->logger->info('Attacker found no new findings, stopping');
                break;
            }

            $reviewCandidates = $this->withoutBaselineAccepted($filtered, $auditContext);

            if ([] === $reviewCandidates) {
                $this->logger->info('Every remaining finding is baseline-accepted, stopping');
                break;
            }

            $filtered = $reviewCandidates;

            $this->progressReporter->report(ProgressEvent::ReviewStarted->value, [
                'findings' => \count($filtered),
            ]);

            try {
                $reviewed = $this->reviewerAgent->review($filtered, $files, $auditContext, $auditContext->isCacheBypassed());
            } catch (BudgetExceededException|LLMProviderException $exception) {
                $this->persistReviewedFindings($auditContext->drainReviewedFindings(), $auditContext);

                throw $exception;
            }

            $newFindings = $this->persistReviewedFindings($this->mergeRecoveredFindings($reviewed, $auditContext->drainReviewedFindings()), $auditContext);

            $acceptedCount = \count(array_filter(
                $reviewed,
                static fn (Vulnerability $vulnerability): bool => $vulnerability->isReviewerValidated(),
            ));
            $this->progressReporter->report(ProgressEvent::ReviewCompleted->value, [
                'accepted' => $acceptedCount,
                'rejected' => \count($reviewed) - $acceptedCount,
            ]);

            $this->logger->info('Iteration complete', [
                'iteration' => $iteration,
                'attacker_found' => \count($rawFindings),
                'reviewer_accepted' => $acceptedCount,
                'new_unique' => $newFindings,
                'total' => \count($auditContext->vulnerabilities()),
                'previous_validated_passed_back' => \count($previousFindings),
            ]);

            if (0 === $newFindings) {
                break;
            }
        } while ($iteration < $this->auditLoopSettings->maxIterations);

        $auditContext->setMeta('audit.baseline_skipped', \count($this->skippedFingerprints($auditContext)));
        $auditContext->setMeta('audit.iterations', $iteration);
        $auditContext->setMeta('audit.total_findings', \count($auditContext->vulnerabilities()));
        $auditContext->setMeta('audit.validated', \count($auditContext->validatedVulnerabilities()));
        $auditContext->setMeta('audit.risk_score', $auditContext->riskScore());
    }

    /**
     * @param list<Vulnerability> $previousFindings
     * @param list<Vulnerability> $rejectedFindings
     * @param list<ProjectFile>   $files
     *
     * @return list<Vulnerability>
     *
     * @throws BudgetExceededException
     * @throws LLMProviderException
     */
    private function analyzeWithRecovery(SymfonyMapping $symfonyMapping, array $files, array $previousFindings, array $rejectedFindings, AuditContext $auditContext): array
    {
        try {
            $rawFindings = $this->attackerAgent->analyze(
                new AttackerAnalysisRequest(
                    files: $files,
                    symfonyMapping: $symfonyMapping,
                    bypassCache: $auditContext->isCacheBypassed(),
                    previousFindings: $previousFindings,
                    rejectedFindings: $rejectedFindings,
                ),
                $auditContext,
            );
        } catch (BudgetExceededException|LLMProviderException $attackerException) {
            $this->reviewRecoveredFindings($auditContext->drainFoundVulnerabilities(), $files, $auditContext);

            throw $attackerException;
        }

        return $this->mergeRecoveredFindings($rawFindings, $auditContext->drainFoundVulnerabilities());
    }

    /**
     * Shared by both the attacker and reviewer recovery paths. A chunk/finding
     * whose own conversation swallowed a generic (non-abort) `Throwable` after
     * a partial `record_vulnerability`/`record_review` success records that
     * finding via the coverage recorder, but the agent's own return value can
     * still come back missing it — draining and merging by id here recovers
     * it. Draining unconditionally (not only on an abort) also keeps the
     * coverage recorder's buffer from accumulating findings across iterations
     * that a later abort would otherwise re-review as if they were never
     * persisted.
     *
     * @param list<Vulnerability> $rawFindings
     * @param list<Vulnerability> $recoveredFindings
     *
     * @return list<Vulnerability>
     */
    private function mergeRecoveredFindings(array $rawFindings, array $recoveredFindings): array
    {
        $byId = [];
        foreach ($rawFindings as $rawFinding) {
            $byId[$rawFinding->id()] = $rawFinding;
        }

        foreach ($recoveredFindings as $recoveredFinding) {
            $byId[$recoveredFinding->id()] = $recoveredFinding;
        }

        return array_values($byId);
    }

    /**
     * Gives raw attacker candidates found before a mid-run abort a chance to
     * reach the report: filters and reviews them exactly like a completed
     * iteration would. A further abort from this review attempt is swallowed
     * after persisting whatever verdicts it managed to reach, so the
     * caller-visible exception is always the original attacker abort.
     *
     * @param list<Vulnerability> $rawFindings
     * @param list<ProjectFile>   $files
     */
    private function reviewRecoveredFindings(array $rawFindings, array $files, AuditContext $auditContext): void
    {
        $filtered = $this->withoutBaselineAccepted($this->filterByConfidence($rawFindings), $auditContext);

        if ([] === $filtered) {
            return;
        }

        $this->progressReporter->report(ProgressEvent::ReviewStarted->value, [
            'findings' => \count($filtered),
        ]);

        try {
            $reviewed = $this->reviewerAgent->review($filtered, $files, $auditContext, $auditContext->isCacheBypassed());
        } catch (BudgetExceededException|LLMProviderException) {
            $this->persistReviewedFindings($auditContext->drainReviewedFindings(), $auditContext);

            return;
        }

        $this->persistReviewedFindings($reviewed, $auditContext);
    }

    /**
     * Findings the reviewer has already rejected in earlier iterations. Fed back
     * to the attacker so it stops re-reporting them — that would otherwise burn
     * tool-call and reviewer budget on findings the deduplication step discards.
     *
     * @return list<Vulnerability>
     */
    private function rejectedFindings(AuditContext $auditContext): array
    {
        return array_values(array_filter(
            $auditContext->vulnerabilities(),
            static fn (Vulnerability $vulnerability): bool => !$vulnerability->isReviewerValidated(),
        ));
    }

    /**
     * Consumes at most as many findings per fingerprint as
     * `$auditContext->acceptedFingerprints()` contains that value — a plain
     * membership test would let one baseline-accepted occurrence of a shared
     * fingerprint (`Vulnerability::fingerprint()` is line-independent by
     * design) suppress every current finding sharing it, including ones that
     * were never actually reviewed. The budget itself lives on
     * `$auditContext` (via `consumeBaselineCredit()`) rather than being
     * recomputed here, so it is shared — and spent at most once — across
     * every iteration of this method's own attacker/reviewer loop, not just
     * within a single call.
     *
     * @param list<Vulnerability> $findings
     *
     * @return list<Vulnerability>
     */
    private function withoutBaselineAccepted(array $findings, AuditContext $auditContext): array
    {
        $remaining = [];
        foreach ($findings as $finding) {
            if ($auditContext->consumeBaselineCredit($finding->fingerprint())) {
                $this->recordBaselineSkip($finding, $auditContext);

                continue;
            }

            $remaining[] = $finding;
        }

        return $remaining;
    }

    private function recordBaselineSkip(Vulnerability $vulnerability, AuditContext $auditContext): void
    {
        $skippedFingerprints = $this->skippedFingerprints($auditContext);
        if (\in_array($vulnerability->fingerprint(), $skippedFingerprints, true)) {
            return;
        }

        $skippedFingerprints[] = $vulnerability->fingerprint();
        $auditContext->setMeta(self::SKIPPED_FINGERPRINTS_META, $skippedFingerprints);

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
     * @return list<string>
     */
    private function skippedFingerprints(AuditContext $auditContext): array
    {
        $skipped = $auditContext->getMeta(self::SKIPPED_FINGERPRINTS_META, []);

        return \is_array($skipped) ? array_values(array_filter($skipped, is_string(...))) : [];
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
     * @param list<Vulnerability> $reviewed
     */
    private function persistReviewedFindings(array $reviewed, AuditContext $auditContext): int
    {
        $newFindings = 0;

        foreach ($reviewed as $vulnerability) {
            if ($this->isDuplicate($vulnerability, $auditContext)) {
                continue;
            }

            $auditContext->addVulnerability($vulnerability);
            ++$newFindings;
        }

        return $newFindings;
    }

    /**
     * A same-id repeat is a duplicate unless it corrects an earlier verdict —
     * an already-validated entry is sticky against a later spurious rejection
     * (that never displaces it), but a corrected accept must be allowed to
     * replace a stale reject, and a later iteration's validated verdict must
     * be allowed to replace an earlier validated verdict when the severity or
     * type differs (e.g. a reviewer's `adjusted_severity`/`corrected_type`
     * applied on re-discovery) — otherwise a genuine correction silently
     * vanishes from the report and the stale, less-accurate verdict persists.
     */
    private function isDuplicate(Vulnerability $vulnerability, AuditContext $auditContext): bool
    {
        $existingById = $auditContext->vulnerabilities()[$vulnerability->id()] ?? null;
        if ($existingById instanceof Vulnerability) {
            return $this->isSameIdDuplicate($existingById, $vulnerability);
        }

        foreach ($auditContext->validatedVulnerabilities() as $existing) {
            if ($existing->filePath() === $vulnerability->filePath()
                && $existing->type() === $vulnerability->type()
                && $this->linesOverlap(
                    $existing->lineStart(),
                    $existing->lineEnd(),
                    $vulnerability->lineStart(),
                    $vulnerability->lineEnd(),
                )
            ) {
                return true;
            }
        }

        return false;
    }

    private function isSameIdDuplicate(Vulnerability $existingById, Vulnerability $vulnerability): bool
    {
        if ($existingById->isReviewerValidated()) {
            if (!$vulnerability->isReviewerValidated()) {
                return true;
            }

            return $existingById->severity() === $vulnerability->severity()
                && $existingById->type() === $vulnerability->type();
        }

        return !$vulnerability->isReviewerValidated();
    }

    private function linesOverlap(int $start1, int $end1, int $start2, int $end2): bool
    {
        return $start1 <= $end2 && $start2 <= $end1;
    }
}
