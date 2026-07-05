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
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\AuditContext;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProgressEvent;
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
            $rawFindings = $this->attackerAgent->analyze(
                new AttackerAnalysisRequest(
                    files: $files,
                    symfonyMapping: $mapping,
                    bypassCache: $auditContext->isCacheBypassed(),
                    previousFindings: $previousFindings,
                    rejectedFindings: $rejectedFindings,
                ),
                $auditContext,
            );
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
            $reviewed = $this->reviewerAgent->review($filtered, $files, $auditContext, $auditContext->isCacheBypassed());
            $newFindings = $this->persistReviewedFindings($reviewed, $auditContext);

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
     * @param list<Vulnerability> $findings
     *
     * @return list<Vulnerability>
     */
    private function withoutBaselineAccepted(array $findings, AuditContext $auditContext): array
    {
        $acceptedFingerprints = $auditContext->acceptedFingerprints();

        $remaining = [];
        foreach ($findings as $finding) {
            if (!\in_array($finding->fingerprint(), $acceptedFingerprints, true)) {
                $remaining[] = $finding;

                continue;
            }

            $this->recordBaselineSkip($finding, $auditContext);
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
        return array_values(array_filter(
            $vulnerabilities,
            fn (Vulnerability $vulnerability): bool => $vulnerability->confidence() >= $this->auditLoopSettings->minConfidence,
        ));
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

    private function isDuplicate(Vulnerability $vulnerability, AuditContext $auditContext): bool
    {
        foreach ($auditContext->vulnerabilities() as $existing) {
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

    private function linesOverlap(int $start1, int $end1, int $start2, int $end2): bool
    {
        return $start1 <= $end2 && $start2 <= $end1;
    }
}
