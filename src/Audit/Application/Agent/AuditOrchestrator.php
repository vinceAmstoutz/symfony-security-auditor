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

use Psr\Log\LoggerInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\AuditContext;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\SymfonyMapping;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\Vulnerability;

/** @internal not part of the BC promise — see docs/versioning.md */
final readonly class AuditOrchestrator implements AuditOrchestratorInterface
{
    public const int DEFAULT_MAX_ITERATIONS = 3;

    public const float DEFAULT_MIN_CONFIDENCE = 0.6;

    public function __construct(
        private AttackerAgentInterface $attackerAgent,
        private ReviewerAgentInterface $reviewerAgent,
        private LoggerInterface $logger,
        private int $maxIterations = self::DEFAULT_MAX_ITERATIONS,
        private float $minConfidence = self::DEFAULT_MIN_CONFIDENCE,
    ) {}

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
            'max_iterations' => $this->maxIterations,
        ]);

        do {
            ++$iteration;
            $this->logger->info(\sprintf('Audit iteration %d/%d', $iteration, $this->maxIterations));

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

            $reviewed = $this->reviewerAgent->review($filtered, $files, $auditContext);
            $newFindings = $this->persistReviewedFindings(array_values($reviewed), $auditContext);

            $this->logger->info('Iteration complete', [
                'iteration' => $iteration,
                'attacker_found' => \count($rawFindings),
                'reviewer_accepted' => \count(array_filter(
                    $reviewed,
                    static fn (Vulnerability $vulnerability): bool => $vulnerability->isReviewerValidated(),
                )),
                'new_unique' => $newFindings,
                'total' => \count($auditContext->vulnerabilities()),
                'previous_validated_passed_back' => \count($previousFindings),
            ]);

            if (0 === $newFindings) {
                break;
            }
        } while ($iteration < $this->maxIterations);

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
     * @param list<Vulnerability> $vulnerabilities
     *
     * @return list<Vulnerability>
     */
    private function filterByConfidence(array $vulnerabilities): array
    {
        return array_values(array_filter(
            $vulnerabilities,
            fn (Vulnerability $vulnerability): bool => $vulnerability->confidence() >= $this->minConfidence,
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
