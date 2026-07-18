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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\UseCase;

use Psr\Log\LoggerInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Budget\BudgetTracker;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Budget\CostCalculator;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Budget\Exception\BudgetExceededException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Exception\AuditAbortedByBudgetException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Exception\AuditAbortedByProviderException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Telemetry\TokenUsageRecorder;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidAuditContextException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidAuditCostException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidTokenUsageException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\LLMProviderException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\AuditContext;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\AuditCost;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\AuditReport;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\TokenUsageSnapshot;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Pipeline\PipelineInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\ReviewerFeedbackSnapshotInterface;

final readonly class RunAuditUseCase
{
    public function __construct(
        private PipelineInterface $pipeline,
        private LoggerInterface $logger,
        private ?TokenUsageRecorder $tokenUsageRecorder = null,
        private ?CostCalculator $costCalculator = null,
        private string $primaryModel = '',
        private ?BudgetTracker $budgetTracker = null,
        private ?ReviewerFeedbackSnapshotInterface $reviewerFeedbackSnapshot = null,
    ) {}

    /**
     * @param list<string> $scanPaths            optional project-relative subdirectories
     *                                           to restrict the scan to; empty list (the
     *                                           default) audits the whole project
     * @param bool         $bypassCache          when true, agents skip the attacker and
     *                                           reviewer caches entirely (no reads, no
     *                                           writes)
     * @param ?string      $diffSinceRef         when set, only files changed against
     *                                           this git ref are audited; null audits
     *                                           every file in scope
     * @param list<string> $acceptedFingerprints
     *                                           baseline fingerprints of accepted
     *                                           findings; matching attacker findings
     *                                           skip the reviewer and never enter the
     *                                           report
     *
     * @throws AuditAbortedByBudgetException
     * @throws AuditAbortedByProviderException
     * @throws InvalidAuditContextException
     * @throws InvalidAuditCostException
     * @throws InvalidTokenUsageException
     */
    public function execute(string $projectPath, array $scanPaths = [], bool $bypassCache = false, ?string $diffSinceRef = null, array $acceptedFingerprints = []): AuditReport
    {
        $this->tokenUsageRecorder?->reset();
        $this->budgetTracker?->reset();
        $this->reviewerFeedbackSnapshot?->resetForNewRun();

        $this->logger->info('Starting audit', [
            'project' => $projectPath,
            'scan_paths' => $scanPaths,
            'cache_bypassed' => $bypassCache,
            'diff_since_ref' => $diffSinceRef,
            'accepted_fingerprints' => \count($acceptedFingerprints),
        ]);

        $auditContext = AuditContext::forProject($projectPath, $scanPaths, $bypassCache, $diffSinceRef, $acceptedFingerprints);

        try {
            $this->pipeline->process($auditContext);
        } catch (BudgetExceededException $budgetExceededException) {
            $partialReport = AuditReport::fromContext($auditContext, $this->buildCost());
            $this->logger->warning('Audit aborted by budget cap', [
                'audit_id' => $partialReport->auditId(),
                'error' => $budgetExceededException->getMessage(),
            ]);

            throw AuditAbortedByBudgetException::from($budgetExceededException, $partialReport);
        } catch (LLMProviderException $llmProviderException) {
            $partialReport = AuditReport::fromContext($auditContext, $this->buildCost());
            $this->logger->warning('Audit aborted by LLM provider failure', [
                'audit_id' => $partialReport->auditId(),
                'error' => $llmProviderException->getMessage(),
            ]);

            throw AuditAbortedByProviderException::from($llmProviderException, $partialReport);
        }

        $auditReport = AuditReport::fromContext($auditContext, $this->buildCost());

        $this->logger->info('Audit complete', [
            'audit_id' => $auditReport->auditId(),
            'risk_level' => $auditReport->riskLevel(),
            'vulnerabilities' => $auditReport->totalVulnerabilities(),
            'duration' => $auditReport->durationSeconds(),
        ]);

        return $auditReport;
    }

    /**
     * @throws InvalidAuditCostException
     * @throws InvalidTokenUsageException
     */
    private function buildCost(): ?AuditCost
    {
        if (!$this->tokenUsageRecorder instanceof TokenUsageRecorder) {
            return null;
        }

        $snapshot = $this->tokenUsageRecorder->snapshot();

        return AuditCost::of($snapshot->inputTokens(), $snapshot->outputTokens(), $this->resolveEstimatedCost($snapshot), $this->primaryModel);
    }

    private function resolveEstimatedCost(TokenUsageSnapshot $tokenUsageSnapshot): float
    {
        if ($this->budgetTracker instanceof BudgetTracker) {
            return $this->budgetTracker->costUsdUsed();
        }

        return $this->costCalculator instanceof CostCalculator
            ? $this->costCalculator->costForCall($tokenUsageSnapshot->inputTokens(), $tokenUsageSnapshot->outputTokens(), $this->primaryModel, $tokenUsageSnapshot->cacheReadTokens(), $tokenUsageSnapshot->cacheCreationTokens())
            : 0.0;
    }
}
