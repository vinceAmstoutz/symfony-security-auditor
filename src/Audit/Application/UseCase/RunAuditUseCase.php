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
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Budget\CostCalculator;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Budget\Exception\BudgetExceededException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Exception\AuditAbortedByBudgetException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Telemetry\TokenUsageRecorder;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\AuditContext;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\AuditCost;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\AuditReport;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Pipeline\PipelineInterface;

final readonly class RunAuditUseCase
{
    public function __construct(
        private PipelineInterface $pipeline,
        private LoggerInterface $logger,
        private ?TokenUsageRecorder $tokenUsageRecorder = null,
        private ?CostCalculator $costCalculator = null,
        private string $primaryModel = '',
    ) {}

    /**
     * @param list<string> $scanPaths   optional project-relative subdirectories
     *                                  to restrict the scan to; empty list (the
     *                                  default) audits the whole project
     * @param bool         $bypassCache when true, agents skip the attacker
     *                                  cache entirely (no reads, no writes)
     */
    public function execute(string $projectPath, array $scanPaths = [], bool $bypassCache = false): AuditReport
    {
        $this->logger->info('Starting audit', [
            'project' => $projectPath,
            'scan_paths' => $scanPaths,
            'cache_bypassed' => $bypassCache,
        ]);

        $auditContext = AuditContext::forProject($projectPath, $scanPaths, $bypassCache);

        try {
            $this->pipeline->process($auditContext);
        } catch (BudgetExceededException $budgetExceededException) {
            $partialReport = AuditReport::fromContext($auditContext, $this->buildCost());
            $this->logger->warning('Audit aborted by budget cap', [
                'audit_id' => $partialReport->auditId(),
                'error' => $budgetExceededException->getMessage(),
            ]);

            throw AuditAbortedByBudgetException::from($budgetExceededException, $partialReport);
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

    private function buildCost(): ?AuditCost
    {
        if (!$this->tokenUsageRecorder instanceof TokenUsageRecorder) {
            return null;
        }

        $snapshot = $this->tokenUsageRecorder->snapshot();
        $estimatedCost = $this->costCalculator instanceof CostCalculator
            ? $this->costCalculator->costForCall($snapshot->inputTokens(), $snapshot->outputTokens(), $this->primaryModel)
            : 0.0;

        return AuditCost::of($snapshot->inputTokens(), $snapshot->outputTokens(), $estimatedCost, $this->primaryModel);
    }
}
