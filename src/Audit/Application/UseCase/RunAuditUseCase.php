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
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\AuditContext;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\AuditReport;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Pipeline\PipelineInterface;

final readonly class RunAuditUseCase
{
    public function __construct(
        private PipelineInterface $pipeline,
        private LoggerInterface $logger,
    ) {}

    public function execute(string $projectPath): AuditReport
    {
        $this->logger->info('Starting audit', ['project' => $projectPath]);

        $auditContext = AuditContext::forProject($projectPath);

        $this->pipeline->process($auditContext);

        $auditReport = AuditReport::fromContext($auditContext);

        $this->logger->info('Audit complete', [
            'audit_id' => $auditReport->auditId(),
            'risk_level' => $auditReport->riskLevel(),
            'vulnerabilities' => $auditReport->totalVulnerabilities(),
            'duration' => $auditReport->durationSeconds(),
        ]);

        return $auditReport;
    }
}
