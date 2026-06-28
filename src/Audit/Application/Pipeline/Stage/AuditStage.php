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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Pipeline\Stage;

use Override;
use Psr\Log\LoggerInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\AuditOrchestratorInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\AuditContext;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\BuiltInStageName;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\SymfonyMapping;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Pipeline\StageInterface;

/** @internal not part of the BC promise — see docs/versioning.md */
final readonly class AuditStage implements StageInterface
{
    public function __construct(
        private AuditOrchestratorInterface $auditOrchestrator,
        private LoggerInterface $logger,
    ) {}

    #[Override]
    public function name(): string
    {
        return BuiltInStageName::Audit->value;
    }

    #[Override]
    public function process(AuditContext $auditContext): void
    {
        if ([] === $auditContext->projectFiles()) {
            $this->logger->warning('No files to audit, skipping');

            return;
        }

        if (!$auditContext->mapping() instanceof SymfonyMapping) {
            $this->logger->warning('Mapping not available, skipping audit stage');

            return;
        }

        $this->auditOrchestrator->orchestrate($auditContext);

        $this->logger->info('Audit stage complete', [
            'vulnerabilities' => \count($auditContext->vulnerabilities()),
            'validated' => \count($auditContext->validatedVulnerabilities()),
            'critical' => \count($auditContext->criticalVulnerabilities()),
            'risk_score' => $auditContext->riskScore(),
        ]);
    }
}
