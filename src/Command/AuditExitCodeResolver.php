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

namespace VinceAmstoutz\SymfonySecurityAuditor\Command;

use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\AuditReport;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\RiskLevel;

/** @internal not part of the BC promise — see docs/versioning.md */
final readonly class AuditExitCodeResolver implements AuditExitCodeResolverInterface
{
    public function resolve(AuditReport $auditReport, RiskLevel $riskLevel): int
    {
        return $auditReport->riskLevelEnum()->isAtLeast($riskLevel)
            ? ExitCode::Failure->value
            : ExitCode::Success->value;
    }
}
