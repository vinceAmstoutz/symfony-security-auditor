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

/** @internal not part of the BC promise, see docs/versioning.md */
interface AuditExitCodeResolverInterface
{
    /**
     * @param ?int $minimumScore     normalized-score floor, a second gate beside the risk level
     * @param bool $failOnIncomplete whether an incomplete report fails the run on its own, after the gates
     */
    public function resolve(AuditReport $auditReport, RiskLevel $riskLevel, ?int $minimumScore = null, bool $failOnIncomplete = false): int;

    /**
     * Whether the run reached no verdict: its scan found no file, or it
     * analyzed none of its files and found nothing.
     */
    public function hasNoVerdict(AuditReport $auditReport): bool;
}
