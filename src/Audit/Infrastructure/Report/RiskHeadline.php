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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Report;

use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\AuditReport;

/**
 * States the risk verdict of a human-facing report: as is for a complete run,
 * limited to the files analyzed for an incomplete one and `UNKNOWN` for a run
 * with no verdict, where a SAFE would vouch for code nobody read.
 *
 * @internal not part of the BC promise, see docs/versioning.md
 */
final readonly class RiskHeadline
{
    public const string UNKNOWN_RISK_LEVEL = 'UNKNOWN';

    public static function riskLevel(AuditReport $auditReport): string
    {
        return $auditReport->isWithoutVerdict() ? self::UNKNOWN_RISK_LEVEL : $auditReport->riskLevel();
    }

    /**
     * Returns what follows the risk level in parentheses.
     */
    public static function scoreDetail(AuditReport $auditReport, string $scoreLabel): string
    {
        if ($auditReport->isWithoutVerdict()) {
            return 'no file was analyzed';
        }

        $score = \sprintf('%s %d', $scoreLabel, $auditReport->riskScore());

        return $auditReport->isComplete() ? $score : \sprintf('%s, on the files analyzed', $score);
    }
}
