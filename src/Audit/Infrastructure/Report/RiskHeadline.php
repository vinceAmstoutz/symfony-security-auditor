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
 * How a human-facing report states its risk verdict: as is for a complete run,
 * qualified as covering only the files analyzed for an incomplete one, and not
 * at all for a run with no verdict, which analyzed no file and found nothing —
 * a SAFE there would vouch for code nobody read. Machine-readable formats keep
 * their fields and carry `complete`.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class RiskHeadline
{
    public const string UNKNOWN_RISK_LEVEL = 'UNKNOWN';

    public static function riskLevel(AuditReport $auditReport): string
    {
        return $auditReport->hasNoVerdict() ? self::UNKNOWN_RISK_LEVEL : $auditReport->riskLevel();
    }

    /**
     * What follows the risk level in parentheses, the score introduced by the
     * format's own `$scoreLabel`.
     */
    public static function scoreDetail(AuditReport $auditReport, string $scoreLabel): string
    {
        if ($auditReport->hasNoVerdict()) {
            return 'no file was analyzed';
        }

        $score = \sprintf('%s %d', $scoreLabel, $auditReport->riskScore());

        return $auditReport->isComplete() ? $score : \sprintf('%s, on the files analyzed', $score);
    }
}
