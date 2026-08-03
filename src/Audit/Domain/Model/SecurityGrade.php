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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model;

/**
 * The letter grade of an {@see AuditReport}, derived from its normalized
 * 0-100 score. The boundaries mirror the {@see RiskLevel} thresholds in
 * {@see AuditReport::riskLevelEnum()}, so a report never reads as a healthy
 * grade while its risk level says otherwise: `A` is `safe`, `B` is `low`,
 * `C` is `medium`, `D` is `high` and `F` is `critical`.
 */
enum SecurityGrade: string
{
    case A = 'A';
    case B = 'B';
    case C = 'C';
    case D = 'D';
    case F = 'F';

    public static function fromNormalizedScore(int $normalizedScore): self
    {
        return match (true) {
            $normalizedScore >= 96 => self::A,
            $normalizedScore >= 86 => self::B,
            $normalizedScore >= 71 => self::C,
            $normalizedScore >= 51 => self::D,
            default => self::F,
        };
    }
}
