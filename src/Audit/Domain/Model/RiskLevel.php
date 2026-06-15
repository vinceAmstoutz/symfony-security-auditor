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

enum RiskLevel: string
{
    case Safe = 'safe';
    case Low = 'low';
    case Medium = 'medium';
    case High = 'high';
    case Critical = 'critical';

    public function isAtLeast(self $threshold): bool
    {
        return $this->rank() >= $threshold->rank();
    }

    /**
     * Ascending ordinal (`safe` = 0 … `critical` = 4) — the basis of
     * `isAtLeast()` ordering, exposed so the absolute values are observable.
     */
    public function rank(): int
    {
        return match ($this) {
            self::Safe => 0,
            self::Low => 1,
            self::Medium => 2,
            self::High => 3,
            self::Critical => 4,
        };
    }
}
