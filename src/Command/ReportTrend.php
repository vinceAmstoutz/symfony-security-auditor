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

/**
 * The outcome of tracking finding counts across a chronological series of
 * reports.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class ReportTrend
{
    /**
     * @param list<TrendPoint> $points one per report, ordered oldest to newest
     */
    public function __construct(
        public array $points,
    ) {}

    /**
     * @return array{points: list<array{report: string, total: int, new: int|null, fixed: int|null}>}
     */
    public function toArray(): array
    {
        return [
            'points' => array_map(static fn (TrendPoint $trendPoint): array => $trendPoint->toArray(), $this->points),
        ];
    }
}
