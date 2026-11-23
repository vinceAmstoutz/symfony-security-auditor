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
 * One report's place in a trend: its total and its changes since the report
 * before it. The first report's `newCount`, `fixedCount` and
 * `unverifiedCount` are null.
 *
 * @internal not part of the BC promise, see docs/versioning.md
 */
final readonly class TrendPoint
{
    public function __construct(
        public string $report,
        public int $totalCount,
        public ?int $newCount,
        public ?int $fixedCount,
        public ?int $unverifiedCount = null,
    ) {}

    /**
     * @return array{report: string, total: int, new: int|null, fixed: int|null, unverified: int|null}
     */
    public function toArray(): array
    {
        return [
            'report' => $this->report,
            'total' => $this->totalCount,
            'new' => $this->newCount,
            'fixed' => $this->fixedCount,
            'unverified' => $this->unverifiedCount,
        ];
    }
}
