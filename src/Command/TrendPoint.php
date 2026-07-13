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
 * One report's place in a trend: its total finding count plus how many
 * findings appeared and disappeared since the report before it. The first
 * report of a trend has no predecessor, so its `newCount` and `fixedCount`
 * are null.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class TrendPoint
{
    public function __construct(
        public string $report,
        public int $totalCount,
        public ?int $newCount,
        public ?int $fixedCount,
    ) {}

    /**
     * @return array{report: string, total: int, new: int|null, fixed: int|null}
     */
    public function toArray(): array
    {
        return [
            'report' => $this->report,
            'total' => $this->totalCount,
            'new' => $this->newCount,
            'fixed' => $this->fixedCount,
        ];
    }
}
