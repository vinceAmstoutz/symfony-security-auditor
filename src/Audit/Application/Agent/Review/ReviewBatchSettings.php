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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\Review;

use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Pipeline\CoverageRecorderInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\Tool\ToolRegistry;

/**
 * @internal not part of the BC promise, see docs/versioning.md
 */
final readonly class ReviewBatchSettings
{
    /**
     * @param int<1, max> $batchSize
     * @param bool        $groupByFile   whether a batch holds the findings of one file only, so the file is sent once
     * @param int<1, max> $maxConcurrent how many batches are sent at once to a client that takes several, without tools
     */
    public function __construct(
        public int $batchSize,
        public bool $structured,
        public bool $bypassCache,
        public CoverageRecorderInterface $coverageRecorder,
        public ?ToolRegistry $toolRegistry,
        public bool $groupByFile = false,
        public int $maxConcurrent = 1,
    ) {}
}
