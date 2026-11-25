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

use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\Vulnerability;

/**
 * @internal not part of the BC promise, see docs/versioning.md
 */
final readonly class ReviewBatches
{
    /**
     * Returns the batches of at most `batchSize` findings, each of one file
     * when the settings group by file, with the input index of each finding
     * in batch order.
     *
     * @param list<Vulnerability> $misses
     * @param list<int>           $missIndexes
     *
     * @return array{list<list<Vulnerability>>, list<int>}
     */
    public static function of(array $misses, array $missIndexes, ReviewBatchSettings $reviewBatchSettings): array
    {
        if (!$reviewBatchSettings->groupByFile) {
            return [array_chunk($misses, $reviewBatchSettings->batchSize), $missIndexes];
        }

        $positionsByFile = [];
        foreach ($misses as $position => $miss) {
            $positionsByFile[$miss->filePath()][] = $position;
        }

        $batches = [];
        $batchedIndexes = [];
        foreach ($positionsByFile as $positions) {
            foreach (array_chunk($positions, $reviewBatchSettings->batchSize) as $batchPositions) {
                $batches[] = array_map(static fn (int $position): Vulnerability => $misses[$position], $batchPositions);
                array_push($batchedIndexes, ...array_map(static fn (int $position): int => $missIndexes[$position], $batchPositions));
            }
        }

        return [$batches, $batchedIndexes];
    }
}
