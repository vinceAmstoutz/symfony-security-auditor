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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\Chunk;

use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\StatusTrackingCoverageRecorder;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFile;

/**
 * The context of an `attacker.chunk.completed` progress event: how the chunk
 * ended and, for one that errored, why.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class ChunkCompletionContext
{
    /**
     * @param list<ProjectFile> $chunk
     *
     * @return array<string, mixed>
     */
    public static function of(int $index, int $totalChunks, float $elapsedSeconds, StatusTrackingCoverageRecorder $statusTrackingCoverageRecorder, array $chunk): array
    {
        $context = [
            'chunk' => $index + 1,
            'total_chunks' => $totalChunks,
            'elapsed_seconds' => $elapsedSeconds,
            'status' => $statusTrackingCoverageRecorder->chunkStatus($chunk),
        ];

        $reason = $statusTrackingCoverageRecorder->chunkFailureReason($chunk);

        return null === $reason ? $context : $context + ['reason' => $reason];
    }
}
