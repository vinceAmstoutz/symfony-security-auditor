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

use Psr\Log\LoggerInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFile;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Pipeline\CoverageRecorderInterface;

/**
 * Settles a chunk whose model sent a finding the recording tool refused and
 * never sent again in full: that finding is lost without a trace in the
 * answer, so the chunk is not the model's complete verdict. The findings that
 * were recorded are kept, the chunk is recorded as errored so the report says
 * it could not be fully analyzed, and nothing is cached, so the next run asks
 * the model again instead of replaying the lossy answer.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class RefusedRecordingRecorder
{
    public function __construct(
        private LoggerInterface $logger,
    ) {}

    /**
     * @param list<ProjectFile> $chunk
     */
    public function record(array $chunk, int $findingsKept, int $refusedCalls, CoverageRecorderInterface $coverageRecorder): void
    {
        $this->logger->warning('Attacker finding was refused by the recording tool and never recorded again; the chunk is recorded as errored and left out of the cache', [
            'files' => array_map(static fn (ProjectFile $projectFile): string => $projectFile->relativePath(), $chunk),
            'findings_kept' => $findingsKept,
            'refused_calls' => $refusedCalls,
        ]);
        ChunkCoverageRecorder::recordErrored($chunk, ChunkFailureReason::RECORDING_REFUSED, $coverageRecorder);
    }
}
