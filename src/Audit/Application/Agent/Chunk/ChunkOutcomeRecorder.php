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
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilityHydrationResult;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Pipeline\CoverageRecorderInterface;

/**
 * Settles a chunk the model answered in full: `analyzed` and cached when every
 * entry of its answer became a finding; `errored` and uncached, keeping the
 * findings, when an entry could not be read. A chunk answered at the
 * tool-call limit with no finding is `analyzed` but uncached.
 *
 * @internal not part of the BC promise, see docs/versioning.md
 */
final readonly class ChunkOutcomeRecorder
{
    public function __construct(
        private AttackerChunkCache $attackerChunkCache,
        private LoggerInterface $logger,
    ) {}

    /**
     * @param list<ProjectFile>          $chunk
     * @param list<array<string, mixed>> $rawVulnerabilities
     */
    public function record(array $chunk, ChunkContext $chunkContext, array $rawVulnerabilities, VulnerabilityHydrationResult $vulnerabilityHydrationResult, CoverageRecorderInterface $coverageRecorder): void
    {
        if ($vulnerabilityHydrationResult->hasDrops()) {
            $this->logger->warning('Attacker answer held entries that could not be read as findings; the chunk is recorded as errored and left out of the cache', [
                'files' => array_map(static fn (ProjectFile $projectFile): string => $projectFile->relativePath(), $chunk),
                'dropped' => $vulnerabilityHydrationResult->dropsByReason(),
            ]);
            ChunkCoverageRecorder::record($chunk, 'errored', $coverageRecorder);

            return;
        }

        if ($chunkContext->reachedToolCap && [] === $rawVulnerabilities) {
            $this->logger->info('Attacker reached its last tool round without a finding; the chunk is recorded as analyzed and left out of the cache, so the next run looks again', [
                'files' => array_map(static fn (ProjectFile $projectFile): string => $projectFile->relativePath(), $chunk),
            ]);
            ChunkCoverageRecorder::recordInconclusive($chunk, $coverageRecorder);

            return;
        }

        if ($chunkContext->cacheable) {
            $this->attackerChunkCache->store($chunk, $chunkContext->contextKey, $rawVulnerabilities);
        }

        ChunkCoverageRecorder::record($chunk, 'analyzed', $coverageRecorder);
    }
}
