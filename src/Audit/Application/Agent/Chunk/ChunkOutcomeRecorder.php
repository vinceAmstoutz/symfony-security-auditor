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
 * entry of its answer became a finding. An entry that could not be read (an
 * unknown type, a blank file path, a line number out of range) is a finding
 * lost, so the chunk is recorded `errored` and left out of the cache instead —
 * the findings that did hydrate are kept, the report says the chunk could not
 * be fully analyzed, and the next run asks the model again rather than
 * replaying the lossy answer as the model's complete verdict.
 *
 * @internal not part of the BC promise — see docs/versioning.md
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

        if ($chunkContext->cacheable) {
            $this->attackerChunkCache->store($chunk, $chunkContext->contextKey, $rawVulnerabilities);
        }

        ChunkCoverageRecorder::record($chunk, 'analyzed', $coverageRecorder);
    }
}
