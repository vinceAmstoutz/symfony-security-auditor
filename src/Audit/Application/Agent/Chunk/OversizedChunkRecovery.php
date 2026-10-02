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

use Closure;
use Psr\Log\LoggerInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\StatusTrackingCoverageRecorder;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\VulnerabilityFactory;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Budget\Exception\BudgetExceededException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\LLMFixedPromptTooLargeException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\LLMProviderException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFile;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\Vulnerability;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilityHydrationResult;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Pipeline\CoverageRecorderInterface;

/**
 * Recovers a chunk the model could not take in whole. A multi-file chunk is
 * split in two and each half goes back through the analyzer's own per-chunk
 * path (so a half already in the cache costs nothing and a half still too
 * large is split again); a single file the model cannot fit is recorded as
 * errored — unless the file, as the prompt carried it after code slicing, is
 * only a small share of the refused prompt, so the prompt's fixed part is
 * what leaves no room, which no split can help: the run stops with the
 * reason.
 * Once every file of a split chunk has been judged, the merged findings are
 * stored under the whole chunk's own cache key, so the next run serves the
 * chunk from the cache instead of sending it to be refused again.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class OversizedChunkRecovery
{
    /**
     * Below this share of the refused prompt, a file is too small to be what
     * made it too large: the system prompt and the project mapping around it
     * take up the rest, and they surround every other file the same way.
     */
    private const int FIXED_PROMPT_BLAMED_BELOW_FILE_PERCENT = 10;

    public function __construct(
        private LoggerInterface $logger,
        private AttackerChunkCache $attackerChunkCache,
        private VulnerabilityFactory $vulnerabilityFactory,
    ) {}

    /**
     * @param list<ProjectFile>                                                                   $chunk
     * @param Closure(list<ProjectFile>, CoverageRecorderInterface): VulnerabilityHydrationResult $analyzeChunk
     *
     * @throws BudgetExceededException
     * @throws LLMProviderException
     */
    public function recover(array $chunk, ChunkContext $chunkContext, string $reason, CoverageRecorderInterface $coverageRecorder, Closure $analyzeChunk): VulnerabilityHydrationResult
    {
        if (1 === \count($chunk)) {
            return $this->failSingleFile($chunk[0], $chunkContext, $reason, $coverageRecorder);
        }

        $this->logger->warning('Attacker chunk exceeds the model input limit; it is split in two and each half analyzed on its own', [
            'files' => array_map(static fn (ProjectFile $projectFile): string => $projectFile->relativePath(), $chunk),
            'error' => $reason,
        ]);

        $firstHalfSize = intdiv(\count($chunk) + 1, 2);
        $secondHalf = \array_slice($chunk, $firstHalfSize);
        $statusTrackingCoverageRecorder = new StatusTrackingCoverageRecorder($coverageRecorder);

        $vulnerabilityHydrationResult = $this->analyzeFirstHalf(\array_slice($chunk, 0, $firstHalfSize), $secondHalf, $statusTrackingCoverageRecorder, $analyzeChunk)
            ->merge($analyzeChunk($secondHalf, $statusTrackingCoverageRecorder));
        $this->cacheWholeChunk($chunk, $chunkContext, $vulnerabilityHydrationResult, $statusTrackingCoverageRecorder);

        return $vulnerabilityHydrationResult;
    }

    /**
     * A half cut short or errored is left out of the cache by the analyzers,
     * and so is the whole chunk then: a cache entry replays as the model's
     * complete verdict, which the merged findings only are once every file
     * ended analyzed or served from the cache.
     *
     * @param list<ProjectFile> $chunk
     */
    private function cacheWholeChunk(array $chunk, ChunkContext $chunkContext, VulnerabilityHydrationResult $vulnerabilityHydrationResult, StatusTrackingCoverageRecorder $statusTrackingCoverageRecorder): void
    {
        if (!$chunkContext->cacheable) {
            return;
        }

        $paths = array_map(static fn (ProjectFile $projectFile): string => $projectFile->relativePath(), $chunk);
        if ([] !== array_diff($paths, $statusTrackingCoverageRecorder->analyzedFiles())) {
            return;
        }

        $this->attackerChunkCache->store(
            $chunk,
            $chunkContext->contextKey,
            array_map(fn (Vulnerability $vulnerability): array => $this->vulnerabilityFactory->toRaw($vulnerability), $vulnerabilityHydrationResult->vulnerabilities()),
        );
    }

    /**
     * @throws LLMFixedPromptTooLargeException
     */
    private function failSingleFile(ProjectFile $projectFile, ChunkContext $chunkContext, string $reason, CoverageRecorderInterface $coverageRecorder): VulnerabilityHydrationResult
    {
        ChunkCoverageRecorder::record([$projectFile], 'errored', $coverageRecorder);

        $bytes = $chunkContext->promptedFileBytes;
        $promptBytes = \strlen($chunkContext->systemPrompt) + \strlen($chunkContext->userMessage);
        if ($bytes * 100 < self::FIXED_PROMPT_BLAMED_BELOW_FILE_PERCENT * $promptBytes) {
            throw LLMFixedPromptTooLargeException::forFile($projectFile->relativePath(), $bytes, $reason);
        }

        $this->logger->warning('Attacker chunk exceeds the model input limit as a single file; it is recorded as errored and left out of the cache', [
            'files' => [$projectFile->relativePath()],
            'error' => $reason,
        ]);

        return VulnerabilityHydrationResult::empty();
    }

    /**
     * An abort while the first half is analyzed leaves the second half with
     * a status of its own, as the analyzers do for the chunks after a failing
     * one — a file without any status would be missing from the report's
     * list of files that could not be fully analyzed.
     *
     * @param list<ProjectFile>                                                                   $firstHalf
     * @param list<ProjectFile>                                                                   $secondHalf
     * @param Closure(list<ProjectFile>, CoverageRecorderInterface): VulnerabilityHydrationResult $analyzeChunk
     *
     * @throws BudgetExceededException
     * @throws LLMProviderException
     */
    private function analyzeFirstHalf(array $firstHalf, array $secondHalf, CoverageRecorderInterface $coverageRecorder, Closure $analyzeChunk): VulnerabilityHydrationResult
    {
        try {
            return $analyzeChunk($firstHalf, $coverageRecorder);
        } catch (BudgetExceededException $budgetExceededException) {
            ChunkCoverageRecorder::record($secondHalf, 'aborted', $coverageRecorder);

            throw $budgetExceededException;
        } catch (LLMProviderException $llmProviderException) {
            ChunkCoverageRecorder::record($secondHalf, 'errored', $coverageRecorder);

            throw $llmProviderException;
        }
    }
}
