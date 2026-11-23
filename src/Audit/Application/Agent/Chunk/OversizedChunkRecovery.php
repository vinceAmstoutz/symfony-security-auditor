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
 * Splits a chunk the model could not take in whole into halves that go back
 * through the analyzer's per-chunk path. Records a single file that does not
 * fit as errored, but stops the run when that file, as sliced, is a small
 * share of the refused prompt, since the prompt's fixed part then leaves no
 * room. Caches the merged findings under the whole chunk's key once every
 * file is judged.
 *
 * @internal not part of the BC promise, see docs/versioning.md
 */
final readonly class OversizedChunkRecovery
{
    /**
     * Below this share of the refused prompt, the prompt's fixed part, not the
     * file, is what does not fit.
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
     * Caches the merged findings only when every file ended analyzed or
     * served from the cache.
     *
     * @param list<ProjectFile> $chunk
     */
    private function cacheWholeChunk(array $chunk, ChunkContext $chunkContext, VulnerabilityHydrationResult $vulnerabilityHydrationResult, StatusTrackingCoverageRecorder $statusTrackingCoverageRecorder): void
    {
        if (!$chunkContext->cacheable) {
            return;
        }

        $paths = array_map(static fn (ProjectFile $projectFile): string => $projectFile->relativePath(), $chunk);
        if ([] !== array_diff($paths, $statusTrackingCoverageRecorder->conclusiveFiles())) {
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
        ChunkCoverageRecorder::recordErrored([$projectFile], ChunkFailureReason::FILE_TOO_LARGE, $coverageRecorder);

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
     * Gives the second half a status of its own when an abort stops the first,
     * so its files are listed as not fully analyzed.
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
