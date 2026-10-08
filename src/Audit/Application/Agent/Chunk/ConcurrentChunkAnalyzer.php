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
use Throwable;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\AttackerAnalysisRequest;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\RecordVulnerabilityToolFactoryInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\RiskMarkerIndex;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\StatusTrackingCoverageRecorder;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\VulnerabilityFactory;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Budget\Exception\BudgetExceededException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidToolRegistryException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\LLMProviderException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProgressEvent;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFile;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\Vulnerability;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilityHydrationResult;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Pipeline\CoverageRecorderInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\LLMResponse;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\ProgressReporterInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\Tool\ToolRegistry;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\ToolBatchCapableLLMClientInterface;

/**
 * Analyzes cache-miss chunks concurrently as a structured-collection wavefront:
 * one `record_vulnerability` registry + collector per chunk, all resolved
 * through the tool-batch-capable client. Cache hits short-circuit first; chunk
 * order, coverage, caching, and drop accounting match the sequential analyzer.
 *
 * Pending chunks are dispatched one `maxConcurrent`-sized window at a time —
 * never as a single oversized batch — so that a failure in a later window
 * cannot discard the already-completed findings, cache stores, and coverage
 * of an earlier window.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class ConcurrentChunkAnalyzer
{
    private OversizedChunkRecovery $oversizedChunkRecovery;

    private RefusedRecordingRecorder $refusedRecordingRecorder;

    private ChunkOutcomeRecorder $chunkOutcomeRecorder;

    public function __construct(
        private ToolBatchCapableLLMClientInterface $toolBatchCapableLLMClient,
        private ChunkContextFactory $chunkContextFactory,
        private AttackerChunkCache $attackerChunkCache,
        private VulnerabilityFactory $vulnerabilityFactory,
        private LoggerInterface $logger,
        private ProgressReporterInterface $progressReporter,
        private int $maxToolIterations,
        private RecordVulnerabilityToolFactoryInterface $recordVulnerabilityToolFactory,
        private int $maxConcurrent,
    ) {
        $this->oversizedChunkRecovery = new OversizedChunkRecovery($logger, $attackerChunkCache, $vulnerabilityFactory);
        $this->refusedRecordingRecorder = new RefusedRecordingRecorder($logger);
        $this->chunkOutcomeRecorder = new ChunkOutcomeRecorder($attackerChunkCache, $logger);
    }

    /**
     * @param list<list<ProjectFile>> $chunks
     *
     * @return array{0: list<Vulnerability>, 1: array<string, int>}
     *
     * @throws BudgetExceededException
     * @throws LLMProviderException
     * @throws InvalidToolRegistryException
     */
    public function analyze(array $chunks, AttackerAnalysisRequest $attackerAnalysisRequest, CoverageRecorderInterface $coverageRecorder, RiskMarkerIndex $riskMarkerIndex, ?ToolRegistry $toolRegistry = null): array
    {
        $totalChunks = \count($chunks);
        $statusTrackingCoverageRecorder = new StatusTrackingCoverageRecorder($coverageRecorder);

        /** @var array<int, VulnerabilityHydrationResult> $cachedResults */
        $cachedResults = [];
        /** @var array<int, list<ProjectFile>> $pending */
        $pending = [];
        foreach ($chunks as $index => $chunk) {
            $this->reportChunkStarted($index, $totalChunks);

            $cached = $this->servedCachedResult($chunk, $this->chunkContextFactory->cacheCoordinates($chunk, $attackerAnalysisRequest, $riskMarkerIndex, $this->attackerChunkCache->isContextAware()), $statusTrackingCoverageRecorder);
            if ($cached instanceof VulnerabilityHydrationResult) {
                $cachedResults[$index] = $cached;
                $this->recordFoundVulnerabilities($cached, $statusTrackingCoverageRecorder);

                continue;
            }

            $pending[$index] = $chunk;
        }

        $dispatchedResults = $this->dispatchInWindows($pending, new ChunkAnalysisScope($attackerAnalysisRequest, $riskMarkerIndex, $toolRegistry), $statusTrackingCoverageRecorder);

        return $this->aggregate($chunks, $cachedResults, $dispatchedResults, $statusTrackingCoverageRecorder);
    }

    private function reportChunkStarted(int $index, int $totalChunks): void
    {
        $this->progressReporter->report(ProgressEvent::AttackerChunkStarted->value, [
            'chunk' => $index + 1,
            'total_chunks' => $totalChunks,
        ]);
    }

    /**
     * @param list<ProjectFile> $chunk
     */
    private function servedCachedResult(array $chunk, ChunkCacheCoordinates $chunkCacheCoordinates, CoverageRecorderInterface $coverageRecorder): ?VulnerabilityHydrationResult
    {
        if (!$chunkCacheCoordinates->cacheable) {
            return null;
        }

        $cached = $this->attackerChunkCache->get($chunk, $chunkCacheCoordinates->contextKey);
        if (null === $cached) {
            return null;
        }

        return $this->attackerChunkCache->served($chunk, $cached, $coverageRecorder);
    }

    /**
     * @param list<ProjectFile> $chunk
     *
     * @throws InvalidToolRegistryException
     */
    private function buildPendingChunk(array $chunk, ChunkAnalysisScope $chunkAnalysisScope): PendingChunk
    {
        return new PendingChunk(
            $chunk,
            $this->chunkContextFactory->create($chunk, $chunkAnalysisScope->attackerAnalysisRequest, $chunkAnalysisScope->riskMarkerIndex, $this->attackerChunkCache->isContextAware()),
            StructuredVulnerabilityCollectionSession::begin($this->recordVulnerabilityToolFactory, $this->logger, $chunkAnalysisScope->toolRegistry?->tools() ?? []),
        );
    }

    /**
     * @param list<list<ProjectFile>>                  $chunks
     * @param array<int, VulnerabilityHydrationResult> $cachedResults
     * @param array<int, VulnerabilityHydrationResult> $dispatchedResults
     *
     * @return array{0: list<Vulnerability>, 1: array<string, int>}
     */
    private function aggregate(array $chunks, array $cachedResults, array $dispatchedResults, StatusTrackingCoverageRecorder $statusTrackingCoverageRecorder): array
    {
        $totalChunks = \count($chunks);
        $allVulnerabilities = [];
        $totalDropsByReason = [];
        $chunkResults = $cachedResults + $dispatchedResults;
        foreach (array_keys($chunks) as $index) {
            $chunkResult = $chunkResults[$index];
            ChunkFindingProgress::report($this->progressReporter, $chunkResult->vulnerabilities());
            $this->progressReporter->report(ProgressEvent::AttackerChunkCompleted->value, ChunkCompletionContext::of($index, $totalChunks, 0.0, $statusTrackingCoverageRecorder, $chunks[$index]));
            array_push($allVulnerabilities, ...$chunkResult->vulnerabilities());
            $totalDropsByReason = $this->mergeDrops($totalDropsByReason, $chunkResult->dropsByReason());
        }

        return [$allVulnerabilities, $totalDropsByReason];
    }

    /**
     * @param array<string, int> $totalDropsByReason
     * @param array<string, int> $dropsByReason
     *
     * @return array<string, int>
     */
    private function mergeDrops(array $totalDropsByReason, array $dropsByReason): array
    {
        foreach ($dropsByReason as $reason => $count) {
            $totalDropsByReason[$reason] = ($totalDropsByReason[$reason] ?? 0) + $count;
        }

        return $totalDropsByReason;
    }

    /**
     * Dispatches pending chunks one `maxConcurrent`-sized window at a time.
     * Each window is finalized (cached + marked analyzed) as soon as it
     * completes, before the next window is attempted, so a failure partway
     * through never discards an earlier window's completed work.
     *
     * A window's prompts and collection sessions are built when it is
     * dispatched, so a project of many chunks never holds more than one
     * window of them at a time.
     *
     * @param array<int, list<ProjectFile>> $pending
     *
     * @return array<int, VulnerabilityHydrationResult>
     *
     * @throws BudgetExceededException
     * @throws LLMProviderException
     * @throws InvalidToolRegistryException
     */
    private function dispatchInWindows(array $pending, ChunkAnalysisScope $chunkAnalysisScope, CoverageRecorderInterface $coverageRecorder): array
    {
        $windows = array_chunk($pending, max(1, $this->maxConcurrent), true);
        $results = [];

        foreach ($windows as $windowNumber => $chunks) {
            $window = array_map(fn (array $chunk): PendingChunk => $this->buildPendingChunk($chunk, $chunkAnalysisScope), $chunks);

            try {
                $results += $this->dispatchWindow($window, $chunkAnalysisScope, $coverageRecorder);
            } catch (BudgetExceededException $budgetExceededException) {
                $this->recordRemainingWindows($windows, $windowNumber + 1, 'aborted', $coverageRecorder);

                throw $budgetExceededException;
            } catch (LLMProviderException $llmProviderException) {
                $this->recordRemainingWindows($windows, $windowNumber + 1, 'errored', $coverageRecorder);

                throw $llmProviderException;
            } catch (Throwable $throwable) {
                $this->logger->warning('Concurrent attacker batch failed; its chunks are recorded as errored and the audit continues.', [
                    'error' => $throwable->getMessage(),
                ]);

                $results += $this->failWindow($window, 'errored', $coverageRecorder, ChunkFailureReason::fromThrowable($throwable));
            }
        }

        return $results;
    }

    /**
     * Dispatches one window and finalizes each of its chunks. The window
     * accounts for its own chunks when a budget or provider abort ends it —
     * only the chunks not finalized yet are recorded as failed, so a chunk
     * finalized before its sibling's abort keeps its `analyzed` status — and
     * leaves the windows after it to the caller. An abort raised while a chunk
     * is being finalized comes from splitting it, which has recorded each of
     * its halves already, so that chunk is left as its halves recorded it.
     *
     * @param array<int, PendingChunk> $window
     *
     * @return array<int, VulnerabilityHydrationResult>
     *
     * @throws BudgetExceededException
     * @throws LLMProviderException
     */
    private function dispatchWindow(array $window, ChunkAnalysisScope $chunkAnalysisScope, CoverageRecorderInterface $coverageRecorder): array
    {
        $results = [];
        $recordedByItsHalves = [];

        try {
            $responses = $this->toolBatchCapableLLMClient->completeBatchWithTools($this->requestsOf($window), $this->maxConcurrent, $this->maxToolIterations);

            $position = 0;
            foreach ($window as $index => $pendingChunk) {
                $recordedByItsHalves = [$index => $pendingChunk];
                $results[$index] = $this->finalizeOrRecordErrored($pendingChunk, $responses[$position], $chunkAnalysisScope, $coverageRecorder);
                ++$position;
            }
        } catch (BudgetExceededException $budgetExceededException) {
            $this->failWindow(array_diff_key($window, $results, $recordedByItsHalves), 'aborted', $coverageRecorder);

            throw $budgetExceededException;
        } catch (LLMProviderException $llmProviderException) {
            $this->failWindow(array_diff_key($window, $results, $recordedByItsHalves), 'errored', $coverageRecorder);

            throw $llmProviderException;
        }

        return $results;
    }

    /**
     * @param array<int, PendingChunk> $window
     *
     * @return list<array{system: string, user: string, tools: ToolRegistry}>
     */
    private function requestsOf(array $window): array
    {
        return array_values(array_map(
            static fn (PendingChunk $pendingChunk): array => ['system' => $pendingChunk->chunkContext->systemPrompt, 'user' => $pendingChunk->chunkContext->userMessage, 'tools' => $pendingChunk->session->toolRegistry],
            $window,
        ));
    }

    /**
     * A chunk the model could not take in whole is split rather than
     * finalized. Any other failure to finalize one entry (e.g. a cache-store
     * I/O error) is isolated to that entry alone, mirroring
     * `SequentialChunkAnalyzer`'s per-chunk isolation — a sibling entry in the
     * same window that already finalized successfully must keep its result.
     *
     * @throws BudgetExceededException
     * @throws LLMProviderException
     */
    private function finalizeOrRecordErrored(PendingChunk $pendingChunk, LLMResponse $llmResponse, ChunkAnalysisScope $chunkAnalysisScope, CoverageRecorderInterface $coverageRecorder): VulnerabilityHydrationResult
    {
        try {
            return $llmResponse->isRequestTooLarge()
                ? $this->recoverOversizedChunk($pendingChunk, $llmResponse, $chunkAnalysisScope, $coverageRecorder)
                : $this->finalize($pendingChunk, $llmResponse, $coverageRecorder);
        } catch (BudgetExceededException|LLMProviderException $exception) {
            throw $exception;
        } catch (Throwable $throwable) {
            $this->logger->warning('Finalizing an attacker chunk result failed; the chunk is recorded as errored and its siblings in the same window are preserved.', [
                'error' => $throwable->getMessage(),
            ]);
            ChunkCoverageRecorder::recordErrored($pendingChunk->chunk, ChunkFailureReason::fromThrowable($throwable), $coverageRecorder);

            return $this->vulnerabilityFactory->fromList([]);
        }
    }

    /**
     * @throws BudgetExceededException
     * @throws LLMProviderException
     */
    private function recoverOversizedChunk(PendingChunk $pendingChunk, LLMResponse $llmResponse, ChunkAnalysisScope $chunkAnalysisScope, CoverageRecorderInterface $coverageRecorder): VulnerabilityHydrationResult
    {
        return $this->oversizedChunkRecovery->recover(
            $pendingChunk->chunk,
            $pendingChunk->chunkContext,
            $llmResponse->content(),
            $coverageRecorder,
            fn (array $half, CoverageRecorderInterface $halfCoverageRecorder): VulnerabilityHydrationResult => $this->analyzeChunkAlone($half, $chunkAnalysisScope, $halfCoverageRecorder),
        );
    }

    /**
     * Analyzes a chunk carved out mid-pass the way `analyze()` treats the
     * chunks the pass started with: served from the cache when it can be,
     * dispatched as a window of its own otherwise.
     *
     * @param list<ProjectFile> $chunk
     *
     * @throws BudgetExceededException
     * @throws LLMProviderException
     * @throws InvalidToolRegistryException
     */
    private function analyzeChunkAlone(array $chunk, ChunkAnalysisScope $chunkAnalysisScope, CoverageRecorderInterface $coverageRecorder): VulnerabilityHydrationResult
    {
        $cached = $this->servedCachedResult($chunk, $this->chunkContextFactory->cacheCoordinates($chunk, $chunkAnalysisScope->attackerAnalysisRequest, $chunkAnalysisScope->riskMarkerIndex, $this->attackerChunkCache->isContextAware()), $coverageRecorder);
        if ($cached instanceof VulnerabilityHydrationResult) {
            $this->recordFoundVulnerabilities($cached, $coverageRecorder);

            return $cached;
        }

        return $this->dispatchWindow([$this->buildPendingChunk($chunk, $chunkAnalysisScope)], $chunkAnalysisScope, $coverageRecorder)[0];
    }

    private function recordFoundVulnerabilities(VulnerabilityHydrationResult $vulnerabilityHydrationResult, CoverageRecorderInterface $coverageRecorder): void
    {
        foreach ($vulnerabilityHydrationResult->vulnerabilities() as $vulnerability) {
            $coverageRecorder->recordFoundVulnerability($vulnerability);
        }
    }

    /**
     * On a fatal budget/provider abort, records every window from
     * `$fromWindowNumber` onward — the ones never attempted, since the window
     * that failed accounted for its own chunks — as failed, without touching
     * windows that already finalized. Side effects only: the caller rethrows,
     * so no hydration result is returned or consumed.
     *
     * @param list<array<int, list<ProjectFile>>> $windows
     */
    private function recordRemainingWindows(array $windows, int $fromWindowNumber, string $status, CoverageRecorderInterface $coverageRecorder): void
    {
        foreach (\array_slice($windows, $fromWindowNumber) as $chunks) {
            foreach ($chunks as $chunk) {
                ChunkCoverageRecorder::record($chunk, $status, $coverageRecorder);
            }
        }
    }

    /**
     * Marks one window's chunks with `$status`, draining any findings the LLM
     * recorded before the batch aborted. Used both to fail the window that
     * threw and — for a fatal budget/provider abort — every window after it.
     *
     * @param array<int, PendingChunk> $window
     * @param ?string                  $reason why the window failed, when it did so as `errored` for a reason worth showing
     *
     * @return array<int, VulnerabilityHydrationResult>
     */
    private function failWindow(array $window, string $status, CoverageRecorderInterface $coverageRecorder, ?string $reason = null): array
    {
        $results = [];
        foreach ($window as $index => $pendingChunk) {
            null === $reason
                ? ChunkCoverageRecorder::record($pendingChunk->chunk, $status, $coverageRecorder)
                : ChunkCoverageRecorder::recordErrored($pendingChunk->chunk, $reason, $coverageRecorder);
            $this->recordDrainedFindings($pendingChunk, $coverageRecorder);
            $results[$index] = $this->vulnerabilityFactory->fromList([]);
        }

        return $results;
    }

    /**
     * Recovers findings the LLM already recorded via `record_vulnerability`
     * tool calls before the batch call carrying this entry's window aborted
     * — otherwise they vanish with the exception even though
     * `drainFoundVulnerabilities()` exists precisely to let a caller recover
     * candidates found before a mid-run abort. A window that was never
     * dispatched drains empty, which is harmless.
     */
    private function recordDrainedFindings(PendingChunk $pendingChunk, CoverageRecorderInterface $coverageRecorder): void
    {
        $vulnerabilities = $this->vulnerabilityFactory->fromList($pendingChunk->session->drain(), $pendingChunk->chunk)->vulnerabilities();
        foreach ($vulnerabilities as $vulnerability) {
            $coverageRecorder->recordFoundVulnerability($vulnerability);
        }

        ChunkFindingProgress::report($this->progressReporter, $vulnerabilities);
    }

    private function finalize(PendingChunk $pendingChunk, LLMResponse $llmResponse, CoverageRecorderInterface $coverageRecorder): VulnerabilityHydrationResult
    {
        $rawData = $pendingChunk->session->drain();
        $vulnerabilityHydrationResult = $this->vulnerabilityFactory->fromList($rawData, $pendingChunk->chunk);
        $this->recordOutcome($pendingChunk, $llmResponse, $rawData, $vulnerabilityHydrationResult, $coverageRecorder);
        $this->recordFoundVulnerabilities($vulnerabilityHydrationResult, $coverageRecorder);

        return $vulnerabilityHydrationResult;
    }

    /**
     * A response cut short — by the output token limit, a content filter, the
     * tool-loop cap or a call that produced no content — is not the model's
     * complete verdict on the chunk: the findings it recorded are kept, but
     * the chunk is recorded as errored so the report says it could not be
     * fully analyzed, and nothing is cached, so the next run retries it
     * instead of replaying an empty result as safe.
     *
     * @param list<array<string, mixed>> $rawData
     */
    private function recordOutcome(PendingChunk $pendingChunk, LLMResponse $llmResponse, array $rawData, VulnerabilityHydrationResult $vulnerabilityHydrationResult, CoverageRecorderInterface $coverageRecorder): void
    {
        if ($llmResponse->isDegraded()) {
            $this->logger->warning('Attacker response was cut short; the chunk is recorded as errored and left out of the cache', [
                'stop_reason' => $llmResponse->stopReason(),
                'files' => array_map(static fn (ProjectFile $projectFile): string => $projectFile->relativePath(), $pendingChunk->chunk),
                'findings_kept' => \count($rawData),
            ]);
            ChunkCoverageRecorder::recordErrored($pendingChunk->chunk, ChunkFailureReason::fromStopReason($llmResponse->stopReason()), $coverageRecorder);

            return;
        }

        $refusedCalls = $pendingChunk->session->unsettledRefusals();
        if ($refusedCalls > 0) {
            $this->refusedRecordingRecorder->record($pendingChunk->chunk, \count($rawData), $refusedCalls, $coverageRecorder);

            return;
        }

        $this->chunkOutcomeRecorder->record($pendingChunk->chunk, $pendingChunk->chunkContext, $rawData, $vulnerabilityHydrationResult, $coverageRecorder);
    }
}
