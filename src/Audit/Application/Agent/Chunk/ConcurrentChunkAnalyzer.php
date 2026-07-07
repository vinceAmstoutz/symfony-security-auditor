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
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\VulnerabilityFactory;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Budget\Exception\BudgetExceededException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidToolRegistryException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\LLMProviderException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProgressEvent;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFile;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\Vulnerability;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilityHydrationResult;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Pipeline\CoverageRecorderInterface;
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
    ) {}

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

        /** @var array<int, VulnerabilityHydrationResult> $cachedResults */
        $cachedResults = [];
        /** @var array<int, array{chunk: list<ProjectFile>, contextKey: string, cacheable: bool, session: StructuredVulnerabilityCollectionSession, systemPrompt: string, userMessage: string}> $pending */
        $pending = [];
        foreach ($chunks as $index => $chunk) {
            $this->reportChunkStarted($index, $totalChunks);

            $chunkContext = $this->chunkContextFactory->create($chunk, $attackerAnalysisRequest, $riskMarkerIndex, $this->attackerChunkCache->isContextAware());

            $cached = $this->servedCachedResult($chunk, $chunkContext, $coverageRecorder);
            if ($cached instanceof VulnerabilityHydrationResult) {
                $cachedResults[$index] = $cached;
                foreach ($cached->vulnerabilities() as $vulnerability) {
                    $coverageRecorder->recordFoundVulnerability($vulnerability);
                }

                continue;
            }

            $pending[$index] = $this->buildPendingChunk($chunk, $chunkContext, $toolRegistry);
        }

        $dispatchedResults = $this->dispatchInWindows($pending, $coverageRecorder);

        return $this->aggregate($chunks, $cachedResults, $dispatchedResults);
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
    private function servedCachedResult(array $chunk, ChunkContext $chunkContext, CoverageRecorderInterface $coverageRecorder): ?VulnerabilityHydrationResult
    {
        if (!$chunkContext->cacheable) {
            return null;
        }

        $cached = $this->attackerChunkCache->get($chunk, $chunkContext->contextKey);
        if (null === $cached) {
            return null;
        }

        return $this->attackerChunkCache->served($chunk, $cached, $coverageRecorder);
    }

    /**
     * @param list<ProjectFile> $chunk
     *
     * @return array{chunk: list<ProjectFile>, contextKey: string, cacheable: bool, session: StructuredVulnerabilityCollectionSession, systemPrompt: string, userMessage: string}
     *
     * @throws InvalidToolRegistryException
     */
    private function buildPendingChunk(array $chunk, ChunkContext $chunkContext, ?ToolRegistry $toolRegistry): array
    {
        $structuredVulnerabilityCollectionSession = StructuredVulnerabilityCollectionSession::begin($this->recordVulnerabilityToolFactory, $this->logger, $toolRegistry?->tools() ?? []);

        return [
            'chunk' => $chunk,
            'contextKey' => $chunkContext->contextKey,
            'cacheable' => $chunkContext->cacheable,
            'session' => $structuredVulnerabilityCollectionSession,
            'systemPrompt' => $chunkContext->systemPrompt,
            'userMessage' => $chunkContext->userMessage,
        ];
    }

    /**
     * @param list<list<ProjectFile>>                  $chunks
     * @param array<int, VulnerabilityHydrationResult> $cachedResults
     * @param array<int, VulnerabilityHydrationResult> $dispatchedResults
     *
     * @return array{0: list<Vulnerability>, 1: array<string, int>}
     */
    private function aggregate(array $chunks, array $cachedResults, array $dispatchedResults): array
    {
        $totalChunks = \count($chunks);
        $allVulnerabilities = [];
        $totalDropsByReason = [];
        foreach (array_keys($chunks) as $index) {
            $chunkResult = $cachedResults[$index] ?? $dispatchedResults[$index];
            ChunkFindingProgress::report($this->progressReporter, $chunkResult->vulnerabilities());
            $this->reportChunkCompleted($index, $totalChunks);
            $allVulnerabilities = [...$allVulnerabilities, ...$chunkResult->vulnerabilities()];
            $totalDropsByReason = $this->mergeDrops($totalDropsByReason, $chunkResult->dropsByReason());
        }

        return [$allVulnerabilities, $totalDropsByReason];
    }

    private function reportChunkCompleted(int $index, int $totalChunks): void
    {
        $this->progressReporter->report(ProgressEvent::AttackerChunkCompleted->value, [
            'chunk' => $index + 1,
            'total_chunks' => $totalChunks,
            'elapsed_seconds' => 0.0,
        ]);
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
     * @param array<int, array{chunk: list<ProjectFile>, contextKey: string, cacheable: bool, session: StructuredVulnerabilityCollectionSession, systemPrompt: string, userMessage: string}> $pending
     *
     * @return array<int, VulnerabilityHydrationResult>
     *
     * @throws BudgetExceededException
     * @throws LLMProviderException
     */
    private function dispatchInWindows(array $pending, CoverageRecorderInterface $coverageRecorder): array
    {
        $windows = array_chunk($pending, max(1, $this->maxConcurrent), true);
        $results = [];

        foreach ($windows as $windowNumber => $window) {
            try {
                $results += $this->dispatchWindow($window, $coverageRecorder);
            } catch (BudgetExceededException $budgetExceededException) {
                $this->failRemainingWindows($windows, $windowNumber, 'aborted', $coverageRecorder);

                throw $budgetExceededException;
            } catch (LLMProviderException $llmProviderException) {
                $this->failRemainingWindows($windows, $windowNumber, 'errored', $coverageRecorder);

                throw $llmProviderException;
            } catch (Throwable $throwable) {
                $this->logger->warning('Concurrent attacker batch failed; its chunks are recorded as errored and the audit continues.', [
                    'error' => $throwable->getMessage(),
                ]);

                return $results + $this->failRemainingWindows($windows, $windowNumber, 'errored', $coverageRecorder);
            }
        }

        return $results;
    }

    /**
     * @param array<int, array{chunk: list<ProjectFile>, contextKey: string, cacheable: bool, session: StructuredVulnerabilityCollectionSession, systemPrompt: string, userMessage: string}> $window
     *
     * @return array<int, VulnerabilityHydrationResult>
     *
     * @throws BudgetExceededException
     * @throws LLMProviderException
     */
    private function dispatchWindow(array $window, CoverageRecorderInterface $coverageRecorder): array
    {
        $requests = array_values(array_map(
            static fn (array $entry): array => ['system' => $entry['systemPrompt'], 'user' => $entry['userMessage'], 'tools' => $entry['session']->toolRegistry],
            $window,
        ));

        $this->toolBatchCapableLLMClient->completeBatchWithTools($requests, $this->maxConcurrent, $this->maxToolIterations);

        $results = [];
        foreach ($window as $index => $entry) {
            $results[$index] = $this->finalizeOrRecordErrored($entry, $coverageRecorder);
        }

        return $results;
    }

    /**
     * Isolates a single entry's `finalize()` failure (e.g. a cache-store I/O
     * error) to that entry alone, mirroring `SequentialChunkAnalyzer`'s
     * per-chunk isolation — a sibling entry in the same window that already
     * finalized successfully must keep its result.
     *
     * @param array{chunk: list<ProjectFile>, contextKey: string, cacheable: bool, session: StructuredVulnerabilityCollectionSession, systemPrompt: string, userMessage: string} $entry
     */
    private function finalizeOrRecordErrored(array $entry, CoverageRecorderInterface $coverageRecorder): VulnerabilityHydrationResult
    {
        try {
            return $this->finalize($entry, $coverageRecorder);
        } catch (Throwable $throwable) {
            $this->logger->warning('Finalizing an attacker chunk result failed; the chunk is recorded as errored and its siblings in the same window are preserved.', [
                'error' => $throwable->getMessage(),
            ]);
            ChunkCoverageRecorder::record($entry['chunk'], 'errored', $coverageRecorder);

            return $this->vulnerabilityFactory->fromList([]);
        }
    }

    /**
     * Marks every window from `$fromWindowNumber` onward — the one that just
     * failed plus any not yet attempted — as failed, without touching windows
     * that already finalized successfully.
     *
     * @param list<array<int, array{chunk: list<ProjectFile>, contextKey: string, cacheable: bool, session: StructuredVulnerabilityCollectionSession, systemPrompt: string, userMessage: string}>> $windows
     *
     * @return array<int, VulnerabilityHydrationResult>
     */
    private function failRemainingWindows(array $windows, int $fromWindowNumber, string $status, CoverageRecorderInterface $coverageRecorder): array
    {
        $results = [];
        foreach ($windows as $windowNumber => $window) {
            if ($windowNumber < $fromWindowNumber) {
                continue;
            }

            foreach ($window as $index => $entry) {
                ChunkCoverageRecorder::record($entry['chunk'], $status, $coverageRecorder);
                $results[$index] = $this->vulnerabilityFactory->fromList([]);
            }
        }

        return $results;
    }

    /**
     * @param array{chunk: list<ProjectFile>, contextKey: string, cacheable: bool, session: StructuredVulnerabilityCollectionSession, systemPrompt: string, userMessage: string} $entry
     */
    private function finalize(array $entry, CoverageRecorderInterface $coverageRecorder): VulnerabilityHydrationResult
    {
        $rawData = $entry['session']->drain();

        if ($entry['cacheable']) {
            $this->attackerChunkCache->store($entry['chunk'], $entry['contextKey'], $rawData);
        }

        ChunkCoverageRecorder::record($entry['chunk'], 'analyzed', $coverageRecorder);

        $vulnerabilityHydrationResult = $this->vulnerabilityFactory->fromList($rawData);
        foreach ($vulnerabilityHydrationResult->vulnerabilities() as $vulnerability) {
            $coverageRecorder->recordFoundVulnerability($vulnerability);
        }

        return $vulnerabilityHydrationResult;
    }
}
