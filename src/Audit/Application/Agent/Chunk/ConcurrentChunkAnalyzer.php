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
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\AttackerAnalysisRequest;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\RecordVulnerabilityToolFactoryInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\RiskMarkerIndex;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\VulnerabilityCollector;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\VulnerabilityFactory;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Budget\Exception\BudgetExceededException;
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
     */
    public function analyze(array $chunks, AttackerAnalysisRequest $attackerAnalysisRequest, CoverageRecorderInterface $coverageRecorder, RiskMarkerIndex $riskMarkerIndex): array
    {
        $totalChunks = \count($chunks);

        /** @var array<int, VulnerabilityHydrationResult> $cachedResults */
        $cachedResults = [];
        /** @var array<int, array{chunk: list<ProjectFile>, contextKey: string, cacheable: bool, collector: VulnerabilityCollector}> $pending */
        $pending = [];
        $requests = [];
        foreach ($chunks as $index => $chunk) {
            $this->reportChunkStarted($index, $totalChunks);

            $chunkContext = $this->chunkContextFactory->create($chunk, $attackerAnalysisRequest, $riskMarkerIndex, $this->attackerChunkCache->isContextAware());

            $cached = $this->servedCachedResult($chunk, $chunkContext, $coverageRecorder);
            if (null !== $cached) {
                $cachedResults[$index] = $cached;

                continue;
            }

            $this->registerPendingRequest($index, $chunk, $chunkContext, $pending, $requests);
        }

        if ([] !== $requests) {
            $this->dispatch($requests, $pending, $coverageRecorder);
        }

        return $this->aggregate($chunks, $cachedResults, $pending, $coverageRecorder, $totalChunks);
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
     * @param list<ProjectFile>                                                                                            $chunk
     * @param array<int, array{chunk: list<ProjectFile>, contextKey: string, cacheable: bool, collector: VulnerabilityCollector}> $pending
     * @param list<array{system: string, user: string, tools: ToolRegistry}>                                              $requests
     */
    private function registerPendingRequest(int $index, array $chunk, ChunkContext $chunkContext, array &$pending, array &$requests): void
    {
        $collector = new VulnerabilityCollector();
        $toolRegistry = new ToolRegistry([$this->recordVulnerabilityToolFactory->create($collector)], $this->logger);
        $pending[$index] = [
            'chunk' => $chunk,
            'contextKey' => $chunkContext->contextKey,
            'cacheable' => $chunkContext->cacheable,
            'collector' => $collector,
        ];
        $requests[] = ['system' => $chunkContext->systemPrompt, 'user' => $chunkContext->userMessage, 'tools' => $toolRegistry];
    }

    /**
     * @param list<list<ProjectFile>>                                                                                      $chunks
     * @param array<int, VulnerabilityHydrationResult>                                                                     $cachedResults
     * @param array<int, array{chunk: list<ProjectFile>, contextKey: string, cacheable: bool, collector: VulnerabilityCollector}> $pending
     *
     * @return array{0: list<Vulnerability>, 1: array<string, int>}
     */
    private function aggregate(array $chunks, array $cachedResults, array $pending, CoverageRecorderInterface $coverageRecorder, int $totalChunks): array
    {
        $allVulnerabilities = [];
        $totalDropsByReason = [];
        foreach (array_keys($chunks) as $index) {
            $chunkResult = $cachedResults[$index] ?? $this->finalize($pending[$index], $coverageRecorder);
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
     * @param list<array{system: string, user: string, tools: ToolRegistry}>                                                      $requests
     * @param array<int, array{chunk: list<ProjectFile>, contextKey: string, cacheable: bool, collector: VulnerabilityCollector}> $pending
     */
    private function dispatch(array $requests, array $pending, CoverageRecorderInterface $coverageRecorder): void
    {
        try {
            $this->toolBatchCapableLLMClient->completeBatchWithTools($requests, $this->maxConcurrent, $this->maxToolIterations);
        } catch (BudgetExceededException $budgetExceededException) {
            $this->recordPendingCoverage($pending, 'aborted', $coverageRecorder);

            throw $budgetExceededException;
        } catch (LLMProviderException $llmProviderException) {
            $this->recordPendingCoverage($pending, 'errored', $coverageRecorder);

            throw $llmProviderException;
        }
    }

    /**
     * @param array<int, array{chunk: list<ProjectFile>, contextKey: string, cacheable: bool, collector: VulnerabilityCollector}> $pending
     */
    private function recordPendingCoverage(array $pending, string $status, CoverageRecorderInterface $coverageRecorder): void
    {
        foreach ($pending as $entry) {
            ChunkCoverageRecorder::record($entry['chunk'], $status, $coverageRecorder);
        }
    }

    /**
     * @param array{chunk: list<ProjectFile>, contextKey: string, cacheable: bool, collector: VulnerabilityCollector} $entry
     */
    private function finalize(array $entry, CoverageRecorderInterface $coverageRecorder): VulnerabilityHydrationResult
    {
        $rawData = $entry['collector']->drain();

        if ($entry['cacheable']) {
            $this->attackerChunkCache->store($entry['chunk'], $entry['contextKey'], $rawData);
        }

        ChunkCoverageRecorder::record($entry['chunk'], 'analyzed', $coverageRecorder);

        return $this->vulnerabilityFactory->fromList($rawData);
    }
}
