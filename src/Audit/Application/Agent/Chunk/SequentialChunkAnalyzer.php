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

use JsonException;
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
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\LLMRequestTooLargeException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProgressEvent;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFile;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\Vulnerability;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilityHydrationResult;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Pipeline\CoverageRecorderInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\LLMClientInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\LLMResponse;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\ProgressReporterInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\Tool\ToolRegistry;

/**
 * Analyzes chunks one at a time. The default structured-collection mode records
 * findings through a per-chunk `record_vulnerability` tool; the opt-out JSON
 * mode parses the model's array response. Cache hits short-circuit the LLM.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class SequentialChunkAnalyzer
{
    private const int PARSE_FAILURE_PREVIEW_BYTES = 512;

    private OversizedChunkRecovery $oversizedChunkRecovery;

    private ChunkOutcomeRecorder $chunkOutcomeRecorder;

    public function __construct(
        private LLMClientInterface $llmClient,
        private ChunkContextFactory $chunkContextFactory,
        private AttackerChunkCache $attackerChunkCache,
        private VulnerabilityFactory $vulnerabilityFactory,
        private LoggerInterface $logger,
        private ProgressReporterInterface $progressReporter,
        private int $maxToolIterations,
        private bool $useStructuredCollection,
        private ?RecordVulnerabilityToolFactoryInterface $recordVulnerabilityToolFactory,
    ) {
        $this->oversizedChunkRecovery = new OversizedChunkRecovery($logger, $attackerChunkCache, $vulnerabilityFactory);
        $this->chunkOutcomeRecorder = new ChunkOutcomeRecorder($attackerChunkCache, $logger);
    }

    /**
     * @param list<list<ProjectFile>> $chunks
     *
     * @return array{0: list<Vulnerability>, 1: array<string, int>}
     *
     * @throws BudgetExceededException
     * @throws LLMProviderException
     */
    public function analyze(array $chunks, AttackerAnalysisRequest $attackerAnalysisRequest, CoverageRecorderInterface $coverageRecorder, ?ToolRegistry $toolRegistry, RiskMarkerIndex $riskMarkerIndex): array
    {
        $allVulnerabilities = [];
        $totalDropsByReason = [];
        $statusTrackingCoverageRecorder = new StatusTrackingCoverageRecorder($coverageRecorder);

        foreach ($chunks as $index => $chunk) {
            $this->logger->debug(\sprintf('Analyzing chunk %d/%d', $index + 1, \count($chunks)));
            $this->progressReporter->report(ProgressEvent::AttackerChunkStarted->value, [
                'chunk' => $index + 1,
                'total_chunks' => \count($chunks),
            ]);

            $start = microtime(true);
            try {
                $chunkResult = $this->analyzeChunk($chunk, $attackerAnalysisRequest, $statusTrackingCoverageRecorder, $toolRegistry, $riskMarkerIndex);
            } catch (BudgetExceededException $budgetExceededException) {
                $this->failRemainingChunks($chunks, $index + 1, 'aborted', $coverageRecorder);

                throw $budgetExceededException;
            } catch (LLMProviderException $llmProviderException) {
                $this->failRemainingChunks($chunks, $index + 1, 'errored', $coverageRecorder);

                throw $llmProviderException;
            }

            $this->recordFindings($chunkResult->vulnerabilities(), $coverageRecorder);
            $this->progressReporter->report(ProgressEvent::AttackerChunkCompleted->value, [
                'chunk' => $index + 1,
                'total_chunks' => \count($chunks),
                'elapsed_seconds' => microtime(true) - $start,
                'status' => $statusTrackingCoverageRecorder->chunkStatus($chunk),
            ]);
            array_push($allVulnerabilities, ...$chunkResult->vulnerabilities());

            foreach ($chunkResult->dropsByReason() as $reason => $count) {
                $totalDropsByReason[$reason] = ($totalDropsByReason[$reason] ?? 0) + $count;
            }

            $this->logger->debug('Chunk analysis complete', [
                'chunk' => $index + 1,
                'found' => \count($chunkResult->vulnerabilities()),
                'dropped' => $chunkResult->totalDropped(),
                'total_so_far' => \count($allVulnerabilities),
            ]);
        }

        return [$allVulnerabilities, $totalDropsByReason];
    }

    /**
     * Marks every chunk from `$fromIndex` onward — the ones the loop never
     * reached because an earlier chunk aborted the run — under the same
     * status, mirroring `ConcurrentChunkAnalyzer::failRemainingWindows()`.
     *
     * @param list<list<ProjectFile>> $chunks
     */
    private function failRemainingChunks(array $chunks, int $fromIndex, string $status, CoverageRecorderInterface $coverageRecorder): void
    {
        foreach ($chunks as $index => $chunk) {
            if ($index < $fromIndex) {
                continue;
            }

            ChunkCoverageRecorder::record($chunk, $status, $coverageRecorder);
        }
    }

    /**
     * @param list<ProjectFile> $chunk
     *
     * @throws BudgetExceededException
     * @throws LLMProviderException
     */
    private function analyzeChunk(array $chunk, AttackerAnalysisRequest $attackerAnalysisRequest, CoverageRecorderInterface $coverageRecorder, ?ToolRegistry $toolRegistry, RiskMarkerIndex $riskMarkerIndex): VulnerabilityHydrationResult
    {
        $chunkContext = $this->chunkContextFactory->create($chunk, $attackerAnalysisRequest, $riskMarkerIndex, $this->attackerChunkCache->isContextAware());

        $servedFromCache = $this->servedFromCacheOrNull($chunk, $chunkContext->cacheable, $chunkContext->contextKey, $coverageRecorder);

        if ($servedFromCache instanceof VulnerabilityHydrationResult) {
            return $servedFromCache;
        }

        try {
            return $this->analyzeChunkThroughLlm($chunk, $chunkContext, $coverageRecorder, $toolRegistry);
        } catch (BudgetExceededException $budgetExceededException) {
            // Budget exhaustion is a deliberate abort, not an LLM failure;
            // let it bubble up so RunAuditUseCase can wrap it with a partial report.
            ChunkCoverageRecorder::record($chunk, 'aborted', $coverageRecorder);

            throw $budgetExceededException;
        } catch (LLMRequestTooLargeException $llmRequestTooLargeException) {
            return $this->oversizedChunkRecovery->recover(
                $chunk,
                $chunkContext,
                $llmRequestTooLargeException->getMessage(),
                $coverageRecorder,
                fn (array $half, CoverageRecorderInterface $halfCoverageRecorder): VulnerabilityHydrationResult => $this->analyzeChunk($half, $attackerAnalysisRequest, $halfCoverageRecorder, $toolRegistry, $riskMarkerIndex),
            );
        } catch (LLMProviderException $llmProviderException) {
            ChunkCoverageRecorder::record($chunk, 'errored', $coverageRecorder);

            throw $llmProviderException;
        } catch (Throwable $exception) {
            $this->logger->error('Attacker agent LLM call failed', [
                'error' => $exception->getMessage(),
            ]);
            ChunkCoverageRecorder::record($chunk, 'errored', $coverageRecorder);

            return VulnerabilityHydrationResult::empty();
        }
    }

    /**
     * @param list<ProjectFile> $chunk
     *
     * @throws BudgetExceededException
     * @throws LLMProviderException
     * @throws InvalidToolRegistryException
     */
    private function analyzeChunkThroughLlm(array $chunk, ChunkContext $chunkContext, CoverageRecorderInterface $coverageRecorder, ?ToolRegistry $toolRegistry): VulnerabilityHydrationResult
    {
        if ($this->useStructuredCollection && $this->recordVulnerabilityToolFactory instanceof RecordVulnerabilityToolFactoryInterface) {
            return $this->analyzeChunkViaStructuredCollection($chunk, $chunkContext, $coverageRecorder, $toolRegistry);
        }

        $response = $toolRegistry instanceof ToolRegistry
            ? $this->llmClient->completeWithTools($chunkContext->systemPrompt, $chunkContext->userMessage, $toolRegistry, $this->maxToolIterations)
            : $this->llmClient->complete($chunkContext->systemPrompt, $chunkContext->userMessage);

        return $this->hydrateChunkResponse($chunk, $response, $chunkContext, $coverageRecorder);
    }

    /**
     * @param list<ProjectFile> $chunk
     */
    private function servedFromCacheOrNull(array $chunk, bool $cacheable, string $contextKey, CoverageRecorderInterface $coverageRecorder): ?VulnerabilityHydrationResult
    {
        if (!$cacheable) {
            return null;
        }

        $cached = $this->attackerChunkCache->get($chunk, $contextKey);

        if (null === $cached) {
            return null;
        }

        return $this->attackerChunkCache->served($chunk, $cached, $coverageRecorder);
    }

    /**
     * @param list<ProjectFile> $chunk
     */
    private function hydrateChunkResponse(array $chunk, LLMResponse $llmResponse, ChunkContext $chunkContext, CoverageRecorderInterface $coverageRecorder): VulnerabilityHydrationResult
    {
        if ($llmResponse->isDegraded()) {
            return $this->hydrateIncompleteResponse($chunk, $llmResponse, $this->parseablePayload($llmResponse), $coverageRecorder);
        }

        if ($llmResponse->isEmpty()) {
            if ($chunkContext->cacheable) {
                $this->attackerChunkCache->store($chunk, $chunkContext->contextKey, []);
            }

            ChunkCoverageRecorder::record($chunk, 'analyzed', $coverageRecorder);

            return VulnerabilityHydrationResult::empty();
        }

        try {
            /** @var list<array<string, mixed>> $rawData */
            $rawData = $llmResponse->parseJson();
        } catch (JsonException $jsonException) {
            $this->logger->error('Failed to parse attacker agent JSON response', [
                'error' => $jsonException->getMessage(),
                'content_preview' => substr($llmResponse->content(), 0, self::PARSE_FAILURE_PREVIEW_BYTES),
            ]);
            ChunkCoverageRecorder::record($chunk, 'errored', $coverageRecorder);

            return VulnerabilityHydrationResult::empty();
        }

        return $this->settleChunk($chunk, $chunkContext, $rawData, $coverageRecorder);
    }

    /**
     * @param list<ProjectFile> $chunk
     *
     * @throws InvalidToolRegistryException
     */
    private function analyzeChunkViaStructuredCollection(array $chunk, ChunkContext $chunkContext, CoverageRecorderInterface $coverageRecorder, ?ToolRegistry $toolRegistry): VulnerabilityHydrationResult
    {
        \assert($this->recordVulnerabilityToolFactory instanceof RecordVulnerabilityToolFactoryInterface);

        $structuredVulnerabilityCollectionSession = StructuredVulnerabilityCollectionSession::begin($this->recordVulnerabilityToolFactory, $this->logger, $toolRegistry?->tools() ?? []);

        try {
            $llmResponse = $this->llmClient->completeWithTools($chunkContext->systemPrompt, $chunkContext->userMessage, $structuredVulnerabilityCollectionSession->toolRegistry, $this->maxToolIterations);
        } catch (Throwable $throwable) {
            $this->recordDrainedFindings($structuredVulnerabilityCollectionSession, $coverageRecorder);

            throw $throwable;
        }

        $rawData = $structuredVulnerabilityCollectionSession->drain();

        if ($llmResponse->isDegraded()) {
            return $this->hydrateIncompleteResponse($chunk, $llmResponse, $rawData, $coverageRecorder);
        }

        return $this->settleChunk($chunk, $chunkContext, $rawData, $coverageRecorder);
    }

    /**
     * @param list<ProjectFile>          $chunk
     * @param list<array<string, mixed>> $rawData
     */
    private function settleChunk(array $chunk, ChunkContext $chunkContext, array $rawData, CoverageRecorderInterface $coverageRecorder): VulnerabilityHydrationResult
    {
        $vulnerabilityHydrationResult = $this->vulnerabilityFactory->fromList($rawData);
        $this->chunkOutcomeRecorder->record($chunk, $chunkContext, $rawData, $vulnerabilityHydrationResult, $coverageRecorder);

        return $vulnerabilityHydrationResult;
    }

    /**
     * A response cut short — by the output token limit, a content filter, the
     * tool-loop cap or a call that produced no content — is not the model's
     * complete verdict on the chunk: the findings it does carry are kept, but
     * the chunk is recorded as errored so the report says it could not be
     * fully analyzed, and nothing is cached, so the next run retries it
     * instead of replaying an empty result as safe.
     *
     * @param list<ProjectFile> $chunk
     * @param list<mixed>       $rawData
     */
    private function hydrateIncompleteResponse(array $chunk, LLMResponse $llmResponse, array $rawData, CoverageRecorderInterface $coverageRecorder): VulnerabilityHydrationResult
    {
        $this->logger->warning('Attacker response was cut short; the chunk is recorded as errored and left out of the cache', [
            'stop_reason' => $llmResponse->stopReason(),
            'files' => array_map(static fn (ProjectFile $projectFile): string => $projectFile->relativePath(), $chunk),
            'findings_kept' => \count($rawData),
        ]);
        ChunkCoverageRecorder::record($chunk, 'errored', $coverageRecorder);

        return $this->vulnerabilityFactory->fromList($rawData);
    }

    /**
     * The findings a cut-short JSON answer still carries: `parseJson()`
     * recovers the first balanced block of a truncated array, which is a
     * single finding object rather than a list, so it is wrapped back into one.
     *
     * @return list<mixed>
     */
    private function parseablePayload(LLMResponse $llmResponse): array
    {
        try {
            $decoded = $llmResponse->parseJson();
        } catch (JsonException) {
            return [];
        }

        return array_is_list($decoded) ? $decoded : [$decoded];
    }

    /**
     * Recovers findings the LLM already recorded via `record_vulnerability`
     * tool calls in an earlier round of this chunk's own conversation before
     * a later round aborted it — otherwise they vanish with the exception
     * even though `drainFoundVulnerabilities()` exists precisely to let a
     * caller recover candidates found before a mid-run abort.
     */
    private function recordDrainedFindings(StructuredVulnerabilityCollectionSession $structuredVulnerabilityCollectionSession, CoverageRecorderInterface $coverageRecorder): void
    {
        $this->recordFindings($this->vulnerabilityFactory->fromList($structuredVulnerabilityCollectionSession->drain())->vulnerabilities(), $coverageRecorder);
    }

    /**
     * @param list<Vulnerability> $vulnerabilities
     */
    private function recordFindings(array $vulnerabilities, CoverageRecorderInterface $coverageRecorder): void
    {
        foreach ($vulnerabilities as $vulnerability) {
            $coverageRecorder->recordFoundVulnerability($vulnerability);
        }

        ChunkFindingProgress::report($this->progressReporter, $vulnerabilities);
    }
}
