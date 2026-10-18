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
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\RecordingToolClients;
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
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\ProgressReporterInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\Tool\ToolRegistry;

/**
 * Analyzes chunks one at a time. The default structured-collection mode records
 * findings through a per-chunk `record_vulnerability` tool; the opt-out JSON
 * mode parses the model's array response, as does a structured turn whose
 * client never offered the tool. Cache hits short-circuit the LLM.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class SequentialChunkAnalyzer
{
    private OversizedChunkRecovery $oversizedChunkRecovery;

    private RefusedRecordingRecorder $refusedRecordingRecorder;

    private ChunkAnswerHydrator $chunkAnswerHydrator;

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
        private RecordingToolClients $recordingToolClients,
    ) {
        $this->oversizedChunkRecovery = new OversizedChunkRecovery($logger, $attackerChunkCache, $vulnerabilityFactory);
        $this->refusedRecordingRecorder = new RefusedRecordingRecorder($logger);
        $this->chunkAnswerHydrator = new ChunkAnswerHydrator($attackerChunkCache, $vulnerabilityFactory, $logger);
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

            $this->progressReporter->report(ProgressEvent::AttackerChunkCompleted->value, ChunkCompletionContext::of($index, \count($chunks), microtime(true) - $start, $statusTrackingCoverageRecorder, $chunk));
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
            return $this->recordedFindings($servedFromCache, $coverageRecorder);
        }

        try {
            return $this->recordedFindings($this->analyzeChunkThroughLlm($chunk, $chunkContext, $coverageRecorder, $toolRegistry), $coverageRecorder);
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
            ChunkCoverageRecorder::recordErrored($chunk, ChunkFailureReason::fromThrowable($exception), $coverageRecorder);

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

        return $this->chunkAnswerHydrator->hydrateJsonAnswer($chunk, $response, $chunkContext, $coverageRecorder);
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
            $this->recordDrainedFindings($structuredVulnerabilityCollectionSession, $chunk, $coverageRecorder);

            throw $throwable;
        }

        $this->recordingToolClients->note($this->llmClient, $structuredVulnerabilityCollectionSession->recordingToolReached());
        if ($this->recordingToolClients->ignoresTools($this->llmClient)) {
            return $this->chunkAnswerHydrator->hydrateJsonAnswer($chunk, $llmResponse, $chunkContext, $coverageRecorder);
        }

        $rawData = $structuredVulnerabilityCollectionSession->drain();

        if ($llmResponse->isDegraded()) {
            return $this->chunkAnswerHydrator->hydrateIncompleteAnswer($chunk, $llmResponse, $rawData, $coverageRecorder);
        }

        $refusedCalls = $structuredVulnerabilityCollectionSession->unsettledRefusals();
        if ($refusedCalls > 0) {
            $this->refusedRecordingRecorder->record($chunk, \count($rawData), $refusedCalls, $coverageRecorder);

            return $this->vulnerabilityFactory->fromList($rawData, $chunk);
        }

        return $this->chunkAnswerHydrator->settle($chunk, $chunkContext->answeredBy($llmResponse), $rawData, $coverageRecorder);
    }

    /**
     * Recovers findings the LLM already recorded via `record_vulnerability`
     * tool calls in an earlier round of this chunk's own conversation before
     * a later round aborted it — otherwise they vanish with the exception
     * even though `drainFoundVulnerabilities()` exists precisely to let a
     * caller recover candidates found before a mid-run abort.
     *
     * @param list<ProjectFile> $chunk
     */
    private function recordDrainedFindings(StructuredVulnerabilityCollectionSession $structuredVulnerabilityCollectionSession, array $chunk, CoverageRecorderInterface $coverageRecorder): void
    {
        $this->recordFindings($this->vulnerabilityFactory->fromList($structuredVulnerabilityCollectionSession->drain(), $chunk)->vulnerabilities(), $coverageRecorder);
    }

    /**
     * A chunk split in two reaches this once per half, as each half is
     * analyzed — not once for the merged chunk — so the findings of a first
     * half are already in the recorder's buffer when an abort ends the second.
     */
    private function recordedFindings(VulnerabilityHydrationResult $vulnerabilityHydrationResult, CoverageRecorderInterface $coverageRecorder): VulnerabilityHydrationResult
    {
        $this->recordFindings($vulnerabilityHydrationResult->vulnerabilities(), $coverageRecorder);

        return $vulnerabilityHydrationResult;
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
