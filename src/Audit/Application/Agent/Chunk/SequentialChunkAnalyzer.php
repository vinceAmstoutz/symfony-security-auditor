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
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\VulnerabilityFactory;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Budget\Exception\BudgetExceededException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidToolRegistryException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\LLMProviderException;
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
    ) {}

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

        foreach ($chunks as $index => $chunk) {
            $this->logger->debug(\sprintf('Analyzing chunk %d/%d', $index + 1, \count($chunks)));
            $this->progressReporter->report(ProgressEvent::AttackerChunkStarted->value, [
                'chunk' => $index + 1,
                'total_chunks' => \count($chunks),
            ]);

            $start = microtime(true);
            try {
                $chunkResult = $this->analyzeChunk($chunk, $attackerAnalysisRequest, $coverageRecorder, $toolRegistry, $riskMarkerIndex);
            } catch (BudgetExceededException $budgetExceededException) {
                $this->failRemainingChunks($chunks, $index + 1, 'aborted', $coverageRecorder);

                throw $budgetExceededException;
            } catch (LLMProviderException $llmProviderException) {
                $this->failRemainingChunks($chunks, $index + 1, 'errored', $coverageRecorder);

                throw $llmProviderException;
            }

            foreach ($chunkResult->vulnerabilities() as $vulnerability) {
                $coverageRecorder->recordFoundVulnerability($vulnerability);
            }

            ChunkFindingProgress::report($this->progressReporter, $chunkResult->vulnerabilities());
            $this->progressReporter->report(ProgressEvent::AttackerChunkCompleted->value, [
                'chunk' => $index + 1,
                'total_chunks' => \count($chunks),
                'elapsed_seconds' => microtime(true) - $start,
            ]);
            $allVulnerabilities = [...$allVulnerabilities, ...$chunkResult->vulnerabilities()];

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
        $contextKey = $chunkContext->contextKey;
        $cacheable = $chunkContext->cacheable;
        $systemPrompt = $chunkContext->systemPrompt;
        $userMessage = $chunkContext->userMessage;

        $servedFromCache = $this->servedFromCacheOrNull($chunk, $cacheable, $contextKey, $coverageRecorder);

        if ($servedFromCache instanceof VulnerabilityHydrationResult) {
            return $servedFromCache;
        }

        try {
            if ($this->useStructuredCollection && $this->recordVulnerabilityToolFactory instanceof RecordVulnerabilityToolFactoryInterface) {
                return $this->analyzeChunkViaStructuredCollection($chunk, $chunkContext, $coverageRecorder, $toolRegistry);
            }

            $response = $toolRegistry instanceof ToolRegistry
                ? $this->llmClient->completeWithTools($systemPrompt, $userMessage, $toolRegistry, $this->maxToolIterations)
                : $this->llmClient->complete($systemPrompt, $userMessage);

            return $this->hydrateChunkResponse($chunk, $response, $cacheable, $contextKey, $coverageRecorder);
        } catch (BudgetExceededException $budgetExceededException) {
            // Budget exhaustion is a deliberate abort, not an LLM failure;
            // let it bubble up so RunAuditUseCase can wrap it with a partial report.
            ChunkCoverageRecorder::record($chunk, 'aborted', $coverageRecorder);

            throw $budgetExceededException;
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
    private function hydrateChunkResponse(array $chunk, LLMResponse $llmResponse, bool $cacheable, string $contextKey, CoverageRecorderInterface $coverageRecorder): VulnerabilityHydrationResult
    {
        if ($llmResponse->isEmpty()) {
            if ($cacheable) {
                $this->attackerChunkCache->store($chunk, $contextKey, []);
            }

            ChunkCoverageRecorder::record($chunk, 'analyzed', $coverageRecorder);

            return VulnerabilityHydrationResult::empty();
        }

        try {
            /** @var list<mixed> $rawData */
            $rawData = $llmResponse->parseJson();
        } catch (JsonException $jsonException) {
            $this->logger->error('Failed to parse attacker agent JSON response', [
                'error' => $jsonException->getMessage(),
                'content_preview' => substr($llmResponse->content(), 0, self::PARSE_FAILURE_PREVIEW_BYTES),
            ]);
            ChunkCoverageRecorder::record($chunk, 'errored', $coverageRecorder);

            return VulnerabilityHydrationResult::empty();
        }

        if ($cacheable) {
            /** @var list<array<string, mixed>> $cacheablePayload */
            $cacheablePayload = array_values(array_filter($rawData, 'is_array'));
            $this->attackerChunkCache->store($chunk, $contextKey, $cacheablePayload);
        }

        ChunkCoverageRecorder::record($chunk, 'analyzed', $coverageRecorder);

        return $this->vulnerabilityFactory->fromList($rawData);
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
            $this->llmClient->completeWithTools($chunkContext->systemPrompt, $chunkContext->userMessage, $structuredVulnerabilityCollectionSession->toolRegistry, $this->maxToolIterations);
        } catch (Throwable $throwable) {
            $this->recordDrainedFindings($structuredVulnerabilityCollectionSession, $coverageRecorder);

            throw $throwable;
        }

        $rawData = $structuredVulnerabilityCollectionSession->drain();

        if ($chunkContext->cacheable) {
            $this->attackerChunkCache->store($chunk, $chunkContext->contextKey, $rawData);
        }

        ChunkCoverageRecorder::record($chunk, 'analyzed', $coverageRecorder);

        return $this->vulnerabilityFactory->fromList($rawData);
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
        foreach ($this->vulnerabilityFactory->fromList($structuredVulnerabilityCollectionSession->drain())->vulnerabilities() as $vulnerability) {
            $coverageRecorder->recordFoundVulnerability($vulnerability);
        }
    }
}
