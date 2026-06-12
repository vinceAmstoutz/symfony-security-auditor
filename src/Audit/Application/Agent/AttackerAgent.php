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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent;

use JsonException;
use Psr\Log\LoggerInterface;
use Throwable;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\Chunking\FileChunker;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Budget\Exception\BudgetExceededException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\LLMProviderException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\AgentRole;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProgressEvent;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFile;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\Vulnerability;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VulnerabilityHydrationResult;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Pipeline\CoverageRecorderInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\AttackerCacheInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\AttackerPromptBuilderInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\CodeSlicerInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\ContextAwareAttackerCacheInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\LLMClientInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\ProgressReporterInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\StaticPreScannerInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\Tool\ToolRegistry;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\Tool\ToolRegistryFactoryInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\ToolBatchCapableLLMClientInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Progress\NullProgressReporter;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Scan\NullCodeSlicer;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Scan\NullStaticPreScanner;

/** @internal not part of the BC promise — see docs/versioning.md */
final readonly class AttackerAgent implements AttackerAgentInterface
{
    private const int PARSE_FAILURE_PREVIEW_BYTES = 512;

    public const int DEFAULT_MAX_TOOL_ITERATIONS = 8;

    public const bool DEFAULT_TOOLS_ENABLED = false;

    public const bool DEFAULT_LEAN_MODE = false;

    public const bool DEFAULT_STRUCTURED_COLLECTION = true;

    public const int DEFAULT_MAX_CONCURRENT = 1;

    private StaticPreScannerInterface $staticPreScanner;

    private FileChunker $fileChunker;

    private CodeSlicerInterface $codeSlicer;

    private AttackerContextPromptRenderer $attackerContextPromptRenderer;

    private ProgressReporterInterface $progressReporter;

    public function __construct(
        private LLMClientInterface $llmClient,
        private AttackerPromptBuilderInterface $attackerPromptBuilder,
        private VulnerabilityFactory $vulnerabilityFactory,
        private AttackerCacheInterface $attackerCache,
        private LoggerInterface $logger,
        private ?ToolRegistryFactoryInterface $toolRegistryFactory = null,
        private bool $toolsEnabled = self::DEFAULT_TOOLS_ENABLED,
        private int $maxToolIterations = self::DEFAULT_MAX_TOOL_ITERATIONS,
        ?StaticPreScannerInterface $staticPreScanner = null,
        private bool $leanMode = self::DEFAULT_LEAN_MODE,
        ?FileChunker $fileChunker = null,
        ?CodeSlicerInterface $codeSlicer = null,
        ?AttackerContextPromptRenderer $attackerContextPromptRenderer = null,
        private ?RecordVulnerabilityToolFactoryInterface $recordVulnerabilityToolFactory = null,
        private bool $useStructuredCollection = self::DEFAULT_STRUCTURED_COLLECTION,
        ?ProgressReporterInterface $progressReporter = null,
        private int $maxConcurrent = self::DEFAULT_MAX_CONCURRENT,
    ) {
        $this->staticPreScanner = $staticPreScanner ?? new NullStaticPreScanner();
        $this->fileChunker = $fileChunker ?? new FileChunker();
        $this->codeSlicer = $codeSlicer ?? new NullCodeSlicer();
        $this->attackerContextPromptRenderer = $attackerContextPromptRenderer ?? new AttackerContextPromptRenderer();
        $this->progressReporter = $progressReporter ?? new NullProgressReporter();
    }

    /**
     * @return list<Vulnerability>
     */
    public function analyze(AttackerAnalysisRequest $attackerAnalysisRequest, CoverageRecorderInterface $coverageRecorder): array
    {
        $files = $attackerAnalysisRequest->files;

        if ([] === $files) {
            return [];
        }

        $useTools = $this->toolsEnabled && $this->toolRegistryFactory instanceof ToolRegistryFactoryInterface;

        $markers = $this->staticPreScanner->scan($files);
        $riskMarkerIndex = new RiskMarkerIndex($markers);
        $effectiveFiles = $this->leanMode ? $riskMarkerIndex->filesWithMarkers($files) : $files;

        if ([] === $effectiveFiles) {
            $this->logger->info('Attacker agent skipped — lean mode filtered all files', [
                'files' => \count($files),
                'markers' => 0,
            ]);
            $this->recordChunkCoverage($files, 'skipped', $coverageRecorder);

            return [];
        }

        $this->logger->info('Attacker agent starting analysis', [
            'files' => \count($effectiveFiles),
            'files_filtered_lean' => \count($files) - \count($effectiveFiles),
            'markers' => \count($markers),
            'tools_enabled' => $useTools,
            'cache_bypassed' => $attackerAnalysisRequest->bypassCache,
            'previous_findings' => \count($attackerAnalysisRequest->previousFindings),
            'rejected_findings' => \count($attackerAnalysisRequest->rejectedFindings),
        ]);

        $toolRegistry = $useTools ? $this->toolRegistryFactory->forProjectFiles($effectiveFiles) : null;

        $chunks = $this->chunkFiles($effectiveFiles);

        $useConcurrent = $this->maxConcurrent > 1
            && $this->useStructuredCollection
            && $this->recordVulnerabilityToolFactory instanceof RecordVulnerabilityToolFactoryInterface
            && $this->llmClient instanceof ToolBatchCapableLLMClientInterface;

        [$allVulnerabilities, $totalDropsByReason] = $useConcurrent
            ? $this->analyzeChunksConcurrently($chunks, $attackerAnalysisRequest, $coverageRecorder, $riskMarkerIndex)
            : $this->analyzeChunksSequentially($chunks, $attackerAnalysisRequest, $coverageRecorder, $toolRegistry, $riskMarkerIndex);

        $this->logger->info('Attacker agent complete', [
            'total_vulnerabilities' => \count($allVulnerabilities),
            'total_dropped_entries' => array_sum($totalDropsByReason),
            'dropped_by_reason' => $totalDropsByReason,
        ]);

        return $allVulnerabilities;
    }

    /**
     * @param list<list<ProjectFile>> $chunks
     *
     * @return array{0: list<Vulnerability>, 1: array<string, int>}
     */
    private function analyzeChunksSequentially(array $chunks, AttackerAnalysisRequest $attackerAnalysisRequest, CoverageRecorderInterface $coverageRecorder, ?ToolRegistry $toolRegistry, RiskMarkerIndex $riskMarkerIndex): array
    {
        $allVulnerabilities = [];
        $totalDropsByReason = [];

        foreach ($chunks as $index => $chunk) {
            $this->logger->debug(\sprintf('Analyzing chunk %d/%d', $index + 1, \count($chunks)));
            $this->progressReporter->report(ProgressEvent::AttackerChunkStarted->value, [
                'chunk' => $index + 1,
                'total_chunks' => \count($chunks),
            ]);

            $chunkResult = $this->analyzeChunk($chunk, $attackerAnalysisRequest, $coverageRecorder, $toolRegistry, $riskMarkerIndex);
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
     * Resolves every cache-miss chunk's structured `record_vulnerability`
     * conversation concurrently (one registry + collector per chunk) via the
     * tool-batch-capable client, while cache hits short-circuit exactly as in
     * the sequential path. Chunk order, coverage, caching, and drop accounting
     * match {@see analyzeChunksSequentially()}; only the LLM round trips
     * overlap on the wire.
     *
     * @param list<list<ProjectFile>> $chunks
     *
     * @return array{0: list<Vulnerability>, 1: array<string, int>}
     */
    private function analyzeChunksConcurrently(array $chunks, AttackerAnalysisRequest $attackerAnalysisRequest, CoverageRecorderInterface $coverageRecorder, RiskMarkerIndex $riskMarkerIndex): array
    {
        \assert($this->recordVulnerabilityToolFactory instanceof RecordVulnerabilityToolFactoryInterface);
        \assert($this->llmClient instanceof ToolBatchCapableLLMClientInterface);

        $totalChunks = \count($chunks);

        /** @var array<int, VulnerabilityHydrationResult> $cachedResults */
        $cachedResults = [];
        /** @var array<int, array{chunk: list<ProjectFile>, contextKey: string, cacheable: bool, collector: VulnerabilityCollector}> $pending */
        $pending = [];
        $requests = [];
        foreach ($chunks as $index => $chunk) {
            $this->progressReporter->report(ProgressEvent::AttackerChunkStarted->value, [
                'chunk' => $index + 1,
                'total_chunks' => $totalChunks,
            ]);

            $context = $this->computeChunkContext($chunk, $attackerAnalysisRequest, $riskMarkerIndex);

            if ($context['cacheable']) {
                $cached = $this->cacheGet($chunk, $context['contextKey']);
                if (null !== $cached) {
                    $cachedResults[$index] = $this->servedFromCache($chunk, $cached, $coverageRecorder);

                    continue;
                }
            }

            $collector = new VulnerabilityCollector();
            $toolRegistry = new ToolRegistry([$this->recordVulnerabilityToolFactory->create($collector)], $this->logger);
            $pending[$index] = [
                'chunk' => $chunk,
                'contextKey' => $context['contextKey'],
                'cacheable' => $context['cacheable'],
                'collector' => $collector,
            ];
            $requests[] = ['system' => $context['systemPrompt'], 'user' => $context['userMessage'], 'tools' => $toolRegistry];
        }

        if ([] !== $requests) {
            $this->dispatchConcurrentChunks($requests, $pending, $coverageRecorder);
        }

        $allVulnerabilities = [];
        $totalDropsByReason = [];
        foreach (array_keys($chunks) as $index) {
            $chunkResult = $cachedResults[$index] ?? $this->finalizeConcurrentChunk($pending[$index], $coverageRecorder);
            $allVulnerabilities = [...$allVulnerabilities, ...$chunkResult->vulnerabilities()];
            foreach ($chunkResult->dropsByReason() as $reason => $count) {
                $totalDropsByReason[$reason] = ($totalDropsByReason[$reason] ?? 0) + $count;
            }
        }

        return [$allVulnerabilities, $totalDropsByReason];
    }

    /**
     * @param list<array{system: string, user: string, tools: ToolRegistry}>                                                      $requests
     * @param array<int, array{chunk: list<ProjectFile>, contextKey: string, cacheable: bool, collector: VulnerabilityCollector}> $pending
     */
    private function dispatchConcurrentChunks(array $requests, array $pending, CoverageRecorderInterface $coverageRecorder): void
    {
        \assert($this->llmClient instanceof ToolBatchCapableLLMClientInterface);

        try {
            $this->llmClient->completeBatchWithTools($requests, $this->maxConcurrent, $this->maxToolIterations);
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
            $this->recordChunkCoverage($entry['chunk'], $status, $coverageRecorder);
        }
    }

    /**
     * @param list<ProjectFile>                $chunk
     * @param array<int, array<string, mixed>> $cached
     */
    private function servedFromCache(array $chunk, array $cached, CoverageRecorderInterface $coverageRecorder): VulnerabilityHydrationResult
    {
        $this->logger->info('Attacker chunk served from cache', ['files' => \count($chunk)]);
        $this->recordChunkCoverage($chunk, 'cached', $coverageRecorder);

        return $this->vulnerabilityFactory->fromList(array_values($cached));
    }

    /**
     * @param array{chunk: list<ProjectFile>, contextKey: string, cacheable: bool, collector: VulnerabilityCollector} $entry
     */
    private function finalizeConcurrentChunk(array $entry, CoverageRecorderInterface $coverageRecorder): VulnerabilityHydrationResult
    {
        $rawData = $entry['collector']->drain();

        if ($entry['cacheable']) {
            $this->cacheStore($entry['chunk'], $entry['contextKey'], $rawData);
        }

        $this->recordChunkCoverage($entry['chunk'], 'analyzed', $coverageRecorder);

        return $this->vulnerabilityFactory->fromList($rawData);
    }

    /**
     * @param list<ProjectFile> $chunk
     */
    private function analyzeChunk(array $chunk, AttackerAnalysisRequest $attackerAnalysisRequest, CoverageRecorderInterface $coverageRecorder, ?ToolRegistry $toolRegistry, RiskMarkerIndex $riskMarkerIndex): VulnerabilityHydrationResult
    {
        $context = $this->computeChunkContext($chunk, $attackerAnalysisRequest, $riskMarkerIndex);
        $contextKey = $context['contextKey'];
        $cacheable = $context['cacheable'];
        $systemPrompt = $context['systemPrompt'];
        $userMessage = $context['userMessage'];

        if ($cacheable) {
            $cached = $this->cacheGet($chunk, $contextKey);

            if (null !== $cached) {
                return $this->servedFromCache($chunk, $cached, $coverageRecorder);
            }
        }

        try {
            if ($this->useStructuredCollection && $this->recordVulnerabilityToolFactory instanceof RecordVulnerabilityToolFactoryInterface) {
                return $this->analyzeChunkViaStructuredCollection($chunk, $systemPrompt, $userMessage, $cacheable, $contextKey, $coverageRecorder);
            }

            $response = $toolRegistry instanceof ToolRegistry
                ? $this->llmClient->completeWithTools($systemPrompt, $userMessage, $toolRegistry, $this->maxToolIterations)
                : $this->llmClient->complete($systemPrompt, $userMessage);

            if ($response->isEmpty()) {
                if ($cacheable) {
                    $this->cacheStore($chunk, $contextKey, []);
                }

                $this->recordChunkCoverage($chunk, 'analyzed', $coverageRecorder);

                return VulnerabilityHydrationResult::empty();
            }

            /** @var list<mixed> $rawData */
            $rawData = $response->parseJson();

            if ($cacheable) {
                /** @var list<array<string, mixed>> $cacheablePayload */
                $cacheablePayload = array_values(array_filter($rawData, 'is_array'));
                $this->cacheStore($chunk, $contextKey, $cacheablePayload);
            }

            $this->recordChunkCoverage($chunk, 'analyzed', $coverageRecorder);

            return $this->vulnerabilityFactory->fromList($rawData);
        } catch (BudgetExceededException $budgetExceededException) {
            // Budget exhaustion is a deliberate abort, not an LLM failure;
            // let it bubble up so RunAuditUseCase can wrap it with a partial report.
            $this->recordChunkCoverage($chunk, 'aborted', $coverageRecorder);

            throw $budgetExceededException;
        } catch (LLMProviderException $llmProviderException) {
            $this->recordChunkCoverage($chunk, 'errored', $coverageRecorder);

            throw $llmProviderException;
        } catch (JsonException $exception) {
            $this->logger->error('Failed to parse attacker agent JSON response', [
                'error' => $exception->getMessage(),
                'content_preview' => substr($response->content(), 0, self::PARSE_FAILURE_PREVIEW_BYTES),
            ]);
            $this->recordChunkCoverage($chunk, 'errored', $coverageRecorder);

            return VulnerabilityHydrationResult::empty();
        } catch (Throwable $exception) {
            $this->logger->error('Attacker agent LLM call failed', [
                'error' => $exception->getMessage(),
            ]);
            $this->recordChunkCoverage($chunk, 'errored', $coverageRecorder);

            return VulnerabilityHydrationResult::empty();
        }
    }

    /**
     * Assembles the per-chunk system/user prompts (markers + cross-iteration
     * preambles) and derives the cache key and cacheability, shared by the
     * sequential and concurrent paths.
     *
     * @param list<ProjectFile> $chunk
     *
     * @return array{systemPrompt: string, userMessage: string, contextKey: string, cacheable: bool}
     */
    private function computeChunkContext(array $chunk, AttackerAnalysisRequest $attackerAnalysisRequest, RiskMarkerIndex $riskMarkerIndex): array
    {
        $chunkMarkers = $riskMarkerIndex->forChunk($chunk);
        $hasMarkers = [] !== $chunkMarkers;

        $rejectedPreamble = [] !== $attackerAnalysisRequest->rejectedFindings
            ? $this->attackerContextPromptRenderer->renderRejectedFindings($attackerAnalysisRequest->rejectedFindings)
            : '';
        $previousPreamble = [] !== $attackerAnalysisRequest->previousFindings
            ? $this->attackerContextPromptRenderer->renderPreviousFindings($attackerAnalysisRequest->previousFindings)
            : '';
        $contextKey = '' === $rejectedPreamble && '' === $previousPreamble
            ? ''
            : hash('sha256', $rejectedPreamble."\0".$previousPreamble);
        $cacheable = !$attackerAnalysisRequest->bypassCache
            && ('' === $contextKey || $this->attackerCache instanceof ContextAwareAttackerCacheInterface);

        $slicedChunk = $this->sliceChunk($chunk);
        $systemPrompt = $this->attackerPromptBuilder->buildSystemPrompt($slicedChunk);
        $userMessage = $this->attackerPromptBuilder->buildUserMessage($slicedChunk, $attackerAnalysisRequest->symfonyMapping);

        if ($hasMarkers) {
            $userMessage = $this->attackerContextPromptRenderer->renderRiskMarkers($chunkMarkers)."\n\n".$userMessage;
        }

        if ('' !== $rejectedPreamble) {
            $userMessage = $rejectedPreamble."\n\n".$userMessage;
        }

        if ('' !== $previousPreamble) {
            $userMessage = $previousPreamble."\n\n".$userMessage;
        }

        return [
            'systemPrompt' => $systemPrompt,
            'userMessage' => $userMessage,
            'contextKey' => $contextKey,
            'cacheable' => $cacheable,
        ];
    }

    /**
     * @param list<ProjectFile> $chunk
     */
    private function analyzeChunkViaStructuredCollection(
        array $chunk,
        string $systemPrompt,
        string $userMessage,
        bool $cacheable,
        string $contextKey,
        CoverageRecorderInterface $coverageRecorder,
    ): VulnerabilityHydrationResult {
        \assert($this->recordVulnerabilityToolFactory instanceof RecordVulnerabilityToolFactoryInterface);

        $vulnerabilityCollector = new VulnerabilityCollector();
        $recordTool = $this->recordVulnerabilityToolFactory->create($vulnerabilityCollector);
        $toolRegistry = new ToolRegistry([$recordTool], $this->logger);

        $this->llmClient->completeWithTools($systemPrompt, $userMessage, $toolRegistry, $this->maxToolIterations);

        $rawData = $vulnerabilityCollector->drain();

        if ($cacheable) {
            $this->cacheStore($chunk, $contextKey, $rawData);
        }

        $this->recordChunkCoverage($chunk, 'analyzed', $coverageRecorder);

        return $this->vulnerabilityFactory->fromList($rawData);
    }

    /**
     * @param list<ProjectFile> $chunk
     *
     * @return array<int, array<string, mixed>>|null
     */
    private function cacheGet(array $chunk, string $contextKey): ?array
    {
        return $this->attackerCache instanceof ContextAwareAttackerCacheInterface
            ? $this->attackerCache->getForContext($chunk, $contextKey)
            : $this->attackerCache->get($chunk);
    }

    /**
     * @param list<ProjectFile>          $chunk
     * @param list<array<string, mixed>> $rawVulnerabilities
     */
    private function cacheStore(array $chunk, string $contextKey, array $rawVulnerabilities): void
    {
        if ($this->attackerCache instanceof ContextAwareAttackerCacheInterface) {
            $this->attackerCache->storeForContext($chunk, $contextKey, $rawVulnerabilities);

            return;
        }

        $this->attackerCache->store($chunk, $rawVulnerabilities);
    }

    /**
     * @param list<ProjectFile> $chunk
     */
    private function recordChunkCoverage(array $chunk, string $status, CoverageRecorderInterface $coverageRecorder): void
    {
        foreach ($chunk as $file) {
            $coverageRecorder->recordCoverage(AgentRole::Attacker->value, $file->relativePath(), $status);
        }
    }

    /**
     * @param list<ProjectFile> $files
     *
     * @return list<list<ProjectFile>>
     */
    private function chunkFiles(array $files): array
    {
        return $this->fileChunker->chunk($files);
    }

    /**
     * Replaces each file in the chunk with a version whose content is sliced
     * down to security-relevant lines. The slicer preserves the original line
     * count by replacing elided lines with a `// elided` placeholder, so the
     * line-numbering protocol in the prompt remains accurate against the
     * original source.
     *
     * @param list<ProjectFile> $chunk
     *
     * @return list<ProjectFile>
     */
    private function sliceChunk(array $chunk): array
    {
        $sliced = [];
        foreach ($chunk as $file) {
            $newContent = $this->codeSlicer->slice($file);

            if ($newContent === $file->content()) {
                $sliced[] = $file;

                continue;
            }

            $sliced[] = ProjectFile::create(
                relativePath: $file->relativePath(),
                absolutePath: $file->absolutePath(),
                content: $newContent,
            );
        }

        return $sliced;
    }
}
