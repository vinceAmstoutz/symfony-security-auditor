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

use Psr\Log\LoggerInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\Chunk\AttackerChunkCache;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\Chunk\ChunkContextFactory;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\Chunk\ChunkCoverageRecorder;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\Chunk\ConcurrentChunkAnalyzer;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\Chunk\SequentialChunkAnalyzer;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\Chunking\FileChunker;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFile;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\RiskMarker;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\Vulnerability;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Pipeline\CoverageRecorderInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\ProgressReporterInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\StaticPreScannerInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\Tool\ToolRegistryFactoryInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\ToolBatchCapableLLMClientInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\NullProgressReporter;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\NullCodeSlicer;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\NullStaticPreScanner;

/**
 * Orchestrates the attacker pass: deterministic pre-scan, optional lean-mode
 * filtering, feature/type chunking, then delegation to a per-chunk analyzer.
 * The per-chunk prompt assembly, caching, and the sequential/concurrent
 * analysis strategies live in dedicated `Chunk\` collaborators built here.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class AttackerAgent implements AttackerAgentInterface
{
    public const int DEFAULT_MAX_TOOL_ITERATIONS = 8;

    public const bool DEFAULT_TOOLS_ENABLED = false;

    public const bool DEFAULT_LEAN_MODE = false;

    public const bool DEFAULT_STRUCTURED_COLLECTION = true;

    public const int DEFAULT_MAX_CONCURRENT = 1;

    private StaticPreScannerInterface $staticPreScanner;

    private FileChunker $fileChunker;

    private ProgressReporterInterface $progressReporter;

    private SequentialChunkAnalyzer $sequentialChunkAnalyzer;

    private ?ConcurrentChunkAnalyzer $concurrentChunkAnalyzer;

    private LoggerInterface $logger;

    private ?ToolRegistryFactoryInterface $toolRegistryFactory;

    private bool $toolsEnabled;

    private bool $leanMode;

    private bool $useStructuredCollection;

    private int $maxConcurrent;

    public function __construct(
        AttackerLlmCollaborators $llm,
        AttackerScanCollaborators $scan,
        AttackerAnalysisSettings $settings,
        LoggerInterface $logger,
    ) {
        $this->logger = $logger;
        $this->toolRegistryFactory = $scan->toolRegistryFactory;
        $this->toolsEnabled = $settings->toolsEnabled;
        $this->leanMode = $settings->leanMode;
        $this->useStructuredCollection = $settings->useStructuredCollection;
        $this->maxConcurrent = $settings->maxConcurrent;
        $this->staticPreScanner = $scan->staticPreScanner ?? new NullStaticPreScanner();
        $this->fileChunker = $scan->fileChunker ?? new FileChunker();
        $this->progressReporter = $scan->progressReporter ?? new NullProgressReporter();

        $chunkContextFactory = new ChunkContextFactory(
            $llm->attackerPromptBuilder,
            $llm->codeSlicer ?? new NullCodeSlicer(),
            new AttackerContextPromptRenderer(),
        );
        $attackerChunkCache = new AttackerChunkCache($scan->attackerCache, $llm->vulnerabilityFactory, $logger);

        $this->sequentialChunkAnalyzer = new SequentialChunkAnalyzer(
            $llm->llmClient,
            $chunkContextFactory,
            $attackerChunkCache,
            $llm->vulnerabilityFactory,
            $logger,
            $this->progressReporter,
            $settings->maxToolIterations,
            $this->useStructuredCollection,
            $llm->recordVulnerabilityToolFactory,
        );

        $this->concurrentChunkAnalyzer = $llm->llmClient instanceof ToolBatchCapableLLMClientInterface && $llm->recordVulnerabilityToolFactory instanceof RecordVulnerabilityToolFactoryInterface
            ? new ConcurrentChunkAnalyzer(
                $llm->llmClient,
                $chunkContextFactory,
                $attackerChunkCache,
                $llm->vulnerabilityFactory,
                $logger,
                $this->progressReporter,
                $settings->maxToolIterations,
                $llm->recordVulnerabilityToolFactory,
                $this->maxConcurrent,
            )
            : null;
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
            return $this->skipLeanFilteredAnalysis($files, $coverageRecorder);
        }

        $this->logStartingAnalysis($files, $effectiveFiles, $markers, $useTools, $attackerAnalysisRequest);

        $toolRegistry = $useTools ? $this->toolRegistryFactory->forProjectFiles($effectiveFiles) : null;

        $chunks = $this->fileChunker->chunk($effectiveFiles);

        $concurrentChunkAnalyzer = $this->concurrentChunkAnalyzerForConcurrentAnalysis();

        [$allVulnerabilities, $totalDropsByReason] = $concurrentChunkAnalyzer instanceof ConcurrentChunkAnalyzer
            ? $concurrentChunkAnalyzer->analyze($chunks, $attackerAnalysisRequest, $coverageRecorder, $riskMarkerIndex)
            : $this->sequentialChunkAnalyzer->analyze($chunks, $attackerAnalysisRequest, $coverageRecorder, $toolRegistry, $riskMarkerIndex);

        $this->logger->info('Attacker agent complete', [
            'total_vulnerabilities' => \count($allVulnerabilities),
            'total_dropped_entries' => array_sum($totalDropsByReason),
            'dropped_by_reason' => $totalDropsByReason,
        ]);

        return $allVulnerabilities;
    }

    /**
     * @param list<ProjectFile> $files
     *
     * @return list<Vulnerability>
     */
    private function skipLeanFilteredAnalysis(array $files, CoverageRecorderInterface $coverageRecorder): array
    {
        $this->logger->info('Attacker agent skipped — lean mode filtered all files', [
            'files' => \count($files),
            'markers' => 0,
        ]);
        ChunkCoverageRecorder::record($files, 'skipped', $coverageRecorder);

        return [];
    }

    /**
     * @param list<ProjectFile> $files
     * @param list<ProjectFile> $effectiveFiles
     * @param list<RiskMarker>  $markers
     */
    private function logStartingAnalysis(
        array $files,
        array $effectiveFiles,
        array $markers,
        bool $useTools,
        AttackerAnalysisRequest $attackerAnalysisRequest,
    ): void {
        $this->logger->info('Attacker agent starting analysis', [
            'files' => \count($effectiveFiles),
            'files_filtered_lean' => \count($files) - \count($effectiveFiles),
            'markers' => \count($markers),
            'tools_enabled' => $useTools,
            'cache_bypassed' => $attackerAnalysisRequest->bypassCache,
            'previous_findings' => \count($attackerAnalysisRequest->previousFindings),
            'rejected_findings' => \count($attackerAnalysisRequest->rejectedFindings),
        ]);
    }

    private function concurrentChunkAnalyzerForConcurrentAnalysis(): ?ConcurrentChunkAnalyzer
    {
        if ($this->maxConcurrent <= 1) {
            return null;
        }

        if (!$this->useStructuredCollection) {
            return null;
        }

        return $this->concurrentChunkAnalyzer;
    }
}
