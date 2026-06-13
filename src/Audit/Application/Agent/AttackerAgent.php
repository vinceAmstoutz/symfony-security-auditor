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
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\Vulnerability;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Pipeline\CoverageRecorderInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\AttackerCacheInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\AttackerPromptBuilderInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\CodeSlicerInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\LLMClientInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\ProgressReporterInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\StaticPreScannerInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\Tool\ToolRegistryFactoryInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\ToolBatchCapableLLMClientInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Progress\NullProgressReporter;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Scan\NullCodeSlicer;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Scan\NullStaticPreScanner;

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

    public function __construct(
        LLMClientInterface $llmClient,
        AttackerPromptBuilderInterface $attackerPromptBuilder,
        VulnerabilityFactory $vulnerabilityFactory,
        AttackerCacheInterface $attackerCache,
        private LoggerInterface $logger,
        private ?ToolRegistryFactoryInterface $toolRegistryFactory = null,
        private bool $toolsEnabled = self::DEFAULT_TOOLS_ENABLED,
        int $maxToolIterations = self::DEFAULT_MAX_TOOL_ITERATIONS,
        ?StaticPreScannerInterface $staticPreScanner = null,
        private bool $leanMode = self::DEFAULT_LEAN_MODE,
        ?FileChunker $fileChunker = null,
        ?CodeSlicerInterface $codeSlicer = null,
        ?RecordVulnerabilityToolFactoryInterface $recordVulnerabilityToolFactory = null,
        private bool $useStructuredCollection = self::DEFAULT_STRUCTURED_COLLECTION,
        ?ProgressReporterInterface $progressReporter = null,
        private int $maxConcurrent = self::DEFAULT_MAX_CONCURRENT,
    ) {
        $this->staticPreScanner = $staticPreScanner ?? new NullStaticPreScanner();
        $this->fileChunker = $fileChunker ?? new FileChunker();
        $this->progressReporter = $progressReporter ?? new NullProgressReporter();

        $chunkContextFactory = new ChunkContextFactory(
            $attackerPromptBuilder,
            $codeSlicer ?? new NullCodeSlicer(),
            new AttackerContextPromptRenderer(),
        );
        $attackerChunkCache = new AttackerChunkCache($attackerCache, $vulnerabilityFactory, $logger);

        $this->sequentialChunkAnalyzer = new SequentialChunkAnalyzer(
            $llmClient,
            $chunkContextFactory,
            $attackerChunkCache,
            $vulnerabilityFactory,
            $logger,
            $this->progressReporter,
            $maxToolIterations,
            $this->useStructuredCollection,
            $recordVulnerabilityToolFactory,
        );

        $this->concurrentChunkAnalyzer = $llmClient instanceof ToolBatchCapableLLMClientInterface && $recordVulnerabilityToolFactory instanceof RecordVulnerabilityToolFactoryInterface
            ? new ConcurrentChunkAnalyzer(
                $llmClient,
                $chunkContextFactory,
                $attackerChunkCache,
                $vulnerabilityFactory,
                $logger,
                $this->progressReporter,
                $maxToolIterations,
                $recordVulnerabilityToolFactory,
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
            $this->logger->info('Attacker agent skipped — lean mode filtered all files', [
                'files' => \count($files),
                'markers' => 0,
            ]);
            ChunkCoverageRecorder::record($files, 'skipped', $coverageRecorder);

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

        $chunks = $this->fileChunker->chunk($effectiveFiles);

        $useConcurrent = $this->maxConcurrent > 1
            && $this->useStructuredCollection
            && $this->concurrentChunkAnalyzer instanceof ConcurrentChunkAnalyzer;

        [$allVulnerabilities, $totalDropsByReason] = $useConcurrent
            ? $this->concurrentChunkAnalyzer->analyze($chunks, $attackerAnalysisRequest, $coverageRecorder, $riskMarkerIndex)
            : $this->sequentialChunkAnalyzer->analyze($chunks, $attackerAnalysisRequest, $coverageRecorder, $toolRegistry, $riskMarkerIndex);

        $this->logger->info('Attacker agent complete', [
            'total_vulnerabilities' => \count($allVulnerabilities),
            'total_dropped_entries' => array_sum($totalDropsByReason),
            'dropped_by_reason' => $totalDropsByReason,
        ]);

        return $allVulnerabilities;
    }
}
