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
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFile;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\Vulnerability;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Pipeline\CoverageRecorderInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\AttackerCacheInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\AttackerPromptBuilderInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\CodeSlicerInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\LLMClientInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\StaticPreScannerInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\Tool\ToolRegistry;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\Tool\ToolRegistryFactoryInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Scan\NullCodeSlicer;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Scan\NullStaticPreScanner;

/** @internal not part of the BC promise — see docs/versioning.md */
final readonly class AttackerAgent implements AttackerAgentInterface
{
    private const int PARSE_FAILURE_PREVIEW_BYTES = 512;

    public const int DEFAULT_MAX_TOOL_ITERATIONS = 8;

    public const bool DEFAULT_TOOLS_ENABLED = false;

    public const bool DEFAULT_LEAN_MODE = false;

    private StaticPreScannerInterface $staticPreScanner;

    private FileChunker $fileChunker;

    private CodeSlicerInterface $codeSlicer;

    private AttackerContextPromptRenderer $attackerContextPromptRenderer;

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
    ) {
        $this->staticPreScanner = $staticPreScanner ?? new NullStaticPreScanner();
        $this->fileChunker = $fileChunker ?? new FileChunker();
        $this->codeSlicer = $codeSlicer ?? new NullCodeSlicer();
        $this->attackerContextPromptRenderer = $attackerContextPromptRenderer ?? new AttackerContextPromptRenderer();
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
        ]);

        $toolRegistry = $useTools ? $this->toolRegistryFactory->forProjectFiles($effectiveFiles) : null;

        $chunks = $this->chunkFiles($effectiveFiles);
        $allVulnerabilities = [];

        foreach ($chunks as $index => $chunk) {
            $this->logger->debug(\sprintf('Analyzing chunk %d/%d', $index + 1, \count($chunks)));

            $vulnerabilities = $this->analyzeChunk($chunk, $attackerAnalysisRequest, $coverageRecorder, $toolRegistry, $riskMarkerIndex);
            $allVulnerabilities = [...$allVulnerabilities, ...$vulnerabilities];

            $this->logger->debug('Chunk analysis complete', [
                'chunk' => $index + 1,
                'found' => \count($vulnerabilities),
                'total_so_far' => \count($allVulnerabilities),
            ]);
        }

        $this->logger->info('Attacker agent complete', [
            'total_vulnerabilities' => \count($allVulnerabilities),
        ]);

        return $allVulnerabilities;
    }

    /**
     * @param list<ProjectFile> $chunk
     *
     * @return list<Vulnerability>
     */
    private function analyzeChunk(array $chunk, AttackerAnalysisRequest $attackerAnalysisRequest, CoverageRecorderInterface $coverageRecorder, ?ToolRegistry $toolRegistry, RiskMarkerIndex $riskMarkerIndex): array
    {
        $hasPreviousFindings = [] !== $attackerAnalysisRequest->previousFindings;
        $chunkMarkers = $riskMarkerIndex->forChunk($chunk);
        $hasMarkers = [] !== $chunkMarkers;
        $cacheable = !$attackerAnalysisRequest->bypassCache && !$hasPreviousFindings;

        if ($cacheable) {
            $cached = $this->attackerCache->get($chunk);

            if (null !== $cached) {
                $this->logger->info('Attacker chunk served from cache', ['files' => \count($chunk)]);
                $this->recordChunkCoverage($chunk, 'cached', $coverageRecorder);

                return $this->vulnerabilityFactory->fromList(array_values($cached))->vulnerabilities();
            }
        }

        $slicedChunk = $this->sliceChunk($chunk);
        $systemPrompt = $this->attackerPromptBuilder->buildSystemPrompt($slicedChunk);
        $userMessage = $this->attackerPromptBuilder->buildUserMessage($slicedChunk, $attackerAnalysisRequest->symfonyMapping);

        if ($hasMarkers) {
            $userMessage = $this->attackerContextPromptRenderer->renderRiskMarkers($chunkMarkers)."\n\n".$userMessage;
        }

        if ($hasPreviousFindings) {
            $userMessage = $this->attackerContextPromptRenderer->renderPreviousFindings($attackerAnalysisRequest->previousFindings)."\n\n".$userMessage;
        }

        try {
            $response = $toolRegistry instanceof ToolRegistry
                ? $this->llmClient->completeWithTools($systemPrompt, $userMessage, $toolRegistry, $this->maxToolIterations)
                : $this->llmClient->complete($systemPrompt, $userMessage);

            if ($response->isEmpty()) {
                if ($cacheable) {
                    $this->attackerCache->store($chunk, []);
                }

                $this->recordChunkCoverage($chunk, 'analyzed', $coverageRecorder);

                return [];
            }

            /** @var list<mixed> $rawData */
            $rawData = $response->parseJson();

            if ($cacheable) {
                /** @var list<array<string, mixed>> $cacheablePayload */
                $cacheablePayload = array_values(array_filter($rawData, 'is_array'));
                $this->attackerCache->store($chunk, $cacheablePayload);
            }

            $this->recordChunkCoverage($chunk, 'analyzed', $coverageRecorder);

            return $this->vulnerabilityFactory->fromList($rawData)->vulnerabilities();
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

            return [];
        } catch (Throwable $exception) {
            $this->logger->error('Attacker agent LLM call failed', [
                'error' => $exception->getMessage(),
            ]);
            $this->recordChunkCoverage($chunk, 'errored', $coverageRecorder);

            return [];
        }
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
