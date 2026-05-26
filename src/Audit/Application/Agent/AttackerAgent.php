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
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\RiskMarker;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\SymfonyMapping;
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
    ) {
        $this->staticPreScanner = $staticPreScanner ?? new NullStaticPreScanner();
        $this->fileChunker = $fileChunker ?? new FileChunker();
        $this->codeSlicer = $codeSlicer ?? new NullCodeSlicer();
    }

    /**
     * @param list<ProjectFile>   $files
     * @param list<Vulnerability> $previousFindings
     *
     * @return list<Vulnerability>
     */
    public function analyze(array $files, SymfonyMapping $symfonyMapping, CoverageRecorderInterface $coverageRecorder, bool $bypassCache = false, array $previousFindings = []): array
    {
        if ([] === $files) {
            return [];
        }

        $useTools = $this->toolsEnabled && $this->toolRegistryFactory instanceof ToolRegistryFactoryInterface;

        $markers = $this->staticPreScanner->scan($files);
        $markersByFile = $this->groupMarkersByFile($markers);
        $effectiveFiles = $this->leanMode ? $this->filterFilesWithMarkers($files, $markersByFile) : $files;

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
            'cache_bypassed' => $bypassCache,
            'previous_findings' => \count($previousFindings),
        ]);

        $toolRegistry = $useTools ? $this->toolRegistryFactory->forProjectFiles($effectiveFiles) : null;

        $chunks = $this->chunkFiles($effectiveFiles);
        $allVulnerabilities = [];

        foreach ($chunks as $index => $chunk) {
            $this->logger->debug(\sprintf('Analyzing chunk %d/%d', $index + 1, \count($chunks)));

            $vulnerabilities = $this->analyzeChunk($chunk, $symfonyMapping, $coverageRecorder, $toolRegistry, $bypassCache, $previousFindings, $markersByFile);
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
     * @param list<ProjectFile>                $chunk
     * @param list<Vulnerability>              $previousFindings
     * @param array<string, list<RiskMarker>>  $markersByFile keyed by file relative path
     *
     * @return list<Vulnerability>
     */
    private function analyzeChunk(array $chunk, SymfonyMapping $symfonyMapping, CoverageRecorderInterface $coverageRecorder, ?ToolRegistry $toolRegistry, bool $bypassCache, array $previousFindings, array $markersByFile): array
    {
        $hasPreviousFindings = [] !== $previousFindings;
        $chunkMarkers = $this->markersForChunk($chunk, $markersByFile);
        $hasMarkers = [] !== $chunkMarkers;
        $cacheable = !$bypassCache && !$hasPreviousFindings;

        if ($cacheable) {
            $cached = $this->attackerCache->get($chunk);

            if (null !== $cached) {
                $this->logger->info('Attacker chunk served from cache', ['files' => \count($chunk)]);
                $this->recordChunkCoverage($chunk, 'cached', $coverageRecorder);

                return $this->vulnerabilityFactory->fromList(array_values($cached));
            }
        }

        $slicedChunk = $this->sliceChunk($chunk);
        $systemPrompt = $this->attackerPromptBuilder->buildSystemPrompt($slicedChunk);
        $userMessage = $this->attackerPromptBuilder->buildUserMessage($slicedChunk, $symfonyMapping);

        if ($hasMarkers) {
            $userMessage = $this->renderRiskMarkers($chunkMarkers)."\n\n".$userMessage;
        }

        if ($hasPreviousFindings) {
            $userMessage = $this->renderPreviousFindings($previousFindings)."\n\n".$userMessage;
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
     * @param list<Vulnerability> $previousFindings
     */
    private function renderPreviousFindings(array $previousFindings): string
    {
        $byType = [];
        foreach ($previousFindings as $vulnerability) {
            $byType[$vulnerability->type()->value][] = \sprintf(
                '%s:%d-%d',
                $vulnerability->filePath(),
                $vulnerability->lineStart(),
                $vulnerability->lineEnd(),
            );
        }

        $lines = [];
        foreach ($byType as $type => $locations) {
            $lines[] = \sprintf('- %s: %s', $type, implode(', ', $locations));
        }

        return <<<PROMPT
            ## Patterns Already Confirmed in Earlier Iterations
            The reviewer has already validated the findings below. Look for the SAME PATTERNS in files not yet covered by these locations. Do NOT re-report the same vulnerability at the same line range — those entries will be filtered as duplicates.

            {$this->indent(implode("\n", $lines))}

            Generalize: if `insecure_direct_object_reference` was confirmed in one controller, hunt for the same idiom in every other controller in this chunk. If `sql_injection` was confirmed in one repository, look for unsafe DQL/SQL concatenation in every other repository.
            PROMPT;
    }

    private function indent(string $content): string
    {
        return implode("\n", array_map(static fn (string $line): string => '  '.$line, explode("\n", $content)));
    }

    /**
     * @param list<RiskMarker> $markers
     *
     * @return array<string, list<RiskMarker>>
     */
    private function groupMarkersByFile(array $markers): array
    {
        $byFile = [];

        foreach ($markers as $marker) {
            $byFile[$marker->filePath()][] = $marker;
        }

        return $byFile;
    }

    /**
     * @param list<ProjectFile>               $chunk
     * @param array<string, list<RiskMarker>> $markersByFile
     *
     * @return list<RiskMarker>
     */
    private function markersForChunk(array $chunk, array $markersByFile): array
    {
        $chunkMarkers = [];

        foreach ($chunk as $file) {
            foreach ($markersByFile[$file->relativePath()] ?? [] as $marker) {
                $chunkMarkers[] = $marker;
            }
        }

        return $chunkMarkers;
    }

    /**
     * @param list<ProjectFile>               $files
     * @param array<string, list<RiskMarker>> $markersByFile
     *
     * @return list<ProjectFile>
     */
    private function filterFilesWithMarkers(array $files, array $markersByFile): array
    {
        return array_values(array_filter(
            $files,
            static fn (ProjectFile $file): bool => isset($markersByFile[$file->relativePath()]),
        ));
    }

    /**
     * @param list<RiskMarker> $markers
     */
    private function renderRiskMarkers(array $markers): string
    {
        $byFile = [];
        foreach ($markers as $marker) {
            $byFile[$marker->filePath()][] = \sprintf(
                'L%d %s — %s',
                $marker->line(),
                $marker->pattern(),
                $marker->description(),
            );
        }

        $blocks = [];
        foreach ($byFile as $filePath => $lines) {
            $blocks[] = \sprintf("%s:\n%s", $filePath, $this->indent(implode("\n", $lines)));
        }

        return <<<PROMPT
            ## Pre-Scan Risk Markers (Deterministic Hints)
            A static pre-scanner flagged the locations below in the chunk. They are NOT confirmed vulnerabilities — only patterns worth investigating. Use them to focus your analysis; ignore markers that the surrounding context proves safe.

            {$this->indent(implode("\n", $blocks))}
            PROMPT;
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
