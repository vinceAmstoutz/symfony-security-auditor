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

use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\AttackerAnalysisRequest;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\AttackerContextPromptRenderer;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\EchoedFilePath;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\RiskMarkerIndex;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFile;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\RiskMarker;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\Vulnerability;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\AttackerPromptBuilderInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\CodeSlicerInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\ProfileAwareAttackerPromptBuilderInterface;
use WeakMap;

/**
 * Builds the cache key of a chunk and its system and user prompts, with its
 * files sliced to their security-relevant lines.
 *
 * @internal not part of the BC promise, see docs/versioning.md
 */
final readonly class ChunkContextFactory
{
    /**
     * The rejected and previous preambles of each request, shared by all its
     * chunks and released with it.
     *
     * @var WeakMap<AttackerAnalysisRequest, array{string, string}>
     */
    private WeakMap $weakMap;

    public function __construct(
        private AttackerPromptBuilderInterface $attackerPromptBuilder,
        private CodeSlicerInterface $codeSlicer,
        private AttackerContextPromptRenderer $attackerContextPromptRenderer,
        private ChunkContextKeyDeriver $chunkContextKeyDeriver,
        private RiskMarkerLineRestorer $riskMarkerLineRestorer = new RiskMarkerLineRestorer(),
    ) {
        $this->weakMap = new WeakMap();
    }

    /**
     * @param list<ProjectFile> $chunk
     */
    public function create(array $chunk, AttackerAnalysisRequest $attackerAnalysisRequest, RiskMarkerIndex $riskMarkerIndex, bool $cacheIsContextAware): ChunkContext
    {
        $chunkPreambles = $this->preambles($chunk, $attackerAnalysisRequest, $riskMarkerIndex);
        $chunkCacheCoordinates = $this->coordinates($chunkPreambles, $attackerAnalysisRequest, $cacheIsContextAware);

        $slicedChunk = $this->sliceChunk($chunk, $riskMarkerIndex);
        $systemPrompt = $this->attackerPromptBuilder instanceof ProfileAwareAttackerPromptBuilderInterface
            ? $this->attackerPromptBuilder->buildSystemPromptFor($slicedChunk, $attackerAnalysisRequest->symfonyMapping)
            : $this->attackerPromptBuilder->buildSystemPrompt($slicedChunk);
        $userMessage = $this->attackerPromptBuilder->buildUserMessage($slicedChunk, $attackerAnalysisRequest->symfonyMapping);
        $userMessage = $this->prependContext($userMessage, $chunkPreambles);

        return new ChunkContext($systemPrompt, $userMessage, $chunkCacheCoordinates->contextKey, $chunkCacheCoordinates->cacheable, array_sum(array_map(static fn (ProjectFile $projectFile): int => \strlen($projectFile->content()), $slicedChunk)), knownFiles: $attackerAnalysisRequest->knownFilesFor($chunk));
    }

    /**
     * Returns the cache key `create()` would use, without building the prompts.
     *
     * @param list<ProjectFile> $chunk
     */
    public function cacheCoordinates(array $chunk, AttackerAnalysisRequest $attackerAnalysisRequest, RiskMarkerIndex $riskMarkerIndex, bool $cacheIsContextAware): ChunkCacheCoordinates
    {
        return $this->coordinates($this->preambles($chunk, $attackerAnalysisRequest, $riskMarkerIndex), $attackerAnalysisRequest, $cacheIsContextAware);
    }

    /**
     * @param list<ProjectFile> $chunk
     */
    private function preambles(array $chunk, AttackerAnalysisRequest $attackerAnalysisRequest, RiskMarkerIndex $riskMarkerIndex): ChunkPreambles
    {
        [$rejectedPreamble, $previousPreamble] = $this->requestPreambles($attackerAnalysisRequest);

        return new ChunkPreambles(
            $this->renderMarkerPreamble($riskMarkerIndex->forChunk($chunk)),
            $rejectedPreamble,
            $previousPreamble,
            $this->renderCandidatePreamble($chunk, $attackerAnalysisRequest),
        );
    }

    private function coordinates(ChunkPreambles $chunkPreambles, AttackerAnalysisRequest $attackerAnalysisRequest, bool $cacheIsContextAware): ChunkCacheCoordinates
    {
        $contextKey = $this->chunkContextKeyDeriver->derive($chunkPreambles->markers, $chunkPreambles->rejected, $chunkPreambles->previous, $chunkPreambles->candidates, $attackerAnalysisRequest->symfonyMapping);

        return new ChunkCacheCoordinates($contextKey, $this->isCacheable($attackerAnalysisRequest, $contextKey, $cacheIsContextAware));
    }

    /**
     * @param list<RiskMarker> $chunkMarkers
     */
    private function renderMarkerPreamble(array $chunkMarkers): string
    {
        if ([] === $chunkMarkers) {
            return '';
        }

        return $this->attackerContextPromptRenderer->renderRiskMarkers($chunkMarkers);
    }

    /**
     * @return array{string, string} the rejected and previous preambles
     */
    private function requestPreambles(AttackerAnalysisRequest $attackerAnalysisRequest): array
    {
        if (!$this->weakMap->offsetExists($attackerAnalysisRequest)) {
            $this->weakMap[$attackerAnalysisRequest] = [
                $this->renderRejectedPreamble($attackerAnalysisRequest),
                $this->renderPreviousPreamble($attackerAnalysisRequest),
            ];
        }

        return $this->weakMap[$attackerAnalysisRequest];
    }

    private function renderRejectedPreamble(AttackerAnalysisRequest $attackerAnalysisRequest): string
    {
        if ([] === $attackerAnalysisRequest->rejectedFindings) {
            return '';
        }

        return $this->attackerContextPromptRenderer->renderRejectedFindings($attackerAnalysisRequest->rejectedFindings);
    }

    private function renderPreviousPreamble(AttackerAnalysisRequest $attackerAnalysisRequest): string
    {
        if ([] === $attackerAnalysisRequest->previousFindings) {
            return '';
        }

        return $this->attackerContextPromptRenderer->renderPreviousFindings($attackerAnalysisRequest->previousFindings);
    }

    /**
     * Renders only the candidates on the chunk's own files, so its cache key
     * does not change with the candidates elsewhere.
     *
     * @param list<ProjectFile> $chunk
     */
    private function renderCandidatePreamble(array $chunk, AttackerAnalysisRequest $attackerAnalysisRequest): string
    {
        $paths = array_map(static fn (ProjectFile $projectFile): string => EchoedFilePath::normalize($projectFile->relativePath()), $chunk);
        $candidates = array_values(array_filter(
            $attackerAnalysisRequest->candidateFindings,
            static fn (Vulnerability $vulnerability): bool => \in_array(EchoedFilePath::normalize($vulnerability->filePath()), $paths, true),
        ));

        if ([] === $candidates) {
            return '';
        }

        return $this->attackerContextPromptRenderer->renderCandidateFindings($candidates);
    }

    private function isCacheable(AttackerAnalysisRequest $attackerAnalysisRequest, string $contextKey, bool $cacheIsContextAware): bool
    {
        return !$attackerAnalysisRequest->bypassCache && ('' === $contextKey || $cacheIsContextAware);
    }

    private function prependContext(string $userMessage, ChunkPreambles $chunkPreambles): string
    {
        if ('' !== $chunkPreambles->markers) {
            $userMessage = \sprintf("%s\n\n%s", $chunkPreambles->markers, $userMessage);
        }

        if ('' !== $chunkPreambles->candidates) {
            $userMessage = \sprintf("%s\n\n%s", $chunkPreambles->candidates, $userMessage);
        }

        if ('' !== $chunkPreambles->rejected) {
            $userMessage = \sprintf("%s\n\n%s", $chunkPreambles->rejected, $userMessage);
        }

        if ('' !== $chunkPreambles->previous) {
            return \sprintf("%s\n\n%s", $chunkPreambles->previous, $userMessage);
        }

        return $userMessage;
    }

    /**
     * Slices each file to its security-relevant lines, keeping its line count.
     * Restores verbatim every risk-marker line with the rest of the call it
     * leaves open.
     *
     * @param list<ProjectFile> $chunk
     *
     * @return list<ProjectFile>
     */
    private function sliceChunk(array $chunk, RiskMarkerIndex $riskMarkerIndex): array
    {
        $sliced = [];
        foreach ($chunk as $file) {
            $newContent = $this->riskMarkerLineRestorer->restore($file, $this->codeSlicer->slice($file), $riskMarkerIndex->forChunk([$file]));

            if ($newContent === $file->content()) {
                $sliced[] = $file;

                continue;
            }

            $sliced[] = $file->withContent($newContent);
        }

        return $sliced;
    }
}
