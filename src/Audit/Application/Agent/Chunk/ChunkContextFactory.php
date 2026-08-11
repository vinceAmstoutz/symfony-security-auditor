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
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Application\Agent\RiskMarkerIndex;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFile;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\RiskMarker;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\AttackerPromptBuilderInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\CodeSlicerInterface;

/**
 * Assembles the per-chunk system/user prompts (risk markers + cross-iteration
 * preambles), slices each file to its security-relevant lines, and derives
 * cacheability from the cache key {@see ChunkContextKeyDeriver} computes.
 * Shared by the sequential and concurrent chunk analyzers.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class ChunkContextFactory
{
    public function __construct(
        private AttackerPromptBuilderInterface $attackerPromptBuilder,
        private CodeSlicerInterface $codeSlicer,
        private AttackerContextPromptRenderer $attackerContextPromptRenderer,
        private ChunkContextKeyDeriver $chunkContextKeyDeriver,
    ) {}

    /**
     * @param list<ProjectFile> $chunk
     */
    public function create(array $chunk, AttackerAnalysisRequest $attackerAnalysisRequest, RiskMarkerIndex $riskMarkerIndex, bool $cacheIsContextAware): ChunkContext
    {
        $chunkMarkers = $riskMarkerIndex->forChunk($chunk);
        $markerPreamble = $this->renderMarkerPreamble($chunkMarkers);

        $rejectedPreamble = $this->renderRejectedPreamble($attackerAnalysisRequest);
        $previousPreamble = $this->renderPreviousPreamble($attackerAnalysisRequest);
        $contextKey = $this->chunkContextKeyDeriver->derive($markerPreamble, $rejectedPreamble, $previousPreamble, $attackerAnalysisRequest->symfonyMapping);
        $cacheable = $this->isCacheable($attackerAnalysisRequest, $contextKey, $cacheIsContextAware);

        $slicedChunk = $this->sliceChunk($chunk, $riskMarkerIndex);
        $systemPrompt = $this->attackerPromptBuilder->buildSystemPrompt($slicedChunk);
        $userMessage = $this->attackerPromptBuilder->buildUserMessage($slicedChunk, $attackerAnalysisRequest->symfonyMapping);
        $userMessage = $this->prependContext($userMessage, $markerPreamble, $rejectedPreamble, $previousPreamble);

        return new ChunkContext($systemPrompt, $userMessage, $contextKey, $cacheable);
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

    private function isCacheable(AttackerAnalysisRequest $attackerAnalysisRequest, string $contextKey, bool $cacheIsContextAware): bool
    {
        return !$attackerAnalysisRequest->bypassCache && ('' === $contextKey || $cacheIsContextAware);
    }

    private function prependContext(string $userMessage, string $markerPreamble, string $rejectedPreamble, string $previousPreamble): string
    {
        if ('' !== $markerPreamble) {
            $userMessage = \sprintf("%s\n\n%s", $markerPreamble, $userMessage);
        }

        if ('' !== $rejectedPreamble) {
            $userMessage = \sprintf("%s\n\n%s", $rejectedPreamble, $userMessage);
        }

        if ('' !== $previousPreamble) {
            return \sprintf("%s\n\n%s", $previousPreamble, $userMessage);
        }

        return $userMessage;
    }

    /**
     * Replaces each file in the chunk with a version whose content is sliced
     * down to security-relevant lines. The slicer preserves the original line
     * count by replacing elided lines with a `// elided` placeholder, so the
     * line-numbering protocol in the prompt stays accurate against the source.
     * Any line the static pre-scanner already flagged as a risk marker is
     * restored verbatim afterward, since the slicer's own keyword list is
     * independently maintained and can miss patterns the pre-scanner catches.
     *
     * @param list<ProjectFile> $chunk
     *
     * @return list<ProjectFile>
     */
    private function sliceChunk(array $chunk, RiskMarkerIndex $riskMarkerIndex): array
    {
        $sliced = [];
        foreach ($chunk as $file) {
            $newContent = $this->restoreRiskMarkerLines($file, $this->codeSlicer->slice($file), $riskMarkerIndex->forChunk([$file]));

            if ($newContent === $file->content()) {
                $sliced[] = $file;

                continue;
            }

            $sliced[] = $file->withContent($newContent);
        }

        return $sliced;
    }

    /**
     * @param list<RiskMarker> $markers
     */
    private function restoreRiskMarkerLines(ProjectFile $projectFile, string $slicedContent, array $markers): string
    {
        $originalLines = explode("\n", $projectFile->content());
        $slicedLines = explode("\n", $slicedContent);

        foreach ($markers as $marker) {
            $index = $marker->line() - 1;
            if (\array_key_exists($index, $slicedLines) && \array_key_exists($index, $originalLines)) {
                $slicedLines[$index] = $originalLines[$index];
            }
        }

        return implode("\n", $slicedLines);
    }
}
