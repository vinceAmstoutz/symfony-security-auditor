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
 * preambles), slices each file to its security-relevant lines, and derives the
 * cache key and cacheability. Shared by the sequential and concurrent chunk
 * analyzers.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class ChunkContextFactory
{
    public function __construct(
        private AttackerPromptBuilderInterface $attackerPromptBuilder,
        private CodeSlicerInterface $codeSlicer,
        private AttackerContextPromptRenderer $attackerContextPromptRenderer,
    ) {}

    /**
     * @param list<ProjectFile> $chunk
     */
    public function create(array $chunk, AttackerAnalysisRequest $attackerAnalysisRequest, RiskMarkerIndex $riskMarkerIndex, bool $cacheIsContextAware): ChunkContext
    {
        $chunkMarkers = $riskMarkerIndex->forChunk($chunk);

        $rejectedPreamble = $this->renderRejectedPreamble($attackerAnalysisRequest);
        $previousPreamble = $this->renderPreviousPreamble($attackerAnalysisRequest);
        $contextKey = $this->deriveContextKey($rejectedPreamble, $previousPreamble);
        $cacheable = $this->isCacheable($attackerAnalysisRequest, $contextKey, $cacheIsContextAware);

        $slicedChunk = $this->sliceChunk($chunk);
        $systemPrompt = $this->attackerPromptBuilder->buildSystemPrompt($slicedChunk);
        $userMessage = $this->attackerPromptBuilder->buildUserMessage($slicedChunk, $attackerAnalysisRequest->symfonyMapping);
        $userMessage = $this->prependContext($userMessage, $chunkMarkers, $rejectedPreamble, $previousPreamble);

        return new ChunkContext($systemPrompt, $userMessage, $contextKey, $cacheable);
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

    private function deriveContextKey(string $rejectedPreamble, string $previousPreamble): string
    {
        if ('' === $rejectedPreamble && '' === $previousPreamble) {
            return '';
        }

        return hash('sha256', \sprintf("%s\0%s", $rejectedPreamble, $previousPreamble));
    }

    private function isCacheable(AttackerAnalysisRequest $attackerAnalysisRequest, string $contextKey, bool $cacheIsContextAware): bool
    {
        return !$attackerAnalysisRequest->bypassCache && ('' === $contextKey || $cacheIsContextAware);
    }

    /**
     * @param list<RiskMarker> $chunkMarkers
     */
    private function prependContext(string $userMessage, array $chunkMarkers, string $rejectedPreamble, string $previousPreamble): string
    {
        if ([] !== $chunkMarkers) {
            $userMessage = \sprintf("%s\n\n%s", $this->attackerContextPromptRenderer->renderRiskMarkers($chunkMarkers), $userMessage);
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
