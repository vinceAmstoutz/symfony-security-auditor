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
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\FormBinding;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFile;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\RiskMarker;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\RouteAccessControl;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\SymfonyMapping;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VoterCapability;
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
        $markerPreamble = $this->renderMarkerPreamble($chunkMarkers);

        $rejectedPreamble = $this->renderRejectedPreamble($attackerAnalysisRequest);
        $previousPreamble = $this->renderPreviousPreamble($attackerAnalysisRequest);
        $mappingFingerprint = $this->mappingFingerprint($attackerAnalysisRequest->symfonyMapping);
        $contextKey = $this->deriveContextKey($markerPreamble, $rejectedPreamble, $previousPreamble, $mappingFingerprint);
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

    /**
     * Hashing each preamble individually before joining fixes each to 64 hex
     * characters, which can never contain the raw-text join's own separator —
     * so a rejected/previous preamble embedding a null byte (both are
     * rendered from LLM-echoed `Vulnerability::filePath()` values, which are
     * never null-byte-sanitized) can't shift content across the join
     * boundary and collide with a genuinely different triple. Mirrors
     * `FilesystemAttackerCache::keyForChunk()`'s per-file hash-then-join.
     *
     * The marker preamble is included so a chunk cache entry is invalidated
     * whenever the risk markers it was built from change — e.g. a custom
     * `StaticPreScannerInterface` implementation (a documented extension
     * point) starts flagging a file differently on an unchanged content hash.
     * The mapping fingerprint serves the same purpose for the access-control
     * data {@see self::mappingFingerprint()} folds in.
     */
    private function deriveContextKey(string $markerPreamble, string $rejectedPreamble, string $previousPreamble, string $mappingFingerprint): string
    {
        if ('' === $markerPreamble && '' === $rejectedPreamble && '' === $previousPreamble && '' === $mappingFingerprint) {
            return '';
        }

        return hash('sha256', hash('sha256', $markerPreamble).hash('sha256', $rejectedPreamble).hash('sha256', $previousPreamble).hash('sha256', $mappingFingerprint));
    }

    /**
     * `AttackerPromptBuilder::buildUserMessage()` renders the firewall,
     * route-access-control, voter-coverage and form-binding sections straight
     * from the mapping, but the chunk cache is keyed only by file content and
     * this class's context key — so, unfingerprinted, a `security.yaml` edit
     * or a voter added elsewhere in the project would replay a verdict
     * computed under the old mapping for a file whose own content never
     * changed. Each list is sorted before hashing since project scanning
     * makes no ordering guarantee, so two scans of the same unchanged
     * codebase still agree.
     */
    private function mappingFingerprint(SymfonyMapping $symfonyMapping): string
    {
        $applicationSecurityMap = $symfonyMapping->toApplicationSecurityMap();

        $signatures = [
            ...$applicationSecurityMap->perimeterRules(),
            ...$this->routeAccessMapSignatures($symfonyMapping->routeAccessMap()),
            ...$this->routeAccessControlSignatures($symfonyMapping->routeAccessControls()),
            ...$this->voterCapabilitySignatures($applicationSecurityMap->authorizationRules()),
            ...$this->formBindingSignatures($symfonyMapping->formBindings()),
            ...$this->entrypointsWithoutAuthorizationRulePaths($applicationSecurityMap->entrypointsWithoutAuthorizationRule()),
        ];

        if ([] === $signatures) {
            return '';
        }

        sort($signatures);

        return hash('sha256', implode("\n", $signatures));
    }

    /**
     * @param array<string, list<string>> $routeAccessMap
     *
     * @return list<string>
     */
    private function routeAccessMapSignatures(array $routeAccessMap): array
    {
        $signatures = [];
        foreach ($routeAccessMap as $pattern => $roles) {
            $signatures[] = \sprintf('%s=%s', $pattern, implode(',', $roles));
        }

        return $signatures;
    }

    /**
     * @param list<RouteAccessControl> $routeAccessControls
     *
     * @return list<string>
     */
    private function routeAccessControlSignatures(array $routeAccessControls): array
    {
        return array_map(serialize(...), $routeAccessControls);
    }

    /**
     * @param list<VoterCapability> $voterCapabilities
     *
     * @return list<string>
     */
    private function voterCapabilitySignatures(array $voterCapabilities): array
    {
        return array_map(serialize(...), $voterCapabilities);
    }

    /**
     * @param list<FormBinding> $formBindings
     *
     * @return list<string>
     */
    private function formBindingSignatures(array $formBindings): array
    {
        return array_map(serialize(...), $formBindings);
    }

    /**
     * @param list<ProjectFile> $entrypointsWithoutAuthorizationRule
     *
     * @return list<string>
     */
    private function entrypointsWithoutAuthorizationRulePaths(array $entrypointsWithoutAuthorizationRule): array
    {
        return array_map(static fn (ProjectFile $projectFile): string => $projectFile->relativePath(), $entrypointsWithoutAuthorizationRule);
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
