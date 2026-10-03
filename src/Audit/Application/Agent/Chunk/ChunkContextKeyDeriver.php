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

use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\FormBinding;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFile;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\RouteAccessControl;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\SymfonyMapping;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VoterCapability;
use WeakMap;

/**
 * Derives the `ChunkContext` cache key everything that isn't the chunk's own
 * file content contributes to: the marker/rejected/previous/candidate
 * preambles {@see ChunkContextFactory} renders, plus a fingerprint of the
 * mapping's access-control data. Every chunk of a request shares the
 * request's mapping, so its fingerprint is computed once per mapping instance
 * and remembered in a `WeakMap` that lets go of it with the mapping.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class ChunkContextKeyDeriver
{
    /**
     * The fingerprint of every mapping this deriver has seen, dropped with it.
     *
     * @var WeakMap<SymfonyMapping, string>
     */
    private WeakMap $weakMap;

    public function __construct()
    {
        $this->weakMap = new WeakMap();
    }

    /**
     * Hashing each input individually before joining fixes each to 64 hex
     * characters, which can never contain the raw-text join's own separator —
     * so a rejected/previous preamble embedding a null byte (both are
     * rendered from LLM-echoed `Vulnerability::filePath()` values, which are
     * never null-byte-sanitized) can't shift content across the join
     * boundary and collide with a genuinely different combination. Mirrors
     * `FilesystemAttackerCache::keyForChunk()`'s per-file hash-then-join.
     *
     * The marker preamble is included so a chunk cache entry is invalidated
     * whenever the risk markers it was built from change — e.g. a custom
     * `StaticPreScannerInterface` implementation (a documented extension
     * point) starts flagging a file differently on an unchanged content hash.
     * The mapping fingerprint serves the same purpose for the access-control
     * data {@see self::mappingFingerprint()} folds in. The candidate preamble
     * only exists in an escalation deep pass, so it joins the key only when it
     * is there: every other chunk keeps the key earlier releases derived, and
     * their cache entries still hit.
     */
    public function derive(string $markerPreamble, string $rejectedPreamble, string $previousPreamble, string $candidatePreamble, SymfonyMapping $symfonyMapping): string
    {
        $mappingFingerprint = $this->mappingFingerprint($symfonyMapping);

        if ('' === $markerPreamble && '' === $rejectedPreamble && '' === $previousPreamble && '' === $candidatePreamble && '' === $mappingFingerprint) {
            return '';
        }

        $candidateHash = '' === $candidatePreamble ? '' : hash('sha256', $candidatePreamble);

        return hash('sha256', hash('sha256', $markerPreamble).hash('sha256', $rejectedPreamble).hash('sha256', $previousPreamble).$candidateHash.hash('sha256', $mappingFingerprint));
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
     *
     * Each signature is hashed individually before joining, for the same
     * reason as {@see self::derive()}: a firewall rule or serialized
     * route/voter/form signature can itself contain a newline (e.g. a
     * `security.yaml` access-control path parsed from a double-quoted YAML
     * string), so joining raw signatures with "\n" before a single hash
     * could let one signature spanning two entries collide with two
     * genuinely different, shorter entries.
     */
    private function mappingFingerprint(SymfonyMapping $symfonyMapping): string
    {
        if (!$this->weakMap->offsetExists($symfonyMapping)) {
            $this->weakMap[$symfonyMapping] = $this->computeMappingFingerprint($symfonyMapping);
        }

        return $this->weakMap[$symfonyMapping];
    }

    private function computeMappingFingerprint(SymfonyMapping $symfonyMapping): string
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

        return hash('sha256', implode('', array_map(static fn (string $signature): string => hash('sha256', $signature), $signatures)));
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
}
