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

namespace VinceAmstoutz\SecurityAuditor\Audit\Application\Agent\Chunk;

use VinceAmstoutz\SecurityAuditor\Audit\Domain\Model\AuthorizationRuleCapability;
use VinceAmstoutz\SecurityAuditor\Audit\Domain\Model\EntrypointAccessControl;
use VinceAmstoutz\SecurityAuditor\Audit\Domain\Model\FormBinding;
use VinceAmstoutz\SecurityAuditor\Audit\Domain\Model\ProjectFile;
use VinceAmstoutz\SecurityAuditor\Audit\Domain\Model\SymfonyMapping;

/**
 * Derives the `ChunkContext` cache key everything that isn't the chunk's own
 * file content contributes to: the marker/rejected/previous preambles
 * {@see ChunkContextFactory} renders, plus a fingerprint of the mapping's
 * access-control data. Stateless — every input arrives as a parameter.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class ChunkContextKeyDeriver
{
    /**
     * Hashing each input individually fixes it to 64 hex characters, which can
     * never contain the join separator — so a preamble embedding a null byte
     * (rendered from never-sanitized LLM-echoed paths) cannot shift content
     * across the boundary and collide. Mirrors
     * `FilesystemAttackerCache::keyForChunk()`.
     *
     * The marker preamble is folded in so an entry is invalidated when the risk
     * markers change on an unchanged content hash; the mapping fingerprint does
     * the same for access-control data.
     */
    public function derive(string $markerPreamble, string $rejectedPreamble, string $previousPreamble, SymfonyMapping $symfonyMapping): string
    {
        $mappingFingerprint = $this->mappingFingerprint($symfonyMapping);

        if ('' === $markerPreamble && '' === $rejectedPreamble && '' === $previousPreamble && '' === $mappingFingerprint) {
            return '';
        }

        return hash('sha256', hash('sha256', $markerPreamble).hash('sha256', $rejectedPreamble).hash('sha256', $previousPreamble).hash('sha256', $mappingFingerprint));
    }

    /**
     * The chunk cache is keyed only by file content and this context key, so
     * without fingerprinting the mapping a `security.yaml` edit or a voter
     * added elsewhere would replay a verdict computed under the old mapping.
     * Lists are sorted first because project scanning makes no ordering
     * guarantee.
     *
     * Each signature is hashed individually before joining, as in
     * {@see self::derive()}: signatures can contain newlines, so joining them
     * raw would let one spanning two entries collide with two shorter ones.
     */
    private function mappingFingerprint(SymfonyMapping $symfonyMapping): string
    {
        $applicationSecurityMap = $symfonyMapping->toApplicationSecurityMap();

        $signatures = [
            ...$applicationSecurityMap->perimeterRules(),
            ...$this->routeAccessMapSignatures($symfonyMapping->routeAccessMap()),
            ...$this->routeAccessControlSignatures($symfonyMapping->routeAccessControls()),
            ...$this->authorizationRuleSignatures($applicationSecurityMap->authorizationRules()),
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
     * @param list<EntrypointAccessControl> $routeAccessControls
     *
     * @return list<string>
     */
    private function routeAccessControlSignatures(array $routeAccessControls): array
    {
        return array_map(serialize(...), $routeAccessControls);
    }

    /**
     * @param list<AuthorizationRuleCapability> $authorizationRules
     *
     * @return list<string>
     */
    private function authorizationRuleSignatures(array $authorizationRules): array
    {
        return array_map(serialize(...), $authorizationRules);
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
