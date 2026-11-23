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

use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\AccessControlRule;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ApplicationAccessControl;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\FormBinding;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFile;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectProfile;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\RouteAccessControl;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\SymfonyMapping;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VoterCapability;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\AttackerPromptBuilderInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\ProfileAwareAttackerPromptBuilderInterface;
use WeakMap;

/**
 * Derives the `ChunkContext` cache key from everything but the chunk's file
 * content: the preambles `ChunkContextFactory` renders and a fingerprint of
 * the mapping's access-control data, computed once per mapping.
 *
 * @internal not part of the BC promise, see docs/versioning.md
 */
final readonly class ChunkContextKeyDeriver
{
    /**
     * The fingerprint of every mapping this deriver has seen, dropped with it.
     *
     * @var WeakMap<SymfonyMapping, string>
     */
    private WeakMap $weakMap;

    public function __construct(
        private ?AttackerPromptBuilderInterface $attackerPromptBuilder = null,
    ) {
        $this->weakMap = new WeakMap();
    }

    /**
     * Hashes each input before joining, so a preamble carrying a null byte
     * from an LLM-echoed file path cannot shift content across the separator
     * and collide with another combination. The key changes with the risk
     * markers and the mapping. It includes the candidate preamble only when
     * that is not empty.
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
     * Fingerprints the mapping data the user message renders, so a
     * `security.yaml` edit or a new voter invalidates the cache of a file
     * whose content did not change. Sorts each list, so two scans of the same
     * code agree. Hashes each signature before joining, since one can hold a
     * newline.
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
            ...$this->accessControlSignatures('', $symfonyMapping->routeAccessMap(), $symfonyMapping->accessControlRules()),
            ...$this->unreadableConfigurationSignatures($symfonyMapping->unreadableConfigurationFiles()),
            ...$this->applicationAccessControlSignatures($symfonyMapping->applicationAccessControls()),
            ...$this->routeAccessControlSignatures($symfonyMapping->routeAccessControls()),
            ...$this->voterCapabilitySignatures($applicationSecurityMap->authorizationRules()),
            ...$this->formBindingSignatures($symfonyMapping->formBindings()),
            ...$this->entrypointsWithoutAuthorizationRulePaths($applicationSecurityMap->entrypointsWithoutAuthorizationRule()),
            ...$this->projectProfileSignatures($symfonyMapping->projectProfile()),
        ];

        if ([] === $signatures) {
            return '';
        }

        sort($signatures);

        return hash('sha256', implode('', array_map(static fn (string $signature): string => hash('sha256', $signature), $signatures)));
    }

    /**
     * Keeps the map and the declared rules in declaration order, one signature
     * each, since the first matching `access_control` rule applies.
     *
     * @param array<string, list<string>> $routeAccessMap
     * @param list<AccessControlRule>     $accessControlRules
     *
     * @return list<string> none for a mapping without access control rules
     */
    private function accessControlSignatures(string $owner, array $routeAccessMap, array $accessControlRules): array
    {
        if ([] === $routeAccessMap && [] === $accessControlRules) {
            return [];
        }

        return [
            \sprintf('%saccess control map: %s', $owner, serialize($routeAccessMap)),
            \sprintf('%saccess control rules: %s', $owner, serialize($accessControlRules)),
        ];
    }

    /**
     * @param list<string> $unreadableConfigurationFiles
     *
     * @return list<string>
     */
    private function unreadableConfigurationSignatures(array $unreadableConfigurationFiles): array
    {
        return array_map(static fn (string $path): string => \sprintf('unreadable configuration: %s', $path), $unreadableConfigurationFiles);
    }

    /**
     * @param array<string, ApplicationAccessControl> $applicationAccessControls
     *
     * @return list<string>
     */
    private function applicationAccessControlSignatures(array $applicationAccessControls): array
    {
        $signatures = [];
        foreach ($applicationAccessControls as $applicationFolder => $applicationAccessControl) {
            $signatures = [...$signatures, ...$this->accessControlSignatures(\sprintf('application %s ', $applicationFolder), $applicationAccessControl->routeAccessMap, $applicationAccessControl->accessControlRules)];

            foreach ($applicationAccessControl->firewallRules as $firewallRule) {
                $signatures[] = \sprintf('application %s firewall: %s', $applicationFolder, $firewallRule);
            }
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

    /**
     * @return list<string>
     */
    private function projectProfileSignatures(ProjectProfile $projectProfile): array
    {
        $projectProfileFingerprint = $this->attackerPromptBuilder instanceof ProfileAwareAttackerPromptBuilderInterface
            ? $this->attackerPromptBuilder->profileFingerprint($projectProfile)
            : '';

        return '' === $projectProfileFingerprint ? [] : [\sprintf('project profile %s', $projectProfileFingerprint)];
    }
}
