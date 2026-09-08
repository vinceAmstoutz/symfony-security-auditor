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

namespace VinceAmstoutz\SecurityAuditor\Audit\Domain\Model;

final readonly class SymfonyMapping
{
    private function __construct(
        private ProjectFileInventory $projectFileInventory,
        private AccessControlMap $accessControlMap,
        private ApplicationSecurityMap $applicationSecurityMap,
    ) {}

    public static function of(ProjectFileInventory $projectFileInventory, AccessControlMap $accessControlMap): self
    {
        return new self(
            $projectFileInventory,
            $accessControlMap,
            ApplicationSecurityMap::of($projectFileInventory, $accessControlMap),
        );
    }

    /**
     * The same survey under framework-neutral names. The Symfony-named accessors
     * below are deprecated in favour of it.
     */
    public function toApplicationSecurityMap(): ApplicationSecurityMap
    {
        return $this->applicationSecurityMap;
    }

    /** @return list<ProjectFile> */
    public function controllers(): array
    {
        return $this->projectFileInventory->entrypoints();
    }

    /** @return list<ProjectFile> */
    public function entities(): array
    {
        return $this->projectFileInventory->domainModels();
    }

    /** @return list<ProjectFile> */
    public function voters(): array
    {
        return $this->projectFileInventory->authorizationRules();
    }

    /** @return list<ProjectFile> */
    public function repositories(): array
    {
        return $this->projectFileInventory->persistenceQueries();
    }

    /** @return list<ProjectFile> */
    public function forms(): array
    {
        return $this->projectFileInventory->inputBindings();
    }

    /** @return list<ProjectFile> */
    public function services(): array
    {
        return $this->projectFileInventory->services();
    }

    /** @return list<ProjectFile> */
    public function templates(): array
    {
        return $this->projectFileInventory->templates();
    }

    /** @return array<string, list<string>> */
    public function routeAccessMap(): array
    {
        return $this->accessControlMap->routeAccessMap();
    }

    /**
     * @return list<string>
     *
     * @deprecated since 1.19, use {@see ApplicationSecurityMap::perimeterRules()} via {@see self::toApplicationSecurityMap()} instead.
     */
    public function firewallRules(): array
    {
        trigger_deprecation('vinceamstoutz/symfony-security-auditor', '1.19', 'SymfonyMapping::firewallRules() is deprecated, use ApplicationSecurityMap::perimeterRules() instead.');

        return $this->applicationSecurityMap->perimeterRules();
    }

    /** @return list<EntrypointAccessControl> */
    public function routeAccessControls(): array
    {
        return $this->accessControlMap->routeAccessControls();
    }

    /** @return list<EntrypointAccessControl> */
    public function controllersWithoutAccessCheck(): array
    {
        return $this->accessControlMap->entrypointsWithoutAccessCheck();
    }

    /**
     * @return list<AuthorizationRuleCapability>
     *
     * @deprecated since 1.19, use {@see ApplicationSecurityMap::authorizationRules()} via {@see self::toApplicationSecurityMap()} instead.
     */
    public function voterCapabilities(): array
    {
        trigger_deprecation('vinceamstoutz/symfony-security-auditor', '1.19', 'SymfonyMapping::voterCapabilities() is deprecated, use ApplicationSecurityMap::authorizationRules() instead.');

        return $this->applicationSecurityMap->authorizationRules();
    }

    /** @return list<AuthorizationRuleCapability> */
    public function votersFor(string $attribute, string $subject): array
    {
        return $this->accessControlMap->authorizationRulesFor($attribute, $subject);
    }

    /** @return list<FormBinding> */
    public function formBindings(): array
    {
        return $this->accessControlMap->formBindings();
    }

    /** @return list<FormBinding> */
    public function formBindingsForController(string $entrypointFilePath): array
    {
        return $this->accessControlMap->fieldBindingsForEntrypoint($entrypointFilePath);
    }

    public function totalFiles(): int
    {
        return $this->projectFileInventory->totalFiles();
    }

    /**
     * @deprecated since 1.19, use {@see ApplicationSecurityMap::hasAuthorizationRuleForModel()} via {@see self::toApplicationSecurityMap()} instead.
     */
    public function hasVoterForEntity(string $entityName): bool
    {
        trigger_deprecation('vinceamstoutz/symfony-security-auditor', '1.19', 'SymfonyMapping::hasVoterForEntity() is deprecated, use ApplicationSecurityMap::hasAuthorizationRuleForModel() instead.');

        return $this->applicationSecurityMap->hasAuthorizationRuleForModel($entityName);
    }

    /**
     * @return list<ProjectFile>
     *
     * @deprecated since 1.19, use {@see ApplicationSecurityMap::entrypointsWithoutAuthorizationRule()} via {@see self::toApplicationSecurityMap()} instead.
     */
    public function controllersWithoutVoters(): array
    {
        trigger_deprecation('vinceamstoutz/symfony-security-auditor', '1.19', 'SymfonyMapping::controllersWithoutVoters() is deprecated, use ApplicationSecurityMap::entrypointsWithoutAuthorizationRule() instead.');

        return $this->applicationSecurityMap->entrypointsWithoutAuthorizationRule();
    }

    public function toSummary(): string
    {
        $lines = [
            \sprintf('Controllers: %d', \count($this->projectFileInventory->entrypoints())),
            \sprintf('Entities: %d', \count($this->projectFileInventory->domainModels())),
            \sprintf('Voters: %d', \count($this->projectFileInventory->authorizationRules())),
            \sprintf('Repositories: %d', \count($this->projectFileInventory->persistenceQueries())),
            \sprintf('Forms: %d', \count($this->projectFileInventory->inputBindings())),
            \sprintf('Services: %d', \count($this->projectFileInventory->services())),
            \sprintf('Templates: %d', \count($this->projectFileInventory->templates())),
            \sprintf('Routes mapped: %d', \count($this->accessControlMap->routeAccessMap())),
            \sprintf('Firewall rules: %d', \count($this->accessControlMap->perimeterRules())),
        ];

        return implode("\n", $lines);
    }
}
