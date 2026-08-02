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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model;

/**
 * A survey of the audited application's security surfaces, named after what each
 * one *is* rather than what Symfony calls it.
 *
 * {@see SymfonyMapping} is the same data under Symfony vocabulary and delegates
 * here; its Symfony-named accessors are deprecated in favour of these. Prompt
 * rendering keeps the framework's words — that is the framework profile's job,
 * not this model's.
 */
final readonly class ApplicationSecurityMap
{
    private function __construct(
        private ProjectFileInventory $projectFileInventory,
        private AccessControlMap $accessControlMap,
    ) {}

    public static function of(ProjectFileInventory $projectFileInventory, AccessControlMap $accessControlMap): self
    {
        return new self($projectFileInventory, $accessControlMap);
    }

    /**
     * Files that receive a request through a route.
     *
     * @return list<ProjectFile>
     */
    public function entrypoints(): array
    {
        return $this->projectFileInventory->controllers();
    }

    /** @return list<ProjectFile> */
    public function domainModels(): array
    {
        return $this->projectFileInventory->entities();
    }

    /**
     * Files that decide whether an actor may act.
     *
     * @return list<ProjectFile>
     */
    public function authorizationRuleFiles(): array
    {
        return $this->projectFileInventory->voters();
    }

    /** @return list<ProjectFile> */
    public function persistenceQueries(): array
    {
        return $this->projectFileInventory->repositories();
    }

    /**
     * Files declaring which request fields may be written.
     *
     * @return list<ProjectFile>
     */
    public function inputBindingFiles(): array
    {
        return $this->projectFileInventory->forms();
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
    public function entrypointAccessMap(): array
    {
        return $this->accessControlMap->routeAccessMap();
    }

    /**
     * Path-pattern rules guarding whole areas of the application.
     *
     * @return list<string>
     */
    public function perimeterRules(): array
    {
        return $this->accessControlMap->firewallRules();
    }

    /** @return list<RouteAccessControl> */
    public function entrypointAccessControls(): array
    {
        return $this->accessControlMap->routeAccessControls();
    }

    /** @return list<RouteAccessControl> */
    public function entrypointsWithoutAccessCheck(): array
    {
        return $this->accessControlMap->controllersWithoutAccessCheck();
    }

    /** @return list<VoterCapability> */
    public function authorizationRules(): array
    {
        return $this->accessControlMap->voterCapabilities();
    }

    /** @return list<VoterCapability> */
    public function authorizationRulesFor(string $attribute, string $subject): array
    {
        return $this->accessControlMap->votersFor($attribute, $subject);
    }

    /** @return list<FormBinding> */
    public function fieldBindings(): array
    {
        return $this->accessControlMap->formBindings();
    }

    /** @return list<FormBinding> */
    public function fieldBindingsForEntrypoint(string $entrypointFilePath): array
    {
        return $this->accessControlMap->formBindingsForController($entrypointFilePath);
    }

    public function totalFiles(): int
    {
        return $this->projectFileInventory->totalFiles();
    }

    public function hasAuthorizationRuleForModel(string $modelName): bool
    {
        return $this->projectFileInventory->hasVoterForEntity($modelName);
    }

    /** @return list<ProjectFile> */
    public function entrypointsWithoutAuthorizationRule(): array
    {
        return $this->projectFileInventory->controllersWithoutVoters();
    }
}
