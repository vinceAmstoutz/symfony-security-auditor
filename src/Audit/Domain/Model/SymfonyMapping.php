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

final readonly class SymfonyMapping
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
     * @param list<ProjectFile>           $controllers
     * @param list<ProjectFile>           $entities
     * @param list<ProjectFile>           $voters
     * @param list<ProjectFile>           $repositories
     * @param list<ProjectFile>           $forms
     * @param list<ProjectFile>           $services
     * @param list<ProjectFile>           $templates
     * @param array<string, list<string>> $routeAccessMap
     * @param list<string>                $firewallRules
     * @param list<RouteAccessControl>    $routeAccessControls
     * @param list<VoterCapability>       $voterCapabilities
     * @param list<FormBinding>           $formBindings
     *
     * @deprecated since 1.13, use {@see self::of()} with a ProjectFileInventory and an AccessControlMap instead.
     */
    public static function create(
        array $controllers = [],
        array $entities = [],
        array $voters = [],
        array $repositories = [],
        array $forms = [],
        array $services = [],
        array $templates = [],
        array $routeAccessMap = [],
        array $firewallRules = [],
        array $routeAccessControls = [],
        array $voterCapabilities = [],
        array $formBindings = [],
    ): self {
        trigger_deprecation('vinceamstoutz/symfony-security-auditor', '1.13', 'SymfonyMapping::create() is deprecated, use SymfonyMapping::of() instead.');

        return self::of(
            ProjectFileInventory::fromGroups([
                'controllers' => $controllers,
                'entities' => $entities,
                'voters' => $voters,
                'repositories' => $repositories,
                'forms' => $forms,
                'services' => $services,
                'templates' => $templates,
            ]),
            new AccessControlMap(
                $routeAccessMap,
                $firewallRules,
                $routeAccessControls,
                $voterCapabilities,
                $formBindings,
            ),
        );
    }

    /** @return list<ProjectFile> */
    public function controllers(): array
    {
        return $this->projectFileInventory->controllers();
    }

    /** @return list<ProjectFile> */
    public function entities(): array
    {
        return $this->projectFileInventory->entities();
    }

    /** @return list<ProjectFile> */
    public function voters(): array
    {
        return $this->projectFileInventory->voters();
    }

    /** @return list<ProjectFile> */
    public function repositories(): array
    {
        return $this->projectFileInventory->repositories();
    }

    /** @return list<ProjectFile> */
    public function forms(): array
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
    public function routeAccessMap(): array
    {
        return $this->accessControlMap->routeAccessMap();
    }

    /** @return list<string> */
    public function firewallRules(): array
    {
        return $this->accessControlMap->firewallRules();
    }

    /** @return list<RouteAccessControl> */
    public function routeAccessControls(): array
    {
        return $this->accessControlMap->routeAccessControls();
    }

    /** @return list<RouteAccessControl> */
    public function controllersWithoutAccessCheck(): array
    {
        return $this->accessControlMap->controllersWithoutAccessCheck();
    }

    /** @return list<VoterCapability> */
    public function voterCapabilities(): array
    {
        return $this->accessControlMap->voterCapabilities();
    }

    /** @return list<VoterCapability> */
    public function votersFor(string $attribute, string $subject): array
    {
        return $this->accessControlMap->votersFor($attribute, $subject);
    }

    /** @return list<FormBinding> */
    public function formBindings(): array
    {
        return $this->accessControlMap->formBindings();
    }

    /** @return list<FormBinding> */
    public function formBindingsForController(string $controllerFilePath): array
    {
        return $this->accessControlMap->formBindingsForController($controllerFilePath);
    }

    public function totalFiles(): int
    {
        return $this->projectFileInventory->totalFiles();
    }

    public function hasVoterForEntity(string $entityName): bool
    {
        return $this->projectFileInventory->hasVoterForEntity($entityName);
    }

    /** @return list<ProjectFile> */
    public function controllersWithoutVoters(): array
    {
        return $this->projectFileInventory->controllersWithoutVoters();
    }

    public function toSummary(): string
    {
        $lines = [
            \sprintf('Controllers: %d', \count($this->projectFileInventory->controllers())),
            \sprintf('Entities: %d', \count($this->projectFileInventory->entities())),
            \sprintf('Voters: %d', \count($this->projectFileInventory->voters())),
            \sprintf('Repositories: %d', \count($this->projectFileInventory->repositories())),
            \sprintf('Forms: %d', \count($this->projectFileInventory->forms())),
            \sprintf('Services: %d', \count($this->projectFileInventory->services())),
            \sprintf('Templates: %d', \count($this->projectFileInventory->templates())),
            \sprintf('Routes mapped: %d', \count($this->accessControlMap->routeAccessMap())),
            \sprintf('Firewall rules: %d', \count($this->accessControlMap->firewallRules())),
        ];

        return implode("\n", $lines);
    }
}
