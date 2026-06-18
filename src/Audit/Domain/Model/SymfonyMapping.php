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
        private ProjectFileInventory $files,
        private AccessControlMap $accessControl,
    ) {}

    public static function of(ProjectFileInventory $files, AccessControlMap $accessControl): self
    {
        return new self($files, $accessControl);
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
        return $this->files->controllers();
    }

    /** @return list<ProjectFile> */
    public function entities(): array
    {
        return $this->files->entities();
    }

    /** @return list<ProjectFile> */
    public function voters(): array
    {
        return $this->files->voters();
    }

    /** @return list<ProjectFile> */
    public function repositories(): array
    {
        return $this->files->repositories();
    }

    /** @return list<ProjectFile> */
    public function forms(): array
    {
        return $this->files->forms();
    }

    /** @return list<ProjectFile> */
    public function services(): array
    {
        return $this->files->services();
    }

    /** @return list<ProjectFile> */
    public function templates(): array
    {
        return $this->files->templates();
    }

    /** @return array<string, list<string>> */
    public function routeAccessMap(): array
    {
        return $this->accessControl->routeAccessMap();
    }

    /** @return list<string> */
    public function firewallRules(): array
    {
        return $this->accessControl->firewallRules();
    }

    /** @return list<RouteAccessControl> */
    public function routeAccessControls(): array
    {
        return $this->accessControl->routeAccessControls();
    }

    /** @return list<RouteAccessControl> */
    public function controllersWithoutAccessCheck(): array
    {
        return $this->accessControl->controllersWithoutAccessCheck();
    }

    /** @return list<VoterCapability> */
    public function voterCapabilities(): array
    {
        return $this->accessControl->voterCapabilities();
    }

    /** @return list<VoterCapability> */
    public function votersFor(string $attribute, string $subject): array
    {
        return $this->accessControl->votersFor($attribute, $subject);
    }

    /** @return list<FormBinding> */
    public function formBindings(): array
    {
        return $this->accessControl->formBindings();
    }

    /** @return list<FormBinding> */
    public function formBindingsForController(string $controllerFilePath): array
    {
        return $this->accessControl->formBindingsForController($controllerFilePath);
    }

    public function totalFiles(): int
    {
        return $this->files->totalFiles();
    }

    public function hasVoterForEntity(string $entityName): bool
    {
        return $this->files->hasVoterForEntity($entityName);
    }

    /** @return list<ProjectFile> */
    public function controllersWithoutVoters(): array
    {
        return $this->files->controllersWithoutVoters();
    }

    public function toSummary(): string
    {
        $lines = [
            \sprintf('Controllers: %d', \count($this->files->controllers())),
            \sprintf('Entities: %d', \count($this->files->entities())),
            \sprintf('Voters: %d', \count($this->files->voters())),
            \sprintf('Repositories: %d', \count($this->files->repositories())),
            \sprintf('Forms: %d', \count($this->files->forms())),
            \sprintf('Services: %d', \count($this->files->services())),
            \sprintf('Templates: %d', \count($this->files->templates())),
            \sprintf('Routes mapped: %d', \count($this->accessControl->routeAccessMap())),
            \sprintf('Firewall rules: %d', \count($this->accessControl->firewallRules())),
        ];

        return implode("\n", $lines);
    }
}
