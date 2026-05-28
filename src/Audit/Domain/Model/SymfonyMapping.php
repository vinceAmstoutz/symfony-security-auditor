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
     */
    private function __construct(
        private array $controllers,
        private array $entities,
        private array $voters,
        private array $repositories,
        private array $forms,
        private array $services,
        private array $templates,
        private array $routeAccessMap,
        private array $firewallRules,
        private array $routeAccessControls,
        private array $voterCapabilities,
        private array $formBindings,
    ) {}

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
        return new self(
            controllers: $controllers,
            entities: $entities,
            voters: $voters,
            repositories: $repositories,
            forms: $forms,
            services: $services,
            templates: $templates,
            routeAccessMap: $routeAccessMap,
            firewallRules: $firewallRules,
            routeAccessControls: $routeAccessControls,
            voterCapabilities: $voterCapabilities,
            formBindings: $formBindings,
        );
    }

    /** @return list<ProjectFile> */
    public function controllers(): array
    {
        return $this->controllers;
    }

    /** @return list<ProjectFile> */
    public function entities(): array
    {
        return $this->entities;
    }

    /** @return list<ProjectFile> */
    public function voters(): array
    {
        return $this->voters;
    }

    /** @return list<ProjectFile> */
    public function repositories(): array
    {
        return $this->repositories;
    }

    /** @return list<ProjectFile> */
    public function forms(): array
    {
        return $this->forms;
    }

    /** @return list<ProjectFile> */
    public function services(): array
    {
        return $this->services;
    }

    /** @return list<ProjectFile> */
    public function templates(): array
    {
        return $this->templates;
    }

    /** @return array<string, list<string>> */
    public function routeAccessMap(): array
    {
        return $this->routeAccessMap;
    }

    /** @return list<string> */
    public function firewallRules(): array
    {
        return $this->firewallRules;
    }

    /** @return list<RouteAccessControl> */
    public function routeAccessControls(): array
    {
        return $this->routeAccessControls;
    }

    /** @return list<RouteAccessControl> */
    public function controllersWithoutAccessCheck(): array
    {
        return array_values(array_filter(
            $this->routeAccessControls,
            static fn (RouteAccessControl $routeAccessControl): bool => $routeAccessControl->lacksAccessCheck(),
        ));
    }

    /** @return list<VoterCapability> */
    public function voterCapabilities(): array
    {
        return $this->voterCapabilities;
    }

    /** @return list<VoterCapability> */
    public function votersFor(string $attribute, string $subject): array
    {
        return array_values(array_filter(
            $this->voterCapabilities,
            static fn (VoterCapability $voterCapability): bool => $voterCapability->coversAttribute($attribute) && $voterCapability->coversSubject($subject),
        ));
    }

    /** @return list<FormBinding> */
    public function formBindings(): array
    {
        return $this->formBindings;
    }

    /** @return list<FormBinding> */
    public function formBindingsForController(string $controllerFilePath): array
    {
        return array_values(array_filter(
            $this->formBindings,
            static fn (FormBinding $formBinding): bool => $formBinding->controllerFilePath() === $controllerFilePath,
        ));
    }

    public function totalFiles(): int
    {
        return \count($this->controllers)
            + \count($this->entities)
            + \count($this->voters)
            + \count($this->repositories)
            + \count($this->forms)
            + \count($this->services)
            + \count($this->templates);
    }

    public function hasVoterForEntity(string $entityName): bool
    {
        foreach ($this->voters as $voter) {
            if (str_contains($voter->content(), $entityName)) {
                return true;
            }
        }

        return false;
    }

    /**
     * @return list<ProjectFile>
     *
     * Rector earlyReturn: uses array_values to return a proper list
     */
    public function controllersWithoutVoters(): array
    {
        return array_values(array_filter(
            $this->controllers,
            static fn (ProjectFile $projectFile): bool => !$projectFile->hasSecurityAnnotations(),
        ));
    }

    public function toSummary(): string
    {
        $lines = [
            \sprintf('Controllers: %d', \count($this->controllers)),
            \sprintf('Entities: %d', \count($this->entities)),
            \sprintf('Voters: %d', \count($this->voters)),
            \sprintf('Repositories: %d', \count($this->repositories)),
            \sprintf('Forms: %d', \count($this->forms)),
            \sprintf('Services: %d', \count($this->services)),
            \sprintf('Templates: %d', \count($this->templates)),
            \sprintf('Routes mapped: %d', \count($this->routeAccessMap)),
            \sprintf('Firewall rules: %d', \count($this->firewallRules)),
        ];

        return implode("\n", $lines);
    }
}
