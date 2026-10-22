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

final readonly class AccessControlMap
{
    /**
     * @param array<string, list<string>>             $routeAccessMap
     * @param list<string>                            $firewallRules
     * @param list<RouteAccessControl>                $routeAccessControls
     * @param list<VoterCapability>                   $voterCapabilities
     * @param list<FormBinding>                       $formBindings
     * @param list<string>                            $unreadableConfigurationFiles the configuration files the application loads that could not be read
     * @param array<string, ApplicationAccessControl> $applicationAccessControls    the access control of each monorepo application the run is narrowed to, by the application's folder, ending with a `/`
     * @param list<AccessControlRule>                 $accessControlRules           the project's `access_control` rules in the order the application declares them, when the parser gave them
     */
    public function __construct(
        private array $routeAccessMap = [],
        private array $firewallRules = [],
        private array $routeAccessControls = [],
        private array $voterCapabilities = [],
        private array $formBindings = [],
        private array $unreadableConfigurationFiles = [],
        private array $applicationAccessControls = [],
        private array $accessControlRules = [],
    ) {}

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

    /**
     * The configuration files the application loads that could not be read,
     * so the rules they may hold are missing from this map.
     *
     * @return list<string>
     *
     * @internal not part of the BC promise — see docs/versioning.md
     */
    public function unreadableConfigurationFiles(): array
    {
        return $this->unreadableConfigurationFiles;
    }

    /**
     * @return array<string, ApplicationAccessControl>
     *
     * @internal not part of the BC promise — see docs/versioning.md
     */
    public function applicationAccessControls(): array
    {
        return $this->applicationAccessControls;
    }

    /**
     * The `access_control` rules that govern the routes of a controller file:
     * those of the nearest application folder holding it whose configuration
     * was read, else the project's.
     *
     * @return array<string, list<string>>
     *
     * @internal not part of the BC promise — see docs/versioning.md
     */
    public function routeAccessMapFor(string $controllerFilePath): array
    {
        return $this->applicationAccessControlFor($controllerFilePath)->routeAccessMap ?? $this->routeAccessMap;
    }

    /**
     * The project's `access_control` rules in the order the application
     * declares them.
     *
     * @return list<AccessControlRule>
     *
     * @internal not part of the BC promise — see docs/versioning.md
     */
    public function accessControlRules(): array
    {
        return $this->accessControlRules;
    }

    /**
     * The `access_control` rules, in the order they are declared, that govern
     * the routes of a controller file: those of the nearest application folder
     * holding it whose configuration was read, else the project's.
     *
     * @return list<AccessControlRule>
     *
     * @internal not part of the BC promise — see docs/versioning.md
     */
    public function accessControlRulesFor(string $controllerFilePath): array
    {
        return $this->applicationAccessControlFor($controllerFilePath)->accessControlRules ?? $this->accessControlRules;
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

    /**
     * The folder of the nearest application holding a controller file whose
     * configuration was read, whose rules govern its routes; none when the
     * project's rules govern them.
     *
     * @internal not part of the BC promise — see docs/versioning.md
     */
    public function applicationFolderFor(string $controllerFilePath): ?string
    {
        foreach ($this->applicationFoldersNearestFirst() as $applicationFolder) {
            if (str_starts_with($controllerFilePath, $applicationFolder)) {
                return $applicationFolder;
            }
        }

        return null;
    }

    private function applicationAccessControlFor(string $controllerFilePath): ?ApplicationAccessControl
    {
        $applicationFolder = $this->applicationFolderFor($controllerFilePath);

        return null === $applicationFolder ? null : $this->applicationAccessControls[$applicationFolder];
    }

    /**
     * @return list<string>
     */
    private function applicationFoldersNearestFirst(): array
    {
        $applicationFolders = array_keys($this->applicationAccessControls);
        usort($applicationFolders, static fn (string $left, string $right): int => \strlen($right) <=> \strlen($left));

        return $applicationFolders;
    }
}
