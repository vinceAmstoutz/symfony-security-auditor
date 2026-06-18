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
     * @param array<string, list<string>> $routeAccessMap
     * @param list<string>                 $firewallRules
     * @param list<RouteAccessControl>     $routeAccessControls
     * @param list<VoterCapability>        $voterCapabilities
     * @param list<FormBinding>            $formBindings
     */
    public function __construct(
        private array $routeAccessMap = [],
        private array $firewallRules = [],
        private array $routeAccessControls = [],
        private array $voterCapabilities = [],
        private array $formBindings = [],
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
}
