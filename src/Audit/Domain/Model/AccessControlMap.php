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
     * @param array<string, list<string>>       $routeAccessMap
     * @param list<string>                      $perimeterRules
     * @param list<EntrypointAccessControl>     $routeAccessControls
     * @param list<AuthorizationRuleCapability> $authorizationRules
     * @param list<FormBinding>                 $formBindings
     */
    public function __construct(
        private array $routeAccessMap = [],
        private array $perimeterRules = [],
        private array $routeAccessControls = [],
        private array $authorizationRules = [],
        private array $formBindings = [],
    ) {}

    /** @return array<string, list<string>> */
    public function routeAccessMap(): array
    {
        return $this->routeAccessMap;
    }

    /** @return list<string> */
    public function perimeterRules(): array
    {
        return $this->perimeterRules;
    }

    /** @return list<EntrypointAccessControl> */
    public function routeAccessControls(): array
    {
        return $this->routeAccessControls;
    }

    /** @return list<EntrypointAccessControl> */
    public function entrypointsWithoutAccessCheck(): array
    {
        return array_values(array_filter(
            $this->routeAccessControls,
            static fn (EntrypointAccessControl $entrypointAccessControl): bool => $entrypointAccessControl->lacksAccessCheck(),
        ));
    }

    /** @return list<AuthorizationRuleCapability> */
    public function authorizationRules(): array
    {
        return $this->authorizationRules;
    }

    /** @return list<AuthorizationRuleCapability> */
    public function authorizationRulesFor(string $attribute, string $subject): array
    {
        return array_values(array_filter(
            $this->authorizationRules,
            static fn (AuthorizationRuleCapability $authorizationRuleCapability): bool => $authorizationRuleCapability->coversAttribute($attribute) && $authorizationRuleCapability->coversSubject($subject),
        ));
    }

    /** @return list<FormBinding> */
    public function formBindings(): array
    {
        return $this->formBindings;
    }

    /** @return list<FormBinding> */
    public function fieldBindingsForEntrypoint(string $entrypointFilePath): array
    {
        return array_values(array_filter(
            $this->formBindings,
            static fn (FormBinding $formBinding): bool => $formBinding->entrypointFilePath() === $entrypointFilePath,
        ));
    }
}
