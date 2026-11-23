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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Prompt;

use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\AccessControlRule;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\RouteAccessControl;

/**
 * Finds the roles of the `access_control` rule that governs a route, the first
 * one matching it as Symfony applies them. A route first matched by a rule
 * without roles or an expression has no governing roles.
 *
 * @internal not part of the BC promise, see docs/versioning.md
 */
final readonly class AccessControlRuleMatcher
{
    private const string ROUTE_TARGET_PREFIX = 'route: ';

    /**
     * @param array<string, list<string>> $routeAccessMap
     * @param list<AccessControlRule>     $accessControlRules the rules in the order they are declared, when the parser gave them
     *
     * @return list<string>|false|null the governing rule's roles, null when no rule governs the route or the first one Symfony applies to some of its requests checks nothing, false when it cannot be told
     */
    public static function rolesFor(RouteAccessControl $routeAccessControl, array $routeAccessMap, array $accessControlRules = []): array|false|null
    {
        return self::rolesForEach([$routeAccessControl], $routeAccessMap, $accessControlRules)[0];
    }

    /**
     * {@see self::rolesFor()} for several routes the same rules govern, each
     * path pattern compiled once for all of them.
     *
     * @param array<int, RouteAccessControl> $routeAccessControls
     * @param array<string, list<string>>    $routeAccessMap
     * @param list<AccessControlRule>        $accessControlRules  the rules in the order they are declared, when the parser gave them
     *
     * @return array<int, list<string>|false|null> by the key of each route, in the order given
     */
    public static function rolesForEach(array $routeAccessControls, array $routeAccessMap, array $accessControlRules = []): array
    {
        $routeMethods = array_map(static fn (RouteAccessControl $routeAccessControl): array => array_map(strtoupper(...), $routeAccessControl->routeMethods()), $routeAccessControls);
        $routePaths = array_filter(array_map(static fn (RouteAccessControl $routeAccessControl): ?string => $routeAccessControl->routePath(), $routeAccessControls), static fn (?string $routePath): bool => null !== $routePath);
        $checksNothing = self::firstMatchingRuleChecksNothing($routeAccessControls, $accessControlRules, $routeMethods, $routePaths);
        $openRoutes = array_filter($routeAccessControls, static fn (int $index): bool => false === $checksNothing[$index], \ARRAY_FILTER_USE_KEY);

        return array_replace(
            array_map(self::rolesSettledBy(...), $checksNothing),
            self::governingRoles($openRoutes, $routeAccessMap, $routeMethods, $routePaths),
        );
    }

    /**
     * @return ?false null when the first rule Symfony applies to some of the route's requests checks nothing, false when it cannot be told; a route the rules leave open takes its governing roles instead
     */
    private static function rolesSettledBy(?bool $checksNothing): ?false
    {
        return null === $checksNothing ? false : null;
    }

    /**
     * @param array<int, RouteAccessControl> $routeAccessControls
     * @param array<string, list<string>>    $routeAccessMap
     * @param array<int, list<string>>       $routeMethods        upper-case, by the key of each route; empty for every method
     * @param array<int, string>             $routePaths          by the key of each route that has a path
     *
     * @return array<int, list<string>|false|null> by the key of each route
     */
    private static function governingRoles(array $routeAccessControls, array $routeAccessMap, array $routeMethods, array $routePaths): array
    {
        $governingRoles = array_map(static fn (): null => null, $routeAccessControls);
        $ungoverned = $routeAccessControls;
        foreach ($routeAccessMap as $target => $roles) {
            foreach (self::routesGovernedBy($target, $roles, $ungoverned, $routeMethods, $routePaths) as $index => $governs) {
                $governingRoles[$index] = true === $governs ? $roles : false;
                unset($ungoverned[$index]);
            }
        }

        return $governingRoles;
    }

    /**
     * @param list<string>                   $roles
     * @param array<int, RouteAccessControl> $routeAccessControls
     * @param array<int, list<string>>       $routeMethods        upper-case, by the key of each route; empty for every method
     * @param array<int, string>             $routePaths          by the key of each route that has a path
     *
     * @return array<int, ?bool> the routes the rule governs, true, or may govern, null
     */
    private static function routesGovernedBy(string $target, array $roles, array $routeAccessControls, array $routeMethods, array $routePaths): array
    {
        $requiredMethods = array_map(self::methodsRequiredBy(...), self::alternativesOf($roles));
        $covered = array_filter($routeAccessControls, static fn (int $index): bool => self::methodsAreCovered($requiredMethods, $routeMethods[$index]), \ARRAY_FILTER_USE_KEY);

        return array_filter(self::targetGovernsEach($target, $covered, $routePaths), static fn (?bool $governs): bool => false !== $governs);
    }

    /**
     * Walks the rules in declaration order until one decides the route: it
     * checks nothing, or checks something and matches all of its requests.
     *
     * @param array<int, RouteAccessControl> $routeAccessControls
     * @param list<AccessControlRule>        $accessControlRules
     * @param array<int, list<string>>       $routeMethods        upper-case, by the key of each route; empty for every method
     * @param array<int, string>             $routePaths          by the key of each route that has a path
     *
     * @return array<int, ?bool> by the key of each route, in the order given: false when a rule that checks something settles the route, or none decides it; null when it cannot be told
     */
    private static function firstMatchingRuleChecksNothing(array $routeAccessControls, array $accessControlRules, array $routeMethods, array $routePaths): array
    {
        $checksNothing = array_map(static fn (): bool => false, $routeAccessControls);
        $undecided = $routeAccessControls;
        foreach ($accessControlRules as $accessControlRule) {
            foreach (self::routesDecidedBy($accessControlRule, $undecided, $routeMethods, $routePaths) as $index => $governs) {
                $checksNothing[$index] = self::checksNothing($accessControlRule, $governs);
                unset($undecided[$index]);
            }
        }

        return $checksNothing;
    }

    /**
     * @param array<int, RouteAccessControl> $routeAccessControls
     * @param array<int, list<string>>       $routeMethods        upper-case, by the key of each route; empty for every method
     * @param array<int, string>             $routePaths          by the key of each route that has a path
     *
     * @return array<int, ?bool> the routes the rule decides, true, or may decide, null
     */
    private static function routesDecidedBy(AccessControlRule $accessControlRule, array $routeAccessControls, array $routeMethods, array $routePaths): array
    {
        $decided = array_filter($routeAccessControls, static fn (int $index): bool => self::decidesTheRoute($accessControlRule, $routeMethods[$index]), \ARRAY_FILTER_USE_KEY);

        return array_filter(self::targetGovernsEach($accessControlRule->target, $decided, $routePaths), static fn (?bool $governs): bool => false !== $governs);
    }

    /**
     * @return bool|null null when it cannot be told whether the rule governs the route
     */
    private static function checksNothing(AccessControlRule $accessControlRule, ?bool $governs): ?bool
    {
        return null === $governs ? null : !$accessControlRule->restricts;
    }

    /**
     * @param list<string> $routeMethods upper-case; empty for every method
     */
    private static function decidesTheRoute(AccessControlRule $accessControlRule, array $routeMethods): bool
    {
        if (!self::ruleMatchesSomeRequests($accessControlRule->methods, $routeMethods)) {
            return false;
        }

        return !$accessControlRule->restricts || self::ruleMatchesEveryRequest($accessControlRule->methods, $routeMethods);
    }

    /**
     * @param list<string> $ruleMethods
     * @param list<string> $routeMethods upper-case; empty for every method
     */
    private static function ruleMatchesSomeRequests(array $ruleMethods, array $routeMethods): bool
    {
        return [] === $ruleMethods || [] === $routeMethods || [] !== array_intersect($routeMethods, $ruleMethods);
    }

    /**
     * @param list<string> $ruleMethods
     * @param list<string> $routeMethods upper-case; empty for every method
     */
    private static function ruleMatchesEveryRequest(array $ruleMethods, array $routeMethods): bool
    {
        return [] === $ruleMethods || ([] !== $routeMethods && [] === array_diff($routeMethods, $ruleMethods));
    }

    /**
     * A `route: <name>` target governs the route of that name. A path pattern
     * governs no route without a path.
     *
     * @param array<int, RouteAccessControl> $routeAccessControls
     * @param array<int, string>             $routePaths          by the key of each route that has a path
     *
     * @return array<int, ?bool> by the key of each route; null when the pattern cannot be decided for it
     */
    private static function targetGovernsEach(string $target, array $routeAccessControls, array $routePaths): array
    {
        if (str_starts_with($target, self::ROUTE_TARGET_PREFIX)) {
            return array_map(static fn (RouteAccessControl $routeAccessControl): bool => self::targetNames($target, $routeAccessControl->routeName()), $routeAccessControls);
        }

        return PathPatternVerdicts::of($target, array_intersect_key($routePaths, $routeAccessControls)) + array_fill_keys(array_keys($routeAccessControls), false);
    }

    private static function targetNames(string $target, ?string $routeName): bool
    {
        return null !== $routeName && $target === self::ROUTE_TARGET_PREFIX.$routeName;
    }

    /**
     * Whether any alternative of a rule (one per `or:` entry) is limited to no
     * method or to a superset of the route's methods. A route declaring no
     * method answers every method, which no method-limited alternative covers.
     *
     * @param list<list<string>|null> $requiredMethods the methods each alternative of a rule is limited to, as {@see self::methodsRequiredBy()} reads them
     * @param list<string>            $routeMethods    upper-case; empty for every method
     */
    private static function methodsAreCovered(array $requiredMethods, array $routeMethods): bool
    {
        foreach ($requiredMethods as $requiredMethod) {
            if (self::alternativeCoversMethods($requiredMethod, $routeMethods)) {
                return true;
            }
        }

        return false;
    }

    /**
     * One string per alternative: the base rule's items joined, then each
     * `or:` entry with its marker.
     *
     * @param list<string> $roles
     *
     * @return list<string>
     */
    private static function alternativesOf(array $roles): array
    {
        $base = [];
        $orAlternatives = [];
        foreach ($roles as $role) {
            if (str_starts_with($role, 'or: ')) {
                $orAlternatives[] = $role;

                continue;
            }

            $base[] = $role;
        }

        return [implode(', ', $base), ...$orAlternatives];
    }

    /**
     * @return list<string>|null null when the alternative is not limited to some methods
     */
    private static function methodsRequiredBy(string $alternative): ?array
    {
        return 1 === preg_match('/methods:\s*([A-Z|]+)/', $alternative, $matches) ? explode('|', $matches[1]) : null;
    }

    /**
     * @param list<string>|null $alternativeMethods
     * @param list<string>      $routeMethods       upper-case; empty for every method
     */
    private static function alternativeCoversMethods(?array $alternativeMethods, array $routeMethods): bool
    {
        if (null === $alternativeMethods) {
            return true;
        }

        return [] !== $routeMethods && [] === array_diff($routeMethods, $alternativeMethods);
    }
}
