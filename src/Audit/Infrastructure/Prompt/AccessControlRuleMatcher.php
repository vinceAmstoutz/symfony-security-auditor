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
 * Finds the roles of the `security.yaml` `access_control` rule that governs a
 * route: the first rule, in the order the map lists them, whose path pattern
 * matches it or that is keyed by its route name. Symfony applies the first
 * rule, in the order they are declared, that matches a request, and a rule
 * without roles or an expression checks nothing, so a route such a rule
 * matches first has no governing roles.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class AccessControlRuleMatcher
{
    private const string ROUTE_TARGET_PREFIX = 'route: ';

    /**
     * A rule whose path pattern cannot be decided for the route, before any
     * rule governs it, leaves the answer open: that rule may be the one
     * Symfony applies, so the route is neither covered nor uncovered.
     *
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
     * The roles {@see self::rolesFor()} finds for each of several routes the
     * same rules govern, each rule matched against every route it has yet to
     * decide before the next one is read, so its path pattern is compiled
     * once for all of them. The map is read only for the routes the rules, in
     * the order they are declared, leave open.
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
     * Walks the rules in the order they are declared, passing those that do
     * not decide a route: the first that does checks nothing, or checks
     * something and matches all of its requests. A rule whose path pattern
     * cannot be decided for the route leaves the answer open.
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
     * A target is either `route: <name>`
     * ({@see SymfonyYamlSecurityConfigParser::targetOf()}), which governs the
     * route of that name, or the `path` pattern of a rule, which governs no
     * route without a path.
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
     * A rule's `methods: GET|POST`-style requirement (recorded verbatim by
     * {@see SymfonyYamlSecurityConfigParser}) only actually governs a route
     * whose own declared methods are a subset of it — Symfony evaluates
     * `access_control` rules in order and skips to the next one on a method
     * mismatch, it does not treat a path-only match as sufficient. A route
     * with no declared methods answers to every HTTP verb, so a
     * method-restricted rule can never fully cover it. A second (or third, …)
     * `access_control` rule for the same path is recorded as one `or: ...`
     * entry per rule ({@see SymfonyYamlSecurityConfigParser::accessControlOf()}),
     * each its own independent alternative Symfony tries in turn — the path
     * is covered for a route if ANY alternative covers it, not just the
     * first.
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
     * Splits the flat, possibly-`or:`-joined roles list into one string per
     * alternative rule: the base rule's own list items joined into a single
     * string, then each `or:` entry on its own. The leading `or: ` marker is
     * left on those entries — {@see self::methodsRequiredBy()} locates
     * the `methods:` requirement anywhere in the string, so the marker never
     * affects the check.
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
     * Extracts the alternative's own `methods: GET|POST` requirement via a
     * targeted regex rather than splitting the comma-joined alternative
     * string apart — `listedRequirements()` already uses `, ` as the
     * separator *within* an `ips: ...` requirement, so a generic split
     * would misparse an alternative combining `ips:` and `methods:`. HTTP
     * method names are always uppercase ASCII letters, which no other
     * requirement value can contain, so the match is unambiguous regardless
     * of what precedes or follows it.
     *
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
