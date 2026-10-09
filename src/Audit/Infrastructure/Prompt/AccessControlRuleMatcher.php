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

use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\RouteAccessControl;

/**
 * Finds the roles of the `security.yaml` `access_control` rule that governs a
 * route: the first rule, in the order the map lists them, whose path pattern
 * matches it or that is keyed by its route name.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class AccessControlRuleMatcher
{
    private const string DELIMITER_CANDIDATES = '#~!%@';

    private const string ROUTE_TARGET_PREFIX = 'route: ';

    /**
     * @param array<string, list<string>> $routeAccessMap
     *
     * @return list<string>|null
     */
    public static function rolesFor(RouteAccessControl $routeAccessControl, array $routeAccessMap): ?array
    {
        foreach ($routeAccessMap as $target => $roles) {
            if (self::methodsAreCovered($roles, $routeAccessControl->routeMethods()) && self::targetGoverns($target, $routeAccessControl)) {
                return $roles;
            }
        }

        return null;
    }

    /**
     * A target is either `route: <name>`
     * ({@see SymfonyYamlSecurityConfigParser::targetOf()}), which governs the
     * route of that name, or the `path` pattern of a rule.
     */
    private static function targetGoverns(string $target, RouteAccessControl $routeAccessControl): bool
    {
        if (str_starts_with($target, self::ROUTE_TARGET_PREFIX)) {
            $routeName = $routeAccessControl->routeName();

            return null !== $routeName && $target === self::ROUTE_TARGET_PREFIX.$routeName;
        }

        $routePath = $routeAccessControl->routePath();

        return null !== $routePath && self::pathPatternMatches($target, $routePath);
    }

    /**
     * Symfony treats the `access_control` `path` as a regular expression, so
     * it is matched as one; a malformed pattern, or one containing every
     * delimiter candidate, simply fails to match rather than throwing.
     */
    private static function pathPatternMatches(string $pattern, string $routePath): bool
    {
        $delimiter = self::delimiterAvoiding($pattern);

        return null !== $delimiter && self::patternMatches($delimiter.$pattern.$delimiter, $routePath);
    }

    /**
     * `preg_match()` raises a warning for a pattern that does not compile
     * (`^/(admin`) and returns false; a warning-throwing error handler
     * (Symfony debug, `mcp:serve`) would abort the prompt build on a pattern
     * taken from the audited repository, so the warning is captured here and
     * the pattern simply matches nothing.
     */
    private static function patternMatches(string $delimitedPattern, string $routePath): bool
    {
        $compilationError = null;
        set_error_handler(static function (int $severity, string $message) use (&$compilationError): bool {
            $compilationError = $message;

            return true;
        });

        try {
            return 1 === preg_match($delimitedPattern, $routePath);
        } finally {
            restore_error_handler();
        }
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
     * entry per rule ({@see SymfonyYamlSecurityConfigParser::recordAccessControlEntry()}),
     * each its own independent alternative Symfony tries in turn — the path
     * is covered for a route if ANY alternative covers it, not just the
     * first.
     *
     * @param list<string> $roles
     * @param list<string> $routeMethods
     */
    private static function methodsAreCovered(array $roles, array $routeMethods): bool
    {
        foreach (self::alternativesOf($roles) as $alternative) {
            if (self::alternativeCoversMethods($alternative, $routeMethods)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Splits the flat, possibly-`or:`-joined roles list into one string per
     * alternative rule: the base rule's own list items joined into a single
     * string, then each `or:` entry on its own. The leading `or: ` marker is
     * left on those entries — {@see self::alternativeCoversMethods()} locates
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
     * @param list<string> $routeMethods
     */
    private static function alternativeCoversMethods(string $alternative, array $routeMethods): bool
    {
        if (1 !== preg_match('/methods:\s*([A-Z|]+)/', $alternative, $matches)) {
            return true;
        }

        if ([] === $routeMethods) {
            return false;
        }

        $ruleMethods = explode('|', $matches[1]);
        $upperRouteMethods = array_map(strtoupper(...), $routeMethods);

        return [] === array_diff($upperRouteMethods, $ruleMethods);
    }

    /**
     * Picks a PCRE delimiter guaranteed absent from the pattern, so the pattern
     * can never prematurely close or corrupt the delimited expression — unlike
     * a fixed delimiter (`#`, `{}`, …), which a sufficiently adversarial pattern
     * can always collide with.
     */
    private static function delimiterAvoiding(string $pattern): ?string
    {
        foreach (str_split(self::DELIMITER_CANDIDATES) as $candidate) {
            if (!str_contains($pattern, $candidate)) {
                return $candidate;
            }
        }

        return null;
    }
}
