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
 * route: the first rule whose path pattern matches it, else the rule keyed by
 * its route name.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class AccessControlRuleMatcher
{
    private const string BACKTRACK_LIMIT = '10000';

    private const string DELIMITER_CANDIDATES = '#~!%@';

    /**
     * @param array<string, list<string>> $routeAccessMap
     *
     * @return list<string>|null
     */
    public static function rolesFor(RouteAccessControl $routeAccessControl, array $routeAccessMap): ?array
    {
        return self::rolesForPath($routeAccessControl->routePath(), $routeAccessControl->routeMethods(), $routeAccessMap)
            ?? self::rolesForRouteName($routeAccessControl->routeName(), $routeAccessControl->routeMethods(), $routeAccessMap);
    }

    /**
     * Returns the roles of the first `security.yaml` `access_control` rule whose
     * path pattern matches the route, or null when none matches. Symfony treats
     * the `access_control` `path` as a regular expression, so it is matched as
     * one; a malformed pattern, or one containing every delimiter candidate,
     * simply fails to match rather than throwing.
     *
     * @param list<string>                $routeMethods
     * @param array<string, list<string>> $routeAccessMap
     *
     * @return list<string>|null
     */
    private static function rolesForPath(?string $routePath, array $routeMethods, array $routeAccessMap): ?array
    {
        if (null === $routePath) {
            return null;
        }

        foreach ($routeAccessMap as $pattern => $roles) {
            if (!self::methodsAreCovered($roles, $routeMethods)) {
                continue;
            }

            $delimiter = self::delimiterAvoiding($pattern);
            if (null !== $delimiter && self::patternMatches($delimiter.$pattern.$delimiter, $routePath)) {
                return $roles;
            }
        }

        return null;
    }

    /**
     * `preg_match()` raises a warning for a pattern that does not compile
     * (`^/(admin`) and returns false; a warning-throwing error handler
     * (Symfony debug, `mcp:serve`) would abort the prompt build on a pattern
     * taken from the audited repository, so the warning is captured here and
     * the pattern simply matches nothing. A pattern from that repository can
     * also backtrack catastrophically (`^/(a+)+$`), so the evaluation runs
     * under {@see self::BACKTRACK_LIMIT}: a rule that exhausts it matches
     * nothing either.
     */
    private static function patternMatches(string $delimitedPattern, string $routePath): bool
    {
        $compilationError = null;
        set_error_handler(static function (int $severity, string $message) use (&$compilationError): bool {
            $compilationError = $message;

            return true;
        });

        $previousLimit = ini_set('pcre.backtrack_limit', self::BACKTRACK_LIMIT);

        try {
            return 1 === preg_match($delimitedPattern, $routePath);
        } finally {
            ini_set('pcre.backtrack_limit', $previousLimit);
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

    /**
     * Returns the roles of the `security.yaml` `access_control` rule keyed by
     * `route: <name>` — {@see SymfonyYamlSecurityConfigParser::targetOf()} —
     * matching this route's name, or null when the route has no name or no
     * such rule exists.
     *
     * @param list<string>                $routeMethods
     * @param array<string, list<string>> $routeAccessMap
     *
     * @return list<string>|null
     */
    private static function rolesForRouteName(?string $routeName, array $routeMethods, array $routeAccessMap): ?array
    {
        if (null === $routeName) {
            return null;
        }

        $roles = $routeAccessMap[\sprintf('route: %s', $routeName)] ?? null;

        return null !== $roles && self::methodsAreCovered($roles, $routeMethods) ? $roles : null;
    }
}
