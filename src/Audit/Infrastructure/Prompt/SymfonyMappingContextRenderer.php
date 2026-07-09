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
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\SymfonyMapping;

/**
 * Renders the {@see SymfonyMapping} sections of the attacker user message:
 * the route access-control map (with firewall-coverage and LACKS markers),
 * voter coverage, and form bindings. Empty mappings render as empty strings
 * so the surrounding prompt collapses cleanly.
 *
 * @internal not part of the BC promise — see docs/versioning.md
 */
final readonly class SymfonyMappingContextRenderer
{
    private const string DELIMITER_CANDIDATES = '#~!%@';

    public static function renderFirewallRules(SymfonyMapping $symfonyMapping): string
    {
        $firewallRules = $symfonyMapping->firewallRules();
        if ([] === $firewallRules) {
            return '';
        }

        $lines = ['## Firewall Rules'];
        $lines[] = 'Each line names a `security.yaml` firewall and any notable flags. A `security: false` firewall enforces no authentication or access control at all on matching paths — treat every route behind it as unauthenticated regardless of voters or `#[IsGranted]`. A `stateless` firewall carries no session, so session-backed CSRF protection is ineffective there.';
        foreach ($firewallRules as $firewallRule) {
            $lines[] = \sprintf('- %s', self::sanitizeLine($firewallRule));
        }

        return \sprintf("%s\n\n", implode("\n", $lines));
    }

    public static function renderVoterCoverage(SymfonyMapping $symfonyMapping): string
    {
        $voterCapabilities = $symfonyMapping->voterCapabilities();
        if ([] === $voterCapabilities) {
            return '';
        }

        $lines = ['## Voter Coverage'];
        $lines[] = 'Each line summarises a `Voter::supports()` body: the attributes it accepts and the subject types it gates. Use this to spot `#[IsGranted(\'ATTR\', $subject)]` calls referencing an attribute or subject type that no voter actually covers — that is a `missing_voter` finding.';
        foreach ($voterCapabilities as $voterCapability) {
            $attributes = [] === $voterCapability->supportedAttributes() ? '(none)' : implode(',', array_map(self::sanitizeLine(...), $voterCapability->supportedAttributes()));
            $subjects = [] === $voterCapability->supportedSubjects() ? '(none)' : implode(',', array_map(self::sanitizeLine(...), $voterCapability->supportedSubjects()));
            $lines[] = \sprintf('- %s — attributes: [%s] — subjects: [%s] — %s', self::sanitizeLine($voterCapability->className()), $attributes, $subjects, self::sanitizeLine($voterCapability->filePath()));
        }

        return \sprintf("%s\n\n", implode("\n", $lines));
    }

    public static function renderFormBindings(SymfonyMapping $symfonyMapping): string
    {
        $formBindings = $symfonyMapping->formBindings();
        if ([] === $formBindings) {
            return '';
        }

        $lines = ['## Form Bindings'];
        $lines[] = 'Each line records a `$this->createForm(FormType::class)` call site. Cross-reference with the form type to spot mass-assignment vectors (`allow_extra_fields: true`, unbounded `EntityType` choices, missing CSRF on state-changing actions).';
        foreach ($formBindings as $formBinding) {
            $lines[] = \sprintf('- %s::%s — %s', self::sanitizeLine($formBinding->controllerFilePath()), $formBinding->controllerMethod(), $formBinding->formTypeClass());
        }

        return \sprintf("%s\n\n", implode("\n", $lines));
    }

    public static function renderRouteAccessControlMap(SymfonyMapping $symfonyMapping): string
    {
        $routeAccessControls = self::routedControls($symfonyMapping);
        if ([] === $routeAccessControls) {
            return '';
        }

        $routeAccessMap = $symfonyMapping->routeAccessMap();

        $lines = ['## Route Access-Control Map'];
        $lines[] = 'Each line describes a controller action: HTTP method(s), route path, source location, and the access-control surface (class- and method-level `#[IsGranted]`, `denyAccessUnlessGranted()` body calls). A line whose surface is empty is tagged at the end: routes with no enforcement at all carry the LACKS marker — treat those as primary candidates for `broken_access_control` and `missing_voter`. Routes with no attribute or body check that nonetheless match a `security.yaml` `access_control` rule on their path carry a firewall-covered marker listing the gating roles — the firewall already protects them, so do NOT report `broken_access_control` there unless the gating role is too permissive for the action.';

        foreach ($routeAccessControls as $routeAccessControl) {
            $methods = [] === $routeAccessControl->routeMethods() ? 'ANY' : implode(',', array_map(self::sanitizeLine(...), $routeAccessControl->routeMethods()));
            $path = self::sanitizeLine($routeAccessControl->routePath() ?? '(unresolved)');
            $checks = self::accessCheckLabelsFor($routeAccessControl);
            $checkLabel = self::checkLabelFor($checks, $routeAccessControl, $routeAccessMap);
            $lines[] = \sprintf('- %s %s — %s::%s — %s', $methods, $path, self::sanitizeLine($routeAccessControl->filePath()), $routeAccessControl->methodName(), $checkLabel);
        }

        return \sprintf("%s\n\n", implode("\n", $lines));
    }

    /**
     * @return list<string>
     */
    private static function accessCheckLabelsFor(RouteAccessControl $routeAccessControl): array
    {
        $checks = [];
        if ($routeAccessControl->classHasIsGranted()) {
            $checks[] = 'class:#[IsGranted]';
        }

        if ([] !== $routeAccessControl->methodLevelIsGranted()) {
            $checks[] = \sprintf('method:#[IsGranted(%s)]', implode(',', array_map(self::sanitizeLine(...), $routeAccessControl->methodLevelIsGranted())));
        }

        if ([] === $routeAccessControl->methodLevelIsGranted() && $routeAccessControl->methodHasIsGrantedAttribute()) {
            $checks[] = 'method:#[IsGranted(unresolved)]';
        }

        if ($routeAccessControl->methodHasDenyAccess()) {
            $checks[] = 'body:denyAccessUnlessGranted()';
        }

        return $checks;
    }

    /**
     * `PhpParserControllerAccessControlParser` emits a `RouteAccessControl`
     * entry for every public method on a controller-like class, not just its
     * routed actions — a plain constructor or helper method still gets one,
     * with `hasRouteAttribute() === false`. Rendering those would tag every
     * such method `LACKS_ACCESS_CHECK` even though it is not an HTTP action
     * at all, injecting a false-positive `broken_access_control` candidate
     * for virtually every controller (which almost always has a
     * constructor).
     *
     * @return list<RouteAccessControl>
     */
    private static function routedControls(SymfonyMapping $symfonyMapping): array
    {
        return array_values(array_filter(
            $symfonyMapping->routeAccessControls(),
            static fn (RouteAccessControl $routeAccessControl): bool => $routeAccessControl->hasRouteAttribute(),
        ));
    }

    /**
     * @param list<string>                $checks
     * @param array<string, list<string>> $routeAccessMap
     */
    private static function checkLabelFor(array $checks, RouteAccessControl $routeAccessControl, array $routeAccessMap): string
    {
        if ([] !== $checks) {
            return implode(' + ', $checks);
        }

        $firewallRoles = self::firewallRolesForPath($routeAccessControl->routePath(), $routeAccessControl->routeMethods(), $routeAccessMap)
            ?? self::firewallRolesForRouteName($routeAccessControl->routeName(), $routeAccessControl->routeMethods(), $routeAccessMap);
        if (null !== $firewallRoles) {
            return \sprintf('COVERED_BY access_control[%s]', implode(',', array_map(self::sanitizeLine(...), $firewallRoles)));
        }

        return 'LACKS_ACCESS_CHECK';
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
    private static function firewallRolesForPath(?string $routePath, array $routeMethods, array $routeAccessMap): ?array
    {
        if (null === $routePath) {
            return null;
        }

        foreach ($routeAccessMap as $pattern => $roles) {
            if (!self::methodsAreCovered($roles, $routeMethods)) {
                continue;
            }

            $delimiter = self::delimiterAvoiding($pattern);
            if (null !== $delimiter && 1 === preg_match($delimiter.$pattern.$delimiter, $routePath)) {
                return $roles;
            }
        }

        return null;
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
     * Splits the flat, possibly-`or:`-joined roles list back into one string
     * per alternative rule. The base rule's own list items are re-joined the
     * same way an `or:` one already is, so both are checked identically by
     * {@see self::alternativeCoversMethods()}.
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
                $orAlternatives[] = substr($role, \strlen('or: '));

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
    private static function firewallRolesForRouteName(?string $routeName, array $routeMethods, array $routeAccessMap): ?array
    {
        if (null === $routeName) {
            return null;
        }

        $roles = $routeAccessMap[\sprintf('route: %s', $routeName)] ?? null;

        return null !== $roles && self::methodsAreCovered($roles, $routeMethods) ? $roles : null;
    }

    /**
     * Every value rendered here — a file path, a class name, or a raw
     * `#[IsGranted("...")]` attribute-argument string literal collected by
     * the AST parsers — comes from the audited (untrusted) project, not from
     * us. A raw embedded newline would let a crafted value forge a fake
     * `##`-prefixed section (e.g. the literal `## Source Code` heading
     * further down the attacker prompt) as unguarded top-level prompt text.
     */
    private static function sanitizeLine(string $value): string
    {
        return str_replace("\n", ' ', $value);
    }
}
