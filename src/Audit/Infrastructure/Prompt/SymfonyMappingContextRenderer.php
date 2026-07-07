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
        $routeAccessControls = $symfonyMapping->routeAccessControls();
        if ([] === $routeAccessControls) {
            return '';
        }

        $routeAccessMap = $symfonyMapping->routeAccessMap();

        $lines = ['## Route Access-Control Map'];
        $lines[] = 'Each line describes a controller action: HTTP method(s), route path, source location, and the access-control surface (class- and method-level `#[IsGranted]`, `denyAccessUnlessGranted()` body calls). A line whose surface is empty is tagged at the end: routes with no enforcement at all carry the LACKS marker — treat those as primary candidates for `broken_access_control` and `missing_voter`. Routes with no attribute or body check that nonetheless match a `security.yaml` `access_control` rule on their path carry a firewall-covered marker listing the gating roles — the firewall already protects them, so do NOT report `broken_access_control` there unless the gating role is too permissive for the action.';

        foreach ($routeAccessControls as $routeAccessControl) {
            $methods = [] === $routeAccessControl->routeMethods() ? 'ANY' : implode(',', $routeAccessControl->routeMethods());
            $path = $routeAccessControl->routePath() ?? '(unresolved)';
            $checks = [];
            if ($routeAccessControl->classHasIsGranted()) {
                $checks[] = 'class:#[IsGranted]';
            }

            if ([] !== $routeAccessControl->methodLevelIsGranted()) {
                $checks[] = \sprintf('method:#[IsGranted(%s)]', implode(',', array_map(self::sanitizeLine(...), $routeAccessControl->methodLevelIsGranted())));
            }

            if ($routeAccessControl->methodHasDenyAccess()) {
                $checks[] = 'body:denyAccessUnlessGranted()';
            }

            $checkLabel = self::checkLabelFor($checks, $routeAccessControl, $routeAccessMap);
            $lines[] = \sprintf('- %s %s — %s::%s — %s', $methods, $path, self::sanitizeLine($routeAccessControl->filePath()), $routeAccessControl->methodName(), $checkLabel);
        }

        return \sprintf("%s\n\n", implode("\n", $lines));
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

        $firewallRoles = self::firewallRolesForPath($routeAccessControl->routePath(), $routeAccessMap)
            ?? self::firewallRolesForRouteName($routeAccessControl->routeName(), $routeAccessMap);
        if (null !== $firewallRoles) {
            return \sprintf('COVERED_BY access_control[%s]', implode(',', $firewallRoles));
        }

        return 'LACKS_ACCESS_CHECK';
    }

    /**
     * Returns the roles of the first `security.yaml` `access_control` rule whose
     * path pattern matches the route, or null when none matches. Symfony treats
     * the `access_control` `path` as a regular expression, so it is matched as
     * one; a malformed pattern simply fails to match rather than throwing.
     *
     * @param array<string, list<string>> $routeAccessMap
     *
     * @return list<string>|null
     */
    private static function firewallRolesForPath(?string $routePath, array $routeAccessMap): ?array
    {
        if (null === $routePath) {
            return null;
        }

        foreach ($routeAccessMap as $pattern => $roles) {
            if (1 === preg_match(\sprintf('#%s#', $pattern), $routePath)) {
                return $roles;
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
     * @param array<string, list<string>> $routeAccessMap
     *
     * @return list<string>|null
     */
    private static function firewallRolesForRouteName(?string $routeName, array $routeAccessMap): ?array
    {
        if (null === $routeName) {
            return null;
        }

        return $routeAccessMap[\sprintf('route: %s', $routeName)] ?? null;
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
