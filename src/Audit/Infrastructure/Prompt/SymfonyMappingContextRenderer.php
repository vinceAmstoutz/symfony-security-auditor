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
 * the route access-control map, voter coverage and form bindings. An empty
 * mapping renders as an empty string.
 *
 * @internal not part of the BC promise, see docs/versioning.md
 */
final readonly class SymfonyMappingContextRenderer
{
    /**
     * The `access_control` roles that grant access to everyone, including the
     * `PUBLIC` marker {@see SymfonyYamlSecurityConfigParser} records for a
     * rule with no requirement. A route they govern is never `COVERED_BY`.
     *
     * @var list<string>
     */
    private const array PUBLIC_ACCESS_PSEUDO_ROLES = ['PUBLIC_ACCESS', 'IS_AUTHENTICATED_ANONYMOUSLY', 'PUBLIC'];

    private const int MAX_LISTED_VOTER_ITEMS = 100;

    private const int MAX_LISTED_VOTER_BYTES = 2048;

    private const int MAX_LISTED_ROUTE_GUARDS = 10;

    private const int MAX_LISTED_ROUTE_GUARD_BYTES = 512;

    private const int MAX_LISTED_RULE_REQUIREMENTS = 20;

    private const int MAX_LISTED_RULE_REQUIREMENT_BYTES = 1024;

    private const int MAX_LISTED_FIREWALL_RULES = 50;

    private const int MAX_LISTED_FIREWALL_RULE_BYTES = 2048;

    private const int MAX_LISTED_UNREADABLE_FILES = 10;

    private const int MAX_LISTED_UNREADABLE_FILE_BYTES = 2048;

    public static function renderUnreadableConfiguration(SymfonyMapping $symfonyMapping): string
    {
        $unreadableFiles = $symfonyMapping->unreadableConfigurationFiles();
        if ([] === $unreadableFiles) {
            return '';
        }

        $lines = ['## Unread Security Configuration'];
        $lines[] = "The production application loads these configuration files, but the audit could not read them (too large, too deeply nested, not valid YAML, or beyond what the audit reads), so the firewalls and `access_control` rules they may hold are missing from this mapping: a route's access-control marker may be wrong.";
        foreach (self::itemsWithOmissionNotice($unreadableFiles, self::MAX_LISTED_UNREADABLE_FILES, self::MAX_LISTED_UNREADABLE_FILE_BYTES) as $unreadableFile) {
            $lines[] = \sprintf('- %s', $unreadableFile);
        }

        return \sprintf("%s\n\n", implode("\n", $lines));
    }

    public static function renderFirewallRules(SymfonyMapping $symfonyMapping): string
    {
        $applicationFirewallRules = self::applicationFirewallRules($symfonyMapping);
        $firewallRules = [...$symfonyMapping->toApplicationSecurityMap()->perimeterRules(), ...$applicationFirewallRules];
        if ([] === $firewallRules) {
            return '';
        }

        $lines = ['## Firewall Rules'];
        $lines[] = 'Each line names a `security.yaml` firewall and any notable flags. A `security: false` firewall enforces no authentication or access control at all on matching paths — treat every route behind it as unauthenticated regardless of voters or `#[IsGranted]`. A `stateless` firewall carries no session, so session-backed CSRF protection is ineffective there.';
        if ([] !== $applicationFirewallRules) {
            $lines[] = 'A line ending with a folder names a firewall of the monorepo application in that folder; it applies to the routes of that application only.';
        }

        foreach (self::itemsWithOmissionNotice($firewallRules, self::MAX_LISTED_FIREWALL_RULES, self::MAX_LISTED_FIREWALL_RULE_BYTES) as $firewallRule) {
            $lines[] = \sprintf('- %s', $firewallRule);
        }

        return \sprintf("%s\n\n", implode("\n", $lines));
    }

    /**
     * @return list<string>
     */
    private static function applicationFirewallRules(SymfonyMapping $symfonyMapping): array
    {
        $applicationFirewallRules = [];
        foreach ($symfonyMapping->applicationAccessControls() as $applicationFolder => $applicationAccessControl) {
            foreach ($applicationAccessControl->firewallRules as $firewallRule) {
                $applicationFirewallRules[] = \sprintf('%s — %s', $firewallRule, $applicationFolder);
            }
        }

        return $applicationFirewallRules;
    }

    public static function renderVoterCoverage(SymfonyMapping $symfonyMapping): string
    {
        $voterCapabilities = $symfonyMapping->toApplicationSecurityMap()->authorizationRules();
        if ([] === $voterCapabilities) {
            return '';
        }

        $lines = ['## Voter Coverage'];
        $lines[] = 'Each line summarises a `Voter::supports()` body: the attributes it accepts and the subject types it gates. Use this to spot `#[IsGranted(\'ATTR\', $subject)]` calls referencing an attribute or subject type that no voter actually covers — that is a `missing_voter` finding.';
        foreach ($voterCapabilities as $voterCapability) {
            $attributes = self::cappedList($voterCapability->supportedAttributes(), self::MAX_LISTED_VOTER_ITEMS, self::MAX_LISTED_VOTER_BYTES);
            $subjects = self::cappedList($voterCapability->supportedSubjects(), self::MAX_LISTED_VOTER_ITEMS, self::MAX_LISTED_VOTER_BYTES);
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

        $lines = ['## Route Access-Control Map'];
        $lines[] = "Each line describes a controller action: HTTP method(s), route path, source location, and the access-control surface (class- and method-level `#[IsGranted]`, `denyAccessUnlessGranted()` body calls). A line whose surface is empty is tagged at the end: routes with no enforcement at all carry the LACKS marker — treat those as primary candidates for `broken_access_control` and `missing_voter`. Routes with no attribute or body check whose path matches an `access_control` rule of the production `security.yaml` carry a firewall-covered marker listing the gating roles. That coverage is read from the repository's YAML, not verified against the running application, so it lowers the priority of `broken_access_control` there without ruling it out: still report it when the rule may not apply to the action or the gating role is too permissive for it.";

        $firewallRoles = self::firewallRolesOf($symfonyMapping, $routeAccessControls);
        foreach ($routeAccessControls as $index => $routeAccessControl) {
            $methods = [] === $routeAccessControl->routeMethods() ? 'ANY' : implode(',', array_map(self::sanitizeLine(...), $routeAccessControl->routeMethods()));
            $path = self::sanitizeLine($routeAccessControl->routePath() ?? '(unresolved)');
            $checks = self::accessCheckLabelsFor($routeAccessControl);
            $checkLabel = self::checkLabelFor($checks, $firewallRoles[$index]);
            $lines[] = \sprintf('- %s %s — %s::%s — %s', $methods, $path, self::sanitizeLine($routeAccessControl->filePath()), $routeAccessControl->methodName(), $checkLabel);
        }

        return \sprintf("%s\n\n", implode("\n", $lines));
    }

    /**
     * The roles of the `access_control` rule that governs each route, matched
     * against the rules of the route's own application.
     *
     * @param list<RouteAccessControl> $routeAccessControls
     *
     * @return array<int, list<string>|false|null> by the index of each route
     */
    private static function firewallRolesOf(SymfonyMapping $symfonyMapping, array $routeAccessControls): array
    {
        $routesByApplication = [];
        foreach ($routeAccessControls as $index => $routeAccessControl) {
            $routesByApplication[$symfonyMapping->applicationFolderFor($routeAccessControl->filePath()) ?? ''][$index] = $routeAccessControl;
        }

        $firewallRoles = [];
        foreach ($routesByApplication as $routes) {
            $controllerFilePath = $routes[array_key_first($routes)]->filePath();
            $firewallRoles += AccessControlRuleMatcher::rolesForEach($routes, $symfonyMapping->routeAccessMapFor($controllerFilePath), $symfonyMapping->accessControlRulesFor($controllerFilePath));
        }

        return $firewallRoles;
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
            $checks[] = \sprintf('method:#[IsGranted(%s)]', self::cappedList(array_values(array_unique($routeAccessControl->methodLevelIsGranted())), self::MAX_LISTED_ROUTE_GUARDS, self::MAX_LISTED_ROUTE_GUARD_BYTES));
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
     * Leaves out the public methods that are no routed action, such as a
     * constructor, which would otherwise read `LACKS_ACCESS_CHECK`.
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
     * @param list<string> $values
     */
    private static function cappedList(array $values, int $maxItems, int $maxBytes): string
    {
        if ([] === $values) {
            return '(none)';
        }

        return implode(',', self::itemsWithOmissionNotice($values, $maxItems, $maxBytes));
    }

    /**
     * Cuts the list at a number of items and of bytes, ending a cut list with
     * `… and N more`.
     *
     * @param list<string> $values
     *
     * @return list<string>
     */
    private static function itemsWithOmissionNotice(array $values, int $maxItems, int $maxBytes): array
    {
        $listed = self::itemsWithinCaps($values, $maxItems, $maxBytes);
        $omitted = \count($values) - \count($listed);
        if (0 < $omitted) {
            $listed[] = \sprintf('… and %d more', $omitted);
        }

        return $listed;
    }

    /**
     * @param list<string> $values
     *
     * @return list<string>
     */
    private static function itemsWithinCaps(array $values, int $maxItems, int $maxBytes): array
    {
        $listed = [];
        $bytes = 0;
        foreach ($values as $value) {
            $item = self::sanitizeLine($value);
            $itemBytes = \strlen($item) + ([] === $listed ? 0 : 1);
            if ($maxItems === \count($listed) || $maxBytes < $bytes + $itemBytes) {
                break;
            }

            $listed[] = $item;
            $bytes += $itemBytes;
        }

        return $listed;
    }

    /**
     * @param list<string>            $checks
     * @param list<string>|false|null $firewallRoles
     */
    private static function checkLabelFor(array $checks, array|false|null $firewallRoles): string
    {
        if ([] !== $checks) {
            return implode(' + ', $checks);
        }

        return self::firewallCoverageLabel($firewallRoles);
    }

    /**
     * Tags a route no rule governs, or one whose rule grants
     * {@see self::PUBLIC_ACCESS_PSEUDO_ROLES public access}, `LACKS_ACCESS_CHECK`
     * and one whose rule cannot be told unknown, never covered.
     *
     * @param list<string>|false|null $firewallRoles
     */
    private static function firewallCoverageLabel(array|false|null $firewallRoles): string
    {
        if (false === $firewallRoles) {
            return 'UNKNOWN_ACCESS_CONTROL (an access_control path pattern was too costly to evaluate against this route)';
        }

        if (null === $firewallRoles || self::grantsPublicAccess($firewallRoles)) {
            return 'LACKS_ACCESS_CHECK';
        }

        return \sprintf('COVERED_BY access_control[%s]', implode(',', self::itemsWithOmissionNotice($firewallRoles, self::MAX_LISTED_RULE_REQUIREMENTS, self::MAX_LISTED_RULE_REQUIREMENT_BYTES)));
    }

    /**
     * @param list<string> $firewallRoles
     */
    private static function grantsPublicAccess(array $firewallRoles): bool
    {
        $tokens = explode(', ', str_replace('or: ', '', implode(', ', $firewallRoles)));

        return [] !== array_intersect($tokens, self::PUBLIC_ACCESS_PSEUDO_ROLES);
    }

    /**
     * Folds line breaks, so a value from the audited project cannot forge a
     * `##` section of the prompt.
     */
    private static function sanitizeLine(string $value): string
    {
        return str_replace(["\r", "\n"], ' ', $value);
    }
}
