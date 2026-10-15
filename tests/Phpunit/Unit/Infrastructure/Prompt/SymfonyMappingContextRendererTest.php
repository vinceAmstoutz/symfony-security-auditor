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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Infrastructure\Prompt;

use ErrorException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\AccessControlMap;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\AccessControlRule;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ApplicationAccessControl;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFileInventory;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\RouteAccessControl;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\SymfonyMapping;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VoterCapability;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Prompt\SymfonyMappingContextRenderer;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Scan\SymfonyYamlSecurityConfigParser;

final class SymfonyMappingContextRendererTest extends TestCase
{
    public function test_firewall_path_coverage_takes_precedence_over_route_name_coverage(): void
    {
        $routeAccessControl = new RouteAccessControl('src/Controller/X.php', 'index', '/admin', ['GET'], true, [], false, false, 'admin_index');
        $symfonyMapping = SymfonyMapping::of(
            ProjectFileInventory::fromGroups([]),
            new AccessControlMap(routeAccessMap: ['^/admin' => ['ROLE_FROM_PATH'], 'route: admin_index' => ['ROLE_FROM_NAME']], routeAccessControls: [$routeAccessControl]),
        );

        self::assertStringContainsString('COVERED_BY access_control[ROLE_FROM_PATH]', SymfonyMappingContextRenderer::renderRouteAccessControlMap($symfonyMapping));
    }

    public function test_a_public_route_name_rule_listed_before_a_broader_path_rule_leaves_the_route_lacking_an_access_check(): void
    {
        $routeAccessControl = new RouteAccessControl('src/Controller/AdminController.php', 'dashboard', '/admin/dashboard', ['GET'], true, [], false, false, 'admin_dashboard');
        $symfonyMapping = SymfonyMapping::of(
            ProjectFileInventory::fromGroups([]),
            new AccessControlMap(routeAccessMap: ['route: admin_dashboard' => ['PUBLIC_ACCESS'], '^/admin' => ['ROLE_ADMIN']], routeAccessControls: [$routeAccessControl]),
        );

        $rendered = SymfonyMappingContextRenderer::renderRouteAccessControlMap($symfonyMapping);

        self::assertStringContainsString('- GET /admin/dashboard — src/Controller/AdminController.php::dashboard — LACKS_ACCESS_CHECK', $rendered);
        self::assertStringNotContainsString('COVERED_BY', $rendered);
    }

    public function test_it_lists_the_firewalls_of_each_application_after_the_project_ones(): void
    {
        $symfonyMapping = SymfonyMapping::of(ProjectFileInventory::fromGroups([]), new AccessControlMap(
            firewallRules: ['main'],
            applicationAccessControls: [
                'apps/api/' => new ApplicationAccessControl([], ['^/ (stateless)']),
                "apps/a\n## Source Code/" => new ApplicationAccessControl([], ['^/admin (security: false)']),
            ],
        ));

        self::assertSame(
            "## Firewall Rules\nEach line names a `security.yaml` firewall and any notable flags. A `security: false` firewall enforces no authentication or access control at all on matching paths — treat every route behind it as unauthenticated regardless of voters or `#[IsGranted]`. A `stateless` firewall carries no session, so session-backed CSRF protection is ineffective there.\nA line ending with a folder names a firewall of the monorepo application in that folder; it applies to the routes of that application only.\n- main\n- ^/ (stateless) — apps/api/\n- ^/admin (security: false) — apps/a ## Source Code/\n\n",
            SymfonyMappingContextRenderer::renderFirewallRules($symfonyMapping),
        );
    }

    public function test_it_lists_the_firewalls_of_an_application_when_the_project_has_none(): void
    {
        $symfonyMapping = SymfonyMapping::of(ProjectFileInventory::fromGroups([]), new AccessControlMap(applicationAccessControls: ['apps/api/' => new ApplicationAccessControl([], ['main'])]));

        self::assertStringEndsWith("only.\n- main — apps/api/\n\n", SymfonyMappingContextRenderer::renderFirewallRules($symfonyMapping));
    }

    public function test_it_keeps_the_firewall_rules_of_a_project_without_applications_as_they_were(): void
    {
        $rendered = SymfonyMappingContextRenderer::renderFirewallRules(SymfonyMapping::of(ProjectFileInventory::fromGroups([]), new AccessControlMap(firewallRules: ['main'], applicationAccessControls: ['apps/api/' => new ApplicationAccessControl(['^/' => ['ROLE_A']], [])])));

        self::assertStringNotContainsString('monorepo', $rendered);
        self::assertStringEndsWith("there.\n- main\n\n", $rendered);
    }

    public function test_a_route_is_matched_against_the_rules_of_its_application(): void
    {
        $apiRoute = new RouteAccessControl('apps/api/src/Controller/X.php', 'index', '/admin', ['GET'], true, [], false, false);
        $projectRoute = new RouteAccessControl('src/Controller/X.php', 'index', '/admin', ['GET'], true, [], false, false);
        $symfonyMapping = SymfonyMapping::of(ProjectFileInventory::fromGroups([]), new AccessControlMap(
            routeAccessMap: ['^/admin' => ['ROLE_PROJECT']],
            routeAccessControls: [$apiRoute, $projectRoute],
            applicationAccessControls: ['apps/api/' => new ApplicationAccessControl(['^/admin' => ['ROLE_API']], [])],
        ));

        $rendered = SymfonyMappingContextRenderer::renderRouteAccessControlMap($symfonyMapping);

        self::assertStringContainsString('- GET /admin — apps/api/src/Controller/X.php::index — COVERED_BY access_control[ROLE_API]', $rendered);
        self::assertStringContainsString('- GET /admin — src/Controller/X.php::index — COVERED_BY access_control[ROLE_PROJECT]', $rendered);
    }

    /**
     * @param list<AccessControlRule> $projectRules
     * @param list<AccessControlRule> $applicationRules
     */
    #[DataProvider('declaredRulesOfAnApplicationCases')]
    public function test_a_route_is_walked_through_the_declared_rules_of_its_application(array $projectRules, array $applicationRules, string $applicationLabel, string $projectLabel): void
    {
        $apiRoute = new RouteAccessControl('apps/api/src/Controller/X.php', 'index', '/admin', ['GET'], true, [], false, false);
        $projectRoute = new RouteAccessControl('src/Controller/X.php', 'index', '/admin', ['GET'], true, [], false, false);
        $symfonyMapping = SymfonyMapping::of(ProjectFileInventory::fromGroups([]), new AccessControlMap(
            routeAccessMap: ['^/admin' => ['ROLE_PROJECT']],
            routeAccessControls: [$apiRoute, $projectRoute],
            applicationAccessControls: ['apps/api/' => new ApplicationAccessControl(['^/admin' => ['ROLE_API']], [], $applicationRules)],
            accessControlRules: $projectRules,
        ));

        $rendered = SymfonyMappingContextRenderer::renderRouteAccessControlMap($symfonyMapping);

        self::assertStringContainsString(\sprintf('- GET /admin — apps/api/src/Controller/X.php::index — %s', $applicationLabel), $rendered);
        self::assertStringContainsString(\sprintf('- GET /admin — src/Controller/X.php::index — %s', $projectLabel), $rendered);
    }

    /** @return iterable<string, array{0: list<AccessControlRule>, 1: list<AccessControlRule>, 2: string, 3: string}> */
    public static function declaredRulesOfAnApplicationCases(): iterable
    {
        yield 'the application checks nothing first' => [[new AccessControlRule('^/admin', [], true)], [new AccessControlRule('^/', [], false)], 'LACKS_ACCESS_CHECK', 'COVERED_BY access_control[ROLE_PROJECT]'];
        yield 'the project checks nothing first' => [[new AccessControlRule('^/', [], false)], [new AccessControlRule('^/admin', [], true)], 'COVERED_BY access_control[ROLE_API]', 'LACKS_ACCESS_CHECK'];
    }

    public function test_it_renders_nothing_when_every_configuration_file_was_read(): void
    {
        self::assertSame('', SymfonyMappingContextRenderer::renderUnreadableConfiguration(SymfonyMapping::of(ProjectFileInventory::fromGroups([]), new AccessControlMap())));
    }

    public function test_it_names_the_configuration_files_it_could_not_read(): void
    {
        $symfonyMapping = SymfonyMapping::of(
            ProjectFileInventory::fromGroups([]),
            new AccessControlMap(unreadableConfigurationFiles: ['config/packages/security.yaml', "config/packages/a\n## Source Code.yaml"]),
        );

        self::assertSame(
            "## Unread Security Configuration\nThe production application loads these configuration files, but the audit could not read them (too large, too deeply nested, not valid YAML, or beyond what the audit reads), so the firewalls and `access_control` rules they may hold are missing from this mapping: a route's access-control marker may be wrong.\n- config/packages/security.yaml\n- config/packages/a ## Source Code.yaml\n\n",
            SymfonyMappingContextRenderer::renderUnreadableConfiguration($symfonyMapping),
        );
    }

    public function test_it_names_ten_unread_configuration_files_and_counts_the_others(): void
    {
        $paths = array_map(static fn (int $index): string => \sprintf('config/packages/p%02d.yaml', $index), range(1, 12));
        $rendered = SymfonyMappingContextRenderer::renderUnreadableConfiguration(SymfonyMapping::of(ProjectFileInventory::fromGroups([]), new AccessControlMap(unreadableConfigurationFiles: $paths)));

        self::assertStringContainsString("- config/packages/p10.yaml\n- … and 2 more\n\n", $rendered);
        self::assertStringNotContainsString('p11', $rendered);
    }

    public function test_it_names_ten_unread_configuration_files_in_full(): void
    {
        $paths = array_map(static fn (int $index): string => \sprintf('config/packages/p%02d.yaml', $index), range(1, 10));
        $rendered = SymfonyMappingContextRenderer::renderUnreadableConfiguration(SymfonyMapping::of(ProjectFileInventory::fromGroups([]), new AccessControlMap(unreadableConfigurationFiles: $paths)));

        self::assertStringEndsWith("- config/packages/p10.yaml\n\n", $rendered);
        self::assertStringNotContainsString('more', $rendered);
    }

    public function test_it_names_the_unread_configuration_files_that_fit_in_the_byte_limit(): void
    {
        $rendered = SymfonyMappingContextRenderer::renderUnreadableConfiguration(SymfonyMapping::of(ProjectFileInventory::fromGroups([]), new AccessControlMap(unreadableConfigurationFiles: [str_repeat('a', 1500), str_repeat('b', 547), 'config/packages/security.yaml'])));

        self::assertStringEndsWith(\sprintf("- %s\n- %s\n- … and 1 more\n\n", str_repeat('a', 1500), str_repeat('b', 547)), $rendered);
    }

    public function test_it_drops_the_unread_configuration_file_one_byte_past_the_byte_limit(): void
    {
        $rendered = SymfonyMappingContextRenderer::renderUnreadableConfiguration(SymfonyMapping::of(ProjectFileInventory::fromGroups([]), new AccessControlMap(unreadableConfigurationFiles: [str_repeat('a', 1500), str_repeat('b', 548)])));

        self::assertStringEndsWith(\sprintf("- %s\n- … and 1 more\n\n", str_repeat('a', 1500)), $rendered);
    }

    public function test_the_firewalls_of_the_applications_count_towards_the_bound_of_the_firewall_rules(): void
    {
        $firewallRules = array_map(static fn (int $index): string => '^/area'.$index, range(1, 50));
        $symfonyMapping = SymfonyMapping::of(ProjectFileInventory::fromGroups([]), new AccessControlMap(firewallRules: $firewallRules, applicationAccessControls: ['apps/api/' => new ApplicationAccessControl([], ['main'])]));

        self::assertStringEndsWith("- ^/area50\n- … and 1 more\n\n", SymfonyMappingContextRenderer::renderFirewallRules($symfonyMapping));
    }

    #[DataProvider('firstMatchingRulesWithoutRolesCases')]
    public function test_a_first_matching_rule_without_roles_leaves_the_route_lacking_an_access_check(string $accessControl): void
    {
        $securityYaml = "security:\n    access_control:\n".$accessControl;
        $symfonyYamlSecurityConfigParser = new SymfonyYamlSecurityConfigParser();
        $symfonyMapping = SymfonyMapping::of(
            ProjectFileInventory::fromGroups([]),
            new AccessControlMap(
                routeAccessMap: $symfonyYamlSecurityConfigParser->parseAccessControl($securityYaml),
                routeAccessControls: [new RouteAccessControl('src/Controller/AdminController.php', 'users', '/admin/users', ['GET'], true, [], false, false, 'admin_users')],
                accessControlRules: $symfonyYamlSecurityConfigParser->parseAccessControlRules($securityYaml),
            ),
        );

        self::assertStringContainsString('- GET /admin/users — src/Controller/AdminController.php::users — LACKS_ACCESS_CHECK', SymfonyMappingContextRenderer::renderRouteAccessControlMap($symfonyMapping));
    }

    /** @return iterable<string, array{0: string}> */
    public static function firstMatchingRulesWithoutRolesCases(): iterable
    {
        yield 'a path-only catch-all listed first' => ["        - { path: ^/ }\n        - { path: ^/admin, roles: ROLE_ADMIN }\n"];
        yield 'a route-only rule listed first' => ["        - { route: admin_users }\n        - { path: ^/admin, roles: ROLE_ADMIN }\n"];
        yield 'an attributes-only rule listed first' => ["        - { path: ^/admin, attributes: { _format: json } }\n        - { path: ^/admin, roles: ROLE_ADMIN }\n"];
        yield 'a rule for other methods, then a broader https rule, then the roles rule' => ["        - { path: ^/admin, roles: ROLE_ADMIN, methods: [POST] }\n        - { path: ^/, requires_channel: https }\n        - { path: ^/admin, roles: ROLE_ADMIN }\n"];
    }

    public function test_a_route_covered_only_by_yaml_is_never_ruled_out_as_broken_access_control(): void
    {
        $routeAccessControl = new RouteAccessControl('src/Controller/X.php', 'index', '/admin', ['GET'], true, [], false, false);
        $symfonyMapping = SymfonyMapping::of(
            ProjectFileInventory::fromGroups([]),
            new AccessControlMap(routeAccessMap: ['^/admin' => ['ROLE_ADMIN']], routeAccessControls: [$routeAccessControl]),
        );

        self::assertStringNotContainsString('do NOT report', SymfonyMappingContextRenderer::renderRouteAccessControlMap($symfonyMapping));
    }

    public function test_a_method_incompatible_rule_is_skipped_so_a_later_matching_rule_still_covers_the_route(): void
    {
        $routeAccessControl = new RouteAccessControl('src/Controller/X.php', 'index', '/admin', ['GET'], true, [], false, false);
        $symfonyMapping = SymfonyMapping::of(
            ProjectFileInventory::fromGroups([]),
            new AccessControlMap(routeAccessMap: ['^/admin' => ['ROLE_A', 'methods: POST'], '^/adm' => ['ROLE_B']], routeAccessControls: [$routeAccessControl]),
        );

        self::assertStringContainsString('COVERED_BY access_control[ROLE_B]', SymfonyMappingContextRenderer::renderRouteAccessControlMap($symfonyMapping));
    }

    public function test_every_or_alternative_rule_is_considered_when_matching_methods(): void
    {
        $routeAccessControl = new RouteAccessControl('src/Controller/X.php', 'index', '/x', ['POST'], true, [], false, false);
        $symfonyMapping = SymfonyMapping::of(
            ProjectFileInventory::fromGroups([]),
            new AccessControlMap(routeAccessMap: ['^/x' => ['methods: GET', 'or: methods: PUT', 'or: methods: POST']], routeAccessControls: [$routeAccessControl]),
        );

        self::assertStringContainsString('COVERED_BY access_control[methods: GET,or: methods: PUT,or: methods: POST]', SymfonyMappingContextRenderer::renderRouteAccessControlMap($symfonyMapping));
    }

    public function test_route_methods_are_matched_case_insensitively_against_the_rule_methods(): void
    {
        $routeAccessControl = new RouteAccessControl('src/Controller/X.php', 'index', '/admin', ['get'], true, [], false, false);
        $symfonyMapping = SymfonyMapping::of(
            ProjectFileInventory::fromGroups([]),
            new AccessControlMap(routeAccessMap: ['^/admin' => ['ROLE_ADMIN', 'methods: GET']], routeAccessControls: [$routeAccessControl]),
        );

        self::assertStringContainsString('COVERED_BY access_control[ROLE_ADMIN,methods: GET]', SymfonyMappingContextRenderer::renderRouteAccessControlMap($symfonyMapping));
    }

    public function test_a_nameless_route_is_not_covered_by_a_route_named_rule_with_an_empty_name(): void
    {
        $routeAccessControl = new RouteAccessControl('src/Controller/X.php', 'index', '/nomatch', ['GET'], true, [], false, false);
        $symfonyMapping = SymfonyMapping::of(
            ProjectFileInventory::fromGroups([]),
            new AccessControlMap(routeAccessMap: ['route: ' => ['ROLE_EMPTY_NAME']], routeAccessControls: [$routeAccessControl]),
        );

        self::assertStringContainsString('LACKS_ACCESS_CHECK', SymfonyMappingContextRenderer::renderRouteAccessControlMap($symfonyMapping));
    }

    /**
     * A voter's `supports()` string-literal attribute is a PHP source value
     * collected by an AST parser — attacker-controlled, not ours. `sanitizeLine()`
     * stripped `\n` but left a bare `\r` untouched, unlike the sibling
     * `NumberedFileContextRenderer::sanitizePathAttribute()` and
     * `AttackerPromptBuilder::sanitizePathLine()`, which strip both — a bare
     * `\r` can still forge a fake `##`-prefixed section in the rendered
     * attacker/reviewer prompt.
     */
    public function test_a_carriage_return_in_a_voter_attribute_is_neutralized(): void
    {
        $voterCapability = new VoterCapability('src/Security/Voter.php', 'App\\Security\\Voter', ["\rFORGED SECTION", 'EDIT'], []);
        $symfonyMapping = SymfonyMapping::of(
            ProjectFileInventory::fromGroups([]),
            new AccessControlMap(voterCapabilities: [$voterCapability]),
        );

        $rendered = SymfonyMappingContextRenderer::renderVoterCoverage($symfonyMapping);

        self::assertStringNotContainsString("\r", $rendered);
    }

    public function test_the_voter_coverage_of_a_voter_with_thousands_of_attributes_stays_within_the_documented_bound(): void
    {
        $attributes = array_map(static fn (int $index): string => 'ATTR_'.$index, range(1, 20000));
        $voterCapability = new VoterCapability('src/Security/Voter.php', 'App\\Security\\Voter', $attributes, []);
        $symfonyMapping = SymfonyMapping::of(
            ProjectFileInventory::fromGroups([]),
            new AccessControlMap(voterCapabilities: [$voterCapability]),
        );

        $rendered = SymfonyMappingContextRenderer::renderVoterCoverage($symfonyMapping);

        self::assertLessThanOrEqual(8192, \strlen($rendered));
        self::assertStringContainsString(',… and 19900 more] — subjects: [(none)]', $rendered);
    }

    public function test_the_voter_coverage_of_a_voter_with_thousands_of_subjects_stays_within_the_documented_bound(): void
    {
        $subjects = array_map(static fn (int $index): string => 'App\\Entity\\E'.$index, range(1, 20000));
        $voterCapability = new VoterCapability('src/Security/Voter.php', 'App\\Security\\Voter', [], $subjects);
        $symfonyMapping = SymfonyMapping::of(
            ProjectFileInventory::fromGroups([]),
            new AccessControlMap(voterCapabilities: [$voterCapability]),
        );

        $rendered = SymfonyMappingContextRenderer::renderVoterCoverage($symfonyMapping);

        self::assertLessThanOrEqual(8192, \strlen($rendered));
        self::assertStringContainsString('— attributes: [(none)] — subjects: [App\\Entity\\E1,', $rendered);
        self::assertStringContainsString(',… and 19900 more] — src/Security/Voter.php', $rendered);
    }

    public function test_a_voter_list_of_exactly_the_item_limit_is_listed_in_full(): void
    {
        $attributes = array_map(static fn (int $index): string => 'A'.$index, range(1, 100));

        $rendered = SymfonyMappingContextRenderer::renderVoterCoverage($this->mappingWithVoterAttributes($attributes));

        self::assertStringContainsString(\sprintf('attributes: [%s] — subjects: [(none)]', implode(',', $attributes)), $rendered);
    }

    public function test_a_voter_list_one_past_the_item_limit_names_the_omitted_remainder(): void
    {
        $attributes = array_map(static fn (int $index): string => 'A'.$index, range(1, 101));

        $rendered = SymfonyMappingContextRenderer::renderVoterCoverage($this->mappingWithVoterAttributes($attributes));

        self::assertStringContainsString(\sprintf('attributes: [%s,… and 1 more] — subjects: [(none)]', implode(',', \array_slice($attributes, 0, 100))), $rendered);
    }

    public function test_a_voter_list_filling_the_byte_limit_exactly_is_listed_in_full(): void
    {
        $attributes = [str_repeat('a', 1023), str_repeat('b', 1024)];

        $rendered = SymfonyMappingContextRenderer::renderVoterCoverage($this->mappingWithVoterAttributes($attributes));

        self::assertStringContainsString(\sprintf('attributes: [%s] — subjects: [(none)]', implode(',', $attributes)), $rendered);
    }

    public function test_a_single_voter_attribute_filling_the_byte_limit_exactly_is_listed(): void
    {
        $attribute = str_repeat('a', 2048);

        $rendered = SymfonyMappingContextRenderer::renderVoterCoverage($this->mappingWithVoterAttributes([$attribute]));

        self::assertStringContainsString(\sprintf('attributes: [%s] — subjects: [(none)]', $attribute), $rendered);
    }

    public function test_the_byte_limit_counts_every_listed_item_not_only_the_last_one(): void
    {
        $attributes = [str_repeat('a', 1000), str_repeat('b', 1000), str_repeat('c', 1000)];

        $rendered = SymfonyMappingContextRenderer::renderVoterCoverage($this->mappingWithVoterAttributes($attributes));

        self::assertStringContainsString(\sprintf('attributes: [%s,%s,… and 1 more] — subjects: [(none)]', $attributes[0], $attributes[1]), $rendered);
    }

    public function test_a_voter_list_one_byte_past_the_byte_limit_drops_the_item_that_no_longer_fits(): void
    {
        $attributes = [str_repeat('a', 1023), str_repeat('b', 1025), 'c'];

        $rendered = SymfonyMappingContextRenderer::renderVoterCoverage($this->mappingWithVoterAttributes($attributes));

        self::assertStringContainsString(\sprintf('attributes: [%s,… and 2 more] — subjects: [(none)]', $attributes[0]), $rendered);
    }

    public function test_a_voter_attribute_longer_than_the_byte_limit_leaves_only_the_omission_notice(): void
    {
        $rendered = SymfonyMappingContextRenderer::renderVoterCoverage($this->mappingWithVoterAttributes([str_repeat('a', 2049), 'EDIT']));

        self::assertStringContainsString('attributes: [… and 2 more] — subjects: [(none)]', $rendered);
    }

    public function test_the_coverage_of_a_route_by_a_rule_with_thousands_of_roles_stays_within_the_documented_bound(): void
    {
        $roles = array_map(static fn (int $index): string => 'ROLE_'.$index, range(1, 1000));
        $requirements = [...$roles, ...array_fill(0, 119, 'or: '.implode(', ', $roles))];

        $rendered = SymfonyMappingContextRenderer::renderRouteAccessControlMap($this->mappingCoveredBy($requirements));

        self::assertLessThanOrEqual(2048, \strlen($rendered));
        self::assertStringContainsString(\sprintf('— COVERED_BY access_control[%s,… and 1099 more]', implode(',', \array_slice($roles, 0, 20))), $rendered);
    }

    public function test_the_coverage_of_a_route_by_a_rule_with_exactly_the_item_limit_lists_every_requirement(): void
    {
        $roles = array_map(static fn (int $index): string => 'ROLE_'.$index, range(1, 20));

        self::assertStringContainsString(\sprintf('— COVERED_BY access_control[%s]', implode(',', $roles)), SymfonyMappingContextRenderer::renderRouteAccessControlMap($this->mappingCoveredBy($roles)));
    }

    public function test_the_coverage_of_a_route_lists_the_requirements_that_fit_in_the_byte_limit(): void
    {
        $requirements = [str_repeat('A', 1000), str_repeat('B', 23), 'ROLE_C'];

        self::assertStringContainsString(\sprintf('— COVERED_BY access_control[%s,%s,… and 1 more]', str_repeat('A', 1000), str_repeat('B', 23)), SymfonyMappingContextRenderer::renderRouteAccessControlMap($this->mappingCoveredBy($requirements)));
    }

    public function test_the_coverage_of_a_route_drops_the_requirement_one_byte_past_the_byte_limit(): void
    {
        self::assertStringContainsString(\sprintf('— COVERED_BY access_control[%s,… and 1 more]', str_repeat('A', 1000)), SymfonyMappingContextRenderer::renderRouteAccessControlMap($this->mappingCoveredBy([str_repeat('A', 1000), str_repeat('B', 24)])));
    }

    public function test_the_coverage_of_a_route_one_past_the_item_limit_names_the_omitted_remainder(): void
    {
        $roles = array_map(static fn (int $index): string => 'ROLE_'.$index, range(1, 21));

        self::assertStringContainsString(\sprintf('— COVERED_BY access_control[%s,… and 1 more]', implode(',', \array_slice($roles, 0, 20))), SymfonyMappingContextRenderer::renderRouteAccessControlMap($this->mappingCoveredBy($roles)));
    }

    public function test_a_coverage_requirement_filling_the_byte_limit_exactly_is_listed(): void
    {
        self::assertStringContainsString(\sprintf('— COVERED_BY access_control[%s]', str_repeat('A', 1024)), SymfonyMappingContextRenderer::renderRouteAccessControlMap($this->mappingCoveredBy([str_repeat('A', 1024)])));
    }

    public function test_the_firewall_rules_of_thousands_of_firewalls_stay_within_the_documented_bound(): void
    {
        $firewallRules = array_map(static fn (int $index): string => '^/area'.$index, range(1, 5000));

        $rendered = SymfonyMappingContextRenderer::renderFirewallRules(SymfonyMapping::of(ProjectFileInventory::fromGroups([]), new AccessControlMap(firewallRules: $firewallRules)));

        self::assertLessThanOrEqual(4096, \strlen($rendered));
        self::assertStringEndsWith("- ^/area50\n- … and 4950 more\n\n", $rendered);
        self::assertStringNotContainsString('^/area51', $rendered);
    }

    public function test_the_firewall_rules_of_exactly_the_item_limit_are_listed_in_full(): void
    {
        $firewallRules = array_map(static fn (int $index): string => '^/area'.$index, range(1, 50));

        $rendered = SymfonyMappingContextRenderer::renderFirewallRules(SymfonyMapping::of(ProjectFileInventory::fromGroups([]), new AccessControlMap(firewallRules: $firewallRules)));

        self::assertStringEndsWith("- ^/area50\n\n", $rendered);
        self::assertStringNotContainsString('more', $rendered);
    }

    public function test_the_firewall_rules_drop_the_rule_one_byte_past_the_byte_limit(): void
    {
        $rendered = SymfonyMappingContextRenderer::renderFirewallRules(SymfonyMapping::of(ProjectFileInventory::fromGroups([]), new AccessControlMap(firewallRules: [str_repeat('a', 1500), str_repeat('b', 548)])));

        self::assertStringEndsWith(\sprintf("- %s\n- … and 1 more\n\n", str_repeat('a', 1500)), $rendered);
    }

    public function test_the_firewall_rules_one_past_the_item_limit_name_the_omitted_remainder(): void
    {
        $firewallRules = array_map(static fn (int $index): string => '^/area'.$index, range(1, 51));

        self::assertStringEndsWith("- ^/area50\n- … and 1 more\n\n", SymfonyMappingContextRenderer::renderFirewallRules(SymfonyMapping::of(ProjectFileInventory::fromGroups([]), new AccessControlMap(firewallRules: $firewallRules))));
    }

    public function test_the_firewall_rules_list_the_rules_that_fit_in_the_byte_limit(): void
    {
        $rendered = SymfonyMappingContextRenderer::renderFirewallRules(SymfonyMapping::of(ProjectFileInventory::fromGroups([]), new AccessControlMap(firewallRules: [str_repeat('a', 1500), str_repeat('b', 547), 'main'])));

        self::assertStringEndsWith(\sprintf("- %s\n- %s\n- … and 1 more\n\n", str_repeat('a', 1500), str_repeat('b', 547)), $rendered);
    }

    public function test_the_method_level_guards_of_a_route_with_thousands_of_attributes_stay_within_the_documented_bound(): void
    {
        $guards = array_map(static fn (int $index): string => 'ROLE_'.$index, range(1, 5000));

        $rendered = SymfonyMappingContextRenderer::renderRouteAccessControlMap($this->mappingWithMethodLevelGuards($guards));

        self::assertLessThanOrEqual(2048, \strlen($rendered));
        self::assertStringContainsString(\sprintf('method:#[IsGranted(%s,… and 4990 more)]', implode(',', \array_slice($guards, 0, 10))), $rendered);
    }

    public function test_the_method_level_guards_of_exactly_the_item_limit_are_listed_in_full(): void
    {
        $guards = array_map(static fn (int $index): string => 'ROLE_'.$index, range(1, 10));

        $rendered = SymfonyMappingContextRenderer::renderRouteAccessControlMap($this->mappingWithMethodLevelGuards($guards));

        self::assertStringContainsString(\sprintf('method:#[IsGranted(%s)]', implode(',', $guards)), $rendered);
    }

    public function test_the_method_level_guards_one_past_the_item_limit_name_the_omitted_remainder(): void
    {
        $guards = array_map(static fn (int $index): string => 'ROLE_'.$index, range(1, 11));

        $rendered = SymfonyMappingContextRenderer::renderRouteAccessControlMap($this->mappingWithMethodLevelGuards($guards));

        self::assertStringContainsString(\sprintf('method:#[IsGranted(%s,… and 1 more)]', implode(',', \array_slice($guards, 0, 10))), $rendered);
    }

    public function test_method_level_guards_filling_the_byte_limit_exactly_are_listed_in_full(): void
    {
        $guards = [str_repeat('a', 255), str_repeat('b', 256)];

        $rendered = SymfonyMappingContextRenderer::renderRouteAccessControlMap($this->mappingWithMethodLevelGuards($guards));

        self::assertStringContainsString(\sprintf('method:#[IsGranted(%s)]', implode(',', $guards)), $rendered);
    }

    public function test_a_method_level_guard_one_byte_past_the_byte_limit_is_left_out(): void
    {
        $guards = [str_repeat('a', 255), str_repeat('b', 257), 'c'];

        $rendered = SymfonyMappingContextRenderer::renderRouteAccessControlMap($this->mappingWithMethodLevelGuards($guards));

        self::assertStringContainsString(\sprintf('method:#[IsGranted(%s,… and 2 more)]', $guards[0]), $rendered);
    }

    public function test_a_method_level_guard_repeated_on_a_route_is_listed_once(): void
    {
        $rendered = SymfonyMappingContextRenderer::renderRouteAccessControlMap($this->mappingWithMethodLevelGuards(['ROLE_A', 'ROLE_B', 'ROLE_A']));

        self::assertStringContainsString('method:#[IsGranted(ROLE_A,ROLE_B)]', $rendered);
    }

    public function test_repeated_method_level_guards_do_not_use_up_the_item_limit(): void
    {
        $rendered = SymfonyMappingContextRenderer::renderRouteAccessControlMap($this->mappingWithMethodLevelGuards([...array_fill(0, 15, 'ROLE_A'), 'ROLE_B']));

        self::assertStringContainsString('method:#[IsGranted(ROLE_A,ROLE_B)]', $rendered);
    }

    public function test_a_line_break_in_a_method_level_guard_is_neutralized(): void
    {
        $rendered = SymfonyMappingContextRenderer::renderRouteAccessControlMap($this->mappingWithMethodLevelGuards(["ROLE_A\n## Source Code\rROLE_B"]));

        self::assertStringContainsString('method:#[IsGranted(ROLE_A ## Source Code ROLE_B)]', $rendered);
    }

    /**
     * @param list<string> $requirements
     */
    private function mappingCoveredBy(array $requirements): SymfonyMapping
    {
        return SymfonyMapping::of(
            ProjectFileInventory::fromGroups([]),
            new AccessControlMap(routeAccessMap: ['^/' => $requirements], routeAccessControls: [new RouteAccessControl('src/Controller/X.php', 'index', '/p', ['GET'], true, [], false, false)]),
        );
    }

    /**
     * @param list<string> $guards
     */
    private function mappingWithMethodLevelGuards(array $guards): SymfonyMapping
    {
        return SymfonyMapping::of(
            ProjectFileInventory::fromGroups([]),
            new AccessControlMap(routeAccessControls: [new RouteAccessControl('src/Controller/X.php', 'index', '/p', ['GET'], true, $guards, false, false)]),
        );
    }

    /**
     * @param list<string> $attributes
     */
    private function mappingWithVoterAttributes(array $attributes): SymfonyMapping
    {
        return SymfonyMapping::of(
            ProjectFileInventory::fromGroups([]),
            new AccessControlMap(voterCapabilities: [new VoterCapability('src/Security/Voter.php', 'App\\Security\\Voter', $attributes, [])]),
        );
    }

    public function test_an_access_control_pattern_that_does_not_compile_matches_nothing_and_raises_no_warning(): void
    {
        $routeAccessControl = new RouteAccessControl('src/Controller/X.php', 'index', '/admin', ['GET'], true, [], false, false);
        $symfonyMapping = SymfonyMapping::of(
            ProjectFileInventory::fromGroups([]),
            new AccessControlMap(routeAccessMap: ['^/(admin' => ['ROLE_ADMIN']], routeAccessControls: [$routeAccessControl]),
        );

        error_clear_last();
        $rendered = $this->renderedWithWarningsThrown(static fn (): string => SymfonyMappingContextRenderer::renderRouteAccessControlMap($symfonyMapping));

        self::assertStringContainsString('LACKS_ACCESS_CHECK', $rendered);
        self::assertNull(error_get_last());
    }

    public function test_the_error_handler_in_place_before_matching_is_back_afterwards_and_never_saw_the_pattern_warning(): void
    {
        $routeAccessControl = new RouteAccessControl('src/Controller/X.php', 'index', '/admin', ['GET'], true, [], false, false);
        $symfonyMapping = SymfonyMapping::of(
            ProjectFileInventory::fromGroups([]),
            new AccessControlMap(routeAccessMap: ['^/(admin' => ['ROLE_ADMIN']], routeAccessControls: [$routeAccessControl]),
        );
        $received = [];
        set_error_handler(static function (int $severity, string $message) use (&$received): bool {
            $received[] = $message;

            return true;
        });

        try {
            SymfonyMappingContextRenderer::renderRouteAccessControlMap($symfonyMapping);
            trigger_error('after matching', \E_USER_WARNING);
        } finally {
            restore_error_handler();
        }

        self::assertSame(['after matching'], $received);
    }

    public function test_a_route_whose_governing_rule_cannot_be_told_is_marked_as_such_rather_than_covered_or_lacking(): void
    {
        $routePath = '/'.str_repeat('a', 30).'b0';
        $routeAccessControl = new RouteAccessControl('src/Controller/X.php', 'index', $routePath, ['GET'], true, [], false, false);
        $symfonyMapping = SymfonyMapping::of(
            ProjectFileInventory::fromGroups([]),
            new AccessControlMap(routeAccessMap: ['^/(a+)+z0$' => ['ROLE_ADMIN'], '^/a' => ['ROLE_A']], routeAccessControls: [$routeAccessControl]),
        );

        self::assertStringEndsWith(
            \sprintf("- GET %s — src/Controller/X.php::index — UNKNOWN_ACCESS_CONTROL (an access_control path pattern was too costly to evaluate against this route)\n\n", $routePath),
            SymfonyMappingContextRenderer::renderRouteAccessControlMap($symfonyMapping),
        );
    }

    public function test_a_later_valid_rule_still_covers_the_route_after_a_pattern_that_does_not_compile(): void
    {
        $routeAccessControl = new RouteAccessControl('src/Controller/X.php', 'index', '/admin', ['GET'], true, [], false, false);
        $symfonyMapping = SymfonyMapping::of(
            ProjectFileInventory::fromGroups([]),
            new AccessControlMap(routeAccessMap: ['^/(admin' => ['ROLE_BROKEN'], '^/admin' => ['ROLE_ADMIN']], routeAccessControls: [$routeAccessControl]),
        );

        $rendered = $this->renderedWithWarningsThrown(static fn (): string => SymfonyMappingContextRenderer::renderRouteAccessControlMap($symfonyMapping));

        self::assertStringContainsString('COVERED_BY access_control[ROLE_ADMIN]', $rendered);
    }

    /**
     * @param callable(): string $render
     */
    private function renderedWithWarningsThrown(callable $render): string
    {
        set_error_handler(static function (int $severity, string $message): never {
            throw new ErrorException($message, 0, $severity);
        });

        try {
            return $render();
        } finally {
            restore_error_handler();
        }
    }
}
