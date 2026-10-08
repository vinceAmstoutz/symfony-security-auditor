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
use PHPUnit\Framework\TestCase;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\AccessControlMap;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFileInventory;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\RouteAccessControl;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\SymfonyMapping;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VoterCapability;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Prompt\SymfonyMappingContextRenderer;

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
