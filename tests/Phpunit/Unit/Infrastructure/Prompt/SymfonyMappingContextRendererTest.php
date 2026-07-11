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

use PHPUnit\Framework\TestCase;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\AccessControlMap;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFileInventory;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\RouteAccessControl;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\SymfonyMapping;
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
}
