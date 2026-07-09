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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Domain\Model;

use PHPUnit\Framework\TestCase;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\RouteAccessControl;

final class RouteAccessControlTest extends TestCase
{
    public function test_action_with_route_and_no_check_lacks_access_check(): void
    {
        $routeAccessControl = new RouteAccessControl(
            filePath: 'src/Controller/AdminController.php',
            methodName: 'deleteUser',
            routePath: '/admin/users/{id}',
            routeMethods: ['DELETE'],
            hasRouteAttribute: true,
            methodLevelIsGranted: [],
            methodHasDenyAccess: false,
            classHasIsGranted: false,
        );

        self::assertFalse($routeAccessControl->hasAccessCheck());
        self::assertTrue($routeAccessControl->lacksAccessCheck());
    }

    public function test_action_with_method_level_is_granted_has_access_check(): void
    {
        $routeAccessControl = new RouteAccessControl(
            filePath: 'src/Controller/AdminController.php',
            methodName: 'deleteUser',
            routePath: '/admin/users/{id}',
            routeMethods: ['DELETE'],
            hasRouteAttribute: true,
            methodLevelIsGranted: ['ROLE_ADMIN'],
            methodHasDenyAccess: false,
            classHasIsGranted: false,
        );

        self::assertTrue($routeAccessControl->hasAccessCheck());
        self::assertFalse($routeAccessControl->lacksAccessCheck());
    }

    public function test_action_with_class_level_is_granted_has_access_check(): void
    {
        $routeAccessControl = new RouteAccessControl(
            filePath: 'src/Controller/AdminController.php',
            methodName: 'list',
            routePath: '/admin/users',
            routeMethods: ['GET'],
            hasRouteAttribute: true,
            methodLevelIsGranted: [],
            methodHasDenyAccess: false,
            classHasIsGranted: true,
        );

        self::assertTrue($routeAccessControl->hasAccessCheck());
        self::assertFalse($routeAccessControl->lacksAccessCheck());
    }

    public function test_action_with_deny_access_call_has_access_check(): void
    {
        $routeAccessControl = new RouteAccessControl(
            filePath: 'src/Controller/AdminController.php',
            methodName: 'edit',
            routePath: '/admin/users/{id}/edit',
            routeMethods: ['POST'],
            hasRouteAttribute: true,
            methodLevelIsGranted: [],
            methodHasDenyAccess: true,
            classHasIsGranted: false,
        );

        self::assertTrue($routeAccessControl->hasAccessCheck());
        self::assertFalse($routeAccessControl->lacksAccessCheck());
    }

    public function test_method_with_an_unresolvable_is_granted_attribute_value_has_access_check(): void
    {
        $routeAccessControl = new RouteAccessControl(
            filePath: 'src/Controller/AdminController.php',
            methodName: 'edit',
            routePath: '/admin/users/{id}/edit',
            routeMethods: ['POST'],
            hasRouteAttribute: true,
            methodLevelIsGranted: [],
            methodHasDenyAccess: false,
            classHasIsGranted: false,
            methodHasIsGrantedAttribute: true,
        );

        self::assertTrue($routeAccessControl->methodHasIsGrantedAttribute());
        self::assertTrue($routeAccessControl->hasAccessCheck());
        self::assertFalse($routeAccessControl->lacksAccessCheck());
    }

    public function test_method_without_route_attribute_does_not_count_as_lacking_access_check(): void
    {
        $routeAccessControl = new RouteAccessControl(
            filePath: 'src/Controller/SupportController.php',
            methodName: 'privateHelper',
            routePath: null,
            routeMethods: [],
            hasRouteAttribute: false,
            methodLevelIsGranted: [],
            methodHasDenyAccess: false,
            classHasIsGranted: false,
        );

        self::assertFalse($routeAccessControl->lacksAccessCheck());
    }
}
