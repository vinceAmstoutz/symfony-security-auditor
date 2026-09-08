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
use VinceAmstoutz\SecurityAuditor\Audit\Domain\Model\EntrypointAccessControl;

final class EntrypointAccessControlTest extends TestCase
{
    public function test_action_with_route_and_no_check_lacks_access_check(): void
    {
        $entrypointAccessControl = new EntrypointAccessControl(
            filePath: 'src/Controller/AdminController.php',
            methodName: 'deleteUser',
            routePath: '/admin/users/{id}',
            routeMethods: ['DELETE'],
            isRouted: true,
            handlerRequiredAttributes: [],
            handlerChecksAccessInBody: false,
            classHasAccessCheck: false,
        );

        self::assertFalse($entrypointAccessControl->hasAccessCheck());
        self::assertTrue($entrypointAccessControl->lacksAccessCheck());
    }

    public function test_guard_attributes_unions_and_deduplicates_every_guard_form(): void
    {
        $entrypointAccessControl = new EntrypointAccessControl(
            filePath: 'src/Controller/PostController.php',
            methodName: 'edit',
            routePath: '/posts/{id}/edit',
            routeMethods: ['POST'],
            isRouted: true,
            handlerRequiredAttributes: ['EDIT'],
            handlerChecksAccessInBody: true,
            classHasAccessCheck: true,
            classRequiredAttributes: ['ROLE_USER', 'EDIT'],
            bodyRequiredAttributes: ['PUBLISH'],
        );

        self::assertSame(['EDIT', 'ROLE_USER', 'PUBLISH'], $entrypointAccessControl->guardAttributes());
    }

    public function test_guard_attributes_is_empty_when_no_guard_is_present(): void
    {
        $entrypointAccessControl = new EntrypointAccessControl(
            filePath: 'src/Controller/PublicController.php',
            methodName: 'index',
            routePath: '/',
            routeMethods: ['GET'],
            isRouted: true,
            handlerRequiredAttributes: [],
            handlerChecksAccessInBody: false,
            classHasAccessCheck: false,
        );

        self::assertSame([], $entrypointAccessControl->guardAttributes());
    }

    public function test_action_with_method_level_is_granted_has_access_check(): void
    {
        $entrypointAccessControl = new EntrypointAccessControl(
            filePath: 'src/Controller/AdminController.php',
            methodName: 'deleteUser',
            routePath: '/admin/users/{id}',
            routeMethods: ['DELETE'],
            isRouted: true,
            handlerRequiredAttributes: ['ROLE_ADMIN'],
            handlerChecksAccessInBody: false,
            classHasAccessCheck: false,
        );

        self::assertTrue($entrypointAccessControl->hasAccessCheck());
        self::assertFalse($entrypointAccessControl->lacksAccessCheck());
    }

    public function test_action_with_class_level_is_granted_has_access_check(): void
    {
        $entrypointAccessControl = new EntrypointAccessControl(
            filePath: 'src/Controller/AdminController.php',
            methodName: 'list',
            routePath: '/admin/users',
            routeMethods: ['GET'],
            isRouted: true,
            handlerRequiredAttributes: [],
            handlerChecksAccessInBody: false,
            classHasAccessCheck: true,
        );

        self::assertTrue($entrypointAccessControl->hasAccessCheck());
        self::assertFalse($entrypointAccessControl->lacksAccessCheck());
    }

    public function test_action_with_deny_access_call_has_access_check(): void
    {
        $entrypointAccessControl = new EntrypointAccessControl(
            filePath: 'src/Controller/AdminController.php',
            methodName: 'edit',
            routePath: '/admin/users/{id}/edit',
            routeMethods: ['POST'],
            isRouted: true,
            handlerRequiredAttributes: [],
            handlerChecksAccessInBody: true,
            classHasAccessCheck: false,
        );

        self::assertTrue($entrypointAccessControl->hasAccessCheck());
        self::assertFalse($entrypointAccessControl->lacksAccessCheck());
    }

    public function test_method_with_an_unresolvable_is_granted_attribute_value_has_access_check(): void
    {
        $entrypointAccessControl = new EntrypointAccessControl(
            filePath: 'src/Controller/AdminController.php',
            methodName: 'edit',
            routePath: '/admin/users/{id}/edit',
            routeMethods: ['POST'],
            isRouted: true,
            handlerRequiredAttributes: [],
            handlerChecksAccessInBody: false,
            classHasAccessCheck: false,
            handlerHasUnresolvedAccessCheck: true,
        );

        self::assertTrue($entrypointAccessControl->handlerHasUnresolvedAccessCheck());
        self::assertTrue($entrypointAccessControl->hasAccessCheck());
        self::assertFalse($entrypointAccessControl->lacksAccessCheck());
    }

    public function test_method_without_route_attribute_does_not_count_as_lacking_access_check(): void
    {
        $entrypointAccessControl = new EntrypointAccessControl(
            filePath: 'src/Controller/SupportController.php',
            methodName: 'privateHelper',
            routePath: null,
            routeMethods: [],
            isRouted: false,
            handlerRequiredAttributes: [],
            handlerChecksAccessInBody: false,
            classHasAccessCheck: false,
        );

        self::assertFalse($entrypointAccessControl->lacksAccessCheck());
    }
}
