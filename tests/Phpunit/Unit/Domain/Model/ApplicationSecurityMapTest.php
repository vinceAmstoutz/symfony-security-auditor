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
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidProjectFileException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\AccessControlMap;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ApplicationSecurityMap;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\AuthorizationRuleCapability;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\EntrypointAccessControl;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\FormBinding;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFileInventory;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Fixture\SymfonyProjectFile;

final class ApplicationSecurityMapTest extends TestCase
{
    public function test_an_empty_application_maps_to_nothing(): void
    {
        $applicationSecurityMap = ApplicationSecurityMap::of(ProjectFileInventory::fromGroups([]), new AccessControlMap());

        self::assertSame(
            [[], [], [], [], [], [], [], [], [], [], [], [], [], 0],
            [
                $applicationSecurityMap->entrypoints(),
                $applicationSecurityMap->domainModels(),
                $applicationSecurityMap->authorizationRuleFiles(),
                $applicationSecurityMap->persistenceQueries(),
                $applicationSecurityMap->inputBindingFiles(),
                $applicationSecurityMap->services(),
                $applicationSecurityMap->templates(),
                $applicationSecurityMap->entrypointAccessMap(),
                $applicationSecurityMap->perimeterRules(),
                $applicationSecurityMap->entrypointAccessControls(),
                $applicationSecurityMap->entrypointsWithoutAccessCheck(),
                $applicationSecurityMap->authorizationRules(),
                $applicationSecurityMap->fieldBindings(),
                $applicationSecurityMap->totalFiles(),
            ],
        );
    }

    /**
     * @throws InvalidProjectFileException
     */
    public function test_it_groups_scanned_files_under_neutral_names(): void
    {
        $projectFile = SymfonyProjectFile::create('src/Controller/UserController.php', '/app/src/Controller/UserController.php', '<?php');
        $entity = SymfonyProjectFile::create('src/Entity/User.php', '/app/src/Entity/User.php', '<?php');
        $voter = SymfonyProjectFile::create('src/Security/UserVoter.php', '/app/src/Security/UserVoter.php', '<?php');

        $applicationSecurityMap = ApplicationSecurityMap::of(
            ProjectFileInventory::fromGroups([
                'entrypoints' => [$projectFile],
                'domainModels' => [$entity],
                'authorizationRules' => [$voter],
            ]),
            new AccessControlMap(),
        );

        self::assertSame(
            [[$projectFile], [$entity], [$voter], 3],
            [$applicationSecurityMap->entrypoints(), $applicationSecurityMap->domainModels(), $applicationSecurityMap->authorizationRuleFiles(), $applicationSecurityMap->totalFiles()],
        );
    }

    public function test_authorization_rules_can_be_looked_up_by_attribute_and_subject(): void
    {
        $authorizationRuleCapability = new AuthorizationRuleCapability(
            filePath: 'src/Security/UserVoter.php',
            className: 'App\\Security\\UserVoter',
            supportedAttributes: ['EDIT'],
            supportedSubjects: ['App\\Entity\\User'],
        );

        $applicationSecurityMap = ApplicationSecurityMap::of(
            ProjectFileInventory::fromGroups([]),
            new AccessControlMap(authorizationRules: [$authorizationRuleCapability]),
        );

        self::assertSame(
            [[$authorizationRuleCapability], [$authorizationRuleCapability], []],
            [$applicationSecurityMap->authorizationRules(), $applicationSecurityMap->authorizationRulesFor('EDIT', 'User'), $applicationSecurityMap->authorizationRulesFor('DELETE', 'User')],
        );
    }

    /**
     * @throws InvalidProjectFileException
     */
    public function test_it_reports_which_models_have_no_authorization_rule(): void
    {
        $applicationSecurityMap = ApplicationSecurityMap::of(
            ProjectFileInventory::fromGroups([
                'authorizationRules' => [SymfonyProjectFile::create(
                    'src/Security/UserVoter.php',
                    '/app/src/Security/UserVoter.php',
                    '<?php class UserVoter { protected function supports($attribute, $subject): bool { return $subject instanceof User; } }',
                )],
            ]),
            new AccessControlMap(),
        );

        self::assertSame(
            [true, false],
            [$applicationSecurityMap->hasAuthorizationRuleForModel('User'), $applicationSecurityMap->hasAuthorizationRuleForModel('Invoice')],
        );
    }

    /**
     * @throws InvalidProjectFileException
     */
    public function test_it_reports_entrypoints_left_without_an_authorization_rule(): void
    {
        $projectFile = SymfonyProjectFile::create('src/Controller/UserController.php', '/app/src/Controller/UserController.php', '<?php');

        $applicationSecurityMap = ApplicationSecurityMap::of(
            ProjectFileInventory::fromGroups(['entrypoints' => [$projectFile]]),
            new AccessControlMap(),
        );

        self::assertSame([$projectFile], $applicationSecurityMap->entrypointsWithoutAuthorizationRule());
    }

    public function test_it_exposes_the_perimeter_rules_and_the_entrypoint_access_map(): void
    {
        $entrypointAccessControl = new EntrypointAccessControl(
            filePath: 'src/Controller/UserController.php',
            methodName: 'edit',
            routePath: '/user/{id}/edit',
            routeMethods: ['GET'],
            isRouted: true,
            handlerRequiredAttributes: ['ROLE_ADMIN'],
            handlerChecksAccessInBody: false,
            classHasAccessCheck: false,
        );

        $applicationSecurityMap = ApplicationSecurityMap::of(
            ProjectFileInventory::fromGroups([]),
            new AccessControlMap(
                routeAccessMap: ['/admin' => ['ROLE_ADMIN']],
                perimeterRules: ['^/admin: ROLE_ADMIN'],
                routeAccessControls: [$entrypointAccessControl],
            ),
        );

        self::assertSame(
            [['/admin' => ['ROLE_ADMIN']], ['^/admin: ROLE_ADMIN'], [$entrypointAccessControl]],
            [$applicationSecurityMap->entrypointAccessMap(), $applicationSecurityMap->perimeterRules(), $applicationSecurityMap->entrypointAccessControls()],
        );
    }

    public function test_field_bindings_can_be_looked_up_per_entrypoint(): void
    {
        $formBinding = new FormBinding(
            entrypointFilePath: 'src/Controller/UserController.php',
            controllerMethod: 'edit',
            formTypeClass: 'App\\Form\\UserType',
        );

        $applicationSecurityMap = ApplicationSecurityMap::of(
            ProjectFileInventory::fromGroups([]),
            new AccessControlMap(formBindings: [$formBinding]),
        );

        self::assertSame(
            [[$formBinding], [$formBinding], []],
            [
                $applicationSecurityMap->fieldBindings(),
                $applicationSecurityMap->fieldBindingsForEntrypoint('src/Controller/UserController.php'),
                $applicationSecurityMap->fieldBindingsForEntrypoint('src/Controller/OtherController.php'),
            ],
        );
    }
}
