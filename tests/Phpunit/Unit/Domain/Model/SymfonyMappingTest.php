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

use PHPUnit\Framework\Attributes\IgnoreDeprecations;
use PHPUnit\Framework\TestCase;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidProjectFileException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\AccessControlMap;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\AuthorizationRuleCapability;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\EntrypointAccessControl;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\FormBinding;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFile;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFileInventory;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\SymfonyMapping;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Fixture\SymfonyProjectFile;

final class SymfonyMappingTest extends TestCase
{
    public function test_it_creates_empty_mapping(): void
    {
        $symfonyMapping = SymfonyMapping::of(ProjectFileInventory::fromGroups([]), new AccessControlMap());

        self::assertEmpty($symfonyMapping->controllers());
        self::assertEmpty($symfonyMapping->entities());
        self::assertEmpty($symfonyMapping->voters());
        self::assertEmpty($symfonyMapping->repositories());
        self::assertEmpty($symfonyMapping->forms());
        self::assertEmpty($symfonyMapping->services());
        self::assertEmpty($symfonyMapping->templates());
        self::assertEmpty($symfonyMapping->routeAccessMap());
        self::assertEmpty($symfonyMapping->toApplicationSecurityMap()->perimeterRules());
        self::assertEmpty($symfonyMapping->routeAccessControls());
        self::assertEmpty($symfonyMapping->controllersWithoutAccessCheck());
        self::assertEmpty($symfonyMapping->toApplicationSecurityMap()->authorizationRules());
        self::assertEmpty($symfonyMapping->formBindings());
        self::assertSame(0, $symfonyMapping->totalFiles());
    }

    public function test_it_exposes_voter_capabilities_and_can_find_voters_for_attribute_and_subject(): void
    {
        $userVoter = new AuthorizationRuleCapability(
            filePath: 'src/Security/UserVoter.php',
            className: 'App\\Security\\UserVoter',
            supportedAttributes: ['EDIT', 'DELETE'],
            supportedSubjects: ['App\\Entity\\User'],
        );
        $commentVoter = new AuthorizationRuleCapability(
            filePath: 'src/Security/CommentVoter.php',
            className: 'App\\Security\\CommentVoter',
            supportedAttributes: ['VIEW'],
            supportedSubjects: ['App\\Entity\\Comment'],
        );

        $symfonyMapping = SymfonyMapping::of(ProjectFileInventory::fromGroups([]), new AccessControlMap(authorizationRules: [$userVoter, $commentVoter]));

        self::assertSame([$userVoter, $commentVoter], $symfonyMapping->toApplicationSecurityMap()->authorizationRules());
        self::assertSame([$userVoter], $symfonyMapping->votersFor('EDIT', 'User'));
        self::assertSame([$commentVoter], $symfonyMapping->votersFor('VIEW', 'App\\Entity\\Comment'));
        self::assertSame([], $symfonyMapping->votersFor('PUBLISH', 'Post'));
    }

    public function test_voters_for_excludes_voter_matching_attribute_but_not_subject(): void
    {
        $authorizationRuleCapability = new AuthorizationRuleCapability('src/Security/UserVoter.php', 'UserVoter', ['EDIT'], ['User']);

        $symfonyMapping = SymfonyMapping::of(ProjectFileInventory::fromGroups([]), new AccessControlMap(authorizationRules: [$authorizationRuleCapability]));

        self::assertSame([], $symfonyMapping->votersFor('EDIT', 'Comment'));
    }

    public function test_voters_for_excludes_voter_matching_subject_but_not_attribute(): void
    {
        $authorizationRuleCapability = new AuthorizationRuleCapability('src/Security/UserVoter.php', 'UserVoter', ['EDIT'], ['User']);

        $symfonyMapping = SymfonyMapping::of(ProjectFileInventory::fromGroups([]), new AccessControlMap(authorizationRules: [$authorizationRuleCapability]));

        self::assertSame([], $symfonyMapping->votersFor('PUBLISH', 'User'));
    }

    public function test_it_exposes_form_bindings_and_can_filter_by_controller(): void
    {
        $userEdit = new FormBinding('src/Controller/UserController.php', 'edit', 'App\\Form\\UserType');
        $userPassword = new FormBinding('src/Controller/UserController.php', 'changePassword', 'App\\Form\\PasswordType');
        $admin = new FormBinding('src/Controller/AdminController.php', 'create', 'App\\Form\\AdminType');

        $symfonyMapping = SymfonyMapping::of(ProjectFileInventory::fromGroups([]), new AccessControlMap(formBindings: [$userEdit, $userPassword, $admin]));

        self::assertSame([$userEdit, $userPassword, $admin], $symfonyMapping->formBindings());
        self::assertSame([$userEdit, $userPassword], $symfonyMapping->formBindingsForController('src/Controller/UserController.php'));
        self::assertSame([], $symfonyMapping->formBindingsForController('src/Controller/Other.php'));
    }

    public function test_it_exposes_route_access_controls(): void
    {
        $protected = new EntrypointAccessControl(
            filePath: 'src/Controller/AdminController.php',
            methodName: 'list',
            routePath: '/admin',
            routeMethods: ['GET'],
            isRouted: true,
            handlerRequiredAttributes: ['ROLE_ADMIN'],
            handlerChecksAccessInBody: false,
            classHasAccessCheck: false,
        );
        $unprotected = new EntrypointAccessControl(
            filePath: 'src/Controller/PublicController.php',
            methodName: 'leak',
            routePath: '/leak',
            routeMethods: [],
            isRouted: true,
            handlerRequiredAttributes: [],
            handlerChecksAccessInBody: false,
            classHasAccessCheck: false,
        );

        $symfonyMapping = SymfonyMapping::of(ProjectFileInventory::fromGroups([]), new AccessControlMap(routeAccessControls: [$protected, $unprotected]));

        self::assertSame([$protected, $unprotected], $symfonyMapping->routeAccessControls());
        self::assertSame([$unprotected], $symfonyMapping->controllersWithoutAccessCheck());
    }

    /**
     * @throws InvalidProjectFileException
     */
    public function test_it_counts_total_files_correctly(): void
    {
        $symfonyMapping = SymfonyMapping::of(
            ProjectFileInventory::fromGroups([
                'entrypoints' => [$this->makeFile('src/Controller/Foo.php')],
                'domainModels' => [$this->makeFile('src/Entity/User.php'), $this->makeFile('src/Entity/Post.php')],
                'authorizationRules' => [$this->makeFile('src/Security/UserVoter.php')],
            ]),
            new AccessControlMap(),
        );

        self::assertSame(4, $symfonyMapping->totalFiles());
    }

    /**
     * @throws InvalidProjectFileException
     */
    public function test_total_files_includes_forms_and_services(): void
    {
        $symfonyMapping = SymfonyMapping::of(
            ProjectFileInventory::fromGroups([
                'inputBindings' => [$this->makeFile('src/Form/UserType.php')],
                'services' => [$this->makeFile('src/Service/FooService.php'), $this->makeFile('src/Service/BarService.php')],
            ]),
            new AccessControlMap(),
        );

        self::assertSame(3, $symfonyMapping->totalFiles());
    }

    /**
     * @throws InvalidProjectFileException
     */
    public function test_total_files_includes_repositories_and_templates(): void
    {
        $symfonyMapping = SymfonyMapping::of(
            ProjectFileInventory::fromGroups([
                'persistenceQueries' => [$this->makeFile('src/Repository/UserRepository.php'), $this->makeFile('src/Repository/PostRepository.php')],
                'templates' => [$this->makeFile('templates/user/index.html.twig')],
            ]),
            new AccessControlMap(),
        );

        self::assertSame(3, $symfonyMapping->totalFiles());
    }

    /**
     * @throws InvalidProjectFileException
     */
    public function test_total_files_sums_all_seven_categories(): void
    {
        $symfonyMapping = SymfonyMapping::of(
            ProjectFileInventory::fromGroups([
                'entrypoints' => [$this->makeFile('src/Controller/FooController.php')],
                'domainModels' => [$this->makeFile('src/Entity/User.php'), $this->makeFile('src/Entity/Post.php')],
                'authorizationRules' => [$this->makeFile('src/Security/UserVoter.php')],
                'persistenceQueries' => [$this->makeFile('src/Repository/UserRepository.php')],
                'inputBindings' => [$this->makeFile('src/Form/UserType.php')],
                'services' => [$this->makeFile('src/Service/FooService.php')],
                'templates' => [$this->makeFile('templates/user/index.html.twig')],
            ]),
            new AccessControlMap(),
        );

        self::assertSame(8, $symfonyMapping->totalFiles());
    }

    /**
     * @throws InvalidProjectFileException
     */
    public function test_it_detects_voter_for_entity(): void
    {
        $projectFile = SymfonyProjectFile::create(
            'src/Security/UserVoter.php',
            '/app/src/Security/UserVoter.php',
            '<?php class UserVoter extends Voter { protected function supports(string $attribute, mixed $subject): bool { return $subject instanceof User; } }',
        );

        $symfonyMapping = SymfonyMapping::of(ProjectFileInventory::fromGroups(['authorizationRules' => [$projectFile]]), new AccessControlMap());

        self::assertTrue($symfonyMapping->toApplicationSecurityMap()->hasAuthorizationRuleForModel('User'));
        self::assertFalse($symfonyMapping->toApplicationSecurityMap()->hasAuthorizationRuleForModel('Post'));
    }

    /**
     * @throws InvalidProjectFileException
     */
    public function test_it_does_not_match_an_entity_name_that_is_only_a_substring_of_an_unrelated_identifier(): void
    {
        $projectFile = SymfonyProjectFile::create(
            'src/Security/AdminUserVoter.php',
            '/app/src/Security/AdminUserVoter.php',
            '<?php class AdminUserVoter extends Voter { protected function supports(string $attribute, mixed $subject): bool { return $subject instanceof AdminUser; } }',
        );

        $symfonyMapping = SymfonyMapping::of(ProjectFileInventory::fromGroups(['authorizationRules' => [$projectFile]]), new AccessControlMap());

        self::assertFalse($symfonyMapping->toApplicationSecurityMap()->hasAuthorizationRuleForModel('User'));
        self::assertTrue($symfonyMapping->toApplicationSecurityMap()->hasAuthorizationRuleForModel('AdminUser'));
    }

    /**
     * @throws InvalidProjectFileException
     */
    public function test_it_treats_a_regex_metacharacter_in_the_entity_name_literally(): void
    {
        $projectFile = SymfonyProjectFile::create(
            'src/Security/RegexVoter.php',
            '/app/src/Security/RegexVoter.php',
            '<?php class RegexVoter extends Voter { protected function supports(string $attribute, mixed $subject): bool { return $subject instanceof UserX; } }',
        );

        $symfonyMapping = SymfonyMapping::of(ProjectFileInventory::fromGroups(['authorizationRules' => [$projectFile]]), new AccessControlMap());

        self::assertFalse($symfonyMapping->toApplicationSecurityMap()->hasAuthorizationRuleForModel('User.'));
    }

    /**
     * @throws InvalidProjectFileException
     */
    public function test_it_finds_controllers_without_security_annotations(): void
    {
        $projectFile = SymfonyProjectFile::create(
            'src/Controller/SecureController.php',
            '/app/src/Controller/SecureController.php',
            '<?php #[IsGranted("ROLE_ADMIN")] class SecureController {}',
        );

        $insecure = SymfonyProjectFile::create(
            'src/Controller/PublicController.php',
            '/app/src/Controller/PublicController.php',
            '<?php class PublicController {}',
        );

        $symfonyMapping = SymfonyMapping::of(ProjectFileInventory::fromGroups(['entrypoints' => [$projectFile, $insecure]]), new AccessControlMap());
        $unprotected = $symfonyMapping->toApplicationSecurityMap()->entrypointsWithoutAuthorizationRule();

        self::assertCount(1, $unprotected);
        self::assertSame('src/Controller/PublicController.php', $unprotected[0]->relativePath());
    }

    /**
     * @throws InvalidProjectFileException
     */
    public function test_it_generates_summary_string(): void
    {
        $symfonyMapping = SymfonyMapping::of(
            ProjectFileInventory::fromGroups([
                'entrypoints' => [$this->makeFile('src/Controller/Foo.php')],
                'domainModels' => [$this->makeFile('src/Entity/User.php')],
            ]),
            new AccessControlMap(
                routeAccessMap: ['/admin' => ['ROLE_ADMIN']],
                perimeterRules: ['^/admin'],
            ),
        );

        $summary = $symfonyMapping->toSummary();

        self::assertStringContainsString('Controllers: 1', $summary);
        self::assertStringContainsString('Entities: 1', $summary);
        self::assertStringContainsString('Routes mapped: 1', $summary);
        self::assertStringContainsString('Firewall rules: 1', $summary);
    }

    /**
     * @deprecated covers the four Symfony-named accessors deprecated in 1.19 until they are removed in 2.0 — each must keep returning what its neutral counterpart does.
     */
    #[IgnoreDeprecations('vinceamstoutz/symfony-security-auditor')]
    public function test_deprecated_voter_capabilities_still_returns_the_authorization_rules(): void
    {
        $authorizationRuleCapability = new AuthorizationRuleCapability(
            filePath: 'src/Security/UserVoter.php',
            className: 'App\\Security\\UserVoter',
            supportedAttributes: ['EDIT'],
            supportedSubjects: ['App\\Entity\\User'],
        );
        $symfonyMapping = SymfonyMapping::of(ProjectFileInventory::fromGroups([]), new AccessControlMap(authorizationRules: [$authorizationRuleCapability]));

        $this->expectUserDeprecationMessageMatches('/SymfonyMapping::voterCapabilities\(\) is deprecated, use ApplicationSecurityMap::authorizationRules\(\) instead\./');

        self::assertSame([$authorizationRuleCapability], $symfonyMapping->voterCapabilities());
    }

    /**
     * @deprecated covers a 1.19 deprecation until 2.0.
     */
    #[IgnoreDeprecations('vinceamstoutz/symfony-security-auditor')]
    public function test_deprecated_firewall_rules_still_returns_the_perimeter_rules(): void
    {
        $symfonyMapping = SymfonyMapping::of(ProjectFileInventory::fromGroups([]), new AccessControlMap(perimeterRules: ['^/admin']));

        $this->expectUserDeprecationMessageMatches('/SymfonyMapping::firewallRules\(\) is deprecated, use ApplicationSecurityMap::perimeterRules\(\) instead\./');

        self::assertSame(['^/admin'], $symfonyMapping->firewallRules());
    }

    /**
     * @deprecated covers a 1.19 deprecation until 2.0.
     *
     * @throws InvalidProjectFileException
     */
    #[IgnoreDeprecations('vinceamstoutz/symfony-security-auditor')]
    public function test_deprecated_controllers_without_voters_still_returns_the_unguarded_entrypoints(): void
    {
        $projectFile = $this->makeFile('src/Controller/A.php');
        $symfonyMapping = SymfonyMapping::of(ProjectFileInventory::fromGroups(['entrypoints' => [$projectFile]]), new AccessControlMap());

        $this->expectUserDeprecationMessageMatches('/SymfonyMapping::controllersWithoutVoters\(\) is deprecated, use ApplicationSecurityMap::entrypointsWithoutAuthorizationRule\(\) instead\./');

        self::assertSame([$projectFile], $symfonyMapping->controllersWithoutVoters());
    }

    /**
     * @deprecated covers a 1.19 deprecation until 2.0.
     *
     * @throws InvalidProjectFileException
     */
    #[IgnoreDeprecations('vinceamstoutz/symfony-security-auditor')]
    public function test_deprecated_has_voter_for_entity_still_answers_for_the_model(): void
    {
        $projectFile = SymfonyProjectFile::create(
            'src/Security/UserVoter.php',
            '/app/src/Security/UserVoter.php',
            '<?php class UserVoter { public function supports($a, $s): bool { return $s instanceof User; } }',
        );
        $symfonyMapping = SymfonyMapping::of(ProjectFileInventory::fromGroups(['authorizationRules' => [$projectFile]]), new AccessControlMap());

        $this->expectUserDeprecationMessageMatches('/SymfonyMapping::hasVoterForEntity\(\) is deprecated, use ApplicationSecurityMap::hasAuthorizationRuleForModel\(\) instead\./');

        self::assertTrue($symfonyMapping->hasVoterForEntity('User'));
    }

    /**
     * @throws InvalidProjectFileException
     */
    private function makeFile(string $path): ProjectFile
    {
        return SymfonyProjectFile::create($path, '/app/'.$path, '<?php');
    }
}
