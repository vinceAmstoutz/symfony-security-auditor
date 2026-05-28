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
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\FormBinding;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFile;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\RouteAccessControl;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\SymfonyMapping;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\VoterCapability;

final class SymfonyMappingTest extends TestCase
{
    public function test_it_creates_empty_mapping(): void
    {
        $symfonyMapping = SymfonyMapping::create();

        self::assertEmpty($symfonyMapping->controllers());
        self::assertEmpty($symfonyMapping->entities());
        self::assertEmpty($symfonyMapping->voters());
        self::assertEmpty($symfonyMapping->repositories());
        self::assertEmpty($symfonyMapping->forms());
        self::assertEmpty($symfonyMapping->services());
        self::assertEmpty($symfonyMapping->templates());
        self::assertEmpty($symfonyMapping->routeAccessMap());
        self::assertEmpty($symfonyMapping->firewallRules());
        self::assertEmpty($symfonyMapping->routeAccessControls());
        self::assertEmpty($symfonyMapping->controllersWithoutAccessCheck());
        self::assertEmpty($symfonyMapping->voterCapabilities());
        self::assertEmpty($symfonyMapping->formBindings());
        self::assertSame(0, $symfonyMapping->totalFiles());
    }

    public function test_it_exposes_voter_capabilities_and_can_find_voters_for_attribute_and_subject(): void
    {
        $userVoter = new VoterCapability(
            filePath: 'src/Security/UserVoter.php',
            className: 'App\\Security\\UserVoter',
            supportedAttributes: ['EDIT', 'DELETE'],
            supportedSubjects: ['App\\Entity\\User'],
        );
        $commentVoter = new VoterCapability(
            filePath: 'src/Security/CommentVoter.php',
            className: 'App\\Security\\CommentVoter',
            supportedAttributes: ['VIEW'],
            supportedSubjects: ['App\\Entity\\Comment'],
        );

        $symfonyMapping = SymfonyMapping::create(voterCapabilities: [$userVoter, $commentVoter]);

        self::assertSame([$userVoter, $commentVoter], $symfonyMapping->voterCapabilities());
        self::assertSame([$userVoter], $symfonyMapping->votersFor('EDIT', 'User'));
        self::assertSame([$commentVoter], $symfonyMapping->votersFor('VIEW', 'App\\Entity\\Comment'));
        self::assertSame([], $symfonyMapping->votersFor('PUBLISH', 'Post'));
    }

    public function test_it_exposes_form_bindings_and_can_filter_by_controller(): void
    {
        $userEdit = new FormBinding('src/Controller/UserController.php', 'edit', 'App\\Form\\UserType');
        $userPassword = new FormBinding('src/Controller/UserController.php', 'changePassword', 'App\\Form\\PasswordType');
        $admin = new FormBinding('src/Controller/AdminController.php', 'create', 'App\\Form\\AdminType');

        $symfonyMapping = SymfonyMapping::create(formBindings: [$userEdit, $userPassword, $admin]);

        self::assertSame([$userEdit, $userPassword, $admin], $symfonyMapping->formBindings());
        self::assertSame([$userEdit, $userPassword], $symfonyMapping->formBindingsForController('src/Controller/UserController.php'));
        self::assertSame([], $symfonyMapping->formBindingsForController('src/Controller/Other.php'));
    }

    public function test_it_exposes_route_access_controls(): void
    {
        $protected = new RouteAccessControl(
            filePath: 'src/Controller/AdminController.php',
            methodName: 'list',
            routePath: '/admin',
            routeMethods: ['GET'],
            hasRouteAttribute: true,
            methodLevelIsGranted: ['ROLE_ADMIN'],
            methodHasDenyAccess: false,
            classHasIsGranted: false,
        );
        $unprotected = new RouteAccessControl(
            filePath: 'src/Controller/PublicController.php',
            methodName: 'leak',
            routePath: '/leak',
            routeMethods: [],
            hasRouteAttribute: true,
            methodLevelIsGranted: [],
            methodHasDenyAccess: false,
            classHasIsGranted: false,
        );

        $symfonyMapping = SymfonyMapping::create(routeAccessControls: [$protected, $unprotected]);

        self::assertSame([$protected, $unprotected], $symfonyMapping->routeAccessControls());
        self::assertSame([$unprotected], $symfonyMapping->controllersWithoutAccessCheck());
    }

    public function test_it_counts_total_files_correctly(): void
    {
        $symfonyMapping = SymfonyMapping::create(
            controllers: [$this->makeFile('src/Controller/Foo.php')],
            entities: [$this->makeFile('src/Entity/User.php'), $this->makeFile('src/Entity/Post.php')],
            voters: [$this->makeFile('src/Security/UserVoter.php')],
        );

        self::assertSame(4, $symfonyMapping->totalFiles());
    }

    public function test_total_files_includes_forms_and_services(): void
    {
        $symfonyMapping = SymfonyMapping::create(
            forms: [$this->makeFile('src/Form/UserType.php')],
            services: [$this->makeFile('src/Service/FooService.php'), $this->makeFile('src/Service/BarService.php')],
        );

        self::assertSame(3, $symfonyMapping->totalFiles());
    }

    public function test_total_files_includes_repositories_and_templates(): void
    {
        $symfonyMapping = SymfonyMapping::create(
            repositories: [$this->makeFile('src/Repository/UserRepository.php'), $this->makeFile('src/Repository/PostRepository.php')],
            templates: [$this->makeFile('templates/user/index.html.twig')],
        );

        self::assertSame(3, $symfonyMapping->totalFiles());
    }

    public function test_total_files_sums_all_seven_categories(): void
    {
        $symfonyMapping = SymfonyMapping::create(
            controllers: [$this->makeFile('src/Controller/FooController.php')],
            entities: [$this->makeFile('src/Entity/User.php'), $this->makeFile('src/Entity/Post.php')],
            voters: [$this->makeFile('src/Security/UserVoter.php')],
            repositories: [$this->makeFile('src/Repository/UserRepository.php')],
            forms: [$this->makeFile('src/Form/UserType.php')],
            services: [$this->makeFile('src/Service/FooService.php')],
            templates: [$this->makeFile('templates/user/index.html.twig')],
        );

        self::assertSame(8, $symfonyMapping->totalFiles());
    }

    public function test_it_detects_voter_for_entity(): void
    {
        $projectFile = ProjectFile::create(
            'src/Security/UserVoter.php',
            '/app/src/Security/UserVoter.php',
            '<?php class UserVoter extends Voter { protected function supports(string $attribute, mixed $subject): bool { return $subject instanceof User; } }',
        );

        $symfonyMapping = SymfonyMapping::create(voters: [$projectFile]);

        self::assertTrue($symfonyMapping->hasVoterForEntity('User'));
        self::assertFalse($symfonyMapping->hasVoterForEntity('Post'));
    }

    public function test_it_finds_controllers_without_security_annotations(): void
    {
        $projectFile = ProjectFile::create(
            'src/Controller/SecureController.php',
            '/app/src/Controller/SecureController.php',
            '<?php #[IsGranted("ROLE_ADMIN")] class SecureController {}',
        );

        $insecure = ProjectFile::create(
            'src/Controller/PublicController.php',
            '/app/src/Controller/PublicController.php',
            '<?php class PublicController {}',
        );

        $symfonyMapping = SymfonyMapping::create(controllers: [$projectFile, $insecure]);
        $unprotected = $symfonyMapping->controllersWithoutVoters();

        self::assertCount(1, $unprotected);
        self::assertSame('src/Controller/PublicController.php', $unprotected[0]->relativePath());
    }

    public function test_it_generates_summary_string(): void
    {
        $symfonyMapping = SymfonyMapping::create(
            controllers: [$this->makeFile('src/Controller/Foo.php')],
            entities: [$this->makeFile('src/Entity/User.php')],
            routeAccessMap: ['/admin' => ['ROLE_ADMIN']],
            firewallRules: ['^/admin'],
        );

        $summary = $symfonyMapping->toSummary();

        self::assertStringContainsString('Controllers: 1', $summary);
        self::assertStringContainsString('Entities: 1', $summary);
        self::assertStringContainsString('Routes mapped: 1', $summary);
        self::assertStringContainsString('Firewall rules: 1', $summary);
    }

    private function makeFile(string $path): ProjectFile
    {
        return ProjectFile::create($path, '/app/'.$path, '<?php');
    }
}
