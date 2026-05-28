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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Infrastructure\Scan;

use PHPUnit\Framework\TestCase;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFile;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\RouteAccessControl;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Scan\PhpParserControllerAccessControlParser;

final class PhpParserControllerAccessControlParserTest extends TestCase
{
    private PhpParserControllerAccessControlParser $phpParserControllerAccessControlParser;

    protected function setUp(): void
    {
        $this->phpParserControllerAccessControlParser = new PhpParserControllerAccessControlParser();
    }

    public function test_it_returns_empty_for_non_controller_file(): void
    {
        $projectFile = $this->makeFile('src/Service/Mailer.php', '<?php class Mailer { public function send() {} }');

        self::assertSame([], $this->phpParserControllerAccessControlParser->parse($projectFile));
    }

    public function test_it_extracts_action_with_route_and_no_access_check(): void
    {
        $source = <<<'PHP'
            <?php
            namespace App\Controller;
            use Symfony\Component\Routing\Attribute\Route;
            final class AdminController {
                #[Route(path: '/admin/users/{id}', methods: ['DELETE'])]
                public function deleteUser(int $id): void {}
            }
            PHP;
        $projectFile = $this->makeFile('src/Controller/AdminController.php', $source);

        $entries = $this->phpParserControllerAccessControlParser->parse($projectFile);

        self::assertCount(1, $entries);
        self::assertInstanceOf(RouteAccessControl::class, $entries[0]);
        self::assertSame('deleteUser', $entries[0]->methodName());
        self::assertSame('/admin/users/{id}', $entries[0]->routePath());
        self::assertSame(['DELETE'], $entries[0]->routeMethods());
        self::assertTrue($entries[0]->hasRouteAttribute());
        self::assertTrue($entries[0]->lacksAccessCheck());
    }

    public function test_it_records_method_level_is_granted(): void
    {
        $source = <<<'PHP'
            <?php
            namespace App\Controller;
            use Symfony\Component\Routing\Attribute\Route;
            use Symfony\Component\Security\Http\Attribute\IsGranted;
            final class AdminController {
                #[Route(path: '/admin/users/{id}', methods: ['DELETE'])]
                #[IsGranted('ROLE_ADMIN')]
                public function deleteUser(int $id): void {}
            }
            PHP;
        $projectFile = $this->makeFile('src/Controller/AdminController.php', $source);

        $entries = $this->phpParserControllerAccessControlParser->parse($projectFile);

        self::assertSame(['ROLE_ADMIN'], $entries[0]->methodLevelIsGranted());
        self::assertTrue($entries[0]->hasAccessCheck());
        self::assertFalse($entries[0]->lacksAccessCheck());
    }

    public function test_it_records_class_level_is_granted(): void
    {
        $source = <<<'PHP'
            <?php
            namespace App\Controller;
            use Symfony\Component\Routing\Attribute\Route;
            use Symfony\Component\Security\Http\Attribute\IsGranted;
            #[IsGranted('ROLE_USER')]
            final class AdminController {
                #[Route(path: '/admin/profile')]
                public function profile(): void {}
            }
            PHP;
        $projectFile = $this->makeFile('src/Controller/AdminController.php', $source);

        $entries = $this->phpParserControllerAccessControlParser->parse($projectFile);

        self::assertTrue($entries[0]->classHasIsGranted());
        self::assertTrue($entries[0]->hasAccessCheck());
    }

    public function test_it_records_deny_access_unless_granted_call(): void
    {
        $source = <<<'PHP'
            <?php
            namespace App\Controller;
            use Symfony\Component\Routing\Attribute\Route;
            final class AdminController {
                #[Route(path: '/admin/users/{id}/edit')]
                public function edit(int $id): void {
                    $this->denyAccessUnlessGranted('EDIT', $id);
                }
            }
            PHP;
        $projectFile = $this->makeFile('src/Controller/AdminController.php', $source);

        $entries = $this->phpParserControllerAccessControlParser->parse($projectFile);

        self::assertTrue($entries[0]->methodHasDenyAccess());
        self::assertTrue($entries[0]->hasAccessCheck());
    }

    public function test_it_emits_one_entry_per_public_method(): void
    {
        $source = <<<'PHP'
            <?php
            namespace App\Controller;
            use Symfony\Component\Routing\Attribute\Route;
            final class UserController {
                #[Route(path: '/users', methods: ['GET'])]
                public function list(): void {}

                #[Route(path: '/users/{id}', methods: ['DELETE'])]
                public function delete(int $id): void {}

                private function helper(): void {}
            }
            PHP;
        $projectFile = $this->makeFile('src/Controller/UserController.php', $source);

        $entries = $this->phpParserControllerAccessControlParser->parse($projectFile);

        self::assertCount(2, $entries);
        self::assertSame('list', $entries[0]->methodName());
        self::assertSame('delete', $entries[1]->methodName());
    }

    public function test_it_returns_empty_for_unparseable_source(): void
    {
        $projectFile = $this->makeFile('src/Controller/Broken.php', '<?php class Broken { public function');

        self::assertSame([], $this->phpParserControllerAccessControlParser->parse($projectFile));
    }

    private function makeFile(string $relativePath, string $content): ProjectFile
    {
        return ProjectFile::create($relativePath, '/app/'.$relativePath, $content);
    }
}
