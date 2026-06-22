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

    public function test_it_extracts_path_from_positional_route_argument(): void
    {
        $source = <<<'PHP'
            <?php
            namespace App\Controller;
            use Symfony\Component\Routing\Attribute\Route;
            final class HomeController {
                #[Route('/home', methods: ['GET'])]
                public function index(): void {}
            }
            PHP;
        $projectFile = $this->makeFile('src/Controller/HomeController.php', $source);

        $entries = $this->phpParserControllerAccessControlParser->parse($projectFile);

        self::assertCount(1, $entries);
        self::assertSame('/home', $entries[0]->routePath());
        self::assertSame(['GET'], $entries[0]->routeMethods());
    }

    public function test_it_continues_past_private_methods_to_reach_public_action_below(): void
    {
        $source = <<<'PHP'
            <?php
            namespace App\Controller;
            use Symfony\Component\Routing\Attribute\Route;
            final class HelpController {
                private function helperOne(): void {}
                private function helperTwo(): void {}
                #[Route(path: '/help', methods: ['GET'])]
                public function show(): void {}
            }
            PHP;
        $projectFile = $this->makeFile('src/Controller/HelpController.php', $source);

        $entries = $this->phpParserControllerAccessControlParser->parse($projectFile);

        self::assertCount(1, $entries);
        self::assertSame('show', $entries[0]->methodName());
    }

    public function test_it_extracts_methods_when_route_uses_methods_only(): void
    {
        $source = <<<'PHP'
            <?php
            namespace App\Controller;
            use Symfony\Component\Routing\Attribute\Route;
            final class GetOnlyController {
                #[Route(methods: ['GET'])]
                public function index(): void {}
            }
            PHP;
        $projectFile = $this->makeFile('src/Controller/GetOnlyController.php', $source);

        $entries = $this->phpParserControllerAccessControlParser->parse($projectFile);

        self::assertCount(1, $entries);
        self::assertSame(['GET'], $entries[0]->routeMethods());
        self::assertNull($entries[0]->routePath());
    }

    public function test_it_extracts_multiple_http_methods_from_route_attribute(): void
    {
        $source = <<<'PHP'
            <?php
            namespace App\Controller;
            use Symfony\Component\Routing\Attribute\Route;
            final class MultiMethodController {
                #[Route(path: '/multi', methods: ['GET', 'POST', 'PATCH'])]
                public function multi(): void {}
            }
            PHP;
        $projectFile = $this->makeFile('src/Controller/MultiMethodController.php', $source);

        $entries = $this->phpParserControllerAccessControlParser->parse($projectFile);

        self::assertSame(['GET', 'POST', 'PATCH'], $entries[0]->routeMethods());
    }

    public function test_it_records_multiple_is_granted_attributes_on_same_method(): void
    {
        $source = <<<'PHP'
            <?php
            namespace App\Controller;
            use Symfony\Component\Routing\Attribute\Route;
            use Symfony\Component\Security\Http\Attribute\IsGranted;
            final class MultiCheckController {
                #[Route(path: '/double')]
                #[IsGranted('ROLE_USER')]
                #[IsGranted('ROLE_ADMIN')]
                public function doubleCheck(): void {}
            }
            PHP;
        $projectFile = $this->makeFile('src/Controller/MultiCheckController.php', $source);

        $entries = $this->phpParserControllerAccessControlParser->parse($projectFile);

        self::assertSame(['ROLE_USER', 'ROLE_ADMIN'], $entries[0]->methodLevelIsGranted());
    }

    public function test_it_keeps_only_first_string_argument_of_is_granted_attribute(): void
    {
        $source = <<<'PHP'
            <?php
            namespace App\Controller;
            use Symfony\Component\Routing\Attribute\Route;
            use Symfony\Component\Security\Http\Attribute\IsGranted;
            final class TwoArgController {
                #[Route(path: '/two-args')]
                #[IsGranted('PRIMARY_ROLE', 'SECONDARY_ROLE')]
                public function twoArgs(): void {}
            }
            PHP;
        $projectFile = $this->makeFile('src/Controller/TwoArgController.php', $source);

        $entries = $this->phpParserControllerAccessControlParser->parse($projectFile);

        self::assertSame(['PRIMARY_ROLE'], $entries[0]->methodLevelIsGranted());
    }

    public function test_it_finds_is_granted_in_attribute_group_after_a_non_is_granted_attribute(): void
    {
        $source = <<<'PHP'
            <?php
            namespace App\Controller;
            use Symfony\Component\Routing\Attribute\Route;
            use Symfony\Component\Security\Http\Attribute\IsGranted;
            final class GroupedController {
                #[Route(path: '/grouped'), IsGranted('ROLE_GROUPED')]
                public function grouped(): void {}
            }
            PHP;
        $projectFile = $this->makeFile('src/Controller/GroupedController.php', $source);

        $entries = $this->phpParserControllerAccessControlParser->parse($projectFile);

        self::assertSame(['ROLE_GROUPED'], $entries[0]->methodLevelIsGranted());
    }

    public function test_it_skips_non_route_attributes_when_extracting_the_route(): void
    {
        $source = <<<'PHP'
            <?php
            namespace App\Controller;
            use Symfony\Component\Routing\Attribute\Route;
            use Symfony\Component\HttpKernel\Attribute\Cache;
            final class CachedController {
                #[Cache(maxage: 60)]
                #[Route(path: '/cached', methods: ['GET'])]
                public function cached(): void {}
            }
            PHP;
        $projectFile = $this->makeFile('src/Controller/CachedController.php', $source);

        $entries = $this->phpParserControllerAccessControlParser->parse($projectFile);

        self::assertSame('/cached', $entries[0]->routePath());
        self::assertTrue($entries[0]->hasRouteAttribute());
    }

    public function test_it_skips_a_non_route_attribute_listed_before_route_in_the_same_group(): void
    {
        $source = <<<'PHP'
            <?php
            namespace App\Controller;
            use Symfony\Component\Routing\Attribute\Route;
            use Symfony\Component\HttpKernel\Attribute\Cache;
            final class GroupedController {
                #[Cache(maxage: 60), Route(path: '/grouped-route', methods: ['GET'])]
                public function grouped(): void {}
            }
            PHP;
        $projectFile = $this->makeFile('src/Controller/GroupedController.php', $source);

        $entries = $this->phpParserControllerAccessControlParser->parse($projectFile);

        self::assertSame('/grouped-route', $entries[0]->routePath());
        self::assertTrue($entries[0]->hasRouteAttribute());
    }

    public function test_it_resolves_path_from_positional_argument_followed_by_a_named_argument(): void
    {
        $source = <<<'PHP'
            <?php
            namespace App\Controller;
            use Symfony\Component\Routing\Attribute\Route;
            final class ProfileController {
                #[Route('/profile', name: 'app_profile', methods: ['GET'])]
                public function profile(): void {}
            }
            PHP;
        $projectFile = $this->makeFile('src/Controller/ProfileController.php', $source);

        $entries = $this->phpParserControllerAccessControlParser->parse($projectFile);

        self::assertSame('/profile', $entries[0]->routePath());
        self::assertSame(['GET'], $entries[0]->routeMethods());
    }

    public function test_it_treats_only_the_first_positional_argument_as_the_path(): void
    {
        $source = <<<'PHP'
            <?php
            namespace App\Controller;
            use Symfony\Component\Routing\Attribute\Route;
            final class TwoPositionalController {
                #[Route('/two-positional', 'the_route_name', methods: ['GET'])]
                public function twoPositional(): void {}
            }
            PHP;
        $projectFile = $this->makeFile('src/Controller/TwoPositionalController.php', $source);

        $entries = $this->phpParserControllerAccessControlParser->parse($projectFile);

        self::assertSame('/two-positional', $entries[0]->routePath());
        self::assertSame(['GET'], $entries[0]->routeMethods());
    }

    public function test_it_resolves_the_first_positional_as_path_even_after_a_leading_named_argument(): void
    {
        // nikic/php-parser tolerates a positional after a named arg (PHP's compile-time ordering rule is not enforced here).
        $source = <<<'PHP'
            <?php
            namespace App\Controller;
            use Symfony\Component\Routing\Attribute\Route;
            final class PositionalAfterNamedController {
                #[Route(name: 'app_pos_after_named', '/positional-after-named', methods: ['GET'])]
                public function positionalAfterNamed(): void {}
            }
            PHP;
        $projectFile = $this->makeFile('src/Controller/PositionalAfterNamedController.php', $source);

        $entries = $this->phpParserControllerAccessControlParser->parse($projectFile);

        self::assertSame('/positional-after-named', $entries[0]->routePath());
    }

    public function test_it_resolves_path_from_named_argument_preceded_by_another_named_argument(): void
    {
        $source = <<<'PHP'
            <?php
            namespace App\Controller;
            use Symfony\Component\Routing\Attribute\Route;
            final class SettingsController {
                #[Route(name: 'app_settings', path: '/settings', methods: ['POST'])]
                public function settings(): void {}
            }
            PHP;
        $projectFile = $this->makeFile('src/Controller/SettingsController.php', $source);

        $entries = $this->phpParserControllerAccessControlParser->parse($projectFile);

        self::assertSame('/settings', $entries[0]->routePath());
        self::assertSame(['POST'], $entries[0]->routeMethods());
    }

    public function test_it_does_not_treat_a_named_first_argument_as_the_positional_path(): void
    {
        $source = <<<'PHP'
            <?php
            namespace App\Controller;
            use Symfony\Component\Routing\Attribute\Route;
            final class NamedOnlyController {
                #[Route(name: 'app_named_only', methods: ['GET'])]
                public function namedOnly(): void {}
            }
            PHP;
        $projectFile = $this->makeFile('src/Controller/NamedOnlyController.php', $source);

        $entries = $this->phpParserControllerAccessControlParser->parse($projectFile);

        self::assertNull($entries[0]->routePath());
        self::assertSame(['GET'], $entries[0]->routeMethods());
    }

    public function test_it_resolves_path_when_methods_argument_precedes_the_named_path(): void
    {
        $source = <<<'PHP'
            <?php
            namespace App\Controller;
            use Symfony\Component\Routing\Attribute\Route;
            final class LatePathController {
                #[Route(methods: ['GET'], path: '/late-path')]
                public function latePath(): void {}
            }
            PHP;
        $projectFile = $this->makeFile('src/Controller/LatePathController.php', $source);

        $entries = $this->phpParserControllerAccessControlParser->parse($projectFile);

        self::assertSame('/late-path', $entries[0]->routePath());
        self::assertSame(['GET'], $entries[0]->routeMethods());
    }

    public function test_it_reports_no_route_attribute_for_a_public_method_without_one(): void
    {
        $source = <<<'PHP'
            <?php
            namespace App\Controller;
            final class PlainController {
                public function noRoute(): void {}
            }
            PHP;
        $projectFile = $this->makeFile('src/Controller/PlainController.php', $source);

        $entries = $this->phpParserControllerAccessControlParser->parse($projectFile);

        self::assertCount(1, $entries);
        self::assertFalse($entries[0]->hasRouteAttribute());
        self::assertNull($entries[0]->routePath());
        self::assertSame([], $entries[0]->routeMethods());
    }

    public function test_it_ignores_is_granted_attribute_with_no_string_argument(): void
    {
        $source = <<<'PHP'
            <?php
            namespace App\Controller;
            use Symfony\Component\Routing\Attribute\Route;
            use Symfony\Component\Security\Http\Attribute\IsGranted;
            use Symfony\Component\ExpressionLanguage\Expression;
            final class ExpressionController {
                #[Route(path: '/expr')]
                #[IsGranted(new Expression('is_authenticated()'))]
                public function expr(): void {}
            }
            PHP;
        $projectFile = $this->makeFile('src/Controller/ExpressionController.php', $source);

        $entries = $this->phpParserControllerAccessControlParser->parse($projectFile);

        self::assertSame([], $entries[0]->methodLevelIsGranted());
    }

    public function test_it_treats_an_abstract_action_without_a_body_as_lacking_deny_access(): void
    {
        $source = <<<'PHP'
            <?php
            namespace App\Controller;
            use Symfony\Component\Routing\Attribute\Route;
            abstract class BaseController {
                #[Route(path: '/abstract')]
                abstract public function handle(): void;
            }
            PHP;
        $projectFile = $this->makeFile('src/Controller/BaseController.php', $source);

        $entries = $this->phpParserControllerAccessControlParser->parse($projectFile);

        self::assertCount(1, $entries);
        self::assertFalse($entries[0]->methodHasDenyAccess());
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
