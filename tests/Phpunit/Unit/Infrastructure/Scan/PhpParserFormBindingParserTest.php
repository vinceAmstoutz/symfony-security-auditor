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
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Scan\PhpParserFormBindingParser;

final class PhpParserFormBindingParserTest extends TestCase
{
    private PhpParserFormBindingParser $phpParserFormBindingParser;

    protected function setUp(): void
    {
        $this->phpParserFormBindingParser = new PhpParserFormBindingParser();
    }

    public function test_it_returns_empty_for_non_controller_file(): void
    {
        $projectFile = ProjectFile::create('src/Service/Mailer.php', '/app/x', '<?php class Mailer {}');

        self::assertSame([], $this->phpParserFormBindingParser->parse($projectFile));
    }

    public function test_it_returns_empty_for_unparseable_controller(): void
    {
        $projectFile = ProjectFile::create('src/Controller/Broken.php', '/app/x', '<?php class Broken { public function');

        self::assertSame([], $this->phpParserFormBindingParser->parse($projectFile));
    }

    public function test_it_extracts_form_type_from_create_form_call(): void
    {
        $source = <<<'PHP'
            <?php
            namespace App\Controller;
            use App\Form\UserType;
            final class UserController {
                public function edit(): void {
                    $form = $this->createForm(UserType::class);
                }
            }
            PHP;
        $projectFile = ProjectFile::create('src/Controller/UserController.php', '/app/x', $source);

        $bindings = $this->phpParserFormBindingParser->parse($projectFile);

        self::assertCount(1, $bindings);
        self::assertSame('edit', $bindings[0]->controllerMethod());
        self::assertSame('App\\Form\\UserType', $bindings[0]->formTypeClass());
        self::assertSame('src/Controller/UserController.php', $bindings[0]->controllerFilePath());
    }

    public function test_it_extracts_multiple_bindings_from_same_method(): void
    {
        $source = <<<'PHP'
            <?php
            namespace App\Controller;
            use App\Form\UserType;
            use App\Form\ProfileType;
            final class UserController {
                public function edit(): void {
                    $userForm = $this->createForm(UserType::class);
                    $profileForm = $this->createForm(ProfileType::class);
                }
            }
            PHP;
        $projectFile = ProjectFile::create('src/Controller/UserController.php', '/app/x', $source);

        $bindings = $this->phpParserFormBindingParser->parse($projectFile);

        self::assertCount(2, $bindings);
        self::assertSame('App\\Form\\UserType', $bindings[0]->formTypeClass());
        self::assertSame('App\\Form\\ProfileType', $bindings[1]->formTypeClass());
    }

    public function test_it_ignores_create_form_calls_with_non_class_argument(): void
    {
        $source = <<<'PHP'
            <?php
            namespace App\Controller;
            final class UserController {
                public function edit(string $formClass): void {
                    $form = $this->createForm($formClass);
                }
            }
            PHP;
        $projectFile = ProjectFile::create('src/Controller/UserController.php', '/app/x', $source);

        $bindings = $this->phpParserFormBindingParser->parse($projectFile);

        self::assertSame([], $bindings);
    }

    public function test_it_emits_no_bindings_when_controller_has_no_create_form_calls(): void
    {
        $source = <<<'PHP'
            <?php
            namespace App\Controller;
            final class UserController {
                public function list(): void {}
            }
            PHP;
        $projectFile = ProjectFile::create('src/Controller/UserController.php', '/app/x', $source);

        self::assertSame([], $this->phpParserFormBindingParser->parse($projectFile));
    }
}
