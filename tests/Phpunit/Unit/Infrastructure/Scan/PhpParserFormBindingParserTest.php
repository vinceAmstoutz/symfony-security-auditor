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

use Override;
use PHPUnit\Framework\TestCase;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidProjectFileException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFile;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Scan\PhpParserFormBindingParser;

final class PhpParserFormBindingParserTest extends TestCase
{
    private PhpParserFormBindingParser $phpParserFormBindingParser;

    #[Override]
    protected function setUp(): void
    {
        $this->phpParserFormBindingParser = new PhpParserFormBindingParser();
    }

    /**
     * @throws InvalidProjectFileException
     */
    public function test_it_returns_empty_for_non_controller_file(): void
    {
        $projectFile = ProjectFile::create('src/Service/Mailer.php', '/app/x', '<?php class Mailer {}');

        self::assertSame([], $this->phpParserFormBindingParser->parse($projectFile));
    }

    /**
     * @throws InvalidProjectFileException
     */
    public function test_it_skips_non_controller_files_even_when_they_call_create_form(): void
    {
        $source = <<<'PHP'
            <?php
            namespace App\Service;
            use App\Form\UserType;
            final class Helper {
                public function build(): void {
                    $form = $this->createForm(UserType::class);
                }
            }
            PHP;
        $projectFile = ProjectFile::create('src/Service/Helper.php', '/app/x', $source);

        self::assertSame([], $this->phpParserFormBindingParser->parse($projectFile));
    }

    /**
     * @throws InvalidProjectFileException
     */
    public function test_it_collects_a_binding_from_a_live_component_that_also_extends_abstract_controller(): void
    {
        $source = <<<'PHP'
            <?php
            namespace App\Twig\Components;
            use App\Form\CartCheckoutType;
            use Symfony\UX\LiveComponent\Attribute\AsLiveComponent;
            use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
            #[AsLiveComponent]
            final class Cart extends AbstractController {
                public function checkout(): void {
                    $form = $this->createForm(CartCheckoutType::class);
                }
            }
            PHP;
        $projectFile = ProjectFile::create('src/Twig/Components/Cart.php', '/app/x', $source);

        $bindings = $this->phpParserFormBindingParser->parse($projectFile);

        self::assertCount(1, $bindings);
        self::assertSame('App\\Form\\CartCheckoutType', $bindings[0]->formTypeClass());
    }

    /**
     * @throws InvalidProjectFileException
     */
    public function test_it_collects_bindings_from_multiple_methods_in_the_same_controller(): void
    {
        $source = <<<'PHP'
            <?php
            namespace App\Controller;
            use App\Form\UserType;
            use App\Form\ProfileType;
            final class UserController {
                public function edit(): void {
                    $form = $this->createForm(UserType::class);
                }

                public function profile(): void {
                    $form = $this->createForm(ProfileType::class);
                }
            }
            PHP;
        $projectFile = ProjectFile::create('src/Controller/UserController.php', '/app/x', $source);

        $bindings = $this->phpParserFormBindingParser->parse($projectFile);

        self::assertCount(2, $bindings);
        self::assertSame('edit', $bindings[0]->controllerMethod());
        self::assertSame('App\\Form\\UserType', $bindings[0]->formTypeClass());
        self::assertSame('profile', $bindings[1]->controllerMethod());
        self::assertSame('App\\Form\\ProfileType', $bindings[1]->formTypeClass());
    }

    /**
     * @throws InvalidProjectFileException
     */
    public function test_it_collects_bindings_from_multiple_classes_in_the_same_file(): void
    {
        $source = <<<'PHP'
            <?php
            namespace App\Controller;
            use App\Form\UserType;
            use App\Form\ProfileType;
            final class UserController {
                public function edit(): void {
                    $form = $this->createForm(UserType::class);
                }
            }
            final class ProfileController {
                public function show(): void {
                    $form = $this->createForm(ProfileType::class);
                }
            }
            PHP;
        $projectFile = ProjectFile::create('src/Controller/UserController.php', '/app/x', $source);

        $bindings = $this->phpParserFormBindingParser->parse($projectFile);

        self::assertCount(2, $bindings);
        self::assertSame('App\\Form\\UserType', $bindings[0]->formTypeClass());
        self::assertSame('App\\Form\\ProfileType', $bindings[1]->formTypeClass());
    }

    /**
     * @throws InvalidProjectFileException
     */
    public function test_it_skips_unresolvable_create_form_call_but_keeps_subsequent_ones(): void
    {
        $source = <<<'PHP'
            <?php
            namespace App\Controller;
            use App\Form\UserType;
            final class MixedController {
                public function edit(string $dynamicClass): void {
                    $unresolvable = $this->createForm($dynamicClass);
                    $resolvable = $this->createForm(UserType::class);
                }
            }
            PHP;
        $projectFile = ProjectFile::create('src/Controller/MixedController.php', '/app/x', $source);

        $bindings = $this->phpParserFormBindingParser->parse($projectFile);

        self::assertCount(1, $bindings);
        self::assertSame('App\\Form\\UserType', $bindings[0]->formTypeClass());
    }

    /**
     * @throws InvalidProjectFileException
     */
    public function test_it_continues_past_private_helpers_to_reach_public_create_form(): void
    {
        $source = <<<'PHP'
            <?php
            namespace App\Controller;
            use App\Form\UserType;
            final class HelpController {
                private function helperOne(): void {}
                private function helperTwo(): void {}
                public function edit(): void {
                    $form = $this->createForm(UserType::class);
                }
            }
            PHP;
        $projectFile = ProjectFile::create('src/Controller/HelpController.php', '/app/x', $source);

        $bindings = $this->phpParserFormBindingParser->parse($projectFile);

        self::assertCount(1, $bindings);
        self::assertSame('edit', $bindings[0]->controllerMethod());
    }

    /**
     * @throws InvalidProjectFileException
     */
    public function test_it_collects_a_binding_from_a_nullsafe_create_form_call(): void
    {
        $source = <<<'PHP'
            <?php
            namespace App\Controller;
            use App\Form\UserType;
            final class UserController {
                public function edit(): void {
                    $form = $this?->createForm(UserType::class);
                }
            }
            PHP;
        $projectFile = ProjectFile::create('src/Controller/UserController.php', '/app/x', $source);

        $bindings = $this->phpParserFormBindingParser->parse($projectFile);

        self::assertCount(1, $bindings);
        self::assertSame('App\\Form\\UserType', $bindings[0]->formTypeClass());
    }

    /**
     * @throws InvalidProjectFileException
     */
    public function test_it_returns_empty_for_unparseable_controller(): void
    {
        $projectFile = ProjectFile::create('src/Controller/Broken.php', '/app/x', '<?php class Broken { public function');

        self::assertSame([], $this->phpParserFormBindingParser->parse($projectFile));
    }

    /**
     * @throws InvalidProjectFileException
     */
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

    /**
     * @throws InvalidProjectFileException
     */
    public function test_it_extracts_form_type_when_named_arguments_reorder_type_after_data(): void
    {
        $source = <<<'PHP'
            <?php
            namespace App\Controller;
            use App\Form\UserType;
            final class UserController {
                public function edit(): void {
                    $form = $this->createForm(data: $this->getUser(), type: UserType::class);
                }
            }
            PHP;
        $projectFile = ProjectFile::create('src/Controller/UserController.php', '/app/x', $source);

        $bindings = $this->phpParserFormBindingParser->parse($projectFile);

        self::assertCount(1, $bindings);
        self::assertSame('App\\Form\\UserType', $bindings[0]->formTypeClass());
    }

    /**
     * @throws InvalidProjectFileException
     */
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

    /**
     * @throws InvalidProjectFileException
     */
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

    /**
     * @throws InvalidProjectFileException
     */
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

    /**
     * @throws InvalidProjectFileException
     */
    public function test_it_skips_an_abstract_action_without_a_body_then_binds_the_concrete_one(): void
    {
        $source = <<<'PHP'
            <?php
            namespace App\Controller;
            use App\Form\UserType;
            abstract class BaseController {
                abstract public function handle(): void;

                public function edit(): void {
                    $form = $this->createForm(UserType::class);
                }
            }
            PHP;
        $projectFile = ProjectFile::create('src/Controller/BaseController.php', '/app/x', $source);

        $bindings = $this->phpParserFormBindingParser->parse($projectFile);

        self::assertCount(1, $bindings);
        self::assertSame('edit', $bindings[0]->controllerMethod());
        self::assertSame('App\\Form\\UserType', $bindings[0]->formTypeClass());
    }

    /**
     * @throws InvalidProjectFileException
     */
    public function test_it_ignores_method_calls_that_are_not_create_form(): void
    {
        $source = <<<'PHP'
            <?php
            namespace App\Controller;
            use App\Form\UserType;
            final class UserController {
                public function edit(): void {
                    $this->renderForm();
                    $form = $this->createForm(UserType::class);
                }
            }
            PHP;
        $projectFile = ProjectFile::create('src/Controller/UserController.php', '/app/x', $source);

        $bindings = $this->phpParserFormBindingParser->parse($projectFile);

        self::assertCount(1, $bindings);
        self::assertSame('App\\Form\\UserType', $bindings[0]->formTypeClass());
    }

    /**
     * @throws InvalidProjectFileException
     */
    public function test_it_does_not_bind_a_non_create_form_call_that_takes_a_class_constant(): void
    {
        $source = <<<'PHP'
            <?php
            namespace App\Controller;
            use App\Twig\ProfileTemplate;
            final class UserController {
                public function edit(): void {
                    $this->render(ProfileTemplate::class);
                }
            }
            PHP;
        $projectFile = ProjectFile::create('src/Controller/UserController.php', '/app/x', $source);

        self::assertSame([], $this->phpParserFormBindingParser->parse($projectFile));
    }

    /**
     * @throws InvalidProjectFileException
     */
    public function test_it_ignores_create_form_called_on_something_other_than_this(): void
    {
        $source = <<<'PHP'
            <?php
            namespace App\Controller;
            final class UserController {
                public function edit(\App\Form\Factory $factory): void {
                    $form = $factory->createForm(\App\Form\UserType::class);
                }
            }
            PHP;
        $projectFile = ProjectFile::create('src/Controller/UserController.php', '/app/x', $source);

        self::assertSame([], $this->phpParserFormBindingParser->parse($projectFile));
    }

    /**
     * @throws InvalidProjectFileException
     */
    public function test_it_ignores_a_dynamic_method_name_call(): void
    {
        $source = <<<'PHP'
            <?php
            namespace App\Controller;
            final class UserController {
                public function edit(string $method): void {
                    $form = $this->$method(\App\Form\UserType::class);
                }
            }
            PHP;
        $projectFile = ProjectFile::create('src/Controller/UserController.php', '/app/x', $source);

        self::assertSame([], $this->phpParserFormBindingParser->parse($projectFile));
    }

    /**
     * @throws InvalidProjectFileException
     */
    public function test_it_ignores_create_form_with_no_arguments(): void
    {
        $source = <<<'PHP'
            <?php
            namespace App\Controller;
            final class UserController {
                public function edit(): void {
                    $form = $this->createForm();
                }
            }
            PHP;
        $projectFile = ProjectFile::create('src/Controller/UserController.php', '/app/x', $source);

        self::assertSame([], $this->phpParserFormBindingParser->parse($projectFile));
    }

    /**
     * @throws InvalidProjectFileException
     */
    public function test_it_ignores_create_form_with_a_dynamic_constant_name(): void
    {
        $source = <<<'PHP'
            <?php
            namespace App\Controller;
            final class UserController {
                public function edit(string $constant): void {
                    $form = $this->createForm(\App\Form\UserType::{$constant});
                }
            }
            PHP;
        $projectFile = ProjectFile::create('src/Controller/UserController.php', '/app/x', $source);

        self::assertSame([], $this->phpParserFormBindingParser->parse($projectFile));
    }

    /**
     * @throws InvalidProjectFileException
     */
    public function test_it_ignores_create_form_with_a_non_class_constant_fetch(): void
    {
        $source = <<<'PHP'
            <?php
            namespace App\Controller;
            final class UserController {
                public function edit(): void {
                    $form = $this->createForm(\App\Form\UserType::DEFAULT_NAME);
                }
            }
            PHP;
        $projectFile = ProjectFile::create('src/Controller/UserController.php', '/app/x', $source);

        self::assertSame([], $this->phpParserFormBindingParser->parse($projectFile));
    }

    /**
     * @throws InvalidProjectFileException
     */
    public function test_it_ignores_create_form_with_class_const_fetched_on_a_variable(): void
    {
        $source = <<<'PHP'
            <?php
            namespace App\Controller;
            final class UserController {
                public function edit(object $formType): void {
                    $form = $this->createForm($formType::class);
                }
            }
            PHP;
        $projectFile = ProjectFile::create('src/Controller/UserController.php', '/app/x', $source);

        self::assertSame([], $this->phpParserFormBindingParser->parse($projectFile));
    }
}
