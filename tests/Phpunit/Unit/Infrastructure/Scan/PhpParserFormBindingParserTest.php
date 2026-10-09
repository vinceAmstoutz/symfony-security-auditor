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
use PhpParser\Node;
use PhpParser\ParserFactory;
use PHPUnit\Framework\TestCase;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Exception\InvalidProjectFileException;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\FormBinding;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFile;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Scan\PhpParserFormBindingParser;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Scan\ThisCallReachability;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Infrastructure\Scan\Fixture\CountingNodeFinder;

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
    public function test_it_attributes_a_create_form_call_inside_a_private_helper_to_the_public_action_that_reaches_it(): void
    {
        $source = <<<'PHP'
            <?php
            namespace App\Controller;
            use App\Form\UserType;
            final class UserController {
                public function edit(): void {
                    $this->processForm();
                }
                private function processForm(): void {
                    $form = $this->createForm(UserType::class);
                }
            }
            PHP;
        $projectFile = ProjectFile::create('src/Controller/UserController.php', '/app/x', $source);

        $bindings = $this->phpParserFormBindingParser->parse($projectFile);

        self::assertCount(1, $bindings);
        self::assertSame('edit', $bindings[0]->controllerMethod());
        self::assertSame('App\\Form\\UserType', $bindings[0]->formTypeClass());
    }

    /**
     * @throws InvalidProjectFileException
     */
    public function test_it_attributes_a_create_form_call_inside_a_helper_reached_via_self_call_to_the_public_action(): void
    {
        $source = <<<'PHP'
            <?php
            namespace App\Controller;
            use App\Form\UserType;
            final class UserController {
                public function edit(): void {
                    self::processForm();
                }
                private function processForm(): void {
                    $form = $this->createForm(UserType::class);
                }
            }
            PHP;
        $projectFile = ProjectFile::create('src/Controller/UserController.php', '/app/x', $source);

        $bindings = $this->phpParserFormBindingParser->parse($projectFile);

        self::assertCount(1, $bindings);
        self::assertSame('edit', $bindings[0]->controllerMethod());
        self::assertSame('App\\Form\\UserType', $bindings[0]->formTypeClass());
    }

    /**
     * @throws InvalidProjectFileException
     */
    public function test_it_collects_a_binding_from_a_direct_create_form_call_via_self(): void
    {
        $source = <<<'PHP'
            <?php
            namespace App\Controller;
            use App\Form\UserType;
            final class UserController {
                public function edit(): void {
                    $form = self::createForm(UserType::class);
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
    public function test_it_does_not_infinitely_recurse_when_private_helpers_call_each_other_in_a_cycle(): void
    {
        $source = <<<'PHP'
            <?php
            namespace App\Controller;
            use App\Form\UserType;
            final class UserController {
                public function edit(): void {
                    $this->helperA();
                }
                private function helperA(): void {
                    $this->helperB();
                }
                private function helperB(): void {
                    $this->helperA();
                    $form = $this->createForm(UserType::class);
                }
            }
            PHP;
        $projectFile = ProjectFile::create('src/Controller/UserController.php', '/app/x', $source);

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

    /**
     * @throws InvalidProjectFileException
     */
    public function test_it_orders_form_bindings_by_source_position_across_call_kinds(): void
    {
        $source = <<<'PHP'
            <?php
            namespace App\Controller;
            use App\Form\FirstType;
            use App\Form\SecondType;
            final class UserController {
                public function edit(): void {
                    $first = self::createForm(FirstType::class);
                    $second = $this->createForm(SecondType::class);
                }
            }
            PHP;
        $projectFile = ProjectFile::create('src/Controller/UserController.php', '/app/x', $source);

        $bindings = $this->phpParserFormBindingParser->parse($projectFile);

        self::assertSame(
            ['App\\Form\\FirstType', 'App\\Form\\SecondType'],
            [$bindings[0]->formTypeClass(), $bindings[1]->formTypeClass()],
        );
    }

    /**
     * @throws InvalidProjectFileException
     */
    public function test_it_skips_a_file_nested_too_deeply_to_parse_safely(): void
    {
        $nesting = str_repeat('f(', 33000).'1'.str_repeat(')', 33000);
        $source = <<<PHP
            <?php
            namespace App\Controller;
            use App\Form\UserType;
            final class UserController {
                public function edit(): void {
                    \$form = \$this->createForm(UserType::class);
                    \$x = {$nesting};
                }
            }
            PHP;
        $projectFile = ProjectFile::create('src/Controller/UserController.php', '/app/x', $source);

        self::assertSame([], $this->phpParserFormBindingParser->parse($projectFile));
    }

    /**
     * @throws InvalidProjectFileException
     */
    public function test_it_skips_a_file_holding_a_flood_of_unmatched_closing_brackets(): void
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
        $projectFile = ProjectFile::create('src/Controller/UserController.php', '/app/x', $source.str_repeat(')', 16000));

        self::assertSame([], $this->phpParserFormBindingParser->parse($projectFile));
    }

    /**
     * @throws InvalidProjectFileException
     */
    public function test_it_binds_a_form_created_in_a_helper_reached_along_two_paths_once(): void
    {
        $source = <<<'PHP'
            <?php
            namespace App\Controller;
            use App\Form\UserType;
            final class UserController {
                public function edit(): void {
                    $this->left();
                    $this->right();
                }
                private function left(): void { $this->build(); }
                private function right(): void { $this->build(); }
                private function build(): void { $form = $this->createForm(UserType::class); }
            }
            PHP;
        $projectFile = ProjectFile::create('src/Controller/UserController.php', '/app/x', $source);

        $bindings = $this->phpParserFormBindingParser->parse($projectFile);

        self::assertCount(1, $bindings);
        self::assertSame('edit', $bindings[0]->controllerMethod());
        self::assertSame('App\\Form\\UserType', $bindings[0]->formTypeClass());
    }

    /**
     * @throws InvalidProjectFileException
     */
    public function test_a_chain_of_public_actions_costs_a_bounded_number_of_tree_walks(): void
    {
        $actionCount = 400;
        $source = $this->chainOfPublicActionsEndingInAForm($actionCount);
        $countingNodeFinder = new CountingNodeFinder();
        $phpParserFormBindingParser = new PhpParserFormBindingParser(new ThisCallReachability($countingNodeFinder), $countingNodeFinder);

        $bindings = $phpParserFormBindingParser->parse(ProjectFile::create('src/Controller/ChainController.php', '/app/x', $source));

        self::assertCount($actionCount + 1, $bindings);
        self::assertSame('m0', $bindings[0]->controllerMethod());
        self::assertLessThan(8 * $this->nodeCount($source), $countingNodeFinder->visitedNodes);
    }

    /**
     * @throws InvalidProjectFileException
     */
    public function test_it_binds_a_form_created_several_times_in_one_action_once(): void
    {
        $source = <<<'PHP'
            <?php
            namespace App\Controller;
            use App\Form\UserType;
            use App\Form\ProfileType;
            final class UserController {
                public function edit(): void {
                    $first = $this->createForm(UserType::class);
                    $profile = $this->createForm(ProfileType::class);
                    $second = $this->createForm(UserType::class);
                }
            }
            PHP;

        $bindings = $this->phpParserFormBindingParser->parse(ProjectFile::create('src/Controller/UserController.php', '/app/x', $source));

        self::assertSame(
            ['App\\Form\\UserType', 'App\\Form\\ProfileType'],
            array_map(static fn (FormBinding $formBinding): string => $formBinding->formTypeClass(), $bindings),
        );
    }

    /**
     * @throws InvalidProjectFileException
     */
    public function test_a_chain_of_actions_each_creating_the_same_form_binds_each_action_once(): void
    {
        $actionCount = 60;
        $source = $this->chainOfActionsEachCreatingAForm($actionCount, static fn (): string => 'ItemType');

        $bindings = $this->phpParserFormBindingParser->parse(ProjectFile::create('src/Controller/ChainController.php', '/app/x', $source));

        self::assertSame(
            array_map(static fn (int $index): string => 'm'.$index, range(0, $actionCount - 1)),
            array_map(static fn (FormBinding $formBinding): string => $formBinding->controllerMethod(), $bindings),
        );
    }

    /**
     * @throws InvalidProjectFileException
     */
    public function test_a_chain_of_actions_each_creating_its_own_form_stops_at_the_binding_cap_per_file(): void
    {
        $source = $this->chainOfActionsEachCreatingAForm(600, static fn (int $index): string => 'Item'.$index.'Type');

        $bindings = $this->phpParserFormBindingParser->parse(ProjectFile::create('src/Controller/ChainController.php', '/app/x', $source));

        self::assertCount(500, $bindings);
        self::assertSame('m0', $bindings[499]->controllerMethod());
        self::assertSame('App\\Controller\\Item0Type', $bindings[0]->formTypeClass());
        self::assertSame('App\\Controller\\Item499Type', $bindings[499]->formTypeClass());
    }

    /**
     * @throws InvalidProjectFileException
     */
    public function test_a_file_binding_exactly_as_many_forms_as_the_cap_keeps_them_all(): void
    {
        $bindings = $this->phpParserFormBindingParser->parse(ProjectFile::create('src/Controller/WideController.php', '/app/x', $this->actionsEachCreatingItsOwnForm(500)));

        self::assertCount(500, $bindings);
        self::assertSame('m499', $bindings[499]->controllerMethod());
    }

    /**
     * @throws InvalidProjectFileException
     */
    public function test_a_file_binding_one_form_more_than_the_cap_drops_only_the_last_one(): void
    {
        $bindings = $this->phpParserFormBindingParser->parse(ProjectFile::create('src/Controller/WideController.php', '/app/x', $this->actionsEachCreatingItsOwnForm(501)));

        self::assertCount(500, $bindings);
        self::assertSame('m499', $bindings[499]->controllerMethod());
    }

    /**
     * @throws InvalidProjectFileException
     */
    public function test_the_binding_cap_is_shared_by_every_class_of_a_file(): void
    {
        $source = $this->actionsEachCreatingItsOwnForm(300)."\nclass SecondController extends AbstractController {\n";
        for ($i = 0; $i < 300; ++$i) {
            $source .= \sprintf("public function s%d() { \$this->createForm(Second%dType::class); }\n", $i, $i);
        }

        $bindings = $this->phpParserFormBindingParser->parse(ProjectFile::create('src/Controller/WideController.php', '/app/x', $source."}\n"));

        self::assertCount(500, $bindings);
        self::assertSame('s199', $bindings[499]->controllerMethod());
    }

    /**
     * @param callable(int): string $formTypeFor
     */
    private function chainOfActionsEachCreatingAForm(int $actionCount, callable $formTypeFor): string
    {
        $source = "<?php\nnamespace App\\Controller;\nfinal class ChainController extends AbstractController {\n";
        for ($i = 0; $i < $actionCount; ++$i) {
            $source .= \sprintf("public function m%d() { \$this->createForm(%s::class); \$this->m%d(); }\n", $i, $formTypeFor($i), $i + 1);
        }

        return $source.\sprintf("public function m%d() {}\n}\n", $actionCount);
    }

    private function actionsEachCreatingItsOwnForm(int $actionCount): string
    {
        $source = "<?php\nnamespace App\\Controller;\nfinal class WideController extends AbstractController {\n";
        for ($i = 0; $i < $actionCount; ++$i) {
            $source .= \sprintf("public function m%d() { \$this->createForm(Item%dType::class); }\n", $i, $i);
        }

        return $source."}\n";
    }

    private function chainOfPublicActionsEndingInAForm(int $actionCount): string
    {
        $source = "<?php\nnamespace App\\Controller;\nuse App\\Form\\ItemType;\nfinal class ChainController extends AbstractController {\n";
        for ($i = 0; $i < $actionCount; ++$i) {
            $source .= \sprintf("public function m%d() { return \$this->m%d(); }\n", $i, $i + 1);
        }

        return $source.\sprintf("public function m%d() { return \$this->createForm(ItemType::class); }\n}\n", $actionCount);
    }

    private function nodeCount(string $source): int
    {
        $ast = (new ParserFactory())->createForNewestSupportedVersion()->parse($source) ?? [];

        return \count((new CountingNodeFinder())->findInstanceOf($ast, Node::class));
    }
}
