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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Infrastructure\Prompt;

use PHPUnit\Framework\TestCase;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFile;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\RouteAccessControl;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\SymfonyMapping;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Prompt\AttackerPromptBuilder;

final class AttackerPromptBuilderTest extends TestCase
{
    private AttackerPromptBuilder $attackerPromptBuilder;

    protected function setUp(): void
    {
        $this->attackerPromptBuilder = new AttackerPromptBuilder();
    }

    public function test_it_formats_no_voter_controller_list_with_prefix_and_path(): void
    {
        $projectFile = ProjectFile::create(
            'src/Controller/PublicController.php',
            '/app/src/Controller/PublicController.php',
            '<?php class PublicController {}',
        );

        $symfonyMapping = SymfonyMapping::create(controllers: [$projectFile]);

        $message = $this->attackerPromptBuilder->buildUserMessage([$projectFile], $symfonyMapping);

        self::assertStringContainsString('  - src/Controller/PublicController.php', $message);
    }

    public function test_user_message_renders_route_access_control_map_with_lacks_check_marker(): void
    {
        $projectFile = ProjectFile::create(
            'src/Controller/AdminController.php',
            '/app/src/Controller/AdminController.php',
            '<?php class AdminController {}',
        );
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

        $symfonyMapping = SymfonyMapping::create(
            controllers: [$projectFile],
            routeAccessControls: [$routeAccessControl],
        );

        $message = $this->attackerPromptBuilder->buildUserMessage([$projectFile], $symfonyMapping);

        self::assertStringContainsString('Route Access-Control Map', $message);
        self::assertStringContainsString('/admin/users/{id}', $message);
        self::assertStringContainsString('DELETE', $message);
        self::assertStringContainsString('AdminController.php::deleteUser', $message);
        self::assertStringContainsString('LACKS_ACCESS_CHECK', $message);
    }

    public function test_user_message_renders_access_check_labels_for_protected_action(): void
    {
        $projectFile = ProjectFile::create(
            'src/Controller/UserController.php',
            '/app/src/Controller/UserController.php',
            '<?php class UserController {}',
        );
        $routeAccessControl = new RouteAccessControl(
            filePath: 'src/Controller/UserController.php',
            methodName: 'show',
            routePath: '/users/{id}',
            routeMethods: ['GET'],
            hasRouteAttribute: true,
            methodLevelIsGranted: ['ROLE_USER'],
            methodHasDenyAccess: true,
            classHasIsGranted: true,
        );

        $symfonyMapping = SymfonyMapping::create(
            controllers: [$projectFile],
            routeAccessControls: [$routeAccessControl],
        );

        $message = $this->attackerPromptBuilder->buildUserMessage([$projectFile], $symfonyMapping);

        self::assertStringContainsString('class:#[IsGranted]', $message);
        self::assertStringContainsString('method:#[IsGranted(ROLE_USER)]', $message);
        self::assertStringContainsString('body:denyAccessUnlessGranted()', $message);
        self::assertStringNotContainsString('LACKS_ACCESS_CHECK', $message);
    }

    public function test_user_message_omits_access_control_section_when_no_routes_parsed(): void
    {
        $projectFile = ProjectFile::create(
            'src/Controller/PlainController.php',
            '/app/src/Controller/PlainController.php',
            '<?php class PlainController {}',
        );

        $symfonyMapping = SymfonyMapping::create(controllers: [$projectFile]);

        $message = $this->attackerPromptBuilder->buildUserMessage([$projectFile], $symfonyMapping);

        self::assertStringNotContainsString('Route Access-Control Map', $message);
    }

    public function test_user_message_renders_any_label_when_route_methods_are_unspecified(): void
    {
        $projectFile = ProjectFile::create(
            'src/Controller/AnyController.php',
            '/app/src/Controller/AnyController.php',
            '<?php class AnyController {}',
        );
        $routeAccessControl = new RouteAccessControl(
            filePath: 'src/Controller/AnyController.php',
            methodName: 'index',
            routePath: '/any',
            routeMethods: [],
            hasRouteAttribute: true,
            methodLevelIsGranted: [],
            methodHasDenyAccess: false,
            classHasIsGranted: false,
        );

        $symfonyMapping = SymfonyMapping::create(
            controllers: [$projectFile],
            routeAccessControls: [$routeAccessControl],
        );

        $message = $this->attackerPromptBuilder->buildUserMessage([$projectFile], $symfonyMapping);

        self::assertStringContainsString('ANY /any', $message);
    }

    public function test_user_message_renders_unresolved_label_when_route_path_is_missing(): void
    {
        $projectFile = ProjectFile::create(
            'src/Controller/UnresolvedController.php',
            '/app/src/Controller/UnresolvedController.php',
            '<?php class UnresolvedController {}',
        );
        $routeAccessControl = new RouteAccessControl(
            filePath: 'src/Controller/UnresolvedController.php',
            methodName: 'index',
            routePath: null,
            routeMethods: ['GET'],
            hasRouteAttribute: true,
            methodLevelIsGranted: [],
            methodHasDenyAccess: false,
            classHasIsGranted: false,
        );

        $symfonyMapping = SymfonyMapping::create(
            controllers: [$projectFile],
            routeAccessControls: [$routeAccessControl],
        );

        $message = $this->attackerPromptBuilder->buildUserMessage([$projectFile], $symfonyMapping);

        self::assertStringContainsString('(unresolved)', $message);
    }

    public function test_it_excludes_secured_controllers_from_no_voter_list(): void
    {
        $projectFile = ProjectFile::create(
            'src/Controller/SecuredController.php',
            '/app/src/Controller/SecuredController.php',
            '<?php class SecuredController { public function __construct() { $this->denyAccessUnlessGranted("ROLE_USER"); } }',
        );

        $symfonyMapping = SymfonyMapping::create(controllers: [$projectFile]);

        $message = $this->attackerPromptBuilder->buildUserMessage([$projectFile], $symfonyMapping);

        self::assertStringNotContainsString('  - src/Controller/SecuredController.php', $message);
    }

    public function test_it_lists_multiple_no_voter_controllers_each_on_own_line(): void
    {
        $projectFile = ProjectFile::create(
            'src/Controller/AController.php',
            '/app/src/Controller/AController.php',
            '<?php class AController {}',
        );
        $controllerB = ProjectFile::create(
            'src/Controller/BController.php',
            '/app/src/Controller/BController.php',
            '<?php class BController {}',
        );

        $symfonyMapping = SymfonyMapping::create(controllers: [$projectFile, $controllerB]);

        $message = $this->attackerPromptBuilder->buildUserMessage([$projectFile, $controllerB], $symfonyMapping);

        self::assertStringContainsString('  - src/Controller/AController.php', $message);
        self::assertStringContainsString('  - src/Controller/BController.php', $message);
    }

    public function test_base_system_prompt_has_no_skill_block_when_no_files(): void
    {
        $prompt = $this->attackerPromptBuilder->buildSystemPrompt();

        self::assertStringContainsString('elite offensive security researcher', $prompt);
        self::assertStringNotContainsString('<skills role="', $prompt);
    }

    public function test_it_injects_controller_skills_when_controller_in_chunk(): void
    {
        $projectFile = ProjectFile::create(
            'src/Controller/UserController.php',
            '/app/src/Controller/UserController.php',
            '<?php class UserController {}',
        );

        $prompt = $this->attackerPromptBuilder->buildSystemPrompt([$projectFile]);

        self::assertStringContainsString('<skills role="controller">', $prompt);
        self::assertStringContainsString('denyAccessUnlessGranted', $prompt);
        self::assertStringNotContainsString('<skills role="voter">', $prompt);
    }

    public function test_it_injects_voter_skills_when_voter_in_chunk(): void
    {
        $projectFile = ProjectFile::create(
            'src/Security/PostVoter.php',
            '/app/src/Security/PostVoter.php',
            '<?php class PostVoter {}',
        );

        $prompt = $this->attackerPromptBuilder->buildSystemPrompt([$projectFile]);

        self::assertStringContainsString('<skills role="voter">', $prompt);
        self::assertStringContainsString('voteOnAttribute', $prompt);
    }

    public function test_it_injects_entity_skills_when_entity_in_chunk(): void
    {
        $projectFile = ProjectFile::create(
            'src/Entity/User.php',
            '/app/src/Entity/User.php',
            '<?php namespace App\\Entity; class User {}',
        );

        $prompt = $this->attackerPromptBuilder->buildSystemPrompt([$projectFile]);

        self::assertStringContainsString('<skills role="entity">', $prompt);
    }

    public function test_it_injects_repository_skills_when_repository_in_chunk(): void
    {
        $projectFile = ProjectFile::create(
            'src/Repository/UserRepository.php',
            '/app/src/Repository/UserRepository.php',
            '<?php class UserRepository {}',
        );

        $prompt = $this->attackerPromptBuilder->buildSystemPrompt([$projectFile]);

        self::assertStringContainsString('<skills role="repository">', $prompt);
    }

    public function test_it_injects_form_skills_when_form_in_chunk(): void
    {
        $projectFile = ProjectFile::create(
            'src/Form/UserType.php',
            '/app/src/Form/UserType.php',
            '<?php class UserType {}',
        );

        $prompt = $this->attackerPromptBuilder->buildSystemPrompt([$projectFile]);

        self::assertStringContainsString('<skills role="form">', $prompt);
    }

    public function test_it_injects_template_skills_when_twig_in_chunk(): void
    {
        $projectFile = ProjectFile::create(
            'templates/base.html.twig',
            '/app/templates/base.html.twig',
            '{{ user.name }}',
        );

        $prompt = $this->attackerPromptBuilder->buildSystemPrompt([$projectFile]);

        self::assertStringContainsString('<skills role="template">', $prompt);
    }

    public function test_it_injects_config_skills_when_yaml_in_chunk(): void
    {
        $projectFile = ProjectFile::create(
            'config/packages/security.yaml',
            '/app/config/packages/security.yaml',
            'security: {}',
        );

        $prompt = $this->attackerPromptBuilder->buildSystemPrompt([$projectFile]);

        self::assertStringContainsString('<skills role="config">', $prompt);
    }

    public function test_it_injects_php_skills_when_generic_service_in_chunk(): void
    {
        $projectFile = ProjectFile::create(
            'src/Service/Mailer.php',
            '/app/src/Service/Mailer.php',
            '<?php class Mailer {}',
        );

        $prompt = $this->attackerPromptBuilder->buildSystemPrompt([$projectFile]);

        self::assertStringContainsString('<skills role="php">', $prompt);
    }

    public function test_skill_block_is_closed_with_matching_tag(): void
    {
        $projectFile = ProjectFile::create(
            'src/Controller/UserController.php',
            '/app/src/Controller/UserController.php',
            '<?php class UserController {}',
        );

        $prompt = $this->attackerPromptBuilder->buildSystemPrompt([$projectFile]);

        self::assertStringContainsString('</skills>', $prompt);
    }

    public function test_it_combines_multiple_skill_blocks_when_chunk_has_mixed_types(): void
    {
        $projectFile = ProjectFile::create(
            'src/Controller/UserController.php',
            '/app/src/Controller/UserController.php',
            '<?php class UserController {}',
        );
        $voter = ProjectFile::create(
            'src/Security/PostVoter.php',
            '/app/src/Security/PostVoter.php',
            '<?php class PostVoter {}',
        );

        $prompt = $this->attackerPromptBuilder->buildSystemPrompt([$projectFile, $voter]);

        self::assertStringContainsString('<skills role="controller">', $prompt);
        self::assertStringContainsString('<skills role="voter">', $prompt);
    }

    public function test_skill_blocks_are_emitted_in_attack_surface_priority_order(): void
    {
        $projectFile = ProjectFile::create(
            'src/Security/PostVoter.php',
            '/app/src/Security/PostVoter.php',
            '<?php class PostVoter {}',
        );
        $controller = ProjectFile::create(
            'src/Controller/UserController.php',
            '/app/src/Controller/UserController.php',
            '<?php class UserController {}',
        );

        $prompt = $this->attackerPromptBuilder->buildSystemPrompt([$projectFile, $controller]);

        // Controller has higher attack-surface priority than Voter — must appear first regardless of input order.
        $controllerPos = strpos($prompt, '<skills role="controller">');
        $voterPos = strpos($prompt, '<skills role="voter">');

        self::assertNotFalse($controllerPos);
        self::assertNotFalse($voterPos);
        self::assertLessThan($voterPos, $controllerPos);
    }

    public function test_template_skill_appears_before_config_skill_under_priority_order(): void
    {
        // Under alphabetical sort, config (c) would precede template (t). Priority order flips this.
        $projectFile = ProjectFile::create(
            'templates/base.html.twig',
            '/app/templates/base.html.twig',
            '{{ user.name }}',
        );
        $config = ProjectFile::create(
            'config/packages/security.yaml',
            '/app/config/packages/security.yaml',
            'security: {}',
        );

        $prompt = $this->attackerPromptBuilder->buildSystemPrompt([$config, $projectFile]);

        $templatePos = strpos($prompt, '<skills role="template">');
        $configPos = strpos($prompt, '<skills role="config">');

        self::assertNotFalse($templatePos);
        self::assertNotFalse($configPos);
        self::assertLessThan($configPos, $templatePos);
    }

    public function test_each_type_skill_block_appears_only_once_when_chunk_has_duplicates(): void
    {
        $projectFile = ProjectFile::create(
            'src/Controller/AController.php',
            '/app/src/Controller/AController.php',
            '<?php class AController {}',
        );
        $controllerB = ProjectFile::create(
            'src/Controller/BController.php',
            '/app/src/Controller/BController.php',
            '<?php class BController {}',
        );

        $prompt = $this->attackerPromptBuilder->buildSystemPrompt([$projectFile, $controllerB]);

        self::assertSame(1, substr_count($prompt, '<skills role="controller">'));
    }

    public function test_unknown_file_type_does_not_inject_skill_block(): void
    {
        $projectFile = ProjectFile::create(
            'unknown.bin',
            '/app/unknown.bin',
            'binary',
        );

        $prompt = $this->attackerPromptBuilder->buildSystemPrompt([$projectFile]);

        self::assertStringNotContainsString('<skills role="', $prompt);
    }

    public function test_base_prompt_has_no_trailing_separator_when_no_files(): void
    {
        $prompt = $this->attackerPromptBuilder->buildSystemPrompt();

        self::assertStringEndsWith('causes the response to be discarded as malformed.', $prompt);
    }

    public function test_base_prompt_has_no_trailing_separator_when_files_have_no_matching_skill(): void
    {
        $projectFile = ProjectFile::create(
            'unknown.bin',
            '/app/unknown.bin',
            'binary',
        );

        $prompt = $this->attackerPromptBuilder->buildSystemPrompt([$projectFile]);

        self::assertStringEndsWith('causes the response to be discarded as malformed.', $prompt);
    }

    public function test_skill_block_is_separated_from_base_by_exactly_one_blank_line(): void
    {
        $projectFile = ProjectFile::create(
            'src/Controller/UserController.php',
            '/app/src/Controller/UserController.php',
            '<?php class UserController {}',
        );

        $prompt = $this->attackerPromptBuilder->buildSystemPrompt([$projectFile]);

        self::assertStringContainsString(
            "causes the response to be discarded as malformed.\n\n<skills role=\"controller\">",
            $prompt,
        );
    }

    public function test_base_prompt_contains_severity_rubric_with_all_five_tiers(): void
    {
        $prompt = $this->attackerPromptBuilder->buildSystemPrompt();

        self::assertStringContainsString('Severity rubric', $prompt);
        self::assertStringContainsString('- critical:', $prompt);
        self::assertStringContainsString('- high:', $prompt);
        self::assertStringContainsString('- medium:', $prompt);
        self::assertStringContainsString('- low:', $prompt);
        self::assertStringContainsString('- info:', $prompt);
    }

    public function test_severity_rubric_anchors_critical_to_unauthenticated_rce(): void
    {
        $prompt = $this->attackerPromptBuilder->buildSystemPrompt();

        // The critical tier is anchored to concrete impact, not left as freeform.
        $criticalLineStart = strpos($prompt, '- critical:');
        self::assertNotFalse($criticalLineStart);

        $criticalLineEnd = strpos($prompt, "\n", $criticalLineStart);
        self::assertNotFalse($criticalLineEnd);

        $criticalLine = substr($prompt, $criticalLineStart, $criticalLineEnd - $criticalLineStart);
        self::assertStringContainsString('unauthenticated RCE', $criticalLine);
    }

    public function test_user_message_wraps_source_files_in_xml_file_tags(): void
    {
        $projectFile = ProjectFile::create(
            'src/Controller/UserController.php',
            '/app/src/Controller/UserController.php',
            '<?php class UserController {}',
        );

        $message = $this->attackerPromptBuilder->buildUserMessage(
            [$projectFile],
            SymfonyMapping::create(),
        );

        self::assertStringContainsString(
            '<file path="src/Controller/UserController.php" type="controller">',
            $message,
        );
        self::assertStringContainsString('</file>', $message);
    }

    public function test_user_message_does_not_use_legacy_markdown_fence_for_source_files(): void
    {
        $projectFile = ProjectFile::create(
            'src/Controller/UserController.php',
            '/app/src/Controller/UserController.php',
            '<?php class UserController {}',
        );

        $message = $this->attackerPromptBuilder->buildUserMessage(
            [$projectFile],
            SymfonyMapping::create(),
        );

        self::assertStringNotContainsString('```php', $message);
        self::assertStringNotContainsString('### src/Controller/UserController.php', $message);
    }

    public function test_prompt_starts_with_base_persona_even_when_skills_present(): void
    {
        $projectFile = ProjectFile::create(
            'src/Controller/UserController.php',
            '/app/src/Controller/UserController.php',
            '<?php class UserController {}',
        );

        $prompt = $this->attackerPromptBuilder->buildSystemPrompt([$projectFile]);

        self::assertStringStartsWith('You are an elite offensive security researcher', $prompt);
    }

    public function test_user_message_prepends_line_numbers_to_each_source_line(): void
    {
        $projectFile = ProjectFile::create(
            'src/Service/Multi.php',
            '/app/src/Service/Multi.php',
            "<?php\n\nclass Multi {}",
        );

        $message = $this->attackerPromptBuilder->buildUserMessage(
            [$projectFile],
            SymfonyMapping::create(),
        );

        // Lock both per-line numbering AND the "\n" separator between lines —
        // mutating implode's separator to "" would collapse these into one string.
        self::assertStringContainsString("  1 | <?php\n  2 | \n  3 | class Multi {}", $message);
    }

    public function test_user_message_explains_line_number_protocol_to_the_model(): void
    {
        $projectFile = ProjectFile::create(
            'src/Controller/UserController.php',
            '/app/src/Controller/UserController.php',
            '<?php class UserController {}',
        );

        $message = $this->attackerPromptBuilder->buildUserMessage(
            [$projectFile],
            SymfonyMapping::create(),
        );

        self::assertStringContainsString('Each line is prefixed with its line number', $message);
        self::assertStringContainsString('do NOT count manually or guess', $message);
    }

    public function test_base_prompt_includes_few_shot_example_with_traceable_line_numbers(): void
    {
        $prompt = $this->attackerPromptBuilder->buildSystemPrompt();

        self::assertStringContainsString('Example finding', $prompt);
        self::assertStringContainsString('"line_start": 42', $prompt);
        self::assertStringContainsString('"line_end": 46', $prompt);
    }

    public function test_base_prompt_warns_example_must_not_be_echoed(): void
    {
        $prompt = $this->attackerPromptBuilder->buildSystemPrompt();

        self::assertStringContainsString('do NOT echo this in your output', $prompt);
    }

    public function test_base_prompt_includes_scope_exclusion_for_vendor_and_cache_paths(): void
    {
        $prompt = $this->attackerPromptBuilder->buildSystemPrompt();

        self::assertStringContainsString('Ignore code under `vendor/`', $prompt);
        self::assertStringContainsString('var/cache/', $prompt);
        self::assertStringContainsString('.generated.', $prompt);
    }

    public function test_base_prompt_includes_confidence_rubric_with_filter_threshold(): void
    {
        $prompt = $this->attackerPromptBuilder->buildSystemPrompt();

        self::assertStringContainsString('Confidence rubric', $prompt);
        self::assertStringContainsString('Below 0.6: do NOT report', $prompt);
    }

    public function test_skill_block_contains_negative_examples_to_curb_false_positives(): void
    {
        $projectFile = ProjectFile::create(
            'src/Controller/UserController.php',
            '/app/src/Controller/UserController.php',
            '<?php class UserController {}',
        );

        $prompt = $this->attackerPromptBuilder->buildSystemPrompt([$projectFile]);

        self::assertStringContainsString('Do NOT flag:', $prompt);
    }

    public function test_php_skill_block_documents_safe_process_invocation(): void
    {
        $projectFile = ProjectFile::create(
            'src/Service/Mailer.php',
            '/app/src/Service/Mailer.php',
            '<?php class Mailer {}',
        );

        $prompt = $this->attackerPromptBuilder->buildSystemPrompt([$projectFile]);

        self::assertStringContainsString("new Process(['ls', '-la'])", $prompt);
    }

    public function test_prompt_version_is_bumped_when_modern_symfony_skill_blocks_are_added(): void
    {
        self::assertSame(6, AttackerPromptBuilder::PROMPT_VERSION);
    }

    public function test_entity_skill_block_mentions_over_permissive_serializer_groups(): void
    {
        $projectFile = ProjectFile::create(
            'src/Entity/User.php',
            '/app/src/Entity/User.php',
            '<?php namespace App\\Entity; class User {}',
        );

        $prompt = $this->attackerPromptBuilder->buildSystemPrompt([$projectFile]);

        self::assertStringContainsString('#[Groups(', $prompt);
        self::assertStringContainsString('over_permissive_serializer_group', $prompt);
    }

    public function test_it_injects_authenticator_skills_when_authenticator_in_chunk(): void
    {
        $projectFile = ProjectFile::create(
            'src/Security/LoginFormAuthenticator.php',
            '/app/src/Security/LoginFormAuthenticator.php',
            '<?php class LoginFormAuthenticator {}',
        );

        $prompt = $this->attackerPromptBuilder->buildSystemPrompt([$projectFile]);

        self::assertStringContainsString('<skills role="authenticator">', $prompt);
        self::assertStringContainsString('SelfValidatingPassport', $prompt);
    }

    public function test_it_injects_messenger_handler_skills_when_handler_in_chunk(): void
    {
        $projectFile = ProjectFile::create(
            'src/Messenger/Handler/SendInvoiceMessageHandler.php',
            '/app/src/Messenger/Handler/SendInvoiceMessageHandler.php',
            '<?php class SendInvoiceMessageHandler {}',
        );

        $prompt = $this->attackerPromptBuilder->buildSystemPrompt([$projectFile]);

        self::assertStringContainsString('<skills role="messenger_handler">', $prompt);
        self::assertStringContainsString('AsMessageHandler', $prompt);
    }

    public function test_it_injects_webhook_consumer_skills_when_webhook_in_chunk(): void
    {
        $projectFile = ProjectFile::create(
            'src/Webhook/StripeWebhookConsumer.php',
            '/app/src/Webhook/StripeWebhookConsumer.php',
            '<?php class StripeWebhookConsumer {}',
        );

        $prompt = $this->attackerPromptBuilder->buildSystemPrompt([$projectFile]);

        self::assertStringContainsString('<skills role="webhook_consumer">', $prompt);
        self::assertStringContainsString('hash_equals', $prompt);
    }

    public function test_it_injects_event_subscriber_skills_when_subscriber_in_chunk(): void
    {
        $projectFile = ProjectFile::create(
            'src/EventSubscriber/AuditSubscriber.php',
            '/app/src/EventSubscriber/AuditSubscriber.php',
            '<?php class AuditSubscriber {}',
        );

        $prompt = $this->attackerPromptBuilder->buildSystemPrompt([$projectFile]);

        self::assertStringContainsString('<skills role="event_subscriber">', $prompt);
        self::assertStringContainsString('KernelEvents::CONTROLLER', $prompt);
    }

    public function test_it_injects_normalizer_skills_when_normalizer_in_chunk(): void
    {
        $projectFile = ProjectFile::create(
            'src/Serializer/UserNormalizer.php',
            '/app/src/Serializer/UserNormalizer.php',
            '<?php class UserNormalizer {}',
        );

        $prompt = $this->attackerPromptBuilder->buildSystemPrompt([$projectFile]);

        self::assertStringContainsString('<skills role="normalizer">', $prompt);
        self::assertStringContainsString('allow_extra_attributes', $prompt);
    }

    public function test_it_injects_scheduler_skills_when_schedule_in_chunk(): void
    {
        $projectFile = ProjectFile::create(
            'src/Schedule/CleanupSchedule.php',
            '/app/src/Schedule/CleanupSchedule.php',
            '<?php class CleanupSchedule {}',
        );

        $prompt = $this->attackerPromptBuilder->buildSystemPrompt([$projectFile]);

        self::assertStringContainsString('<skills role="scheduler">', $prompt);
        self::assertStringContainsString('AsSchedule', $prompt);
    }

    public function test_authenticator_skill_appears_before_voter_under_priority_order(): void
    {
        $projectFile = ProjectFile::create(
            'src/Security/PostVoter.php',
            '/app/src/Security/PostVoter.php',
            '<?php class PostVoter {}',
        );
        $authenticator = ProjectFile::create(
            'src/Security/LoginFormAuthenticator.php',
            '/app/src/Security/LoginFormAuthenticator.php',
            '<?php class LoginFormAuthenticator {}',
        );

        $prompt = $this->attackerPromptBuilder->buildSystemPrompt([$projectFile, $authenticator]);

        $authenticatorPos = strpos($prompt, '<skills role="authenticator">');
        $voterPos = strpos($prompt, '<skills role="voter">');

        self::assertNotFalse($authenticatorPos);
        self::assertNotFalse($voterPos);
        self::assertLessThan($voterPos, $authenticatorPos);
    }

    public function test_base_prompt_lists_modern_symfony_vulnerability_types(): void
    {
        $prompt = $this->attackerPromptBuilder->buildSystemPrompt();

        self::assertStringContainsString('missing_signature_verification', $prompt);
        self::assertStringContainsString('messenger_handler_unsafe', $prompt);
        self::assertStringContainsString('missing_rate_limiting', $prompt);
        self::assertStringContainsString('cache_poisoning', $prompt);
        self::assertStringContainsString('mailer_header_injection', $prompt);
        self::assertStringContainsString('webhook_replay', $prompt);
        self::assertStringContainsString('authenticator_bypass', $prompt);
    }

    public function test_base_prompt_references_modern_symfony_components_in_expertise(): void
    {
        $prompt = $this->attackerPromptBuilder->buildSystemPrompt();

        self::assertStringContainsString('Messenger', $prompt);
        self::assertStringContainsString('Webhook', $prompt);
        self::assertStringContainsString('Authenticator', $prompt);
        self::assertStringContainsString('RateLimiter', $prompt);
    }

    public function test_controller_skill_block_covers_map_request_payload(): void
    {
        $projectFile = ProjectFile::create(
            'src/Controller/UserController.php',
            '/app/src/Controller/UserController.php',
            '<?php class UserController {}',
        );

        $prompt = $this->attackerPromptBuilder->buildSystemPrompt([$projectFile]);

        self::assertStringContainsString('#[MapRequestPayload]', $prompt);
    }

    public function test_template_skill_block_covers_live_components(): void
    {
        $projectFile = ProjectFile::create(
            'templates/user/index.html.twig',
            '/app/templates/user/index.html.twig',
            '{{ user.name }}',
        );

        $prompt = $this->attackerPromptBuilder->buildSystemPrompt([$projectFile]);

        self::assertStringContainsString('Live Components', $prompt);
    }

    public function test_php_skill_block_covers_mailer_header_injection(): void
    {
        $projectFile = ProjectFile::create(
            'src/Service/Mailer.php',
            '/app/src/Service/Mailer.php',
            '<?php class Mailer {}',
        );

        $prompt = $this->attackerPromptBuilder->buildSystemPrompt([$projectFile]);

        self::assertStringContainsString('MailerInterface::send()', $prompt);
        self::assertStringContainsString('header injection', $prompt);
    }

    public function test_config_skill_block_covers_messenger_transport_serializer(): void
    {
        $projectFile = ProjectFile::create(
            'config/packages/messenger.yaml',
            '/app/config/packages/messenger.yaml',
            'framework: { messenger: {} }',
        );

        $prompt = $this->attackerPromptBuilder->buildSystemPrompt([$projectFile]);

        self::assertStringContainsString('php_serialize', $prompt);
    }

    public function test_base_prompt_forbids_non_object_array_elements(): void
    {
        $prompt = $this->attackerPromptBuilder->buildSystemPrompt();

        self::assertStringContainsString('Every element of the JSON array MUST be a vulnerability object', $prompt);
        self::assertStringContainsString('NEVER emit a bare string, number, boolean, or null as an array element', $prompt);
        self::assertStringContainsString('return `[]`', $prompt);
    }

    public function test_base_prompt_instructs_model_to_converge_within_tool_call_budget(): void
    {
        $prompt = $this->attackerPromptBuilder->buildSystemPrompt();

        self::assertStringContainsString('tool-call budget', $prompt);
    }
}
