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

namespace VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Infrastructure\Prompt\Skill;

use ArrayIterator;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFileType;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Prompt\Skill\AdminPanelAttackerSkill;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Prompt\Skill\ApiResourceAttackerSkill;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Prompt\Skill\AttackerSkillInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Prompt\Skill\AttackerSkillRegistry;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Prompt\Skill\AuthenticatorAttackerSkill;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Prompt\Skill\ConfigAttackerSkill;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Prompt\Skill\ControllerAttackerSkill;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Prompt\Skill\ControllerFileUploadAttackerSkill;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Prompt\Skill\ControllerTrustBoundaryAttackerSkill;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Prompt\Skill\EntityAttackerSkill;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Prompt\Skill\EntityFileUploadAttackerSkill;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Prompt\Skill\EventSubscriberAttackerSkill;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Prompt\Skill\FileUploadAttackerSkill;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Prompt\Skill\FormAttackerSkill;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Prompt\Skill\LdapServiceAttackerSkill;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Prompt\Skill\LiveComponentAttackerSkill;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Prompt\Skill\MessengerHandlerAttackerSkill;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Prompt\Skill\NormalizerAttackerSkill;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Prompt\Skill\PhpAttackerSkill;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Prompt\Skill\RepositoryAttackerSkill;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Prompt\Skill\SchedulerAttackerSkill;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Prompt\Skill\TemplateAttackerSkill;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Prompt\Skill\TrustBoundaryAttackerSkill;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Prompt\Skill\TwigExtensionAttackerSkill;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Prompt\Skill\VoterAttackerSkill;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Prompt\Skill\WebhookConsumerAttackerSkill;

final class AttackerSkillRegistryTest extends TestCase
{
    /**
     * @param non-empty-string $expectedRole
     */
    #[DataProvider('everySkill')]
    public function test_each_skill_declares_its_surface_priority_and_block(
        AttackerSkillInterface $attackerSkill,
        ProjectFileType $projectFileType,
        int $expectedPriority,
        string $expectedRole,
    ): void {
        self::assertSame($projectFileType, $attackerSkill->fileType());
        self::assertSame($expectedPriority, $attackerSkill->priority());
        self::assertStringContainsString(\sprintf('<skills role="%s">', $expectedRole), $attackerSkill->block());
    }

    /**
     * @return iterable<string, array{AttackerSkillInterface, ProjectFileType, int, non-empty-string}>
     */
    public static function everySkill(): iterable
    {
        yield 'controller' => [new ControllerAttackerSkill(), ProjectFileType::CONTROLLER, 10, 'controller'];
        yield 'file_upload_controller' => [new ControllerFileUploadAttackerSkill(), ProjectFileType::CONTROLLER, 15, 'file_upload_controller'];
        yield 'controller_trust_boundary' => [new ControllerTrustBoundaryAttackerSkill(), ProjectFileType::CONTROLLER, 17, 'controller_trust_boundary'];
        yield 'api_resource' => [new ApiResourceAttackerSkill(), ProjectFileType::API_RESOURCE, 20, 'api_resource'];
        yield 'live_component' => [new LiveComponentAttackerSkill(), ProjectFileType::LIVE_COMPONENT, 30, 'live_component'];
        yield 'authenticator' => [new AuthenticatorAttackerSkill(), ProjectFileType::AUTHENTICATOR, 40, 'authenticator'];
        yield 'ldap_service' => [new LdapServiceAttackerSkill(), ProjectFileType::LDAP_SERVICE, 42, 'ldap_service'];
        yield 'admin_panel' => [new AdminPanelAttackerSkill(), ProjectFileType::ADMIN_PANEL, 45, 'admin_panel'];
        yield 'voter' => [new VoterAttackerSkill(), ProjectFileType::VOTER, 50, 'voter'];
        yield 'webhook_consumer' => [new WebhookConsumerAttackerSkill(), ProjectFileType::WEBHOOK_CONSUMER, 60, 'webhook_consumer'];
        yield 'messenger_handler' => [new MessengerHandlerAttackerSkill(), ProjectFileType::MESSENGER_HANDLER, 70, 'messenger_handler'];
        yield 'event_subscriber' => [new EventSubscriberAttackerSkill(), ProjectFileType::EVENT_SUBSCRIBER, 80, 'event_subscriber'];
        yield 'normalizer' => [new NormalizerAttackerSkill(), ProjectFileType::NORMALIZER, 90, 'normalizer'];
        yield 'scheduler' => [new SchedulerAttackerSkill(), ProjectFileType::SCHEDULER, 100, 'scheduler'];
        yield 'form' => [new FormAttackerSkill(), ProjectFileType::FORM, 110, 'form'];
        yield 'file_upload' => [new FileUploadAttackerSkill(), ProjectFileType::FORM, 115, 'file_upload'];
        yield 'repository' => [new RepositoryAttackerSkill(), ProjectFileType::REPOSITORY, 120, 'repository'];
        yield 'entity' => [new EntityAttackerSkill(), ProjectFileType::ENTITY, 130, 'entity'];
        yield 'file_upload_entity' => [new EntityFileUploadAttackerSkill(), ProjectFileType::ENTITY, 135, 'file_upload_entity'];
        yield 'template' => [new TemplateAttackerSkill(), ProjectFileType::TEMPLATE, 140, 'template'];
        yield 'twig_extension' => [new TwigExtensionAttackerSkill(), ProjectFileType::TWIG_EXTENSION, 145, 'twig_extension'];
        yield 'config' => [new ConfigAttackerSkill(), ProjectFileType::CONFIG, 150, 'config'];
        yield 'trust_boundary' => [new TrustBoundaryAttackerSkill(), ProjectFileType::CONFIG, 155, 'trust_boundary'];
        yield 'php' => [new PhpAttackerSkill(), ProjectFileType::PHP, 160, 'php'];
    }

    public function test_it_emits_only_the_blocks_for_present_file_types(): void
    {
        $attackerSkillRegistry = new AttackerSkillRegistry();

        $output = $attackerSkillRegistry->render([ProjectFileType::VOTER], emitAll: false);

        self::assertStringContainsString('<skills role="voter">', $output);
        self::assertStringNotContainsString('<skills role="controller">', $output);
        self::assertStringNotContainsString('<skills role="php">', $output);
    }

    public function test_emit_all_ignores_present_types_and_returns_every_block(): void
    {
        $attackerSkillRegistry = new AttackerSkillRegistry();

        $output = $attackerSkillRegistry->render([], emitAll: true);

        self::assertSame(24, substr_count($output, '<skills role="'));
    }

    public function test_it_emits_blocks_in_attack_surface_priority_order(): void
    {
        $attackerSkillRegistry = new AttackerSkillRegistry();

        $output = $attackerSkillRegistry->render([], emitAll: true);

        preg_match_all('/<skills role="([^"]+)">/', $output, $matches);

        self::assertSame([
            'controller',
            'file_upload_controller',
            'controller_trust_boundary',
            'api_resource',
            'live_component',
            'authenticator',
            'ldap_service',
            'admin_panel',
            'voter',
            'webhook_consumer',
            'messenger_handler',
            'event_subscriber',
            'normalizer',
            'scheduler',
            'form',
            'file_upload',
            'repository',
            'entity',
            'file_upload_entity',
            'template',
            'twig_extension',
            'config',
            'trust_boundary',
            'php',
        ], $matches[1]);
    }

    /**
     * @param list<non-empty-string> $roles
     */
    #[DataProvider('everyFileTypeWithASkill')]
    public function test_each_file_type_emits_its_own_skill_blocks(ProjectFileType $projectFileType, array $roles): void
    {
        $attackerSkillRegistry = new AttackerSkillRegistry();

        $output = $attackerSkillRegistry->render([$projectFileType], emitAll: false);

        self::assertSame(\count($roles), substr_count($output, '<skills role="'));
        foreach ($roles as $role) {
            self::assertStringContainsString(\sprintf('<skills role="%s">', $role), $output);
        }
    }

    /**
     * @return iterable<string, array{ProjectFileType, list<non-empty-string>}>
     */
    public static function everyFileTypeWithASkill(): iterable
    {
        yield 'controller' => [ProjectFileType::CONTROLLER, ['controller', 'file_upload_controller', 'controller_trust_boundary']];
        yield 'api_resource' => [ProjectFileType::API_RESOURCE, ['api_resource']];
        yield 'live_component' => [ProjectFileType::LIVE_COMPONENT, ['live_component']];
        yield 'authenticator' => [ProjectFileType::AUTHENTICATOR, ['authenticator']];
        yield 'ldap_service' => [ProjectFileType::LDAP_SERVICE, ['ldap_service']];
        yield 'admin_panel' => [ProjectFileType::ADMIN_PANEL, ['admin_panel']];
        yield 'voter' => [ProjectFileType::VOTER, ['voter']];
        yield 'webhook_consumer' => [ProjectFileType::WEBHOOK_CONSUMER, ['webhook_consumer']];
        yield 'messenger_handler' => [ProjectFileType::MESSENGER_HANDLER, ['messenger_handler']];
        yield 'event_subscriber' => [ProjectFileType::EVENT_SUBSCRIBER, ['event_subscriber']];
        yield 'normalizer' => [ProjectFileType::NORMALIZER, ['normalizer']];
        yield 'scheduler' => [ProjectFileType::SCHEDULER, ['scheduler']];
        yield 'form' => [ProjectFileType::FORM, ['form', 'file_upload']];
        yield 'repository' => [ProjectFileType::REPOSITORY, ['repository']];
        yield 'entity' => [ProjectFileType::ENTITY, ['entity', 'file_upload_entity']];
        yield 'template' => [ProjectFileType::TEMPLATE, ['template']];
        yield 'twig_extension' => [ProjectFileType::TWIG_EXTENSION, ['twig_extension']];
        yield 'config' => [ProjectFileType::CONFIG, ['config', 'trust_boundary']];
        yield 'php' => [ProjectFileType::PHP, ['php']];
    }

    public function test_it_accepts_a_traversable_of_skills(): void
    {
        $attackerSkillRegistry = new AttackerSkillRegistry(new ArrayIterator([
            new VoterAttackerSkill(),
            new ControllerAttackerSkill(),
        ]));

        $output = $attackerSkillRegistry->render([], emitAll: true);

        $controllerPosition = strpos($output, '<skills role="controller">');
        $voterPosition = strpos($output, '<skills role="voter">');
        self::assertNotFalse($controllerPosition);
        self::assertNotFalse($voterPosition);
        self::assertLessThan($voterPosition, $controllerPosition);
    }

    public function test_it_returns_empty_string_when_no_skill_matches(): void
    {
        $attackerSkillRegistry = new AttackerSkillRegistry([new VoterAttackerSkill()]);

        self::assertSame('', $attackerSkillRegistry->render([ProjectFileType::CONTROLLER], emitAll: false));
    }

    public function test_blocks_are_separated_by_a_blank_line(): void
    {
        $attackerSkillRegistry = new AttackerSkillRegistry([
            new ControllerAttackerSkill(),
            new VoterAttackerSkill(),
        ]);

        $output = $attackerSkillRegistry->render([], emitAll: true);

        self::assertStringContainsString("</skills>\n\n<skills role=\"voter\">", $output);
    }

    public function test_entity_file_upload_skill_does_not_wave_off_vich_s_unconfigured_default_namer(): void
    {
        $block = (new EntityFileUploadAttackerSkill())->block();

        self::assertStringNotContainsString('using its default namer', $block);
    }

    public function test_file_upload_skill_does_not_wave_off_vich_s_unconfigured_default_namer(): void
    {
        $block = (new FileUploadAttackerSkill())->block();

        self::assertStringNotContainsString("`VichUploaderBundle`'s default namer —", $block);
    }

    public function test_messenger_handler_skill_references_a_real_amqp_stamp_method(): void
    {
        $block = (new MessengerHandlerAttackerSkill())->block();

        self::assertStringNotContainsString('getApplicationHeaders()', $block);
        self::assertStringContainsString("AmqpStamp::getAttributes()['headers']['x-message-id']", $block);
    }

    public function test_normalizer_skill_references_a_real_ignored_attributes_mechanism(): void
    {
        $block = (new NormalizerAttackerSkill())->block();

        self::assertStringNotContainsString('setIgnoredAttributes()', $block);
        self::assertStringContainsString('AbstractNormalizer::IGNORED_ATTRIBUTES', $block);
    }

    public function test_twig_extension_skill_does_not_claim_is_safe_causes_double_escaping(): void
    {
        $block = (new TwigExtensionAttackerSkill())->block();

        self::assertStringNotContainsString('double-escape', $block);
    }

    public function test_webhook_consumer_skill_does_not_reference_a_fictitious_webhook_component(): void
    {
        $block = (new WebhookConsumerAttackerSkill())->block();

        self::assertStringNotContainsString('WebhookComponent', $block);
    }

    public function test_config_skill_references_the_real_html_sanitizer_option_name(): void
    {
        $block = (new ConfigAttackerSkill())->block();

        self::assertStringNotContainsString('allowAllStaticAttributes()', $block);
        self::assertStringContainsString('allow_static_elements: true', $block);
    }

    /**
     * Symfony Messenger's real default serializer (when `serializer` is
     * omitted, the overwhelmingly common case) is native PHP
     * `serialize()`/`unserialize()` via `messenger.transport.native_php_serializer`
     * — `messenger.transport.symfony_serializer` is an explicit, safer
     * opt-in, never the default. Confirmed against
     * `vendor/symfony/framework-bundle/DependencyInjection/FrameworkExtension.php`'s
     * `default_serializer` config node, whose default value is literally
     * `messenger.transport.native_php_serializer`.
     */
    public function test_config_skill_does_not_claim_the_symfony_serializer_is_messengers_default(): void
    {
        $block = (new ConfigAttackerSkill())->block();

        self::assertStringNotContainsString('the safe default', $block);
        self::assertStringContainsString('native_php_serializer', $block);
    }

    public function test_messenger_handler_skill_does_not_claim_json_serializer_is_the_default(): void
    {
        $block = (new MessengerHandlerAttackerSkill())->block();

        self::assertStringNotContainsString('the default `JsonSerializer`', $block);
        self::assertStringContainsString('native_php_serializer', $block);
    }

    /**
     * `Email::subject()` RFC-2047-encodes an embedded newline into the
     * header body, and `Email::from()`/`addBcc()` either strip control
     * characters or throw `InvalidArgumentException` for them — verified
     * directly against a real `symfony/mime` `Email` instance. Unconditionally
     * flagging these calls as header injection is a broad false positive for
     * one of the most common real-world Mailer patterns (a dynamic subject
     * or reply-to on a transactional email).
     */
    public function test_php_skill_does_not_unconditionally_flag_symfony_mailer_header_fields(): void
    {
        $block = (new PhpAttackerSkill())->block();

        self::assertStringContainsString('RFC 2047', $block);
    }
}
