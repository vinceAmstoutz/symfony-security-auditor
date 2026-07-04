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
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Prompt\Skill\ApiResourceAttackerSkill;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Prompt\Skill\AttackerSkillInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Prompt\Skill\AttackerSkillRegistry;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Prompt\Skill\AuthenticatorAttackerSkill;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Prompt\Skill\ConfigAttackerSkill;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Prompt\Skill\ControllerAttackerSkill;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Prompt\Skill\EntityAttackerSkill;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Prompt\Skill\EventSubscriberAttackerSkill;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Prompt\Skill\FormAttackerSkill;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Prompt\Skill\LiveComponentAttackerSkill;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Prompt\Skill\MessengerHandlerAttackerSkill;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Prompt\Skill\NormalizerAttackerSkill;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Prompt\Skill\PhpAttackerSkill;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Prompt\Skill\RepositoryAttackerSkill;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Prompt\Skill\SchedulerAttackerSkill;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Prompt\Skill\TemplateAttackerSkill;
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
        ProjectFileType $expectedFileType,
        int $expectedPriority,
        string $expectedRole,
    ): void {
        self::assertSame($expectedFileType, $attackerSkill->fileType());
        self::assertSame($expectedPriority, $attackerSkill->priority());
        self::assertStringContainsString(\sprintf('<skills role="%s">', $expectedRole), $attackerSkill->block());
    }

    /**
     * @return iterable<string, array{AttackerSkillInterface, ProjectFileType, int, non-empty-string}>
     */
    public static function everySkill(): iterable
    {
        yield 'controller' => [new ControllerAttackerSkill(), ProjectFileType::CONTROLLER, 10, 'controller'];
        yield 'api_resource' => [new ApiResourceAttackerSkill(), ProjectFileType::API_RESOURCE, 20, 'api_resource'];
        yield 'live_component' => [new LiveComponentAttackerSkill(), ProjectFileType::LIVE_COMPONENT, 30, 'live_component'];
        yield 'authenticator' => [new AuthenticatorAttackerSkill(), ProjectFileType::AUTHENTICATOR, 40, 'authenticator'];
        yield 'voter' => [new VoterAttackerSkill(), ProjectFileType::VOTER, 50, 'voter'];
        yield 'webhook_consumer' => [new WebhookConsumerAttackerSkill(), ProjectFileType::WEBHOOK_CONSUMER, 60, 'webhook_consumer'];
        yield 'messenger_handler' => [new MessengerHandlerAttackerSkill(), ProjectFileType::MESSENGER_HANDLER, 70, 'messenger_handler'];
        yield 'event_subscriber' => [new EventSubscriberAttackerSkill(), ProjectFileType::EVENT_SUBSCRIBER, 80, 'event_subscriber'];
        yield 'normalizer' => [new NormalizerAttackerSkill(), ProjectFileType::NORMALIZER, 90, 'normalizer'];
        yield 'scheduler' => [new SchedulerAttackerSkill(), ProjectFileType::SCHEDULER, 100, 'scheduler'];
        yield 'form' => [new FormAttackerSkill(), ProjectFileType::FORM, 110, 'form'];
        yield 'repository' => [new RepositoryAttackerSkill(), ProjectFileType::REPOSITORY, 120, 'repository'];
        yield 'entity' => [new EntityAttackerSkill(), ProjectFileType::ENTITY, 130, 'entity'];
        yield 'template' => [new TemplateAttackerSkill(), ProjectFileType::TEMPLATE, 140, 'template'];
        yield 'config' => [new ConfigAttackerSkill(), ProjectFileType::CONFIG, 150, 'config'];
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

        self::assertSame(16, substr_count($output, '<skills role="'));
    }

    public function test_it_emits_blocks_in_attack_surface_priority_order(): void
    {
        $attackerSkillRegistry = new AttackerSkillRegistry();

        $output = $attackerSkillRegistry->render([], emitAll: true);

        preg_match_all('/<skills role="([^"]+)">/', $output, $matches);

        self::assertSame([
            'controller',
            'api_resource',
            'live_component',
            'authenticator',
            'voter',
            'webhook_consumer',
            'messenger_handler',
            'event_subscriber',
            'normalizer',
            'scheduler',
            'form',
            'repository',
            'entity',
            'template',
            'config',
            'php',
        ], $matches[1]);
    }

    /**
     * @param non-empty-string $role
     */
    #[DataProvider('everyFileTypeWithASkill')]
    public function test_each_file_type_emits_its_own_skill_block(ProjectFileType $projectFileType, string $role): void
    {
        $attackerSkillRegistry = new AttackerSkillRegistry();

        $output = $attackerSkillRegistry->render([$projectFileType], emitAll: false);

        self::assertSame(1, substr_count($output, '<skills role="'));
        self::assertStringContainsString(\sprintf('<skills role="%s">', $role), $output);
    }

    /**
     * @return iterable<string, array{ProjectFileType, non-empty-string}>
     */
    public static function everyFileTypeWithASkill(): iterable
    {
        yield 'controller' => [ProjectFileType::CONTROLLER, 'controller'];
        yield 'api_resource' => [ProjectFileType::API_RESOURCE, 'api_resource'];
        yield 'live_component' => [ProjectFileType::LIVE_COMPONENT, 'live_component'];
        yield 'authenticator' => [ProjectFileType::AUTHENTICATOR, 'authenticator'];
        yield 'voter' => [ProjectFileType::VOTER, 'voter'];
        yield 'webhook_consumer' => [ProjectFileType::WEBHOOK_CONSUMER, 'webhook_consumer'];
        yield 'messenger_handler' => [ProjectFileType::MESSENGER_HANDLER, 'messenger_handler'];
        yield 'event_subscriber' => [ProjectFileType::EVENT_SUBSCRIBER, 'event_subscriber'];
        yield 'normalizer' => [ProjectFileType::NORMALIZER, 'normalizer'];
        yield 'scheduler' => [ProjectFileType::SCHEDULER, 'scheduler'];
        yield 'form' => [ProjectFileType::FORM, 'form'];
        yield 'repository' => [ProjectFileType::REPOSITORY, 'repository'];
        yield 'entity' => [ProjectFileType::ENTITY, 'entity'];
        yield 'template' => [ProjectFileType::TEMPLATE, 'template'];
        yield 'config' => [ProjectFileType::CONFIG, 'config'];
        yield 'php' => [ProjectFileType::PHP, 'php'];
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
}
