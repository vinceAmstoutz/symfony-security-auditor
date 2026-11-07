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

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFileType;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectProfile;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Prompt\Skill\AttackerSkillInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Prompt\Skill\AttackerSkillRegistry;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Prompt\Skill\AuthenticatorAttackerSkill;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Prompt\Skill\ConfigAttackerSkill;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Prompt\Skill\ControllerAttackerSkill;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Prompt\Skill\FormAttackerSkill;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Prompt\Skill\MessengerHandlerAttackerSkill;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Prompt\Skill\PhpAttackerSkill;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Prompt\Skill\RepositoryAttackerSkill;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Prompt\Skill\TemplateAttackerSkill;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Prompt\Skill\UseCaseAttackerSkill;
use VinceAmstoutz\SymfonySecurityAuditor\Tests\Unit\Infrastructure\Prompt\Skill\Fixture\FixedBlockAttackerSkill;

final class GatedHuntTest extends TestCase
{
    private const array BARE_SYMFONY_8_1_PROJECT = ['symfony/http-kernel' => 'v8.1.4'];

    public function test_a_gated_hunt_is_kept_without_its_tag_when_the_project_is_not_profiled(): void
    {
        $attackerSkillRegistry = new AttackerSkillRegistry([new FixedBlockAttackerSkill("Hunt:\n- {requires symfony/ai-agent} Tools acting as the app.\n- Always.")]);

        self::assertSame("Hunt:\n- Tools acting as the app.\n- Always.", $attackerSkillRegistry->render([ProjectFileType::PHP], emitAll: false));
    }

    public function test_a_hunt_the_project_does_not_need_is_left_out(): void
    {
        $attackerSkillRegistry = new AttackerSkillRegistry([new FixedBlockAttackerSkill("Hunt:\n- {requires symfony/ai-agent} Tools acting as the app.\n- Always.")]);

        self::assertSame("Hunt:\n- Always.", $attackerSkillRegistry->renderFor([ProjectFileType::PHP], false, ProjectProfile::of(['symfony/http-kernel' => 'v8.2.0'], [])));
    }

    public function test_a_hunt_the_project_needs_is_kept_without_its_tag(): void
    {
        $attackerSkillRegistry = new AttackerSkillRegistry([new FixedBlockAttackerSkill("Hunt:\n- {requires symfony/ai-agent} Tools acting as the app.\n- Always.")]);

        self::assertSame("Hunt:\n- Tools acting as the app.\n- Always.", $attackerSkillRegistry->renderFor([ProjectFileType::PHP], false, ProjectProfile::of(['symfony/ai-agent' => 'v0.15.0'], [])));
    }

    /**
     * @param array<string, string> $neededPackages
     */
    #[DataProvider('huntsGatedByWhatTheProjectInstalls')]
    public function test_a_hunt_is_not_sent_to_a_project_without_what_it_needs(AttackerSkillInterface $attackerSkill, string $hunt, array $neededPackages): void
    {
        self::assertStringNotContainsString($hunt, (new AttackerSkillRegistry([$attackerSkill]))->renderFor([$attackerSkill->fileType()], false, ProjectProfile::of(self::BARE_SYMFONY_8_1_PROJECT, [])));
    }

    /**
     * @param array<string, string> $neededPackages
     */
    #[DataProvider('huntsGatedByWhatTheProjectInstalls')]
    public function test_a_hunt_is_sent_to_a_project_with_what_it_needs(AttackerSkillInterface $attackerSkill, string $hunt, array $neededPackages): void
    {
        self::assertStringContainsString($hunt, (new AttackerSkillRegistry([$attackerSkill]))->renderFor([$attackerSkill->fileType()], false, ProjectProfile::of($neededPackages, [])));
    }

    /**
     * @return iterable<string, array{AttackerSkillInterface, non-empty-string, array<string, string>}>
     */
    public static function huntsGatedByWhatTheProjectInstalls(): iterable
    {
        $symfony82 = ['symfony/http-kernel' => 'v8.2.0'];

        yield 'recoverable controller attributes' => [new ControllerAttackerSkill(), 'carries on with the protected operation', $symfony82];
        yield 'client-picked rate limit and lock keys' => [new ControllerAttackerSkill(), 'every new value gets a fresh limiter or lock', $symfony82];
        yield 'voting on a mapped payload' => [new ControllerAttackerSkill(), 'the voter decides on attacker-chosen data', $symfony82];
        yield 'entity lists and existence checks' => [new ControllerAttackerSkill(), 'existence is not ownership', $symfony82];
        yield 'csrf-less user switching' => [new ConfigAttackerSkill(), '`switch_user` enabled without `path` and `enable_csrf: true`', $symfony82];
        yield 'foreign access tokens' => [new ConfigAttackerSkill(), '`enforce_at_jwt_type: true`', $symfony82];
        yield 'test mode in production' => [new ConfigAttackerSkill(), '`framework.test: true` outside `when@test`', $symfony82];
        yield 'webhooks to private networks' => [new ConfigAttackerSkill(), '`webhook.no_private_network` left disabled', [...$symfony82, 'symfony/webhook' => 'v8.2.0']];
        yield 'unsigned messenger transports' => [new ConfigAttackerSkill(), 'without `sign: true`', [...$symfony82, 'symfony/messenger' => 'v8.2.0']];
        yield 'ldap logins of other providers' => [new ConfigAttackerSkill(), 'without `ldap_users_only: true`', [...$symfony82, 'symfony/ldap' => 'v8.2.0']];
        yield 'forged authentication proofs' => [new AuthenticatorAttackerSkill(), 'forges the proof step-up checks rely on', $symfony82];
        yield 'messages marked as trusted' => [new MessengerHandlerAttackerSkill(), '`TrustStamp::trusted()`', $symfony82];
        yield 'transports that deduplicate' => [new MessengerHandlerAttackerSkill(), 'the transport `inbox` option', $symfony82];
        yield 'signatures handed out by a page' => [new TemplateAttackerSkill(), 'valid signatures for attacker-chosen URLs', $symfony82];
        yield 'whole entities normalized into a page' => [new TemplateAttackerSkill(), '`|normalize` (Symfony ≥ 8.2) on an entity', $symfony82];
        yield 'privileged properties as form fields' => [new FormAttackerSkill(), '`#[FormField]` on a privileged property', $symfony82];
        yield 'workflow transitions without guard' => [new PhpAttackerSkill(), 'a user approves or pays their own object', ['symfony/workflow' => 'v8.1.0']];
        yield 'key management misuse' => [new PhpAttackerSkill(), 'a ciphertext moved to another row still decrypts there', ['symfony/key-management' => 'v8.2.0']];
        yield 'prompt injection backed by authority' => [new PhpAttackerSkill(), 'prompt injection alone is not a finding', ['openai-php/client' => 'v0.10.0']];
        yield 'tools acting as the application' => [new PhpAttackerSkill(), 'tool arguments and model output are untrusted input', ['symfony/ai-agent' => 'v0.15.0']];
        yield 'nosql operator injection' => [new RepositoryAttackerSkill(), 'NoSQL operator injection', ['doctrine/mongodb-odm' => '2.10.0']];
        yield 'query extensions scoping some operations' => [new RepositoryAttackerSkill(), 'leak through the operation it skips', ['api-platform/doctrine-orm' => 'v4.2.0']];
        yield 'state processors saving rewritten owners' => [new UseCaseAttackerSkill(), '`securityPostDenormalize`', ['api-platform/core' => 'v3.4.0']];
    }
}
