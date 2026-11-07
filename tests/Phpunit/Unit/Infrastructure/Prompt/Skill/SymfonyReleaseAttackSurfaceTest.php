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
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Prompt\Skill\AttackerSkillInterface;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Prompt\Skill\AuthenticatorAttackerSkill;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Prompt\Skill\ConfigAttackerSkill;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Prompt\Skill\ControllerAttackerSkill;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Prompt\Skill\FormAttackerSkill;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Prompt\Skill\MessengerHandlerAttackerSkill;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Prompt\Skill\PhpAttackerSkill;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Prompt\Skill\TemplateAttackerSkill;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Prompt\Skill\VoterAttackerSkill;

final class SymfonyReleaseAttackSurfaceTest extends TestCase
{
    #[DataProvider('symfonyEightTwoAttackSurfaces')]
    public function test_the_skill_hunts_an_attack_surface_symfony_8_2_introduces(AttackerSkillInterface $attackerSkill, string $hunt): void
    {
        self::assertStringContainsString($hunt, $attackerSkill->block());
    }

    /**
     * @return iterable<string, array{AttackerSkillInterface, non-empty-string}>
     */
    public static function symfonyEightTwoAttackSurfaces(): iterable
    {
        yield 'a recoverable controller attribute whose failure the action ignores' => [new ControllerAttackerSkill(), 'carries on with the protected operation'];
        yield 'a rate limit or lock keyed on a value the client chooses' => [new ControllerAttackerSkill(), 'every new value gets a fresh limiter or lock'];
        yield 'an IsGranted subject read from a mapped request payload' => [new ControllerAttackerSkill(), 'the voter decides on attacker-chosen data'];
        yield 'an entity list or existence check standing in for ownership' => [new ControllerAttackerSkill(), 'existence is not ownership'];
        yield 'an account takeover action a remember-me cookie is enough for' => [new ControllerAttackerSkill(), 'IS_AUTHENTICATED_RECENTLY'];
        yield 'not an account takeover action that asks for the current password again' => [new ControllerAttackerSkill(), 'asks for the current password again in the same request'];
        yield 'an entity serialized whole as the controller result' => [new ControllerAttackerSkill(), 'password hash included, reaches the response'];
        yield 'an access control rule read as requiring every role it lists' => [new ConfigAttackerSkill(), 'any one of them grants access'];
        yield 'user switching any page can trigger' => [new ConfigAttackerSkill(), '`switch_user` enabled without `path` and `enable_csrf: true`'];
        yield 'an access token handler accepting tokens issued for something else' => [new ConfigAttackerSkill(), '`enforce_at_jwt_type: true`'];
        yield 'test mode enabled outside the test environment' => [new ConfigAttackerSkill(), '`framework.test: true` outside `when@test`'];
        yield 'webhooks sent to internal hosts or replayed' => [new ConfigAttackerSkill(), '`webhook.no_private_network` left disabled'];
        yield 'an unsigned transport carrying privileged commands' => [new ConfigAttackerSkill(), 'without `sign: true`'];
        yield 'an LDAP login binding accounts of another provider' => [new ConfigAttackerSkill(), 'without `ldap_users_only: true`'];
        yield 'login errors telling which accounts exist' => [new ConfigAttackerSkill(), '`security.expose_security_errors: all`'];
        yield 'an authentication proof the authenticator never checked' => [new AuthenticatorAttackerSkill(), 'forges the proof step-up checks rely on'];
        yield 'an ID token replayed as an access token' => [new AuthenticatorAttackerSkill(), '`typ` header is `at+jwt`'];
        yield 'an unknown username answered differently from a wrong password' => [new AuthenticatorAttackerSkill(), 'user enumeration by message or timing'];
        yield 'a voter that grants every guest' => [new VoterAttackerSkill(), 'grants every anonymous visitor'];
        yield 'a message from outside marked as verified' => [new MessengerHandlerAttackerSkill(), '`TrustStamp::trusted()`'];
        yield 'not a handler the transport already deduplicates' => [new MessengerHandlerAttackerSkill(), 'the transport `inbox` option'];
        yield 'a page signing URLs the user picks' => [new TemplateAttackerSkill(), 'valid signatures for attacker-chosen URLs'];
        yield 'a whole entity normalized into the page' => [new TemplateAttackerSkill(), '`|normalize` (Symfony ≥ 8.2) on an entity'];
        yield 'a privileged property made a submittable form field' => [new FormAttackerSkill(), '`#[FormField]` on a privileged property'];
        yield 'a workflow transition anyone can fire' => [new PhpAttackerSkill(), 'a user approves or pays their own object'];
        yield 'key management with committed keys or swappable ciphertexts' => [new PhpAttackerSkill(), 'a ciphertext moved to another row still decrypts there'];
    }
}
