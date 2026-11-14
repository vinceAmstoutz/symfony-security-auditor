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
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Prompt\Skill\ConfigAttackerSkill;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Prompt\Skill\ControllerAttackerSkill;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Prompt\Skill\EventSubscriberAttackerSkill;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Prompt\Skill\FileUploadAttackerSkill;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Prompt\Skill\PhpAttackerSkill;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Prompt\Skill\RepositoryAttackerSkill;

final class SecurityAdvisoryAttackSurfaceTest extends TestCase
{
    #[DataProvider('appLevelAnaloguesOfSymfonyAdvisories')]
    public function test_the_skill_hunts_the_app_level_analogue_of_a_symfony_advisory(AttackerSkillInterface $attackerSkill, string $hunt): void
    {
        self::assertStringContainsString($hunt, $attackerSkill->block());
    }

    /**
     * @return iterable<string, array{AttackerSkillInterface, non-empty-string}>
     */
    public static function appLevelAnaloguesOfSymfonyAdvisories(): iterable
    {
        yield 'a token set by hand instead of a login' => [new ControllerAttackerSkill(), 'skips the user checker and the session migration'];
        yield 'a sub-request into a controller only access control guards' => [new ControllerAttackerSkill(), 'the firewall checks main requests only'];
        yield 'a payload property typed as a file' => [new ControllerAttackerSkill(), 'point it at any file on the server'];
        yield 'a personal response marked publicly cacheable' => [new ControllerAttackerSkill(), 'a shared cache serves that cookie or page to other visitors'];
        yield 'sessions and remember-me cookies outliving what should end them' => [new ConfigAttackerSkill(), 'remember-me cookies survive a password change'];
        yield 'a check limited to some verbs of a path' => [new ConfigAttackerSkill(), 'no rule for the other verbs of that path'];
        yield 'an allow-list regex a trailing newline or stray branch passes' => [new PhpAttackerSkill(), 'a trailing `\n` or the unanchored branch passes the check'];
        yield 'a user value read as a command option' => [new PhpAttackerSkill(), 'argument injection without a shell'];
        yield 'a path kept in a folder by comparing strings' => [new PhpAttackerSkill(), 'a sibling folder escapes the confinement'];
        yield 'a client credential or SSRF guard a crafted address slips past' => [new PhpAttackerSkill(), 'the credentials go to another host'];
        yield 'a listener authorizing by the URL text' => [new EventSubscriberAttackerSkill(), 'instead of the matched route'];
        yield 'mailer header fields trusted only on a patched mime component' => [new PhpAttackerSkill(), 'on a patched `symfony/mime` (5.4.52, 6.4.40, 7.4.12, 8.0.12 or later)'];
        yield 'a search term whose wildcards are not escaped' => [new RepositoryAttackerSkill(), 'without escaping `%` and `_`'];
        yield 'an SVG upload served from the app origin' => [new FileUploadAttackerSkill(), '`image/svg+xml` accepted'];
        yield 'request input echoed into a raw response' => [new ControllerAttackerSkill(), 'is served as `text/html` and reflects script'];
        yield 'an export cell read as a spreadsheet formula' => [new PhpAttackerSkill(), 'formula injection'];
    }
}
