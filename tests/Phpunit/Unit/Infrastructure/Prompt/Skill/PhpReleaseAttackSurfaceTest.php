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
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Prompt\Skill\FileUploadAttackerSkill;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Prompt\Skill\PhpAttackerSkill;

final class PhpReleaseAttackSurfaceTest extends TestCase
{
    #[DataProvider('weaknessesThePhpChangelogNames')]
    public function test_the_skill_hunts_a_weakness_the_php_changelog_names(AttackerSkillInterface $attackerSkill, string $hunt): void
    {
        self::assertStringContainsString($hunt, $attackerSkill->block());
    }

    /**
     * @return iterable<string, array{AttackerSkillInterface, non-empty-string}>
     */
    public static function weaknessesThePhpChangelogNames(): iterable
    {
        yield 'a return in finally discarding a refusal' => [new PhpAttackerSkill(), 'discards the exception that call threw'];
        yield 'a regex error read as no match' => [new PhpAttackerSkill(), 'the input passes as no match'];
        yield 'a stream wrapper in a user-supplied path' => [new PhpAttackerSkill(), '`php://filter` chains'];
        yield 'a host checked by one URL parser and requested by another' => [new PhpAttackerSkill(), 'read differently on each side'];
        yield 'a session default PHP 8.6 secures, turned off in code' => [new PhpAttackerSkill(), 'an attacker-chosen session id is accepted'];
        yield 'an uploaded archive unpacked by its entry names' => [new FileUploadAttackerSkill(), 'an entry named `../../public/shell.php`'];
    }
}
