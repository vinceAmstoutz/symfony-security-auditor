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
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Prompt\Skill\PhpAttackerSkill;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Prompt\Skill\RepositoryAttackerSkill;

final class TaintKindAttackSurfaceTest extends TestCase
{
    #[DataProvider('taintKindsNoSkillCoveredYet')]
    public function test_the_skill_hunts_a_flow_static_taint_analysis_names(AttackerSkillInterface $attackerSkill, string $hunt): void
    {
        self::assertStringContainsString($hunt, $attackerSkill->block());
    }

    /**
     * @return iterable<string, array{AttackerSkillInterface, non-empty-string}>
     */
    public static function taintKindsNoSkillCoveredYet(): iterable
    {
        yield 'llm_prompt: injected text acting with authority the user lacks' => [new PhpAttackerSkill(), 'prompt injection alone is not a finding'];
        yield 'llm_prompt: a tool the model aims at any record' => [new PhpAttackerSkill(), 'tool arguments and model output are untrusted input'];
        yield 'url_path and url_component: an outbound path the user re-targets' => [new PhpAttackerSkill(), 're-targets the call to another endpoint'];
        yield 'nosql: a document query shaped by the request' => [new RepositoryAttackerSkill(), 'NoSQL operator injection'];
    }
}
