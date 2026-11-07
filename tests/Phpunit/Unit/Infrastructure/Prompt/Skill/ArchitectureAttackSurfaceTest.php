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
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Prompt\Skill\MessengerHandlerAttackerSkill;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Prompt\Skill\RepositoryAttackerSkill;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Prompt\Skill\UseCaseAttackerSkill;

final class ArchitectureAttackSurfaceTest extends TestCase
{
    #[DataProvider('layeredArchitectureAttackSurfaces')]
    public function test_the_skill_hunts_an_attack_surface_of_a_layered_architecture(AttackerSkillInterface $attackerSkill, string $hunt): void
    {
        self::assertStringContainsString($hunt, $attackerSkill->block());
    }

    /**
     * @return iterable<string, array{AttackerSkillInterface, non-empty-string}>
     */
    public static function layeredArchitectureAttackSurfaces(): iterable
    {
        yield 'the acting user read from the message itself' => [new UseCaseAttackerSkill(), 'the client picks whose record changes'];
        yield 'an authorization check skipped when the worker has no user' => [new UseCaseAttackerSkill(), 'so a `null` user must deny'];
        yield 'any command dispatched by name from the request' => [new UseCaseAttackerSkill(), 'privileged ones included, can be dispatched'];
        yield 'a bus middleware a command can slip past' => [new UseCaseAttackerSkill(), 'or dispatched on another bus, skips it'];
        yield 'a read side query trusting the query fields' => [new UseCaseAttackerSkill(), 'on the read side'];
        yield 'concurrent commands spending the same balance' => [new UseCaseAttackerSkill(), 'concurrent commands double-spend'];
        yield 'not a handler whose only caller already authorizes' => [new UseCaseAttackerSkill(), 'whose caller in the chunk enforces the same rule'];
        yield 'not an actor id the server set from the authenticated user' => [new UseCaseAttackerSkill(), 'set by server code from the authenticated user'];
        yield 'not a query handler serving public data' => [new UseCaseAttackerSkill(), 'Query handlers returning public data'];
        yield 'a bus command handler trusting the actor in its message' => [new MessengerHandlerAttackerSkill(), 'the worker runs it with no token'];
        yield 'an api platform processor saving what the client rewrote' => [new UseCaseAttackerSkill(), '`securityPostDenormalize`'];
        yield 'a query extension scoping rows for some operations only' => [new RepositoryAttackerSkill(), 'leak through the operation it skips'];
        yield 'a blocked account that keeps its session' => [new AuthenticatorAttackerSkill(), 'a blocked or downgraded account keeps working'];
    }
}
