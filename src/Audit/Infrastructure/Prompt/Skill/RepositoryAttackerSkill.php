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

namespace VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Prompt\Skill;

use Override;
use VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Model\ProjectFileType;

/** @internal not part of the BC promise — see docs/versioning.md */
final readonly class RepositoryAttackerSkill implements AttackerSkillInterface
{
    #[Override]
    public function fileType(): ProjectFileType
    {
        return ProjectFileType::REPOSITORY;
    }

    #[Override]
    public function priority(): int
    {
        return 120;
    }

    #[Override]
    public function block(): string
    {
        return <<<'SKILL'
            <skills role="repository">
            Hunt:
            - DQL/SQL injection via string concatenation in custom finder methods; absence of `setParameter()`.
            - Dynamic `ORDER BY` / `LIMIT` fed from request input — Doctrine does NOT parameterize these.
            - `NativeQuery` / `getConnection()->executeQuery()` with interpolated user input.
            - Methods exposing arbitrary criteria (`findBy(['role' => $userInput])`) where caller forgot to constrain values.
            - Subquery building that bypasses voters/filters applied at the controller layer.
            Do NOT flag:
            - QueryBuilder calls that use `setParameter()` for every user-controlled value — Doctrine binds those safely.
            - `findOneBy([...])` / `findAll()` on non-sensitive entities; access control belongs to the voter, not the repository.
            </skills>
            SKILL;
    }
}
