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
            - {requires doctrine/mongodb-odm|mongodb/mongodb} A MongoDB / Doctrine ODM query whose filter, update or pipeline comes from a request array (`find($request->toArray())`, `->equals($request->get('filter'))`) — operators such as `$ne`, `$gt`, `$regex` or `$where` rewrite the query: NoSQL operator injection.
            - {requires api-platform/core|api-platform/doctrine-orm|api-platform/symfony} An API Platform `QueryCollectionExtensionInterface` / `QueryItemExtensionInterface` that scopes rows to the current user for collections but not items (or the reverse), for one resource class but not its siblings, or that returns early on a role broader than intended — other users' rows leak through the operation it skips.
            - A user search term bound into `LIKE` (`'%'.$term.'%'`) without escaping `%` and `_` — a lone `%` or `_` matches every row, enumerating data the search should only reveal on an exact or prefix match (e.g. another user's email).
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
