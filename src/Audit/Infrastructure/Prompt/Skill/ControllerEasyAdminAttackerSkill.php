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
final readonly class ControllerEasyAdminAttackerSkill implements AttackerSkillInterface
{
    #[Override]
    public function fileType(): ProjectFileType
    {
        return ProjectFileType::CONTROLLER;
    }

    #[Override]
    public function priority(): int
    {
        return 18;
    }

    #[Override]
    public function block(): string
    {
        return <<<'SKILL'
            <skills role="controller_easyadmin">
            Hunt (EasyAdmin `AbstractCrudController`):
            - `configureFields()` exposing a privileged property (`roles`, `password`, `isAdmin`, `isSuperAdmin`) with no `->setPermission('ROLE_...')` on the field — EasyAdmin fields are visible/editable by any role that can reach the dashboard unless individually scoped; a bare field surfacing one of these leaks or allows editing it to every admin user, not only a super-admin.
            - `configureActions()` referencing `Action::DELETE` / `Action::BATCH_DELETE` (or a custom destructive action) with no `->setPermission(Action::…, 'ROLE_...')` call — the action inherits only the dashboard's coarse-grained access check, not a per-action role.
            - A `configureFields()` field bound to an association (`AssociationField::new('owner')`/`'tenant'`) that lets one tenant's admin browse or reassign another tenant's records — EasyAdmin has no built-in per-row ownership check; it must be added in the controller (e.g. filtering `createIndexQueryBuilder()`).
            Do NOT flag:
            - Fields already scoped with `->setPermission(...)`, or rendered via a form type that is inherently read-only (`FormField::addFieldset` display-only rows).
            - `configureActions()` calls that only reorder/relabel actions without touching `Action::DELETE`/`Action::BATCH_DELETE`.
            </skills>
            SKILL;
    }
}
