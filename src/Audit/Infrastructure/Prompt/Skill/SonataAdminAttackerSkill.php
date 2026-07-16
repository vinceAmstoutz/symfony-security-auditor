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
final readonly class SonataAdminAttackerSkill implements AttackerSkillInterface
{
    #[Override]
    public function fileType(): ProjectFileType
    {
        return ProjectFileType::SONATA_ADMIN;
    }

    #[Override]
    public function priority(): int
    {
        return 45;
    }

    #[Override]
    public function block(): string
    {
        return <<<'SKILL'
            <skills role="sonata_admin">
            Hunt:
            - `configureFormFields()`/`configureListFields()` exposing a privileged field (`roles`, `password`, `isAdmin`, `isSuperAdmin`) for edit by every role that can reach this admin class — Sonata Admin routes a class-level role by default, so any field surfaced here is editable by everyone with access to the panel, not only a super-admin.
            - No per-object ownership check on an admin whose entity is scoped to a tenant/owner — Sonata's default access check is class-level only. On SonataAdminBundle 4.x, `checkAccess()`/`hasAccess()` are `final` and can no longer be overridden, so the guard must come from a dedicated Security Voter wired via `getAccessMapping()`; on 3.x, an overridden `checkAccess()` is still valid. Flag a tenant-scoped admin with neither before trusting it with multi-tenant data.
            - `configureRoutes()` leaving destructive actions (`delete`, `batch`) enabled for an entity whose workflow never needs them — an action left in inherits the class-level role rather than a narrower one.
            - A custom action (`getAccessMapping()` / a route added via `configureRoutes()->add(...)`) with no matching role declared — Sonata falls back to its default role for anything not explicitly mapped.
            Do NOT flag:
            - Sensitive fields rendered through a read-only mapper option (`'disabled' => true`) rather than an editable widget.
            </skills>
            SKILL;
    }
}
