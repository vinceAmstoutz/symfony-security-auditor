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
final readonly class EntityAttackerSkill implements AttackerSkillInterface
{
    #[Override]
    public function fileType(): ProjectFileType
    {
        return ProjectFileType::ENTITY;
    }

    #[Override]
    public function priority(): int
    {
        return 130;
    }

    #[Override]
    public function block(): string
    {
        return <<<'SKILL'
            <skills role="entity">
            Hunt:
            - Lifecycle callbacks (`#[PrePersist]`, `#[PreUpdate]`) calling unsanitized methods, command execution, or external HTTP.
            - Public setters on sensitive fields (`isAdmin`, `roles`, `passwordHash`) exposed via form normalization.
            - Custom Doctrine types using `convertToPHPValue` with `unserialize` or `eval`-equivalent.
            - DQL/QueryBuilder usage with string concatenation of request input — even inside the entity class.
            - Boolean / enum coercion via Doctrine type juggling that lets attacker promote a role string.
            - Serializer groups: `#[Groups([...])]` (or `@Groups({...})`) that places a privileged field (`roles`, `isAdmin`, `passwordHash`, `apiToken`, `internal*`) into a write-side group (e.g. `user:write`, `*:write`, `admin:*`) — denormalization will set it from request payload. Report as `over_permissive_serializer_group`.
            - Read-side groups (`*:read`, `public`) leaking sensitive fields (`passwordHash`, `tokens`, internal ids) when the entity is serialized in API responses — also `over_permissive_serializer_group`.
            Do NOT flag:
            - Public setters on non-sensitive fields (titles, descriptions) where the form `mapped: false` or constraints validate input.
            - `#[ORM\Column]` with `nullable: true` — nullability is a schema concern, not a security one.
            - Read-only groups on safe fields (display name, public bio) — non-sensitive read groups are by design.
            - Fields annotated `#[Ignore]` / `#[SerializedName]` redirecting to a public alias — those are explicit safe overrides.
            </skills>
            SKILL;
    }
}
