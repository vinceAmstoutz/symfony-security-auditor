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
final readonly class ApiResourceAttackerSkill implements AttackerSkillInterface
{
    #[Override]
    public function fileType(): ProjectFileType
    {
        return ProjectFileType::API_RESOURCE;
    }

    #[Override]
    public function priority(): int
    {
        return 20;
    }

    #[Override]
    public function block(): string
    {
        return <<<'SKILL'
            <skills role="api_resource">
            API Platform resources declare their entire HTTP surface in attributes — every operation is a routeless endpoint that never appears in a controller or access_control map. Hunt:
            - Operations without `security:` — any `Get`/`GetCollection`/`Post`/`Patch`/`Put`/`Delete` in `operations: [...]`, as a standalone class attribute (e.g. `#[GetCollection]` without a wrapping `#[ApiResource]`), or as a resource-level default lacking a `security`/`securityPostDenormalize` expression is callable by anyone. Report as `broken_access_control`.
            - Write operations relying only on `security:` — the expression runs BEFORE denormalization, against the object's OLD state. Ownership or role checks on writable data need `securityPostDenormalize:` (with `previous_object` where relevant) or an attacker updates other users' objects. Report as `broken_access_control` or `role_escalation`.
            - Collection `GetCollection` without `security` or a Doctrine extension scoping the query to the current user — every record leaks. Report as `insecure_direct_object_reference`.
            - `#[ApiFilter(SearchFilter::class, properties: [...])]` exposing sensitive or foreign-key properties (`user.id`, `email`, `token`) — filters become data-exfiltration oracles even when item access is denied. Report as `sensitive_data_exposure`.
            - Serialization groups: `normalizationContext`/`denormalizationContext` groups placing privileged fields (`roles`, `isAdmin`, `passwordHash`, internal ids) on the read or write side. Write-side exposure is `over_permissive_serializer_group`.
            - `paginationEnabled: false` (or client-controlled `paginationClientEnabled: true`) on large collections — unbounded result sets. Report as `missing_rate_limiting`.
            - `Patch`/`Put` with `validationContext` groups that skip constraints enforced elsewhere.
            - Custom state processors/providers that skip the voter/ownership checks the equivalent controller would perform.
            Do NOT flag:
            - Operations guarded at the firewall/access_control level when the pattern provably covers the resource route prefix.
            - `security: "is_granted('PUBLIC_ACCESS')"` on intentionally public read-only catalogs.
            - Filters on non-sensitive catalog fields (title, name, public slugs).
            </skills>
            SKILL;
    }
}
