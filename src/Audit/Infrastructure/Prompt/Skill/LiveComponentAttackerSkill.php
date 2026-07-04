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
final readonly class LiveComponentAttackerSkill implements AttackerSkillInterface
{
    #[Override]
    public function fileType(): ProjectFileType
    {
        return ProjectFileType::LIVE_COMPONENT;
    }

    #[Override]
    public function priority(): int
    {
        return 30;
    }

    #[Override]
    public function block(): string
    {
        return <<<'SKILL'
            <skills role="live_component">
            Symfony UX Live Components are HTTP endpoints without routes: every `#[LiveAction]` method is invokable via POST by anyone who can reach the component, and every writable `#[LiveProp]` is bound from the request payload. Neither appears in a controller or the access_control map. Hunt:
            - `#[LiveAction]` methods performing privileged work (delete, promote, pay, toggle flags) without `denyAccessUnlessGranted()` / an `#[IsGranted]` attribute on the method or class. The surrounding page's access control does NOT protect the component endpoint. Report as `broken_access_control`.
            - `#[LiveProp(writable: true)]` on sensitive fields (ids of owned resources, prices, quantities, role-ish flags) — the client can set them to arbitrary values before an action runs. Report as `mass_assignment` or `price_manipulation`.
            - Writable props flowing into queries, file paths, or redirects inside actions — standard injection sinks reached from a non-obvious source.
            - `hydrateWith`/`dehydrateWith` custom hydration performing `unserialize` or object construction from client data. Report as `insecure_deserialization`.
            - `#[LiveListener]` handlers trusting event payloads emitted client-side.
            - Actions mutating entities loaded by client-supplied ids without an ownership check (IDOR through the component).
            Do NOT flag:
            - Read-only props (`#[LiveProp]` without `writable: true`) — the client cannot change them.
            - Actions guarded by `#[IsGranted]` on the class or method, or an explicit `denyAccessUnlessGranted()` first statement.
            - `#[AsTwigComponent]` (non-live) classes — they render server-side only and expose no endpoint.
            </skills>
            SKILL;
    }
}
