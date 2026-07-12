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
final readonly class ControllerAttackerSkill implements AttackerSkillInterface
{
    #[Override]
    public function fileType(): ProjectFileType
    {
        return ProjectFileType::CONTROLLER;
    }

    #[Override]
    public function priority(): int
    {
        return 10;
    }

    #[Override]
    public function block(): string
    {
        return <<<'SKILL'
            <skills role="controller">
            Hunt:
            - Missing `denyAccessUnlessGranted()` / `#[IsGranted]` on state-changing or sensitive read actions.
            - `ParamConverter` / `MapEntity` / `#[MapRequestPayload]` / `#[MapQueryString]` flows for IDOR: path id → entity fetch with no ownership check.
            - Mass-assignment: form `->submit($request->request->all())` without `allow_extra_fields: false` or restricted setters.
            - `#[MapRequestPayload]` / `#[MapQueryString]` DTO mapping over an entity-shaped class with public mutable properties (mass-assignment via Serializer).
            - Redirect targets and `RedirectResponse` arguments against open-redirect via user-controlled URLs.
            - File-upload handlers: missing MIME validation, predictable upload paths, no content-type enforcement.
            - Authentication endpoints (login, password reset, 2FA, registration) without rate-limiter binding (`RateLimiterFactory::create()` / `framework.rate_limiter`).
            - `Request::get()` / `getContent()` flowing into Doctrine raw queries, `exec`, `passthru`, `eval`, `unserialize`, `simplexml_load_string`.
            - Live Components: `#[LiveAction]` / `#[LiveProp(writable: true)]` exposing privileged setters or unbounded properties to the browser.
            Do NOT flag:
            - Controllers inheriting `denyAccessUnlessGranted()` from a parent class or a `#[IsGranted]` attribute on the class itself.
            - Routes restricted by `methods: ['POST']` plus a CSRF-protected form — the form covers the CSRF concern.
            - `#[MapRequestPayload]` / `#[MapQueryString]` over a DTO with validation constraints (`#[Assert\…]`) AND no privileged setters.
            </skills>
            SKILL;
    }
}
