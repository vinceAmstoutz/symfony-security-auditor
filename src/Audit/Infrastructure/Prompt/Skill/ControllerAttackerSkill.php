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
            - Symfony ≥ 8.2 recoverable attributes (`#[IsCsrfTokenValid]`, `#[IsSignatureValid]`, `#[RateLimit]`, `#[Lock]`): an action taking their exception as a parameter (`InvalidCsrfTokenException`, `SignedUriException`, `RateLimitExceededException`, `LockConflictedException`) that carries on with the protected operation when it is set — the check no longer stops the request.
            - `#[RateLimit]` / `#[Lock]` whose `key` reads a `{name}` placeholder the client picks (a route or query value it can vary) instead of the user or account, or a `#[RateLimit(if: …)]` expression the client can make false — every new value gets a fresh limiter or lock.
            - `#[IsGranted(…, subject: …)]` whose subject reads a `#[MapRequestPayload]` / `#[MapQueryString]` / `#[MapUploadedFile]` argument (mapped before voting since Symfony 8.2) and trusts an owner or tenant id the client sent instead of loading the stored record — the voter decides on attacker-chosen data.
            - `#[MapEntity]` loading an `array` argument through `findBy()` criteria or a closure (Symfony ≥ 8.2) with no ownership filter — IDOR over many rows at once; and a payload id checked only by an `#[EntityExists]` constraint — existence is not ownership.
            - Account-takeover actions (change email or password, disable 2FA, create an API token, delete the account) granted on `IS_AUTHENTICATED_REMEMBERED` or a bare role — a stolen remember-me cookie is enough; expect `IS_AUTHENTICATED_FULLY`, or `IS_AUTHENTICATED_RECENTLY` on Symfony ≥ 8.2.
            - An action returning an entity through `#[Serialize]` with no `groups` in its `context` and no `map` DTO (Symfony ≥ 8.2) — every readable property, password hash included, reaches the response.
            - `JsonResponse`/serialized payloads returned from a `GET`-only action with a bare top-level indexed array (`[{...}, {...}]` instead of `{"data": [...]}`) — XSSI "JSON Hijacking": a cross-origin `<script src>` include can read the array literal before same-origin policy applies. Report as `json_hijacking`.
            Do NOT flag:
            - Account-takeover actions whose form asks for the current password again in the same request.
            - Controllers inheriting `denyAccessUnlessGranted()` from a parent class or a `#[IsGranted]` attribute on the class itself.
            - Routes restricted by `methods: ['POST']` plus a CSRF-protected form — the form covers the CSRF concern.
            - `#[MapRequestPayload]` / `#[MapQueryString]` over a DTO with validation constraints (`#[Assert\…]`) AND no privileged setters.
            - A bare indexed-array JSON response from an action whose route `methods:` excludes `GET` (e.g. `POST`/`PUT`/`PATCH`/`DELETE` only) — `<script src>` inclusion only issues GET requests, so a non-GET route cannot be hijacked this way.
            </skills>
            SKILL;
    }
}
