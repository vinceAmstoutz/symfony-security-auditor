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
final readonly class ConfigAttackerSkill implements AttackerSkillInterface
{
    #[Override]
    public function fileType(): ProjectFileType
    {
        return ProjectFileType::CONFIG;
    }

    #[Override]
    public function priority(): int
    {
        return 150;
    }

    #[Override]
    public function block(): string
    {
        return <<<'SKILL'
            <skills role="config">
            Hunt:
            - Hardcoded secrets, API keys, DSNs (look for `_KEY`, `_SECRET`, `_TOKEN`, `password:`, full DSN strings).
            - `security.firewalls` with `security: false` on protected paths, or `access_control` rules with overly broad path patterns.
            - `framework.session.cookie_secure: false` / `cookie_samesite: none` / missing `cookie_httponly` in non-test envs.
            - Dev-only routes (`_profiler`, `_wdt`) not gated by environment or IP allowlist.
            - `cors.allow_origin: '*'` combined with `allow_credentials: true` — credential leak.
            - Exposed services with public `true` that wrap dangerous primitives (filesystem, process, raw SQL).
            - `framework.rate_limiter` absent for login / password-reset / API endpoints declared elsewhere.
            - `framework.messenger.transports.*.serializer` omitted, or set to `messenger.transport.native_php_serializer` — this is Messenger's real default (native PHP `unserialize()` on dequeued payloads), not an opt-in; any class implementing `SerializerInterface` that calls `unserialize` on dequeued payloads is the same risk.
            - `framework.webhook` declared without an HMAC secret env var or with the secret committed in plaintext.
            - `framework.lock` not configured for routes that perform balance-affecting operations.
            - `framework.html_sanitizer` sanitizers with `allow_static_elements: true` plus a broad `allow_elements`/`allow_attributes` list — XSS via "sanitized" output.
            - `framework.http_client.scoped_clients.*.verify_peer: false` / `verify_host: false` — MITM exposure.
            - `messenger.routing` directing privileged commands to a transport with `failure_transport: null` — silent loss of audit trail.
            - `security.password_hashers.*.algorithm` set to `plaintext`, `md5`, or `sha1` instead of `auto` (bcrypt/argon2id) — fast, unsalted or reversible hashing.
            - `remember_me` cookie configured with `secure: false` — a long-lived authentication cookie sent over plain HTTP.
            - NelmioCors `origin_regex: true` paired with an `allow_origin` pattern that is not anchored with `^...$` — an unanchored regex matches as a substring and can allow unintended origins.
            Do NOT flag:
            - Environment-variable references like `%env(DATABASE_URL)%` — those are externalized, not hardcoded.
            - `_profiler` / `_wdt` declarations gated by `when@dev` / `when@test`.
            - `framework.messenger.transports.*.serializer: messenger.transport.symfony_serializer` — an explicit, safer opt-in (not Messenger's default).
            </skills>
            SKILL;
    }
}
