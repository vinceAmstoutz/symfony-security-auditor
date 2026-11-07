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
            - An `access_control` rule listing several `roles`, or combining `roles` with `allow_if`, written as if all were required: under the default `affirmative` strategy any one of them grants access (deprecated in Symfony 8.2 for that reason).
            - An `access_control` rule or firewall limited by `methods:` with no rule for the other verbs of that path, while its controller answers them too — a `HEAD`, `PUT` or `PATCH` request (or a `_method` override when `framework.http_method_override` is on) runs it unchecked.
            - {requires symfony>=8.2} On Symfony ≥ 8.2, `switch_user` enabled without `path` and `enable_csrf: true` — impersonation starts from a `?_switch_user=` GET request any page can make an allowed user send (CSRF).
            - {requires symfony>=8.2} `access_token` token handlers: `oidc` without `enforce_at_jwt_type: true` (an ID token is accepted as an access token, RFC 9068); `oauth2` without `audience` and `issuer` (Symfony ≥ 8.2) — a token issued for another client or resource server is accepted.
            - `security.expose_security_errors: all` — login errors tell which accounts exist (user enumeration), and Symfony ≥ 8.2 then skips the password hash it otherwise spends on an unknown username.
            - {requires symfony>=8.2 symfony/ldap} `form_login_ldap` / `json_login_ldap` / `http_basic_ldap` on a firewall whose `chain` provider mixes LDAP with another provider, without `ldap_users_only: true` (Symfony ≥ 8.2) — an account of the other provider is logged in by binding a same-named directory entry.
            - {requires symfony>=8.2} `framework.test: true` outside `when@test` or `config/packages/test/` — on Symfony ≥ 8.2 password hashers then default to the lowest bcrypt/argon2 cost and sessions to the mock file storage.
            - `framework.session.cookie_secure: false` / `cookie_samesite: none` / missing `cookie_httponly` in non-test envs.
            - Dev-only routes (`_profiler`, `_wdt`) not gated by environment or IP allowlist.
            - `cors.allow_origin: '*'` combined with `allow_credentials: true` — credential leak.
            - Exposed services with public `true` that wrap dangerous primitives (filesystem, process, raw SQL).
            - `framework.rate_limiter` absent for login / password-reset / API endpoints declared elsewhere.
            - `framework.messenger.transports.*.serializer` omitted, or set to `messenger.transport.native_php_serializer` — this is Messenger's real default (native PHP `unserialize()` on dequeued payloads), not an opt-in; any class implementing `SerializerInterface` that calls `unserialize` on dequeued payloads is the same risk.
            - {requires symfony>=8.2 symfony/messenger} A Messenger transport other systems can write to (shared Redis, SQS, AMQP) carrying privileged commands without `sign: true` and a `messenger.serializer.signing_secret` (Symfony ≥ 8.2) — whoever can enqueue can forge a command.
            - `framework.webhook` declared without an HMAC secret env var or with the secret committed in plaintext.
            - {requires symfony>=8.2 symfony/webhook} `webhook.no_private_network` left disabled (Symfony ≥ 8.2) while the app sends webhooks to subscriber-supplied URLs — SSRF into internal hosts; `webhook.timestamp_tolerance: 0` turns off the replay window of incoming Standard Webhooks.
            - `framework.lock` not configured for routes that perform balance-affecting operations.
            - `framework.html_sanitizer` sanitizers with `allow_static_elements: true` plus a broad `allow_elements`/`allow_attributes` list — XSS via "sanitized" output.
            - `framework.http_client.scoped_clients.*.verify_peer: false` / `verify_host: false` — MITM exposure.
            - `messenger.routing` directing privileged commands to a transport with `failure_transport: null` — silent loss of audit trail.
            - `security.password_hashers.*.algorithm` set to `plaintext`, `md5`, or `sha1` instead of `auto` (bcrypt/argon2id) — fast, unsalted or reversible hashing.
            - `security.session_fixation_strategy: none`, `remember_me.signature_properties` without `password`, or a stricter firewall (admin) sharing one `context:` with a looser one — a session id planted before login survives it, remember-me cookies survive a password change, and a token from one area opens the other.
            - `remember_me` cookie configured with `secure: false` — a long-lived authentication cookie sent over plain HTTP.
            - NelmioCors `origin_regex: true` paired with an `allow_origin` pattern that is not anchored with `^...$` — an unanchored regex matches as a substring and can allow unintended origins.
            - A Content-Security-Policy directive allowing `'unsafe-inline'` or `'unsafe-eval'` — defeats CSP's main protection against injected/inline script execution.
            - NelmioSecurity `forced_ssl.enabled: false` — HSTS not enforced, leaving the first plaintext request open to SSL-stripping.
            - `APP_DEBUG=1` (or `=true`) in a committed base `.env` file with no environment-specific override visible — if it reaches production, the Symfony error page leaks stack traces, source paths, and environment variables.
            - `MERCURE_JWT_SECRET` still set to the recipe's default placeholder value — anyone can forge a JWT and publish/subscribe to any topic on the hub.
            - A Mercure JWT `publish`/`subscribe` claim scoped to `'*'` — grants access to every topic instead of the specific ones this client needs.
            Do NOT flag:
            - Environment-variable references like `%env(DATABASE_URL)%` — those are externalized, not hardcoded.
            - `_profiler` / `_wdt` declarations gated by `when@dev` / `when@test`.
            - `framework.messenger.transports.*.serializer: messenger.transport.symfony_serializer` — an explicit, safer opt-in (not Messenger's default).
            </skills>
            SKILL;
    }
}
