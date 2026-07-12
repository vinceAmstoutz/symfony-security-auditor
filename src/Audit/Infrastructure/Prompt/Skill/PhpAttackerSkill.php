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
final readonly class PhpAttackerSkill implements AttackerSkillInterface
{
    #[Override]
    public function fileType(): ProjectFileType
    {
        return ProjectFileType::PHP;
    }

    #[Override]
    public function priority(): int
    {
        return 160;
    }

    #[Override]
    public function block(): string
    {
        return <<<'SKILL'
            <skills role="php">
            Hunt:
            - Symfony ExpressionLanguage / Security Expression evaluating strings derived from user input.
            - `HttpClientInterface` calls with user-controlled URL or host — SSRF; check for protocol & host allowlist; `max_redirects` not bounded + redirect host not re-validated.
            - `unserialize()` / `igbinary_unserialize()` on untrusted payloads (cache values, queue messages, request body).
            - `Process` / `proc_open` / `shell_exec` constructed with user input concatenation; no `escapeshellarg`.
            - PSR-3 logger sinks receiving raw request payloads without redaction (log injection, log forging).
            - Cryptography: `md5`/`sha1` for security purposes, `random_int` vs `rand`/`mt_rand`, hardcoded IVs/keys.
            - Raw header assembly via `Headers::addTextHeader()`/`addMailboxListHeader()`, or a custom `SerializerInterface`/transport bypassing `symfony/mime`, fed with unsanitized user input — header injection.
            - `CacheInterface::get($key, ...)` where `$key` is derived from request input without normalization — cache poisoning / cross-tenant leak.
            - `CacheItemPoolInterface` reads writing user-derived payloads then trusting them on subsequent reads (poisoned cache → privilege bypass).
            - `LockFactory::createLock()` missing on critical sections (refund, balance mutation, idempotent webhook) — race condition.
            - `HtmlSanitizerInterface::sanitize()` configured with `allowElement('script')` / `allowAttribute('on*')` — sanitizer disarmed.
            - `RateLimiterFactory::create($key)` with `$key` constant (`'global'`) instead of per-user/per-IP — limiter trivially exhausted.
            - PSR-16 / PSR-6 store handing back unserialized objects when the cache backend was filled with user input.
            Do NOT flag:
            - `md5`/`sha1` on non-security data (cache keys, ETags, file fingerprints) — those are integrity, not authentication.
            - `Process` invocations with hardcoded argument arrays (`new Process(['ls', '-la'])`) — no shell interpolation occurs.
            - `HttpClient::request()` against `%env(INTERNAL_SERVICE_URL)%` — that is an externally-configured trusted host, not SSRF.
            - `Email::from($userInput)` / `subject($userInput)` / `addBcc($userInput)` — `Address` strips embedded newlines and rejects control characters, and `AbstractHeader` RFC 2047-encodes any header body containing one, before either ever reaches the wire.
            </skills>
            SKILL;
    }
}
