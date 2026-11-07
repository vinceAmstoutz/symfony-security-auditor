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
            - {requires symfony/ai-platform|symfony/ai-agent|openai-php/client} User or stored content placed into `Message::forSystem()`, an `ai.agent.*.prompt`, or fed back from a tool result as instructions, while the agent holds `#[AsTool]` tools, data or credentials the requester lacks — the injected text acts with that authority; prompt injection alone is not a finding.
            - {requires symfony/ai-agent} An `#[AsTool]` tool acting with the app's own identity on a record, path or URL the model picked, without re-checking the end user's permission, or passing its arguments to SQL, file, HTTP or shell sinks unchecked; and model output rendered with `|raw` or used as a redirect, path or query — tool arguments and model output are untrusted input (confused deputy).
            - `HttpClientInterface` calls with user-controlled URL or host — SSRF; check for protocol & host allowlist; `max_redirects` not bounded + redirect host not re-validated.
            - A scoped HTTP client carrying `auth_bearer`, `auth_basic` or auth headers given a URL or path whose start the user controls (`//evil.example/x`) — the credentials go to another host; an SSRF guard built on `#[Assert\Ip]` / `FILTER_FLAG_NO_PRIV_RANGE` instead of `NoPrivateNetworkHttpClient` — IPv6 forms such as `::ffff:10.0.0.1`, 6to4 or NAT64 pass it.
            - A user value placed in the path or query of an outbound request without `rawurlencode()` (`"https://billing.internal/users/{$id}"`) — `../`, `?`, `&` or `#` re-targets the call to another endpoint of a trusted API.
            - `unserialize()` / `igbinary_unserialize()` on untrusted payloads (cache values, queue messages, request body).
            - `Process` / `proc_open` / `shell_exec` constructed with user input concatenation; no `escapeshellarg`.
            - An allow-list regex (`preg_match()`, `#[Assert\Regex]`) ending in `$` without `\z` or the `D` modifier, or with an alternation outside a group (`/^admin|editor$/`) — a trailing `\n` or the unanchored branch passes the check.
            - `new Process([...])` given a user value with no `--` before it and no refusal of a leading `-` — the value becomes an option (`--upload-pack=…`, `-oProxyCommand=…`): argument injection without a shell.
            - A user-supplied path kept inside a folder by `str_starts_with()`, `Path::isBasePath()` or `Path::canonicalize()` on the unresolved string — `..`, a `scheme://` prefix or a sibling folder escapes the confinement (`/uploads-old` passes a `/uploads` check); expect `realpath()` compared with the folder plus its trailing separator.
            - A CSV or spreadsheet export (`fputcsv()`, `CsvEncoder` without `csv_escape_formulas: true`, PhpSpreadsheet) writing user-supplied cells that may start with `=`, `+`, `-`, `@`, tab or carriage return — formula injection when staff open the file.
            - PSR-3 logger sinks receiving raw request payloads without redaction (log injection, log forging).
            - Cryptography: `md5`/`sha1` for security purposes, `random_int` vs `rand`/`mt_rand`, hardcoded IVs/keys.
            - {requires symfony/key-management} KeyManagement (Symfony ≥ 8.2): key material written in the code (an `InMemoryKeyLoader` fed a literal key outside tests), or `EnvelopeEncrypter::encrypt()` / a KMS `encrypt()` of a record with no `$aad` binding it to its owner or row id — a ciphertext moved to another row still decrypts there.
            - Raw header assembly via `Headers::addTextHeader()`/`addMailboxListHeader()`, or a custom `SerializerInterface`/transport bypassing `symfony/mime`, fed with unsanitized user input — header injection.
            - `CacheInterface::get($key, ...)` where `$key` is derived from request input without normalization — cache poisoning / cross-tenant leak.
            - `CacheItemPoolInterface` reads writing user-derived payloads then trusting them on subsequent reads (poisoned cache → privilege bypass).
            - `LockFactory::createLock()` missing on critical sections (refund, balance mutation, idempotent webhook) — race condition.
            - `HtmlSanitizerInterface::sanitize()` configured with `allowElement('script')` / `allowAttribute('on*')` — sanitizer disarmed.
            - `RateLimiterFactory::create($key)` with `$key` constant (`'global'`) instead of per-user/per-IP — limiter trivially exhausted.
            - {requires symfony/workflow} A Workflow transition named by request input and fired with `$workflow->apply()` while no guard (`guard:` expression, `#[AsGuardListener]`) restricts who may fire it — including workflows declared in a class with `#[AsWorkflow]` / `#[Transition]` (Symfony ≥ 8.2): a user approves or pays their own object.
            - PSR-16 / PSR-6 store handing back unserialized objects when the cache backend was filled with user input.
            Do NOT flag:
            - `md5`/`sha1` on non-security data (cache keys, ETags, file fingerprints) — those are integrity, not authentication.
            - `Process` invocations with hardcoded argument arrays (`new Process(['ls', '-la'])`) — no shell interpolation occurs.
            - `HttpClient::request()` against `%env(INTERNAL_SERVICE_URL)%` — that is an externally-configured trusted host, not SSRF.
            - `Email::from($userInput)` / `subject($userInput)` / `addBcc($userInput)` on a patched `symfony/mime` (5.4.52, 6.4.40, 7.4.12, 8.0.12 or later) — `Address` rejects embedded newlines and control characters, and `AbstractHeader` RFC 2047-encodes any header body containing one, before either ever reaches the wire.
            </skills>
            SKILL;
    }
}
