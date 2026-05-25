# Changelog

All notable changes to `vinceamstoutz/symfony-security-auditor` are documented
in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning 2.0.0](https://semver.org). See
[`docs/versioning.md`](docs/versioning.md) for the backward compatibility policy
— what is public API, what is internal, and how deprecations are handled.

## [Unreleased]

### Added

- New `scan.included_paths` configuration key (`string[]`, default
  `['src', 'config', 'templates', 'public/index.php']`) is the **sole scoping
  knob** for the audit. Only the listed project-relative directories and files
  are inspected; everything else — `vendor/`, `node_modules/`, `var/`, `tests/`,
  `migrations/`, `translations/`, `bin/`, root scripts, IDE folders, build
  artefacts, monorepo siblings — is silently skipped. Symfony Finder is invoked
  with the resolved directories as its `in()` roots so it never traverses
  outside the allow-list. If none of the entries resolve in the project root the
  scanner logs `No included paths exist in project` at `warning` level and
  returns an empty result.

### Removed

- **Breaking:** `scan.excluded_dirs` configuration key. The previous deny-list
  mechanism (hard defaults plus user-supplied exclusions) has been replaced by
  `scan.included_paths`. To prune a sub-tree inside an included path (e.g. drop
  `src/Migrations`), tighten `included_paths` to specific sub-directories:

  ```yaml
  symfony_security_auditor:
      scan:
          included_paths: ['src/Controller', 'src/Form', 'src/Voter']
  ```

- **Breaking:** the internal `HARD_EXCLUDED_DIRS` list on `ProjectFileScanner`
  is gone. With Finder scanning only included paths, walking into `vendor/` or
  `node_modules/` no longer happens, so the prune list is unnecessary.

### Fixed

- `scan.max_file_size_kb` now interprets the unit as kibibytes (`1024`-byte
  blocks) for both directory-scanned and explicitly-listed paths. The previous
  implementation routed the directory scan through Symfony Finder's `K` suffix
  (`1000`-byte kilobytes) while the explicit-file path used `*1024`, so files
  between `1000 * N` and `1024 * N` bytes were treated differently depending on
  which leg of the scanner saw them. Both paths now share the `Ki` suffix.
- `LLMResponse::parseJson()` now recovers from conversational prose around a
  balanced JSON block. With `audit.tools_enabled: true` (the default), the
  attacker model sometimes ignores the "Return ONLY the JSON array" prompt
  instruction and wraps its answer in commentary, which previously caused a
  whole chunk's findings to be dropped with `JsonException: Syntax error`.
- `AttackerAgent` / `ReviewerAgent` parse-failure error logs now include a
  512-byte `content_preview` of the LLM response so the actual shape of an
  unrecoverable payload is diagnosable without re-running the audit.

## [1.2.0] — 2026-05-25

### Added

- `audit:run --path=<subdir>` (repeatable, shortcut `-p`) restricts the scan to
  one or several project-relative subdirectories. The project root remains the
  argument (or working directory), so advisory lookups still see
  `composer.lock`. Useful for monorepos where only a single app needs to be
  audited.
- `audit:run --no-cache` bypasses the attacker cache for the run: every chunk
  hits the LLM and no cache entries are written or read. Existing cache stays on
  disk untouched.
- New `Audit\Domain\Port\ProgressReporterInterface` plus two ready-to-use
  implementations (`NullProgressReporter`, `LoggerProgressReporter`). The audit
  pipeline now emits `pipeline.started`, `stage.started`, `stage.completed`, and
  `pipeline.completed` events so hosts can render progress without polling.
  Default is `NullProgressReporter` — silent unless the host wires another
  implementation.
- `CharacterBasedTokenEstimator` now covers Mistral / Codestral, Llama
  (`llama-*`, `llama3*`, `llama4*`, `meta-llama/*`), and DeepSeek model families
  in addition to Claude / GPT (incl. `o3` / `o4`) / Gemini. The constructor
  accepts an optional `$charsPerTokenByPrefix` map so hosts can add or override
  ratios for fine-tuned or self-hosted models without subclassing.
- `AuditCost` carries an optional per-role breakdown (`byRole()`, also surfaced
  under `by_role` in `toArray()`). `EstimateAuditCostUseCase` now computes
  attacker and reviewer cost separately and populates the breakdown, so
  `audit:run --dry-run` reports show `$X for the attacker model` and
  `$Y for the reviewer model` instead of a single bundled total. The console
  template renders the breakdown automatically when present.
- New `Audit\Domain\Port\RateLimiterInterface` plus two ready-to-use
  implementations (`NullRateLimiter`, `TokenBucketRateLimiter`). Wrapped around
  every LLM call, the limiter blocks ahead of time so the audit stays inside the
  provider's per-minute quota instead of relying on reactive 429 retries. Three
  independent dimensions track requests-per-minute, input-tokens-per-minute and
  output-tokens-per-minute; each is independently nullable.
- New
  `audit.rate_limit.{requests_per_minute, input_tokens_per_minute, output_tokens_per_minute}`
  configuration keys (all `int|null`, default `null`). When every dimension is
  `null` (the default) the bundle wires `NullRateLimiter` and behavior matches
  the pre-existing retry-only path; setting any dimension wires
  `TokenBucketRateLimiter` keyed by the configured limits. Recommended starting
  point for Anthropic Tier 1 is `requests_per_minute: 50`,
  `input_tokens_per_minute: 500_000`, `output_tokens_per_minute: 80_000` on
  Opus, scaled down for Haiku/Sonnet.
- `RetryAfterHeaderParser` reads the server-issued `Retry-After` hint from
  `Symfony\AI\Platform\Exception\RateLimitExceededException::getRetryAfter()`
  (or a `retry-after: <int>` substring in the chained messages) and feeds it
  into `RetryPolicy::rateLimitDelayMs()` plus
  `RateLimiterInterface::pauseUntil()`. Chunks scheduled after a 429 share the
  freeze instead of stampeding the provider.
- `RetryPolicy::rateLimitDelayMs()` now accepts an optional
  `?int $serverHintSeconds`. When set and positive, the hint wins over the local
  exponential schedule; the result is clamped to `rateLimitMaxDelayMs` (default
  `300_000`) so a hostile provider cannot push the wait past a sane ceiling.
  `null` hints preserve the existing exponential behavior.
- README now opens with a 30-second quick-start section above the full Getting
  Started guide.

### Changed

- The attacker cache key now folds in the configured attacker model name and a
  prompt-builder version constant (`AttackerPromptBuilder::PROMPT_VERSION`).
  Switching models or bumping the prompt automatically invalidates
  previously-cached LLM responses; identical configuration across instances
  still hits the cache as before.
- `composer audit` results are now persisted to disk across runs, keyed by a
  SHA-256 of the project's `composer.lock`. Re-running the audit (CI, repeated
  `--dry-run`) reuses the cached advisory data instead of spawning composer
  again. Projects without a lockfile transparently fall back to running the
  underlying audit on every call; cache I/O failures are logged and swallowed.
- `SymfonyAiLLMClient::invokeWithRetry()` now eagerly resolves the
  `Symfony\AI\Platform\Result\DeferredResult` returned by `platform->invoke()`
  before exiting the retry block. Previously the wrapped HTTP body was read
  lazily by `asText()` / `getResult()` in `complete()` / `completeWithTools()`,
  so transient failures emitted by `symfony/http-client`'s deferred body read
  escaped the retry classifier — most visibly, `HTTP 429` responses bypassed the
  rate-limit-specific backoff. Eager resolution surfaces those failures inside
  the retry loop so backoff, retry-after hints, and budget enforcement all
  behave as documented.

### Fixed

- `audit:run` no longer crashes on the first chunk that draws a `429`. The
  combination of eager `DeferredResult` resolution plus the new rate-limit
  pipeline (`RateLimiterInterface`, server-hint backoff) means rate-limited
  responses now flow through retry + pause instead of escaping as a raw
  `\Throwable` to the agent layer.

### Tooling

- Dev dependency `phpunit/phpunit` bumped from `^11.5` to `^12.5`. PHPUnit 12
  drops the abandoned `sebastian/code-unit` and
  `sebastian/code-unit-reverse-lookup` transitives so `composer audit` no longer
  reports abandoned-package warnings on a fresh install. Supported PHP range is
  unchanged (`>=8.3`); test runner setup is otherwise compatible.
- New runtime dependency `psr/clock` (the abstract `ClockInterface` the bucket
  consumes). New dev dependency `symfony/clock` (provides `MockClock` for the
  time-driven `TokenBucketRateLimiter` tests).
- `castor.php` PHPUnit step drops the legacy `-d --min-coverage=100` PHPUnit CLI
  flag — PHPUnit 12 no longer accepts the unknown option; coverage enforcement
  is delegated to `robiningelbrecht/phpunit-coverage-tools` (already wired in
  `phpunit.dist.xml`). The Infection step now passes `-d memory_limit=1G` to
  clear the 128 MB default on the larger mutant tree.

### Notes

- All changes in this release are additive — existing public APIs (configuration
  keys, `audit:run` arguments / options / exit codes, JSON and SARIF schemas,
  Domain ports) keep their previous signatures. New optional constructor
  parameters on `AuditCost`, `AuditContext::forProject()`,
  `EstimateAuditCostUseCase`, `RunAuditUseCase::execute()`,
  `FilesystemAttackerCache`, and `SymfonyAiLLMClient` all default to their
  previous behavior.
- `ProgressReporterInterface` and `RateLimiterInterface` are Domain ports
  covered by the BC promise (see `docs/versioning.md`). For
  `ProgressReporterInterface`, host implementations should expect new event
  names to be added in `MINOR` releases (additive) but never have their payload
  schemas changed without a `MAJOR`. `TokenBucketRateLimiter` state is
  per-process: multi-process audits sharing one API key (parallel CI matrices)
  still race on the provider window — out-of-process coordination (Redis/file
  lock) can be added by implementing `RateLimiterInterface` and aliasing it in
  `config/services.yaml`.

## [1.1.1] — 2026-05-24

### Fixed

- Mutation gate now kills the `MethodCallRemoval` mutant on the
  `logReviewDecision()` call inside the rejected-finding early-return branch of
  `ReviewerAgent::applyReview()`. Existing tests covered the accepted /
  severity-elevated paths but left the rejection-path debug log unasserted, so
  removing the call escaped Infection — added a targeted unit test that
  exercises a rejected review and asserts the `'Vulnerability reviewed'` debug
  entry is emitted with `accepted => false`. No production code change.

## [1.1.0] — 2026-05-24

### Added

- `Vulnerability::withCorrectedType()` — copy-on-write reclassification when the
  reviewer determines the attacker mislabelled the finding's type. The original
  `id` is preserved so downstream consumers can still correlate the corrected
  record with its pre-correction source.
- Reviewer prompt accepts a `corrected_type` field (nullable string) per
  finding; `ReviewerAgent` parses it, validates against `VulnerabilityType`, and
  applies it via `withCorrectedType()`. Invalid values are logged and ignored —
  original type is preserved.
- New configuration key `symfony_security_auditor.provider_json_mode` (boolean,
  default `false`). When `true`, every LLM call carries
  `response_format: {type: json_object}` to the underlying provider — honored by
  OpenAI / Mistral / Ollama (provider-enforced JSON output), silently ignored by
  Anthropic and any provider without an equivalent knob. The prompt contract
  (_"Return ONLY the JSON array"_) remains authoritative; this is a
  belt-and-braces opt-in for providers that support it.

### Changed

- Prompt builders restructured for accuracy: source files are now wrapped as
  `<file path="…" type="…">…</file>` with each line prefixed by its line number
  in the form `` `NNN | ` ``. The attacker prompt instructs the model to use
  those exact line numbers for `line_start` / `line_end` instead of counting
  manually. Skill blocks switched from `### Heading` to
  `<skills role="…">…</skills>` form and are emitted in attack-surface priority
  order rather than alphabetically.
- Attacker base prompt now includes a severity rubric, a confidence rubric (with
  a hard `< 0.6` filter threshold), a single canonical few-shot example with
  concrete line numbers, and an explicit scope exclusion for `vendor/`,
  `var/cache/`, `var/log/`, `.generated.*`, and `.cache.*` paths.
- Each per-artifact skill block now lists both attack patterns to hunt and
  patterns explicitly NOT to flag — reduces false positives from the attacker
  agent before the reviewer ever sees them.
- Reviewer prompts (single and batch) now share a common core-instructions block
  to prevent drift, include the same severity rubric as the attacker, and embed
  a Symfony-specific false-positive playbook (Doctrine `setParameter()`, default
  CSRF, `mapped: false` form fields, hardcoded-argv `Process` invocations,
  `_profiler` gated by `when@dev`, etc.). Batch mode no longer requires findings
  to be returned in input order — entries are re-keyed by `id` on parse.

---

## [1.0.0] — 2026-05-24

First stable release.

### Added

#### Core audit pipeline

- **Multi-agent security audit pipeline**: Ingestion → Mapping → Audit, driven
  by an adversarial **Attacker** agent and a skeptical **Reviewer** agent (up to
  3 iterations; stops early when no new findings emerge).
- **Provider-agnostic LLM backend** via
  [`symfony/ai`](https://symfony.com/doc/current/ai/index.html): works out of
  the box with Anthropic (Claude), OpenAI, Azure OpenAI, Google Gemini, Google
  Vertex AI, AWS Bedrock, DeepSeek, Mistral, Meta (Llama), and Ollama (local).
  Swapping providers requires only `config/packages/ai.yaml` changes.
- **32 vulnerability types** across 6 OWASP-aligned categories: Injection,
  Broken Access Control, Logic Flaws, Symfony-specific, Data Exposure,
  Cryptographic.
- **Split-model support** — pair a larger model for attack discovery with a
  faster, cheaper model for review (e.g. `attacker_model: claude-opus-4-7` +
  `reviewer_model: claude-haiku-4-5-20251001`).

#### `audit:run` console command

- Three output formats: `console` (human-readable), `json` (machine-readable),
  `sarif` (SARIF 2.1.0 for GitHub Code Scanning and GitLab Security Dashboard).
- `--output` option writes JSON or SARIF to a file path.
- `--dry-run` flag estimates token usage and cost without invoking the LLM.
  Exits `0` with zero findings and a populated `cost` block.
- Exit codes: `0` audit complete (SAFE/LOW/MEDIUM/HIGH), `1` CRITICAL risk or
  invalid project path, `2` token or cost budget exceeded (partial report
  emitted).

#### Token & cost tracking

- Real token usage (input, output, cached tokens) recorded from platform
  response metadata on every LLM call.
- `AuditReport` carries a `cost` block: total tokens and estimated USD cost.
- Character-based token estimator (`CharacterBasedTokenEstimator`) using
  `mb_strlen` for correct multibyte handling on providers without token counts.

#### Budget cap

- Hard token and cost budget enforced via `audit.budget.max_tokens` and
  `audit.budget.max_cost_usd`. Audit aborts cleanly with exit code `2` and emits
  a partial report when either limit is exceeded. Both default to `null`
  (unlimited).

#### Resilience — retry with exponential backoff

- Jittered exponential backoff around every LLM call. Transient errors (HTTP
  429, 5xx, network blips) are retried; non-transient errors (auth, validation)
  fail fast. Configurable: `audit.retry.max_attempts` (3),
  `audit.retry.initial_delay_ms` (500), `audit.retry.backoff_multiplier` (2.0),
  `audit.retry.jitter_ratio` (0.2).

#### Security — credential scrubbing

- Credential-shaped strings (AWS/GitHub/Stripe/Slack/Google API keys, JWTs, PEM
  private keys, env-style assignments) are redacted from file content before
  reaching any LLM provider. Enabled by default
  (`scan.secret_scrubbing.enabled: true`); extensible via
  `scan.secret_scrubbing.additional_patterns`.

#### Attacker tools

- `read_file`, `grep`, `list_files` — cross-file investigation tools.
- `lookup_advisory` — live CVE feed via `composer audit --format=json --locked`.
  Degrades gracefully (empty database + `warning` log) when `composer` or
  `composer.lock` is absent.

#### Caching

- Content-hash filesystem cache for attacker chunks (`cache.enabled: true`);
  skips the LLM call entirely when an identical chunk was analyzed before.
- Provider-side prompt caching via `cache_control: ephemeral`
  (`cache.prompt_caching: true`); honored by Anthropic (~90% input-token
  discount), silently ignored by others.

#### Bundle configuration

- Typed Configuration value objects for all bundle settings (replaces raw array
  access throughout the bundle).
- Full YAML configuration surface under `symfony_security_auditor:`:
  - `model` / `attacker_model` / `reviewer_model`
  - `scan.*`: `excluded_dirs`, `respect_gitignore`, `max_file_size_kb`,
    `secret_scrubbing.*`
  - `audit.*`: `max_iterations`, `min_confidence`, `reviewer_batch_size`,
    `tools_enabled`, `max_tool_iterations`, `budget.*`, `retry.*`
  - `cache.*`: `enabled`, `dir`, `prompt_caching`

#### Architecture

- Strict DDD layering: `Command → Application → Domain ← Infrastructure`.
  `LLMClientInterface` is the sole seam between Application and `symfony/ai`; no
  agent imports any `symfony/ai` type directly.
- Domain ports (`LLMClientInterface`, `AttackerCacheInterface`,
  `ProjectFileScannerInterface`, `*PromptBuilderInterface`, `Tool/*`) live in
  `src/Audit/Domain/Port/`.
- All non-extension-point classes tagged `@internal`.

#### Extension points

`LLMClientInterface`, `AdvisoryDatabaseInterface`,
`AttackerPromptBuilderInterface`, `ReviewerPromptBuilderInterface`,
`ProjectFileScannerInterface`, `AttackerCacheInterface`, `ToolInterface`,
`PipelineInterface`, `StageInterface`. See
[`docs/extending.md`](docs/extending.md).

#### Documentation

- [`docs/architecture.md`](docs/architecture.md) — layer overview, data flow,
  domain model, extension points.
- [`docs/configuration.md`](docs/configuration.md) — full bundle configuration
  reference.
- [`docs/extending.md`](docs/extending.md) — how to plug in custom advisory
  sources, tools, prompt builders, and pipeline stages.
- [`docs/ci.md`](docs/ci.md) — CI pipeline documentation (PHP matrix, Infection,
  PHPStan max).
- [`docs/diagrams.md`](docs/diagrams.md) — architecture and data-flow diagrams.
- [`docs/faq.md`](docs/faq.md) — cost, accuracy, model selection, privacy,
  comparisons.
- [`docs/troubleshooting.md`](docs/troubleshooting.md) — empty reports, LLM
  errors, advisory issues, cache, CI failures.
- [`docs/versioning.md`](docs/versioning.md) — semantic versioning policy and
  public API surface.

### Changed

- `AdvisoryDatabaseInterface` moved from `Audit\Infrastructure\Advisory\` to
  `Audit\Domain\Port\`. The interface is a public extension point, so its
  canonical home is the Domain port namespace alongside `LLMClientInterface`,
  `AttackerCacheInterface`, etc. Host applications aliasing the interface in
  `config/services.yaml` must update the FQCN; concrete implementations
  (`ComposerAuditAdvisoryDatabase`, `InMemoryAdvisoryDatabase`) keep their
  existing FQCNs in `Infrastructure\`.
- Default model updated from `claude-opus-4-5` (retired) to `claude-opus-4-7`.
- Default reviewer model updated from `claude-haiku-4-5` (retired) to
  `claude-haiku-4-5-20251001`.
- **Pricing table corrected**: Anthropic Claude 4 Opus prices were set to the
  Claude 3 Opus rate (`$15.00 / $75.00` per MTok) — corrected to the actual
  Claude 4 Opus rate (`$5.00 / $25.00` per MTok input/output). Haiku and Sonnet
  entries unchanged. Existing cost estimates in CI reports will recalculate at
  the correct rate once updated.
- Pricing table extended with additional current and legacy model entries:
  `claude-opus-4-7`, `claude-sonnet-4-6`, `claude-haiku-4-5-20251001`,
  `claude-opus-4-6`, `claude-opus-4-1`, `claude-opus-4` (deprecated alias),
  `claude-sonnet-4` (deprecated alias), `gpt-4.1`, `o3`, `o4-mini`,
  `gemini-2.0-flash`, `mistral-large`. Legacy `claude-opus-4-5` /
  `claude-haiku-4-5` entries retained for cost reporting on existing
  configurations.

### Fixed

- Budget exceptions now rethrown from `AttackerAgent` so abort propagates to the
  pipeline and triggers exit code `2`.
- SARIF `tool.driver.version` previously hardcoded; now resolved from installed
  Composer metadata at runtime.
- `RegexSecretScrubber` replaced `set_error_handler`/`try-finally` around PCRE
  calls with a leading `@` suppressor — eliminates `UnwrapFinally`/`TrueValue`
  mutation escapes and removes dead early-return path.
- Non-transient LLM failures (missing platform configuration, auth errors,
  retired model names) now abort the audit with exit code `1` and a clear error
  message instead of silently producing a false-negative SAFE result. Introduced
  `Audit\Domain\Exception\LLMProviderException` as the catchable Domain type;
  `AttackerAgent` and `ReviewerAgent` rethrow it rather than swallowing it.

### Compatibility

| Axis                | Requirement      |
| ------------------- | ---------------- |
| PHP                 | `^8.3`           |
| Symfony             | `^7.4 \|\| ^8.0` |
| `symfony/ai-bundle` | `^0.9`           |

CI test matrix: PHP 8.3 / 8.4 / 8.5 × Symfony 7.4 / 8.0 / 8.1.

### Notes

- Default model is `claude-opus-4-7`. Change via `model:`, `attacker_model:`, or
  `reviewer_model:`.
- Register bundle in `dev` and `test` environments only (per
  `config/bundles.php` guidance in the README).

[1.2.0]:
  https://github.com/vinceamstoutz/symfony-security-auditor/releases/tag/v1.2.0
[1.1.1]:
  https://github.com/vinceamstoutz/symfony-security-auditor/releases/tag/v1.1.1
[1.1.0]:
  https://github.com/vinceamstoutz/symfony-security-auditor/releases/tag/v1.1.0
[1.0.0]:
  https://github.com/vinceamstoutz/symfony-security-auditor/releases/tag/v1.0.0
