# Changelog

All notable changes to `vinceamstoutz/symfony-security-auditor` are documented
in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning 2.0.0](https://semver.org). See
[`docs/versioning.md`](docs/versioning.md) for the backward compatibility policy
— what is public API, what is internal, and how deprecations are handled.

## [Unreleased]

## [1.6.4] — 2026-05-28 — Hush

A log-hygiene release. `audit:run` no longer emits a `warning` when the
attacker's structured-collection tool loop ends with empty content after at
least one tool-using iteration — that is the intended termination signal in
structured-collection mode, not an error.

### Fixed

- **`Tool-using loop ended with empty content response` no longer fires at
  `warning` level for normal-flow completions.** In structured-collection mode
  (default since 1.6.0), the attacker emits findings via `record_vulnerability`
  tool calls and is contracted to return no final prose — the empty content
  block is how the model says "I'm done."
  `SymfonyAiLLMClient::emptyToolLoopResponseAndLog()`
  (`src/Audit/Infrastructure/LLM/SymfonyAiLLMClient.php`) was logging at
  `warning` level regardless of iteration count, spamming the audit output once
  per chunk on healthy runs (typical signature:
  `iterations: 1, output_tokens: 1485, error: "Response does not contain any content."`).
  The log now routes through `debug` when at least one tool-using iteration has
  produced findings before the empty turn, and only stays at `warning` when the
  very first call returns empty (genuine anomaly — refusal, content filter, or
  provider quirk before any work was done). The message string and payload shape
  are unchanged so existing log scrapers / dashboards continue to match.
- **Cost line removed from the real-run console report.**
  `ReportRenderer::renderConsole()`
  (`src/Audit/Infrastructure/Report/ReportRenderer.php`) used to print
  `Cost    : $X.XXXX` and a per-role breakdown after every audit. The number
  comes from a static `PricingProvider` table multiplied against actual token
  usage, so it's a rough estimate that diverges from real provider invoices
  (volume discounts, contract pricing, prompt-cache rebates) and operators
  shouldn't anchor on it. The tokens line still prints (factual, model-tagged),
  and the dry-run path (`AuditPresenter::dryRunResult()`) is unchanged —
  estimating cost is its whole point. JSON and SARIF outputs still carry
  `estimated_cost_usd` for downstream parsers / dashboards.

## [1.6.3] — 2026-05-28 — Watertight

A bug-fix release closing a credential-leak gap in the secret scrubber. URIs
with embedded credentials — the canonical Symfony `DATABASE_URL` / `REDIS_URL`
shape — were sent verbatim to the LLM provider because no pattern matched them.
The scrubber now redacts connection-string credentials before any content leaves
the machine.

### Fixed

- **Connection-string credentials leaked to the LLM.** `RegexSecretScrubber`
  (`src/Audit/Infrastructure/FileSystem/RegexSecretScrubber.php`) had no pattern
  for URIs with embedded credentials, so values like
  `DATABASE_URL=postgres://user:s3cret@host` or `REDIS_URL=redis://:pass@host`
  were sent verbatim to the LLM provider — the env-assignment pattern only
  matches names ending in `_TOKEN`/`_SECRET`/`_PASSWORD`/`_KEY`/`_DSN`, never
  `_URL`. A new `connection_uri` pattern surgically redacts the `user:pass@`
  segment while preserving the scheme and host
  (`postgres://***REDACTED:connection_uri***@host`).

## [1.6.2] — 2026-05-28 — Headroom

A bug-fix release. The audit was silently truncating every LLM call at ~1000
output tokens because `symfony/ai`'s Anthropic bridge defaults `max_tokens` to
`1000` when callers don't supply one, and the bundle never did. The bundle now
sets `max_tokens` explicitly on every platform request and exposes the value as
a public configuration key.

### Fixed

- **Silent 1000-token output cap.** `SymfonyAiLLMClient::baseOptions()`
  (`src/Audit/Infrastructure/LLM/SymfonyAiLLMClient.php`) never set `max_tokens`
  on platform invocations. `symfony/ai`'s Claude bridge then applied its
  built-in `max_tokens = 1000` default, capping every attacker / reviewer /
  cheap-attacker call. In structured-collection mode this cut off
  `record_vulnerability` tool-call arguments mid-finding (severity, location,
  proof, remediation fields), inflated tool-loop iteration counts, and most
  visibly surfaced as
  `WARNING [app] Tool-using loop ended with empty content response` log lines
  with cumulative `output_tokens` clustering at ~1000 × `iterations`.
  `baseOptions()` now sets `max_tokens` from the new
  `LLMConfiguration::maxOutputTokens` / `attackerMaxOutputTokens` /
  `reviewerMaxOutputTokens` accessors so the value is bounded by bundle
  configuration rather than the upstream default.

### Added

- **`max_output_tokens` configuration key** — top-level `int`, default `4096`.
  Sets `max_tokens` on every LLM call. The new default is enough headroom for
  detailed `record_vulnerability` tool-call arguments on a typical chunk while
  staying well inside provider per-response ceilings. Public API per
  `docs/versioning.md`.
- **`attacker_max_output_tokens` / `reviewer_max_output_tokens`** — optional
  per-role overrides (`int|null`, default `null`). Fall back to
  `max_output_tokens` when null. Mirrors the existing `attacker_model` /
  `reviewer_model` split, so split-model setups can give the attacker more
  headroom for detailed findings (e.g. `8192`) while leaving the reviewer on a
  tighter cap (e.g. `2048`).

### Notes

- This release sets `max_tokens` explicitly on every request where it previously
  omitted the option. Existing audits will see longer (untruncated) completions,
  fewer tool-loop iterations per chunk, and an effectively higher output-token
  spend per call.
- When raising `max_output_tokens` substantially, consider raising
  `audit.rate_limit.output_tokens_per_minute` proportionally — see
  [`docs/configuration.md`](docs/configuration.md). With the default `4096` cap
  and an `80_000` OTPM ceiling the limiter trips after ~19 calls/min; doubling
  the cap halves that.

## [1.6.1] — 2026-05-28 — Soft Landing

A resilience release. The LLM client now treats truly empty model responses as a
graceful drop instead of a fatal abort, and the mutation gate becomes
deterministic on `AuditContext::auditId` so the test matrix stops flapping on
randomness.

### Fixed

- **Empty-content LLM responses no longer abort the audit.** Anthropic (and
  other providers) occasionally return a successful response with zero content
  blocks — refusal-style stops, content-filter hits, or quirks under heavy
  prompt-cache pressure. `symfony/ai`'s converter then throws "Response does not
  contain any content." from `DeferredResult::getResult()`. Previously that
  bubbled through `SymfonyAiLLMClient::invokeWithRetry()` →
  `TransientFailureClassifier` (no transient match) →
  `NonTransientLLMFailureException`, aborting the entire audit mid-run — most
  visibly at ~50% on a long `audit.structured_collection: true` run where the
  attacker had already recorded findings via `record_vulnerability` tool calls.
  `TransientFailureClassifier` now exposes `isEmptyContent()`; the client
  rethrows those as the new internal `EmptyLLMResponseException`, and
  `complete()` / `completeWithTools()` catch and translate into an empty
  `LLMResponse` with `stopReason: 'empty_content'`. The attacker chunk records
  as `analyzed`, the `VulnerabilityCollector` still drains any
  `record_vulnerability` calls that preceded the empty turn, and the pipeline
  continues. The retry classifier is unchanged for transport / auth / rate-limit
  failures — only the framework-level "no content blocks" signature is reclassed
  out of the non-transient path.

### Tooling

- Mutation gate now deterministically kills the `UnwrapStrToUpper` mutant on
  `AuditContext::forProject()`'s `auditId` formatting. The single-draw assertion
  let the mutant escape whenever `bin2hex(random_bytes(4))` rolled all digits
  (~2.33% per Infection run, ~19% across the 9-cell PHP × Symfony matrix) — the
  source of the matrix-cell-specific escapes recently observed on `main`. The
  test now loops 64 draws, dropping the escape probability to ~10⁻¹⁰⁴.

## [1.6.0] — 2026-05-28 — Sentinel

A correctness release. The attacker now records findings through a strict
JSON-Schema tool call validated by the provider, replacing the JSON-array parse
path as the default. Bundle-level switch keeps the legacy path available for
environments without tool-use support.

### Added

- **Schema-enforced finding collection.** New `RecordVulnerabilityTool` exposes
  a `record_vulnerability` tool with a strict JSON-Schema input mirroring the
  `Vulnerability` shape. The attacker now calls this tool once per finding
  instead of returning a JSON array; the provider validates each call against
  the schema before the agent ever sees it, making bare-string drift (`"dev"`,
  `"test"`) and wrapper-object drift (`{"vulnerabilities": [...]}`) structurally
  impossible across Anthropic, OpenAI, Mistral, and tool-capable Ollama models.
- **`audit.structured_collection` config key** — `true` by default. Set to
  `false` to fall back to the tightened JSON-array prompt path, which remains as
  the safety net for models without tool-use support. Public API per
  `docs/versioning.md`.
- **`VulnerabilityCollector` and `RecordVulnerabilityToolFactoryInterface`**
  (Application). The collector is the documented mutable context carrier the
  tool writes into; the factory is the seam Infrastructure plugs into so the
  agent can build a fresh collector + tool pair per chunk without importing
  Infrastructure types. The bundle wires `RecordVulnerabilityToolFactory`
  (Infrastructure) at the composition root.
- **Tightened JSON-array safety net.** When `audit.structured_collection` is set
  to `false`, the prompt explicitly forbids non-object array elements,
  environment-keyed wrapper objects, and bare environment-name strings — the
  failure modes that previously slipped past the parser and were silently
  dropped by `VulnerabilityFactory::fromList()`. Both paths ship in this
  release; the JSON-array path is now opt-in.

### Changed

- **Default attacker collection mechanism is now the `record_vulnerability` tool
  call.** Existing audits that did not pin `audit.structured_collection` will
  switch to the tool-call path on upgrade and benefit from provider-side schema
  validation. Behavior is preserved for opt-out users: set
  `audit.structured_collection: false` in
  `config/packages/symfony_security_auditor.yaml` to keep the JSON array path.

## [1.5.0] — 2026-05-28 — Cartographer

A visibility, hardening, and coverage release. The auditor now reports how much
LLM output it had to drop on the floor, warns operators on stderr when sensitive
content will be sent to the cloud unscrubbed, looks for over-permissive
serializer groups on entities, and parses controller routes and access-control
attributes into a graph fed to the attacker prompt. Every change is backward
compatible — no existing key, default, exit code, JSON/SARIF schema field, or
Domain port signature changed.

### Added

- **Visible hydration drops.** `VulnerabilityFactory::fromList()` now returns a
  `VulnerabilityHydrationResult` value object (vulnerabilities + drop counts
  bucketed by `VulnerabilityDropReason`: `non_array_entry`, `validation_failed`,
  `hydration_failed`). Each drop is logged with a structured `reason` code, and
  per-audit totals appear on the `Attacker agent complete` info log line under
  `total_dropped_entries` / `dropped_by_reason` — so silent loss of an LLM-
  proposed vulnerability is no longer invisible to operators.
- **`symfony/validator` constraints on hydrated findings.** The factory now
  validates raw LLM payloads against `Assert\Collection` constraints (non-blank
  `title` / `description` / `file_path`, sane length bounds on all free-text
  fields) and drops violators under the new `validation_failed` reason, with the
  structured violation messages in the log payload. Catches pathological LLM
  output (empty file paths, 100 KB descriptions) that previously slipped through
  `Vulnerability::create`'s coarser guards.
- **Secret-scrubbing pre-flight warning.** `audit:run` now emits a one-shot
  warning on **stderr** after the header when `scan.secret_scrubbing.enabled` is
  set to `false`, explaining that file contents will be sent verbatim to the
  configured LLM provider. Routing to stderr means the warning always surfaces
  (including when `--format=json|sarif` writes to stdout) without polluting the
  parseable machine-readable payload. The default (`true`) is unchanged.
- **`over_permissive_serializer_group` coverage.** New
  `VulnerabilityType::OVER_PERMISSIVE_SERIALIZER_GROUP` (category
  Symfony-Specific, OWASP A05:2021) plus a `RegexStaticPreScanner` marker for
  the PHP-attribute and annotation forms of `#[Groups(...)]` / `@Groups({...})`
  on entities. The attacker entity skill block now flags privileged fields
  (`roles`, `isAdmin`, `passwordHash`, `apiToken`) landing in write-side groups
  (`*:write`) and sensitive fields leaking via read-side groups (`*:read`,
  `public`).
- **Full route → controller → voter → form semantic graph.** Three new Domain
  ports (`ControllerAccessControlParserInterface`,
  `VoterCapabilityParserInterface`, `FormBindingParserInterface`) with AST-based
  default implementations (backed by `nikic/php-parser`):
  - `PhpParserControllerAccessControlParser` walks every controller and emits
    one `RouteAccessControl` per public action, capturing the
    `#[Route(path:, methods:)]` attribute, both class- and method-level
    `#[IsGranted(...)]`, and `denyAccessUnlessGranted()` call sites.
  - `PhpParserVoterCapabilityParser` walks every voter file and emits a
    `VoterCapability` describing the attribute strings and `instanceof` subject
    types referenced inside its `supports()` body.
  - `PhpParserFormBindingParser` walks every controller and emits one
    `FormBinding` per `$this->createForm(SomeFormType::class)` call site.

  `SymfonyMapping` gains `routeAccessControls()`,
  `controllersWithoutAccessCheck()`, `voterCapabilities()`, `votersFor()`,
  `formBindings()`, and `formBindingsForController()` accessors. `MappingStage`
  populates the graph and surfaces `mapping.routes`,
  `mapping.routes_without_access_check`, `mapping.voter_capabilities`, and
  `mapping.form_bindings` metadata on `AuditContext`. The attacker prompt now
  ships three new context blocks — `Route Access-Control Map`, `Voter Coverage`,
  and `Form Bindings` — so the LLM can cross-reference an
  `#[IsGranted('ATTR', $subject)]` against the voters that actually accept that
  attribute on that subject (a `missing_voter` finding when nothing matches),
  and cross-reference `createForm()` call sites against the form types involved
  (mass-assignment / CSRF surface).

### Changed

- `AttackerPromptBuilder::PROMPT_VERSION` bumped to **5** and
  `RegexStaticPreScanner::CACHE_VERSION` bumped to **2** so cached attacker
  responses invalidate automatically against the new prompt and pattern.
- `VulnerabilityFactory` now takes a
  `Symfony\Component\Validator\Validator\ValidatorInterface` as a constructor
  argument (autowired via a private inline factory in `config/services.php`).
  The factory is `@internal`, so this is a non-BC change for end users;
  downstream custom-agent code that constructs the factory manually must pass a
  `ValidatorInterface` (typically `Validation::createValidator()`).
- `MappingStage` now takes three optional parser arguments
  (`ControllerAccessControlParserInterface`, `VoterCapabilityParserInterface`,
  `FormBindingParserInterface`); each defaults to a no-op parser, preserving the
  previous shape. The DI wiring binds the real parsers in production.
- `nikic/php-parser ^5.3` is now a runtime dependency (previously transitive via
  `phpunit/php-code-coverage`); used by the three AST parsers.

## [1.4.0] — 2026-05-27 — Bloodhound

A detection-and-cost release. The auditor now covers the modern Symfony 7.x/8.x
attack surface, follows data flow across files, and gives operators several
opt-in levers to cut token spend. Every addition is backward compatible — new
configuration keys, new Domain ports, a new `audit:run` option, new
`VulnerabilityType` cases, and additive JSON/SARIF fields. No existing key,
default, exit code, or schema field changed meaning.

### Added

- **Symfony 7.x/8.x attack surface.** Six new file-type detectors
  (Authenticator, Messenger handler, Webhook consumer, EventSubscriber,
  Normalizer, Scheduler) each get a dedicated attacker skill block hunting
  modern failure modes: `SelfValidatingPassport` misuse, missing/`==`-based
  webhook HMAC verification, `php_serialize` Messenger transports,
  mass-assignment via Serializer denormalizers, lock-less recurring tasks, and
  Live Components leaking writable props. Existing
  controller/template/config/php blocks now also cover `#[MapRequestPayload]`,
  Twig Components/Live Components, `html_sanitizer`, mailer header injection,
  cache poisoning, `RateLimiterFactory` scope confusion, and `HttpClient`
  redirect-host bypass. Seven new `VulnerabilityType` cases back this surface:
  `missing_signature_verification`, `messenger_handler_unsafe`,
  `missing_rate_limiting`, `cache_poisoning`, `mailer_header_injection`,
  `webhook_replay`, `authenticator_bypass`.
- **Static pre-scanner** (`StaticPreScannerInterface` →
  `RegexStaticPreScanner`). A deterministic, zero-token pass tags files with ~30
  risk markers (unserialize, shell exec, `|raw`, `csrf_protection: false`,
  hardcoded secrets, Doctrine string concatenation, …) that are injected into
  the attacker prompt so the LLM focuses on concrete locations. New keys
  `audit.static_prescan.enabled` (default `true`) and
  `audit.static_prescan.lean_mode` (default `false`; drops marker-free files to
  slash token spend).
- **Custom risk patterns** (`scan.custom_risk_patterns`). Project-specific regex
  markers merged into the pre-scanner dictionary, keyed by file-type bucket.
- **Feature-based chunking** (`audit.chunking.strategy`, default `feature`).
  Groups a controller with its entity, repository, form, voter, and templates in
  one chunk so the LLM can follow cross-file data flow. `type` restores the
  legacy priority-window chunking.
- **Cross-iteration finding propagation.** Iterations 2+ receive a compact
  summary of already-validated findings so the attacker generalizes patterns to
  uncovered files instead of re-discovering the same bugs.
- **Reviewer tools** (`audit.reviewer_tools_enabled`, default `false`). The
  reviewer can use the same `read_file`/`grep`/`list_files`/`lookup_advisory`
  registry as the attacker to verify cross-file mitigations, with its own
  `audit.reviewer_max_tool_iterations` cap.
- **PoC synthesis stage** (`audit.poc_synthesis.enabled`, default `false`;
  `audit.poc_synthesis.severity_floor`, default `high`). Generates a concrete,
  copy-pasteable reproduction artifact (curl, console invocation, payload) for
  validated findings at or above the floor, exposed as the additive
  `synthesized_poc` report field.
- **Code slicing** (`audit.code_slicing.enabled`, default `false`;
  `audit.code_slicing.min_lines_before_slicing`, default `80`). Trims large PHP
  files to security-relevant lines (structure, signatures, token-bearing lines),
  eliding the rest one-for-one so line numbers stay accurate. New
  `CodeSlicerInterface` port with `RegexCodeSlicer` / `NullCodeSlicer`.
- **Diff mode** (`audit:run --since=<ref>`). Audits only files changed against a
  git ref (committed `ref...HEAD` delta plus uncommitted working-tree changes),
  for fast pull-request scans. New `GitChangedFilesResolverInterface` port with
  a `symfony/process`-based adapter.
- **Cheap→expensive escalation** (`audit.escalation.enabled`, default `false`;
  `audit.escalation.cheap_model`). A cheap-model sweep runs first; the expensive
  model only re-analyses files the sweep flagged, with the cheap findings fed in
  as context.
- **Concurrent reviewer calls** (`audit.reviewer_max_concurrent`, default `1`).
  When reviewing one finding per call with tools off, the new opt-in
  `BatchCapableLLMClientInterface` resolves reviews concurrently (real I/O
  overlap on async transports, safe sequential fallback otherwise), cutting the
  reviewer phase wall-clock.

### Changed

- `AttackerPromptBuilder` prompt bumped to version 4 (modern-Symfony skill
  blocks + expanded type list); the cache-key fold invalidates stale v3
  payloads.
- Default file chunking is now `feature` (was an internal priority-window
  scheme). Set `audit.chunking.strategy: type` to restore the previous
  behaviour.
- The attacker cache key now folds in the pre-scanner version and a hash of
  `scan.custom_risk_patterns`, so changing custom patterns invalidates stale
  entries. Empty LLM responses are now persisted as negative-cache entries.
- **File-type vocabulary is now a `ProjectFileType` enum** (Domain). The
  detector, chunk-priority ordering, pre-scanner pattern buckets, and attacker
  skill-block ordering all reference the enum instead of duplicated magic
  strings. `ProjectFile::type()` still returns the string value (no schema
  change); a new `ProjectFile::fileType()` exposes the typed case.
- **`symfony/string` and `symfony/filesystem` adopted** across the Application,
  Infrastructure, and Command layers (string manipulation and filesystem access)
  per `.claude/rules/php-classes.md`. The Domain layer intentionally stays
  dependency-free native PHP (documented carve-out). Adds `symfony/string` as a
  runtime dependency.
- **`AttackerAgent` slimmed** — `analyze()` takes an immutable
  `AttackerAnalysisRequest` value object (was five positional parameters), and
  risk-marker indexing and prompt-context rendering moved to dedicated
  `RiskMarkerIndex` and `AttackerContextPromptRenderer` collaborators.
  `AttackerAgentInterface` is `@internal`, so this is not a public API change.
- **Internal cleanup** — `FileChunker` feature/priority logic split into smaller
  predicates to cut cyclomatic complexity, and the unused `SEVERITY_FLOOR_*`
  constants on `PoCSynthesizer` (superseded by the `VulnerabilitySeverity` enum)
  were removed.

## [1.3.3] — 2026-05-26 — Mesh

### Changed

- `AttackerPromptBuilder` prompt bumped to version 3: the attacker is now
  explicitly forbidden from emitting bare strings, numbers, booleans, or `null`
  as JSON array elements, and is told to return `[]` rather than
  `["no findings"]` or any prose substitute. Audits against vulnerability-free
  projects previously logged a handful of `warning`-level
  `Skipping non-array vulnerability entry from LLM` records per run because the
  model occasionally interleaved prose entries with the expected vulnerability
  dicts. Bumping the cache-key fold prevents stale v2 payloads — which may
  already contain stray strings — from being replayed and re-triggering the
  warning on a cache hit.
- `VulnerabilityFactory` warning payload now carries an `entry_preview` field —
  the first 120 bytes of the skipped value when it is a string, `null` otherwise
  — so operators can see what the model emitted instead of a vulnerability dict
  without having to enable debug logging.

### Fixed

- `AttackerAgent::analyzeChunk()` now filters non-array entries out of the raw
  LLM payload before handing it to `AttackerCacheInterface::store()` and re-keys
  the survivors as a list. Previously, any stray string, number, or `null` from
  a chatty model was persisted to the filesystem cache as a gapped numeric-keyed
  array, and the same warning re-fired on every subsequent cache hit. Only the
  cache write path is affected; `VulnerabilityFactory::fromList()` still
  receives the full unfiltered payload so the diagnostic warning continues to
  surface model drift.

## [1.3.2] — 2026-05-26 — Sieve

### Fixed

- `VulnerabilityFactory::fromList()` now silently drops non-array entries from
  the decoded LLM payload (with a `warning`-level log carrying the offender's
  `get_debug_type`). The attacker chunk-analysis path previously assumed
  `LLMResponse::parseJson()` always returned a list of dicts; when the
  tool-using loop exhausted its iteration cap or the model emitted a malformed
  payload, scalar entries (string, int, null) interleaved with the expected
  vulnerability dicts surfaced as a `TypeError` from `fromArray()` and aborted
  the entire chunk. The guard now matches the `fromList silently drops nulls`
  contract documented in `.claude/rules/llm-seam.md`. Phpdoc on `fromArray`
  relaxed from `array<string, mixed>` to `array<array-key, mixed>` and on
  `fromList` from `list<array<string, mixed>>` to `list<mixed>` so the static
  type matches the runtime tolerance.
- `RegexSecretScrubber::scrub()` no longer redacts Symfony configuration
  indirections inside otherwise-credentialed assignments. Quoted values matching
  a Symfony parameter reference (`%env(ANTHROPIC_API_KEY)%`,
  `%env(string:DB_PASSWORD)%`, `%kernel.secret%`) or a shell-style env expansion
  (`$NAME`, `${NAME}`) are now passed through unmodified by the
  `inline_assignment` pattern, while literal secrets and the other pattern
  families (AWS, GitHub, Stripe, Slack, Google, JWT, PEM, `env_assignment`) keep
  their existing behavior. Previously, code following the recommended Symfony
  secrets workflow (`api_key: '%env(ANTHROPIC_API_KEY)%'`) was reported to the
  LLM as `api_key: '***REDACTED:inline_assignment***'`, which the attacker then
  escalated to a CRITICAL "hardcoded credential" finding — a false positive on
  the documented best practice. Implementation switched the `inline_assignment`
  arm from `preg_replace` to `preg_replace_callback` so the placeholder check
  can short-circuit per match without affecting the other patterns.
- `AttackerPromptBuilder::basePrompt()` now carries a "Tool Usage Discipline"
  section instructing the model that (1) it has a limited, finite tool-call
  budget per chunk, (2) it must stop using tools and emit the final JSON the
  moment evidence is sufficient, (3) it must emit `[]` immediately when the
  initial scan surfaces no findings rather than continuing to call tools "just
  to be thorough", and (4) any prose, reasoning, or further tool call emitted
  after the answer-decision causes the response to be discarded as malformed.
  Real-world audits were exhausting the `max_tool_iterations` budget (default
  `8`) on Read/Grep/ListFiles/LookupAdvisory calls without ever emitting a final
  answer, leaving downstream consumers with reasoning prose instead of a
  vulnerability list. `PROMPT_VERSION` bumped from `1` to `2` so the attacker
  cache key (which folds in the prompt version) invalidates previously-cached
  responses produced under the old prompt.
- `LLMResponse::parseJson()` JSON-block recovery no longer locks on the first
  `[`/`{` it sees. The new algorithm iterates every opener position outside JSON
  string literals, attempts `scanBalancedBlockFrom` + `json_decode` at each, and
  returns the first block that decodes successfully; the original
  `JsonException` is rethrown only when no candidate block decodes. Recovery is
  skipped entirely when the trimmed content is itself a single balanced block,
  preserving the depth-limit semantics of the top-level decode (which already
  attempted exactly that payload) and preventing silent acceptance of shallower
  inner sub-blocks inside malformed top-level JSON. Models that wrap their final
  answer in prose containing PHP-style array access (e.g.
  `recommendation.contents[locale]`) followed by a trailing `[]` previously had
  the answer dropped — the first `[` was extracted as `[locale]`, failed to
  decode, and the recovery never tried the actual JSON tail.
- `audit:run --dry-run` no longer shows
  `RISK LEVEL: SAFE / No validated vulnerabilities found / Audit complete` —
  output that implied a real audit had run and found nothing. Dry-run is a
  **cost estimate only**: no LLM calls, no vulnerability scan. The new output
  shows the estimated token counts and cost, followed by
  `Dry run — no LLM calls were made. This is a cost estimate only.` /
  `Dry run complete.`. For `--format=json/sarif --output=<file>` the structured
  report is still written to disk so cost data is machine-readable; the human
  summary is shown alongside. For `--format=json/sarif` piped to stdout, only
  the machine-readable output is emitted.

### Added

- `audit:run` now renders a live **console progress bar** while the pipeline
  runs. Each of the three stages (Ingestion → Mapping → Audit) advances the bar
  by one step; the stage name appears as the bar message. The bar is suppressed
  automatically for `--format=json/sarif` piped to stdout and for `--dry-run`.
  Implemented via a new `ConsoleProgressReporter` (Infrastructure) driven by the
  existing
  `pipeline.started / stage.started / stage.completed / pipeline.completed`
  events that `AuditPipeline` already emits, and wired through a new
  `ProgressReporterHolder` mutable delegate so the live `SymfonyStyle` output
  handle can be injected at invocation time without changing
  `PipelineInterface`.

### Refactored

- Removed multi-line `//` comment blocks from `src/` and `tests/` that explained
  what self-evident code does. A new `.claude/rules/no-comments.md` rule
  codifies the policy: comments signal poorly written code; fix the code
  instead.
- Replaced duplicated string literals on four hot paths with `@internal`
  backed-string enums under `Audit\Domain\Model\`: `ProgressEvent`
  (`pipeline.started` / `stage.started` / `stage.completed` /
  `pipeline.completed`) used by `AuditPipeline` and `ConsoleProgressReporter`;
  `AgentRole` (`attacker` / `reviewer`) used by `AttackerAgent`, `ReviewerAgent`
  and `EstimateAuditCostUseCase`'s by-role cost breakdown; `BuiltInStageName`
  (`ingestion` / `mapping` / `audit`) used by the three built-in
  `StageInterface::name()` returns; and `SecretPatternLabel` (`aws_access_key` /
  … / `inline_assignment`) used as the key set of
  `RegexSecretScrubber::DEFAULT_PATTERNS` and its `replacementFor()` match arm.
  Enum values stay equal to the previously hard-coded strings so every
  wire-format contract — `ProgressReporterInterface::report()`,
  `CoverageRecorderInterface::recordCoverage()`, JSON/SARIF `cost.by_role` keys,
  the `***REDACTED:<label>***` placeholder — is byte-identical; the enums are
  not exposed on any public port signature.

### Tooling

- Mutation gate now kills the five escaped mutants on the new progress-bar /
  dry-run path (`ConsoleProgressReporter::onPipelineStarted`,
  `onStageCompleted`, `onPipelineCompleted` and `AuditCommand`'s
  `estimatingSection` call + `isMachineReadableToStdout` negation). Added
  targeted unit tests pinning the `starting…` initial message, the intermediate
  `1/3` advance frame visible between `stage.completed` and the next
  `stage.started`, and the `3/3` snap-to-max forced by `finish()`; the E2E suite
  now wires the shared `ProgressReporterHolder` into both `AuditPipeline` and
  `AuditCommand` so it can assert the bar renders in `--format=console` and
  stays suppressed in `--format=json` to stdout, plus the dry-run path now
  asserts the `Estimating audit cost` section header.

## [1.3.1] — 2026-05-26 — Watertight

### Tooling

- Mutation gate now kills the `UnwrapTrim` and `ArrayOneItem` mutants escaping
  the LLM seam (`LLMResponse::parseJson()` markdown-fence stripping path). Added
  targeted unit tests that pin the trimmed payload around the JSON block and
  that the recovery path returns the decoded array (not the wrapping list) after
  stripping fences. No production code change.

## [1.3.0] — 2026-05-26 — Bonsaï

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

### Changed

- The explicit-file leg of `ProjectFileScanner` now routes through Symfony
  Finder (`->in(dirname)->depth('== 0')->name(basename)->size('<= NKi')`)
  instead of a hand-rolled `filesize() > kb * 1024` check, so both legs of the
  scanner share a single size-comparison implementation.

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
  and its `additionalExcludedDirs` constructor parameter are gone. With Finder
  scanning only included paths, walking into `vendor/` or `node_modules/` no
  longer happens, so the prune list is unnecessary.

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

## [1.2.1] — 2026-05-25 — High Temperature

### Fixed

- `SymfonyAiLLMClient` now omits the `temperature` option from the platform
  invocation unless the host has explicitly configured one. Forwarding the
  default `temperature: 1.0` was rejected by reasoning-only models (notably
  GPT-5) which require the platform's own default, surfacing as a
  `temperature does not support` provider error before any chunk could be
  analyzed. The option is still forwarded verbatim when set, so existing
  configurations keep their previous behavior.

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

[1.6.4]:
  https://github.com/vinceAmstoutz/symfony-security-auditor/releases/tag/1.6.4
[1.6.3]:
  https://github.com/vinceAmstoutz/symfony-security-auditor/releases/tag/1.6.3
[1.6.2]:
  https://github.com/vinceAmstoutz/symfony-security-auditor/releases/tag/1.6.2
[1.6.1]:
  https://github.com/vinceAmstoutz/symfony-security-auditor/releases/tag/1.6.1
[1.6.0]:
  https://github.com/vinceAmstoutz/symfony-security-auditor/releases/tag/1.6.0
[1.5.0]:
  https://github.com/vinceAmstoutz/symfony-security-auditor/releases/tag/1.5.0
[1.4.0]:
  https://github.com/vinceAmstoutz/symfony-security-auditor/releases/tag/1.4.0
[1.3.3]:
  https://github.com/vinceAmstoutz/symfony-security-auditor/releases/tag/1.3.3
[1.3.2]:
  https://github.com/vinceAmstoutz/symfony-security-auditor/releases/tag/1.3.2
[1.3.1]:
  https://github.com/vinceAmstoutz/symfony-security-auditor/releases/tag/1.3.1
[1.3.0]:
  https://github.com/vinceAmstoutz/symfony-security-auditor/releases/tag/1.3.0
[1.2.1]:
  https://github.com/vinceAmstoutz/symfony-security-auditor/releases/tag/1.2.1
[1.2.0]:
  https://github.com/vinceAmstoutz/symfony-security-auditor/releases/tag/1.2.0
[1.1.1]:
  https://github.com/vinceAmstoutz/symfony-security-auditor/releases/tag/1.1.1
[1.1.0]:
  https://github.com/vinceAmstoutz/symfony-security-auditor/releases/tag/1.1.0
[1.0.0]:
  https://github.com/vinceAmstoutz/symfony-security-auditor/releases/tag/1.0.0
