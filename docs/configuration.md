# Configuration Reference

Full configuration reference for the `symfony-security-auditor` bundle. Covers bundle registration, bundle-level configuration, platform wiring via `symfony/ai`, model options, and the CLI command.

## Table of Contents

- [Bundle Registration](#bundle-registration)
- [Manual Setup (without Flex)](#manual-setup-without-flex)
- [Bundle Configuration](#bundle-configuration)
  - [Top-level](#top-level)
  - [`scan.*` — file discovery](#scan--file-discovery)
  - [`audit.*` — orchestrator knobs](#audit--orchestrator-knobs)
  - [`cache.*` — caching layers](#cache--caching-layers)
- [`privacy.*` — data egress](#privacy--data-egress)
  - [Simple mode](#simple-mode--one-model-for-both-roles)
  - [Split mode](#split-mode--separate-models-per-role)
  - [Full example](#full-configuration-example)
- [Advisory Source (`lookup_advisory`)](#advisory-source-lookup_advisory-tool)
- [Platform Configuration](#platform-configuration)
- [Model Options](#model-options)
- [Split-Model Setup](#split-model-setup)
- [Standalone Configuration](#standalone-configuration)
- [Providing the API key](#providing-the-api-key)
- [CLI Reference](#cli-reference)
  - [Output Formats Reference](#output-formats-reference)
  - [`audit:diff`](#auditdiff--comparing-two-reports)
  - [`audit:trend`](#audittrend--tracking-findings-across-reports)
  - [`audit:baseline`](#auditbaseline--maintaining-the-accepted-finding-baseline)
  - [`mcp:serve`](#mcpserve--model-context-protocol-server)
  - [`init`](#init--generating-the-standalone-configuration)
  - [`self-update`](#self-update--updating-the-standalone-binary)
  - [`doctor`](#doctor--preflight-environment-check)
  - [Update notifications](#update-notifications)

> See also: [Architecture](architecture.md) · [Extending](extending.md) · [CI](ci.md) · [FAQ](faq.md) · [Troubleshooting](troubleshooting.md)

## Bundle Registration

Register both bundles in `config/bundles.php`. Symfony Flex does this automatically via the recipe. `AiBundle` must be installed and registered alongside this bundle — it provides the `PlatformInterface` service this bundle references — but array order does not matter: the reference is a lazy `nullOnInvalid()` service resolved by the container compiler after every bundle's `loadExtension()` has already run.

```php
// config/bundles.php
return [
    // ...
    Symfony\AI\AiBundle\AiBundle::class => ['all' => true],
    VinceAmstoutz\SymfonySecurityAuditor\SymfonySecurityAuditorBundle::class => ['dev' => true, 'test' => true],
];
```

## Manual Setup (without Flex)

Without Symfony Flex (or with `composer require --no-scripts`), do by hand what the recipe automates:

1. Register both bundles in `config/bundles.php` — see [Bundle Registration](#bundle-registration).
2. Create `config/packages/symfony_security_auditor.yaml` — see [Bundle Configuration](#bundle-configuration) — or copy the [recipe's template](https://github.com/symfony/recipes-contrib/blob/main/vinceamstoutz/symfony-security-auditor/1.0/config/packages/symfony_security_auditor.yaml).

## Bundle Configuration

Create `config/packages/symfony_security_auditor.yaml`. The bundle exposes the following keys:

> **Editor autocompletion.** A JSON Schema for this configuration ships at [`resources/schema.json`](../resources/schema.json). Editors pick it up from a `# $schema:` modeline on the first line of your config file — both the [YAML Language Server](https://github.com/redhat-developer/yaml-language-server) (VS Code, Neovim, …) and PhpStorm/IntelliJ understand this form:
>
> ```yaml
> # $schema: https://raw.githubusercontent.com/vinceamstoutz/symfony-security-auditor/main/resources/schema.json
>
> symfony_security_auditor:
>     model: "claude-opus-5"
> ```
>
> This gives key completion, type checking, and inline docs as you edit. The example files under [`examples/configs/`](../examples/configs/) include the modeline. The URL tracks the `main` branch so it always resolves to the current schema — no per-release bump needed.

### Top-level

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `profile` | string | `'balanced'` | One-knob preset bundling the cost/speed/depth levers: `fast`, `balanced`, or `thorough`. A profile only fills the keys you left unset — any explicitly configured key always wins. `fast`: one attacker iteration, lean pre-scan, code slicing on, four concurrent attacker and reviewer calls. `balanced`: identical to configuring nothing. `thorough`: balanced plus PoC synthesis. |
| `model` | string | `'claude-opus-4-8'` | Model name used for both Attacker and Reviewer roles |
| `attacker_model` | string | `null` | Override: dedicated model for the Attacker role |
| `reviewer_model` | string | `null` | Override: dedicated model for the Reviewer role |
| `max_output_tokens` | `int` (≥ 1) | `4096` | Maximum output tokens per LLM call, set as `max_tokens` on every platform request **to a Claude/Anthropic-dialect model**. Default `4096` — `symfony/ai`'s Anthropic bridge would otherwise apply its own much smaller default (~1000) and silently truncate `record_vulnerability` tool-call arguments mid-finding. **Currently a no-op for non-Claude models**: `symfony/ai`'s Gemini and OpenAI Responses bridges reject the `max_tokens` option key outright, so `PlatformOptionsFactory` only forwards it when the configured model name contains `claude`. |
| `attacker_max_output_tokens` | `int` (≥ 1) | `null` | Override: dedicated max output tokens for the Attacker. Falls back to `max_output_tokens` when `null`. Useful for headroom on detailed tool-call arguments. Same Claude-only caveat as `max_output_tokens` above. |
| `reviewer_max_output_tokens` | `int` (≥ 1) | `null` | Override: dedicated max output tokens for the Reviewer. Falls back to `max_output_tokens` when `null`. Same Claude-only caveat as `max_output_tokens` above. |
| `provider_json_mode` | bool | `false` | Send `response_format: {type: json_object}` on every LLM call **to a Claude/Anthropic-dialect model** so the provider enforces JSON output natively. **Currently a no-op for non-Claude models**, for the same bridge-compatibility reason as `max_output_tokens` above. Default `false`. The prompt contract (_"Return ONLY the JSON array"_) remains authoritative. |

`attacker_model` / `reviewer_model` and `attacker_max_output_tokens` / `reviewer_max_output_tokens` fall back to `model` and `max_output_tokens` respectively when not set. Model names must be supported by the platform configured in `ai.yaml`.

When raising `max_output_tokens`, consider raising `audit.rate_limit.output_tokens_per_minute` proportionally — otherwise the output-tokens bucket becomes the binding throttle long before `requests_per_minute` does. For example, with the default `4096` cap and an 80 000 OTPM ceiling the limiter trips after ~19 calls/min; doubling the cap halves that.

### `scan.*` — file discovery

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `scan.included_paths` | `string[]` | `['src', 'config', 'templates', 'public/index.php', '.env', '.env.local', '.env.dev', '.env.test', '.env.prod', '.env.dist']` | Project-relative directories and files that define the scan surface — the **sole scoping setting**, which a `--path` on the command line replaces for that run. Defaults match the Symfony Flex skeleton plus the root dotenv files (committed secrets hide there; the gitignored `.env.local` variants are pruned by the default `respect_gitignore: true`). Anything outside this list is silently skipped: `vendor/`, `node_modules/`, `var/`, `tests/`, `migrations/`, ad-hoc root scripts, `bin/`, `app/`, `lib/`, build artefacts, IDE folders, and any other top-level tree. Tighten or extend the list to match non-standard layouts (e.g. monorepos, `app/`). An entry resolving outside the project root (e.g. `../secret`) is skipped and logged rather than scanned. |
| `scan.respect_gitignore` | `bool` | `true` | When `true` (default), files matched by the project `.gitignore` are skipped. Set `false` for full-tree scans that include generated/cached artefacts (rare). |
| `scan.max_file_size_kb` | `int` (≥ 1) | `512` | Skip files larger than this size, in kilobytes. |
| `scan.import_sarif` | `string[]` | `[]` | Paths to SARIF 2.1.0 report files produced by other SAST tools (Psalm, PHPStan, Progpilot, Semgrep, …) whose results are imported as additional deterministic risk markers: each result becomes a `sarif:<tool>:<rule>` marker at its file and line, focusing the attacker on the external tool's concrete leads. When a result carries a `codeFlows` taint-tracking path, its source-to-sink steps are appended to the marker description as `(taint path: file:line -> file:line -> …)`, so the attacker sees the concrete flow instead of just the sink line. Relative paths resolve against the audited project root; an artifact URI may be relative, absolute or a `file://` URI, and a Windows drive path (`file:///C:/proj/src/A.php`) matches the project root whether that is spelled `C:/proj` or `C:\proj`. Imports apply even when `audit.static_prescan.enabled` is `false`; results (and taint-path steps) pointing outside the scan surface are dropped. A missing or malformed file aborts the audit with a clear error. |
| `scan.secret_scrubbing.enabled` | `bool` | `true` | Redact credential-shaped strings (AWS/GitHub/Stripe/Slack/Google API keys, JWTs, PEM private keys, env-style credential assignments, and connection-string URIs with embedded credentials such as `postgres://user:pass@host`) from file content before it reaches the LLM. Default `true` — credentials in committed sample configs or `.env.dist` files would otherwise be sent verbatim to the LLM provider. Scrubbing fails closed: if the PCRE engine refuses to evaluate a pattern (a file crafted to exhaust `pcre.backtrack_limit`, a `/u` custom pattern meeting invalid UTF-8), that file's content is withheld from the LLM entirely and a warning is logged, rather than sent only part-scanned. _Since 1.21._ Such a file is also recorded as not analyzed (`secret_scrubbing` stage, `errored`), so the report says it is incomplete. |
| `scan.secret_scrubbing.additional_patterns` | `string[]` | `[]` | Extra PCRE patterns merged with the defaults. Use to redact project-specific tokens (e.g. internal API key shapes). |
| `scan.custom_risk_patterns` | `map` | `{}` | Project-specific risk markers merged into the deterministic pre-scanner, keyed by file-type bucket (`controller`, `api_resource`, `live_component`, `voter`, `entity`, `repository`, `form`, `template`, `twig_extension`, `config`, `php`, `authenticator`, `messenger_handler`, `webhook_consumer`, `event_subscriber`, `normalizer`, `scheduler`). Each entry is `<label>: { regex: <PCRE>, description: <text> }`. Surface team idioms the built-ins do not know about. Each `regex` is validated at startup — an empty or syntactically invalid pattern aborts the audit with a clear error — and a pattern the PCRE engine refuses to evaluate at scan time (e.g. `pcre.backtrack_limit` exhausted) stops being evaluated for the rest of that file, logging a warning, rather than repeating a failing, CPU-costly call per line. |

### `audit.*` — orchestrator knobs

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `audit.max_iterations` | `int` (≥ 1) | profile | Maximum number of attacker/reviewer iterations per audit (balanced/thorough: `3`, fast: `1`). Loop stops earlier when no new findings emerge. |
| `audit.min_confidence` | `float` 0–1 | `0.6` | Minimum attacker self-reported confidence required to forward a finding to the reviewer. Tune for precision vs. recall: CI gate `0.8`, discovery scan `0.3`, default audit `0.6`. |
| `audit.reviewer_batch_size` | `int` (≥ 1) | `1` | Number of findings reviewed per LLM call. `1` = one-by-one (highest precision, highest latency). Larger values reduce cost/latency at risk of cross-talk between findings in the prompt. Try `5` for cost-sensitive runs. The reviewer-verdict cache applies in this mode too — cached verdicts are served first and only the cache-miss findings are batched to the LLM. |
| `audit.tools_enabled` | `bool` | `true` | Give the attacker access to tools (`read_file`, `grep`, `list_files`, `lookup_advisory`) for cross-file investigation. Default `true` — without tools, `lookup_advisory` is dead weight and the attacker is blind across files. Costs more LLM round-trips per chunk; mostly offset by Anthropic prompt caching (`cache_retention` in `ai.yaml`). Set `false` only if you need the cheapest possible single-file scan. |
| `audit.structured_collection` | `bool` | `true` | When `true` (default), the attacker emits findings by calling a schema-enforced `record_vulnerability` tool — one call per finding — instead of returning a JSON array. The provider validates each call against the tool's input schema, so malformed shapes (bare strings like `"dev"`/`"test"`, wrapper objects like `{"vulnerabilities": [...]}`) become structurally impossible. Provider-agnostic: works on Anthropic, OpenAI, Mistral, and Ollama tool-capable models. Set to `false` to fall back to the tightened JSON-array prompt path. Pairs well with Anthropic prompt caching (`cache_retention` in `ai.yaml`). |
| `audit.reviewer_structured_collection` | `bool` | `true` | When `true` (the default), the reviewer records each verdict by calling a schema-enforced `record_review` tool instead of returning a JSON array, so a malformed verdict never costs a discarded (but fully billed) response. Verdicts are served from and stored to the reviewer-verdict cache exactly like the JSON path. The explicit opt-in `reviewer_tools_enabled: true` takes precedence and keeps the JSON path. `reviewer_max_concurrent` > 1 composes with the structured mode on platforms with an async transport (each finding still records through its own `record_review` tool); on platforms without one it falls back to the JSON path. Set `false` to force JSON-array output (the safety net for models without tool-use support). |
| `audit.stable_system_prompt` | `bool` | `true` | When `true` (the default), the attacker emits its full expert skill set in the system prompt for every chunk instead of only the skills matching the chunk's file types. This makes the system-prompt prefix byte-identical across chunks, so provider prompt caching reads it on every call after the first — Anthropic (`cache_retention` in `ai.yaml`, default `short`), OpenAI, Gemini, and DeepSeek all cache prompt prefixes. A large input-token saving on multi-chunk audits. Set `false` (relevance-only skills, smaller prompt) for providers without prompt caching. Toggling this key (or `structured_collection`) invalidates the attacker cache — both flags are folded into its key salt. |
| `audit.max_tool_iterations` | `int` (≥ 1) | `8` | Maximum tool-call rounds per chunk. Bounds runaway tool use. _Since 1.22_ the last round is announced to the model, in the tool result that precedes it (so from a cap of `2` up), and a last round that records its findings ends the conversation: a chunk that explored up to the cap completes, and is cached like any other (the value is part of the attacker cache key). A model that ignores the notice and asks to read one more file keeps the findings it recorded but the chunk is recorded as errored and left out of the cache, so the next run retries it and the report says it could not be fully analyzed. Raising the value gives the model more rounds to read, at the price of more rounds (each re-reads the prompt) and of a one-time re-analysis. |
| `audit.reviewer_tools_enabled` | `bool` | `false` | Give the reviewer the same tool registry as the attacker so it can verify cross-file mitigations (parent-class guards, `access_control` rules, upstream sanitizers) instead of guessing from the file context alone. Default `false` — adds round-trips per finding; opt-in for high-precision audits. |
| `audit.reviewer_max_tool_iterations` | `int` (≥ 1) | `4` | Maximum tool-call rounds per finding for the reviewer (lower than the attacker's: verification, not exploration). |
| `audit.baseline` | `string` \| `null` | `null` | Default path to a baseline file of accepted findings (fingerprint = type + file + title). Baselined findings are dropped **before the reviewer runs** — each skip streams a `[BASELINE-SKIPPED]` line (`⚖ ⤳` on a decorated terminal) and costs zero reviewer tokens — and are excluded from the report and the exit code, so previously-accepted findings no longer fail CI. `--generate-baseline` writes one JSON entry per finding (`fingerprint`, `type`, `file`, `title`, `added_at`) so reviews of the baseline file stay readable; add a free-form `reason` to any entry and it does double duty: it documents the acceptance for your future self, **and** every reasoned entry is injected into the reviewer's system prompt as false-positive feedback (capped at 20 entries and, _since 1.21_, at 32 KiB in all, each field capped by code points — `type` 64, `file` 512, `title` 300, `reason` 5,000, the triage memory's cap — and quoted as data the reviewer must never take as an instruction, since a pull request can edit the file), so the reviewer recognizes the named mitigating control when judging _similar_ findings instead of re-flagging the same pattern. Reviewer-verdict cache keys incorporate the feedback, so editing a reason re-reviews affected findings. The legacy flat fingerprint array is still read. The `--baseline` CLI option overrides this key; `null` (default) disables baselining. A relative path written in a standalone project's `.symfony-security-auditor.yaml` is read from the folder that holds that file. **`--format=sarif` is the one exception to "excluded from the report":** any finding that still carries an accepted fingerprint when SARIF is rendered is kept in the output with a `suppressions: [{"kind": "external", "justification": "Accepted via audit baseline"}]` entry instead of being dropped, so GitHub Code Scanning / GitLab render it as suppressed rather than making it disappear silently. Every other format keeps the drop-before-render behavior above unchanged. |
| `audit.triage_memory` | `bool` | `false` | When `true`, every finding the reviewer rejects with a non-empty `reviewer_notes` explanation is persisted to a cross-run memory file (one file per audited project under `<cache.dir>/triage-memory/`, keyed by type+file+title+line, capped at 500 entries) and surfaced back to the reviewer on later runs exactly like a baseline entry's `reason` — but recorded automatically from the reviewer's own reasoning instead of hand-curated. Memory is scoped to the audited project, so a shared (user-global) cache directory never leaks one project's rejections into another's review. The first reason recorded for a finding is kept on later runs, so the combined feedback set stabilizes: reviewer-verdict cache keys incorporate it, and affected findings are re-reviewed once when the feedback set grows, then served from cache. Merges with any baseline-sourced feedback. Default `false` — opt-in, since it changes reviewer prompt content and writes to disk on every run. |
| `audit.fail_on` | `safe` \| `low` \| `medium` \| `high` \| `critical` | `critical` | Minimum **aggregate** risk level that makes `audit:run` exit `1` (the CI gate). The audit exits `1` when the report's risk level is at or above this threshold, `0` otherwise (a budget abort still exits `2`). Default `critical` preserves the historical behaviour (only a `CRITICAL` risk level fails). Set `high` (recommended for CI) / `medium` / `low` to fail pull requests earlier; `safe` fails on every completed audit. The `--fail-on` CLI option overrides this per run. **Planned to default to `high` in the next major** — pin it explicitly to be safe. |
| `audit.min_score` | `int` (0–100) \| `null` | `null` | _Since 1.22._ Minimum [normalized score](#normalized-score-and-grade) below which `audit:run` exits `1`, beside the `audit.fail_on` risk gate: the audit fails when **either** trips. `null` (default) gates on the risk level alone. The `--min-score` option overrides it for one run. |
| `audit.fail_on_incomplete` | `bool` | `false` | _Since 1.22._ Exit `3` when some file could not be fully analyzed — a scan or LLM call failed — so a partial report cannot pass CI; a tripped `fail_on` or `min_score` gate still exits `1`. Default `false` only prints a warning. `--fail-on-incomplete` and `--no-fail-on-incomplete` override it for one run. |
| `audit.format` | one of the `--format` values | `console` | _Since 1.22._ Report format when `--format` is not given. The `--format` option overrides it for one run, even when it names the default (`--format console`). |
| `audit.output` | `string` \| `null` | `null` | _Since 1.22._ Path the report is written to when `--output` is not given; `null` (default) prints it. The `--output` option overrides it for one run, and `--no-output` prints the report for one run instead. A `--dry-run` never writes to it, so an estimate cannot replace the last real report; give `--output` to write one. In the standalone binary a project `.symfony-security-auditor.yaml` may not set it: that file ships with the audited repository, which must not choose where your report is written. |
| `audit.report_path_prefix` | `string` \| `null` | `null` | _Since 1.22._ Folder, relative to the repository root, the audited project lives in (`backend` when `project-path` is `backend`). A finding's path is relative to the project, but GitHub resolves the locations of a SARIF upload and the `file=` of a `--format=github` annotation from the repository root, so an alert on a project in a sub-folder points at a file that does not exist. With this key set, that folder is put in front of every path in those two formats (`backend/src/Controller/UserController.php`); `null` (default) leaves them as they were. The JSON report, the baseline and every other format keep project-relative paths, so fingerprints and `audit:diff` are unaffected. A project `.symfony-security-auditor.yaml` may set it. |
| `audit.since_closure` | `none` \| `direct` | profile | When a `--since` diff-mode run is active, whether to widen the audited file set beyond the raw git diff. `none` audits exactly the changed files, matching every prior release. `direct` additionally pulls in a changed voter's first-degree dependents — the controllers guarded by an `#[IsGranted]` attribute whose name the voter's `supports()` accepts — from the full project mapping, so a voter edit that silently weakens an unrelated controller's access control is still caught, at the cost of widening `--since` runs' scope (balanced/fast: `none`, thorough: `direct`). |
| `audit.excluded_types` | `string[]` (VulnerabilityType values) | `[]` | Vulnerability types dropped from the report **and** the exit code, even when a finding of that type is validated. Mutes a noisy class (e.g. `missing_rate_limiting`) without enumerating per-finding baseline fingerprints. Each value must be a `VulnerabilityType` (`sql_injection`, `missing_voter`, …). Wins over `included_types`. Empty (default) mutes nothing. |
| `audit.included_types` | `string[]` (VulnerabilityType values) | `[]` | Allowlist of vulnerability types: when non-empty, only findings whose type is listed are reported and counted toward the exit code (`excluded_types` still wins). Each value must be a `VulnerabilityType`. Empty (default) includes every type. |
| `audit.custom_skills` | `map` | `{}` | Project-defined attacker skill blocks merged into the attacker prompt beside the built-ins. Keyed by skill name; each entry has `file_type` (a bucket: `controller`, `voter`, `entity`, `repository`, `form`, `template`, `config`, `php`, …), free-form `instructions` (what to hunt and what NOT to flag), and an optional `priority` (default `500`, emitted after the built-ins). Injected whenever a file of `file_type` appears in the chunk. Lets standalone-binary users encode company-specific rules without owning a PHP extension point. Editing any skill re-runs the affected attacker chunks (folded into the attacker cache key). |
| `audit.reviewer_max_concurrent` | `int` (≥ 1) | profile | Maximum reviewer LLM calls resolved concurrently when reviewing one finding per call (`reviewer_batch_size <= 1`) with reviewer tools off (balanced/thorough: `1`, fast: `4`). The reviewer phase is often half the wall-clock; `4`–`8` (within provider rate limits) cuts it proportionally. Composes with the structured `record_review` mode and the reviewer-verdict cache: cached verdicts are served first and only the misses are dispatched. Ignored when reviewer tools are on or the platform has no async transport. |
| `audit.attacker_max_concurrent` | `int` (≥ 1) | profile | Maximum attacker chunk analyses resolved concurrently in the default structured-collection mode, when the platform exposes an async transport (balanced/thorough: `1`, fast: `4`). The attacker phase is usually the longest; `4`–`8` (within provider rate limits) cuts it proportionally. Cache hits short-circuit and only misses are dispatched concurrently — each chunk records through its own `record_vulnerability` registry. With `audit.tools_enabled` on, the investigation tools ride alongside each chunk's `record_vulnerability` registry. Ignored when `structured_collection` is off. |
| `audit.static_prescan.enabled` | `bool` | `true` | Run the deterministic, zero-token risk-marker pre-scan and inject markers into the attacker prompt so it focuses on concrete locations. Pure detection-quality win. |
| `audit.static_prescan.lean_mode` | `bool` | profile | Drop files with zero pre-scan markers before the LLM sees them (balanced/thorough: `false`, fast: `true`). Slashes token spend (often 40–70%) at the cost of patterns the regex pre-scanner does not know about. |
| `audit.chunking.strategy` | `feature` \| `type` | `feature` | How files are grouped into LLM calls. `feature` colocates a controller with its entity/repository/form/voter/templates so the LLM follows cross-file flow; `type` uses the legacy attack-surface priority window. |
| `audit.code_slicing.enabled` | `bool` | profile | Trim large PHP files to security-relevant lines (structure, signatures, token-bearing lines) before the LLM, eliding the rest one-for-one so line numbers stay accurate, and putting back every line a pre-scan risk marker flags together with the rest of the call it opens (balanced/thorough: `false`, fast: `true`). |
| `audit.code_slicing.min_lines_before_slicing` | `int` (≥ 10) | `80` | Files shorter than this are sent unsliced (the saving is not worth the lost context). |
| `audit.poc_synthesis.enabled` | `bool` | profile | After the audit, generate a concrete copy-pasteable PoC (curl, console, payload) for validated findings ≥ the severity floor, exposed as the `synthesized_poc` report field (thorough: `true`, balanced/fast: `false`). Spends extra reviewer-model tokens per finding. An answer the output token limit or a content filter cut short is never attached: the finding keeps its original `proof` and a warning is logged. |
| `audit.poc_synthesis.severity_floor` | `critical` \| `high` \| `medium` \| `low` \| `info` | `high` | Minimum severity that triggers PoC synthesis. |
| `audit.fix_synthesis.enabled` | `bool` | `false` | After the audit, generate a suggested fix — a minimal unified-diff patch against the vulnerable file — for validated findings ≥ the severity floor, exposed as the `suggested_fix` report field and rendered in console/markdown/html output. Off by default and, unlike PoC synthesis, not implied by any profile; opt in explicitly. Spends extra reviewer-model tokens per finding. A patch the output token limit or a content filter cut short is never attached: the finding keeps its original `remediation` and a warning is logged. |
| `audit.fix_synthesis.severity_floor` | `critical` \| `high` \| `medium` \| `low` \| `info` | `high` | Minimum severity that triggers fix synthesis. |
| `audit.escalation.enabled` | `bool` | `false` | Two-pass attacker: a cheap-model sweep runs first; the expensive model only re-analyses files the sweep flagged. Cuts attacker token spend ~3–5× on inert codebases. Uses `escalation.cheap_model` for the first pass, falling back to the reviewer model when unset. |
| `audit.escalation.cheap_model` | `string` or `null` | `null` | Provider model id for the cheap first pass (e.g. `claude-haiku-4-5-20251001`). Falls back to the reviewer model when `null`. If the resolved cheap model equals the attacker model, escalation saves nothing and `audit:run` prints a pre-flight notice — set a genuinely cheaper model. |
| `audit.budget.max_tokens` | `int` (≥ 1) or `null` | `null` | Maximum total tokens (input + output + provider prompt-cache reads/writes, across attacker + reviewer) before the audit aborts cleanly with exit code `2`. `null` = unlimited. |
| `audit.budget.max_cost_usd` | `float` (≥ 0.01) or `null` | `null` | Maximum estimated cost (USD) before the audit aborts cleanly with exit code `2`. Cost is computed via the configured `PricingProviderInterface`. `null` = unlimited. |
| `audit.retry.max_attempts` | `int` (≥ 1) | `3` | Total attempts per LLM call, including the first try. `1` disables retries. Transient failures (provider 429/5xx, network blips) are retried with jittered exponential backoff; non-transient failures (auth, validation) fail fast. |
| `audit.retry.initial_delay_ms` | `int` (≥ 0) | `500` | Base delay (milliseconds) before the first retry. Subsequent retries multiply by `backoff_multiplier`. |
| `audit.retry.backoff_multiplier` | `float` (≥ 1.0) | `2.0` | Exponential growth factor between retries. With initial 500ms and multiplier 2.0, retries wait ~500, ~1000, ~2000 ms. |
| `audit.retry.jitter_ratio` | `float` 0–1 | `0.2` | Jitter applied to each computed delay, as a fraction in `[0.0, 1.0]`. `0.2` means each delay varies within ±20% of the base. |

### `audit.rate_limit.*` — proactive throttling

Token-bucket limiter wrapped around every LLM call. Each dimension is independently nullable; when **all three are `null` (default)** the bundle wires `NullRateLimiter` and the reactive retry path applies unchanged. Set the limits enforced by your provider tier (e.g. Anthropic RPM/ITPM/OTPM) so the steady-state path stays inside quota — `Retry-After` parsing still surfaces server-driven backoff when an estimate misses.

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `audit.rate_limit.requests_per_minute` | `int` (≥ 1) or null | `null` | Maximum LLM requests per minute. `null` disables this dimension. |
| `audit.rate_limit.input_tokens_per_minute` | `int` (≥ 1) or null | `null` | Maximum input tokens per minute. `null` disables this dimension. A chunk whose estimated input exceeds the cap is split in two and each half sent on its own (`RateLimitRequestTooLargeException`, extending `LLMRequestTooLargeException`); a single file whose prompt still exceeds the cap is recorded as errored, unless the file is under a tenth of that prompt: its fixed part, the system prompt and the project mapping, is then what leaves no room, and the run stops. |
| `audit.rate_limit.output_tokens_per_minute` | `int` (≥ 1) or null | `null` | Maximum output tokens per minute. `null` disables this dimension. Counted post-hoc from each call's actual usage so the next `acquire()` defers until the window resets once the bucket is full. |

State is per-process. Parallel runs sharing one API key (e.g. CI matrix) still race on the provider window — out-of-process coordination (Redis/file lock) is not provided by v1.

### `cache.*` — caching layers

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `cache.enabled` | `bool` | `true` | Enable the filesystem caches keyed by content hash: attacker chunks (skips the LLM call when an identical chunk was analyzed before) and reviewer verdicts (skips re-reviewing a finding with identical content against the same code context). The reviewer-verdict cache applies to every review mode: one-finding-per-call reviews (the default — structured, JSON, and concurrent, which serve cached verdicts first and dispatch only the misses) and batched reviews (`reviewer_batch_size > 1`, which serve cached verdicts first and batch only the cache-miss findings to the LLM). The attacker cache also covers iterations 2+ (chunks carrying prior-finding or rejected-finding context are keyed by chunk + context). Default `true` — large cost saver on repeated runs (CI, PR scans). Set `false` for one-shot audits or to debug LLM behavior. |
| `cache.dir` | `string` | `%kernel.cache_dir%/symfony_security_auditor/attacker` | Attacker cache storage path. Created on first write, owner-only: the entries hold the findings the model reported, with the source excerpts it quoted, and the reviewer's reasoning — never a project file — so the files are written `0600` and the directories the auditor creates `0700` (a directory that already exists keeps its permissions, so tighten one an earlier release made). The reviewer-verdict cache lives in a `reviewer` subdirectory alongside it. In the standalone user config, give an absolute path: a relative one is read against the directory the binary runs from, usually the audited checkout. |
| `cache.prompt_caching` | `bool` | `true` | **Deprecated since 1.7 and ignored.** Previously set `cache_control: ephemeral` on every LLM call, but current `symfony/ai` bridges drive caching elsewhere (see below). The key is still accepted for BC and emits a deprecation notice when set. Configure caching as described under [Prompt caching](#prompt-caching) instead. |

#### Prompt caching

Prompt caching is **not** controlled by this bundle — it is configured on the `symfony/ai` platform (your `config/packages/ai.yaml`), upstream of the auditor:

- **Anthropic** — set `cache_retention` (`none` \| `short` \| `long`) on the `anthropic` platform. The bridge auto-injects the cache markers; the default `short` (5-minute window) already enables the ~90% input-token discount. Use `long` for a 1-hour window on `api.anthropic.com`.
- **OpenAI / Gemini** — caching is **automatic** for long prompt prefixes; there is no flag to set.

```yaml
# config/packages/ai.yaml
ai:
    platform:
        anthropic:
            api_key: '%env(ANTHROPIC_API_KEY)%'
            cache_retention: long   # 1-hour cache window
```

Each model is priced from the `symfony/models-dev` listing of the `symfony/ai` platform the audit runs against — the one `PlatformInterface` resolves to, or the standalone `provider` — so a model served by Together, Venice, OVH, Bedrock or another gateway is billed at that platform's rate rather than at whichever provider re-lists the same id. A model the platform does not list, or a platform with no listing of its own (`generic`, `ollama`, `lmstudio`, …), falls back to the first-party providers, and then to the catalog at large for a provider-qualified id. When the provider reports which model actually answered — a gateway routing on its own, a failover platform, an alias resolved to a dated release — the call is billed as that model whenever the serving platform's own listing prices it, and as the configured model otherwise, so another provider re-listing the reported id at its own price never sets the bill. On a platform with no listing of its own, the reported model is billed as itself whenever the catalog lists it at all. The JSON report names the models each configured model was billed as under `cost.by_model.<model>.billed_models`.

When the provider reports cache usage, the auditor prices it into the cost it tracks and reports using the model's real per-provider cache rates from the `symfony/models-dev` catalog (for Anthropic that works out to cache reads at `0.1x` and cache writes at `1.25x` the input rate; other providers carry their own rates). Models with no published cache rate fall back to the base input rate. So the budget tracker and the `estimated_cost_usd` in the report reflect the real discounted spend rather than charging every input token at the full rate.

### `privacy.*` — data egress

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `privacy.offline_only` | `bool` | `false` | Refuse every network call the auditor itself owns. The advisory feed is replaced by an empty in-memory database, so `composer audit` never runs and `lookup_advisory` always answers "no advisories". In **standalone** mode the configured platform endpoints are also checked before the audit boots: every provider must carry at least one endpoint and every endpoint must be loopback, link-local or private-range (Ollama, LM Studio, a LAN inference box), otherwise the run aborts naming the offending provider. In **bundle** mode the platform lives in your own `ai.yaml`, which the auditor cannot inspect, so pointing it at a local platform stays your responsibility. Model pricing needs no network in **bundle** mode (it is read from the `symfony/models-dev` catalog in `vendor/`). In **standalone** mode, `self-update` also refreshes that catalog from a network call unless `privacy.offline_only` is enabled, in which case it is skipped and pricing keeps reading the catalog frozen into the binary at build time. A failed or corrupt refresh leaves whatever catalog is already in place — an earlier successful refresh takes precedence over the packaged one — and `self-update` prints a warning when that happens so a stale catalog is never silent. A cost whose `input` rate is missing, or whose rates are negative or not finite, is dropped from the refreshed catalog (that model is then unpriced rather than billed at a rate nobody set), and a refreshed catalog the audit cannot read, decode or price any model from is ignored in favor of the packaged one. The standalone update-availability check is separate — set `SSA_NO_UPDATE_CHECK=1` to silence it. See [How do I verify that nothing leaves my machine?](faq.md#how-do-i-verify-that-nothing-leaves-my-machine) |

```yaml
# config/packages/symfony_security_auditor.yaml
symfony_security_auditor:
    model: 'llama3.2'
    privacy:
        offline_only: true
```

### Simple mode — one model for both roles

```yaml
# config/packages/symfony_security_auditor.yaml
symfony_security_auditor:
    model: 'claude-opus-5'
```

### Split mode — separate models per role

```yaml
# config/packages/symfony_security_auditor.yaml
symfony_security_auditor:
    attacker_model: 'claude-opus-5'   # powerful model for discovery
    reviewer_model: 'claude-haiku-4-5-20251001'  # faster model for validation
```

### Full configuration example

```yaml
# config/packages/symfony_security_auditor.yaml
symfony_security_auditor:
    attacker_model: 'claude-opus-5'
    reviewer_model: 'claude-haiku-4-5-20251001'
    scan:
        included_paths:
            - 'src'
            - 'config'
            - 'templates'
            - 'public/index.php'
        respect_gitignore: true
        max_file_size_kb: 256
        secret_scrubbing:
            enabled: true
            additional_patterns:
                - '/MY_INTERNAL_TOKEN-[A-Z0-9]{16}/'
    audit:
        max_iterations: 5
        min_confidence: 0.7
        reviewer_batch_size: 5
        tools_enabled: true
    cache:
        enabled: true
```

## Advisory Source (`lookup_advisory` tool)

The `lookup_advisory` tool exposed to the attacker is backed by `ComposerAuditAdvisoryDatabase`, which shells out to **`composer audit --format=json --locked`** against `%kernel.project_dir%` on first call and caches the result for the lifetime of the request.

- **Data source.** `composer audit` is the Composer 2.4+ built-in command. It reads `composer.lock` and queries Packagist's advisory feed, which is sourced from `FriendsOfPHP/security-advisories` plus GitHub Security Advisories. Output is per-package CVE entries with affected version ranges and advisory links.
- **The audited project's own Composer settings are not used.** `composer audit` does not run inside the audited project: `IsolatedComposerAuditRunner` runs it (still with `--locked --no-scripts --no-plugins`) in a private temporary directory holding a copy of the project's `composer.lock` and an empty `composer.json`, removed once the audit is done. So the repository under audit decides neither where advisories come from — its `repositories` can disable Packagist (`"packagist.org": false`), list a feed of its own that reports nothing, or point Composer at an internal address of the audit host — nor which advisories are hidden: what it filters out with `config.audit.ignore` or `config.audit.ignore-severity` is looked up like the rest. The other side of it: a private repository publishing advisories for your private packages, or a project-level `auth.json`, no longer reaches the audit; configure them for the user who runs the auditor, in Composer's global configuration (`COMPOSER_HOME`). A `composer.lock` that is missing, a symlink or larger than 8 MiB is refused, and the database stays empty. The auditor also still reads the `ignored-advisories` key Composer reports, for a runner you substitute.
- **Graceful degradation.** When `composer` is missing from `PATH`, when `composer.lock` is absent, when the JSON is malformed, or when the process errors out for any reason, the database initializes empty and a `LoggerInterface::warning()` is recorded. `lookup_advisory` then returns `[]` for every package — the audit continues without CVE data.
- **Pair with `audit.tools_enabled: true`.** With tools disabled, the attacker cannot call `lookup_advisory`, so the live advisory feed is wasted effort. The recommended setup for any real audit is `tools_enabled: true` combined with Anthropic prompt caching (`cache_retention` in `ai.yaml`) to amortize the additional round-trips.
- **Overriding the source.** Need a custom feed (Snyk, internal CVE list, …)? Implement `Audit\Domain\Port\AdvisoryDatabaseInterface` in your project and override the alias in `config/services.yaml`:

```yaml
# config/services.yaml
services:
    VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\AdvisoryDatabaseInterface:
        alias: App\Security\MyCustomAdvisoryDatabase
```

## Platform Configuration

Install the Composer package for your chosen provider, then configure it under `ai.platform` in `config/packages/ai.yaml`. The bundle consumes `PlatformInterface` directly — no `ai.agent` configuration is needed.

### Supported platforms

| Platform | Composer package | Required env var(s) |
| --- | --- | --- |
| Anthropic (Claude) | `symfony/ai-anthropic-platform` | `ANTHROPIC_API_KEY` |
| OpenAI | `symfony/ai-open-ai-platform` | `OPENAI_API_KEY` |
| OpenAI Responses API | `symfony/ai-open-responses-platform` | `OPENAI_API_KEY` plus a `base_url` |
| Azure OpenAI | `symfony/ai-azure-platform` | `AZURE_OPENAI_API_KEY`, `AZURE_OPENAI_BASEURL` |
| Google Gemini | `symfony/ai-gemini-platform` | `GEMINI_API_KEY` |
| Google Vertex AI | `symfony/ai-vertex-ai-platform` | `GOOGLE_CLOUD_PROJECT`, `GOOGLE_CLOUD_LOCATION` |
| AWS Bedrock | `symfony/ai-bedrock-platform` | AWS credentials, or an API key on Mantle routes |
| DeepSeek | `symfony/ai-deep-seek-platform` | `DEEPSEEK_API_KEY` |
| Mistral AI | `symfony/ai-mistral-platform` | `MISTRAL_API_KEY` |
| MiniMax | `symfony/ai-mini-max-platform` | `MINIMAX_API_KEY` |
| Ollama (local) | `symfony/ai-ollama-platform` | none |
| Albert (French gov) | `symfony/ai-albert-platform` | `ALBERT_API_KEY` plus a `base_url` |
| amazee.ai | `symfony/ai-amazee-ai-platform` | `AMAZEEAI_API_KEY` plus a `base_url` |
| Fireworks AI | `symfony/ai-fireworks-platform` | `FIREWORKS_API_KEY` |
| Together AI | `symfony/ai-together-platform` | `TOGETHER_API_KEY` |
| Venice AI | `symfony/ai-venice-platform` | `VENICE_API_KEY` |
| Eden AI | `symfony/ai-eden-ai-platform` | `EDENAI_API_KEY` |
| Generic (AI gateway) | `symfony/ai-generic-platform` | depends on the gateway |

### Full `ai.yaml` example

Uncomment the block for the platform you want to use.

```yaml
# config/packages/ai.yaml
ai:
  platform:
    anthropic:
      api_key: '%env(ANTHROPIC_API_KEY)%'
    # openai:
    #   api_key: '%env(OPENAI_API_KEY)%'
    # openresponses:
    #   my_instance:
    #     base_url: '%env(OPENAI_BASEURL)%'
    #     api_key: '%env(OPENAI_API_KEY)%'
    # azure:
    #   my_deployment:
    #     base_url: '%env(AZURE_OPENAI_BASEURL)%'
    #     deployment: '%env(AZURE_OPENAI_DEPLOYMENT)%'
    #     api_key: '%env(AZURE_OPENAI_API_KEY)%'
    #     api_version: '%env(AZURE_OPENAI_API_VERSION)%'
    # gemini:
    #   api_key: '%env(GEMINI_API_KEY)%'
    # vertexai:
    #   project_id: '%env(GOOGLE_CLOUD_PROJECT)%'
    #   location: '%env(GOOGLE_CLOUD_LOCATION)%'
    # bedrock:
    #   default: ~
    # deepseek:
    #   api_key: '%env(DEEPSEEK_API_KEY)%'
    # mistral:
    #   api_key: '%env(MISTRAL_API_KEY)%'
    # minimax:
    #   api_key: '%env(MINIMAX_API_KEY)%'
    # ollama:
    #   endpoint: 'http://localhost:11434'
    # generic:
    #   my_gateway:
    #     base_url: '%env(GATEWAY_URL)%'
    #     api_key: '%env(GATEWAY_TOKEN)%'
```

### Instance-keyed platforms

Most platforms take their settings directly (`anthropic: {api_key: …}`). Six of them are keyed by an instance name instead, because you may configure several of each: `generic`, `openresponses`, `azure`, `bedrock`, `cache` and `failover`. Their settings live one level deeper, under a name you choose:

```yaml
ai:
    platform:
        generic:
            my_gateway:
                base_url: '%env(GATEWAY_URL)%'
                api_key: '%env(GATEWAY_TOKEN)%'
```

In **bundle** mode that is all you need: `symfony/ai-bundle` selects the platform by itself when exactly one is configured.

In **standalone** mode the top-level `provider:` key selects which platform the audit runs against, and for these six it must carry the instance name too:

```yaml
# ~/.config/symfony-security-auditor/config.yaml
provider: generic.my_gateway
platform:
    generic:
        my_gateway:
            base_url: 'https://your-gateway.example'
            api_key: '%env(GATEWAY_TOKEN)%'
model: 'your-model'
```

`init` writes that configuration, and installs `symfony/ai-generic-platform` for you, given `--provider=generic.my_gateway`, `--base-url=https://your-gateway.example`, `--model=your-model` and `--env-var=GATEWAY_TOKEN`. Leave the last two out and `init` prompts for them, or under `--no-interaction` falls back to `claude-opus-4-8` and `GENERIC_API_KEY`.

The instance name is required: `init` refuses a bare `--provider=generic` and tells you to use `generic.<instance>`, just as it refuses an instance on a platform that takes a single block (`--provider=anthropic.prod`). Its case is preserved, but surrounding whitespace is trimmed, and a hyphen is folded to an underscore the way `symfony/config` will, in both `provider:` and the `platform:` block at once so the two always agree (`generic.my-gateway` is written as `generic.my_gateway`). A name the config file could not be read back with is refused outright: `0`, because YAML writes that block as a sequence entry rather than as a key; `.inf` or `.nan`, because YAML writes those unquoted and then refuses them on the way back in; and a name read as a YAML tag or as the merge key, such as `!php/const` or `<<`, because the block comes back under a different name than `provider:` points at. Two more are refused for what happens after the file is read: a name holding a single quote, a NUL, a carriage return or a newline, or ending in a backslash, because `ai.platform.<platform>.<instance>` would not be a service id the container accepts; and a name holding a `%...%` pair, a whole-value `%env(VAR)%` included, because the container would read it as a reference rather than as a name (`--model` and the connection URLs accept a whole-value `%env(VAR)%`; an instance name is a key, which no environment variable can fill in). Every other number is accepted, subject to the same hyphen fold, so `generic.-1` is written as `generic._1`. A bare `provider: generic` in a hand-written config aborts the run saying so and listing the instances you configured.

`base_url` is the origin only. The `generic` bridge appends its own `completions_path`, which defaults to `/v1/chat/completions`, so a `base_url` already ending in `/v1` produces `/v1/v1/chat/completions`, a path your gateway does not serve. Give it `https://your-gateway.example` and, if your gateway serves a different route, set `completions_path` rather than folding the prefix into `base_url`:

```yaml
ai:
    platform:
        generic:
            my_gateway:
                base_url: '%env(GATEWAY_URL)%'
                api_key: '%env(GATEWAY_TOKEN)%'
                completions_path: '/chat/completions'
```

`init` asks for a `base_url`, the only child either platform requires, plus an API key. Everything else in their prototype is optional: `http_client` and the route key (`completions_path` on `generic`, `responses_path` on `openresponses`) carry defaults, `generic` adds `supports_completions`, `supports_embeddings` and `embeddings_path`, and `model_catalog` has no default at all. Set any of them by hand — except `http_client` in the standalone binary, whose container holds no other client to name: its timeout is the standalone-only [`http_timeout:`](#standalone-configuration) key. Six platforms need something it never asks for and are refused with exit code `2` rather than written half-configured: `azure` (a `deployment`), `cartesia` (a `version`) and `higgsfield` (an `api_secret`) want an extra field beside the key, and `dockermodelrunner`, `lmstudio` and `transformersphp` have no `api_key` node at all. Write those blocks by hand, pointing `provider:` at the matching `<platform>.<instance>` when the platform is instance keyed. `cache` and `failover` are refused outright: they wrap other platforms through a container service only a Symfony application defines (the serializer for `cache`, a rate limiter for `failover`), so they run from the bundle but not from the standalone binary.

Being instance keyed and taking a `base_url` are independent. `albert` and `amazeeai` require a `base_url` on a flat block, so `init` asks them for one too and writes it without an instance level:

```yaml
provider: albert
platform:
    albert:
        base_url: 'https://your-albert.example'
        api_key: '%env(ALBERT_API_KEY)%'
model: 'your-model'
```

## Model Options

The bundle exposes `max_output_tokens` directly at the top level (see [Top-level](#top-level)) — prefer that key for capping per-call output, since its default (`4096`) bypasses `symfony/ai`'s much smaller built-in default (~1000) that would otherwise truncate `record_vulnerability` tool-call arguments mid-finding.

Other provider-specific parameters (e.g. `temperature`) can still be passed through the model name using the query-string syntax `symfony/ai-bundle` supports:

```yaml
symfony_security_auditor:
    model: 'claude-haiku-4-5-20251001?temperature=0.2'
```

> Sampling parameters are model-specific: the current Claude generation (Opus 4.7/4.8, Opus 5, Sonnet 5, Fable 5) no longer accepts `temperature`, `top_p`, or `top_k`, and rejects such a request outright. Steer those models with `effort` or `thinking` instead.

`max_tokens` set this way overrides the bundle's `max_output_tokens` for that role. `symfony/ai-bundle`'s own `ai.yaml` platform config additionally accepts an expanded `{name, options}` mapping for a model — this bundle's `model` / `attacker_model` / `reviewer_model` keys do not: they are plain strings, so only the query-string form works here.

## Split-Model Setup

Using separate models per role lets you pair a large, high-accuracy model for attack discovery with a faster or cheaper model for review — reducing cost and latency without sacrificing thoroughness.

Both roles share the **same platform**; only the model name differs.

### `config/packages/ai.yaml`

```yaml
ai:
  platform:
    anthropic:
      api_key: '%env(ANTHROPIC_API_KEY)%'
```

### `config/packages/symfony_security_auditor.yaml`

```yaml
symfony_security_auditor:
    attacker_model: 'claude-opus-5'   # deep reasoning for vuln discovery
    reviewer_model: 'claude-haiku-4-5-20251001'  # fast + cheap for false-positive filtering
```

The attacker agent receives all source files grouped into chunks of 10, sorted by security priority (controllers first, then voters, entities, repositories, forms, then everything else). The reviewer agent then evaluates each candidate finding individually and decides whether to accept or escalate it.

## Standalone Configuration

When you run the [standalone binary](../README.md#standalone-tool-binary) instead of the bundle, configuration is read from a single user-level file. On Linux and macOS it follows the XDG Base Directory specification; on Windows it uses the native app-data directories:

| Purpose | Linux / macOS | Windows |
| --- | --- | --- |
| the configuration file | `$XDG_CONFIG_HOME/symfony-security-auditor/config.yaml` (→ `~/.config/…`) | `%APPDATA%\symfony-security-auditor\config.yaml` |
| attacker/reviewer and advisory caches | `$XDG_CACHE_HOME/symfony-security-auditor` (→ `~/.cache/…`) | `%LOCALAPPDATA%\symfony-security-auditor` |
| the downloaded provider bridge(s) | `$XDG_DATA_HOME/symfony-security-auditor` (→ `~/.local/share/…`) | `%LOCALAPPDATA%\symfony-security-auditor` |

> **Requirements & platform support.** Each release ships a self-contained native binary that bundles its own PHP runtime (nothing to install on the host) for **Linux** (x86-64, arm64), **macOS** (Intel, Apple Silicon), and **Windows** (x86-64) — install it with the script or download it from the release. `init` fetches the provider bridge with `composer`, and `--since` uses `git`, so those tools must be present on the host when you use those features (the audit itself needs only the binary).

**Redirecting the base directory (`SYMFONY_SECURITY_AUDITOR_HOME`).** Some container base images export `XDG_CONFIG_HOME` to a root-owned path — Caddy and FrankenPHP set it to `/config`, for example — so a non-root user running `init` there hits `mkdir(): Permission denied`. Set `SYMFONY_SECURITY_AUDITOR_HOME` to the absolute path of any writable directory to override where the config, cache, and bridge directories live; it outranks the XDG variables and `$HOME`, giving `~/.config`, `~/.cache`, and `~/.local/share` beneath it:

```bash
SYMFONY_SECURITY_AUDITOR_HOME=/app/var/ssa symfony-security-auditor init
# → /app/var/ssa/.config/symfony-security-auditor/config.yaml
```

A relative path is refused rather than resolved against the directory the command runs in, which would put the config, the credentials and the cache inside the project being audited: the command stops and names the variable. An empty value counts as unset.

Run `symfony-security-auditor init` to generate the file interactively and fetch the provider bridge — into its own composer project under the data directory, pinned to the binary's PHP version and to the `symfony/ai-platform` release the binary bundles, both refreshed on every run. Every bridge that project already requires is required again in the same `composer require`, so a second bridge you fetched by hand moves with the pin.

The binary loads that project ahead of its own classes, so a project holding another `symfony/ai-platform` release — one an older version of the binary installed, 1.20.x included — would replace the bundled one and fail every LLM call. The binary reads the release from the project's `vendor/composer/installed.php` first and leaves such a project unloaded: `audit`, `mcp:serve` and `doctor` then say so and name the command that rebuilds it, `init --provider=<your provider> --force`. `init` replaces the `provider:`, `platform:` and `model:` of `config.yaml` and keeps every other setting (budget caps, `privacy`, `cache`, `scan`, `http_timeout`, split-model overrides and the rest), so give it your model and connection options again, and `--force` keeps it from stopping at the overwrite question, which `--no-interaction` answers with no.

The file is **rootless** — the same keys as the bundle configuration above, without the `symfony_security_auditor:` wrapper — plus three standalone-only top-level keys:

- **`platform:`** — handed verbatim to `symfony/ai`'s `ai.platform` config, so it takes the exact shape documented in [Platform Configuration](#platform-configuration).
- **`provider:`** — optional selector naming the active platform when several are declared; omit it when only one platform is configured. With it set, the run needs only the selected platform's settings: another platform's unset `api_key` variable, or another instance's, does not stop it.
- **`http_timeout:`** — _Since 1.21._ How many seconds a request may wait for the provider to send anything before the binary gives up on it — the HTTP client's idle timeout. Default `600`; the total duration of a request is not bounded. Raise it for a slow local model or a self-hosted gateway that answers a long non-streamed request only once it is done: past the timeout the call fails with `Idle timeout reached for "…"`. A number of seconds above zero; anything else is refused.

```yaml
# ~/.config/symfony-security-auditor/config.yaml
provider: anthropic
platform:
    anthropic:
        api_key: '%env(ANTHROPIC_API_KEY)%'
model: claude-opus-4-8
# scan:, audit:, cache: are all accepted here too, unwrapped.
```

`init` is also scriptable: pass `--provider`, `--model`, `--env-var`, `--base-url`, `--endpoint` and `--no-api-key` to skip the matching prompt. Any option left out falls back to its interactive prompt (or, under `--no-interaction`, to its default — `anthropic`, `claude-opus-4-8`, and `<PLATFORM>_API_KEY` respectively). `--base-url` is only prompted for when `init` can write the platform's block and that block declares one, namely `albert`, `amazeeai`, `generic` and `openresponses`, and all four require it, so an empty answer is rejected with exit code `2` rather than written without it. `azure` declares a `base_url` too but is refused earlier for needing a `deployment`. A platform naming the same field `endpoint` takes `--endpoint` instead (`deepgram`, `elevenlabs`, `minimax`, `ollama`, `together`, `venice`); every other platform either names it differently again (`lmstudio` uses `host_url`) or hosts none, so passing either option with one is rejected with exit code `2` before anything is written. A blank provider or model, or an `--env-var` that is not a valid environment variable name, is rejected with exit code `2` before anything is written. The provider bridge is downloaded **before** the configuration file is replaced, so a failed download (offline, `composer` missing) leaves the previous, working configuration untouched. When a configuration already exists, `init` asks before overwriting it — and declines by default under `--no-interaction` — so scripted reconfiguration needs `--force` to replace the existing file without asking. Either way only `provider:`, `platform:` and `model:` are replaced: every other setting of the file stays, so after switching provider update any `attacker_model`, `reviewer_model` or `audit.escalation.cheap_model` still naming a model of the previous one. The `SSA_INIT` installer flag's no-terminal fallback and the GitHub Action run plain `init --no-interaction`, which keeps those Anthropic defaults — pass the options yourself to script any other provider:

```bash
symfony-security-auditor init --provider=openai --model=gpt-5.6 --no-interaction
# --env-var omitted → derived as OPENAI_API_KEY
```

```bash
# an AI gateway: the instance name belongs to both --provider and the config
symfony-security-auditor init \
    --provider=generic.my_gateway \
    --model=your-model \
    --base-url=https://your-gateway.example \
    --env-var=GATEWAY_TOKEN \
    --no-interaction
```

### Per-project overrides

A `.symfony-security-auditor.yaml` in the audited project is layered **over** the user config, with the project values winning. This lets a repository pin its own audit settings (chunking strategy, `fail_on`, scan scope, …) while the API credentials stay in the shared user config. The audited project is the `project-path` argument, relative to the folder you run the command from, or the working directory (`$PWD`) when the argument is omitted: `symfony-security-auditor audit ~/work/shop` reads `~/work/shop/.symfony-security-auditor.yaml`, whatever folder you run it from. _Since 1.22_ the file of the project the command names is the one read; before, only the working directory's was, so auditing a project from another folder skipped its file and applied the working directory's. `mcp:serve` still reads the working directory's, since one server audits whichever project each tool call names. The effective precedence, highest first, is:

1. CLI options (`--fail-on`, `--format`, …)
2. The per-project `.symfony-security-auditor.yaml`
3. The user-level `config.yaml`
4. Built-in defaults

When a project file is found, the audit header notes it — `Project config <path> is layered over your user config: …` — so a setting that comes from the checkout rather than from your own file is never silent.

> Scalars and mappings deep-merge; a **list** key (e.g. `scan.included_paths`) set in both files is replaced wholesale by whichever file sets it last — the per-project file's list fully overrides the user config's list rather than merging element-wise.

The per-project file may **not** declare `platform:` or `provider:` — a run whose project file carries either key is rejected before it starts. That file ships with the repository you are auditing, and `%env(VAR)%` placeholders resolve against _your_ environment, so honoring it would let any repository point your resolved API key (and every prompt, i.e. the source code) at an endpoint of its choosing. Connection settings are read from the user config alone.

The same reasoning bars `scan.import_sarif`: it reads whatever file it names — an absolute path included — and folds its contents into the LLM prompt, so a project file declaring it would let the repository point the scanner at paths of its own choosing. Configure SARIF imports in your user config instead.

Six more keys are yours alone, because they decide what the run trusts or writes rather than what it audits: `cache` (a cache directory inside the repository could be pre-seeded with forged "no findings" entries), `privacy` (the offline guard), `audit.custom_skills` (text placed in the attacker's system prompt), `audit.output` (where the report is written), `scan.custom_risk_patterns` (regexes and descriptions placed in the attacker prompt as pre-scanner hints) and `scan.secret_scrubbing`. A project file declaring any of them is rejected before the run starts, naming the key. A project file may override single keys beneath a section of your user config, never replace the section itself: `audit: []` or `audit: ~` would drop your budget caps and custom skills in one stroke, so a non-map value where your config has a map is rejected too. Hyphenated spellings (`secret-scrubbing`) are folded to their underscore form before these rules apply, exactly as the configuration component does when it reads the merged file. Every value the project file sets must be plain text the container takes literally: one holding a control character (a tab aside), a line break, a bidirectional override, bytes that are not UTF-8, a double colon or a legacy `##[`, which would reach your terminal or CI log — as a workflow command, for the last two — when the value is echoed back, is rejected before the run starts, naming the key without echoing the value; a key holding a double colon or a legacy `##[` is rejected the same way, before any other check can quote it. So is a value or key holding a container reference such as `%env(VAR)%`, which would read your environment into a setting the repository chose: write the value itself (a single `%` stays text), or keep the placeholder in your user config, where a value needing two `%` signs is written with each doubled. A model name the project file sets must be a model id alone — letters, digits and `. _ : / @ + -`, without `..` or `//`: the request options symfony/ai reads after a `?` (`?temperature=…`, `?effort=…`) and any path segment reach the provider as written, tools and headers included, so options belong in your user config. The project file itself must not be a symlink: one committed as a symlink could point at any file of yours, so it is rejected before it is read. `audit.budget` may only tighten your caps: a project file setting `max_cost_usd` or `max_tokens` at or below your own value (or where you set none) is honoured; one raising, removing or mis-typing a cap is rejected. `http_timeout` works the other way round: a project file may give the provider more time than your user config does (or than the default `600` seconds when you set none), never less, since a shorter timeout could cut its own audit short. A project file holding 10,000 values or more once its YAML aliases are expanded is refused before anything walks it — a few hundred bytes of nested aliases expand into billions; your user config is held to the same limit. `scan.included_paths` stays available to the project file: every included path is confined to the project root by its **real** path, so a symlink committed in the repository cannot walk the scanner out of it.

Everything else stays open to the project file — the models, `profile`, `max_iterations`, concurrency and PoC or fix synthesis included — and `audit.budget` has no cap by default, so an untrusted repository decides what an uncapped run spends. Before auditing a repository you do not trust, set `audit.budget.max_cost_usd` (or `max_tokens`) in your user config: the project file can then only lower it.

### Switching providers

`%env(VAR)%` placeholders in the `platform:` block are resolved from the environment, so secrets never live in the file. To switch providers, configure several platforms and change `provider:`; only the selected platform's variables need to be set. `init` writes a single-platform file, so fetch the second bridge by hand instead of running it again — into the bridge directory, whose `composer.json` already pins the PHP and `symfony/ai-platform` versions the binary needs:

```bash
composer require symfony/ai-open-ai-platform \
    --working-dir="${XDG_DATA_HOME:-$HOME/.local/share}/symfony-security-auditor"
```

That is the bridge directory from the [table above](#standalone-configuration): with `SYMFONY_SECURITY_AUDITOR_HOME` set, use `"$SYMFONY_SECURITY_AUDITOR_HOME/.local/share/symfony-security-auditor"` instead, and on Windows `"%LOCALAPPDATA%\symfony-security-auditor"`.

```yaml
provider: openai
platform:
    anthropic: { api_key: '%env(ANTHROPIC_API_KEY)%' }
    openai: { api_key: '%env(OPENAI_API_KEY)%' }
model: gpt-5.6
```

## Providing the API key

The `platform:` block holds a `%env(...)%` placeholder, never the key itself. Where that value comes from is yours to choose:

| Source | Config value | Typical setup |
| --- | --- | --- |
| Environment variable | `'%env(ANTHROPIC_API_KEY)%'` | CI secret store, `systemd` unit, a per-command assignment |
| Stored on this machine | `'%env(ANTHROPIC_API_KEY)%'` | `auth:set` — a developer laptop, set up once |
| File on disk | `'%env(file:ANTHROPIC_API_KEY_FILE)%'` | Docker/Kubernetes secrets, `systemd` `LoadCredential=`, 0600 file |
| Secret manager | either of the above | `pass`, 1Password, Vault — read at launch, see below |

For a value that is a placeholder as a whole, those two spellings are the only ones the standalone binary resolves: it applies no Symfony env processor there, so `%env(trim:VAR)%` or `%env(default::VAR)%` stops the run with a message naming the supported forms. The bundle, inside a Symfony application, keeps every env processor Symfony offers.

### Which one wins

Resolution order is fixed, and the first hit wins:

1. **The environment variable**, when it is set and non-empty.
2. **The credential stored by `auth:set`**, under that same variable name.
3. Otherwise the run stops before contacting the provider, naming all three ways to fix it.

The environment coming first is what keeps containers, CI and per-run secret-manager prefixes behaving exactly as they did before a key was ever stored. `auth:status` says which one is in play, and warns when an exported variable is shadowing a stored key.

### Storing the key on this machine

Standalone only, _since 1.21_. `init` offers it at the end of setup, and `auth:set` does it at any time:

```bash
symfony-security-auditor auth:set
# Paste the API key for ANTHROPIC_API_KEY (input stays hidden): ****
# [OK] Stored ANTHROPIC_API_KEY (sk-ant…qF4A, SHA256:ed9ff73cc4b2cd57) in
#      /home/you/.config/symfony-security-auditor/credentials.json. Audits pick
#      it up on their own from now on — an exported ANTHROPIC_API_KEY still
#      takes precedence when you want to override it for one run.
```

The prompt never echoes, so the key reaches neither the terminal nor the shell history. It is written to `credentials.json` beside your config file, keyed by the variable your `platform:` block names — so switching provider with `init` cannot make a run pick up the previous provider's key.

| Command | What it does |
| --- | --- |
| `auth:set` | Store or replace the key; `--env-var` targets a variable other than the configured one |
| `auth:status` | Report the variable, the source, the masked key, its fingerprint and the file path |
| `auth:remove` | Forget the stored key (the key stays valid with your provider — revoke it there too) |

**File permissions.** The file is created `0600` and its directory `0700`, and those are re-applied on every write. On a read, a file that group or others can open is **refused**, not used:

```text
The stored credentials at "…/credentials.json" are readable by other users on
this machine (permissions 0644). Anyone who could read them may already have
your API key, so rotate it with your provider, then run "chmod 600 …".
```

Only reading refuses. `auth:set` and `auth:remove` rewrite the file and restore `0600` as they go, so an exposed key is always replaceable or deletable from the tool itself rather than only by hand. A file that no longer parses as JSON is refused on read the same way, and `auth:set` replaces it.

**Exit codes.** All three commands exit `2` when no API-key variable is configured yet and none is named with `--env-var`, and when the name given is not a valid environment variable name (letters, digits and underscores, not starting with a digit — the name a `%env()%` placeholder can read back). The error quotes a short name as typed, with control bytes escaped, and masks anything longer than 23 characters the way a key is masked, in case it is the key itself pasted into the wrong option. `auth:status` then exits `0` when a key resolves for the variable — exported, read from the file a `%env(file:VAR)%` placeholder points at, or stored — and `1` when none does; `auth:set` exits `2` when nothing usable was entered or the terminal cannot hide what you type, `1` when there is nowhere to store the key (checked before it asks for one), the file cannot be read or written, or the key is not valid UTF-8, `0` once the key is stored; `auth:remove` exits `1` when the file cannot be read or rewritten, `0` whether or not a key was stored.

`auth:status --env-var` naming the variable your configuration reads through `%env(file:VAR)%` reports the key in that file, the way an audit reads it; any other variable is reported as its own value. When an exported variable decides the key, a credential file that cannot be read is reported as a warning rather than a failure — the audit does not open it either — and a run that needs no key (`--dry-run`) never opens it at all.

Windows has no POSIX permission bits — `fileperms()` reports the same mode for every file on an NTFS volume — so the permission check is skipped there and the file is protected by the user-profile ACL it inherits from `%APPDATA%`, the same protection `~/.aws/credentials` and `gh`'s `hosts.yml` rely on. If you want stronger guarantees on Windows, keep using `%env(file:…)%` with a file your own tooling protects, or a secret manager.

**Naming the key in output.** A stored or exported key is never printed. It is identified two ways instead: a masked preview (`sk-ant…qF4A`, the first six and last four characters, matching what your provider console shows) and a truncated SHA-256 fingerprint (`SHA256:ed9ff73cc4b2cd57`) that identifies it exactly and cannot be turned back into the key — though anyone who already holds a candidate key can confirm whether it is the one, so treat a fingerprint as you would a username rather than as public noise. A key shorter than 24 characters is masked entirely. Every audit run prints the preview in its header; `auth:status` and `doctor` print both.

**Nothing is required.** The store is a convenience for a machine you set up by hand. A container with no resolvable home directory simply has nothing stored, and falls back to the environment variable exactly as before.

### Reading the key from a file

`%env(file:VAR)%` reads the file whose **path** `VAR` holds, rather than the variable's own value — in the standalone binary _since 1.21_; a Symfony application gets it from Symfony's own `file:` env processor:

```yaml
platform:
    anthropic: { api_key: '%env(file:ANTHROPIC_API_KEY_FILE)%' }
```

```bash
ANTHROPIC_API_KEY_FILE=/run/secrets/anthropic symfony-security-auditor audit .
```

Surrounding whitespace is stripped, so a file written with `echo` or saved with Windows line endings works as is. The run stops before contacting the provider when `VAR` is unset, when the file cannot be read, or when it holds only whitespace; `doctor` reports the same failure under its `API key` check, and `--dry-run` tolerates all three because it never reaches the provider.

This is the portable option. No shell is involved, so it behaves identically on every shell and operating system, and it is how container runtimes and service managers already hand a secret to a process.

### Keeping the key out of your shell history

`export ANTHROPIC_API_KEY=sk-…` typed interactively is appended verbatim to `~/.bash_history` or `~/.zsh_history`. Read the key from your secret manager instead, scoped to the single command that needs it:

```bash
# bash, zsh
ANTHROPIC_API_KEY=$(pass show anthropic/api-key) symfony-security-auditor audit .
```

```fish
# fish
env ANTHROPIC_API_KEY=(pass show anthropic/api-key) symfony-security-auditor audit .
```

```powershell
# PowerShell
$env:ANTHROPIC_API_KEY = (op read 'op://Private/Anthropic/credential')
symfony-security-auditor audit .
```

Only the command reaches the history file; the key itself never appears on the line. With no secret manager to read from, either store the key once with `auth:set` (above), or prompt for it per shell:

```bash
printf 'Anthropic API key: '; read -rs ANTHROPIC_API_KEY; echo
export ANTHROPIC_API_KEY
```

### In CI

Keep the key in the runner's secret store and expose it to the step as an environment variable, never in the workflow file itself. The environment outranks any stored credential, so a runner is unaffected by what a developer machine keeps. See [CI](ci.md#github-actions) for GitHub Actions and [GitLab](ci.md#gitlab-ci) examples.

### In a Symfony application

The bundle resolves `ai.yaml` through Symfony's own environment handling, so `.env.local` (gitignored), the [secrets vault](https://symfony.com/doc/current/configuration/secrets.html) (`bin/console secrets:set ANTHROPIC_API_KEY`) and `%env(file:VAR)%` for a mounted secret all work unchanged.

### No key at all

Running against [Ollama](#supported-platforms) needs no credential. Pair it with [`privacy.offline_only: true`](#privacy--data-egress) to have that enforced rather than assumed.

## CLI Reference

The bundle registers the `audit:run` console command, also reachable through the shorter `audit` alias (`bin/console audit`), plus `audit:diff`, `audit:trend` and `audit:baseline` for working with previously generated reports. The standalone CLI exposes the same commands, run as `symfony-security-auditor audit:diff …`, and the three report commands need neither a configuration nor an API key.

```bash
bin/console audit:run [<project-path>] [options]
# `audit` is an equivalent alias:
bin/console audit [<project-path>] [options]
```

### Arguments

| Name | Required | Default | Description |
| --- | --- | --- | --- |
| `project-path` | no | `getcwd()` | Path to the Symfony project to audit. Defaults to current dir. |

### Options

| Option | Short | Default | Description |
| --- | --- | --- | --- |
| `--format` | `-f` | `console` | Output format: `console` (human-readable), `executive` (stakeholder summary — risk level, one-line business impact, and the severity / vulnerability-type / most-affected-file distributions, with no per-finding technical detail), `json`, `sarif`, `html` (self-contained, HTML-escaped report for sharing or archiving, with inline-SVG severity and vulnerability-type distribution charts), `markdown` (GitHub-flavored report for a PR comment or `$GITHUB_STEP_SUMMARY`), `junit` (JUnit XML — one failed test case per finding, rendered by CI test-report panels such as GitLab merge-request widgets on every tier), `github` (GitHub Actions workflow-command annotations — one `::error`/`::warning`/`::notice` line per finding, rendered inline on the PR's Files Changed view without a SARIF upload step), or `github-comment` (_since 1.19_ — a pull-request comment body: the grade and normalized score as a headline, then the most severe findings one table row each, opened by a marker comment so a rerun can edit its own comment in place) _Since 1.22_ `audit.format` gives it a default, and the flag wins over it, even when it names `console`. |
| `--output` | `-o` | none | Write the rendered report to a file path, for any `--format`. Also works with `--dry-run`. Not recommended with `--format=github` — annotations must go to the workflow log for GitHub to render them; see the CI recipes below. A path the report could never be saved to — a symlink on the way, a directory, a path ending with a separator such as `reports/` (_since 1.21_), an existing path that is not a regular file (a device such as `/dev/null`, a pipe or a socket, which saving the report would replace with a regular file; _since 1.22_), or a directory the file cannot be written into — is refused before the audit runs. _Since 1.22_ `audit.output` gives it a default, and the flag wins over it. |
| `--no-output` |  | `false` | _Since 1.22._ Print the report instead of writing it to a file, whatever `audit.output` says: it switches a configured `audit.output` off for one run. Cannot be combined with `--output`, which asks for the opposite: the command fails before the audit runs. |
| `--dry-run` |  | `false` | Estimate token usage and cost without invoking the LLM. Exits `0` with zero findings and a populated `cost` block. Since no file is analyzed, a report it writes is incomplete (_since 1.21_): the JSON report carries `complete: false`, SARIF `executionSuccessful: false`, and the human formats say no file was analyzed instead of "No validated vulnerabilities found". If a configured model (`model`, `attacker_model`, `reviewer_model`) has no pricing entry in the `PricingProviderInterface`, a warning is printed to stderr and that role's estimated cost shows `$0.00`. The estimate does not model provider prompt-cache discounts, so real runs with caching enabled typically come in under it. In the standalone binary it also runs without a provider credential: an unresolved `%env(...)%` placeholder that makes up a whole value in the `platform` block is tolerated for a dry run, since nothing reaches the provider — a real run still refuses to start without it. A placeholder no run could resolve, such as `%env(trim:API_KEY)%`, is refused by a dry run too. |
| `--path` | `-p` | none | Scan these directories or files, relative to the project root, **instead of** `scan.included_paths`: a flag wins over the configuration, so a path the configured scope does not reach is scanned (`--path apps/api` on a monorepo). Repeat to give several; paths that overlap list each file once. File types (`.php`, `.twig`, `.yaml`, `.yml`, `.xml`; a file named explicitly is read whatever its type), `scan.max_file_size_kb`, `scan.respect_gitignore`, secret scrubbing and the refusal of symlinks and of paths outside the project still apply. `--path .`, or the project root itself, keeps the configured scope. The paths narrow the files that are audited, not the Symfony mapping: `security.yaml`, voters and forms of the configured scope still tell the model which routes are guarded, so `--path src/Controller` does not turn every protected route into one that lacks an access check. _Since 1.22_ an absolute path inside the project is made relative to its root, and one outside it is refused with exit code `1`; the project is the `project-path` argument, or the current directory when it is omitted. _Since 1.22_ the paths replace `scan.included_paths` instead of narrowing it: before, a path outside the configured scope listed nothing. |
| `--show-scanned` |  | `false` | List the files that would be audited — those of `scan.included_paths`, or of the `--path` values that replace it — grouped by type with a per-type and total count, then exit, without invoking the LLM. Use it to confirm your scan scope before paying for a run. Combine with `--dry-run` to print the file list first and the cost estimate after. |
| `--no-cache` |  | `false` | Bypass the filesystem caches — attacker chunks and reviewer verdicts — for this run (no reads, no writes). Use after upgrading the auditor or to force a fresh analysis. |
| `--since` |  | none | Diff mode: audit only files changed against the given git ref (e.g. `main`, `origin/main`, `abc1234`). Honors committed (`ref...HEAD`) and uncommitted working-tree changes, including a new file that was never `git add`ed (unless a `.gitignore` leaves it out). Designed for pull-request CI; the cache stays warm for unchanged files. |
| `--baseline` |  | none | Path to a baseline file of accepted findings. Baselined findings skip the reviewer entirely (streamed as `[BASELINE-SKIPPED]` lines) and are excluded from the report and the exit code. With `--format=sarif`, a matching finding is instead kept and marked with a SARIF `suppressions` entry — see `audit.baseline` above. Entries annotated with a `reason` also feed the reviewer prompt as false-positive feedback — see `audit.baseline` above. Overrides the `audit.baseline` config key. A missing file suppresses nothing. |
| `--fail-on` |  | `critical` | Minimum aggregate risk level (`safe`, `low`, `medium`, `high`, `critical`) that makes the command exit `1`. Overrides the `audit.fail_on` config key for this run. Defaults to the configured value (`critical`) when omitted. |
| `--min-score` |  | none | _Since 1.19._ Minimum [normalized score](#normalized-score-and-grade) (0-100) below which the command exits `1`. Independent of `--fail-on`: the audit fails when **either** gate trips, so a project can be gated on one tunable number instead of severity buckets. Omit to gate on the risk level alone. A value outside `0`-`100` is refused with exit code `1` before the audit runs: it would fail every run or gate none. _Since 1.22_ `audit.min_score` gives it a default, and the flag wins over it. |
| `--fail-on-incomplete` |  | `false` | _Since 1.21._ Exit `3` when some file could not be fully analyzed — a scan or LLM call failed — so a partial report cannot pass CI. A tripped `--fail-on` or `--min-score` gate still exits `1`, as does a run that analyzed no file and found nothing, and an aborted run keeps its own code. Without it, such a run keeps the exit code its gates earn and prints an `Audit incomplete` warning (on stderr when the report goes to stdout). _Since 1.22_ `audit.fail_on_incomplete` gives it a default, and the flag wins over it: `--no-fail-on-incomplete` switches a configured `true` off for one run. |
| `--generate-baseline` |  | none | Run the audit, then write one baseline entry per current finding (`fingerprint`, `type`, `file`, `title`, `added_at`) to the given file and exit `0` without failing on findings (`3` under `--fail-on-incomplete` when some file could not be fully analyzed, since its findings are then missing from the baseline). Use to accept the current findings so future runs only report new ones. _Since 1.21_, its path is checked before the audit runs, as `--output` is (an existing path that is not a regular file is refused too), the report is still written when the baseline cannot be saved, and a run with no verdict — its scan found no file, or it analyzed none and found nothing — writes no baseline, leaves an existing one untouched, still writes the report and exits `1`, so a provider outage cannot replace every accepted finding and its reason with an empty file. Needs a real audit run, so combining it with `--dry-run` or `--show-scanned` (both of which exit before the LLM is invoked) fails fast with a clear error instead of silently writing nothing. |

### Examples

```bash
bin/console audit:run /path/to/symfony/project
```

```bash
bin/console audit:run /path/to/project --format=json --output=report.json
```

```bash
bin/console audit:run --format=sarif --output=report.sarif
```

```bash
bin/console audit:run --dry-run --format=json
```

```bash
# List the files that would be audited, without invoking the LLM
bin/console audit:run --show-scanned
```

```bash
bin/console audit:run --format=html --output=report.html
```

```bash
# Accept the current findings, then suppress them on later runs
bin/console audit:run --generate-baseline=.security-baseline.json
bin/console audit:run --baseline=.security-baseline.json
```

### Output Formats Reference

What each format produces. For ready-to-paste pipeline snippets, see [Output Formats in CI](ci.md#output-formats-in-ci).

#### `executive`

```text
══════════════════════════════════════════════════════════════════════
  EXECUTIVE SUMMARY — SECURITY AUDIT
  /srv/shop
══════════════════════════════════════════════════════════════════════

  Audited : 2026-07-26 06:02:59 (148 files, 192.4s)
  Audit ID: AUDIT-772F0F3E

──────────────────────────────────────────────────────────────────────
  RISK LEVEL: HIGH  (Score: 46)
──────────────────────────────────────────────────────────────────────

  Action required this sprint: findings at this level are
  exploitable by a motivated attacker and put user data or business
  logic at risk.

  7 validated finding(s) across 5 file(s).

  BY SEVERITY
  🔴 CRITICAL                                         2
  🟠 HIGH                                             2
  🟡 MEDIUM                                           2
  🟢 LOW                                              1

  BY TYPE
  broken_access_control                              1
  insecure_direct_object_reference                   1
  mass_assignment                                    1
  messenger_handler_unsafe                           1
  misconfigured_firewall                             1
  sql_injection                                      1
  twig_injection                                     1

  TOP AFFECTED FILES (of 5)
  src/Controller/Admin/UserController.php            3
  config/packages/security.yaml                      1
  src/Messenger/ImportHandler.php                    1
  src/Repository/ProductRepository.php               1
  src/Twig/ReviewExtension.php                       1

──────────────────────────────────────────────────────────────────────
  Findings are validated by a reviewer agent but not human-triaged.
  Run with --format=console for the full technical detail of each one.
──────────────────────────────────────────────────────────────────────
```

#### `github-comment`

_Since 1.19._ A pull-request comment body, sized for a comment rather than a full report: the [grade and normalized score](#normalized-score-and-grade) as a headline, the run summarized on one line, and the ten most severe findings as one table row each (with a note naming how many were left out). The body opens with an invisible `<!-- symfony-security-auditor:pr-comment -->` marker so a workflow can find its own previous comment and edit it in place instead of appending a new one on every push — which is exactly what the GitHub Action's `comment-pr` input does. See [Sticky PR comment with the audit summary](ci.md#sticky-pr-comment-with-the-audit-summary).

```markdown
<!-- symfony-security-auditor:pr-comment -->

## Security audit: D (58/100)

**Risk level:** HIGH · **Findings:** 7 · **Files scanned:** 148 · **Duration:** 192.4s

| Severity | Finding | Location | Type |
| --- | --- | --- | --- |
| 🔴 CRITICAL | Unprotected administrative action | `src/Controller/Admin/UserController.php:41` | `broken_access_control` |
| 🟠 HIGH | Unescaped user input in a Twig template | `src/Twig/ReviewExtension.php:23` | `twig_injection` |

---

Generated by [vinceamstoutz/symfony-security-auditor](https://github.com/vinceamstoutz/symfony-security-auditor).
```

#### `html`

A single self-contained file — no external stylesheet, font, image or script — carrying the risk badge and run metadata, a Distribution section of two inline-SVG bar charts (by severity, by vulnerability type), and one card per finding with its location, description, vulnerable code, attack vector, proof of concept and remediation. Colors come from the report's own stylesheet, so it follows the reader's light/dark preference.

![The HTML report: risk badge, run metadata, distribution charts and one card per finding](../assets/html-report.png?raw=true)

### Normalized score and grade

_Since 1.19._ Alongside `risk_score` — an unbounded weighted sum that grows with every finding — a report carries a **normalized score** and a **letter grade**, both bounded and both meant to be read at a glance in a badge, a pull-request comment or a CI gate.

The normalized score starts at `100` and deducts each finding's severity weight (`critical` 10, `high` 7, `medium` 5, `low` 2, `info` 0 — the same table `risk_score` sums), floored at `0`. So a clean report scores `100`, and one critical finding costs 10 points.

The grade boundaries mirror the `risk_level` thresholds, so the two never disagree:

| Grade | Score    | `risk_level` | `risk_score` |
| ----- | -------- | ------------ | ------------ |
| `A`   | 96 – 100 | `SAFE`       | 0 – 4        |
| `B`   | 86 – 95  | `LOW`        | 5 – 14       |
| `C`   | 71 – 85  | `MEDIUM`     | 15 – 29      |
| `D`   | 51 – 70  | `HIGH`       | 30 – 49      |
| `F`   | 0 – 50   | `CRITICAL`   | 50 +         |

`--format=json` exposes them as the additive root keys `score` and `grade`; `risk_score` and `risk_level` are unchanged.

### Exit codes

| Code | Meaning |
| --- | --- |
| `0` | Audit ran to its end; aggregate risk level is below the `fail_on` threshold (default `critical` → SAFE, LOW, MEDIUM, or HIGH) and, when `--min-score` is given, the normalized score is at or above it |
| `1` | Aggregate risk level is at or above the `fail_on` threshold (default `critical`), the normalized score is below `--min-score`, **the scan discovered no file to audit**, **no file in scope could be analyzed and nothing was found** (_since 1.21_), the audit itself failed, or the path was invalid |
| `2` | The audit budget could not be honored: either it aborted mid-run because the configured token or cost budget was exceeded (partial report still emitted), or it never started because an unpriced model makes `audit.budget.max_cost_usd` unenforceable and the run was declined or non-interactive (no report emitted in that case) |
| `3` | _Since 1.21._ `--fail-on-incomplete` is set, no gate tripped, and some file could not be fully analyzed |

An audit that ran to its end but could not fully analyze every file (a scan or LLM call failed) keeps the exit code its gates earn unless `--fail-on-incomplete` is set, in which case it exits `3` — or still `1` when a gate tripped. Either way it says so: the report reads `Audit incomplete`, the JSON report carries `complete: false`, SARIF sets `executionSuccessful: false`, and the command prints its own `Audit incomplete` notice — a warning naming `--fail-on-incomplete` when the run would otherwise pass, a plain warning when a gate already failed it, and an error when the option turned it into exit `3` — on stderr when the report itself goes to stdout, so a partial run never passes silently. An aborted run keeps exit code `1` (or `2` for a budget abort).

A run whose scan discovered **no file at all** exits `1` rather than reporting SAFE with a perfect score. Nothing was examined, so there is no verdict to pass — this catches a mistyped `project-path`, a `scan.included_paths` entry matching nothing, an over-broad `excluded_paths`, or a `.gitignore` that leaves nothing to scan while `scan.respect_gitignore` is on, instead of letting the gate go green. A `--since` run whose diff left nothing changed still exits `0`: there the scan did find files, and none of them changed. The command prints a `The scan found no file to audit, so the run has no verdict` error, the human-readable reports state the risk level as `UNKNOWN (no file was analyzed)` with an `Audit incomplete: the scan found no file to audit` notice instead of a grade, SARIF sets `executionSuccessful: false` with that notice, and the JUnit and GitHub annotation reports carry it as an errored test case and a warning; the JSON report keeps its field values.

_Since 1.21_, the same holds for a run that ran to its end without analyzing **any** file in scope and found nothing: the attacker analyzed (or served from its cache) none of them, whatever left them unanalyzed — a scan or LLM call that failed, or a run that stopped before reaching them. It exits `1` whatever `--fail-on`, `--min-score` or `--fail-on-incomplete` say, prints an `Audit incomplete: none of the N file(s) in scope could be analyzed, so the run has no verdict` error, and its human-readable reports state the risk level as `UNKNOWN (no file was analyzed)` instead of a SAFE verdict nobody earned. A run that holds a finding is not one of them, even when it analyzed no file in full — a response cut short keeps the findings it recorded while its chunk is recorded as errored. Such a run, like one that analyzed some files but not all, keeps the rule above: exit `0` with a warning, or `3` under `--fail-on-incomplete`, and its reports qualify the risk level as covering only the files analyzed.

### `audit:diff` — comparing two reports

Compares two JSON reports produced by `audit:run --format=json` and classifies every finding by its stable `fingerprint` (the same per-finding identity used by baseline suppression): findings only in the later report are **New**, findings only in the earlier report are **Fixed**, and findings in both are **Persisting**. A finding that disappeared from a file the later run could not fully analyze (its `coverage` ledger says the file `errored` or was `aborted`, so the report carries `complete: false`) is **Unverified** rather than fixed (_since 1.21_): nobody looked, so nothing says it is gone. The same holds for a file the later run never looked at — one the lean pre-scan skipped, one outside its `--since` or `--path` scope: a finding counts as fixed only when the later report's ledger says the attacker analyzed its file, or served it from its cache — or when its file is gone: the later report is complete (`complete: true`), analyzed at least one file, ran over the whole history (its `scope.since` is `null`), its `scope.paths` hold the file, and its ledger never lists the file, as for a file deleted since. The scan records nothing for a file it leaves out — one larger than `scan.max_file_size_kb`, matched by a `.gitignore` while `scan.respect_gitignore` is on, outside `scan.included_paths`, a symlink or an unreadable file — so a finding in such a file counts as fixed too. A file the ledger lists as `skipped`, `errored` or `aborted` stays unverified, as does one outside the scope, and a report written before the `scope` key existed relies on its ledger alone. A report generated before the `fingerprint` key existed is still accepted — the fingerprint is recomputed from `type`, `file`, and `title` — and one written before the coverage ledger existed simply has no unverified findings.

```bash
bin/console audit:diff previous.json current.json
```

| Argument          | Required | Description                      |
| ----------------- | -------- | -------------------------------- |
| `previous-report` | yes      | Path to the earlier JSON report. |
| `current-report`  | yes      | Path to the later JSON report.   |

| Option     | Short | Default   | Description                        |
| ---------- | ----- | --------- | ---------------------------------- |
| `--format` | `-f`  | `console` | Output format: `console` or `json` |

```bash
bin/console audit:diff previous.json current.json --format=json
```

The JSON document carries a `new`, `fixed`, `unverified` and `persisting` list; the console output shows the **Unverified** section, and counts it in its summary line, only when there is something in it.

Exit codes: `0` on a successful comparison (regardless of whether any findings are new, fixed, unverified, or persisting), `1` if a report file is missing or is not valid JSON.

### `audit:trend` — tracking findings across reports

Tracks how finding counts evolve across two or more JSON reports produced by `audit:run --format=json`, given oldest to newest. Every consecutive report pair is compared by the same stable `fingerprint` identity `audit:diff` uses, so each report's line shows its total plus how many findings appeared (**new**) and disappeared (**fixed**) since the report before it.

```bash
bin/console audit:trend nightly-01.json nightly-02.json nightly-03.json
```

```text
Trend (3 reports)
  1. nightly-01.json — 5 findings
  2. nightly-02.json — 4 findings (1 new, 2 fixed)
  3. nightly-03.json — 6 findings (2 new, 0 fixed)
Summary: 5 → 6 findings (+1) across 3 reports.
```

When some finding disappeared from a file a later run could not analyze, the summary says how many, as in `Summary: 5 → 2 findings (-3) across 2 reports, 3 unverified rather than fixed.` (_since 1.21_).

| Argument | Required | Description |
| --- | --- | --- |
| `reports` | yes | Paths to two or more JSON reports, ordered oldest to newest. |

| Option     | Short | Default   | Description                                 |
| ---------- | ----- | --------- | ------------------------------------------- |
| `--format` | `-f`  | `console` | Output format: `console`, `json`, or `html` |

With `--format=json` the trend is emitted as a `points` array — one entry per report with `report`, `total`, `new`, `fixed`, and `unverified` (_since 1.21_) keys (`new`, `fixed`, and `unverified` are `null` on the first point, which has no predecessor to compare against). `unverified` counts the findings that disappeared from files the report's run could not fully analyze or never looked at, by the rule [`audit:diff`](#auditdiff--comparing-two-reports) applies — they are neither fixed nor part of its total, and the console line mentions them only when there are some.

With `--format=html` the trend is emitted as a single self-contained HTML page (no external assets, light and dark mode): an SVG line chart of finding totals over the report series plus a table of per-report new/fixed/unverified deltas, under the same summary sentence as the console — redirect stdout to publish it as a dashboard:

```bash
bin/console audit:trend nightly-*.json --format=html > trend.html
```

Exit codes: `0` on a successful trend (regardless of how the counts evolve), `1` if fewer than two reports are given or a report file is missing or is not valid JSON.

### `audit:baseline` — maintaining the accepted-finding baseline

Creates or updates a baseline file from a JSON report produced by `audit:run --format=json`, **without re-running the audit**. Unlike `audit:run --generate-baseline` — which needs a fresh (paid) audit run and overwrites the file — this command merges: existing entries are preserved verbatim, so hand-written `reason` annotations (the ones that teach the reviewer, see [`audit.baseline`](#audit--orchestrator-knobs)) survive, and only findings not yet covered by an entry are appended.

```bash
bin/console audit:baseline report.json .security-baseline.json --prune --annotate
```

| Argument | Required | Description |
| --- | --- | --- |
| `report` | yes | Path to a JSON report produced by `audit:run --format=json`. |
| `baseline` | no | Baseline file to create or update (default `.security-baseline.json`). |

| Option | Default | Description |
| --- | --- | --- |
| `--prune` | off | Drop baseline entries whose findings no longer appear in the report. _Since 1.21_, an entry whose file the report did not analyze — its run failed on the file, or never looked at it — is kept with its reason, the way `audit:diff` calls such a finding unverified rather than fixed; an entry whose file a complete run that analyzed at least one file no longer lists anywhere in its scope — a deleted file, or one the scan now leaves out (see [`audit:diff`](#auditdiff--comparing-two-reports)) — is pruned. |
| `--annotate` | off | Ask a reason for each newly accepted finding; reasoned entries teach the reviewer. |

Each appended entry carries `fingerprint`, `type`, `file`, `title`, `added_at`, and — when `--annotate` supplied one — `reason`. Matching is count-aware, the same rule the audit itself applies: each entry accepts one occurrence, so a finding duplicated beyond its accepted count registers as new again. Entries whose `attacker_fingerprint` matches a report finding count as covering it.

Exit codes: `0` on success, `1` if the report is missing or malformed, the baseline file is malformed, or the baseline path is a symlink (refused, exactly as every other writer in this tool refuses symlinked destinations).

### `mcp:serve` — Model Context Protocol server

Starts a [Model Context Protocol](https://modelcontextprotocol.io) server over stdio, exposing the auditor as MCP **tools** so any MCP client — Claude Code, Claude Desktop, Cursor, VS Code, Windsurf, Gemini CLI, Codex CLI, … — can run an audit on demand. The server is built on the official [`mcp/sdk`](https://github.com/modelcontextprotocol/php-sdk) and speaks JSON-RPC on stdin/stdout, so the command prints nothing else to stdout: while it runs, PHP notices and warnings are displayed on stderr whatever `display_errors` says, so a stray one cannot corrupt the protocol stream.

It is available both ways the auditor ships, the standalone binary _since 1.21_:

```bash
symfony-security-auditor mcp:serve   # standalone binary, reads your user-level config.yaml
bin/console mcp:serve                # Symfony bundle, reads the application's configuration
```

Exposed tools:

| Tool | Arguments | Description |
| --- | --- | --- |
| `audit` | `path` (string, req.) | Runs the multi-agent audit on the project directory at `path` (an absolute path) and returns the JSON vulnerability report. It applies the configured `audit.baseline`, `audit.included_types` and `audit.excluded_types` as `audit:run` does, and answers a run with no verdict — the scan found no file, or none of the files could be analyzed — with an error instead of a report (_since 1.21_). It also refuses, before any LLM call, a run whose `audit.budget.max_cost_usd` cannot be enforced because a configured model has no published price: no prompt can accept that risk over MCP, so it answers as `audit:run --no-interaction` does. |

#### Registering it with an MCP client

Every client launches the server as a subprocess from a command and its arguments. With the standalone binary that is `symfony-security-auditor` and `mcp:serve`; with the bundle, `php` and the **absolute** path to your application's `bin/console` followed by `mcp:serve`, since a client does not start it from your project directory.

Claude Code:

```bash
claude mcp add --transport stdio symfony-security-auditor -- symfony-security-auditor mcp:serve
```

Claude Desktop (`claude_desktop_config.json`), Cursor (`.cursor/mcp.json`), Windsurf (`~/.codeium/windsurf/mcp_config.json`) and Gemini CLI (`~/.gemini/settings.json`) share one shape:

```json
{
    "mcpServers": {
        "symfony-security-auditor": {
            "command": "symfony-security-auditor",
            "args": ["mcp:serve"]
        }
    }
}
```

VS Code (`.vscode/mcp.json`):

```json
{
    "servers": {
        "symfony-security-auditor": {
            "type": "stdio",
            "command": "symfony-security-auditor",
            "args": ["mcp:serve"]
        }
    }
}
```

Codex CLI (`~/.codex/config.toml`):

```toml
[mcp_servers.symfony-security-auditor]
command = "symfony-security-auditor"
args = ["mcp:serve"]
```

#### Which model runs the audit — and the API key

The audit runs with the auditor's own configured platform, models and profile: `mcp:serve` is a transport in front of the same pipeline `audit:run` uses, so an audit triggered over MCP bills the configured LLM provider exactly as a CLI run would. **The MCP client's own model is not used**, and your provider credential is still required. Letting the client's model do the work would need MCP _sampling_, which the major clients do not offer.

- An audit needs **no API key** only when the configured platform takes none, such as a local [Ollama](#supported-platforms) — nothing then leaves your machine either.
- A client started from a desktop app does not inherit your shell's environment variables. With the standalone binary, store the key once with [`auth:set`](#providing-the-api-key) so the server finds it however it is launched; otherwise pass the variable through the client's `env` setting.
- A full report can be large. Claude Code caps a tool's output at 25,000 tokens by default; raise `MAX_MCP_OUTPUT_TOKENS` if a report is cut off.
- An audit takes minutes and the tool call is synchronous: it sends no progress, and a client that gives up on it — the MCP TypeScript SDK's default request timeout is 60 seconds — leaves the server finishing the audit, and spending on the provider, for an answer nobody reads. Raise the client's tool timeout (Claude Code reads `MCP_TOOL_TIMEOUT`, in milliseconds) or keep audits driven over MCP short with the `fast` profile and a narrow `scan.included_paths`.

### `init` — generating the standalone configuration

Standalone only. Writes `config.yaml` and downloads the provider bridge it needs. Every option it is not given is prompted for. Under `--no-interaction` the ones with defaults fall back to them, and a platform that requires a `--base-url` or an `--endpoint` is refused rather than written half-configured.

| Option | Default | Description |
| --- | --- | --- |
| `--provider` | `anthropic` | Any platform the bundled `symfony/ai-bundle` declares; any other — `meta`, which 0.14 dropped, or a misspelling — is refused with exit code `2` before anything is installed, listing the ones it declares. A platform configured per instance takes it too, e.g. `generic.my_gateway`. |
| `--model` | `claude-opus-4-8` | Used for every provider, not derived from one — set it for anything other than Anthropic. |
| `--env-var` | `<PLATFORM>_API_KEY` | The environment variable the configuration reads the API key from. A platform you host yourself (`ollama`) defaults to none instead. |
| `--base-url` | prompted when required | _Since 1.21._ The connection origin, for `albert`, `amazeeai`, `generic.<instance>` and `openresponses.<instance>`. Rejected for any other platform. |
| `--endpoint` | prompted when required | _Since 1.21._ The connection URL under the name those platforms give it: `deepgram`, `elevenlabs`, `minimax`, `ollama`, `together` and `venice`. For `ollama` and `together` it is the origin; `deepgram`, `elevenlabs`, `minimax` and `venice` take it with the API version path their default carries (`https://api.deepgram.com/v1/`), since the bridge appends only the route. Rejected for any other platform. |
| `--no-api-key` | off | _Since 1.21._ Write no `api_key` at all, for the platforms whose key the bundle leaves optional (`bedrock`, `deepgram`, `elevenlabs`, `generic`, `ollama`, `openresponses`). |
| `--force` | off | Replace `provider:`, `platform:` and `model:` of an existing configuration without asking; its other settings are kept. |

```bash
symfony-security-auditor init --provider=openai --model=gpt-5.6 --no-interaction

# an AI gateway: base_url is the origin only, with no trailing /v1 —
# the bridge appends its own completions_path
symfony-security-auditor init \
    --provider=generic.my_gateway \
    --base-url=https://your-gateway.example \
    --env-var=GATEWAY_TOKEN \
    --model=your-model \
    --no-interaction

# a local Ollama: no credential is written, because a local install
# authenticates nobody
symfony-security-auditor init \
    --provider=ollama \
    --endpoint=http://localhost:11434 \
    --model=llama3.2 \
    --no-interaction
```

A platform spells its connection URL `base_url` or `endpoint`, never both, so the two options each reject what the other accepts. `ollama` declares no default endpoint, so `init` refuses with exit code `2` rather than writing a configuration whose requests would go out against no base URI at all. It is also the one platform written without a credential by default: the bundle leaves its `api_key` optional and the docs list no required variable, so naming one would only produce a run that stops at `No API key available`. Pass `--env-var` to add a key anyway, which is what Ollama Cloud needs. That keyless shape is what `privacy.offline_only: true` expects — see [privacy.\*](#privacy--data-egress).

A URL may carry percent-encoded octets (`https://gw.example/v1%2Fx%3Fy`): `init` writes it with every `%` doubled, the container's own escape, so it reaches the platform exactly as typed. Any other `%…%` in a URL is refused, since the container would read it as a parameter; pass `%env(VAR)%` as the whole value to read the URL from the environment instead.

`bedrock` is written on a Bedrock Mantle route, the one that takes an API key where the default InvokeModel route needs an AWS SDK client service. Name the model after its vendor, as Bedrock does: `anthropic.claude-opus-4-8` is written with `api: messages`, `google.gemma-…` with `api: responses`, and every other model (`openai.gpt-oss-120b`, `qwen.…`) with `api: completions`; `init` also installs the `generic` or `openresponses` bridge those last two routes borrow their protocol from. A bare `claude-opus-4-8` is refused, since it names no route. The key comes from `BEDROCK_API_KEY` by default; `--no-api-key` writes none, so requests are signed with AWS SigV4 from your usual AWS credentials. Mantle defaults to `us-west-2`: add `region:` to the block for another one.

Six platforms are not written, because `init` only ever writes an `api_key` and an optional `base_url` or `endpoint`: `azure`, `cartesia` and `higgsfield` need an extra field beside the key, and `dockermodelrunner`, `lmstudio` and `transformersphp` take no `api_key` at all. The refusal names the field the platform wants; its connection block goes under `platform:` in `config.yaml`, with the same children `symfony/ai-bundle` documents for it. `azure` nests one level deeper under an instance name — see [Instance-keyed platforms](#instance-keyed-platforms); the other five take a flat block.

For these, `init` still installs the bridge into the standalone data directory, pinned to the binary's own PHP version and to the `symfony/ai-platform` release it bundles, then prints the block to paste into `config.yaml` instead of writing it, and exits with code `2`. What it is given is checked first, as for any other platform: an instance name `init` would refuse elsewhere (`azure.0`, `azure.%gw%`, `azure.o'brien`), an instance on a platform taking a single block (`lmstudio.x`) and an `--env-var` that is no variable name are refused before the bridge is installed. Replace every `<placeholder>` before running an audit:

```bash
symfony-security-auditor init --provider=lmstudio --model=qwen3-coder --no-interaction
```

```yaml
provider: lmstudio
platform:
    lmstudio:
        host_url: 'http://127.0.0.1:1234'
model: qwen3-coder
```

`cache` and `failover` get neither a block nor a bridge: `init` exits with code `2` and says why. Both wrap other platforms through a container service only a Symfony application defines — the serializer for `cache`, a rate limiter for `failover` — which the standalone binary does not have and its `config.yaml` cannot declare, so no block written for them could boot. Configure the platform they would wrap directly, or use them from the bundle.

Every value `init` writes or prints is quoted whenever YAML would otherwise read it back as something else, so a model named `.inf` stays the string `.inf` rather than becoming a float.

### `self-update` — updating the standalone binary

Updates the [standalone binary](#standalone-configuration) in place to the latest released version. This command exists **only in the standalone binary** (the Composer bundle updates through `composer update`).

```bash
symfony-security-auditor self-update          # download + verify + replace, if newer
symfony-security-auditor self-update --check  # only report whether a newer version exists
```

It queries the GitHub releases API for the latest version (a release tag is accepted only as `X.Y.Z`, with an optional pre-release suffix and an optional leading `v`, and anything else is refused before it reaches a download URL or the terminal) and, when the running binary is older, downloads the asset for your platform (the same OS/arch detection `install.sh` uses) next to the running executable, **verifies its `.sha256` checksum before replacing anything**, and renames it over the executable — an atomic swap — as the command exits, once nothing more is loaded from the running binary. The command therefore reports `Downloaded and verified <new>; it replaces <old> as this command exits.`; if that final swap fails, it prints why on stderr, keeps the previous binary, and exits `1`. Downloads use `curl`, so it must be on the host (as it already is for the install script).

| Option | Default | Description |
| --- | --- | --- |
| `--check` | off | Report whether a newer version is available; make no changes to the binary. |

The swap writes a new file into the directory holding the binary, so that directory must be writable — the binary's own permissions do not matter. If it is not (e.g. installed in `/usr/local/bin` without write access), the command refuses to update before downloading anything and tells you to re-run with the necessary permissions (`sudo`) or reinstall with the install script.

### `doctor` — preflight environment check

Verifies that the [standalone binary](#standalone-configuration) is ready to run an audit before you start one. Like `self-update` and `init`, this command exists **only in the standalone binary** — the Composer bundle relies on your application's own container and Composer autoloader.

```bash
symfony-security-auditor doctor
```

It runs four checks and prints one line for each:

| Check | What it verifies |
| --- | --- |
| Configuration | `config.yaml` resolves, a `platform:` block is present, and every `%env(...)%` variable the selected platform references is set — an unset API-key variable is reported under the label `API key` instead |
| Provider bridge | the `symfony/ai-*` bridge autoloader is installed under the data directory (`init` downloads it), holds the `symfony/ai-platform` release the binary bundles, **and the audit actually boots with it** — a leftover bridge from a previously configured provider fails here, and so does one an older version of the binary installed |
| Composer | a runnable `composer` is reachable — needed only to run `init` or switch providers, not to audit |
| Pricing catalog | the `symfony/models-dev` catalog the run prices from is there, naming the refreshed one `self-update` wrote when the run can use it, and the packaged one otherwise |

A missing `composer` or pricing catalog is reported as a **warning** (auditing still works); a missing/invalid configuration or an uninstalled — or unbootable — bridge is a **failure**. The command exits `0` when every check passes or only warns, and `1` when any check fails, so it drops into a CI preflight step:

```bash
symfony-security-auditor doctor && symfony-security-auditor audit path/to/app
```

### Update notifications

When you run the [standalone binary](#standalone-configuration) interactively, it prints a one-line notice to **stderr** once a command finishes if a newer release is available:

```text
A new version (1.17.0) is available. Run "symfony-security-auditor self-update" to upgrade.
```

The check is designed to stay out of the way:

- It runs **only on an interactive terminal**, so piped or CI runs — and machine-readable stdout such as `--format=json` — are never touched.
- The GitHub release lookup is **throttled to once per 24 hours** (the answer is cached under the XDG cache directory), and any failure (offline, rate-limited) is silent — it never changes a command's exit code. When that cache cannot be written (an unwritable or unresolvable cache directory), the lookup is skipped rather than repeated on every command.
- It exists **only in the standalone binary**; the Composer bundle updates through `composer update`.

Set `SSA_NO_UPDATE_CHECK=1` to turn the check off entirely.
