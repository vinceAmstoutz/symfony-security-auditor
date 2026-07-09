# Configuration Reference

Full configuration reference for the `symfony-security-auditor` bundle. Covers
bundle registration, bundle-level configuration, platform wiring via
`symfony/ai`, model options, and the CLI command.

## Table of Contents

- [Bundle Registration](#bundle-registration)
- [Manual Setup (without Flex)](#manual-setup-without-flex)
- [Bundle Configuration](#bundle-configuration)
  - [Top-level](#top-level)
  - [`scan.*` — file discovery](#scan--file-discovery)
  - [`audit.*` — orchestrator knobs](#audit--orchestrator-knobs)
  - [`cache.*` — caching layers](#cache--caching-layers)
  - [Simple mode](#simple-mode--one-model-for-both-roles)
  - [Split mode](#split-mode--separate-models-per-role)
  - [Full example](#full-configuration-example)
- [Advisory Source (`lookup_advisory`)](#advisory-source-lookup_advisory-tool)
- [Platform Configuration](#platform-configuration)
- [Model Options](#model-options)
- [Split-Model Setup](#split-model-setup)
- [Standalone Configuration](#standalone-configuration)
- [CLI Reference](#cli-reference)
  - [`audit:diff`](#auditdiff--comparing-two-reports)

> See also: [Architecture](architecture.md) · [Extending](extending.md) ·
> [CI](ci.md) · [FAQ](faq.md) · [Troubleshooting](troubleshooting.md)

## Bundle Registration

Register both bundles in `config/bundles.php`. Symfony Flex does this
automatically via the recipe. `AiBundle` must be installed and registered
alongside this bundle — it provides the `PlatformInterface` service this bundle
references — but array order does not matter: the reference is a lazy
`nullOnInvalid()` service resolved by the container compiler after every
bundle's `loadExtension()` has already run.

```php
// config/bundles.php
return [
    // ...
    Symfony\AI\AiBundle\AiBundle::class => ['all' => true],
    VinceAmstoutz\SymfonySecurityAuditor\SymfonySecurityAuditorBundle::class => ['dev' => true, 'test' => true],
];
```

## Manual Setup (without Flex)

Without Symfony Flex (or with `composer require --no-scripts`), do by hand what
the recipe automates:

1. Register both bundles in `config/bundles.php` — see
   [Bundle Registration](#bundle-registration).
2. Create `config/packages/symfony_security_auditor.yaml` — see
   [Bundle Configuration](#bundle-configuration) — or copy the
   [recipe's template](https://github.com/symfony/recipes-contrib/blob/main/vinceamstoutz/symfony-security-auditor/1.0/config/packages/symfony_security_auditor.yaml).

## Bundle Configuration

Create `config/packages/symfony_security_auditor.yaml`. The bundle exposes the
following keys:

> **Editor autocompletion.** A JSON Schema for this configuration ships at
> [`resources/schema.json`](../resources/schema.json). Editors pick it up from a
> `# $schema:` modeline on the first line of your config file — both the
> [YAML Language Server](https://github.com/redhat-developer/yaml-language-server)
> (VS Code, Neovim, …) and PhpStorm/IntelliJ understand this form:
>
> ```yaml
> # $schema: https://raw.githubusercontent.com/vinceamstoutz/symfony-security-auditor/main/resources/schema.json
>
> symfony_security_auditor:
>     model: "claude-opus-4-8"
> ```
>
> This gives key completion, type checking, and inline docs as you edit. The
> example files under [`examples/configs/`](../examples/configs/) include the
> modeline. The URL tracks the `main` branch so it always resolves to the
> current schema — no per-release bump needed.

### Top-level

| Key                          | Type        | Default             | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| ---------------------------- | ----------- | ------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `profile`                    | string      | `'balanced'`        | One-knob preset bundling the cost/speed/depth levers: `fast`, `balanced`, or `thorough`. A profile only fills the keys you left unset — any explicitly configured key always wins. `fast`: one attacker iteration, lean pre-scan, code slicing on, four concurrent attacker and reviewer calls. `balanced`: identical to configuring nothing. `thorough`: balanced plus PoC synthesis.                                                                                                                                                                           |
| `model`                      | string      | `'claude-opus-4-8'` | Model name used for both Attacker and Reviewer roles                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| `attacker_model`             | string      | `null`              | Override: dedicated model for the Attacker role                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| `reviewer_model`             | string      | `null`              | Override: dedicated model for the Reviewer role                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| `max_output_tokens`          | `int` (≥ 1) | `4096`              | Maximum output tokens per LLM call, set as `max_tokens` on every platform request **to a Claude/Anthropic-dialect model**. Default `4096` — `symfony/ai`'s Anthropic bridge would otherwise apply its own much smaller default (~1000) and silently truncate `record_vulnerability` tool-call arguments mid-finding. **Currently a no-op for non-Claude models**: `symfony/ai`'s Gemini and OpenAI Responses bridges reject the `max_tokens` option key outright, so `PlatformOptionsFactory` only forwards it when the configured model name contains `claude`. |
| `attacker_max_output_tokens` | `int` (≥ 1) | `null`              | Override: dedicated max output tokens for the Attacker. Falls back to `max_output_tokens` when `null`. Useful for headroom on detailed tool-call arguments. Same Claude-only caveat as `max_output_tokens` above.                                                                                                                                                                                                                                                                                                                                                |
| `reviewer_max_output_tokens` | `int` (≥ 1) | `null`              | Override: dedicated max output tokens for the Reviewer. Falls back to `max_output_tokens` when `null`. Same Claude-only caveat as `max_output_tokens` above.                                                                                                                                                                                                                                                                                                                                                                                                     |
| `provider_json_mode`         | bool        | `false`             | Send `response_format: {type: json_object}` on every LLM call **to a Claude/Anthropic-dialect model** so the provider enforces JSON output natively. **Currently a no-op for non-Claude models**, for the same bridge-compatibility reason as `max_output_tokens` above. Default `false`. The prompt contract (_"Return ONLY the JSON array"_) remains authoritative.                                                                                                                                                                                            |

`attacker_model` / `reviewer_model` and `attacker_max_output_tokens` /
`reviewer_max_output_tokens` fall back to `model` and `max_output_tokens`
respectively when not set. Model names must be supported by the platform
configured in `ai.yaml`.

When raising `max_output_tokens`, consider raising
`audit.rate_limit.output_tokens_per_minute` proportionally — otherwise the
output-tokens bucket becomes the binding throttle long before
`requests_per_minute` does. For example, with the default `4096` cap and an 80
000 OTPM ceiling the limiter trips after ~19 calls/min; doubling the cap halves
that.

### `scan.*` — file discovery

| Key                                         | Type        | Default                                                                                                                       | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| ------------------------------------------- | ----------- | ----------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `scan.included_paths`                       | `string[]`  | `['src', 'config', 'templates', 'public/index.php', '.env', '.env.local', '.env.dev', '.env.test', '.env.prod', '.env.dist']` | Project-relative directories and files that define the scan surface — the **sole scoping knob**. Defaults match the Symfony Flex skeleton plus the root dotenv files (committed secrets hide there; the gitignored `.env.local` variants are pruned by the default `respect_gitignore: true`). Anything outside this list is silently skipped: `vendor/`, `node_modules/`, `var/`, `tests/`, `migrations/`, ad-hoc root scripts, `bin/`, `app/`, `lib/`, build artefacts, IDE folders, and any other top-level tree. Tighten or extend the list to match non-standard layouts (e.g. monorepos, `app/`). |
| `scan.respect_gitignore`                    | `bool`      | `true`                                                                                                                        | When `true` (default), files matched by the project `.gitignore` are skipped. Set `false` for full-tree scans that include generated/cached artefacts (rare).                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| `scan.max_file_size_kb`                     | `int` (≥ 1) | `512`                                                                                                                         | Skip files larger than this size, in kilobytes.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| `scan.secret_scrubbing.enabled`             | `bool`      | `true`                                                                                                                        | Redact credential-shaped strings (AWS/GitHub/Stripe/Slack/Google API keys, JWTs, PEM private keys, env-style credential assignments, and connection-string URIs with embedded credentials such as `postgres://user:pass@host`) from file content before it reaches the LLM. Default `true` — credentials in committed sample configs or `.env.dist` files would otherwise be sent verbatim to the LLM provider.                                                                                                                                                                                         |
| `scan.secret_scrubbing.additional_patterns` | `string[]`  | `[]`                                                                                                                          | Extra PCRE patterns merged with the defaults. Use to redact project-specific tokens (e.g. internal API key shapes).                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| `scan.custom_risk_patterns`                 | `map`       | `{}`                                                                                                                          | Project-specific risk markers merged into the deterministic pre-scanner, keyed by file-type bucket (`controller`, `api_resource`, `live_component`, `voter`, `entity`, `repository`, `form`, `template`, `twig_extension`, `config`, `php`, `authenticator`, `messenger_handler`, `webhook_consumer`, `event_subscriber`, `normalizer`, `scheduler`). Each entry is `<label>: { regex: <PCRE>, description: <text> }`. Surface team idioms the built-ins do not know about.                                                                                                                             |

### `audit.*` — orchestrator knobs

| Key                                           | Type                                                | Default    | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| --------------------------------------------- | --------------------------------------------------- | ---------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `audit.max_iterations`                        | `int` (≥ 1)                                         | profile    | Maximum number of attacker/reviewer iterations per audit (balanced/thorough: `3`, fast: `1`). Loop stops earlier when no new findings emerge.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
| `audit.min_confidence`                        | `float` 0–1                                         | `0.6`      | Minimum attacker self-reported confidence required to forward a finding to the reviewer. Tune for precision vs. recall: CI gate `0.8`, discovery scan `0.3`, default audit `0.6`.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| `audit.reviewer_batch_size`                   | `int` (≥ 1)                                         | `1`        | Number of findings reviewed per LLM call. `1` = one-by-one (highest precision, highest latency). Larger values reduce cost/latency at risk of cross-talk between findings in the prompt. Try `5` for cost-sensitive runs. The reviewer-verdict cache applies in this mode too — cached verdicts are served first and only the cache-miss findings are batched to the LLM.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| `audit.tools_enabled`                         | `bool`                                              | `true`     | Give the attacker access to tools (`read_file`, `grep`, `list_files`, `lookup_advisory`) for cross-file investigation. Default `true` — without tools, `lookup_advisory` is dead weight and the attacker is blind across files. Costs more LLM round-trips per chunk; mostly offset by Anthropic prompt caching (`cache_retention` in `ai.yaml`). Set `false` only if you need the cheapest possible single-file scan.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| `audit.structured_collection`                 | `bool`                                              | `true`     | When `true` (default), the attacker emits findings by calling a schema-enforced `record_vulnerability` tool — one call per finding — instead of returning a JSON array. The provider validates each call against the tool's input schema, so malformed shapes (bare strings like `"dev"`/`"test"`, wrapper objects like `{"vulnerabilities": [...]}`) become structurally impossible. Provider-agnostic: works on Anthropic, OpenAI, Mistral, and Ollama tool-capable models. Set to `false` to fall back to the tightened JSON-array prompt path. Pairs well with Anthropic prompt caching (`cache_retention` in `ai.yaml`).                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
| `audit.reviewer_structured_collection`        | `bool`                                              | `true`     | When `true` (the default), the reviewer records each verdict by calling a schema-enforced `record_review` tool instead of returning a JSON array, so a malformed verdict never costs a discarded (but fully billed) response. Verdicts are served from and stored to the reviewer-verdict cache exactly like the JSON path. The explicit opt-in `reviewer_tools_enabled: true` takes precedence and keeps the JSON path. `reviewer_max_concurrent` > 1 composes with the structured mode on platforms with an async transport (each finding still records through its own `record_review` tool); on platforms without one it falls back to the JSON path. Set `false` to force JSON-array output (the safety net for models without tool-use support).                                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| `audit.stable_system_prompt`                  | `bool`                                              | `true`     | When `true` (the default), the attacker emits its full expert skill set in the system prompt for every chunk instead of only the skills matching the chunk's file types. This makes the system-prompt prefix byte-identical across chunks, so provider prompt caching reads it on every call after the first — Anthropic (`cache_retention` in `ai.yaml`, default `short`), OpenAI, Gemini, and DeepSeek all cache prompt prefixes. A large input-token saving on multi-chunk audits. Set `false` (relevance-only skills, smaller prompt) for providers without prompt caching. Toggling this key (or `structured_collection`) invalidates the attacker cache — both flags are folded into its key salt.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| `audit.max_tool_iterations`                   | `int` (≥ 1)                                         | `8`        | Maximum tool-call rounds per chunk before the attacker is forced to commit to a final answer. Bounds runaway tool use.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| `audit.reviewer_tools_enabled`                | `bool`                                              | `false`    | Give the reviewer the same tool registry as the attacker so it can verify cross-file mitigations (parent-class guards, `access_control` rules, upstream sanitizers) instead of guessing from the file context alone. Default `false` — adds round-trips per finding; opt-in for high-precision audits.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| `audit.reviewer_max_tool_iterations`          | `int` (≥ 1)                                         | `4`        | Maximum tool-call rounds per finding for the reviewer (lower than the attacker's: verification, not exploration).                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| `audit.baseline`                              | `string` \| `null`                                  | `null`     | Default path to a baseline file of accepted findings (fingerprint = type + file + title). Baselined findings are dropped **before the reviewer runs** — each skip streams a `[BASELINE-SKIPPED]` line (`⚖ ⤳` on a decorated terminal) and costs zero reviewer tokens — and are excluded from the report and the exit code, so previously-accepted findings no longer fail CI. `--generate-baseline` writes one JSON entry per finding (`fingerprint`, `type`, `file`, `title`, `added_at`) so reviews of the baseline file stay readable; add a free-form `reason` to any entry for your future self. The legacy flat fingerprint array is still read. The `--baseline` CLI option overrides this key; `null` (default) disables baselining. **`--format=sarif` is the one exception to "excluded from the report":** any finding that still carries an accepted fingerprint when SARIF is rendered is kept in the output with a `suppressions: [{"kind": "external", "justification": "Accepted via audit baseline"}]` entry instead of being dropped, so GitHub Code Scanning / GitLab render it as suppressed rather than making it disappear silently. Every other format keeps the drop-before-render behavior above unchanged. |
| `audit.fail_on`                               | `safe` \| `low` \| `medium` \| `high` \| `critical` | `critical` | Minimum **aggregate** risk level that makes `audit:run` exit `1` (the CI gate). The audit exits `1` when the report's risk level is at or above this threshold, `0` otherwise (a budget abort still exits `2`). Default `critical` preserves the historical behaviour (only a `CRITICAL` risk level fails). Set `high` (recommended for CI) / `medium` / `low` to fail pull requests earlier; `safe` fails on every completed audit. The `--fail-on` CLI option overrides this per run. **Planned to default to `high` in the next major** — pin it explicitly to be safe.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| `audit.excluded_types`                        | `string[]` (VulnerabilityType values)               | `[]`       | Vulnerability types dropped from the report **and** the exit code, even when a finding of that type is validated. Mutes a noisy class (e.g. `missing_rate_limiting`) without enumerating per-finding baseline fingerprints. Each value must be a `VulnerabilityType` (`sql_injection`, `missing_voter`, …). Wins over `included_types`. Empty (default) mutes nothing.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| `audit.included_types`                        | `string[]` (VulnerabilityType values)               | `[]`       | Allowlist of vulnerability types: when non-empty, only findings whose type is listed are reported and counted toward the exit code (`excluded_types` still wins). Each value must be a `VulnerabilityType`. Empty (default) includes every type.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| `audit.reviewer_max_concurrent`               | `int` (≥ 1)                                         | profile    | Maximum reviewer LLM calls resolved concurrently when reviewing one finding per call (`reviewer_batch_size <= 1`) with reviewer tools off (balanced/thorough: `1`, fast: `4`). The reviewer phase is often half the wall-clock; `4`–`8` (within provider rate limits) cuts it proportionally. Composes with the structured `record_review` mode and the reviewer-verdict cache: cached verdicts are served first and only the misses are dispatched. Ignored when reviewer tools are on or the platform has no async transport.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| `audit.attacker_max_concurrent`               | `int` (≥ 1)                                         | profile    | Maximum attacker chunk analyses resolved concurrently in the default structured-collection mode, when the platform exposes an async transport (balanced/thorough: `1`, fast: `4`). The attacker phase is usually the longest; `4`–`8` (within provider rate limits) cuts it proportionally. Cache hits short-circuit and only misses are dispatched concurrently — each chunk records through its own `record_vulnerability` registry. With `audit.tools_enabled` on, the investigation tools ride alongside each chunk's `record_vulnerability` registry. Ignored when `structured_collection` is off.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| `audit.static_prescan.enabled`                | `bool`                                              | `true`     | Run the deterministic, zero-token risk-marker pre-scan and inject markers into the attacker prompt so it focuses on concrete locations. Pure detection-quality win.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| `audit.static_prescan.lean_mode`              | `bool`                                              | profile    | Drop files with zero pre-scan markers before the LLM sees them (balanced/thorough: `false`, fast: `true`). Slashes token spend (often 40–70%) at the cost of patterns the regex pre-scanner does not know about.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| `audit.chunking.strategy`                     | `feature` \| `type`                                 | `feature`  | How files are grouped into LLM calls. `feature` colocates a controller with its entity/repository/form/voter/templates so the LLM follows cross-file flow; `type` uses the legacy attack-surface priority window.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| `audit.code_slicing.enabled`                  | `bool`                                              | profile    | Trim large PHP files to security-relevant lines (structure, signatures, token-bearing lines) before the LLM, eliding the rest one-for-one so line numbers stay accurate (balanced/thorough: `false`, fast: `true`).                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| `audit.code_slicing.min_lines_before_slicing` | `int` (≥ 10)                                        | `80`       | Files shorter than this are sent unsliced (the saving is not worth the lost context).                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| `audit.poc_synthesis.enabled`                 | `bool`                                              | profile    | After the audit, generate a concrete copy-pasteable PoC (curl, console, payload) for validated findings ≥ the severity floor, exposed as the `synthesized_poc` report field (thorough: `true`, balanced/fast: `false`). Spends extra reviewer-model tokens per finding.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| `audit.poc_synthesis.severity_floor`          | `critical` \| `high` \| `medium` \| `low` \| `info` | `high`     | Minimum severity that triggers PoC synthesis.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
| `audit.escalation.enabled`                    | `bool`                                              | `false`    | Two-pass attacker: a cheap-model sweep runs first; the expensive model only re-analyses files the sweep flagged. Cuts attacker token spend ~3–5× on inert codebases. Uses `escalation.cheap_model` for the first pass, falling back to the reviewer model when unset.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| `audit.escalation.cheap_model`                | `string` or `null`                                  | `null`     | Provider model id for the cheap first pass (e.g. `claude-haiku-4-5-20251001`). Falls back to the reviewer model when `null`. If the resolved cheap model equals the attacker model, escalation saves nothing and `audit:run` prints a pre-flight notice — set a genuinely cheaper model.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| `audit.budget.max_tokens`                     | `int` (≥ 1) or `null`                               | `null`     | Maximum total tokens (input + output, across attacker + reviewer) before the audit aborts cleanly with exit code `2`. `null` = unlimited.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| `audit.budget.max_cost_usd`                   | `float` (≥ 0.01) or `null`                          | `null`     | Maximum estimated cost (USD) before the audit aborts cleanly with exit code `2`. Cost is computed via the configured `PricingProviderInterface`. `null` = unlimited.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| `audit.retry.max_attempts`                    | `int` (≥ 1)                                         | `3`        | Total attempts per LLM call, including the first try. `1` disables retries. Transient failures (provider 429/5xx, network blips) are retried with jittered exponential backoff; non-transient failures (auth, validation) fail fast.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| `audit.retry.initial_delay_ms`                | `int` (≥ 0)                                         | `500`      | Base delay (milliseconds) before the first retry. Subsequent retries multiply by `backoff_multiplier`.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| `audit.retry.backoff_multiplier`              | `float` (≥ 1.0)                                     | `2.0`      | Exponential growth factor between retries. With initial 500ms and multiplier 2.0, retries wait ~500, ~1000, ~2000 ms.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| `audit.retry.jitter_ratio`                    | `float` 0–1                                         | `0.2`      | Jitter applied to each computed delay, as a fraction in `[0.0, 1.0]`. `0.2` means each delay varies within ±20% of the base.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |

### `audit.rate_limit.*` — proactive throttling

Token-bucket limiter wrapped around every LLM call. Each dimension is
independently nullable; when **all three are `null` (default)** the bundle wires
`NullRateLimiter` and the reactive retry path applies unchanged. Set the limits
enforced by your provider tier (e.g. Anthropic RPM/ITPM/OTPM) so the
steady-state path stays inside quota — `Retry-After` parsing still surfaces
server-driven backoff when an estimate misses.

| Key                                         | Type                | Default | Description                                                                                                                                                                                          |
| ------------------------------------------- | ------------------- | ------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `audit.rate_limit.requests_per_minute`      | `int` (≥ 1) or null | `null`  | Maximum LLM requests per minute. `null` disables this dimension.                                                                                                                                     |
| `audit.rate_limit.input_tokens_per_minute`  | `int` (≥ 1) or null | `null`  | Maximum input tokens per minute. `null` disables this dimension. A single request whose estimated input exceeds the cap throws `RateLimitRequestTooLargeException` (extends `LLMProviderException`). |
| `audit.rate_limit.output_tokens_per_minute` | `int` (≥ 1) or null | `null`  | Maximum output tokens per minute. `null` disables this dimension. Counted post-hoc from each call's actual usage so the next `acquire()` defers until the window resets once the bucket is full.     |

State is per-process. Parallel runs sharing one API key (e.g. CI matrix) still
race on the provider window — out-of-process coordination (Redis/file lock) is
not provided by v1.

### `cache.*` — caching layers

| Key                    | Type     | Default                                                | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| ---------------------- | -------- | ------------------------------------------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `cache.enabled`        | `bool`   | `true`                                                 | Enable the filesystem caches keyed by content hash: attacker chunks (skips the LLM call when an identical chunk was analyzed before) and reviewer verdicts (skips re-reviewing a finding with identical content against the same code context). The reviewer-verdict cache applies to every review mode: one-finding-per-call reviews (the default — structured, JSON, and concurrent, which serve cached verdicts first and dispatch only the misses) and batched reviews (`reviewer_batch_size > 1`, which serve cached verdicts first and batch only the cache-miss findings to the LLM). The attacker cache also covers iterations 2+ (chunks carrying prior-finding or rejected-finding context are keyed by chunk + context). Default `true` — large cost saver on repeated runs (CI, PR scans). Set `false` for one-shot audits or to debug LLM behavior. |
| `cache.dir`            | `string` | `%kernel.cache_dir%/symfony_security_auditor/attacker` | Attacker cache storage path. Created on first write. The reviewer-verdict cache lives in a `reviewer` subdirectory alongside it.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| `cache.prompt_caching` | `bool`   | `true`                                                 | **Deprecated since 1.7 and ignored.** Previously set `cache_control: ephemeral` on every LLM call, but current `symfony/ai` bridges drive caching elsewhere (see below). The key is still accepted for BC and emits a deprecation notice when set. Configure caching as described under [Prompt caching](#prompt-caching) instead.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               |

#### Prompt caching

Prompt caching is **not** controlled by this bundle — it is configured on the
`symfony/ai` platform (your `config/packages/ai.yaml`), upstream of the auditor:

- **Anthropic** — set `cache_retention` (`none` \| `short` \| `long`) on the
  `anthropic` platform. The bridge auto-injects the cache markers; the default
  `short` (5-minute window) already enables the ~90% input-token discount. Use
  `long` for a 1-hour window on `api.anthropic.com`.
- **OpenAI / Gemini** — caching is **automatic** for long prompt prefixes; there
  is no flag to set.

```yaml
# config/packages/ai.yaml
ai:
    platform:
        anthropic:
            api_key: '%env(ANTHROPIC_API_KEY)%'
            cache_retention: long   # 1-hour cache window
```

When the provider reports cache usage, the auditor prices it into the cost it
tracks and reports using the model's real per-provider cache rates from the
`symfony/models-dev` catalog (for Anthropic that works out to cache reads at
`0.1x` and cache writes at `1.25x` the input rate; other providers carry their
own rates). Models with no published cache rate fall back to the base input
rate. So the budget tracker and the `estimated_cost_usd` in the report reflect
the real discounted spend rather than charging every input token at the full
rate.

### Simple mode — one model for both roles

```yaml
# config/packages/symfony_security_auditor.yaml
symfony_security_auditor:
    model: 'claude-opus-4-8'
```

### Split mode — separate models per role

```yaml
# config/packages/symfony_security_auditor.yaml
symfony_security_auditor:
    attacker_model: 'claude-opus-4-8'   # powerful model for discovery
    reviewer_model: 'claude-haiku-4-5-20251001'  # faster model for validation
```

### Full configuration example

```yaml
# config/packages/symfony_security_auditor.yaml
symfony_security_auditor:
    attacker_model: 'claude-opus-4-8'
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

The `lookup_advisory` tool exposed to the attacker is backed by
`ComposerAuditAdvisoryDatabase`, which shells out to
**`composer audit --format=json --locked`** against `%kernel.project_dir%` on
first call and caches the result for the lifetime of the request.

- **Data source.** `composer audit` is the Composer 2.4+ built-in command. It
  reads `composer.lock` and queries Packagist's advisory feed, which is sourced
  from `FriendsOfPHP/security-advisories` plus GitHub Security Advisories.
  Output is per-package CVE entries with affected version ranges and advisory
  links.
- **Graceful degradation.** When `composer` is missing from `PATH`, when
  `composer.lock` is absent, when the JSON is malformed, or when the process
  errors out for any reason, the database initializes empty and a
  `LoggerInterface::warning()` is recorded. `lookup_advisory` then returns `[]`
  for every package — the audit continues without CVE data.
- **Pair with `audit.tools_enabled: true`.** With tools disabled, the attacker
  cannot call `lookup_advisory`, so the live advisory feed is wasted effort. The
  recommended setup for any real audit is `tools_enabled: true` combined with
  Anthropic prompt caching (`cache_retention` in `ai.yaml`) to amortize the
  additional round-trips.
- **Overriding the source.** Need a custom feed (Snyk, internal CVE list, …)?
  Implement `Audit\Domain\Port\AdvisoryDatabaseInterface` in your project and
  override the alias in `config/services.yaml`:

```yaml
# config/services.yaml
services:
    VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\AdvisoryDatabaseInterface:
        alias: App\Security\MyCustomAdvisoryDatabase
```

## Platform Configuration

Install the Composer package for your chosen provider, then configure it under
`ai.platform` in `config/packages/ai.yaml`. The bundle consumes
`PlatformInterface` directly — no `ai.agent` configuration is needed.

### Supported platforms

| Platform             | Composer package                     | Required env var(s)                             |
| -------------------- | ------------------------------------ | ----------------------------------------------- |
| Anthropic (Claude)   | `symfony/ai-anthropic-platform`      | `ANTHROPIC_API_KEY`                             |
| OpenAI               | `symfony/ai-open-ai-platform`        | `OPENAI_API_KEY`                                |
| OpenAI Responses API | `symfony/ai-open-responses-platform` | `OPENAI_API_KEY`                                |
| Azure OpenAI         | `symfony/ai-azure-platform`          | `AZURE_OPENAI_API_KEY`, `AZURE_OPENAI_BASEURL`  |
| Google Gemini        | `symfony/ai-gemini-platform`         | `GEMINI_API_KEY`                                |
| Google Vertex AI     | `symfony/ai-vertex-ai-platform`      | `GOOGLE_CLOUD_PROJECT`, `GOOGLE_CLOUD_LOCATION` |
| AWS Bedrock          | `symfony/ai-bedrock-platform`        | AWS credentials (env or instance role)          |
| DeepSeek             | `symfony/ai-deep-seek-platform`      | `DEEPSEEK_API_KEY`                              |
| Mistral AI           | `symfony/ai-mistral-platform`        | `MISTRAL_API_KEY`                               |
| Meta (Llama)         | `symfony/ai-meta-platform`           | `META_API_KEY`                                  |
| Ollama (local)       | `symfony/ai-ollama-platform`         | none                                            |

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
    # open_responses:
    #   api_key: '%env(OPENAI_API_KEY)%'
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
    # meta:
    #   api_key: '%env(META_API_KEY)%'
    # ollama:
    #   endpoint: 'http://localhost:11434'
```

## Model Options

The bundle exposes `max_output_tokens` directly at the top level (see
[Top-level](#top-level)) — prefer that key for capping per-call output, since
its default (`4096`) bypasses `symfony/ai`'s much smaller built-in default
(~1000) that would otherwise truncate `record_vulnerability` tool-call arguments
mid-finding.

Other provider-specific parameters (e.g. `temperature`) can still be passed
through the model name using the query-string syntax `symfony/ai-bundle`
supports:

```yaml
symfony_security_auditor:
    model: 'claude-opus-4-8?temperature=0.2'
```

`max_tokens` set this way overrides the bundle's `max_output_tokens` for that
role. `symfony/ai-bundle`'s own `ai.yaml` platform config additionally accepts
an expanded `{name, options}` mapping for a model — this bundle's `model` /
`attacker_model` / `reviewer_model` keys do not: they are plain strings, so only
the query-string form works here.

## Split-Model Setup

Using separate models per role lets you pair a large, high-accuracy model for
attack discovery with a faster or cheaper model for review — reducing cost and
latency without sacrificing thoroughness.

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
    attacker_model: 'claude-opus-4-8'   # deep reasoning for vuln discovery
    reviewer_model: 'claude-haiku-4-5-20251001'  # fast + cheap for false-positive filtering
```

The attacker agent receives all source files grouped into chunks of 10, sorted
by security priority (controllers first, then voters, entities, repositories,
forms, then everything else). The reviewer agent then evaluates each candidate
finding individually and decides whether to accept or escalate it.

## Standalone Configuration

When you run the [standalone binary](../README.md#standalone-tool-binary)
instead of the bundle, configuration is read from a single user-level file. On
Linux and macOS it follows the XDG Base Directory specification; on Windows it
uses the native app-data directories:

| Purpose                               | Linux / macOS                                                             | Windows                                          |
| ------------------------------------- | ------------------------------------------------------------------------- | ------------------------------------------------ |
| the configuration file                | `$XDG_CONFIG_HOME/symfony-security-auditor/config.yaml` (→ `~/.config/…`) | `%APPDATA%\symfony-security-auditor\config.yaml` |
| attacker/reviewer and advisory caches | `$XDG_CACHE_HOME/symfony-security-auditor` (→ `~/.cache/…`)               | `%LOCALAPPDATA%\symfony-security-auditor`        |
| the downloaded provider bridge(s)     | `$XDG_DATA_HOME/symfony-security-auditor` (→ `~/.local/share/…`)          | `%LOCALAPPDATA%\symfony-security-auditor`        |

> **Requirements & platform support.** Each release ships a self-contained
> native binary that bundles its own PHP runtime (nothing to install on the
> host) for **Linux** (x86-64, arm64), **macOS** (Intel, Apple Silicon), and
> **Windows** (x86-64) — install it with the script or download it from the
> release. `init` fetches the provider bridge with `composer`, and `--since`
> uses `git`, so those tools must be present on the host when you use those
> features (the audit itself needs only the binary).

Run `symfony-security-auditor init` to generate the file interactively and fetch
the provider bridge. The file is **rootless** — the same keys as the bundle
configuration above, without the `symfony_security_auditor:` wrapper — plus two
standalone-only top-level keys:

- **`platform:`** — handed verbatim to `symfony/ai`'s `ai.platform` config, so
  it takes the exact shape documented in
  [Platform Configuration](#platform-configuration).
- **`provider:`** — optional selector naming the active platform when several
  are declared; omit it when only one platform is configured.

```yaml
# ~/.config/symfony-security-auditor/config.yaml
provider: anthropic
platform:
    anthropic:
        api_key: '%env(ANTHROPIC_API_KEY)%'
model: claude-opus-4-8
# scan:, audit:, cache: are all accepted here too, unwrapped.
```

### Per-project overrides

A `.symfony-security-auditor.yaml` in the working directory (`$PWD`) is layered
**over** the user config, with the project values winning. This lets a
repository pin its own audit settings (chunking strategy, `fail_on`, excluded
paths, …) while the API credentials stay in the shared user config. The
effective precedence, highest first, is:

1. CLI options (`--fail-on`, `--format`, …)
2. The per-project `.symfony-security-auditor.yaml`
3. The user-level `config.yaml`
4. Built-in defaults

> Scalars and mappings deep-merge; a **list** key (e.g. `scan.included_paths`)
> set in both files is replaced wholesale by whichever file sets it last — the
> per-project file's list fully overrides the user config's list rather than
> merging element-wise.

### Switching providers

`%env(VAR)%` placeholders in the `platform:` block are resolved from the
environment, so secrets never live in the file. To switch providers, configure
several platforms and change `provider:` (run `init` again to fetch the other
bridge):

```yaml
provider: openai
platform:
    anthropic: { api_key: '%env(ANTHROPIC_API_KEY)%' }
    openai: { api_key: '%env(OPENAI_API_KEY)%' }
model: gpt-5.4
```

## CLI Reference

The bundle registers the `audit:run` console command, also reachable through the
shorter `audit` alias (`bin/console audit`), plus the `audit:diff` command for
comparing two previously generated reports. The standalone CLI exposes the same
commands.

```bash
bin/console audit:run [<project-path>] [options]
# `audit` is an equivalent alias:
bin/console audit [<project-path>] [options]
```

### Arguments

| Name           | Required | Default    | Description                                                    |
| -------------- | -------- | ---------- | -------------------------------------------------------------- |
| `project-path` | no       | `getcwd()` | Path to the Symfony project to audit. Defaults to current dir. |

### Options

| Option                | Short | Default    | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| --------------------- | ----- | ---------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `--format`            | `-f`  | `console`  | Output format: `console` (human-readable), `json`, `sarif`, `html` (self-contained, HTML-escaped report for sharing or archiving), `markdown` (GitHub-flavored report for a PR comment or `$GITHUB_STEP_SUMMARY`), `junit` (JUnit XML — one failed test case per finding, rendered by CI test-report panels such as GitLab merge-request widgets on every tier), or `github` (GitHub Actions workflow-command annotations — one `::error`/`::warning`/`::notice` line per finding, rendered inline on the PR's Files Changed view without a SARIF upload step) |
| `--output`            | `-o`  | none       | Write the rendered report to a file path, for any `--format`. Also works with `--dry-run`. Not recommended with `--format=github` — annotations must go to the workflow log for GitHub to render them; see the CI recipes below.                                                                                                                                                                                                                                                                                                                               |
| `--dry-run`           |       | `false`    | Estimate token usage and cost without invoking the LLM. Exits `0` with zero findings and a populated `cost` block. If a configured model (`model`, `attacker_model`, `reviewer_model`) has no pricing entry in the `PricingProviderInterface`, a warning is printed to stderr and that role's estimated cost shows `$0.00`. The estimate does not model provider prompt-cache discounts, so real runs with caching enabled typically come in under it.                                                                                                         |
| `--path`              | `-p`  | none       | Restrict the scan to a project subdirectory (relative to the root). Repeat to include several. Useful for monorepos.                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| `--show-scanned`      |       | `false`    | List the files that would be audited — after applying `included_paths` and any `--path` filters — grouped by type with a per-type and total count, then exit, without invoking the LLM. Use it to confirm your scan scope before paying for a run. Combine with `--dry-run` to print the file list first and the cost estimate after.                                                                                                                                                                                                                          |
| `--no-cache`          |       | `false`    | Bypass the filesystem caches — attacker chunks and reviewer verdicts — for this run (no reads, no writes). Use after upgrading the auditor or to force a fresh analysis.                                                                                                                                                                                                                                                                                                                                                                                       |
| `--since`             |       | none       | Diff mode: audit only files changed against the given git ref (e.g. `main`, `origin/main`, `abc1234`). Honors committed (`ref...HEAD`) and uncommitted working-tree changes. Designed for pull-request CI; the cache stays warm for unchanged files.                                                                                                                                                                                                                                                                                                           |
| `--baseline`          |       | none       | Path to a baseline file of accepted findings. Baselined findings skip the reviewer entirely (streamed as `[BASELINE-SKIPPED]` lines) and are excluded from the report and the exit code. With `--format=sarif`, a matching finding is instead kept and marked with a SARIF `suppressions` entry — see `audit.baseline` above. Overrides the `audit.baseline` config key. A missing file suppresses nothing.                                                                                                                                                    |
| `--fail-on`           |       | `critical` | Minimum aggregate risk level (`safe`, `low`, `medium`, `high`, `critical`) that makes the command exit `1`. Overrides the `audit.fail_on` config key for this run. Defaults to the configured value (`critical`) when omitted.                                                                                                                                                                                                                                                                                                                                 |
| `--generate-baseline` |       | none       | Run the audit, then write one baseline entry per current finding (`fingerprint`, `type`, `file`, `title`, `added_at`) to the given file and exit `0` without failing on findings. Use to accept the current findings so future runs only report new ones.                                                                                                                                                                                                                                                                                                      |

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

### Exit codes

| Code | Meaning                                                                                                                                                                                                                                                                                                                              |
| ---- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `0`  | Audit completed; aggregate risk level is below the `fail_on` threshold (default `critical` → SAFE, LOW, MEDIUM, or HIGH)                                                                                                                                                                                                             |
| `1`  | Aggregate risk level is at or above the `fail_on` threshold (default `critical`), the audit itself failed, or the path was invalid                                                                                                                                                                                                   |
| `2`  | The audit budget could not be honored: either it aborted mid-run because the configured token or cost budget was exceeded (partial report still emitted), or it never started because an unpriced model makes `audit.budget.max_cost_usd` unenforceable and the run was declined or non-interactive (no report emitted in that case) |

### `audit:diff` — comparing two reports

Compares two JSON reports produced by `audit:run --format=json` and classifies
every finding by its stable `fingerprint` (the same per-finding identity used by
baseline suppression): findings only in the later report are **New**, findings
only in the earlier report are **Fixed**, and findings in both are
**Persisting**. A report generated before the `fingerprint` key existed is still
accepted — the fingerprint is recomputed from `type`, `file`, and `title`.

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

Exit codes: `0` on a successful comparison (regardless of whether any findings
are new, fixed, or persisting), `1` if a report file is missing or is not valid
JSON.
