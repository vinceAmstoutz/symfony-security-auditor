# Configuration Reference

Full configuration reference for the `symfony-security-auditor` bundle. Covers
bundle registration, bundle-level configuration, platform wiring via
`symfony/ai`, model options, and the CLI command.

## Table of Contents

- [Bundle Registration](#bundle-registration)
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
- [CLI Reference](#cli-reference)

> See also: [Architecture](architecture.md) · [Extending](extending.md) ·
> [CI](ci.md) · [FAQ](faq.md) · [Troubleshooting](troubleshooting.md)

---

## Bundle Registration

Register both bundles in `config/bundles.php`. Symfony Flex does this
automatically via the recipe. `AiBundle` must appear first — it provides the
`PlatformInterface` service that this bundle references.

```php
// config/bundles.php
return [
    // ...
    Symfony\AI\AiBundle\AiBundle::class => ['all' => true],
    VinceAmstoutz\SymfonySecurityAuditor\SymfonySecurityAuditorBundle::class => ['dev' => true, 'test' => true],
];
```

---

## Bundle Configuration

Create `config/packages/symfony_security_auditor.yaml`. The bundle exposes the
following keys:

### Top-level

| Key                  | Type   | Default             | Description                                                                                                                                                                                                                                                                                                                                                                              |
| -------------------- | ------ | ------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `model`              | string | `'claude-opus-4-7'` | Model name used for both Attacker and Reviewer roles                                                                                                                                                                                                                                                                                                                                     |
| `attacker_model`     | string | `null`              | Override: dedicated model for the Attacker role                                                                                                                                                                                                                                                                                                                                          |
| `reviewer_model`     | string | `null`              | Override: dedicated model for the Reviewer role                                                                                                                                                                                                                                                                                                                                          |
| `provider_json_mode` | bool   | `false`             | Send `response_format: {type: json_object}` on every LLM call so the provider enforces JSON output natively. Honored by OpenAI / Mistral / Ollama; silently ignored by Anthropic (no equivalent knob). Default `false` because behaviour is provider-dependent — only enable when your provider supports it. The prompt contract (_"Return ONLY the JSON array"_) remains authoritative. |

`attacker_model` and `reviewer_model` fall back to `model` when not set. Model
names must be supported by the platform configured in `ai.yaml`.

### `scan.*` — file discovery

| Key                                         | Type        | Default                                              | Description                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| ------------------------------------------- | ----------- | ---------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `scan.included_paths`                       | `string[]`  | `['src', 'config', 'templates', 'public/index.php']` | Project-relative directories and files that define the scan surface — the **sole scoping knob**. Defaults match the Symfony Flex skeleton. Anything outside this list is silently skipped: `vendor/`, `node_modules/`, `var/`, `tests/`, `migrations/`, ad-hoc root scripts, `bin/`, `app/`, `lib/`, build artefacts, IDE folders, and any other top-level tree. Tighten or extend the list to match non-standard layouts (e.g. monorepos, `app/`). |
| `scan.respect_gitignore`                    | `bool`      | `true`                                               | When `true` (default), files matched by the project `.gitignore` are skipped. Set `false` for full-tree scans that include generated/cached artefacts (rare).                                                                                                                                                                                                                                                                                       |
| `scan.max_file_size_kb`                     | `int` (≥ 1) | `512`                                                | Skip files larger than this size, in kilobytes.                                                                                                                                                                                                                                                                                                                                                                                                     |
| `scan.secret_scrubbing.enabled`             | `bool`      | `true`                                               | Redact credential-shaped strings (AWS/GitHub/Stripe/Slack/Google API keys, JWTs, PEM private keys, env-style credential assignments) from file content before it reaches the LLM. Default `true` — credentials in committed sample configs or `.env.dist` files would otherwise be sent verbatim to the LLM provider.                                                                                                                               |
| `scan.secret_scrubbing.additional_patterns` | `string[]`  | `[]`                                                 | Extra PCRE patterns merged with the defaults. Use to redact project-specific tokens (e.g. internal API key shapes).                                                                                                                                                                                                                                                                                                                                 |
| `scan.custom_risk_patterns`                 | `map`       | `{}`                                                 | Project-specific risk markers merged into the deterministic pre-scanner, keyed by file-type bucket (`controller`, `voter`, `entity`, `repository`, `form`, `template`, `config`, `php`, `authenticator`, `messenger_handler`, `webhook_consumer`, `event_subscriber`, `normalizer`, `scheduler`). Each entry is `<label>: { regex: <PCRE>, description: <text> }`. Surface team idioms the built-ins do not know about.                             |

### `audit.*` — orchestrator knobs

| Key                                           | Type                                                | Default   | Description                                                                                                                                                                                                                                                                                                                                                                                      |
| --------------------------------------------- | --------------------------------------------------- | --------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `audit.max_iterations`                        | `int` (≥ 1)                                         | `3`       | Maximum number of attacker/reviewer iterations per audit. Loop stops earlier when no new findings emerge.                                                                                                                                                                                                                                                                                        |
| `audit.min_confidence`                        | `float` 0–1                                         | `0.6`     | Minimum attacker self-reported confidence required to forward a finding to the reviewer. Tune for precision vs. recall: CI gate `0.8`, discovery scan `0.3`, default audit `0.6`.                                                                                                                                                                                                                |
| `audit.reviewer_batch_size`                   | `int` (≥ 1)                                         | `1`       | Number of findings reviewed per LLM call. `1` = one-by-one (highest precision, highest latency). Larger values reduce cost/latency at risk of cross-talk between findings in the prompt. Try `5` for cost-sensitive runs.                                                                                                                                                                        |
| `audit.tools_enabled`                         | `bool`                                              | `true`    | Give the attacker access to tools (`read_file`, `grep`, `list_files`, `lookup_advisory`) for cross-file investigation. Default `true` — without tools, `lookup_advisory` is dead weight and the attacker is blind across files. Costs more LLM round-trips per chunk; mostly offset by `cache.prompt_caching` on Anthropic. Set `false` only if you need the cheapest possible single-file scan. |
| `audit.structured_collection`                 | `bool`                                              | `false`   | When `true`, the attacker emits findings by calling a schema-enforced `record_vulnerability` tool — one call per finding — instead of returning a JSON array. The provider validates each call against the tool's input schema, so malformed shapes (bare strings like `"dev"`/`"test"`, wrapper objects like `{"vulnerabilities": [...]}`) become structurally impossible. Provider-agnostic: works on Anthropic, OpenAI, Mistral, and Ollama tool-capable models. Default `false` — opt-in. Pairs well with `cache.prompt_caching` on Anthropic.                                                                                                                                                                                                                                                                                                                                                |
| `audit.max_tool_iterations`                   | `int` (≥ 1)                                         | `8`       | Maximum tool-call rounds per chunk before the attacker is forced to commit to a final answer. Bounds runaway tool use.                                                                                                                                                                                                                                                                           |
| `audit.reviewer_tools_enabled`                | `bool`                                              | `false`   | Give the reviewer the same tool registry as the attacker so it can verify cross-file mitigations (parent-class guards, `access_control` rules, upstream sanitizers) instead of guessing from the file context alone. Default `false` — adds round-trips per finding; opt-in for high-precision audits.                                                                                           |
| `audit.reviewer_max_tool_iterations`          | `int` (≥ 1)                                         | `4`       | Maximum tool-call rounds per finding for the reviewer (lower than the attacker's: verification, not exploration).                                                                                                                                                                                                                                                                                |
| `audit.reviewer_max_concurrent`               | `int` (≥ 1)                                         | `1`       | Maximum reviewer LLM calls resolved concurrently when reviewing one finding per call (`reviewer_batch_size <= 1`) with reviewer tools off. The reviewer phase is often half the wall-clock; `4`–`8` (within provider rate limits) cuts it proportionally. Ignored when reviewer tools are on or the platform has no async transport.                                                             |
| `audit.static_prescan.enabled`                | `bool`                                              | `true`    | Run the deterministic, zero-token risk-marker pre-scan and inject markers into the attacker prompt so it focuses on concrete locations. Pure detection-quality win.                                                                                                                                                                                                                              |
| `audit.static_prescan.lean_mode`              | `bool`                                              | `false`   | Drop files with zero pre-scan markers before the LLM sees them. Slashes token spend (often 40–70%) at the cost of patterns the regex pre-scanner does not know about. Opt-in.                                                                                                                                                                                                                    |
| `audit.chunking.strategy`                     | `feature` \| `type`                                 | `feature` | How files are grouped into LLM calls. `feature` colocates a controller with its entity/repository/form/voter/templates so the LLM follows cross-file flow; `type` uses the legacy attack-surface priority window.                                                                                                                                                                                |
| `audit.code_slicing.enabled`                  | `bool`                                              | `false`   | Trim large PHP files to security-relevant lines (structure, signatures, token-bearing lines) before the LLM, eliding the rest one-for-one so line numbers stay accurate. Opt-in token saver.                                                                                                                                                                                                     |
| `audit.code_slicing.min_lines_before_slicing` | `int` (≥ 10)                                        | `80`      | Files shorter than this are sent unsliced (the saving is not worth the lost context).                                                                                                                                                                                                                                                                                                            |
| `audit.poc_synthesis.enabled`                 | `bool`                                              | `false`   | After the audit, generate a concrete copy-pasteable PoC (curl, console, payload) for validated findings ≥ the severity floor, exposed as the `synthesized_poc` report field. Spends extra reviewer-model tokens per finding.                                                                                                                                                                     |
| `audit.poc_synthesis.severity_floor`          | `critical` \| `high` \| `medium` \| `low` \| `info` | `high`    | Minimum severity that triggers PoC synthesis.                                                                                                                                                                                                                                                                                                                                                    |
| `audit.escalation.enabled`                    | `bool`                                              | `false`   | Two-pass attacker: a cheap-model sweep runs first; the expensive model only re-analyses files the sweep flagged. Cuts attacker token spend ~3–5× on inert codebases. Requires `escalation.cheap_model`.                                                                                                                                                                                          |
| `audit.escalation.cheap_model`                | `string` or `null`                                  | `null`    | Provider model id for the cheap first pass (e.g. `claude-haiku-4-5-20251001`). Falls back to the reviewer model when `null`.                                                                                                                                                                                                                                                                     |
| `audit.budget.max_tokens`                     | `int` (≥ 1) or `null`                               | `null`    | Maximum total tokens (input + output, across attacker + reviewer) before the audit aborts cleanly with exit code `2`. `null` = unlimited.                                                                                                                                                                                                                                                        |
| `audit.budget.max_cost_usd`                   | `float` (> 0) or `null`                             | `null`    | Maximum estimated cost (USD) before the audit aborts cleanly with exit code `2`. Cost is computed via the configured `PricingProviderInterface`. `null` = unlimited.                                                                                                                                                                                                                             |
| `audit.retry.max_attempts`                    | `int` (≥ 1)                                         | `3`       | Total attempts per LLM call, including the first try. `1` disables retries. Transient failures (provider 429/5xx, network blips) are retried with jittered exponential backoff; non-transient failures (auth, validation) fail fast.                                                                                                                                                             |
| `audit.retry.initial_delay_ms`                | `int` (≥ 0)                                         | `500`     | Base delay (milliseconds) before the first retry. Subsequent retries multiply by `backoff_multiplier`.                                                                                                                                                                                                                                                                                           |
| `audit.retry.backoff_multiplier`              | `float` (≥ 1.0)                                     | `2.0`     | Exponential growth factor between retries. With initial 500ms and multiplier 2.0, retries wait ~500, ~1000, ~2000 ms.                                                                                                                                                                                                                                                                            |
| `audit.retry.jitter_ratio`                    | `float` 0–1                                         | `0.2`     | Jitter applied to each computed delay, as a fraction in `[0.0, 1.0]`. `0.2` means each delay varies within ±20% of the base.                                                                                                                                                                                                                                                                     |

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

| Key                    | Type     | Default                                                | Description                                                                                                                                                                                                                                                                   |
| ---------------------- | -------- | ------------------------------------------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `cache.enabled`        | `bool`   | `true`                                                 | Enable filesystem cache for attacker chunks keyed by content hash. Skips the LLM call entirely when an identical chunk has been analyzed before. Default `true` — large cost saver on repeated runs (CI, PR scans). Set `false` for one-shot audits or to debug LLM behavior. |
| `cache.dir`            | `string` | `%kernel.cache_dir%/symfony_security_auditor/attacker` | Cache storage path. Created on first write.                                                                                                                                                                                                                                   |
| `cache.prompt_caching` | `bool`   | `true`                                                 | Opt into provider-side prompt caching by setting `cache_control: ephemeral` on every LLM call. Default `true` — Anthropic honors it for ~90% input-token discount; other providers silently ignore the flag (zero cost to leave on).                                          |

### Simple mode — one model for both roles

```yaml
# config/packages/symfony_security_auditor.yaml
symfony_security_auditor:
    model: 'claude-opus-4-7'
```

### Split mode — separate models per role

```yaml
# config/packages/symfony_security_auditor.yaml
symfony_security_auditor:
    attacker_model: 'claude-opus-4-7'   # powerful model for discovery
    reviewer_model: 'claude-haiku-4-5-20251001'  # faster model for validation
```

### Full configuration example

```yaml
# config/packages/symfony_security_auditor.yaml
symfony_security_auditor:
    attacker_model: 'claude-opus-4-7'
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
        prompt_caching: true
```

---

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
  `cache.prompt_caching: true` to amortize the additional round-trips.
- **Overriding the source.** Need a custom feed (Snyk, internal CVE list, …)?
  Implement `Audit\Domain\Port\AdvisoryDatabaseInterface` in your project and
  override the alias in `config/services.yaml`:

```yaml
# config/services.yaml
services:
    VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\AdvisoryDatabaseInterface:
        alias: App\Security\MyCustomAdvisoryDatabase
```

---

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
    #   host_url: 'http://localhost:11434'
```

---

## Model Options

Provider-specific parameters such as `max_tokens` and `temperature` are passed
via the model name. Two syntaxes are supported in
`symfony_security_auditor.yaml`.

### Query-string syntax

```yaml
symfony_security_auditor:
    model: 'claude-opus-4-7?max_tokens=4096&temperature=0.2'
```

### Expanded syntax

```yaml
symfony_security_auditor:
    model:
        name: 'claude-opus-4-7'
        options:
            max_tokens: 4096
            temperature: 0.2
```

Both forms are equivalent. Use expanded syntax when setting many options or
preferring readability.

---

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
    attacker_model: 'claude-opus-4-7'   # deep reasoning for vuln discovery
    reviewer_model: 'claude-haiku-4-5-20251001'  # fast + cheap for false-positive filtering
```

The attacker agent receives all source files grouped into chunks of 10, sorted
by security priority (controllers first, then voters, entities, repositories,
forms, then everything else). The reviewer agent then evaluates each candidate
finding individually and decides whether to accept or escalate it.

---

## CLI Reference

The bundle registers a single console command.

```bash
bin/console audit:run <project-path> [options]
```

### Arguments

| Name           | Required | Default    | Description                                                    |
| -------------- | -------- | ---------- | -------------------------------------------------------------- |
| `project-path` | no       | `getcwd()` | Path to the Symfony project to audit. Defaults to current dir. |

### Options

| Option       | Short | Default   | Description                                                                                                                                                                                                                                          |
| ------------ | ----- | --------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `--format`   | `-f`  | `console` | Output format: `console` (human-readable), `json`, or `sarif`                                                                                                                                                                                        |
| `--output`   | `-o`  | none      | Write the JSON or SARIF report to a file path                                                                                                                                                                                                        |
| `--dry-run`  |       | `false`   | Estimate token usage and cost without invoking the LLM. Exits `0` with zero findings and a populated `cost` block.                                                                                                                                   |
| `--path`     | `-p`  | none      | Restrict the scan to a project subdirectory (relative to the root). Repeat to include several. Useful for monorepos.                                                                                                                                 |
| `--no-cache` |       | `false`   | Bypass the attacker cache for this run (no reads, no writes). Use after upgrading the auditor or to force a fresh analysis.                                                                                                                          |
| `--since`    |       | none      | Diff mode: audit only files changed against the given git ref (e.g. `main`, `origin/main`, `abc1234`). Honors committed (`ref...HEAD`) and uncommitted working-tree changes. Designed for pull-request CI; the cache stays warm for unchanged files. |

### Examples

```bash
bin/console audit:run /path/to/symfony/project
```

```bash
bin/console audit:run /path/to/project --format=json --output=report.json
```

```bash
bin/console audit:run . --format=sarif --output=report.sarif
```

```bash
bin/console audit:run . --dry-run --format=json
```

### Exit codes

| Code | Meaning                                                                                               |
| ---- | ----------------------------------------------------------------------------------------------------- |
| `0`  | Audit completed; risk level is SAFE, LOW, MEDIUM, or HIGH                                             |
| `1`  | Risk level is CRITICAL, or the project path is invalid                                                |
| `2`  | Audit aborted because the configured token or cost budget was exceeded (partial report still emitted) |
