# Configuration Reference

Full configuration reference for the `symfony-security-auditor` bundle. Covers bundle registration, bundle-level configuration, platform wiring via `symfony/ai`, model options and the CLI command.

## Table of Contents

- [Bundle Registration](#bundle-registration)
- [Manual Setup (without Flex)](#manual-setup-without-flex)
- [Bundle Configuration](#bundle-configuration)
  - [Top-level](#top-level)
  - [`scan.*`: file discovery](#scan-file-discovery)
  - [`audit.*`: orchestrator knobs](#audit-orchestrator-knobs)
  - [`audit.rate_limit.*`: proactive throttling](#auditrate_limit-proactive-throttling)
  - [`cache.*`: caching layers](#cache-caching-layers)
  - [`privacy.*`: data egress](#privacy-data-egress)
  - [Full example](#full-configuration-example)
- [Advisory Source (`lookup_advisory`)](#advisory-source-lookup_advisory-tool)
- [Platform Configuration](#platform-configuration)
- [Model Options](#model-options)
- [Split-Model Setup](#split-model-setup)
- [Standalone Configuration](#standalone-configuration)
- [Providing the API key](#providing-the-api-key)
- [CLI Reference](#cli-reference)
  - [Output Formats Reference](#output-formats-reference)
  - [`audit:diff`](#auditdiff-comparing-two-reports)
  - [`audit:trend`](#audittrend-tracking-findings-across-reports)
  - [`audit:baseline`](#auditbaseline-maintaining-the-accepted-finding-baseline)
  - [`mcp:serve`](#mcpserve-model-context-protocol-server)
  - [`init`](#init-generating-the-standalone-configuration)
  - [`self-update`](#self-update-updating-the-standalone-binary)
  - [`doctor`](#doctor-preflight-environment-check)
  - [Shell completion](#shell-completion)
  - [Update notifications](#update-notifications)

> See also: [Architecture](architecture.md) · [Extending](extending.md) · [CI](ci.md) · [FAQ](faq.md) · [Troubleshooting](troubleshooting.md)

## Bundle Registration

Register both bundles in `config/bundles.php`. Symfony Flex does this automatically via the recipe. `AiBundle` must be installed and registered alongside this bundle (it provides the `PlatformInterface` service this bundle references), but array order does not matter: the reference is a lazy `nullOnInvalid()` service resolved by the container compiler after every bundle's `loadExtension()` has already run.

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

1. Register both bundles in `config/bundles.php` (see [Bundle Registration](#bundle-registration)).
2. Create `config/packages/symfony_security_auditor.yaml` (see [Bundle Configuration](#bundle-configuration)) or copy the [recipe's template](https://github.com/symfony/recipes-contrib/blob/main/vinceamstoutz/symfony-security-auditor/1.0/config/packages/symfony_security_auditor.yaml).

## Bundle Configuration

Create `config/packages/symfony_security_auditor.yaml`. The bundle exposes the following keys:

> **Editor autocompletion.** A JSON Schema for this configuration ships at [`resources/schema.json`](../resources/schema.json). Editors pick it up from a `# $schema:` modeline on the first line of your config file. Both the [YAML Language Server](https://github.com/redhat-developer/yaml-language-server) (VS Code, Neovim, …) and PhpStorm/IntelliJ understand this form:
>
> ```yaml
> # $schema: https://raw.githubusercontent.com/vinceamstoutz/symfony-security-auditor/main/resources/schema.json
>
> symfony_security_auditor:
>     model: "claude-opus-5-5"
> ```
>
> This gives key completion, type checking and inline docs as you edit. The example files under [`examples/configs/`](../examples/configs/) include the modeline. The URL tracks the `main` branch so it always resolves to the current schema: no per-release bump needed.
>
> **Environment variables.** A `%env(VAR)%` placeholder is accepted on the settings that stay text, such as `model`, `attacker_model`, `reviewer_model`, `audit.escalation.cheap_model` and `cache.dir`. A choice kept as text (`audit.format`, `audit.chunking.strategy`, `audit.since_closure`, `audit.poc_synthesis.severity_floor`, `audit.fix_synthesis.severity_floor` and an entry of `audit.excluded_types` or `audit.included_types`) takes one only when its variable declares a default among the choices (`parameters: { 'env(SSA_FORMAT)': 'console' }`): a Symfony kernel checks the placeholder against the choices with that default (or with an empty string when there is none) and stops with `The value "" is not allowed for path …`. A number, a switch, a list or a choice read as a PHP enum (`audit.budget.max_cost_usd`, `audit.min_score`, `audit.tools_enabled`, `cache.enabled`, `privacy.offline_only`, `audit.fail_on`, …) is read while the container is built, before the variable has a value, so a placeholder there stops the build with a configuration error that names the key: set a literal value.

### Top-level

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `profile` | string | `'balanced'` | One-knob preset: `fast`, `balanced` or `thorough`. It only fills the keys you leave unset. `fast`: one attacker iteration, lean pre-scan, code slicing, four concurrent attacker and reviewer calls; `balanced`: the defaults; `thorough`: balanced plus PoC synthesis. See [Cost & Performance](cost-and-performance.md). |
| `model` | string | `'claude-opus-5-5'` | Model used by both the attacker and the reviewer. |
| `attacker_model` | string | `null` | Attacker model; `model` when unset. |
| `reviewer_model` | string | `null` | Reviewer model; `model` when unset. |
| `max_output_tokens` | `int` (≥ 1) | `4096` for a Claude model | Output token cap per LLM call. A Claude model gets it, `4096` when unset, as `symfony/ai`'s `max_output_tokens` on a platform whose bridge translates it (`anthropic`, `bedrock`, `vertexai`, `gemini`, `mistral`, `openai`, the generic-bridge gateways, …) and as `max_tokens` on any other. _Since 1.23_, another model gets it only when you set it (this key or the role's own) on a platform whose bridge translates it: its cap also counts its reasoning tokens, so a default one could cut a thinking model's answer short. _Since 1.23_ a tool call the cap cuts off is asked again with twice the cap, once per tool conversation, which keeps the raised cap for its later rounds; when the provider refuses the raised cap, the call ends as the answer the cap cut off. |
| `attacker_max_output_tokens` | `int` (≥ 1) | `null` | Attacker output token cap; `max_output_tokens` when unset. |
| `reviewer_max_output_tokens` | `int` (≥ 1) | `null` | Reviewer output token cap; `max_output_tokens` when unset. |
| `provider_json_mode` | bool | `false` | Ask a gateway serving a Claude model (`openrouter`, `generic`, …) to enforce JSON output with `response_format: {type: json_object}`. Not sent on `anthropic` and `bedrock`; no effect on other models. |
| `cli_agent.platform` | `string` \| `null` | `null` | _Since 1.23._ Run the audit on a subscription through a CLI installed on the machine: `claudecode` (Claude, through `claude`) or `codex` (ChatGPT, through `codex`). The application's own `symfony/ai` platform is left alone. Needs `symfony/ai-claude-code-platform` or `symfony/ai-codex-platform`; see [Running on a subscription](#running-on-a-subscription). |
| `cli_agent.effort` | `string` \| `null` | `null` | _Since 1.23._ The effort the CLI runs at: `low`, `medium`, `high`, `xhigh` or `max`, passed to Claude Code as `--effort` and to Codex as `model_reasoning_effort`. `null` keeps the CLI's own. |
| `cli_agent.cli_binary` | `string` \| `null` | `null` | _Since 1.23._ Path to the CLI when it is not on the `PATH`. |

Model names must be ones the platform configured in `ai.yaml` serves. When you raise `max_output_tokens`, raise `audit.rate_limit.output_tokens_per_minute` too, or that bucket throttles first.

### `scan.*`: file discovery

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `scan.included_paths` | `string[]` | `['src', 'config', 'templates', 'public/index.php', '.env', '.env.local', '.env.dev', '.env.test', '.env.prod', '.env.dist']` | Directories and files scanned when no `--path` is given; a `--path` replaces the list for that run (_since 1.22_). The default is the Symfony Flex skeleton plus the root dotenv files: `vendor/`, `tests/`, `migrations/` and anything unlisted are skipped. So are dot files inside a listed directory (see `scan.include_dotfiles`). Adapt it to layouts such as `app/` or a monorepo. An entry outside the project root is ignored. |
| `scan.respect_gitignore` | `bool` | `true` | Skip the files the project's `.gitignore` matches, tracked or not (see `scan.include_tracked_ignored`). Set `false` to scan generated files too. |
| `scan.include_tracked_ignored` | `bool` | `false` | _Since 1.22._ With `scan.respect_gitignore`, still audit a file git tracks although a `.gitignore` pattern matches it, so a pull request cannot hide a file by ignoring it. Runs `git ls-files`, so it needs `git`. |
| `scan.include_dotfiles` | `bool` | `false` | _Since 1.22._ Also scan the dot files and dot directories inside the listed directories (`.helpers.php`, `.row.html.twig`). Version-control directories always stay out. |
| `scan.max_file_size_kb` | `int` (≥ 1) | `512` | Skip files larger than this, in kilobytes. _Since 1.22_ the report lists them as `skipped` in its `coverage`, with unreadable files and symlinks, without marking the run incomplete. |
| `scan.import_sarif` | `string[]` | `[]` | SARIF 2.1.0 reports from other SAST tools (Psalm, PHPStan, Progpilot, Semgrep, …) whose results, taint paths included, become risk markers for the attacker. Relative paths resolve against the project root; results outside the scan surface are dropped. A missing, malformed or over-32 MiB file stops the audit. |
| `scan.secret_scrubbing.enabled` | `bool` | `true` | Redact credentials from file content before it reaches the LLM: API keys and tokens (AWS, GitHub, Stripe, Slack, Google), JWTs, private keys, Symfony secrets-vault keys, env-style assignments, credentials passed in code (PDO, LDAP, Redis, HttpClient, `Authorization` headers, …) and URLs with embedded credentials. A scrubbed file still parses. A file the scrubber cannot evaluate is withheld from the LLM and reported as not analyzed (_since 1.21_). |
| `scan.secret_scrubbing.additional_patterns` | `string[]` | `[]` | Extra PCRE patterns merged with the defaults. Use to redact project-specific tokens (e.g. internal API key shapes). |
| `scan.custom_risk_patterns` | `map` | `{}` | Your own pre-scan risk markers, keyed by file type (`controller`, `api_resource`, `live_component`, `voter`, `entity`, `repository`, `form`, `template`, `twig_extension`, `config`, `php`, `authenticator`, `use_case` (_since 1.23_), `messenger_handler`, `webhook_consumer`, `event_subscriber`, `normalizer`, `scheduler`); each entry is `<label>: { regex: <PCRE>, description: <text> }`. An invalid regex stops the audit at startup. A key naming no file type is deprecated _since 1.22_ and will be refused in 2.0. |

### `audit.*`: orchestrator knobs

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `audit.max_iterations` | `int` (≥ 1) | profile | Maximum attacker/reviewer iterations (balanced/thorough: `3`, fast: `1`); the loop stops earlier when an iteration finds nothing new. |
| `audit.min_confidence` | `float` 0-1 | `0.6` | Minimum attacker confidence for a finding to reach the reviewer. Higher favors precision (`0.8` for a CI gate), lower favors recall (`0.3` for discovery). |
| `audit.reviewer_batch_size` | `int` (≥ 1) | `1` | Findings reviewed per LLM call. `1` is the most precise; larger values (try `5`) cut cost and latency. Cached verdicts are served first either way. |
| `audit.report_static_findings` | `bool` | `false` | _Since 1.23._ Also report every credential the secret scrubber redacted and every pre-scan match, up to 20 matches of one pattern per file, as a finding on its line, validated or rejected by the reviewer like the attacker's. An attacker finding of the same type on that line is reviewed in its place. The configuration `init` writes turns it on; see [Cost & Performance](cost-and-performance.md#speed--cost-levers) for what the review costs. |
| `audit.tools_enabled` | `bool` | `true` | Let the attacker investigate across files with `read_file`, `grep`, `list_files` and `lookup_advisory`. Costs extra round-trips, mostly offset by prompt caching; set `false` only for the cheapest single-file scan. |
| `audit.tools_scope` | `audited` \| `scanned` | `audited` | _Since 1.22._ Which files the file tools may open. `audited` limits them to the files the run audits (the narrowed set on a `--since`, `--path` or escalated run); `scanned` opens every scanned file, so the attacker can follow a changed controller into unchanged code, at the price of sending those files to the provider. User config only in the standalone binary. |
| `audit.structured_collection` | `bool` | `true` | The attacker records each finding through a schema-enforced `record_vulnerability` tool call, so its answer cannot be malformed. Set `false` to fall back to a JSON array, for models without tool use. |
| `audit.reviewer_structured_collection` | `bool` | `true` | The reviewer records each verdict through a schema-enforced `record_review` tool call. `reviewer_tools_enabled: true` keeps the JSON path. Set `false` for models without tool use. |
| `audit.stable_system_prompt` | `bool` | `true` | Send the attacker's full skill set with every chunk, so the system prompt is identical across chunks and provider prompt caching (Anthropic, OpenAI, Gemini, DeepSeek) reads it after the first call. Set `false` for a smaller prompt on a provider without prompt caching. Changing it refreshes the attacker cache. |
| `audit.max_tool_iterations` | `int` (≥ 1) | `8` | Maximum tool-call rounds per chunk. _Since 1.22_ the model is told when it reaches its last round, so it records what it found instead of failing; a chunk that ends there with no finding is not cached, so the next run looks again. Raise it to let the model read more, at the cost of more rounds. |
| `audit.reviewer_tools_enabled` | `bool` | `false` | Give the reviewer the attacker's tools to check cross-file mitigations (parent-class guards, `access_control` rules, upstream sanitizers). Adds round-trips per finding; opt in for high-precision audits. |
| `audit.reviewer_max_tool_iterations` | `int` (≥ 1) | `4` | Maximum tool-call rounds per finding for the reviewer. A verdict given at the limit after reading files is applied but not cached, so the next run reviews the finding again. |
| `audit.baseline` | `string` \| `null` | `null` | Path to a baseline of accepted findings: they are dropped before the reviewer runs and left out of the report and the exit code (SARIF keeps them, marked suppressed). Write one with `--generate-baseline`; a `reason` added to an entry is also given to the reviewer as false-positive feedback. `--baseline` overrides this key. A relative path in a project's `.symfony-security-auditor.yaml` is read from that file's folder. See [`audit:baseline`](#auditbaseline-maintaining-the-accepted-finding-baseline). |
| `audit.triage_memory` | `bool` | `false` | Remember each finding the reviewer rejects with a reason, per project under `<cache.dir>/triage-memory/` (up to 500 entries), to give those reasons back to the reviewer on later runs as a baseline `reason` is. Opt-in: it changes the reviewer prompt and writes to disk on every run. |
| `audit.fail_on` | `safe` \| `low` \| `medium` \| `high` \| `critical` | `critical` | Lowest aggregate risk level that makes `audit:run` exit `1`. `high` is recommended for CI; `safe` fails every completed audit. `--fail-on` overrides it. **Planned to default to `high` in the next major**, so pin it. |
| `audit.min_score` | `int` (0-100) \| `null` | `null` | _Since 1.22._ Minimum [normalized score](#normalized-score-and-grade): below it `audit:run` exits `1`, whatever `audit.fail_on` says. `null` gates on the risk level alone. `--min-score` overrides it. |
| `audit.fail_on_incomplete` | `bool` | `false` | _Since 1.22._ Exit `3` when a file could not be fully analyzed, so a partial report cannot pass CI; otherwise only a warning is printed. `--fail-on-incomplete` and `--no-fail-on-incomplete` override it. |
| `audit.format` | one of the `--format` values | `console` | _Since 1.22._ Report format when `--format` is not given. |
| `audit.output` | `string` \| `null` | `null` | _Since 1.22._ File the report is written to when `--output` is not given; `null` or an empty value prints it; `--no-output` prints it for one run. `--dry-run` never writes here. User config only in the standalone binary. |
| `audit.report_path_prefix` | `string` \| `null` | `null` | _Since 1.22._ Folder the project lives in, relative to the repository root (`backend`). It goes before every path of the SARIF and `github` formats, which GitHub resolves from the repository root, so alerts land on the right file in a monorepo. Other formats, the baseline and fingerprints keep project-relative paths. |
| `audit.since_closure` | `none` \| `direct` | profile | On a `--since` run, `direct` also audits the controllers a changed voter guards, so a voter edit that weakens an unchanged controller is caught; `none` audits only the changed files (balanced/fast: `none`, thorough: `direct`). |
| `audit.excluded_types` | `string[]` (VulnerabilityType values) | `[]` | Vulnerability types left out of the report and the exit code, to mute a noisy class such as `missing_rate_limiting`. Wins over `included_types`. `twig_injection` and `sensitive_data_exposure` also mute `xss` (_since 1.22_). |
| `audit.included_types` | `string[]` (VulnerabilityType values) | `[]` | When non-empty, only these vulnerability types are reported and gated on. `twig_injection` and `sensitive_data_exposure` also keep `xss` (_since 1.22_). |
| `audit.custom_skills` | `map` | `{}` | Your own attacker instructions, keyed by skill name: `file_type` (a file-type bucket, as in `scan.custom_risk_patterns`), `instructions` (what to hunt and what not to flag) and an optional `priority` (default `500`). Added to the prompt whenever a chunk holds a file of that type; editing one re-runs the affected chunks. |
| `audit.reviewer_max_concurrent` | `int` (≥ 1) | profile | Reviewer calls run at once when findings are reviewed one per call or, for static findings, file by file (balanced/thorough: `1`, fast: `4`). `4`-`8`, within your rate limits, shortens the review phase accordingly. Ignored with reviewer tools on or on a platform without an async transport. |
| `audit.attacker_max_concurrent` | `int` (≥ 1) | profile | Attacker chunks analyzed at once (balanced/thorough: `1`, fast: `4`). `4`-`8`, within your rate limits, shortens the longest phase accordingly. Needs `structured_collection` and a platform with an async transport. |
| `audit.static_prescan.enabled` | `bool` | `true` | Run the zero-token regex pre-scan and show its risk markers to the attacker, so it focuses on concrete locations. |
| `audit.static_prescan.lean_mode` | `bool` | profile | Skip files with no pre-scan marker (balanced/thorough: `false`, fast: `true`). Often cuts tokens by 40-70%, at the cost of what the regexes do not know. |
| `audit.chunking.strategy` | `feature` \| `type` | `feature` | How files are grouped into LLM calls. `feature` colocates a controller with its entity/repository/form/voter/templates so the LLM follows cross-file flow; `type` uses the legacy attack-surface priority window. |
| `audit.code_slicing.enabled` | `bool` | profile | Trim large PHP files to their security-relevant lines before the LLM, keeping line numbers and every flagged line (balanced/thorough: `false`, fast: `true`). |
| `audit.code_slicing.min_lines_before_slicing` | `int` (≥ 10) | `80` | Files shorter than this are sent unsliced (the saving is not worth the lost context). |
| `audit.poc_synthesis.enabled` | `bool` | profile | After the audit, write a reproduction (curl, console, payload) for each validated finding at or above the severity floor, in the `synthesized_poc` field (thorough: `true`). Costs reviewer-model tokens per finding. |
| `audit.poc_synthesis.severity_floor` | `critical` \| `high` \| `medium` \| `low` \| `info` | `high` | Minimum severity that triggers PoC synthesis. |
| `audit.fix_synthesis.enabled` | `bool` | `false` | After the audit, write a minimal unified-diff patch for each validated finding at or above the severity floor, in the `suggested_fix` field: shown by the human formats, carried as SARIF `fixes` and `github-comment` suggestions (_since 1.23_). No profile turns it on. Costs reviewer-model tokens per finding. |
| `audit.fix_synthesis.severity_floor` | `critical` \| `high` \| `medium` \| `low` \| `info` | `high` | Minimum severity that triggers fix synthesis. |
| `audit.escalation.enabled` | `bool` | `false` | Two-pass attacker: a cheap model sweeps every file and the attacker model re-analyzes only the files it flagged. Cuts attacker spend 3-5× on mostly inert code. |
| `audit.escalation.cheap_model` | `string` or `null` | `null` | Model of the cheap pass (e.g. `claude-haiku-5-5`); the reviewer model when `null`. `audit:run` warns when it is the attacker model, which saves nothing. |
| `audit.budget.max_tokens` | `int` (≥ 1) or `null` | `null` | Total tokens (input, output and cache reads and writes, both agents) after which the audit stops with exit code `2`. `null` is unlimited. |
| `audit.budget.max_cost_usd` | `float` (≥ 0.01) or `null` | `null` | Estimated cost in USD after which the audit stops with exit code `2`. `null` is unlimited. |
| `audit.retry.max_attempts` | `int` (≥ 1) | `3` | Attempts per LLM call, the first included; `1` disables retries. Transient failures (HTTP 408, 425, 429, 5xx, network errors) are retried with jittered exponential backoff; any other fails at once. |
| `audit.retry.initial_delay_ms` | `int` (≥ 0) | `500` | Base delay (milliseconds) before the first retry. Subsequent retries multiply by `backoff_multiplier`. |
| `audit.retry.backoff_multiplier` | `float` (≥ 1.0) | `2.0` | Exponential growth factor between retries. With initial 500ms and multiplier 2.0, retries wait ~500, ~1000, ~2000 ms. |
| `audit.retry.jitter_ratio` | `float` 0-1 | `0.2` | Jitter applied to each computed delay, as a fraction in `[0.0, 1.0]`. `0.2` means each delay varies within ±20% of the base. |

### `audit.rate_limit.*`: proactive throttling

A token-bucket limiter in front of every LLM call. Set the limits of your provider tier so runs stay inside quota; when all three are `null` (default) only the reactive `Retry-After`-aware retry applies.

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `audit.rate_limit.requests_per_minute` | `int` (≥ 1) or null | `null` | Maximum LLM requests per minute. `null` disables this dimension. |
| `audit.rate_limit.input_tokens_per_minute` | `int` (≥ 1) or null | `null` | Maximum input tokens per minute, counted as the provider meters them. A chunk over the cap is split in two; a single file still over it is recorded as errored. `null` disables this dimension. |
| `audit.rate_limit.output_tokens_per_minute` | `int` (≥ 1) or null | `null` | Maximum output tokens per minute, counted from each call's actual usage. `null` disables this dimension. |

Limits are per process: parallel runs sharing one API key (a CI matrix) still compete for the provider's quota.

### `cache.*`: caching layers

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `cache.enabled` | `bool` | `true` | Cache attacker answers and reviewer verdicts by content hash, so an unchanged chunk or finding costs no LLM call on the next run, in every review mode and iteration. A large saving on repeated CI runs; set `false` for a one-shot audit or to debug the model. |
| `cache.dir` | `string` | `%kernel.cache_dir%/symfony_security_auditor/attacker` | Cache location, created owner-only on first write (files `0600`, directories `0700`); reviewer verdicts go in its `reviewer` subdirectory. Entries hold findings, the excerpts they quote and the reviewer's reasoning, never a project file. In the standalone user config, give an absolute path. |
| `cache.prompt_caching` | `bool` | `true` | **Deprecated since 1.7 and ignored.** Configure [prompt caching](#prompt-caching) on the platform instead. |

#### Prompt caching

Prompt caching is **not** controlled by this bundle: it is configured on the `symfony/ai` platform (your `config/packages/ai.yaml`), upstream of the auditor:

- **Anthropic**: set `cache_retention` (`none` \| `short` \| `long`) on the `anthropic` platform. The bridge auto-injects the cache markers; the default `short` (5-minute window) already enables the ~90% input-token discount. Use `long` for a 1-hour window on `api.anthropic.com`.
- **OpenAI / Gemini**: caching is **automatic** for long prompt prefixes; there is no flag to set.

```yaml
# config/packages/ai.yaml
ai:
    platform:
        anthropic:
            api_key: '%env(ANTHROPIC_API_KEY)%'
            cache_retention: long   # 1-hour cache window
```

Each model is priced from the `symfony/models-dev` listing of the platform the audit runs on, so a model served by a gateway is billed at that gateway's rate; a platform with no listing of its own (`generic`, `ollama`, …) falls back to the first-party providers. When the provider reports which model actually answered, the call is billed as that model if the platform prices it. The JSON report lists them under `cost.by_model.<model>.billed_models`.

Cache reads and writes are billed at the model's own cache rates (for Anthropic, reads at `0.1x` and writes at `1.25x` the input rate, `2x` with `cache_retention: long`), so the budget and `estimated_cost_usd` reflect the discounted spend.

_Since 1.23_ every call streams its answer, so a proxy that closes idle connections no longer cuts a long generation. Vertex AI, Venice, Cohere, MiniMax, Bedrock and `cli_agent` stay buffered, as does a gateway that cannot stream. A gateway whose stream reports no usage is switched to buffered calls after its first call, which is booked at its estimated input. When a call is cut mid-answer, or a streamed call fails without the usage it reported, the report states its cost as a minimum and counts it in `cost.interrupted_calls`.

### `privacy.*`: data egress

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `privacy.offline_only` | `bool` | `false` | Refuse every network call the auditor itself makes: `composer audit` never runs, so `lookup_advisory` finds no advisory; `self-update` no longer refreshes the pricing catalog. The standalone binary also refuses to start unless every platform endpoint is loopback or private-range (Ollama, LM Studio, a LAN box) and ignores proxy variables for a loopback endpoint. In bundle mode, pointing `ai.yaml` at a local platform is up to you; a `cli_agent` is refused. See [How do I verify that nothing leaves my machine?](faq.md#how-do-i-verify-that-nothing-leaves-my-machine) |

```yaml
# config/packages/symfony_security_auditor.yaml
symfony_security_auditor:
    model: 'llama3.2'
    privacy:
        offline_only: true
```

### Full configuration example

```yaml
# config/packages/symfony_security_auditor.yaml
symfony_security_auditor:
    attacker_model: 'claude-opus-5'
    reviewer_model: 'claude-haiku-5-5'
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

The attacker's `lookup_advisory` tool reads the CVEs of the project's dependencies from **`composer audit --format=json --locked`** (Packagist's feed: FriendsOfPHP security advisories and GitHub Security Advisories), run once per audit.

- **Isolated.** It runs in a private temporary directory holding only a copy of `composer.lock`, so the audited project's `composer.json`, scripts, plugins and ignored advisories decide nothing. Advisories of a private repository need its settings in Composer's global configuration.
- **Never blocking.** Without `composer`, without a `composer.lock`, or when the command fails, the audit goes on without CVE data and logs a warning.
- **Needs `audit.tools_enabled`**, the default: without tools the attacker cannot call it.
- **Replaceable.** Implement `AdvisoryDatabaseInterface` (Snyk, an internal CVE list, …) and alias it:

```yaml
# config/services.yaml
services:
    VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\AdvisoryDatabaseInterface:
        alias: App\Security\MyCustomAdvisoryDatabase
```

## Platform Configuration

Install the Composer package for your chosen provider, then configure it under `ai.platform` in `config/packages/ai.yaml`. The bundle consumes `PlatformInterface` directly: no `ai.agent` configuration is needed.

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
| OpenRouter | `symfony/ai-open-router-platform` | `OPENROUTER_API_KEY` |
| Generic (AI gateway) | `symfony/ai-generic-platform` | depends on the gateway |
| Claude subscription | `symfony/ai-claude-code-platform` | none: the `claude` CLI, logged in ([details](#running-on-a-claude-subscription)) |
| ChatGPT subscription | `symfony/ai-codex-platform` | none: the `codex` CLI, logged in ([details](#running-on-a-chatgpt-subscription)) |

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

### Several platforms in a Symfony application

`symfony/ai-bundle` wires `Symfony\AI\Platform\PlatformInterface`, the platform the audit runs against, only when `ai.yaml` configures exactly one platform. When it configures several, or several instances of an instance-keyed platform, select the one to audit with by aliasing the interface to its service, `ai.platform.<platform>` or `ai.platform.<platform>.<instance>`, in your application's services:

```yaml
# config/services.yaml
services:
    Symfony\AI\Platform\PlatformInterface: '@ai.platform.anthropic'
```

The alias also decides whose rates price the run. Without it, the audit stops at its first LLM call with `Several AI platforms are configured (ai.platform.anthropic, ai.platform.openai) and none is selected`, naming the services you can alias to; a `--dry-run` estimate, which calls no model, still runs.

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

In **bundle** mode that is all you need: `symfony/ai-bundle` selects the platform by itself when exactly one is configured; you alias `PlatformInterface` to one of them when there are several (see [Several platforms in a Symfony application](#several-platforms-in-a-symfony-application)).

In **standalone** mode the top-level `provider:` key selects which platform the audit runs against. For these six it must carry the instance name too:

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

`init --provider=generic.my_gateway --base-url=https://your-gateway.example` writes it and installs the bridge. The instance name is required (`init` refuses a bare `--provider=generic`); a hyphen in it is folded to an underscore, as `symfony/config` does. A name the container or the YAML file could not read back is refused.

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

Other settings of these platforms (`completions_path`, `responses_path`, `model_catalog`, …) are optional and set by hand; in the standalone binary use [`http_timeout:`](#standalone-configuration) rather than `http_client`. `init` refuses `cartesia`, `higgsfield`, `dockermodelrunner`, `lmstudio` and `transformersphp`, which need fields it never asks for: it prints their block to complete by hand; `cache` and `failover` wrap other platforms through services only a Symfony application defines, so they run from the bundle only. _Since 1.23_ `init` writes `azure` too, asking its resource URL and deployment name.

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

Cap each call's output with [`max_output_tokens`](#top-level). Other provider-specific parameters (e.g. `temperature`) can still be passed through the model name using the query-string syntax `symfony/ai-bundle` supports:

```yaml
symfony_security_auditor:
    model: 'claude-haiku-5-5?temperature=0.2'
```

> Sampling parameters are model-specific: the current Claude generation (Opus 4.7/4.8, Opus 5, Sonnet 5, Fable 5) no longer accepts `temperature`, `top_p` or `top_k` and rejects such a request outright. Steer those models with `effort` or `thinking` instead.

`max_tokens` set this way overrides `max_output_tokens` for that role. The `model` keys take a plain string only, not `symfony/ai-bundle`'s `{name, options}` mapping.

## Split-Model Setup

Pair a strong model for the attacker with a cheaper, faster one for the reviewer: both run on the same platform, only the model differs.

```yaml
# config/packages/symfony_security_auditor.yaml
symfony_security_auditor:
    attacker_model: 'claude-opus-5'     # finds vulnerabilities
    reviewer_model: 'claude-haiku-5-5'  # filters false positives
```

## Standalone Configuration

To move an existing bundle setup to the binary, or back, follow [Switching Between the Standalone Binary and the Bundle](switching-standalone-bundle.md).

When you run the [standalone binary](../README.md#standalone-tool-binary) instead of the bundle, configuration is read from a single user-level file. On Linux and macOS it follows the XDG Base Directory specification; on Windows it uses the native app-data directories:

| Purpose | Linux / macOS | Windows |
| --- | --- | --- |
| the configuration file | `$XDG_CONFIG_HOME/symfony-security-auditor/config.yaml` (→ `~/.config/…`) | `%APPDATA%\symfony-security-auditor\config.yaml` |
| attacker/reviewer and advisory caches | `$XDG_CACHE_HOME/symfony-security-auditor` (→ `~/.cache/…`) | `%LOCALAPPDATA%\symfony-security-auditor` |
| the downloaded provider bridge(s) | `$XDG_DATA_HOME/symfony-security-auditor` (→ `~/.local/share/…`) | `%LOCALAPPDATA%\symfony-security-auditor` |

> **Requirements.** One self-contained binary per platform (Linux x86-64 and arm64, macOS Intel and Apple Silicon, Windows x86-64) with its own PHP and Composer. `--since` needs `git`. Live CVE lookups use `composer audit` when `composer` is present.

**`SYMFONY_SECURITY_AUDITOR_HOME`** moves the three directories above under one absolute path (`~/.config`, `~/.cache` and `~/.local/share` beneath it), for container images whose `XDG_CONFIG_HOME` is not writable (Caddy and FrankenPHP set `/config`). A relative path is refused.

```bash
SYMFONY_SECURITY_AUDITOR_HOME=/app/var/ssa symfony-security-auditor init
# → /app/var/ssa/.config/symfony-security-auditor/config.yaml
```

Run [`init`](#init-generating-the-standalone-configuration) to write the file and install the provider bridge, pinned to the binary's PHP and `symfony/ai-platform` release. When an upgrade changes that release, `audit`, `mcp:serve` and `doctor` report the bridge as stale: rebuild it with `init --provider=<your provider> --force`.

The file is **rootless**: it takes the same keys as the bundle configuration above, without the `symfony_security_auditor:` wrapper, plus three standalone-only top-level keys:

- **`platform:`**: handed verbatim to `symfony/ai`'s `ai.platform` config, so it takes the exact shape documented in [Platform Configuration](#platform-configuration).
- **`provider:`**: the platform to run on, needed only when several are declared (`generic.my_gateway` for an [instance-keyed](#instance-keyed-platforms) one).
- **`http_timeout:`**: _Since 1.21._ Seconds a request may wait for the provider to send anything (default `600`). Raise it for a slow local model or a gateway that answers only once done; past it the call fails with `Idle timeout reached`.

```yaml
# ~/.config/symfony-security-auditor/config.yaml
provider: anthropic
platform:
    anthropic:
        api_key: '%env(ANTHROPIC_API_KEY)%'
model: claude-opus-5-5
# scan:, audit:, cache: are all accepted here too, unwrapped.
```

### Per-project overrides

The standalone binary layers its configuration, each layer overriding the keys set before it, so a repository can pin its audit settings while your credentials stay in your user config. Highest first:

1. CLI options (`--fail-on`, `--format`, …)
2. The `.symfony-security-auditor.yaml` of the audited project, when `audit <project-path>` names another folder than the one you run from (_since 1.22_; the Composer project it lies in when that folder is not one)
3. The `.symfony-security-auditor.yaml` of the folder you run from
4. Your user `config.yaml`
5. Built-in defaults

Maps merge key by key; a list such as `scan.included_paths` is replaced whole by the last file that sets it. The audit header names every file layered in. `mcp:serve` reads only the file of the folder it starts in, for every project it audits, so start it from that project.

A project file ships with the repository you audit, so it may not decide what the run trusts, where your key and code go, or what it writes:

- **Keys it may not set:** `platform`, `provider` and `scan.import_sarif`, which could send your API key, your code or any file of yours elsewhere; `cli_agent`, which could start a program of its choosing with your environment; and `cache`, `privacy`, `audit.custom_skills`, `audit.output`, `audit.tools_scope`, `scan.custom_risk_patterns` and `scan.secret_scrubbing`.
- **Values it may not set:** a `%env()%` or other container reference, text that is not plain (control characters, `::`), a model name that is not a bare model id, a non-map value in place of one of your sections or an `audit.budget` that raises or removes your caps, which it may only lower. `http_timeout` may only be raised.
- **Files refused:** a symlink, a file over 512 KiB, nested over 32 levels or expanding to 10,000 values or more, and, in the audited project, one naming an `audit.baseline` that is not a regular file of at most 1 MiB inside the project. `scan.included_paths` stays confined to the project root by real path.

A working-directory file that breaks a rule stops the run before it starts; the audited project's is skipped instead: the header says why and the run goes on without it.

> [!WARNING]
>
> An untrusted repository still picks the models, the profile and the concurrency, so it decides what an uncapped run spends. Set `audit.budget.max_cost_usd` in your user config before auditing one: the project file can only lower it.

In your user config, a `%…%` pair that names no container parameter is kept as typed in risk patterns, scrubbing patterns and skill instructions (`/sprintf\(.*%s.*%d/`).

### Switching providers

`%env(VAR)%` placeholders in the `platform:` block are resolved from the environment, so secrets never live in the file. To switch providers, configure several platforms and change `provider:`; only the selected platform's variables need to be set. `init` writes a single-platform file, so fetch the second bridge by hand instead of running it again. Fetch it into the bridge directory, whose `composer.json` already pins the PHP and `symfony/ai-platform` versions the binary needs:

```bash
composer require symfony/ai-open-ai-platform \
    --working-dir="${XDG_DATA_HOME:-$HOME/.local/share}/symfony-security-auditor"
```

That is the bridge directory from the [table above](#standalone-configuration): with `SYMFONY_SECURITY_AUDITOR_HOME` set, use `"$SYMFONY_SECURITY_AUDITOR_HOME/.local/share/symfony-security-auditor"` instead; on Windows, use `"%LOCALAPPDATA%\symfony-security-auditor"`.

```yaml
provider: openai
platform:
    anthropic: { api_key: '%env(ANTHROPIC_API_KEY)%' }
    openai: { api_key: '%env(OPENAI_API_KEY)%' }
model: gpt-5.6
```

### Running on a subscription

_Since 1.23_ the standalone binary can run the audit on your Claude or ChatGPT subscription instead of an API key, through that vendor's CLI installed on the machine.

1. Install the CLI and log in to your subscription.
2. Run `init` with the provider of your subscription. It downloads what it needs, then asks which models to use and the effort (how hard they think). `--model`, `--reviewer-model` and `--effort` answer without asking.

`init` writes a config you can edit afterwards:

- `model` finds the issues and `reviewer_model` double-checks them.
- `effort` is `low`, `medium`, `high`, `xhigh` or `max`; `init` suggests `medium`. Higher finds more and uses more of your plan. Without it, the CLI keeps its own default.
- When the CLI is not on the `PATH`, give its path as `cli_binary:` next to `effort:`.

Good to know:

- Your plan's usage limits apply and its terms decide what automated use it allows.
- The run has no price: `--dry-run` shows no cost and an `audit.budget` cost cap cannot be enforced.
- Each call bills the subscription the CLI is logged in to: the auditor starts it without your API keys. The audit header, `auth:status`, `auth:test` and `doctor` name that account. An audit refuses to start while the CLI is not logged in.
- `privacy.offline_only` refuses both platforms.
- It does not run on Windows: the auditor's instructions do not fit the command line Windows starts the CLI with, so the run stops at its first call. Use WSL, Linux, macOS or an API platform.
- The CLI runs outside the audited project with its own tools off, so the code it reads cannot make it act. It sees only the code the auditor sends: `audit.tools_enabled`, `audit.structured_collection`, `audit.reviewer_tools_enabled` and `audit.reviewer_structured_collection` are always off.

#### Running on a Claude subscription

Install the [Claude Code](https://code.claude.com) CLI (`claude`), then run `init --provider=claudecode`. It writes:

```yaml
provider: claudecode
platform:
    claudecode: { effort: medium }
model: claude-opus-5-5
reviewer_model: claude-haiku-5-5
```

- Any Claude model id works, as do the aliases `opus`, `sonnet` and `haiku`.
- On a CI runner, set `CLAUDE_CODE_OAUTH_TOKEN` to the token `claude setup-token` prints.
- The auditor ignores `ANTHROPIC_API_KEY`, `ANTHROPIC_AUTH_TOKEN`, the Bedrock, Vertex and Foundry switches and the `apiKeyHelper` of your settings files. You get a warning when an API key still bills in place of your subscription, such as one set by managed settings. When `claude` names no subscription plan, only such a helper, the audit refuses to start.
- Claude Code ignores the MCP servers of the machine.
- In a Symfony application, require `symfony/ai-claude-code-platform` and set `cli_agent: { platform: claudecode, effort: medium }` with `model: claude-opus-5-5` and `reviewer_model: claude-haiku-5-5` under `symfony_security_auditor:`. Your application's own `symfony/ai` platform is left as it is.

#### Running on a ChatGPT subscription

Install the [Codex](https://github.com/openai/codex) CLI (`codex`), then run `init --provider=codex`. It writes:

```yaml
provider: codex
platform:
    codex: { effort: medium }
model: gpt-6.2-sol
reviewer_model: gpt-6-luna
```

- `init` also offers `gpt-6.2-astra` for the hardest projects. Any model id your Codex CLI runs works.
- The auditor ignores `CODEX_API_KEY` and `OPENAI_API_KEY`. When `codex` is logged in with an API key, the audit refuses to start: run `codex logout`, then `codex login` with your ChatGPT account.
- Codex runs read-only with its shell and web search off. It ignores your Codex configuration and rules and keeps nothing of the session.
- In a Symfony application, require `symfony/ai-codex-platform` and set `cli_agent: { platform: codex, effort: medium }` with `model: gpt-6.2-sol` and `reviewer_model: gpt-6-luna` under `symfony_security_auditor:`. Your application's own `symfony/ai` platform is left as it is.

## Providing the API key

The `platform:` block holds a `%env(...)%` placeholder, never the key itself. Where that value comes from is yours to choose:

| Source | Config value | Typical setup |
| --- | --- | --- |
| Environment variable | `'%env(ANTHROPIC_API_KEY)%'` | CI secret store, `systemd` unit, a per-command assignment |
| Stored on this machine | `'%env(ANTHROPIC_API_KEY)%'` | `auth:set` on a developer laptop, set up once |
| File on disk | `'%env(file:ANTHROPIC_API_KEY_FILE)%'` | Docker/Kubernetes secrets, `systemd` `LoadCredential=`, 0600 file |
| Secret manager | either of the above | `pass`, 1Password, Vault (read at launch, see below) |

The standalone binary resolves only those two spellings (no other env processor such as `trim:`); a Symfony application keeps every processor Symfony offers.

### Which one wins

Resolution order is fixed and the first hit wins:

1. **The environment variable**, when it is set and non-empty.
2. **The credential stored by `auth:set`**, under that same variable name.
3. Otherwise the run stops before contacting the provider, naming all three ways to fix it.

So containers, CI and per-run secret-manager prefixes behave the same whatever a machine stores. `auth:status` says which source is used and warns when a variable shadows a stored key.

### Storing the key on this machine

Standalone only, _since 1.21_. `init` offers it at the end of setup and `auth:set` does it at any time:

```bash
symfony-security-auditor auth:set
# Paste the API key for ANTHROPIC_API_KEY (input stays hidden): ****
# [OK] Stored ANTHROPIC_API_KEY (sk-ant…qF4A, SHA256:ed9ff73cc4b2cd57) in
#      /home/you/.config/symfony-security-auditor/credentials.json. Audits pick
#      it up on their own from now on — an exported ANTHROPIC_API_KEY still
#      takes precedence when you want to override it for one run.
```

The prompt never echoes, so the key stays out of the terminal and the shell history. It is written to `credentials.json` beside your config, under the variable your `platform:` block names.

| Command | What it does |
| --- | --- |
| `auth:set` | Store or replace the key; `--env-var` targets a variable other than the configured one |
| `auth:status` | _Since 1.23_, name the provider, the models and what each call bills: the key's variable, nothing for a local model, or the account a subscription's CLI is logged in to, with a warning when an API key bills in place of the subscription. Then report the variable, the source, the masked key, its fingerprint and the file path, or that the configured platform needs no key |
| `auth:remove` | Forget the stored key (the key stays valid with your provider, so revoke it there too) |
| `auth:test` | _Since 1.23._ Name the provider, the models and what each call bills, as `auth:status` does, then send one short test request (billed by a paid API, usually well under a cent) and say whether the provider answers; exits `1` with the provider's reason when it does not. Same check as `doctor --check-connection` |

**Permissions.** The file is written `0600` in a `0700` directory. A file other users can read, or that is not valid JSON, is refused on read with a message telling you to rotate the key; `auth:set` and `auth:remove` still rewrite it. On Windows, which has no POSIX permission bits, the file relies on the ACL of `%APPDATA%`.

**In output** a key is never printed: it is named by a masked preview (`sk-ant…qF4A`) and a truncated SHA-256 fingerprint (`SHA256:ed9ff73cc4b2cd57`). A key shorter than 24 characters is masked entirely.

**Exit codes.** The `auth:*` commands exit `2` when no API-key variable is configured or named with `--env-var`, or when the name is not a valid variable name. _Since 1.23_, when the configured platform needs no key (a subscription, a local model), `auth:status` and `auth:remove` say so and exit `0`; `auth:set` exits `2`. Otherwise `auth:status` exits `0` when a key resolves and `1` when none does; `auth:set` exits `2` when nothing usable was entered or the terminal cannot hide input, `1` when the key cannot be stored; `auth:remove` exits `1` when the file cannot be rewritten.

Nothing is required: a machine with nothing stored falls back to the environment variable.

### Reading the key from a file

`%env(file:VAR)%` reads the file whose **path** `VAR` holds, rather than the variable's own value. The standalone binary supports it _since 1.21_; a Symfony application gets it from Symfony's own `file:` env processor:

```yaml
platform:
    anthropic: { api_key: '%env(file:ANTHROPIC_API_KEY_FILE)%' }
```

```bash
ANTHROPIC_API_KEY_FILE=/run/secrets/anthropic symfony-security-auditor audit .
```

Surrounding whitespace is stripped. The run stops before contacting the provider when `VAR` is unset or the file is unreadable or blank; `doctor` reports it too. No shell is involved, so it works the same everywhere and is how container runtimes and service managers hand a secret to a process.

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

Only the command reaches the history file. Without a secret manager, store the key once with `auth:set`.

### In CI

Keep the key in the runner's secret store and expose it to the step as an environment variable, never in the workflow file itself. The environment outranks any stored credential, so a runner is unaffected by what a developer machine keeps. See [CI](ci.md#github-actions) for GitHub Actions and [GitLab](ci.md#gitlab-ci) examples.

### In a Symfony application

The bundle resolves `ai.yaml` through Symfony's own environment handling, so `.env.local` (gitignored), the [secrets vault](https://symfony.com/doc/current/configuration/secrets.html) (`bin/console secrets:set ANTHROPIC_API_KEY`) and `%env(file:VAR)%` for a mounted secret all work unchanged.

### No key at all

Running against [Ollama](#supported-platforms) needs no credential. Pair it with [`privacy.offline_only: true`](#privacy-data-egress) to have that enforced rather than assumed.

On Ollama, `audit:run` asks the server which models it pulled before the run starts (in a Symfony application as in the binary) and notes each configured `model`, `attacker_model` or `reviewer_model` it has not pulled. The run still goes ahead; a model the provider does not know stops it with an error naming the model and the setting to change.

## CLI Reference

The bundle registers the `audit:run` console command, also reachable through the shorter `audit` alias (`bin/console audit`), plus `audit:diff`, `audit:trend` and `audit:baseline` for working with previously generated reports. The standalone CLI exposes the same commands, run as `symfony-security-auditor audit:diff …`; its three report commands need neither a configuration nor an API key.

```bash
bin/console audit:run [<project-path>] [options]
# `audit` is an equivalent alias:
bin/console audit [<project-path>] [options]
```

### Arguments

| Name | Required | Default | Description |
| --- | --- | --- | --- |
| `project-path` | no | `getcwd()` | Project to audit. _Since 1.22_ a folder that is not a project (no `composer.json`, no file the scan reaches) is audited as a `--path` of the Composer project above it: `audit app/src` audits `app` with `--path src`. That project's `.symfony-security-auditor.yaml` applies. |

### Options

| Option | Short | Default | Description |
| --- | --- | --- | --- |
| `--format` | `-f` | `console` | Report format: `console`, `executive` (stakeholder summary, no per-finding detail), `json`, `sarif`, `html` (self-contained, with charts), `markdown` (PR comment or `$GITHUB_STEP_SUMMARY`), `junit` (CI test panels), `github` (inline workflow annotations) or `github-comment` (_since 1.19_, a self-updating PR comment). See [Output formats](#output-formats-reference). Defaults to `audit.format` (_since 1.22_). |
| `--output` | `-o` | none | Write the report to this file, for any format, `--dry-run` included. A path it could never be saved to (a symlink, a directory, a pipe) is refused before the audit runs; `/dev/null` works. Leave it out with `--format=github`, whose annotations must reach the workflow log. Defaults to `audit.output` (_since 1.22_). Without it, `--format=html` on a terminal saves the report to a file only you can read in the temporary directory and prints a `file://` link to open it in a browser; piped or redirected, it prints the HTML (_since 1.23_). |
| `--no-output` |  | `false` | _Since 1.22._ Print the report for this run, whatever `audit.output` says. Cannot be combined with `--output`. |
| `--dry-run` |  | `false` | Estimate tokens and cost without calling the LLM, then exit `0`. The estimate ignores prompt-cache discounts, so real runs usually cost less; an unpriced model shows `$0.00` with a warning. The standalone binary runs it without an API key. A report it writes is marked incomplete (_since 1.21_). |
| `--path` | `-p` | none | Audit these directories or files instead of `scan.included_paths`, relative to the project root; repeat for several. _Since 1.22_ they replace the configured scope (`--path apps/api` reaches a folder the configuration leaves out) and may be absolute when inside the project. File types, size limit, gitignore and scrubbing still apply. The `security.yaml`, voters and forms of the whole project still tell the model which routes are guarded; in a monorepo, the application's own security configuration is read too. A path outside the project exits `1`. |
| `--show-scanned` |  | `false` | List the files that would be audited, grouped by type, then exit without calling the LLM. Combine with `--dry-run` to see the list and the estimate. |
| `--no-cache` |  | `false` | Bypass the attacker and reviewer caches for this run, reading and writing nothing. |
| `--since` |  | none | Audit only the files changed against this git ref (`main`, `origin/main`, `abc1234`), committed or not, untracked files included. Made for pull-request CI. |
| `--baseline` |  | none | Baseline of accepted findings to leave out; overrides [`audit.baseline`](#audit-orchestrator-knobs). A missing file suppresses nothing. |
| `--fail-on` |  | `critical` | Lowest aggregate risk level (`safe`, `low`, `medium`, `high`, `critical`) that makes the command exit `1`. Defaults to `audit.fail_on`. |
| `--min-score` |  | none | _Since 1.19._ Minimum [normalized score](#normalized-score-and-grade) (0-100); below it the command exits `1`, whichever gate trips first. Defaults to `audit.min_score` (_since 1.22_). |
| `--fail-on-incomplete` |  | `false` | _Since 1.21._ Exit `3` when a file could not be fully analyzed, so a partial report cannot pass CI; a tripped risk or score gate still exits `1`. `--no-fail-on-incomplete` overrides a configured `audit.fail_on_incomplete: true`. |
| `--generate-baseline` |  | none | Run the audit and write its findings to this baseline file, then exit `0` (`3` under `--fail-on-incomplete` when the run is incomplete). A run with no verdict, such as a provider outage, leaves an existing baseline untouched and exits `1`. Cannot be combined with `--dry-run` or `--show-scanned`. |

### Examples

```bash
bin/console audit:run /path/to/project --format=json --output=report.json
bin/console audit:run --format=sarif --output=report.sarif
bin/console audit:run --show-scanned --dry-run    # files and cost, no LLM call
bin/console audit:run --since=origin/main         # changed files only

# accept the current findings, then report only new ones
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
  xss                                                1

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

_Since 1.19._ A pull-request comment body, sized for a comment rather than a full report: the [grade and normalized score](#normalized-score-and-grade) as a headline, the run summarized on one line and the ten most severe findings as one table row each (with a note naming how many were left out). The body opens with an invisible `<!-- symfony-security-auditor:pr-comment -->` marker so a workflow can find its own previous comment and edit it in place instead of appending a new one on every push. That is exactly what the GitHub Action's `comment-pr` input does. See [Sticky PR comment with the audit summary](ci.md#sticky-pr-comment-with-the-audit-summary).

```markdown
<!-- symfony-security-auditor:pr-comment -->

## Security audit: D (58/100)

**Risk level:** HIGH · **Findings:** 7 · **Files scanned:** 148 · **Duration:** 192.4s

| Severity | Finding | Location | Type |
| --- | --- | --- | --- |
| 🔴 CRITICAL | Unprotected administrative action | `src/Controller/Admin/UserController.php:41` | `broken_access_control` |
| 🟠 HIGH | Unescaped user input in a Twig template | `src/Twig/ReviewExtension.php:23` | `xss` |

---

Generated by [vinceamstoutz/symfony-security-auditor](https://github.com/vinceamstoutz/symfony-security-auditor).
```

_Since 1.23._ With [`audit.fix_synthesis`](#audit-orchestrator-knobs) enabled, a `### Suggested fixes` section follows the table: each listed finding whose fix replaces one run of lines of its own file gets a GitHub ` ```suggestion ` block naming those lines. A fix spanning several hunks or files, one that only adds lines or one whose code holds a hidden marker of the auditor gets no suggestion block. The body also ends with a hidden, base64-encoded list of those suggestions, which the GitHub Action's `comment-pr` posts as a pull-request review (see [CI](ci.md#sticky-pr-comment-with-the-audit-summary)).

#### `html`

A single self-contained file (no external stylesheet, font, image or script) carrying the risk badge and run metadata, a Distribution section of two inline-SVG bar charts (by severity, by vulnerability type) and one card per finding with its location, description, vulnerable code, attack vector, proof of concept and remediation. Colors come from the report's own stylesheet, so it follows the reader's light/dark preference.

![The HTML report: branded header, risk badge, run metadata, distribution charts and one card per finding](../assets/html-report.png?raw=true)

### Normalized score and grade

_Since 1.19._ Alongside `risk_score` (an unbounded weighted sum that grows with every finding), a report carries a **normalized score** and a **letter grade**, both bounded and both meant to be read at a glance in a badge, a pull-request comment or a CI gate.

The normalized score starts at `100` and deducts each finding's severity weight (`critical` 10, `high` 7, `medium` 5, `low` 2, `info` 0; the same table `risk_score` sums), floored at `0`. So a clean report scores `100` and one critical finding costs 10 points.

The grade boundaries mirror the `risk_level` thresholds, so the two never disagree:

| Grade | Score  | `risk_level` | `risk_score` |
| ----- | ------ | ------------ | ------------ |
| `A`   | 96-100 | `SAFE`       | 0-4          |
| `B`   | 86-95  | `LOW`        | 5-14         |
| `C`   | 71-85  | `MEDIUM`     | 15-29        |
| `D`   | 51-70  | `HIGH`       | 30-49        |
| `F`   | 0-50   | `CRITICAL`   | 50 +         |

`--format=json` exposes them as the additive root keys `score` and `grade`; `risk_score` and `risk_level` are unchanged.

### Exit codes

| Code | Meaning |
| --- | --- |
| `0` | The audit completed below the `fail_on` threshold and, if set, at or above `--min-score` |
| `1` | The risk level reached `fail_on`, the score fell below `--min-score`, the run has no verdict (the scan found no file, or no file could be analyzed and nothing was found, _since 1.21_), or the audit failed or was given an invalid path. _Since 1.23_ it also covers an audit on a subscription that refuses to start because the CLI is not logged in or would bill an API key in its place |
| `2` | The token or cost budget was exceeded (the partial report is still written), or a cost budget could not be enforced on an unpriced model and the run was declined |
| `3` | _Since 1.21._ `--fail-on-incomplete` (or, _since 1.22_, `audit.fail_on_incomplete`) is set, no gate tripped and some file could not be fully analyzed |

An incomplete run (a scan or LLM call failed) keeps the exit code its gates earn unless `--fail-on-incomplete` is set. It always says so: `Audit incomplete` in the report, `complete: false` in JSON, `executionSuccessful: false` in SARIF. A run with no verdict exits `1` instead of reporting a perfect score, which catches a mistyped `project-path` or a scan scope that matches nothing; a `--since` run with nothing changed still exits `0`.

### `audit:diff`: comparing two reports

Compares two JSON reports by finding `fingerprint`: findings only in the later one are **New**, only in the earlier one **Fixed**, in both **Persisting**. A finding gone from a file the later run did not fully analyze, or that it left out as accepted or muted, is **Unverified** rather than fixed.

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

The JSON document carries `new`, `fixed`, `unverified` and `persisting` lists.

Exit codes: `0` on a successful comparison (regardless of whether any findings are new, fixed, unverified, or persisting), `1` if a report file is missing or is not valid JSON.

### `audit:trend`: tracking findings across reports

Tracks finding counts across two or more JSON reports, oldest to newest, comparing each with the one before it as `audit:diff` does.

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

Findings gone from a file a later run could not analyze are counted as unverified rather than fixed (_since 1.21_).

| Argument | Required | Description |
| --- | --- | --- |
| `reports` | yes | Paths to two or more JSON reports, ordered oldest to newest. |

| Option     | Short | Default   | Description                                 |
| ---------- | ----- | --------- | ------------------------------------------- |
| `--format` | `-f`  | `console` | Output format: `console`, `json`, or `html` |

`--format=json` emits a `points` array, one entry per report with `report`, `total`, `new`, `fixed` and `unverified` (`null` on the first).

`--format=html` emits a self-contained page with a line chart and a table of deltas, ready to publish as a dashboard:

```bash
bin/console audit:trend nightly-*.json --format=html > trend.html
```

Exit codes: `0` on a successful trend (regardless of how the counts evolve), `1` if fewer than two reports are given or a report file is missing or is not valid JSON.

### `audit:baseline`: maintaining the accepted-finding baseline

Creates or updates a baseline from a JSON report **without re-running the audit**. Unlike `audit:run --generate-baseline`, which overwrites the file, it merges: existing entries and their `reason` are kept; only new findings are appended.

```bash
bin/console audit:baseline report.json .security-baseline.json --prune --annotate
```

| Argument | Required | Description |
| --- | --- | --- |
| `report` | yes | Path to a JSON report produced by `audit:run --format=json`. |
| `baseline` | no | Baseline file to create or update (default `.security-baseline.json`). |

| Option | Default | Description |
| --- | --- | --- |
| `--prune` | off | Drop entries whose findings no longer appear in the report. An entry whose file the report did not analyze is kept (_since 1.21_). |
| `--annotate` | off | Ask a reason for each newly accepted finding; reasoned entries teach the reviewer. |

Each appended entry carries `fingerprint`, `type`, `file`, `title`, `added_at` and, with `--annotate`, `reason`. Each entry accepts one occurrence of its finding, as in the audit itself. Entries written by earlier releases keep matching.

Exit codes: `0` on success, `1` if the report is missing or malformed, the baseline file is malformed, or the baseline path is a symlink (refused, exactly as every other writer in this tool refuses symlinked destinations).

### `mcp:serve`: Model Context Protocol server

> [!WARNING] `mcp:serve` is **experimental**: the command, the `audit` tool and its input schema may change in any release (including a `MINOR` or `PATCH` one) and are not covered by the [backward compatibility promise](versioning.md#experimental-features).

Starts a [Model Context Protocol](https://modelcontextprotocol.io) server over stdio, built on the official [`mcp/sdk`](https://github.com/modelcontextprotocol/php-sdk), so any MCP client (Claude Code, Claude Desktop, Cursor, VS Code, Windsurf, Gemini CLI, Codex CLI, …) can run an audit on demand.

It is available both ways the auditor ships, the standalone binary _since 1.21_:

```bash
symfony-security-auditor mcp:serve   # standalone binary, reads your user-level config.yaml
bin/console mcp:serve                # Symfony bundle, reads the application's configuration
```

The standalone server reads your user config and the `.symfony-security-auditor.yaml` of the folder it starts in, once and applies them to every project it audits; it does not layer the audited project's own file. Start it from the project it will audit.

Exposed tools:

| Tool | Arguments | Description |
| --- | --- | --- |
| `audit` | `path` (string, req.) | Audits the project at the absolute `path` and returns the JSON report, applying `audit.baseline`, `audit.included_types` and `audit.excluded_types` like `audit:run`. A run with no verdict answers with an error; a run stopped by `audit.budget` or a provider failure answers with the reason followed by its partial report (_since 1.22_). |

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

#### Which model runs the audit (and the API key)

The audit runs on the auditor's own configured platform and models and bills that provider as a CLI run would. **The MCP client's model is not used**, so your provider credential is still required.

- An audit needs **no API key** only when the configured platform takes none, such as a local [Ollama](#supported-platforms); nothing then leaves your machine either.
- On a [Claude](#running-on-a-claude-subscription) or [ChatGPT](#running-on-a-chatgpt-subscription) subscription, the `audit` tool refuses to start, as `audit:run` does, while the CLI is not logged in or would bill an API key in place of the subscription. The client receives the reason.
- A client started from a desktop app does not inherit your shell's environment variables. With the standalone binary, store the key once with [`auth:set`](#providing-the-api-key) so the server finds it however it is launched; otherwise pass the variable through the client's `env` setting.
- A full report can be large. Claude Code caps a tool's output at 25,000 tokens by default; raise `MAX_MCP_OUTPUT_TOKENS` if a report is cut off.
- An audit takes minutes and sends no progress; a client that times out (60 seconds by default in the MCP TypeScript SDK) leaves the server spending on an answer nobody reads. Raise the client's tool timeout (Claude Code: `MCP_TOOL_TIMEOUT`, in milliseconds) or keep MCP audits short with the `fast` profile.

### `init`: generating the standalone configuration

Standalone only. Writes `config.yaml` and installs the provider bridge with the Composer the binary bundles. _Since 1.23_ it first asks how you access AI models (a Claude or ChatGPT [subscription](#running-on-a-subscription), an API key, a local model such as Ollama, an AI gateway or a cloud account), then lists the matching providers and the newest model of each family with its price per million tokens, defaulting to `claude-opus-5-5` where listed. Type any other provider or model id to skip a list. It can end with one test request, sent only on `yes`. Each option given skips its prompt; under `--no-interaction` a missing option takes its default and a platform that needs a URL is refused rather than written half-configured. A model `init` writes as a placeholder is marked with a comment in `config.yaml`; `doctor` warns about it until it is replaced.

| Option | Default | Description |
| --- | --- | --- |
| `--provider` | `anthropic` | _Since 1.23_ also `claudecode` or `codex`, to run on a [Claude](#running-on-a-claude-subscription) or [ChatGPT](#running-on-a-chatgpt-subscription) subscription. Any platform the bundled `symfony/ai-bundle` declares; any other (`meta`, which 0.14 dropped, or a misspelling) is refused with exit code `2` before anything is installed, listing the ones it declares. A platform configured per instance takes it too, e.g. `generic.my_gateway`. |
| `--model` | The model `init` offers first | `claude-opus-5-5` for Anthropic or where the provider lists it, else a mid-priced model it lists, the first model of a subscription or the first model Ollama pulled. Where `init` can list no model (a gateway, an Ollama it cannot reach or with no model pulled, a provider the price catalog does not list), `--no-interaction` writes `claude-opus-5-5` as a placeholder and warns: set `model:` in the written file or pass `--model`. |
| `--env-var` | `<PLATFORM>_API_KEY` | The environment variable the configuration reads the API key from. A platform you host yourself (`ollama`) defaults to none instead. |
| `--base-url` | prompted when required | _Since 1.21._ The connection origin, for `albert`, `amazeeai`, `generic.<instance>` and `openresponses.<instance>`. Rejected for any other platform. |
| `--endpoint` | prompted when required | _Since 1.21._ The connection URL under the name those platforms give it: `deepgram`, `elevenlabs`, `minimax`, `ollama`, `together` and `venice`. For `ollama` and `together` it is the origin; `deepgram`, `elevenlabs`, `minimax` and `venice` take it with the API version path their default carries (`https://api.deepgram.com/v1/`), since the bridge appends only the route. Rejected for any other platform. |
| `--deployment` | prompted when required | _Since 1.23._ The Azure OpenAI deployment name, for `azure.<instance>`; its `--base-url` is the resource URL. Rejected for any other platform. |
| `--no-api-key` | off | _Since 1.21._ Write no `api_key` at all, for the platforms whose key the bundle leaves optional (`bedrock`, `deepgram`, `elevenlabs`, `generic`, `ollama`, `openresponses`). |
| `--force` | off | Overwrite an existing configuration without asking. |

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

- **URLs.** A platform takes `--base-url` or `--endpoint`, never both. Pass `%env(VAR)%` as the whole value to read the URL from the environment.
- **Ollama** needs `--endpoint` and is written without a key, as `privacy.offline_only` expects; `--env-var` adds one for Ollama Cloud.
- **Bedrock** is written on a Mantle route, which takes an API key: name the model after its vendor (`anthropic.claude-opus-4-8`). The key comes from `BEDROCK_API_KEY`; `--no-api-key` signs requests with your AWS credentials. Add `region:` for another region than `us-west-2`.
- **`cartesia`, `higgsfield`, `dockermodelrunner`, `lmstudio`, `transformersphp`** need fields `init` never asks for: it installs the bridge, prints the block with a `<placeholder>` per missing value and exits `2`.
- **`cache` and `failover`** wrap other platforms through services only a Symfony application defines: refused, use them from the bundle.

### `self-update`: updating the standalone binary

Updates the [standalone binary](#standalone-configuration) in place to the latest released version. This command exists **only in the standalone binary** (the Composer bundle updates through `composer update`).

```bash
symfony-security-auditor self-update          # download + verify + replace, if newer
symfony-security-auditor self-update --check  # only report whether a newer version exists
symfony-security-auditor self-update --snapshot  # switch to the latest snapshot
```

It downloads the binary for your platform with `curl`, **verifies its `.sha256` checksum before replacing anything**, then swaps it in atomically as the command exits; if the swap fails, the previous binary stays and the command exits `1`. A terminal shows the download progress.

| Option | Default | Description |
| --- | --- | --- |
| `--check` | off | Report whether a newer version is available; make no changes to the binary. |
| `--snapshot` | off | _Since 1.22._ Use the latest snapshot instead of the latest release. |

#### Snapshots

_Since 1.22._ Every push to `1.x` publishes the `snapshot` pre-release, built and checksummed like a release, to try a fix before it ships: `self-update --snapshot`, or `SSA_VERSION=snapshot` with the installers (`curl -fsSL …/install.sh | SSA_VERSION=snapshot sh`, `$env:SSA_VERSION = 'snapshot'` before `install.ps1`).

A snapshot reports a version such as `1.21.0+14.g4531440` (last release, commits since, commit). A plain `self-update` returns to the latest release. A snapshot is tested by CI only and replaced on every push.

The directory holding the binary must be writable (use `sudo` for `/usr/local/bin`, or reinstall with the install script); otherwise the command refuses before downloading anything.

### `doctor`: preflight environment check

Checks that the [standalone binary](#standalone-configuration) is ready to audit before you spend a token. Standalone only, like `self-update` and `init`.

```bash
symfony-security-auditor doctor
```

It runs four checks and prints one line for each. _Since 1.23_ it adds a `Provider` line once a provider is configured:

| Check | What it verifies |
| --- | --- |
| Configuration | `config.yaml` resolves, holds a `platform:` block and sets every `%env(...)%` variable of the selected platform (an unset key is reported as `API key`); a key that resolves is shown masked, with a pointer to `auth:status` (_since 1.23_) for where it comes from |
| Provider bridge | the bridge `init` installed is there, matches the binary's `symfony/ai-platform` release and boots the audit |
| Composer | the Composer the binary bundles runs, for the `lookup_advisory` tool; `init` runs it too |
| Pricing catalog | the `symfony/models-dev` catalog that prices the run is there |
| Provider | _Since 1.23._ The provider, the models and what each call bills. On a subscription, the account `claude auth status` or `codex login status` reports: a **warning** when an API key the auditor cannot keep from the CLI (an API-key Codex login, a key of managed settings) bills in place of the subscription or the CLI cannot tell, a **failure** while the CLI is not logged in |

A Composer that does not run or a missing pricing catalog is a **warning**; a bad configuration or bridge is a **failure**. The command exits `1` on a failure only, so it fits a CI preflight step:

```bash
symfony-security-auditor doctor && symfony-security-auditor audit path/to/app
```

_Since 1.23._ `doctor --check-connection` also sends one short request to the provider and adds a `Connection` line, a **failure** naming why when it does not answer (refused key, unknown model, unreachable endpoint). A paid API bills it, usually well under a cent, so it runs only when asked; an interactive `init` offers it at the end.

### Shell completion

The binary completes its commands, options and arguments in bash, zsh and fish. `completion` prints the script for your shell and, _since 1.23_, stays out of the command list. Write it once to the directory your shell loads completions from:

```bash
# bash (needs bash-completion 2.x, which loads it on first use)
mkdir -p ~/.local/share/bash-completion/completions
symfony-security-auditor completion bash > ~/.local/share/bash-completion/completions/symfony-security-auditor

# zsh
mkdir -p ~/.zfunc
symfony-security-auditor completion zsh > ~/.zfunc/_symfony-security-auditor

# fish
mkdir -p ~/.config/fish/completions
symfony-security-auditor completion fish > ~/.config/fish/completions/symfony-security-auditor.fish
```

Then open a new shell. bash-completion 1.x, the version Homebrew installs for the bash 3.2 macOS ships, never reads that directory: add `source ~/.local/share/bash-completion/completions/symfony-security-auditor` to `~/.bashrc` instead. For zsh, `~/.zfunc` must be on your `fpath` before `compinit` runs: add `fpath=(~/.zfunc $fpath)` to `~/.zshrc` above `compinit`, or above the `source $ZSH/oh-my-zsh.sh` line with Oh My Zsh. If completion still does not show up, delete zsh's cache with `rm -f ~/.zcompdump*` and open a new shell.

Loading the script from your startup file works too (`eval "$(symfony-security-auditor completion bash)"`), but it starts the binary every time a shell opens.

The script asks the installed binary for its completions on every <kbd>Tab</kbd>, so you do not need to write it again after a `self-update`. It is registered for the command name `symfony-security-auditor`, so a copy of the binary renamed to anything else gets no completion. In a Symfony application, `bin/console completion` sets up the bundle's commands the same way.

### Update notifications

When you run the [standalone binary](#standalone-configuration) interactively, it prints a one-line notice to **stderr** once a command finishes if a newer release is available:

```text
A new version (1.17.0) is available. Run "symfony-security-auditor self-update" to upgrade.
```

It runs only on an interactive terminal, so CI and machine-readable output are never touched, looks up GitHub at most once a day and stays silent on any failure. Set `SSA_NO_UPDATE_CHECK=1` to turn the check off entirely.
