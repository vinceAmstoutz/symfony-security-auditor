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

| Key              | Type   | Default             | Description                                          |
| ---------------- | ------ | ------------------- | ---------------------------------------------------- |
| `model`          | string | `'claude-opus-4-5'` | Model name used for both Attacker and Reviewer roles |
| `attacker_model` | string | `null`              | Override: dedicated model for the Attacker role      |
| `reviewer_model` | string | `null`              | Override: dedicated model for the Reviewer role      |

`attacker_model` and `reviewer_model` fall back to `model` when not set. Model
names must be supported by the platform configured in `ai.yaml`.

### `scan.*` — file discovery

| Key                      | Type        | Default | Description                                                                                                                                                     |
| ------------------------ | ----------- | ------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `scan.excluded_dirs`     | `string[]`  | `[]`    | Extra directories to skip. **Appended** to the hard defaults (`vendor`, `node_modules`, `.git`, `var/cache`, `var/log`, `public/bundles`); never replaces them. |
| `scan.respect_gitignore` | `bool`      | `true`  | When `true` (default), files matched by the project `.gitignore` are skipped. Set `false` for full-tree scans that include generated/cached artefacts (rare).   |
| `scan.max_file_size_kb`  | `int` (≥ 1) | `512`   | Skip files larger than this size, in kilobytes.                                                                                                                 |
| `scan.secret_scrubbing.enabled` | `bool` | `true` | Redact credential-shaped strings (AWS/GitHub/Stripe/Slack/Google API keys, JWTs, PEM private keys, env-style credential assignments) from file content before it reaches the LLM. Default `true` — credentials in committed sample configs or `.env.dist` files would otherwise be sent verbatim to the LLM provider. |
| `scan.secret_scrubbing.additional_patterns` | `string[]` | `[]` | Extra PCRE patterns merged with the defaults. Use to redact project-specific tokens (e.g. internal API key shapes). |

### `audit.*` — orchestrator knobs

| Key                         | Type        | Default | Description                                                                                                                                                                                                                                                                                                                                                                                      |
| --------------------------- | ----------- | ------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `audit.max_iterations`      | `int` (≥ 1) | `3`     | Maximum number of attacker/reviewer iterations per audit. Loop stops earlier when no new findings emerge.                                                                                                                                                                                                                                                                                        |
| `audit.min_confidence`      | `float` 0–1 | `0.6`   | Minimum attacker self-reported confidence required to forward a finding to the reviewer. Tune for precision vs. recall: CI gate `0.8`, discovery scan `0.3`, default audit `0.6`.                                                                                                                                                                                                                |
| `audit.reviewer_batch_size` | `int` (≥ 1) | `1`     | Number of findings reviewed per LLM call. `1` = one-by-one (highest precision, highest latency). Larger values reduce cost/latency at risk of cross-talk between findings in the prompt. Try `5` for cost-sensitive runs.                                                                                                                                                                        |
| `audit.tools_enabled`       | `bool`      | `true`  | Give the attacker access to tools (`read_file`, `grep`, `list_files`, `lookup_advisory`) for cross-file investigation. Default `true` — without tools, `lookup_advisory` is dead weight and the attacker is blind across files. Costs more LLM round-trips per chunk; mostly offset by `cache.prompt_caching` on Anthropic. Set `false` only if you need the cheapest possible single-file scan. |
| `audit.max_tool_iterations` | `int` (≥ 1) | `8`     | Maximum tool-call rounds per chunk before the attacker is forced to commit to a final answer. Bounds runaway tool use.                                                                                                                                                                                                                                                                           |

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
    model: 'claude-opus-4-5'
```

### Split mode — separate models per role

```yaml
# config/packages/symfony_security_auditor.yaml
symfony_security_auditor:
    attacker_model: 'claude-opus-4-5'   # powerful model for discovery
    reviewer_model: 'claude-haiku-4-5'  # faster model for validation
```

### Full configuration example

```yaml
# config/packages/symfony_security_auditor.yaml
symfony_security_auditor:
    attacker_model: 'claude-opus-4-5'
    reviewer_model: 'claude-haiku-4-5'
    scan:
        excluded_dirs:
            - 'legacy'
            - 'tests/fixtures/generated'
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
  Implement `Audit\Infrastructure\Advisory\AdvisoryDatabaseInterface` in your
  project and override the alias in `config/services.yaml`:

```yaml
# config/services.yaml
services:
    VinceAmstoutz\SymfonySecurityAuditor\Audit\Infrastructure\Advisory\AdvisoryDatabaseInterface:
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
    model: 'claude-opus-4-5?max_tokens=4096&temperature=0.2'
```

### Expanded syntax

```yaml
symfony_security_auditor:
    model:
        name: 'claude-opus-4-5'
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
    attacker_model: 'claude-opus-4-5'   # deep reasoning for vuln discovery
    reviewer_model: 'claude-haiku-4-5'  # fast + cheap for false-positive filtering
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

| Option     | Short | Default   | Description                                                   |
| ---------- | ----- | --------- | ------------------------------------------------------------- |
| `--format` | `-f`  | `console` | Output format: `console` (human-readable), `json`, or `sarif` |
| `--output` | `-o`  | none      | Write the JSON or SARIF report to a file path                 |

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

### Exit codes

| Code | Meaning                                                   |
| ---- | --------------------------------------------------------- |
| `0`  | Audit completed; risk level is SAFE, LOW, MEDIUM, or HIGH |
| `1`  | Risk level is CRITICAL, or the project path is invalid    |
