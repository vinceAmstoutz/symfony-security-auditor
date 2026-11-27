# Symfony Security Auditor

[![CI](https://github.com/vinceamstoutz/symfony-security-auditor/actions/workflows/ci.yaml/badge.svg)](https://github.com/vinceamstoutz/symfony-security-auditor/actions/workflows/ci.yaml) [![codecov](https://codecov.io/gh/vinceamstoutz/symfony-security-auditor/branch/main/graph/badge.svg)](https://codecov.io/gh/vinceamstoutz/symfony-security-auditor) [![Mutation testing badge](https://img.shields.io/endpoint?style=flat&url=https%3A%2F%2Fbadge-api.stryker-mutator.io%2Fgithub.com%2FvinceAmstoutz%2Fsymfony-security-auditor%2Fmain)](https://dashboard.stryker-mutator.io/reports/github.com/vinceAmstoutz/symfony-security-auditor/main) [![Total Downloads](https://poser.pugx.org/vinceamstoutz/symfony-security-auditor/downloads)](https://packagist.org/packages/vinceamstoutz/symfony-security-auditor) [![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

AI-powered, multi-agent security auditor for Symfony applications. An adversarial **Attacker ⚔ Reviewer** loop catches the application-level flaws SAST tools miss. Provider-agnostic via [`symfony/ai`](https://symfony.com/doc/current/ai/index.html).

![Symfony Security Auditor](assets/banner.webp?raw=true)

> [!NOTE]
>
> `main` holds **exactly the latest release**, so everything documented here is in the version you install. Development happens on [version branches](docs/versioning.md#branches--maintenance).

## Why this auditor?

Traditional PHP static analysis tools (PHPStan, Psalm) catch type errors. Static SAST tools (Psalm Security, Progpilot) follow taint flows but cannot reason about business logic, missing authorization, or multi-file attack chains. Dependency scanners (Dependabot, Renovate, Snyk) only flag known CVEs in third-party packages. This auditor runs alongside them, **targeting the application-level logic flaws they cannot see**.

Side-by-side comparison with PHPStan, Psalm, Progpilot, Dependabot and Snyk: [FAQ](docs/faq.md#comparisons).

## What it does

An adversarial **Attacker** agent hunts for vulnerabilities; a skeptical **Reviewer** agent culls false positives over up to three iterations, then emits a validated report in console, JSON, SARIF, HTML, or Markdown.

🔀 **Pipeline**: Ingestion → Mapping → Audit (Attacker ⚔ Reviewer) → Report.

## See it in action

### Live audit

![Live audit: the Attacker vs Reviewer feed streaming to the validated report](assets/demo.gif?raw=true)

While the pipeline runs, the audit narrates itself live: an attack-surface overview, each finding streamed (color-coded by severity in a terminal) the moment the Attacker flags it, per-chunk timing and a reviewer tally. In CI or any non-TTY output it degrades to clean, append-only lines (no bar, no ANSI codes). Progress is suppressed for any non-`console` `--format` to stdout and for `--dry-run`.

The full report renders the same way in console, JSON, SARIF, HTML and Markdown: see [CLI reference](docs/configuration.md#cli-reference) and [output formats](docs/configuration.md#output-formats-reference).

### Cost estimate with `--dry-run`

![Dry run: token and cost estimate with no LLM calls](assets/dry-run.gif?raw=true)

Scans files and estimates token usage and cost without calling the LLM. Use this to gauge cost before committing to a full audit.

```bash
bin/console audit:run --dry-run
```

No LLM calls are made; the exit code is `0` unless the command is refused before the estimate (an invalid option or project path, or a `--path` outside the project), which exits `1`.

## Getting Started

The auditor ships two maintained ways to run it. Pick the one that fits:

- **[Standalone CLI](#standalone-tool-binary) (recommended)**: one download, configured once, audits any project with zero footprint in it. Best for most users and for auditing a project you don't want to add a dependency to.
- **[Symfony bundle](#use-it-as-a-symfony-bundle)**: wired into a Symfony app via Flex. Pick this to extend the auditor (custom services, decorated ports) or to pin it in the app's `dev` dependencies.

> [!TIP]
>
> Both expose the same `audit` command, options and output formats (see the [CLI reference](docs/configuration.md#cli-reference)) and both can serve the auditor to your AI assistant over [MCP](#use-it-from-your-ai-assistant-mcp) (experimental). To move an existing setup from one to the other, follow [Switching Between the Standalone Binary and the Bundle](docs/switching-standalone-bundle.md).

## Standalone tool (binary)

One install, many projects, zero footprint in the audited app. Each release ships a **self-contained native binary** with its own PHP runtime for Linux, macOS and Windows.

### Requirements

Nothing but the binary and access to a model: an API key, a Claude or ChatGPT subscription through its CLI, or a [local model](#supported-platforms) such as Ollama. No PHP or Composer: the one-time [`init`](#2-configure-the-guided-init) fetches the provider bridge with the Composer the binary bundles. `--since` needs `git`. Live CVE lookups run `composer audit` with that bundled Composer too.

### 1. Install

```bash
# Linux, macOS, Windows under WSL
curl -fsSL https://raw.githubusercontent.com/vinceAmstoutz/symfony-security-auditor/main/install.sh | sh
```

```powershell
# Native Windows (PowerShell, Git Bash, MSYS, Cygwin)
irm https://raw.githubusercontent.com/vinceAmstoutz/symfony-security-auditor/main/install.ps1 | iex
```

Both detect your OS and CPU, download the matching binary and **abort** rather than install one whose SHA-256 checksum they cannot verify. You can also download an asset from the [latest release](https://github.com/vinceAmstoutz/symfony-security-auditor/releases/latest) and check it with its `.sha256` file.

> [!TIP]
>
> Set `SSA_INIT=1` on either command and the installer runs the guided [`init`](#2-configure-the-guided-init) right after downloading (`$env:SSA_INIT = '1'` in PowerShell). With a terminal it prompts for your provider and API key; in a pipe or CI it takes the Anthropic defaults and stores no key.

### 2. Configure: the guided `init`

```bash
symfony-security-auditor init
```

`init` asks how you access AI models (subscription, API key, local model, gateway or cloud account), lists the matching providers and models with their price, installs the provider bridge and takes your API key invisibly. Press Enter to skip it and run `auth:set` later, or keep using an environment variable. It writes `~/.config/symfony-security-auditor/config.yaml` (`%APPDATA%\symfony-security-auditor\config.yaml` on Windows), which takes the bundle's keys without the `symfony_security_auditor:` wrapper plus a `platform:` block. See [configuration](docs/configuration.md#standalone-configuration). It can end by sending one test request (`doctor --check-connection`).

Check the setup at any time with `doctor`, before you spend a token: configuration and API key, provider bridge, Composer and pricing catalog. It exits `1` when a check fails, so it drops into a CI preflight step. See [`doctor`](docs/configuration.md#doctor-preflight-environment-check).

```bash
symfony-security-auditor doctor
```

![Doctor: the standalone binary checks its configuration, provider bridge, Composer and pricing catalog](assets/doctor.gif?raw=true)

### 3. Run

```bash
symfony-security-auditor audit /path/to/your/symfony/project
```

`audit` is an alias for `audit:run`; every option of the [CLI reference](docs/configuration.md#cli-reference) (`--format`, `--output`, `--dry-run`, `--since`, `--fail-on`, …) works identically. Every run names the key it is about to spend, masked (`API key: sk-ant…qF4A`).

#### Managing the stored key

| Command | What it does |
| --- | --- |
| `auth:set` | Store or replace the key: prompts invisibly, writes an owner-only file |
| `auth:status` | Show which key an audit would use, where it came from and its SHA-256 fingerprint (never the key) |
| `auth:test` | Send one short test request to check the provider answers |
| `auth:remove` | Forget the stored key on this machine |

The key lives in an owner-only `credentials.json` next to your config, which an audit refuses to read if other users can. **An exported variable always wins**, so Docker, Kubernetes and CI are unchanged: `ANTHROPIC_API_KEY=$(pass show anthropic/api-key) symfony-security-auditor audit .`. Storing nothing is fine too: [Providing the API key](docs/configuration.md#providing-the-api-key) covers environment variables, mounted secret files, password managers and CI secrets.

### 4. Keep it up to date

```bash
symfony-security-auditor self-update          # download + verify + replace, if newer
symfony-security-auditor self-update --check  # only report whether a newer version exists
```

`self-update` verifies the checksum before replacing the binary. See the [CLI reference](docs/configuration.md#self-update-updating-the-standalone-binary). `self-update --snapshot` (or `SSA_VERSION=snapshot` with the installers) installs the pre-release built from every push to the development branch; a plain `self-update` returns to the latest release.

### 5. Shell completion (optional)

`symfony-security-auditor completion bash|zsh|fish` prints a script that makes <kbd>Tab</kbd> complete commands, options and arguments. [Shell completion](docs/configuration.md#shell-completion) shows where each shell loads it from. You write it once: it keeps working after a `self-update`.

## Use it as a Symfony bundle

### 1. Install: Symfony Flex wires everything

Installing the bundle requires **PHP 8.3+ and Symfony 7.4+** in the host application (see [`composer.json`](composer.json)).

```bash
composer require --dev vinceamstoutz/symfony-security-auditor
```

The official [Flex recipe](https://github.com/symfony/recipes-contrib/tree/main/vinceamstoutz/symfony-security-auditor) registers the bundle (`dev`/`test`) and drops a pre-configured `config/packages/symfony_security_auditor.yaml`.

Not using Flex? See [Manual setup](docs/configuration.md#manual-setup-without-flex).

### 2. Install a platform bridge

```bash
# Anthropic shown
composer require symfony/ai-anthropic-platform
```

Full list of supported providers: [Configuration → Supported platforms](docs/configuration.md#supported-platforms).

### 3. Configure the platform

```yaml
# config/packages/ai.yaml (or e.g. config/packages/ai_anthropic_platform.yaml)
ai:
  platform:
    anthropic:
      api_key: '%env(ANTHROPIC_API_KEY)%'
```

### 4. Adjust the auditor config

The Flex recipe already created this file. Pick your model and report what the deterministic scans find (redacted secrets, pre-scan matches) as reviewed findings:

```yaml
# config/packages/symfony_security_auditor.yaml
symfony_security_auditor:
    model: 'claude-opus-5-5'
    audit:
        report_static_findings: true
```

Optionally pick a one-knob preset, `fast`, `balanced` (default), or `thorough`:

```yaml
# config/packages/symfony_security_auditor.yaml
symfony_security_auditor:
    profile: 'fast'
```

A profile only fills the keys you leave unset: any explicitly configured key always wins. See [Cost & Performance](docs/cost-and-performance.md) for exactly what each profile sets.

### 5. Run

```bash
# audit the current directory (`bin/console audit` is an equivalent alias)
bin/console audit:run

# or point at another project
bin/console audit:run /path/to/your/symfony/project
```

Want JSON, SARIF, HTML, or Markdown instead? Add `--format json --output report.json`, `--format sarif --output report.sarif`, `--format html --output report.html`, or `--format markdown --output report.md`. See [CLI reference](docs/configuration.md#cli-reference).

Estimate cost before running:

```bash
bin/console audit:run --dry-run
```

> [!WARNING]
>
> **Audit reports list your application's vulnerabilities.** On a **public repository**, CI artifacts are publicly downloadable, so storing the report exposes your attack surface. Prefer GitHub Code Scanning (SARIF, restricted to collaborators), private storage (S3/GCS with IAM), or notification-only. See [Report Visibility on Public Repositories](docs/ci.md#report-visibility-on-public-repositories).

<!-- -->

> [!TIP]
>
> Schedule the audit as a nightly CI job: the multi-agent LLM loop can take minutes, so blocking PRs on it hurts productivity. [CI Integration](docs/ci.md) has ready-to-copy GitHub Actions and GitLab CI schedules and a split-model config to [control API costs](docs/ci.md#managing-llm-costs). For **dependency CVEs**, pair it with [Dependabot](https://docs.github.com/en/code-security/dependabot) or [Renovate](https://docs.renovatebot.com/). This auditor targets the application-level logic flaws those scanners cannot see.

## Use it from your AI assistant (MCP)

> [!WARNING]
>
> **`mcp:serve` is experimental.** The command, the `audit` tool and its input schema may change in any release (including a `MINOR` or `PATCH` one) and are not covered by the [backward compatibility promise](docs/versioning.md#experimental-features).

`mcp:serve` starts a [Model Context Protocol](https://modelcontextprotocol.io) server, so any MCP client (Claude Code, Claude Desktop, Cursor, VS Code, Windsurf, Gemini CLI, Codex CLI, …) can audit a project on request and read back the JSON report. It works from the standalone binary and from the bundle alike:

```bash
# Claude Code, with the standalone binary
claude mcp add --transport stdio symfony-security-auditor -- symfony-security-auditor mcp:serve
```

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

The second snippet is the shape Claude Desktop, Cursor, Windsurf and Gemini CLI read; with the bundle, use `"command": "php"` and `"args": ["/absolute/path/to/bin/console", "mcp:serve"]`.

With the binary, the server reads its configuration once, when it starts (your user config and the `.symfony-security-auditor.yaml` of the folder it starts in) and applies it to every project it audits, never the audited project's own file: start it from the project it will audit (see [Per-project overrides](docs/configuration.md#per-project-overrides)).

> [!NOTE]
>
> The audit still runs on **your configured provider and model**, not on the assistant's, so it needs the same API key as a CLI run. With the binary, store it once with `auth:set` so a desktop client finds it. Point the auditor at a local Ollama and it needs no key at all. Setup for every client, including VS Code and Codex CLI: [`mcp:serve`](docs/configuration.md#mcpserve-model-context-protocol-server).

## Features

- **Finds what SAST tools miss**: an Attacker agent hunts, a Reviewer agent rejects false positives, over up to three rounds: broken access control, IDOR, business-logic flaws, injections and 50 vulnerability types mapped to OWASP and CWE.
- **Knows Symfony**: controllers, voters, firewalls, `access_control`, forms, `#[IsGranted]`, `#[MapRequestPayload]`, Twig and Live Components, Messenger, Webhooks, API Platform. It flags routes without an access check and reads a controller together with its entity, repository, form, voter and templates.
- **Pull-request ready**: `--since=main` audits only the changed files. The [GitHub Action](https://github.com/marketplace/actions/symfony-security-auditor) (`uses: vinceamstoutz/symfony-security-auditor@1.22.1`) posts annotations, a PR comment and one-click fix suggestions; SARIF feeds GitHub Code Scanning and GitLab. See [CI Integration](docs/ci.md).
- **Actionable findings**: each one has its file and line, a CVSS v4.0 estimate and a remediation, plus, on request, a reproduction and a suggested patch.
- **Any model**: Claude, GPT, Gemini, Mistral, DeepSeek, Bedrock, Azure OpenAI, any OpenAI-compatible gateway, a local Ollama, or your Claude or ChatGPT subscription.
- **Private by default**: secrets are scrubbed before any code leaves your machine; `privacy.offline_only` enforces a fully local run (see [Security by design](#security-by-design)).
- **Cost under control**: `--dry-run` estimates the bill, budgets stop a run at a cap. Profiles, split models, caching and concurrency cut cost and time (see [Cost & Performance](docs/cost-and-performance.md)).
- **Works with your other tools**: imports PHPStan, Psalm or Semgrep results as leads through SARIF and checks dependency CVEs with `composer audit`.
- **Nine report formats**: console, executive summary, JSON, SARIF, HTML, Markdown, JUnit, GitHub annotations and PR comment. A baseline and `--min-score` let CI fail on new findings only.
- **Findings over time**: `audit:diff` compares two reports, `audit:trend` tracks a series, `audit:baseline` maintains accepted findings.
- **From your AI assistant**: `mcp:serve` (experimental) lets Claude Code, Cursor, VS Code or any MCP client run an audit.
- **Extensible**: strict DDD layers behind one `LLMClientInterface` seam for custom providers, stages, advisory feeds or report formats; project-specific attacker rules need only configuration.
- **Bundle or standalone**: add it to a Symfony app, or audit any project with one self-contained binary, kept current by `self-update` and checked by `doctor`.

## Security by design

The auditor is conservative about what leaves your machine:

- **Secrets are scrubbed before they leave your machine.** With `scan.secret_scrubbing.enabled: true` (the default), credential-shaped strings are redacted from file content _before_ it reaches the LLM: AWS / GitHub / Stripe / Slack / Google API keys, JWTs, PEM private keys, Symfony secrets-vault decryption keys, env-style credential assignments, `Authorization` headers, connection-string URIs with embedded credentials (`postgres://user:pass@host`) and the credentials passed in code to PDO, LDAP, Redis or HttpClient. Add project-specific shapes with `scan.secret_scrubbing.additional_patterns`.
- **The cache never stores your files.** The filesystem cache keys LLM _responses_ by content hash. An entry holds the findings the model reported (with the short source excerpts it quoted) and the reviewer's reasoning (never a project file), so treat `cache.dir` like a report: keep it out of shared CI caches and public artifacts.
- **You choose where the code goes.** Source is sent only to the provider you wire in `ai.yaml`. For zero third-party exposure, run fully offline with [Ollama](docs/configuration.md#supported-platforms): nothing leaves your network. Set [`privacy.offline_only: true`](docs/configuration.md#privacy-data-egress) to have that enforced rather than assumed: the advisory feed is dropped (no `composer audit`) and the standalone CLI refuses to boot against a platform endpoint that is not loopback or private-range. `docs/faq.md` carries a `tcpdump` recipe for verifying it yourself.
- **Reports are sensitive: they list your weak spots.** On public repos, prefer SARIF → GitHub Code Scanning (collaborator-only) over downloadable CI artifacts. See [Report Visibility](docs/ci.md#report-visibility-on-public-repositories).

## Supported Platforms

Any platform `symfony/ai` supports (Anthropic, OpenAI, Azure OpenAI, Gemini, Vertex AI, Bedrock, Mistral, DeepSeek, Ollama, OpenRouter, any OpenAI-compatible gateway through the generic platform and more), plus a Claude or ChatGPT subscription through the Claude Code or Codex CLI. Swapping providers is a configuration change, no PHP edits. Bridges, keys and examples: [Configuration → Supported platforms](docs/configuration.md#supported-platforms).

## Documentation

- [Configuration](docs/configuration.md): every config key, all platforms, split-model, model options, CLI reference
- [Switching Binary and Bundle](docs/switching-standalone-bundle.md): move a setup from the standalone binary to the bundle and back
- [Cost & Performance](docs/cost-and-performance.md): profiles, split-model, concurrency, caching, budgets and rate-limit handling
- [Architecture](docs/architecture.md): DDD layers, pipeline, agent loop, domain model, design decisions
- [CI Integration](docs/ci.md): scheduled GitHub Actions & GitLab CI, SARIF upload, cost management
- [Extending](docs/extending.md): custom LLM clients, agents, pipeline stages, report formats
- [FAQ](docs/faq.md): accuracy, cost, privacy, model picks, comparisons
- [Troubleshooting](docs/troubleshooting.md): empty reports, LLM errors, composer audit failures, cache issues
- [Contributing](CONTRIBUTING.md): dev setup, Docker workflow, QA, PR checklist

## Contributing

Contributions welcome, please refer to [CONTRIBUTING.md](CONTRIBUTING.md).

## Security

Found a vulnerability **in the auditor itself**? Do **not** open a public issue. Report privately via [GitHub Security Advisories](https://github.com/vinceamstoutz/symfony-security-auditor/security/advisories/new).

See [SECURITY.md](SECURITY.md).

## License

[MIT](LICENSE). Copyright © Vincent Amstoutz
