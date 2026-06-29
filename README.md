# Symfony Security Auditor

[![CI](https://github.com/vinceamstoutz/symfony-security-auditor/actions/workflows/ci.yaml/badge.svg)](https://github.com/vinceamstoutz/symfony-security-auditor/actions/workflows/ci.yaml)
[![codecov](https://codecov.io/gh/vinceamstoutz/symfony-security-auditor/branch/main/graph/badge.svg)](https://codecov.io/gh/vinceamstoutz/symfony-security-auditor)
[![Mutation testing badge](https://img.shields.io/endpoint?style=flat&url=https%3A%2F%2Fbadge-api.stryker-mutator.io%2Fgithub.com%2FvinceAmstoutz%2Fsymfony-security-auditor%2Fmain)](https://dashboard.stryker-mutator.io/reports/github.com/vinceAmstoutz/symfony-security-auditor/main)
[![Total Downloads](https://poser.pugx.org/vinceamstoutz/symfony-security-auditor/downloads)](https://packagist.org/packages/vinceamstoutz/symfony-security-auditor)
[![PHP 8.3+](https://img.shields.io/badge/PHP-8.3%2B-blue)](composer.json)
[![Symfony 7.4+](https://img.shields.io/badge/Symfony-7.4%2B-black)](composer.json)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

AI-powered, multi-agent security auditor for Symfony applications. An
adversarial **Attacker ⚔ Reviewer** loop catches the application-level flaws
SAST tools miss. Provider-agnostic via
[`symfony/ai`](https://symfony.com/doc/current/ai/index.html).

![Symfony Security Auditor](assets/banner.webp?raw=true)

## Why this auditor?

Traditional PHP static analysis tools (PHPStan, Psalm) catch type errors. Static
SAST tools (Psalm Security, Progpilot) follow taint flows but cannot reason
about business logic, missing authorization, or multi-file attack chains.
Dependency scanners (Dependabot, Renovate, Snyk) only flag known CVEs in
third-party packages. This auditor runs alongside them, **targeting the
application-level logic flaws they cannot see**.

Side-by-side comparison with PHPStan, Psalm, Progpilot, Dependabot, and Snyk:
[FAQ](docs/faq.md#comparisons).

## What it does

An adversarial **Attacker** agent hunts for vulnerabilities; a skeptical
**Reviewer** agent culls false positives over up to three iterations — then
emits a validated report in console, JSON, SARIF, HTML, or Markdown.

🔀 **Pipeline**: Ingestion → Mapping → Audit (Attacker ⚔ Reviewer) → Report.

## See it in action

### `--dry-run` mode

![Dry run — token and cost estimate with no LLM calls](assets/dry-run.gif?raw=true)

Scans files and estimates token usage and cost without calling the LLM. Use this
to gauge cost before committing to a full audit.

```bash
bin/console audit:run --dry-run
```

No LLM calls are made; exit code is always `0`.

### Console mode

![Live audit — the Attacker vs Reviewer feed streaming to the validated report](assets/demo.gif?raw=true)

While the pipeline runs, the audit narrates itself live — an attack-surface
overview, each finding streamed (color-coded by severity in a terminal) the
moment the Attacker flags it, per-chunk timing, and a reviewer tally. In CI or
any non-TTY output it degrades to clean, append-only lines (no bar, no ANSI
codes). Progress is suppressed for `--format=json/sarif` to stdout and for
`--dry-run`.

The full report renders the same way in console, JSON, SARIF, HTML, and Markdown
— see [CLI reference](docs/configuration.md#cli-reference) and
[output formats](docs/ci.md#output-formats-reference).

## Getting Started

### 1. Install — Symfony Flex wires everything

```bash
composer require --dev vinceamstoutz/symfony-security-auditor
```

The official
[Flex recipe](https://github.com/symfony/recipes-contrib/tree/main/vinceamstoutz/symfony-security-auditor)
registers the bundle (`dev`/`test`) and drops a pre-configured
`config/packages/symfony_security_auditor.yaml`.

Not using Flex? See
[Manual setup](docs/configuration.md#manual-setup-without-flex).

### 2. Install a platform bridge

```bash
# Anthropic shown
composer require symfony/ai-anthropic-platform
```

Full list of supported providers:
[Configuration → Supported platforms](docs/configuration.md#supported-platforms).

### 3. Configure the platform

```yaml
# config/packages/ai.yaml (or e.g. config/packages/ai_anthropic_platform.yaml)
ai:
  platform:
    anthropic:
      api_key: '%env(ANTHROPIC_API_KEY)%'
```

### 4. Adjust the auditor config

The Flex recipe already created this file — pick your model:

```yaml
# config/packages/symfony_security_auditor.yaml
symfony_security_auditor:
    model: 'claude-opus-4-8'
```

Optionally pick a one-knob preset — `fast`, `balanced` (default), or `thorough`:

```yaml
# config/packages/symfony_security_auditor.yaml
symfony_security_auditor:
    profile: 'fast'
```

A profile only fills the keys you leave unset — any explicitly configured key
always wins. See [Cost & Performance](docs/cost-and-performance.md) for exactly
what each profile sets.

### 5. Run

```bash
# audit the current directory
bin/console audit:run

# or point at another project
bin/console audit:run /path/to/your/symfony/project
```

Want JSON, SARIF, HTML, or Markdown instead? Add
`--format json --output report.json`, `--format sarif --output report.sarif`,
`--format html --output report.html`, or `--format markdown --output report.md`.
See [CLI reference](docs/configuration.md#cli-reference).

Estimate cost before running:

```bash
bin/console audit:run --dry-run
```

> [!WARNING]
>
> **Audit reports list your application's vulnerabilities.** On a **public
> repository**, CI artifacts are publicly downloadable — storing the report
> exposes your attack surface. Prefer GitHub Code Scanning (SARIF, restricted to
> collaborators), private storage (S3/GCS with IAM), or notification-only. See
> [Report Visibility on Public Repositories](docs/ci.md#report-visibility-on-public-repositories).

<!-- -->

> [!TIP]
>
> Schedule the audit as a nightly CI job — the multi-agent LLM loop can take
> minutes, so blocking PRs on it hurts productivity.
> [CI Integration](docs/ci.md) has ready-to-copy GitHub Actions and GitLab CI
> schedules and a split-model config to
> [control API costs](docs/ci.md#managing-llm-costs). For **dependency CVEs**,
> pair it with [Dependabot](https://docs.github.com/en/code-security/dependabot)
> or [Renovate](https://docs.renovatebot.com/) — this auditor targets the
> application-level logic flaws those scanners cannot see.

## Standalone tool (PHAR)

Prefer to run the auditor like PHPStan or Psalm — one install, many projects,
zero footprint in the audited app? Use the standalone executable instead of the
bundle. Configure it **once** at the user level and point it at any project.

```bash
# 1. Download the PHAR from the latest release
curl -L -o symfony-security-auditor.phar \
  https://github.com/vinceAmstoutz/symfony-security-auditor/releases/latest/download/symfony-security-auditor.phar
chmod +x symfony-security-auditor.phar

# 2. Guided setup: writes ~/.config/symfony-security-auditor/config.yaml and
#    downloads the provider bridge you pick into ~/.local/share/…
./symfony-security-auditor.phar init

# 3. Export the API key the config references, then audit any project
export ANTHROPIC_API_KEY=sk-…
./symfony-security-auditor.phar audit /path/to/your/symfony/project
```

Each release also ships a dependency-free native binary
(`symfony-security-auditor`, Linux x64) for hosts without PHP — download it the
same way and run `./symfony-security-auditor audit …`. The PHAR needs a PHP
**8.3+** CLI; see
[platform support](docs/configuration.md#standalone-configuration).

`audit` is an alias for `audit:run`; every option documented in the
[CLI reference](docs/configuration.md#cli-reference) (`--format`, `--output`,
`--dry-run`, `--since`, `--fail-on`, …) works identically. Configuration lives
in `$XDG_CONFIG_HOME/symfony-security-auditor/config.yaml` (rootless — the same
keys as the bundle, without the `symfony_security_auditor:` wrapper) plus a
`platform:` block handed verbatim to `symfony/ai`. See
[configuration](docs/configuration.md#standalone-configuration) for the file
format and provider switching.

## Features

- **Multi-agent loop** — adversarial Attacker + skeptical Reviewer cut false
  positives across up to 3 iterations, with confirmed findings fed back so later
  iterations generalize patterns instead of re-finding the same bugs.
- **39 vulnerability types** covering OWASP-aligned categories: Injection,
  Broken Access Control, Logic Flaws, Symfony-specific, Data Exposure,
  Cryptographic — including the modern Symfony 7.x/8.x surface (Authenticators,
  Messenger handlers, Webhooks, Serializer denormalizers, Schedules,
  RateLimiter, Mailer, cache poisoning).
- **Symfony-aware** — understands Controllers, Voters, Forms, Firewalls, Routes,
  `#[IsGranted]`, `denyAccessUnlessGranted`, `#[MapRequestPayload]`, Twig/Live
  Components, and surfaces controllers without proper access checks.
- **Feature-based chunking** — groups a controller with its entity, repository,
  form, voter, and templates so the Attacker can follow data flow across files.
- **Deterministic pre-scan** — a zero-token risk-marker pass flags concrete
  locations (unserialize, `|raw`, hardcoded secrets, unsafe Doctrine, …) to
  focus the LLM; optional **lean mode** drops marker-free files to cut tokens.
- **Diff mode** — `audit:run --since=main` audits only changed files for fast
  pull-request CI.
- **Cross-file investigation tools** — Attacker (and optionally Reviewer) can
  `read_file`, `grep`, `list_files`, and `lookup_advisory` (zero-config live CVE
  lookups via `composer audit`, backed by Packagist + GitHub Security
  Advisories).
- **One-knob profiles** — `fast`, `balanced`, and `thorough` preset the
  cost/speed/depth levers in a single line; any explicit key still wins.
- **Tunable for speed & cost** — split-model (powerful Attacker + cheap
  Reviewer, ~20× cheaper), concurrent Attacker **and** Reviewer calls
  (`attacker_max_concurrent` / `reviewer_max_concurrent`), Anthropic prompt
  caching on by default (~90% input-token discount), content-hash caching that
  skips identical chunks, cheap→expensive escalation, and code slicing.
- **Secret-safe by default** — credential-shaped strings are scrubbed from file
  content **before** it reaches the LLM (see
  [Security by design](#security-by-design)).
- **Rate-limit aware** — reactive retry with `Retry-After`-aware exponential
  backoff plus an optional proactive token-bucket limiter keep you inside
  provider quotas (see
  [Cost & Performance](docs/cost-and-performance.md#avoiding-rate-limits-429)).
- **PoC synthesis** — optionally attach a concrete, copy-pasteable reproduction
  (curl/console/payload) to every high-severity finding.
- **Five output formats** — `console`, `json`, `sarif` (GitHub Code Scanning /
  GitLab Security Dashboard), `html` (self-contained, shareable), and `markdown`
  (PR-friendly). Baseline suppression: `--generate-baseline` accepts known
  findings, `--baseline` drops them from the report and exit code so only new
  findings fail CI.
- **CI-ready** — a reusable
  [GitHub Action](https://github.com/marketplace/actions/symfony-security-auditor)
  (`uses: vinceamstoutz/symfony-security-auditor@1.12.0`) plus GitLab CI
  templates, with SARIF upload to Code Scanning. See
  [CI Integration](docs/ci.md).
- **DDD architecture** — strict layering and a sole `LLMClientInterface` seam
  let you plug in custom providers, agents, stages, advisory feeds, or report
  formats.

## Security by design

The auditor is conservative about what leaves your machine:

- **Secrets are scrubbed before they leave your machine.** With
  `scan.secret_scrubbing.enabled: true` (the default), credential-shaped strings
  are redacted from file content _before_ it reaches the LLM: AWS / GitHub /
  Stripe / Slack / Google API keys, JWTs, PEM private keys, env-style credential
  assignments, and connection-string URIs with embedded credentials
  (`postgres://user:pass@host`). Add project-specific shapes with
  `scan.secret_scrubbing.additional_patterns`.
- **The cache never stores your source.** The filesystem cache keys LLM
  _responses_ by content hash — no plaintext source code is written to
  `cache.dir`.
- **You choose where the code goes.** Source is sent only to the provider you
  wire in `ai.yaml`. For zero third-party exposure, run fully offline with
  [Ollama](docs/configuration.md#supported-platforms) — nothing leaves your
  network.
- **Reports are sensitive — they list your weak spots.** On public repos, prefer
  SARIF → GitHub Code Scanning (collaborator-only) over downloadable CI
  artifacts. See
  [Report Visibility](docs/ci.md#report-visibility-on-public-repositories).

## Tuning & cost

Profiles (`fast` / `balanced` / `thorough`), split-model, concurrency, caching,
budget caps, and `429` rate-limit handling are covered in
**[Cost & Performance](docs/cost-and-performance.md)** — start with a profile,
then override individual keys as needed.

## Supported Platforms

| Platform             | Bridge package                       | Key env var            |
| -------------------- | ------------------------------------ | ---------------------- |
| Anthropic (Claude)   | `symfony/ai-anthropic-platform`      | `ANTHROPIC_API_KEY`    |
| OpenAI               | `symfony/ai-open-ai-platform`        | `OPENAI_API_KEY`       |
| OpenAI Responses API | `symfony/ai-open-responses-platform` | `OPENAI_API_KEY`       |
| Azure OpenAI         | `symfony/ai-azure-platform`          | `AZURE_OPENAI_API_KEY` |
| Google Gemini        | `symfony/ai-gemini-platform`         | `GEMINI_API_KEY`       |
| Google Vertex AI     | `symfony/ai-vertex-ai-platform`      | GCP credentials        |
| AWS Bedrock          | `symfony/ai-bedrock-platform`        | AWS credentials        |
| DeepSeek             | `symfony/ai-deep-seek-platform`      | `DEEPSEEK_API_KEY`     |
| Mistral              | `symfony/ai-mistral-platform`        | `MISTRAL_API_KEY`      |
| Meta (Llama)         | `symfony/ai-meta-platform`           | `META_API_KEY`         |
| Ollama (local)       | `symfony/ai-ollama-platform`         | _(none)_               |

Swapping providers requires only a `config/packages/ai.yaml` change — no PHP
edits.

## Documentation

- [Configuration](docs/configuration.md) — every config key, all platforms,
  split-model, model options, CLI reference
- [Cost & Performance](docs/cost-and-performance.md) — profiles, split-model,
  concurrency, caching, budgets, and rate-limit handling
- [Architecture](docs/architecture.md) — DDD layers, pipeline, agent loop,
  domain model, design decisions
- [CI Integration](docs/ci.md) — scheduled GitHub Actions & GitLab CI, SARIF
  upload, cost management
- [Extending](docs/extending.md) — custom LLM clients, agents, pipeline stages,
  report formats
- [FAQ](docs/faq.md) — accuracy, cost, privacy, model picks, comparisons
- [Troubleshooting](docs/troubleshooting.md) — empty reports, LLM errors,
  composer audit failures, cache issues
- [Contributing](CONTRIBUTING.md) — dev setup, Docker workflow, QA, PR checklist

## FAQ

**How much does an audit cost?** Depends on project size and model. A medium
Symfony app (~150 files) on Claude Opus + Haiku split-model with prompt caching
enabled costs roughly $0.50 per nightly run. See
[CI → Managing LLM Costs](docs/ci.md#managing-llm-costs).

**Does it send my code to the cloud?** Only to the LLM provider you configure,
and credential-shaped strings are scrubbed first (see
[Security by design](#security-by-design)). For zero-cloud operation, use the
[Ollama local platform](docs/configuration.md#supported-platforms).

Full FAQ — privacy, false positives, model picks, comparisons:
[docs/faq.md](docs/faq.md).

## Contributing

Contributions welcome, please refer to [CONTRIBUTING.md](CONTRIBUTING.md).

## Security

Found a vulnerability **in the auditor itself**? Do **not** open a public issue.
Report privately via
[GitHub Security Advisories](https://github.com/vinceamstoutz/symfony-security-auditor/security/advisories/new).

See [SECURITY.md](SECURITY.md).

## License

[MIT](LICENSE) — Copyright © Vincent Amstoutz
