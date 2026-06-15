# symfony-security-auditor

> **AI-powered multi-agent security auditor for Symfony applications.** Catches
> business logic flaws, broken access control, missing Voters, mass assignment,
> and complex injection chains that traditional SAST tools miss.
> Provider-agnostic via
> [`symfony/ai`](https://symfony.com/doc/current/ai/index.html) — works with
> Claude, GPT, Gemini, Mistral, Llama, DeepSeek, and Ollama.

[![CI](https://github.com/vinceamstoutz/symfony-security-auditor/actions/workflows/ci.yaml/badge.svg)](https://github.com/vinceamstoutz/symfony-security-auditor/actions/workflows/ci.yaml)
[![Total Downloads](https://poser.pugx.org/vinceamstoutz/symfony-security-auditor/downloads)](https://packagist.org/packages/vinceamstoutz/symfony-security-auditor)
![PHP 8.3+](https://img.shields.io/badge/PHP-8.3%2B-blue)
![Symfony 7.4+](https://img.shields.io/badge/Symfony-7.4%2B-black)
![License MIT](https://img.shields.io/badge/License-MIT-green)
[![SemVer 2.0.0](https://img.shields.io/badge/SemVer-2.0.0-brightgreen)](docs/versioning.md)

---

## Table of Contents

- [What it does](#what-it-does)
- [Getting Started](#getting-started)
- [Features](#features)
- [Why this auditor?](#why-this-auditor)
- [Example Output](#example-output)
- [Supported Platforms](#supported-platforms)
- [Documentation](#documentation)
- [FAQ](#faq)
- [Contributing](#contributing)
- [Security](#security)
- [License](#license)

---

## What it does

Feeds your Symfony project through a three-stage AI pipeline that catches what
SAST tools miss: broken access control, complex injection chains, business logic
flaws, missing Voters, and mass assignment vulnerabilities. An adversarial
**Attacker** agent hunts for issues; a skeptical **Reviewer** agent eliminates
false positives over up to three iterations. Output is a validated vulnerability
report in your console, as JSON, or as SARIF for GitHub Code Scanning / GitLab
Security Dashboard.

```text
  Project files
       │
       ▼
  1. Ingestion — scans .php / .twig / .yaml / .xml recursively
       │
       ▼
  2. Mapping — classifies Controllers, Entities, Voters, Forms, Routes
       │
       ▼
  3. Audit — Attacker ⚔ Reviewer multi-agent loop (up to 3 iterations)
       │
       ▼
  Validated vulnerability report: console, JSON, or SARIF
```

---

## Getting Started

### 1. Install — Symfony Flex wires everything

```bash
composer require --dev vinceamstoutz/symfony-security-auditor
```

The official
[Flex recipe](https://github.com/symfony/recipes-contrib/tree/main/vinceamstoutz/symfony-security-auditor)
(published in
[`symfony/recipes-contrib`](https://github.com/symfony/recipes-contrib))
automatically:

- registers `SymfonySecurityAuditorBundle` in `config/bundles.php` for the `dev`
  and `test` environments;
- creates a pre-configured `config/packages/symfony_security_auditor.yaml` with
  a default model and commented split-model and rate-limit examples ready to
  uncomment.

Not using Flex? See [Manual setup](#manual-setup-without-flex).

### 2. Install a platform bridge (Anthropic shown)

```bash
composer require symfony/ai-anthropic-platform
```

Full list of supported providers:
[Configuration → Supported platforms](docs/configuration.md#supported-platforms).

### 3. Configure the platform (`config/packages/ai.yaml`)

```yaml
ai:
  platform:
    anthropic:
      api_key: '%env(ANTHROPIC_API_KEY)%'
```

### 4. Adjust the auditor config (`config/packages/symfony_security_auditor.yaml`)

The Flex recipe already created this file — pick your model:

```yaml
symfony_security_auditor:
    model: 'claude-opus-4-8'
```

Optionally pick a one-knob preset — `fast`, `balanced` (default), or `thorough`;
any explicitly configured key always wins:

```yaml
symfony_security_auditor:
    profile: 'fast'
```

### 5. Run

```bash
# audit the current directory
bin/console audit:run

# or point at another project
bin/console audit:run /path/to/your/symfony/project
```

Want JSON, SARIF, or HTML instead? Add `--format json --output report.json`,
`--format sarif --output report.sarif`, or `--format html --output report.html`.
See [CLI reference](docs/configuration.md#cli-reference).

Estimate cost before running:

```bash
bin/console audit:run --dry-run
```

> [!WARNING]
>
> **Security audit reports contain a list of vulnerabilities in your
> application.** On a **public repository**, GitHub Actions artifacts and GitLab
> CI artifacts are publicly downloadable — storing the report as an artifact
> exposes your attack surface to anyone.
>
> Safe options: **GitHub Code Scanning** (SARIF upload — restricted to
> collaborators even on public repos), **external private storage** (S3, GCS
> with IAM), or **notification-only** (Slack/email, no stored file). See
> [Report Visibility on Public Repositories](docs/ci.md#report-visibility-on-public-repositories)
> for details.

### Manual setup (without Flex)

Without Symfony Flex (or with `composer require --no-scripts`), do by hand what
the recipe automates:

1. Register the bundles in `config/bundles.php`:

   ```php
   return [
       // ...
       Symfony\AI\AiBundle\AiBundle::class => ['all' => true],
       VinceAmstoutz\SymfonySecurityAuditor\SymfonySecurityAuditorBundle::class => ['dev' => true, 'test' => true],
   ];
   ```

2. Create `config/packages/symfony_security_auditor.yaml` yourself (step 4
   above), or copy the
   [recipe's template](https://github.com/symfony/recipes-contrib/blob/main/vinceamstoutz/symfony-security-auditor/1.0/config/packages/symfony_security_auditor.yaml).

---

> [!TIP]
>
> Schedule the audit as a nightly CI job — the multi-agent LLM loop can take
> minutes, so blocking PRs on it hurts productivity. See
> [CI Integration](docs/ci.md) for ready-to-copy GitHub Actions and GitLab CI
> schedules (SARIF → Code Scanning / Security Dashboard). Use a split-model
> config (large attacker, cheap reviewer) to
> [control API costs](docs/ci.md#managing-llm-costs).
>
> For **dependency CVEs**, use
> [Dependabot](https://docs.github.com/en/code-security/dependabot) or
> [Renovate](https://docs.renovatebot.com/) — they automate `composer audit`
> checks and open PRs automatically. This auditor targets **application-level**
> logic flaws (broken access control, injection chains, missing Voters) that
> static dependency scanners cannot see.

---

## Features

- **Symfony Flex recipe** — one `composer require` registers the bundle and
  ships a pre-configured `symfony_security_auditor.yaml`
  ([official recipe](https://github.com/symfony/recipes-contrib/tree/main/vinceamstoutz/symfony-security-auditor)
  in `symfony/recipes-contrib`).
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
- **Cost levers** — opt-in cheap→expensive escalation, code slicing, concurrent
  reviewer calls, and lean pre-scan to dial token spend up or down.
- **Provider-agnostic** — swap Claude / GPT / Gemini / Mistral / Llama /
  DeepSeek / Ollama with a 2-line YAML change. No code edits.
- **Cross-file investigation tools** — Attacker (and optionally Reviewer) can
  `read_file`, `grep`, `list_files`, and `lookup_advisory` (live CVE lookups via
  `composer audit`).
- **PoC synthesis** — optionally attach a concrete, copy-pasteable reproduction
  (curl/console/payload) to every high-severity finding.
- **Split-model support** — pair a powerful Attacker (e.g. Claude Opus) with a
  fast Reviewer (e.g. Claude Haiku) to cut cost ~20×.
- **Prompt caching** — Anthropic prompt caching enabled by default (~90%
  input-token discount), silently ignored elsewhere.
- **Content-hash cache** — identical chunks skip the LLM entirely. Massive
  savings on repeated CI runs.
- **Four output formats** — `console` (human-readable), `json`
  (machine-readable), `sarif` (GitHub Code Scanning / GitLab Security
  Dashboard), and `html` (self-contained, shareable report).
- **Baseline suppression** — accept known findings with `--generate-baseline`,
  then `--baseline` drops them from the report and the exit code so only new
  findings fail CI.
- **CI-ready** — a reusable
  [GitHub Action](https://github.com/marketplace/actions/symfony-security-auditor)
  (`uses: vinceamstoutz/symfony-security-auditor@1.11.0`) plus GitLab CI
  templates, with SARIF upload to Code Scanning. See
  [CI Integration](docs/ci.md).
- **Zero-config CVE feed** — `lookup_advisory` is backed by `composer audit`
  (Packagist + GitHub Security Advisories) out of the box.
- **DDD architecture** — strict layering, sole `LLMClientInterface` seam means
  you can plug in custom providers, agents, stages, advisory feeds, or report
  formats.

---

## Why this auditor?

Traditional **PHP static analysis** tools (PHPStan, Psalm) catch type errors.
**Static SAST tools** (Psalm Security, Progpilot) follow taint flows but cannot
reason about business logic, missing authorization, or multi-file attack chains.
**Dependency scanners** (Dependabot, Renovate, Snyk) only flag known CVEs in
third-party packages.

| Concern                                 | This auditor               | PHPStan / Psalm | Psalm Security / Progpilot (SAST) | Dependabot / Snyk |
| --------------------------------------- | -------------------------- | --------------- | --------------------------------- | ----------------- |
| Type bugs                               | ❌                         | ✅              | partial                           | ❌                |
| Taint flow (SQLi, XSS)                  | ✅                         | ❌              | ✅                                | ❌                |
| Missing `#[IsGranted]` / Voter          | ✅                         | ❌              | ❌                                | ❌                |
| Business logic flaws                    | ✅                         | ❌              | ❌                                | ❌                |
| IDOR / mass assignment                  | ✅                         | ❌              | partial                           | ❌                |
| Firewall misconfiguration               | ✅                         | ❌              | ❌                                | ❌                |
| Cross-file attack chains                | ✅                         | ❌              | partial                           | ❌                |
| Dependency CVEs                         | ✅ (via `lookup_advisory`) | ❌              | ❌                                | ✅                |
| OWASP Top 10 application-level coverage | ✅                         | ❌              | partial                           | ❌                |

> **Use this alongside — not instead of — PHPStan/Psalm and Dependabot.** It
> targets the application-level logic flaws those tools cannot see.

---

## Example Output

### Console mode (truncated)

The command renders a live progress bar while the pipeline runs (suppressed for
`--format=json/sarif` to stdout and for `--dry-run`):

```text
 Running audit pipeline...
 ─────────────────────────
 1/3 [=======>                  ]  33% — ingestion
 2/3 [===============>          ]  67% — mapping
 3/3 [==========================] 100% — audit
```

Full output after the pipeline completes:

```text
══════════════════════════════════════════════════════════════════════
  🔍 SYMFONY LLM AUDIT REPORT — AUDIT-a1b2c3d4
  vinceamstoutz/symfony-security-auditor
══════════════════════════════════════════════════════════════════════

  Project : /var/www/my-app
  Started : 2026-05-22 09:14:02
  Duration: 2m 31s
  Files   : 142 scanned

──────────────────────────────────────────────────────────────────────
  RISK LEVEL: HIGH  (Score: 34)
──────────────────────────────────────────────────────────────────────

  [1] VULN-7f3a1b2c   CRITICAL    broken_access_control
      src/Controller/AdminController.php:42-58
      Title: Missing #[IsGranted] on admin DELETE endpoint
      OWASP: A01:2021 — Broken Access Control
      Confidence: 0.95   Reviewer: ✓ validated

  [2] VULN-2e9d5c1a   HIGH        mass_assignment
      src/Controller/UserController.php:71-89
      Title: Form type binds isAdmin field from untrusted request
      OWASP: A04:2021 — Insecure Design
      Confidence: 0.88   Reviewer: ✓ validated

  ... (3 more findings)
```

### `--dry-run` mode

Scans files and estimates token usage and cost without calling the LLM. Use this
to gauge cost before committing to a full audit.

```bash
bin/console audit:run --dry-run
```

```text
 Symfony LLM Security Auditor
 =============================

 Project: /var/www/my-app
 Pipeline: Ingestion → Mapping → Audit (Attacker ⚔ Reviewer)

 Estimating audit cost (dry run)...
 ───────────────────────────────────

 * Model : claude-opus-4-8
 * Tokens: 52,400 in / 4,200 out (total: 56,600)
 * Cost  : $0.3670 (estimate)

 ! [NOTE] Dry run — no LLM calls were made. This is a cost estimate only.

 [OK] Dry run complete.
```

No LLM calls are made; exit code is always `0`.

JSON / SARIF formats are documented in
[CLI Reference](docs/configuration.md#cli-reference) and
[Output Formats Reference](docs/ci.md#output-formats-reference).

---

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

---

## Documentation

- [Configuration](docs/configuration.md) — every config key, all platforms,
  split-model, model options, CLI reference
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

---

## FAQ

**Is this a replacement for PHPStan or Psalm?** No. PHPStan/Psalm catch type
errors; this auditor catches application-level logic flaws (missing
authorization, mass assignment, business logic bugs). Use both.

**How much does an audit cost?** Depends on project size and model. A medium
Symfony app (~150 files) on Claude Opus + Haiku split-model with prompt caching
enabled costs roughly $0.50 per nightly run. See
[CI → Managing LLM Costs](docs/ci.md#managing-llm-costs).

**Does it send my code to the cloud?** Only to the LLM provider you configure.
For zero-cloud operation, use the
[Ollama local platform](docs/configuration.md#supported-platforms). See
[FAQ → Privacy](docs/faq.md#does-this-send-my-source-code-to-a-third-party).

**Are false positives a problem?** The Reviewer agent filters them out — only
`reviewer_validated` findings appear in the final report. Tune
`audit.min_confidence` (default `0.6`) up for stricter precision, down for
higher recall.

**Which model should I pick?** For accuracy: Claude Opus / GPT-4o / Gemini 2.5
Pro. For speed/cost: Claude Haiku / DeepSeek / Mistral Large. For zero-cost
local: Ollama (`llama3.3`, `deepseek-r1`). See
[FAQ → Model picks](docs/faq.md#which-llm-model-should-i-use).

Full FAQ: [docs/faq.md](docs/faq.md).

---

## Contributing

Contributions welcome, please refer to [CONTRIBUTING.md](CONTRIBUTING.md).

---

## Security

Found a vulnerability **in the auditor itself**? Do **not** open a public issue.
Report privately via
[GitHub Security Advisories](https://github.com/vinceamstoutz/symfony-security-auditor/security/advisories/new).
See [SECURITY.md](SECURITY.md).

---

## License

[MIT](LICENSE) — Copyright © Vincent Amstoutz
