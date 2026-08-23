# Frequently Asked Questions

Common questions about **symfony-security-auditor** — an AI-powered multi-agent
security auditor for Symfony applications.

## Table of Contents

- [About the project](#about-the-project)
- [Comparisons](#comparisons)
- [Accuracy & False Positives](#accuracy--false-positives)
- [Cost & Performance](#cost--performance)
- [Privacy & Data Handling](#privacy--data-handling)
- [Model Selection](#model-selection)
- [Compatibility](#compatibility)
- [Integration & Workflow](#integration--workflow)
- [Customization](#customization)

> See also: [Configuration](configuration.md) · [Architecture](architecture.md)
> · [CI Integration](ci.md) · [Troubleshooting](troubleshooting.md)

## About the project

### What does it do?

It feeds your Symfony project through a three-stage AI pipeline:

1. **Ingestion** — scans `.php`, `.twig`, `.yaml`, `.yml`, `.xml` files
   recursively.
2. **Mapping** — classifies files as Controllers, Entities, Voters, Forms,
   Repositories, Templates, Config; builds a route/firewall map.
3. **Audit** — an adversarial Attacker agent hunts for vulnerabilities; a
   skeptical Reviewer agent validates each finding. Up to 3 iterations, stops
   earlier when no new findings emerge.

Output is a validated vulnerability report in your console, as JSON, or as SARIF
for GitHub Code Scanning / GitLab Security Dashboard.

### What kinds of vulnerabilities does it catch?

49 types across six categories (OWASP-aligned):

- **Injection** — SQL, command, LDAP, XPath, Twig, header.
- **Broken Access Control** — missing Voter, Voter bypass, role escalation,
  IDOR, missing CSRF.
- **Logic Flaw** — business logic, race condition, state machine bypass, price
  manipulation, insecure workflow.
- **Symfony-Specific** — mass assignment, insecure deserialization, unsafe
  parameter binding, misconfigured firewall, insecure redirect, exposed internal
  service.
- **Data Exposure** — sensitive data leak, log injection, path traversal, SSRF,
  XXE, open redirect.
- **Cryptographic** — weak crypto, insecure random, hardcoded secret.

Full enum:
[`Audit/Domain/Model/VulnerabilityType.php`](../src/Audit/Domain/Model/VulnerabilityType.php).

### Is it a SAST tool?

It is **closer to AI-assisted SAST + business logic auditing** than traditional
static analysis. It does not perform pure AST-based taint tracking — it gives
the LLM the source code (plus optional `read_file` / `grep` / `list_files` /
`lookup_advisory` tools) and asks it to reason about security.

It detects classes of bug pure SAST tools cannot see (missing authorization,
broken business logic, multi-file attack chains) at the cost of nondeterministic
output and a per-run LLM cost.

### Is it ready for production use?

The auditor is actively developed. Output is validated by a Reviewer agent
before being included in the final report. A **scheduled nightly CI job**
alongside existing tools (PHPStan / Psalm / Dependabot) is the lowest-friction
default, but gating pull requests directly is also supported: scope the run to
changed files with `--since`, then gate on `--fail-on` / `--min-score`, with
baseline suppression (`--baseline`/`--generate-baseline`) so previously-accepted
findings don't fail CI. See [CI Integration](ci.md).

## Comparisons

Where this auditor fits among the tools you already run:

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

### How does it compare to PHPStan or Psalm?

PHPStan and Psalm catch **type errors** and code-shape bugs. This auditor
catches **application-level logic flaws** (missing authorization, mass
assignment, business logic bugs). Use both — they cover different concerns.

### How does it compare to Psalm Security Analyzer or Progpilot (static SAST)?

Static SAST tools follow taint flows from sources to sinks. They are excellent
for SQLi and XSS but cannot reason about:

- Whether a controller is **missing** `#[IsGranted]`.
- Whether a Voter implementation has a logic flaw.
- Whether a Form Type binds a privileged field (e.g. `isAdmin`).
- Whether a multi-step workflow allows state-machine bypass.

This auditor reasons about those. Run both for layered coverage.

### How does it compare to Dependabot, Renovate, or Snyk?

Dependency scanners flag **known CVEs in third-party packages** (via
`composer audit`, GitHub Advisory Database, Snyk DB). This auditor focuses on
**your own application code**. The Attacker can call the `lookup_advisory` tool
(backed by `composer audit`) to enrich its analysis, but it's not a replacement
for a dedicated dependency scanner.

Use Dependabot/Renovate for CVE patching + this auditor for application-level
flaws.

### How does it compare to Snyk Code, Semgrep, or GitHub Copilot Code Review?

Snyk Code and Semgrep are commercial / open-source static SAST. They are
language-agnostic but **not Symfony-aware** — they don't understand Voters,
Firewalls, Forms, or `#[IsGranted]` attributes. This auditor's prompts encode
Symfony-specific knowledge and the Mapping stage builds a Symfony-aware project
model.

GitHub Copilot Code Review is generalist code review — not focused on security
and not Symfony-aware.

### Can I use this instead of all my other tools?

No. We recommend the layered approach:

| Tool                         | Purpose                                              |
| ---------------------------- | ---------------------------------------------------- |
| PHPStan / Psalm              | Type bugs, dead code                                 |
| Psalm Security / Progpilot   | Taint-based SAST (SQLi, XSS)                         |
| Dependabot / Renovate / Snyk | CVE-known dependency vulnerabilities                 |
| **symfony-security-auditor** | Logic flaws, missing authorization, Symfony-specific |

## Accuracy & False Positives

### How accurate is it?

Accuracy depends on the LLM model. Stronger models (Claude Opus, GPT-5.6, Gemini
3 Pro) produce fewer false positives and catch deeper flaws. The Reviewer agent
filters Attacker output — only `reviewer_validated` findings appear in the final
report.

Tune `audit.min_confidence` (default `0.6`) to trade precision for recall. CI
gating: try `0.8`. Discovery scan: try `0.3`.

### What's a false positive?

A finding the Attacker generates that turns out not to be exploitable. The
Reviewer rejects most of them. If you still see false positives in the final
report, raise `min_confidence`, or
[file an issue](https://github.com/vinceamstoutz/symfony-security-auditor/issues)
with a reproducer.

### What if I see a false negative (missed vulnerability)?

That's a harder problem — LLMs miss things. Options:

1. Raise `audit.max_iterations` from `3` to `5` (more passes).
2. Switch to a stronger model.
3. Drop `audit.min_confidence` to `0.3` and review unvalidated findings
   manually.
4. [File an issue](https://github.com/vinceamstoutz/symfony-security-auditor/issues)
   with the file/snippet — we update prompts based on real misses.

### Is the output deterministic?

**No.** LLM output is nondeterministic by default. On models that accept it, set
`temperature: 0.0` (or low like `0.1`) in your model options to reduce variation
— the current Claude generation (Opus 5, Sonnet 5, Fable 5) rejects
`temperature` outright and is steered via `effort`/`thinking` instead (see Model
Selection below) — but identical input may still produce different findings
across runs. The cache (`cache.enabled: true`) makes a _repeated_ run on
identical code deterministic — chunks with the same content hash are
short-circuited.

## Cost & Performance

### How much does an audit cost?

Roughly, for a medium Symfony app (~150 files), running once with Anthropic
prompt caching enabled (default):

| Setup                               | Approx. cost per run |
| ----------------------------------- | -------------------- |
| Claude Fable 5 only                 | $6 – $16             |
| Claude Opus only                    | $3 – $8              |
| Claude Opus + Haiku (split-model)   | $0.50 – $2           |
| GPT-5.6 only                        | $3 – $8              |
| DeepSeek / Mistral / Ollama (local) | ~$0 / $0             |

Tips: set `profile: fast` (one attacker iteration, lean pre-scan, code slicing,
concurrent reviews), enable Anthropic prompt caching (`cache_retention` in
`ai.yaml`; default `short` already on), use `cache.enabled` for repeated CI
runs, use split-model in CI, run nightly not per-PR. See
[CI → Managing LLM Costs](ci.md#managing-llm-costs).

### How long does an audit take?

30 seconds to several minutes depending on project size, model latency, and
`audit.max_iterations`. The Reviewer is run **per-finding** by default
(`reviewer_batch_size: 1`) — increase that to batch reviews and cut latency at
the risk of cross-talk between findings in the prompt.

### Why is the cache so important?

By default, the Attacker groups files by feature
(`audit.chunking.strategy: feature`) — a controller together with its related
entity/repository/form/voter/templates, capped at 10 files per chunk — and
computes a content hash per chunk. Identical chunks (same files, same content)
skip the LLM entirely — `cache.enabled: true` (the default) gives ~80% cost
reduction on repeated CI runs of unchanged code.

Provider-side **prompt caching** stacks on top of that for a ~90%
**input-token** discount on prompts that share a long system message. It is
configured on the `symfony/ai` platform, not by the auditor itself: set
`cache_retention` (`short`/`long`) on the `anthropic` platform in `ai.yaml`
(default `short` already enables it); OpenAI and Gemini cache automatically. The
old `cache.prompt_caching` flag is deprecated since 1.7 and ignored.

## Privacy & Data Handling

### Does this send my source code to a third party?

**Yes, by default.** It sends file contents to the LLM provider you configure in
`ai.yaml`. Read the provider's data retention policy:

- [Anthropic — data handling](https://www.anthropic.com/legal/privacy)
- [OpenAI — API data usage](https://openai.com/policies/api-data-usage-policies/)
- [Google Gemini — data handling](https://ai.google.dev/gemini-api/terms)
- [Mistral — data privacy](https://mistral.ai/terms/)
- [Azure OpenAI](https://learn.microsoft.com/en-us/azure/ai-services/openai/concepts/data-privacy)
  — enterprise data residency
- [AWS Bedrock](https://docs.aws.amazon.com/bedrock/latest/userguide/data-protection.html)
  — AWS data isolation

### Can I run it fully offline?

Yes. Use the [Ollama platform](configuration.md#supported-platforms) and a
locally pulled model:

```yaml
# config/packages/ai.yaml
ai:
  platform:
    ollama:
      endpoint: 'http://localhost:11434'

# config/packages/symfony_security_auditor.yaml
symfony_security_auditor:
    model: 'llama3.3'  # or any model from `ollama pull`
```

No data leaves your machine. Add
[`privacy.offline_only: true`](configuration.md#privacy--data-egress) to have
the auditor enforce that rather than rely on it: it drops the advisory feed (no
`composer audit`) and, in standalone mode, aborts before the audit boots if a
configured platform endpoint is not loopback or private-range.

### How do I verify that nothing leaves my machine?

Do not take the claim on trust — watch the wire. Set
[`privacy.offline_only: true`](configuration.md#privacy--data-egress) so the
auditor refuses its own network calls (and, in standalone mode, refuses to boot
against a non-local platform endpoint), export `SSA_NO_UPDATE_CHECK=1` to
silence the standalone release check, then capture traffic while an audit runs:

```bash
# Terminal 1 — capture everything that is not loopback and not your local LLM
sudo tcpdump -n -i any 'not host 127.0.0.1 and not port 11434'

# Terminal 2 — run the audit
SSA_NO_UPDATE_CHECK=1 symfony-security-auditor audit /path/to/project
```

Expect the capture to stay empty for the whole run. Two notes on reading it:

- `composer install` and your editor make their own connections — run the audit
  in an otherwise idle shell so anything captured is attributable.
- With `privacy.offline_only` off, an audit legitimately talks to your LLM
  provider and (through `composer audit`) to the Packagist advisory feed, so a
  non-empty capture there is expected, not a leak.
- This applies to the `audit` command specifically. Standalone's `self-update`
  is a separate command that also refreshes the bundled pricing catalog from
  `symfony/models-dev` unless `privacy.offline_only` is set — it is not covered
  by the capture above unless you run it too.

For a stricter guarantee, run the audit in a network namespace or container that
has no route off the host at all except to the Ollama socket — if the auditor
still completes, nothing it needs is remote.

### Does it log my source code anywhere?

Locally, only via `LoggerInterface` warnings if the Attacker / Reviewer fails to
parse JSON or the advisory feed fails to load — and only the **error context**,
not the source. The filesystem cache (`cache.dir`) stores LLM **responses**
keyed by content hash; no plaintext source code is written to the cache.

### What about the `lookup_advisory` tool?

`lookup_advisory` shells out to `composer audit --format=json --locked` against
your `composer.lock`. The shell-out happens on the host machine — only the LLM
prompt receives the resulting CVE summaries, not your dependency list itself.

## Model Selection

### Which LLM model should I use?

| Goal              | Recommended setup                                                               |
| ----------------- | ------------------------------------------------------------------------------- |
| Most demanding    | `attacker_model: claude-fable-5` + `reviewer_model: claude-haiku-4-5-20251001`  |
| Highest accuracy  | `attacker_model: claude-opus-5` + `reviewer_model: claude-opus-5`               |
| Best cost/quality | `attacker_model: claude-opus-5` + `reviewer_model: claude-haiku-4-5-20251001`   |
| Strong + cheaper  | `attacker_model: claude-sonnet-5` + `reviewer_model: claude-haiku-4-5-20251001` |
| Cheapest paid     | `model: deepseek-chat` or `mistral-large-latest`                                |
| Offline / free    | `model: llama3.3` via Ollama                                                    |
| Enterprise        | Azure OpenAI / AWS Bedrock with split-model                                     |

See [Configuration → Split-Model Setup](configuration.md#split-model-setup).

### Why split-model?

The Attacker has the harder job (discover vulnerabilities). The Reviewer's job
(validate one finding at a time) is easier and benefits from a faster, cheaper
model. Pairing Opus + Haiku saves ~20× on the Reviewer phase with no accuracy
loss in practice.

### How should I set reasoning effort / thinking per agent?

The two agents want opposite trade-offs, so tune them independently with the
split-model setup above plus per-agent model options (see
[Configuration → Model Options](configuration.md#model-options)):

- **Attacker — favour capability and reasoning depth.** It runs a long-horizon,
  recall-sensitive search across the whole codebase, so it benefits from a more
  capable model and higher reasoning effort. On models that expose an `effort`
  option (e.g. Claude Opus 5, Sonnet 5 and Fable 5, where `high`/`xhigh` are the
  sweet spot for this kind of work) or an adaptive `thinking` option, set it on
  the attacker:

  ```yaml
  symfony_security_auditor:
      attacker_model: 'claude-opus-5?effort=high'
      reviewer_model: 'claude-haiku-4-5-20251001'
  ```

- **Reviewer — favour speed.** It validates one finding against context you
  already hand it, so a faster, cheaper model at lower effort is usually enough;
  spend the budget on the attacker instead.

A note on recall: recent Claude models follow strict instructions literally, so
at the _finding_ stage you want coverage, not premature filtering — the reviewer
is where findings are adjudicated and ranked. Forcing the attacker into a very
low effort or an aggressively terse budget can suppress the multi-step reasoning
that surfaces business-logic and access-control flaws, which is exactly the
class of issue this tool exists to find.

> Which option keys are accepted (`effort`, `thinking`, …) depends on the
> provider and model behind `symfony/ai`. Unknown options are passed straight
> through to the provider, so check your provider's documentation; the auditor
> does not validate them.

### Can I tune model parameters (temperature, max_tokens)?

Yes. For `max_tokens`, use the dedicated `max_output_tokens` key — it defaults
to `4096` and avoids `symfony/ai`'s built-in ~1000-token cap. This key currently
only takes effect for Claude/Anthropic-dialect models — see
[Configuration → Top-level](configuration.md#top-level):

```yaml
symfony_security_auditor:
    max_output_tokens: 4096
    # or, split per agent:
    attacker_max_output_tokens: 8192
    reviewer_max_output_tokens: 2048
```

Other params (e.g. `temperature`) flow through the model name, using the
query-string syntax:

```yaml
symfony_security_auditor:
    model: 'claude-haiku-4-5-20251001?temperature=0.1'
```

> `model`, `attacker_model`, and `reviewer_model` are plain strings, so the
> expanded `{name, options}` mapping that `symfony/ai-bundle`'s own `ai.yaml`
> accepts for a model is **not** valid here — only the query-string form above
> works. See [Configuration → Model Options](configuration.md#model-options).

## Compatibility

### What PHP versions are supported?

Installing the **bundle** requires PHP **8.3+** in the host application (PHP 8.4
and 8.5 are covered by the CI matrix). The **standalone binary** bundles its own
PHP runtime, so the PHP version of the audited project does not matter.

### What Symfony versions are supported?

Installing the **bundle** requires Symfony **7.4+** or **8.x** in the host
application — check `composer.json` for the authoritative constraint. The
**standalone binary** imposes no Symfony version on the project it audits.

### Can I audit a project on an older Symfony or PHP version?

Yes — use the [standalone binary](../README.md#standalone-tool-binary) (or the
GitHub Action, which installs it for you). The auditor never executes the
audited project's code — it reads the sources — so a Symfony 4/5 app on an older
PHP can be audited without adding any dependency to it. One caveat: detection is
tuned for attribute- and YAML-era Symfony (`#[Route]`, `#[IsGranted]`,
`security.yaml`). On annotation-based apps (`@Route`, `@IsGranted`) the LLM
still reads the annotations in context, but the deterministic parsers that
enrich the mapping stage target attributes, so route and access-control mapping
may be less complete.

### Does it work on non-Symfony PHP projects?

It targets Symfony specifically — the Mapping stage classifies Symfony
Controllers, Voters, Forms, and Firewalls. Running it on a Laravel or Drupal
project would still feed files to the LLM, but the Symfony-specific prompt
context wouldn't apply, so accuracy drops. **Not recommended.**

### What file types does it scan?

`.php`, `.twig`, `.yaml`, `.yml`, `.xml`, plus the explicitly listed root dotenv
files (`.env`, `.env.local`, `.env.dev`, `.env.test`, `.env.prod`, `.env.dist`)
— the places where Symfony security-relevant code and committed secrets live.
Other extensions are skipped.

### Does it scan `vendor/`, `tests/`, or `migrations/`?

No. The scan is a strict **allow-list**: only the paths listed in
`scan.included_paths` are inspected, defaulting to `src`, `config`, `templates`,
`public/index.php`, and the root dotenv files (the Symfony Flex skeleton).
Anything outside — `vendor/`, `node_modules/`, `var/`, `tests/`, `migrations/`,
`translations/`, `bin/`, `app/`, root-level scripts, IDE folders, build
artefacts — is silently skipped. To prune a sub-tree inside an included path
(e.g. drop `src/Migrations` from the audit), tighten `included_paths` to the
specific sub-directories you want instead — e.g.:

```yaml
symfony_security_auditor:
    scan:
        included_paths:
            - 'src/Controller'
            - 'src/Form'
            - 'src/Voter'
            - 'config'
            - 'templates'
            - 'public/index.php'
```

`composer audit` covers vendor CVEs via the `lookup_advisory` tool.

## Integration & Workflow

### How do I run it in CI?

Nightly scheduling is simplest — the multi-agent loop can take minutes, so a
full audit on every push adds latency. See [CI Integration](ci.md) for
ready-to-copy GitHub Actions and GitLab CI templates, including scheduled SARIF
upload and a `--since`-scoped, `--fail-on`-gated pattern for teams that want the
audit to block pull requests directly.

### Can I run it on every PR?

You **can** — this is now a well-supported pattern. Scope the run to changed
files with `--since` (fast, and the cache stays warm) and gate on `--fail-on` /
`--min-score`, with `--baseline` to keep already-accepted findings from failing
the check. A full (non-`--since`) audit on every PR is still costlier and slower
than a nightly run — reserve that for the scheduled job.

### How do I get findings into GitHub Code Scanning?

```bash
php bin/console audit:run --format sarif --output report.sarif
```

Then upload via `github/codeql-action/upload-sarif@v4`. Findings appear in the
GitHub Security tab and as annotations on the diff. Restricted to collaborators
even on public repos. See [CI → GitHub Actions](ci.md#github-actions).

### How do I get findings into the GitLab Security Dashboard?

GitLab natively parses SARIF when uploaded as a `sast` report artifact. See
[CI → GitLab CI](ci.md#gitlab-ci).

### Can I store the JSON report somewhere private?

Yes. The [CI doc](ci.md#report-visibility-on-public-repositories) covers four
storage modes: GitHub Code Scanning (SARIF), private S3/GCS bucket,
notification-only (Slack/email), and storage in a private repo via PAT.

> **Public-repo warning**: do **not** store the JSON report as a public CI
> artifact. It advertises your attack surface. Use SARIF + Code Scanning or
> external private storage instead.

## Customization

### Can I add custom vulnerability types?

Yes. Add a case to `Audit/Domain/Model/VulnerabilityType`, extend `category()`,
`owaspReference()`, `owaspReferenceUrl()`, and `cwe()`, then update
`AttackerPromptBuilder` to mention the new type. See
[Contributing → Common Tasks](../CONTRIBUTING.md#add-a-new-vulnerability-type).

### Can I add custom pipeline stages?

Yes. Implement `Audit/Domain/Pipeline/StageInterface`. Stages auto-register via
the `symfony_security_auditor.pipeline_stage` tag. See
[Extending → Custom Pipeline Stage](extending.md#2-custom-pipeline-stage).

### Can I swap the LLM client entirely?

Yes. Implement `Audit/Domain/Port/LLMClientInterface` and alias it. See
[Extending → Custom LLM Client](extending.md#1-custom-llm-client).

### Can I use a custom CVE database instead of `composer audit`?

Yes. Implement `Audit/Domain/Port/AdvisoryDatabaseInterface` and override the
alias in `config/services.yaml`. See
[Configuration → Advisory Source](configuration.md#advisory-source-lookup_advisory-tool).

### Can I add a new output format?

Yes. Add a case to `Command/OutputFormat`, then a `<Name>ReportRenderer` class
implementing `ReportRendererInterface` and register it in `config/services.php`
— autoconfiguration wires it into `ReportWriter`, no `match` arm to edit. See
[Extending → Custom Report Output](extending.md#3-custom-report-output).
