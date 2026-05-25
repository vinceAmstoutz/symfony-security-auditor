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

---

## About the project

### What does it do?

It feeds your Symfony project through a three-stage AI pipeline:

1. **Ingestion** — scans `.php`, `.twig`, `.yaml`, `.yml`, `.xml` files
   recursively.
2. **Mapping** — classifies files as Controllers, Entities, Voters, Forms,
   Repositories, Templates, Config, Services; builds a route/firewall map.
3. **Audit** — an adversarial Attacker agent hunts for vulnerabilities; a
   skeptical Reviewer agent validates each finding. Up to 3 iterations, stops
   earlier when no new findings emerge.

Output is a validated vulnerability report in your console, as JSON, or as SARIF
for GitHub Code Scanning / GitLab Security Dashboard.

### What kinds of vulnerabilities does it catch?

32 types across six categories (OWASP-aligned):

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

The bundle is actively developed. Output is validated by a Reviewer agent before
being included in the final report. We recommend running it as a **scheduled
nightly CI job** alongside existing tools (PHPStan / Psalm / Dependabot), not as
a blocking PR gate. See [CI Integration](ci.md).

---

## Comparisons

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

---

## Accuracy & False Positives

### How accurate is it?

Accuracy depends on the LLM model. Stronger models (Claude Opus, GPT-4o, Gemini
2.5 Pro) produce fewer false positives and catch deeper flaws. The Reviewer
agent filters Attacker output — only `reviewer_validated` findings appear in the
final report.

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

**No.** LLM output is nondeterministic by default. Set `temperature: 0.0` (or
low like `0.1`) in your model options to reduce variation, but identical input
may still produce different findings across runs. The cache
(`cache.enabled: true`) makes a _repeated_ run on identical code deterministic —
chunks with the same content hash are short-circuited.

---

## Cost & Performance

### How much does an audit cost?

Roughly, for a medium Symfony app (~150 files), running once with Anthropic
prompt caching enabled (default):

| Setup                               | Approx. cost per run |
| ----------------------------------- | -------------------- |
| Claude Opus only                    | $3 – $8              |
| Claude Opus + Haiku (split-model)   | $0.50 – $2           |
| GPT-4o only                         | $2 – $6              |
| DeepSeek / Mistral / Ollama (local) | ~$0 / $0             |

Tips: enable `cache.prompt_caching` (default), use `cache.enabled` for repeated
CI runs, use split-model in CI, run nightly not per-PR. See
[CI → Managing LLM Costs](ci.md#managing-llm-costs).

### How long does an audit take?

30 seconds to several minutes depending on project size, model latency, and
`audit.max_iterations`. The Reviewer is run **per-finding** by default
(`reviewer_batch_size: 1`) — increase that to batch reviews and cut latency at
the risk of cross-talk between findings in the prompt.

### Why is the cache so important?

The Attacker chunks files in groups of 10 and computes a content hash. Identical
chunks (same files, same content) skip the LLM entirely — `cache.enabled: true`
(the default) gives ~80% cost reduction on repeated CI runs of unchanged code.

`cache.prompt_caching: true` (also default) is Anthropic-specific prompt caching
for ~90% **input-token** discount on prompts that share a long system message.
Silently ignored by non-Anthropic providers (zero cost to leave on).

---

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
      host_url: 'http://localhost:11434'

# config/packages/symfony_security_auditor.yaml
symfony_security_auditor:
    model: 'llama3.3'  # or any model from `ollama pull`
```

No data leaves your machine.

### Does it log my source code anywhere?

Locally, only via `LoggerInterface` warnings if the Attacker / Reviewer fails to
parse JSON or the advisory feed fails to load — and only the **error context**,
not the source. The filesystem cache (`cache.dir`) stores LLM **responses**
keyed by content hash; no plaintext source code is written to the cache.

### What about the `lookup_advisory` tool?

`lookup_advisory` shells out to `composer audit --format=json --locked` against
your `composer.lock`. The shell-out happens on the host machine — only the LLM
prompt receives the resulting CVE summaries, not your dependency list itself.

---

## Model Selection

### Which LLM model should I use?

| Goal              | Recommended setup                                                               |
| ----------------- | ------------------------------------------------------------------------------- |
| Highest accuracy  | `attacker_model: claude-opus-4-7` + `reviewer_model: claude-opus-4-7`           |
| Best cost/quality | `attacker_model: claude-opus-4-7` + `reviewer_model: claude-haiku-4-5-20251001` |
| Cheapest paid     | `model: deepseek-chat` or `mistral-large`                                       |
| Offline / free    | `model: llama3.3` via Ollama                                                    |
| Enterprise        | Azure OpenAI / AWS Bedrock with split-model                                     |

See [Configuration → Split-Model Setup](configuration.md#split-model-setup).

### Why split-model?

The Attacker has the harder job (discover vulnerabilities). The Reviewer's job
(validate one finding at a time) is easier and benefits from a faster, cheaper
model. Pairing Opus + Haiku saves ~20× on the Reviewer phase with no accuracy
loss in practice.

### Can I tune model parameters (temperature, max_tokens)?

Yes, via two equivalent syntaxes:

```yaml
# Query-string
symfony_security_auditor:
    model: 'claude-opus-4-7?temperature=0.1&max_tokens=4096'

# Expanded
symfony_security_auditor:
    model:
        name: 'claude-opus-4-7'
        options:
            temperature: 0.1
            max_tokens: 4096
```

See [Configuration → Model Options](configuration.md#model-options).

---

## Compatibility

### What PHP versions are supported?

PHP **8.3+**. PHP 8.4 and 8.5 are supported via the CI matrix.

### What Symfony versions are supported?

Symfony **7.4+** and Symfony **8.x**. Check `composer.json` for the
authoritative constraint.

### Does it work on non-Symfony PHP projects?

It targets Symfony specifically — the Mapping stage classifies Symfony
Controllers, Voters, Forms, and Firewalls. Running it on a Laravel or Drupal
project would still feed files to the LLM, but the Symfony-specific prompt
context wouldn't apply, so accuracy drops. **Not recommended.**

### What file types does it scan?

`.php`, `.twig`, `.yaml`, `.yml`, `.xml` — the file types where Symfony
security-relevant code lives. Other extensions are skipped.

### Does it scan `vendor/`, `tests/`, or `migrations/`?

No. The scan is a strict **allow-list**: only the paths listed in
`scan.included_paths` are inspected, defaulting to `src`, `config`, `templates`,
and `public/index.php` (the Symfony Flex skeleton). Anything outside —
`vendor/`, `node_modules/`, `var/`, `tests/`, `migrations/`, `translations/`,
`bin/`, `app/`, root-level scripts, IDE folders, build artefacts — is silently
skipped. To prune a sub-tree inside an included path (e.g. drop `src/Migrations`
from the audit), tighten `included_paths` to the specific sub-directories you
want instead — e.g.:

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

---

## Integration & Workflow

### How do I run it in CI?

Schedule it nightly — the multi-agent loop takes minutes, so blocking PRs hurts
productivity. See [CI Integration](ci.md) for ready-to-copy GitHub Actions and
GitLab CI templates with SARIF upload.

### Can I run it on every PR?

You **can** (with `audit.max_iterations: 1` + split-model to keep latency low)
but the cost-vs-value usually favors nightly scheduled runs.

### How do I get findings into GitHub Code Scanning?

```bash
php bin/console audit:run . --format sarif --output report.sarif
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

---

## Customization

### Can I add custom vulnerability types?

Yes. Add a case to `Audit/Domain/Model/VulnerabilityType`, extend `category()`
and `owaspReference()`, then update `AttackerPromptBuilder` to mention the new
type. See
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

Yes. Add a case to `Command/OutputFormat`, a `render<Name>()` method to
`ReportRenderer`, and a `match` arm in `ReportWriter::write()`. See
[Extending → Custom Report Output](extending.md#4-custom-report-output).
