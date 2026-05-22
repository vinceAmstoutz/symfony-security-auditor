# CI Integration

Run the AI security audit on a nightly schedule and ship the SARIF report to GitHub Code Scanning or the GitLab Security Dashboard.

## Table of Contents

- [Why Scheduled, Not Per-Push](#why-scheduled-not-per-push)
- [Managing LLM Costs](#managing-llm-costs)
- [Report Visibility on Public Repositories](#report-visibility-on-public-repositories)
- [GitHub Actions](#github-actions)
- [GitLab CI](#gitlab-ci)
- [Output Formats Reference](#output-formats-reference)

> See also: [Configuration](configuration.md) · [FAQ](faq.md) · [Troubleshooting](troubleshooting.md)

---

## Why Scheduled, Not Per-Push

The auditor runs a multi-agent LLM loop (up to 3 attacker/reviewer iterations). A single audit can take **30 seconds to several minutes** depending on project size and provider latency. Running it on every push or pull request blocks developers and inflates CI costs with no proportional benefit — vulnerabilities are not introduced commit-by-commit.

**Recommended pattern**: nightly scheduled pipeline. Results land in your security dashboard (GitHub Code Scanning, GitLab Security Dashboard) and can trigger alerts on new findings.

---

## Managing LLM Costs

Each audit run makes multiple LLM API calls: up to **3 iterations × N file chunks × 2 agents** (Attacker + Reviewer). Token usage grows with project size.

### Reduce cost with split-model

Use a powerful model for discovery and a cheap/fast model for validation:

```yaml
# config/packages/symfony_security_auditor.yaml
symfony_security_auditor:
    attacker_model: 'claude-opus-4-5'   # deep reasoning for vulnerability discovery
    reviewer_model: 'claude-haiku-4-5'  # ~20× cheaper for false-positive filtering
```

Any supported provider works — see [Configuration](configuration.md#split-model-setup) for all options.

### Run less often on large projects

Nightly is a sensible default. For large monorepos or expensive models, weekly is fine — most vulnerability patterns are stable across commits:

```yaml
# GitHub Actions
schedule:
  - cron: '0 2 * * 1'  # weekly on Monday at 02:00 UTC

# GitLab CI → Schedules → set interval to "Every week"
```

### Run locally for free with Ollama

Ollama has no API cost. Useful for one-off audits or validating new rules:

```yaml
symfony_security_auditor:
    model: 'llama3.2'  # or any model pulled via `ollama pull`
```

See [Configuration](configuration.md#supported-platforms) for Ollama setup.

### Set a spend cap

All major providers offer budget alerts or hard caps — set one before enabling scheduled runs:

- Anthropic: [console.anthropic.com](https://console.anthropic.com) → Billing → Usage limits
- OpenAI: [platform.openai.com](https://platform.openai.com) → Settings → Limits
- Others: check your provider's billing dashboard

---

## Report Visibility on Public Repositories

> [!WARNING]
> Security audit reports list vulnerabilities in your application. Storing them where anyone can read them
> **advertises your attack surface publicly**. Evaluate report storage carefully before enabling CI uploads.

| Storage method                   | Public repo risk          | Notes                                                    |
|----------------------------------|---------------------------|----------------------------------------------------------|
| GitHub Actions artifact          | **Publicly downloadable** | Anyone with repo URL can fetch it                        |
| GitLab CI artifact               | **Publicly downloadable** | Same — public project = public artifacts                 |
| GitHub Code Scanning (SARIF)     | **Safe**                  | Security tab requires write access, even on public repos |
| External storage (S3, GCS + IAM) | **Safe**                  | Access controlled by your cloud IAM policy               |
| Notification only (Slack, email) | **Safe**                  | No persistent file stored                                |

### Option 1 — GitHub Code Scanning (recommended for GitHub)

SARIF upload to Code Scanning is restricted to collaborators even on public repositories. The workflow shown
below already uses this approach — prefer it over raw artifact uploads.

### Option 2 — External private storage

```yaml
      - name: Upload report to private S3 bucket
        run: |
          aws s3 cp report.json s3://your-private-bucket/audits/$(date +%Y-%m-%d).json
        env:
          AWS_ACCESS_KEY_ID: ${{ secrets.AWS_ACCESS_KEY_ID }}
          AWS_SECRET_ACCESS_KEY: ${{ secrets.AWS_SECRET_ACCESS_KEY }}
          AWS_DEFAULT_REGION: eu-west-1
```

Replace the `upload-artifact` step with this. Requires an S3 bucket with a bucket policy that blocks public access.

### Option 3 — Notification only (no stored report)

Run the audit and send a summary notification — no file persisted, no public exposure:

```yaml
      - name: Run security audit
        run: php bin/console audit:run . > audit-output.txt 2>&1 || true

      - name: Notify Slack
        run: |
          curl -s -X POST "${{ secrets.SLACK_WEBHOOK_URL }}" \
            -H 'Content-type: application/json' \
            --data "{\"text\": \"🔍 Nightly security audit complete — check CI logs for findings.\"}"
```

### Option 4 — Store artifact in a private repository

Use a scoped Personal Access Token (PAT) with `contents: write` on a private repo to push reports there.
Keeps your source repo public while centralising security findings privately.

---

## GitHub Actions

Add your LLM provider key as a repository secret (`Settings → Secrets → Actions`). Example for Anthropic: `ANTHROPIC_API_KEY`.

See [supported platforms](../README.md#supported-platforms) for other providers.

### Nightly SARIF upload to GitHub Code Scanning

```yaml
# .github/workflows/security-audit.yaml
name: Security Audit

on:
  schedule:
    - cron: '0 2 * * *'  # nightly at 02:00 UTC
  workflow_dispatch: ~    # allow manual trigger

permissions:
  contents: read
  security-events: write  # required for Code Scanning upload

jobs:
  audit:
    name: Symfony Security Audit
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: shivammathur/setup-php@v2
        with:
          php-version: '8.3' # Or 8.4 or 8.5
          coverage: none

      - name: Install dependencies
        run: composer install --no-interaction --prefer-dist --no-progress

      - name: Run security audit
        env:
          ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}
        run: |
          php bin/console audit:run . --format sarif --output report.sarif

      - name: Upload to GitHub Code Scanning
        uses: github/codeql-action/upload-sarif@v4
        if: always()
        with:
          sarif_file: report.sarif
```

### JSON report as artifact

```yaml
      - name: Run security audit
        env:
          ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}
        run: |
          php bin/console audit:run . --format json --output report.json

      - uses: actions/upload-artifact@v4
        if: always()
        with:
          name: security-audit-report
          path: report.json
          retention-days: 30
```

---

## GitLab CI

Add your LLM provider key as a CI/CD variable (`Settings → CI/CD → Variables`). Example: `ANTHROPIC_API_KEY` (masked, not protected unless you only audit protected branches).

### Scheduled pipeline with Security Dashboard upload

GitLab natively parses SARIF and displays findings in the **Security Dashboard** and **Vulnerability Report** when you upload a `gl-sast-report.json` (GitLab SAST format) or use the `security` artifact report type.

```yaml
# .gitlab-ci.yml (add to existing file or create standalone)

symfony-security-audit:
  image: php:8.3-cli # Or 8.4 or 8.5
  stage: test
  rules:
    - if: $CI_PIPELINE_SOURCE == "schedule"
    - if: $CI_PIPELINE_SOURCE == "web"   # allow manual trigger from UI
  before_script:
    - apt-get update -qq && apt-get install -y -qq unzip git
    - curl -sS https://getcomposer.org/installer | php -- --install-dir=/usr/local/bin --filename=composer
    - composer install --no-interaction --prefer-dist --no-progress
  script:
    - php bin/console audit:run . --format sarif --output gl-sast-report.sarif
  artifacts:
    when: always
    reports:
      sast: gl-sast-report.sarif
    paths:
      - gl-sast-report.sarif
    expire_in: 30 days
```

Set the schedule in `CI/CD → Schedules` (e.g., every night at 02:00).

### JSON artifact only (no dashboard)

```yaml
symfony-security-audit:
  image: php:8.3-cli # Or 8.4 or 8.5
  stage: test
  rules:
    - if: $CI_PIPELINE_SOURCE == "schedule"
    - if: $CI_PIPELINE_SOURCE == "web"
  before_script:
    - apt-get update -qq && apt-get install -y -qq unzip git
    - curl -sS https://getcomposer.org/installer | php -- --install-dir=/usr/local/bin --filename=composer
    - composer install --no-interaction --prefer-dist --no-progress
  script:
    - php bin/console audit:run . --format json --output report.json
  artifacts:
    when: always
    paths:
      - report.json
    expire_in: 30 days
```

---

## Output Formats Reference

```bash
# Console (default — useful for workflow logs)
php bin/console audit:run /path/to/project

# JSON — machine-readable, good for custom dashboards
php bin/console audit:run /path/to/project --format json --output report.json

# SARIF — GitHub Code Scanning / GitLab Security Dashboard
php bin/console audit:run /path/to/project --format sarif --output report.sarif
```
