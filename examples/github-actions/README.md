# GitHub Actions recipes

Ready-to-copy workflow files for running `symfony-security-auditor` in CI.

| File                                               | Trigger        | What it does                                                                                                         |
| -------------------------------------------------- | -------------- | -------------------------------------------------------------------------------------------------------------------- |
| [`pull-request-audit.yml`](pull-request-audit.yml) | `pull_request` | Audits only files changed in the PR (`--since`), suppresses baselined findings (`--baseline`), uploads SARIF + HTML. |

For a nightly full-project scan, see the workflow in
[`docs/ci.md`](../../docs/ci.md#github-actions).

## Setup

1. Copy the chosen file into your project's `.github/workflows/` directory.
2. Add your LLM provider key as a repository secret
   (`Settings → Secrets → Actions`), e.g. `ANTHROPIC_API_KEY`.
3. (Optional) Accept the current findings as a baseline so future runs only
   report new ones:

   ```bash
   php bin/console audit:run . --generate-baseline=.security-baseline.json
   git add .security-baseline.json && git commit -m "chore: add security audit baseline"
   ```

See [`docs/ci.md`](../../docs/ci.md) for cost management and provider notes.
