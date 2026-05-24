# Troubleshooting

Common problems running **symfony-security-auditor** and how to fix them. Found
a new gotcha?
[Open an issue](https://github.com/vinceamstoutz/symfony-security-auditor/issues)
so we can document it.

## Table of Contents

- [Installation & Setup](#installation--setup)
- [Running the Audit](#running-the-audit)
- [LLM & Provider Errors](#llm--provider-errors)
- [Empty / Surprising Reports](#empty--surprising-reports)
- [Performance & Cost](#performance--cost)
- [Cache Issues](#cache-issues)
- [Advisory (`composer audit`) Issues](#advisory-composer-audit-issues)
- [Tools (`read_file`, `grep`, `list_files`, `lookup_advisory`)](#tools-read_file-grep-list_files-lookup_advisory)
- [CI Failures](#ci-failures)
- [Dev / Quality Gate Failures](#dev--quality-gate-failures)

> See also: [FAQ](faq.md) · [Configuration](configuration.md) ·
> [CI Integration](ci.md)

---

## Installation & Setup

### `Class "Symfony\AI\AiBundle\AiBundle" not found`

You forgot to install a platform bridge **or** to register `AiBundle` before
`SymfonySecurityAuditorBundle`.

```bash
composer require symfony/ai-anthropic-platform  # or any other bridge
```

```php
// config/bundles.php — AiBundle MUST come first
Symfony\AI\AiBundle\AiBundle::class => ['all' => true],
VinceAmstoutz\SymfonySecurityAuditor\SymfonySecurityAuditorBundle::class => ['dev' => true, 'test' => true],
```

### `The service "VinceAmstoutz\..." has a dependency on a non-existent service "Symfony\AI\Platform\PlatformInterface"`

No platform configured in `config/packages/ai.yaml`. Add one — see
[Configuration → Platform Configuration](configuration.md#platform-configuration).

### `Argument #1 ... must be of type Symfony\AI\Platform\PlatformInterface, NULL given`

Same root cause as above. Verify `ai.yaml` has a `platform:` block and the
corresponding `symfony/ai-*-platform` package is installed.

---

## Running the Audit

### `audit:run` not registered / unknown command

`SymfonySecurityAuditorBundle` is registered for `dev` and `test` only by
default. Run from those environments:

```bash
APP_ENV=dev bin/console audit:run /path/to/project
```

To enable in `prod`, change `config/bundles.php`:

```php
VinceAmstoutz\SymfonySecurityAuditor\SymfonySecurityAuditorBundle::class => ['all' => true],
```

### `[ERROR] Path "/x" is not a valid directory`

The `project-path` argument must point to a directory that exists. Use an
absolute path, or omit the argument to default to the current working directory.

### `[ERROR] Project does not look like a Symfony app`

The auditor walks the project for `.php`, `.twig`, `.yaml`, `.yml`, `.xml`
files. If nothing is found, the path is wrong or the project is empty after
exclusions. Check `scan.excluded_dirs` and `scan.respect_gitignore`.

### Audit exits with code `1` even though risk is LOW

Exit code `1` is also used for:

- Invalid `project-path` argument.
- Unhandled exception during pipeline execution (check stderr).
- Validator errors on the input (e.g. `--format` not one of
  `console|json|sarif`).

Re-run with `-v` or `-vv` to see the underlying error.

---

## LLM & Provider Errors

### `API key not set` / `401 Unauthorized`

Confirm the env var is exported in the same shell:

```bash
echo $ANTHROPIC_API_KEY    # should not be empty
```

In Docker, pass it through:

```bash
docker compose exec -e ANTHROPIC_API_KEY="$ANTHROPIC_API_KEY" php bin/console audit:run .
```

### `Rate limit exceeded` / `429`

Reduce concurrent load:

- Lower `audit.max_iterations` (default `3`) to `1`.
- Raise `reviewer_batch_size` from `1` to `5` (fewer reviewer calls).
- Use a split-model with a cheaper Reviewer (Haiku, DeepSeek, Mistral) — they
  have higher rate limits.
- Run nightly, not on every PR.

### `LLM response was empty` / `JsonException: Syntax error`

The model returned blank or non-JSON output. The chunk is skipped automatically
and logged at `warning` level via `LoggerInterface`. Causes:

- Model context limit exceeded — lower `audit.max_tool_iterations` or
  split-model to a model with a larger context.
- Model refused the prompt — try a different model (some smaller open-weight
  models refuse "hacking" prompts).
- Network timeout — retry; check the provider's status page.

If it happens for **every** chunk, the model is unsuitable. Switch model.

### `Ollama: model not found`

Pull the model first:

```bash
ollama pull llama3.3
```

Then verify with `ollama list`. The model name in
`symfony_security_auditor.yaml` must match exactly.

---

## Empty / Surprising Reports

### Report has zero vulnerabilities but I know there are some

Diagnostic order:

1. **Lower `audit.min_confidence`** from `0.6` to `0.3` — borderline findings
   now pass to the Reviewer.
2. **Inspect attacker output before review** — temporarily decorate
   `ReviewerAgent` to log all incoming candidates, including non-validated ones.
3. **Raise `audit.max_iterations`** to `5` — the loop stops early when no new
   findings emerge; a stronger pass can surface more.
4. **Switch to a stronger model** — Claude Opus and GPT-4o consistently
   outperform small models.
5. **Check the file actually got scanned** — run with `-vv` to see ingested file
   counts and chunk counts.
6. **`scan.respect_gitignore: true`** silently skips files in `.gitignore`. Set
   to `false` to include them.
7. **`scan.max_file_size_kb`** drops large files. Default `512` KB; raise if
   your project has bigger files.

### Report has too many false positives

- Raise `audit.min_confidence` from `0.6` to `0.8`.
- Switch Reviewer to a **stronger** model (counterintuitive — Reviewer needs
  accuracy, not speed).
- Inspect the LLM's `reviewer_notes` (logged at `info` level) — the Reviewer
  often explains why it accepted weak findings.

### Same code, different findings on each run

LLM output is **nondeterministic** by design. Set `temperature: 0.0` (or `0.1`)
on the model:

```yaml
symfony_security_auditor:
    model:
        name: 'claude-opus-4-7'
        options:
            temperature: 0.0
```

With `temperature: 0.0` + `cache.enabled: true`, repeated runs on identical code
become deterministic.

---

## Performance & Cost

### Audit takes 10+ minutes

Expected behavior on large projects. Mitigations:

- Use **split-model** — Opus Attacker + Haiku Reviewer cuts ~50% wall time.
- Raise `reviewer_batch_size` from `1` to `5` — fewer Reviewer round-trips.
- Lower `audit.max_iterations` from `3` to `1` or `2`.
- Trim scan scope via `scan.excluded_dirs` — e.g. exclude `tests/Fixtures` if it
  has no real code.
- Enable both caches: `cache.enabled: true` and `cache.prompt_caching: true`
  (defaults).

### Cost blew past my budget

- Confirm `cache.prompt_caching: true` (default) — Anthropic provides ~90%
  input-token discount on cached prompts.
- Confirm `cache.enabled: true` (default) — repeated chunks skip the LLM
  entirely.
- Switch to a cheaper Reviewer (`reviewer_model: claude-haiku-4-5-20251001` or
  `deepseek-chat`).
- Set a provider-side hard cap. See
  [CI → Set a spend cap](ci.md#set-a-spend-cap).
- Run weekly instead of nightly for large monorepos.

---

## Cache Issues

### Cache seems stale — old findings persist after fixing code

The cache is keyed by **chunk content hash**. If your fix changes the file's
bytes, the cache key changes and the LLM is re-invoked. If you see stale
findings, the file content didn't actually change — diff to confirm.

To force a full re-audit:

```bash
docker compose exec php bin/console cache:clear
rm -rf var/cache/dev/symfony_security_auditor/attacker
```

Adjust the path to match `cache.dir` if you overrode it.

### `Permission denied` writing to `cache.dir`

```bash
chown -R www-data:www-data var/cache
```

Or pick a writable directory:

```yaml
symfony_security_auditor:
    cache:
        dir: '/tmp/symfony-security-auditor/cache'
```

### Disable cache for one-off debugging

```yaml
symfony_security_auditor:
    cache:
        enabled: false
```

`AttackerCacheInterface` is aliased to `NullAttackerCache` — every chunk hits
the LLM.

---

## Advisory (`composer audit`) Issues

### `lookup_advisory` always returns empty results

Causes (each logs a `warning` via `LoggerInterface`):

- **`composer` not in `PATH`** — install Composer 2.4+ on the audit host.
- **`composer.lock` missing** — run `composer install` first; advisory data
  comes from the lockfile.
- **Malformed JSON output** — corrupted `composer.lock`. Regenerate it.
- **Process error** — network failure to Packagist. Retry.

When `lookup_advisory` returns empty, the audit continues without CVE data — no
audit failure.

### `composer audit` is slow

It runs **once** per audit and the result is cached for the lifetime of the
request. If it's the bottleneck, you can pre-warm it before the audit or
override `AdvisoryDatabaseInterface` with `InMemoryAdvisoryDatabase` containing
a baked snapshot.

### Override the advisory source

Implement `Audit/Domain/Port/AdvisoryDatabaseInterface`:

```yaml
# config/services.yaml
services:
    VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\AdvisoryDatabaseInterface:
        alias: App\Security\MyCustomAdvisoryDatabase
```

See
[Configuration → Advisory Source](configuration.md#advisory-source-lookup_advisory-tool).

---

## Tools (`read_file`, `grep`, `list_files`, `lookup_advisory`)

### Attacker never calls tools

Verify `audit.tools_enabled: true` (the default). With tools disabled, the
Attacker uses `LLMClientInterface::complete()` (single-shot) instead of
`completeWithTools()`.

Some models do not support tool/function calling — verify your provider's docs.
Most major providers (Anthropic, OpenAI, Gemini, Mistral) do; some smaller
Ollama models don't.

### Attacker loops indefinitely on tool calls

Lower `audit.max_tool_iterations` from the default `8`. Once the cap is hit, the
Attacker is forced to commit to a final JSON answer.

### `lookup_advisory` always returns `[]`

See [Advisory (`composer audit`) Issues](#advisory-composer-audit-issues) above.

### `read_file` / `grep` returns nothing for files I know exist

The tools are scoped to the project path passed to `audit:run`. Symlinks outside
that path are not followed. Use absolute paths only when the file is under the
project root.

---

## CI Failures

### GitHub Actions: `SARIF upload failed: not authorized`

The workflow needs `security-events: write` permission:

```yaml
permissions:
  contents: read
  security-events: write
```

### GitLab CI: SARIF report not visible in Security Dashboard

Upload it as a `sast` report:

```yaml
artifacts:
  reports:
    sast: gl-sast-report.sarif
```

Path can be anything — GitLab parses the file. See
[CI → GitLab CI](ci.md#gitlab-ci).

### Audit succeeds locally but fails in CI

Common causes:

- API key secret not exposed to the job (check the workflow `env` block).
- CI runner lacks Composer 2.4+ → `lookup_advisory` reports empty.
- `composer.lock` not committed → `lookup_advisory` reports empty.
- Different model name between local config and CI config.

---

## Dev / Quality Gate Failures

### PHPStan max fails on a finding I think is wrong

Do **not** silence it. PHPStan suppressions (`@phpstan-ignore-*`, baseline) are
forbidden — see
[CLAUDE.md → Never Silence Quality Gates](../CLAUDE.md#5-never-silence-quality-gates).
Fix the underlying type issue. Genuine PHPStan false positives require a
tracking issue and a justification in the PR description.

### Infection MSI is below 100%

A mutation survived your tests. Read the Infection log (`var/infection.log`) to
see which mutator and which line. Add a test that distinguishes the mutated
behavior. Suppression annotations are forbidden.

### PHP CS Fixer / Rector wants to change code I deliberately wrote that way

Run `bin/castor lint:fix` to apply the changes. Both tools enforce the project
style — diverging styles get rejected in CI. If you genuinely need a deviation,
document the reason in the PR.

### Tests pass locally, fail in CI

- Different PHP version — CI matrix runs 8.3, 8.4, 8.5; pin locally with Docker.
- Filesystem case sensitivity — Linux CI is case-sensitive; macOS is not.
- Random test order — Infection runs with random order; reproduce locally with
  `--order=random --random-order-seed=<seed>`.
