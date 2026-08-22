# Troubleshooting

Common problems running **symfony-security-auditor** and how to fix them. Found
a new gotcha?
[Open an issue](https://github.com/vinceamstoutz/symfony-security-auditor/issues)
so we can document it.

## Table of Contents

- [Standalone Binary Issues](#standalone-binary-issues)
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

## Standalone Binary Issues

Entries in this section apply only to the standalone binary (`init`,
`self-update`, `doctor`) — not to the Symfony bundle, which has no equivalent
commands.

### `doctor` reports a Configuration or API key failure

`doctor`'s "Configuration" and "API key" lines surface
`StandaloneConfigLoader::load()` failures directly:

- **`No provider is configured — run "init".`** — no `platform:` block in
  `config.yaml`; run `init`.
- **`The environment variable "<VAR>", referenced by your config, is not set.`**
  (reported under the `API key` label) — export the `%env(VAR)%` variable your
  `platform:` block references.
- **`Config file "<path>" is not valid YAML: <detail>`** — fix the malformed
  `config.yaml` or `.symfony-security-auditor.yaml` at `<path>`.
- **Cannot resolve the user configuration directory** — set `$HOME`, or set
  `SYMFONY_SECURITY_AUDITOR_HOME` to a writable directory:

  ```text
  Cannot resolve the user configuration directory: neither the relevant XDG
  base-directory variable nor $HOME is set.
  ```

Running `audit`/`init` directly without `doctor` first hits the same underlying
failures.

### `doctor` reports the provider bridge as not installed or unbootable

Two distinct "Provider bridge" failures:

- **`Not installed — run "init" to download it.`** —
  `<data-dir>/vendor/autoload.php` does not exist yet.
- **`Installed, but the audit cannot start with it: <reason>`** — the autoloader
  exists, but `doctor` also builds the container to confirm it actually boots,
  not just that the file is present. A bridge left over from a previously
  configured provider passes the file check but fails here, since the container
  needs the _currently_ configured provider's classes, not whichever bridge
  happens to be installed. Re-run `init` for the current provider (`--force`
  skips the overwrite prompt) to install the matching bridge.

### `.symfony-security-auditor.yaml` cannot override `platform`, `provider`, or `scan.import_sarif`

Fixed as a security issue in `1.19.0`. A per-project
`.symfony-security-auditor.yaml` ships with the audited repository, so letting
it contribute these keys allowed a malicious or compromised repository to
redirect your resolved API key — and every prompt, i.e. the source code — to an
endpoint of its choosing via `platform:`/`provider:`, or to point the SARIF
importer at an arbitrary file via `scan.import_sarif`. Both are now rejected
outright before the audit starts:

- Declaring `platform` and/or `provider` aborts with
  `ProjectConfigPlatformOverrideException`:

  ```text
  The project config "<path>" declares "platform", but LLM connection
  settings are read from your user config only — a repository you audit
  must not be able to point your API credentials at another endpoint.
  Configure the platform in your user config instead.
  ```

- Declaring `scan.import_sarif` aborts with `ProjectConfigScanOverrideException`
  carrying the equivalent message for that key.

`doctor` reports the same message under a failed `Configuration` check.
Per-project overrides of audit settings (chunking strategy, `fail_on`, excluded
paths, …) are unaffected — move only `platform`/`provider`/`scan.import_sarif`
to your user `config.yaml`.

### `self-update` fails

`self-update` exists only in the standalone binary. Failures:

- **Any platform other than Linux or macOS** —
  `UnsupportedSelfUpdatePlatformException`. There is no Windows `self-update`;
  reinstall with `install.ps1` or download the new release asset directly:

  ```text
  Self-update does not support the "Windows" / "<machine>" platform;
  download the binary for your platform from the releases page instead.
  ```

- **Cannot reach GitHub** — `SelfUpdateFailedException`:
  `Failed to download "<url>".` (curl itself failed — offline, DNS, TLS) or
  `Could not determine the latest released version from "<url>".` (GitHub
  answered but without a usable `tag_name` — an API outage or rate limit).
- **Checksum mismatch** — the downloaded file is deleted and nothing is
  replaced; retry, or download the asset manually and verify its `.sha256`
  yourself:

  ```text
  Checksum verification failed for "<asset>"; the download was not trusted
  and has been discarded.
  ```

- **Binary not writable**:

  ```text
  The binary at "<path>" is not writable; re-run the update with the
  necessary permissions (e.g. sudo) or reinstall with the install script.
  ```

- **Replacement failed mid-swap** —
  `Failed to replace the binary at "<path>": <reason>.` The new binary is moved
  into place as the command exits, not while it runs — the running process still
  loads classes from the archive being replaced — so this one surfaces after
  `Updated from … to ….` has already printed. The previous binary is left in
  place, so re-running `self-update` is safe.

### `init` fails to install the provider bridge

`init` always runs `composer require symfony/ai-<slug>-platform` under the data
directory before it writes the config file. `BridgeInstallationFailedException`:

- **No `composer` binary reachable**:

  ```text
  Could not run composer to install the "<package>" provider bridge; is
  composer on the PATH?
  ```

- **`composer require` ran but exited non-zero** (no network, or the package
  does not exist for a misspelled `--provider`):

  ```text
  Installing the "<package>" provider bridge failed: <composer's error output>
  ```

- **`Could not initialize a composer project in "<dir>": <reason>`** — the data
  directory has no `composer.json` yet and one could not be written there
  (permissions).
- **The data directory or its `composer.json` is a symlink** — `init` refuses to
  write through it:

  ```text
  Refusing to initialize a composer project in "<dir>": the target or its
  manifest path is a symlink.
  ```

These surface directly from `init` itself — `doctor`'s "Provider bridge" check
only inspects the _result_ of a previous `init` run, so a failed installation
never shows up there.

## Installation & Setup

### `Class "Symfony\AI\AiBundle\AiBundle" not found`

`symfony/ai-bundle` isn't installed, or Composer's autoloader hasn't picked it
up yet. This is a Composer/autoload issue, not a `config/bundles.php` ordering
problem — `AiBundle` and `SymfonySecurityAuditorBundle` can be registered in
either order.

```bash
composer require symfony/ai-anthropic-platform  # or any other bridge
```

```php
// config/bundles.php — either order works
Symfony\AI\AiBundle\AiBundle::class => ['all' => true],
VinceAmstoutz\SymfonySecurityAuditor\SymfonySecurityAuditorBundle::class => ['dev' => true, 'test' => true],
```

### `No AI platform is configured`

`audit:run` aborts with this message when no
`Symfony\AI\Platform\PlatformInterface` service exists in the container. The
`symfony/ai-bundle` recipe ships `config/packages/ai.yaml` with **every platform
commented out** — uncomment one (e.g. `anthropic`) and set its API key. See
[Configuration → Platform Configuration](configuration.md#platform-configuration).

### `The service "security_auditor.attacker_client" has a dependency on a non-existent service "Symfony\AI\Platform\PlatformInterface"`

Same root cause as above, surfaced at container compile time (`cache:clear`,
`cache:warmup`) by versions **≤ 1.7.0**. Upgrade to `1.7.1` or later — the
container then compiles without a platform and the actionable error above is
raised only when an audit actually runs.

### `Argument #1 ... must be of type Symfony\AI\Platform\PlatformInterface, NULL given`

Same root cause as above — another **≤ 1.7.0** symptom. Since `1.7.1`,
`PlatformBinding`'s platform property (and every collaborator built from it) is
typed `?PlatformInterface`, so a missing platform can no longer reach a
constructor as a hard type error. Upgrade to `1.7.1` or later, or verify
`ai.yaml` has a `platform:` block and the corresponding `symfony/ai-*-platform`
package is installed.

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

### `[ERROR] Project path "/x" is not a valid directory`

The `project-path` argument must point to a directory that exists. Use an
absolute path, or omit the argument to default to the current working directory.

### `[ERROR] Project does not look like a Symfony app`

The auditor walks the project for `.php`, `.twig`, `.yaml`, `.yml`, `.xml` files
inside `scan.included_paths` (default: `src/`, `config/`, `templates/`,
`public/index.php`, and the root dotenv files — the Symfony Flex skeleton). If
nothing is found, the path is wrong, the layout is non-standard, or
`scan.respect_gitignore` is filtering everything out. A log line
`No included paths exist in project` at `warning` level confirms the allow-list
resolved to nothing.

### Audit exits with code `1` even though risk is LOW

Exit code `1` is also used for:

- Invalid `project-path` argument.
- The scan discovered no file to audit at all — a mistyped path, a
  `scan.included_paths` entry matching nothing, or an over-narrow `--path` —
  fails rather than reporting a hollow SAFE result. A `--since` run that finds
  no _changed_ files still exits `0`.
- The normalized score fell below `--min-score`, if set.
- Unhandled exception during pipeline execution (check stderr).
- Validator errors on the input (e.g. `--format` set to a value it does not
  support — see [Configuration → Options](configuration.md#options)).

Re-run with `-v` or `-vv` to see the underlying error.

## LLM & Provider Errors

### `API key not set` / `401 Unauthorized`

Confirm the env var is exported in the same shell:

```bash
echo $ANTHROPIC_API_KEY    # should not be empty
```

In Docker, pass it through:

```bash
docker compose exec -e ANTHROPIC_API_KEY="$ANTHROPIC_API_KEY" php bin/console audit:run
```

### `Rate limit exceeded` / `429`

Configure `audit.rate_limit.requests_per_minute` / `input_tokens_per_minute` /
`output_tokens_per_minute` to your provider tier's limits so the auditor
throttles proactively instead of hitting a `429`. Otherwise, reduce concurrent
load:

- Lower `audit.max_iterations` (default `3`) to `1`.
- Raise `reviewer_batch_size` from `1` to `5` (fewer reviewer calls).
- Use a split-model with a cheaper Reviewer (Haiku, DeepSeek, Mistral) — they
  have higher rate limits.
- Run nightly, not on every PR.

### `LLM response was empty` / `Failed to parse … JSON response`

The model returned blank or non-JSON output. The chunk is skipped automatically
and logged at `error` level via `LoggerInterface`. The log entry includes a
`content_preview` field with the first 512 bytes of the response — inspect it to
see what the model actually emitted. Causes:

- Model context limit exceeded — lower `audit.max_tool_iterations` or
  split-model to a model with a larger context.
- Model refused the prompt — try a different model (some smaller open-weight
  models refuse "hacking" prompts).
- Network timeout — retry; check the provider's status page.

The parser tolerates prose wrapped around a balanced JSON block (the model
sometimes ignores the "Return ONLY the JSON array" instruction when tools are
enabled); a residual `JsonException: Syntax error` therefore means the response
contains no recoverable JSON at all, not just chatty prose.

This error only arises with `audit.structured_collection: false`. In the default
(`true`) mode, findings come in via `record_vulnerability` tool calls that the
provider validates against the schema, so there is no JSON parsing on the agent
side and no `JsonException` can be raised. Switching to the default is the
simplest fix when the model repeatedly produces unparseable prose.

If it happens for **every** chunk, the model is unsuitable. Switch model.

### `Tool-using loop ended with empty content response` warnings

Logged at `warning` level when the empty response is the very first LLM call in
the loop (no tool round happened yet); once at least one tool round has run, a
later empty response logs the same message at `debug` instead — grep by message
text rather than filtering on `warning` alone if the loop used tools first. Look
at the `output_tokens` field: if it sits near a multiple of ~1000 (e.g. `1971`,
`2000`), the model is being truncated by `symfony/ai`'s default
`max_tokens = 1000` that ships with the Anthropic bridge. Set
`max_output_tokens` in the bundle config (default `4096` since this fix) — or
`attacker_max_output_tokens` / `reviewer_max_output_tokens` for per-agent
tuning:

```yaml
symfony_security_auditor:
    max_output_tokens: 4096
    attacker_max_output_tokens: 8192 # optional, for chunks with many findings
    reviewer_max_output_tokens: 2048 # optional, reviewer needs less headroom
```

When raising the cap, raise `audit.rate_limit.output_tokens_per_minute`
proportionally — otherwise the output-tokens bucket becomes the binding
throttle.

When the provider reports why generation stopped (`symfony/ai` ≥ 0.11 exposes a
normalized finish reason), the auditor logs an explicit
`LLM response was truncated by the output token limit` warning — no output-token
forensics needed. A `LLM response was suppressed by the provider content filter`
warning likewise flags responses the provider filtered out.

### `Ollama: model not found`

Pull the model first:

```bash
ollama pull llama3.3
```

Then verify with `ollama list`. The model name in
`symfony_security_auditor.yaml` must match exactly.

## Empty / Surprising Reports

### Report has zero vulnerabilities but I know there are some

Diagnostic order:

1. **Lower `audit.min_confidence`** from `0.6` to `0.3` — borderline findings
   now pass to the Reviewer.
2. **Inspect attacker output before review** — temporarily decorate
   `ReviewerAgent` to log all incoming candidates, including non-validated ones.
3. **Raise `audit.max_iterations`** to `5` — the loop stops early when no new
   findings emerge; a stronger pass can surface more.
4. **Switch to a stronger model** — Claude Opus and GPT-5.6 consistently
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
- Inspect the LLM's `reviewer_notes` (logged at `debug` level in the
  `Vulnerability reviewed` entry) — the Reviewer often explains why it accepted
  weak findings.

### Same code, different findings on each run

LLM output is **nondeterministic** by design. Set `temperature: 0.0` (or `0.1`)
on the model:

```yaml
symfony_security_auditor:
    model: 'claude-haiku-4-5-20251001?temperature=0.0'
```

With `temperature: 0.0` + `cache.enabled: true`, repeated runs on identical code
become deterministic.

The current Claude generation (Opus 4.7/4.8, Opus 5, Sonnet 5, Fable 5) no
longer accepts `temperature` and rejects a request that sets it — on those
models rely on `cache.enabled: true` alone for run-to-run stability.

## Performance & Cost

### Audit takes 10+ minutes

Expected behavior on large projects. Mitigations:

- Use **split-model** — Opus Attacker + Haiku Reviewer cuts ~50% wall time.
- Raise `reviewer_batch_size` from `1` to `5` — fewer Reviewer round-trips.
- Lower `audit.max_iterations` from `3` to `1` or `2`.
- Tighten `scan.included_paths` to specific sub-directories — e.g. point it at
  `src/Controller`, `src/Form`, `src/Voter`, `config`, `templates` so high-value
  surfaces are audited and infrastructure code is dropped.
- Enable both caches: `cache.enabled: true` (default) and Anthropic prompt
  caching via `cache_retention` in `ai.yaml` (default `short` already on).

### What happens on a very large project (10 000+ files)?

Nothing special happens — and that is the problem. The pipeline is linear in the
number of files it keeps, so a 10 000-file repository is not "slow", it is
proportionally expensive: the scanner walks the tree once, drops everything
outside `scan.included_paths` and every file over `scan.max_file_size_kb`
(default `512`), groups what remains into chunks, and spends at least one LLM
call per chunk per iteration. Triple that for the default
`audit.max_iterations: 3`, then add one reviewer call per surviving finding.

Measure before you spend: `audit:run --dry-run` reports the retained file count
and the estimated token/cost total for **your** repository and model without
making a single audit call. Treat that number as the decision input; wall-clock
and dollar figures quoted for other projects will not transfer.

To bring a repository of that size into a sane envelope, in the order that helps
most:

- **Audit a slice, not the monolith.** `--path src/Controller --path src/Form`
  (repeatable) or a tightened `scan.included_paths` targets the code that
  actually faces user input. On a monorepo, run one audit per bounded context.
- **Audit only what changed.** `--since main` (or any git ref) restricts the run
  to files touched since that ref, which is what you want on a PR — cost then
  tracks the diff, not the repository.
- **Use `profile: fast`.** One iteration, lean pre-scan (marker-free files are
  dropped), code slicing (large files are trimmed to security-relevant lines)
  and 4× attacker/reviewer concurrency.
- **Cap the run.** `audit.budget.max_tokens` / `audit.budget.max_cost_usd` abort
  mid-run and still emit the partial report with exit code `2`, so a
  misestimated scan cannot run away with your budget.
- **Keep the cache on.** `cache.enabled: true` (default) means the second and
  later runs pay only for chunks whose content changed.

### Cost blew past my budget

- Confirm `scan.included_paths` matches the deployable code surface. The default
  (the Flex skeleton plus root dotenv files) already skips every file outside
  the Symfony skeleton — `vendor/`, `node_modules/`, `var/`, `tests/`,
  `migrations/`, `translations/`, `bin/`, root scripts, IDE folders, build
  artefacts — without you having to enumerate them.
- Trim further by tightening `scan.included_paths`: drop `templates/` or
  `config/` if you only want to audit PHP, or replace `src` with a list of
  specific sub-directories (e.g. `src/Controller`, `src/Form`, `src/Voter`) to
  focus the audit on high-value security surfaces.
- Confirm Anthropic prompt caching is on — `cache_retention` in `ai.yaml`
  (default `short`) gives a ~90% input-token discount on cached prompts.
- Confirm `cache.enabled: true` (default) — repeated chunks skip the LLM
  entirely.
- Lower `audit.max_tool_iterations` from `8` to `4` or `5` — caps chatty
  tool-use loops on each chunk at the cost of less cross-file investigation.
- Switch to a cheaper Reviewer (`reviewer_model: claude-haiku-4-5-20251001` or
  `deepseek-chat`).
- Set a provider-side hard cap. See
  [CI → Set a spend cap](ci.md#set-a-spend-cap).
- Run weekly instead of nightly for large monorepos.

### `--dry-run` estimate shows `$0.00`

The cost estimate multiplies token counts by per-model prices from the
configured `PricingProviderInterface` (the bundled `ModelsDevPricingProvider`
reads prices from the `symfony/models-dev` catalog shipped in `vendor/`). When a
configured model (`model`, `attacker_model`, or `reviewer_model`) is absent from
that catalog — a typo, or a model `symfony/ai` supports but the catalog does not
list — its price resolves to `0.0` and the dry run now prints a stderr warning:

```text
No published pricing for the configured model(s): <model>. The dry-run cost
estimate shows $0.00 for these. If you are running a local or self-hosted model
(e.g. Ollama, LM Studio), $0.00 is correct — you can ignore this notice.
Otherwise the name is likely a typo or an unlisted model: check it in your
symfony_security_auditor configuration against the models supported by your
symfony/ai platform.
```

Fix the model identifier if it is a typo. If the name is correct but missing
from the catalog, the token counts in the report are still accurate — only the
USD figure is unavailable. Run `composer update symfony/models-dev` to pull a
fresher catalog, or alias your own `PricingProviderInterface` implementation to
supply prices (see [Extending](extending.md)).

**Standalone binary:** `composer update` does not apply — there is no
user-facing `vendor/` or `composer.json`; the catalog is baked into the binary
at release-build time from whatever `symfony/models-dev` version that release's
CI resolved. The only way to get a newer catalog is `self-update` to a newer
release, and even that only carries whatever was current when that release was
built — there is no way to refresh the catalog independently of a release yet.

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

`AttackerCacheInterface` is aliased to `NullAttackerCache` (and
`ReviewerCacheInterface` to `NullReviewerCache`) — every chunk, and every
reviewer verdict, hits the LLM.

## Advisory (`composer audit`) Issues

### `lookup_advisory` always returns empty results

Causes (each logs a `warning` via `LoggerInterface`, except the deliberate
`offline_only` case below):

- **`composer` not in `PATH`** — install Composer 2.4+ on the audit host.
- **`composer.lock` missing** — run `composer install` first; advisory data
  comes from the lockfile.
- **Malformed JSON output** — corrupted `composer.lock`. Regenerate it.
- **Process error** — network failure to Packagist. Retry.
- **`privacy.offline_only: true`** — the advisory feed is intentionally replaced
  by an empty in-memory database, so `composer audit` never runs; no warning is
  logged since this is configured behavior, not a failure.

When `lookup_advisory` returns empty, the audit continues without CVE data — no
audit failure.

### `composer audit` is slow

Within a run it executes **once** and the result is cached for the lifetime of
the request. Across runs, with `cache.enabled: true` (default),
`LockfileHashedAdvisoryCache` also persists the JSON payload to disk for 24h,
keyed by a SHA-256 hash of `composer.lock` — an unchanged lockfile skips
`composer audit` entirely on the next run. If it's still the bottleneck, you can
pre-warm it before the audit or override `AdvisoryDatabaseInterface` with
`InMemoryAdvisoryDatabase` containing a baked snapshot.

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

Both tools only search the files `ProjectFileScanner` already loaded into memory
during ingestion — neither touches the filesystem live. Causes:

- The file falls outside `scan.included_paths`, is excluded by
  `scan.respect_gitignore`, or exceeds `scan.max_file_size_kb`.
- The file, or one of its `scan.included_paths` ancestors, is a symlink.
  `ProjectFileScanner` skips symlinks unconditionally regardless of where they
  point (logged as `Skipped symlinked file` / `Skipped symlinked included path`)
  — a symlink pointing back inside the project is skipped too, not just one
  pointing outside it.
- `read_file`'s `relative_path` argument must match
  `ProjectFile::relativePath()` exactly (e.g.
  `src/Controller/UserController.php`). It has no absolute-path fallback — an
  absolute path never matches and returns
  `Error: file "..." is not part of the audited project.`

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

## Dev / Quality Gate Failures

### PHPStan max fails on a finding I think is wrong

Do **not** silence it. PHPStan suppressions (`@phpstan-ignore-*`, baseline) are
forbidden — see
[CLAUDE.md → Never Silence Quality Gates](../CLAUDE.md#5-never-silence-quality-gates).
Fix the underlying type issue. Genuine PHPStan false positives require a
tracking issue and a justification in the PR description.

### Infection MSI is below 100%

A mutation survived your tests. Read the Infection log
(`infection/infection.log`) to see which mutator and which line. Add a test that
distinguishes the mutated behavior. Suppression annotations are forbidden.

### PHP CS Fixer / Rector wants to change code I deliberately wrote that way

Run `bin/castor lint:fix` to apply the changes. Both tools enforce the project
style — diverging styles get rejected in CI. If you genuinely need a deviation,
document the reason in the PR.

### Tests pass locally, fail in CI

- Different PHP version — CI matrix runs 8.3, 8.4, 8.5; pin locally with Docker.
- Filesystem case sensitivity — Linux CI is case-sensitive; macOS is not.
- Random test order — Infection rewrites `phpunit.dist.xml` to force
  `executionOrder="defects,random"` for its own runs; reproduce locally with
  `--order-by=defects,random --random-order-seed=<seed>`.
