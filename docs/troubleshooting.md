# Troubleshooting

Find the error message or symptom below and apply the fix. Found a new one? [Open an issue](https://github.com/vinceamstoutz/symfony-security-auditor/issues).

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

> See also: [FAQ](faq.md) · [Configuration](configuration.md) · [CI Integration](ci.md)

## Standalone Binary Issues

These apply to the standalone binary only (`init`, `doctor`, `self-update`).

### `doctor` reports a Configuration or API key failure

`audit` and `init` fail on the same causes. Fix the one `doctor` names:

- **`No provider is configured — run "init".`**: run `init`.
- **`No API key available. Your config reads it from "<VAR>", …`**: store the key with `auth:set --env-var=<VAR>`, export `<VAR>` or pass it for one run. Check with `auth:status --env-var=<VAR>`. Without `provider:`, every configured platform needs its key. See [Providing the API key](configuration.md#providing-the-api-key).
- **`The environment variable "<VAR>", referenced by your config, is not set.`**: a setting other than the key (a `base_url` or `endpoint` written as `%env(VAR)%`) has no value. Export `<VAR>`.
- **`Config file "<path>" is not valid YAML: <detail>`**: fix the YAML at `<path>`. After `Audited project config <path> was skipped and the run goes on without it:` it is only a note: the audited project's own file was left out.
- **`Cannot resolve the user configuration directory: …`**: set `$HOME`, or set `SYMFONY_SECURITY_AUDITOR_HOME` to the absolute path of a writable directory. When the message names `SYMFONY_SECURITY_AUDITOR_HOME`, it holds a relative path: make it absolute or unset it.

### `doctor` reports the provider bridge as not installed or unbootable

- **`Not installed — run "init --provider=<platform>" to download it.`**: run that command.
- **`Installed, but the audit cannot start with it: <reason>`**: the bridge was installed for another provider or by another binary version. Run `init --provider=<current provider> --force` (see [the next entry](#the-provider-bridge-under--was-installed-for-symfonyai-platform--but-this-binary-bundles-) for the options to pass).
- **`Installed, but the audit cannot start with it: The service "Symfony\AI\Platform\PlatformInterface" has a dependency on a non-existent service "http_client".`** (Ollama, 1.20.1 and earlier): run `self-update`. Re-running `init` does not help.

### `The provider bridge under "…" was installed for symfony/ai-platform …, but this binary bundles …`

`audit`, `mcp:serve` and `doctor` stop: another version of the binary installed the bridge, which would fail every LLM call. Run the `init` command the message names. It rewrites `config.yaml`, so pass your `--model` and connection options again (`--endpoint`, `--base-url`, `--env-var`, `--no-api-key`):

```bash
symfony-security-auditor init --provider=ollama --force --model=<your model> --endpoint=<your endpoint>
```

Without `--force`, `init` asks before overwriting `config.yaml` and `--no-interaction` answers no.

### `The project config "…" declares …` or `sets …`

The `.symfony-security-auditor.yaml` of the audited repository sets a key only your user `config.yaml` may set. Move the key to your user `config.yaml`:

- `platform`, `provider` or `scan.import_sarif`, which could send your API key, your code or your files elsewhere.
- `cache`, `privacy`, `audit.custom_skills`, `audit.output`, `audit.tools_scope`, `scan.custom_risk_patterns` or `scan.secret_scrubbing`.

A project file that loosens your `audit.budget`, shortens your `http_timeout` or replaces a whole section fails with `The project config "…" sets "…" …`: it may only lower the budget, raise the timeout and override single keys. The file of the folder you run from stops the run (and fails `doctor`'s `Configuration` check). The file of another project named by `project-path` is skipped instead, with an `Audited project config <path> was skipped and the run goes on without it: …` note. See [Per-project overrides](configuration.md#per-project-overrides).

### `self-update` fails

- **`Self-update does not support the "Windows" / "<machine>" platform; …`**: only Linux and macOS update themselves. Reinstall with `install.ps1` or download the release asset.
- **`Failed to download "<url>": <reason>`**: curl failed (offline, DNS, TLS, GitHub's `403` rate limit, release metadata over 1 MiB or a download over 256 MiB). `<reason>` is curl's error. Retry later or download the asset by hand.
- **`Could not determine the latest released version from "<url>".`**: GitHub answered without a usable release tag (outage, rate limit). Retry later.
- **`Checksum verification failed for "<asset>"; …`**: nothing was replaced. Retry, or download the asset and check its `.sha256` yourself.
- **`The directory "<dir>" holding the binary is not writable …`**: the directory must be writable, not only the binary. Rerun with the needed permissions (`sudo`) or reinstall with the install script.
- **`Failed to replace the binary at "<path>": <reason>`** (exit `1`, after `Downloaded and verified …`): the previous version is still installed. Rerun `self-update`.

### Every command warns `The provider bridge under "…" cannot be loaded by this binary`

The bridge tree was built for another PHP than the binary's (typically by a release before 1.15). `init`, `self-update` and `--version` still work; `audit` stops at the missing bridge. Rebuild it with `init --provider=<platform> --force`.

### `init` fails to install the provider bridge

`init` installs the bridge under the data directory with the `composer.phar` 2.8.12 it bundles, before it writes the config. `doctor` does not report these failures. Fix by message:

- **`The composer.phar 2.8.12 this binary bundles does not match its pinned SHA-256 checksum; …`**: the binary is damaged. Download it again.
- **`Could not copy composer.phar 2.8.12 to "<dir>": <reason>`** or **`Could not initialize a composer project in "<dir>": <reason>`**: make the data directory writable (permissions, disk space).
- **`This build bundles no composer.phar 2.8.12 …`**: you run a source checkout. Put that `composer.phar` release at `resources/composer.phar`.
- **`Installing the "<package>" provider bridge failed: <composer's error output>`**: check the network and the spelling of `--provider`.
- **`Refusing to initialize a composer project in "<dir>": the target or its manifest path is a symlink.`**: replace the symlinked data directory or `composer.json` with a real one.

## Installation & Setup

### `Class "Symfony\AI\AiBundle\AiBundle" not found`

`symfony/ai-bundle` is not installed or not autoloaded yet. Install a platform bridge, then register both bundles, in either order:

```bash
composer require symfony/ai-anthropic-platform  # or any other bridge
```

```php
// config/bundles.php
Symfony\AI\AiBundle\AiBundle::class => ['all' => true],
VinceAmstoutz\SymfonySecurityAuditor\SymfonySecurityAuditorBundle::class => ['dev' => true, 'test' => true],
```

### `No AI platform is configured`

The `symfony/ai-bundle` recipe ships `config/packages/ai.yaml` with every platform commented out. Uncomment one (e.g. `anthropic`) and set its API key. See [Platform Configuration](configuration.md#platform-configuration).

On 1.7.0 and earlier, the same cause shows as `The service "security_auditor.attacker_client" has a dependency on a non-existent service "Symfony\AI\Platform\PlatformInterface"` (at `cache:clear`) or `Argument #1 ... must be of type Symfony\AI\Platform\PlatformInterface, NULL given`. Upgrade to 1.7.1 or later, then configure a platform and install its `symfony/ai-*-platform` package.

### `Several AI platforms are configured (…) and none is selected`

Alias the interface to the platform to audit with, one the message names:

```yaml
# config/services.yaml
services:
    Symfony\AI\Platform\PlatformInterface: '@ai.platform.anthropic'
```

See [Several platforms in a Symfony application](configuration.md#several-platforms-in-a-symfony-application).

## Running the Audit

### `audit:run` not registered / unknown command

The bundle is registered for `dev` and `test` only. Run in one of them:

```bash
APP_ENV=dev bin/console audit:run /path/to/project
```

Or enable it everywhere in `config/bundles.php`:

```php
VinceAmstoutz\SymfonySecurityAuditor\SymfonySecurityAuditorBundle::class => ['all' => true],
```

### `[ERROR] Project path "/x" is not a valid directory`

The `project-path` argument is not an existing directory. A relative path is resolved against the folder you run from: `audit src/Command` run from your home folder looks for `~/src/Command`. Pass an absolute path, or omit it to audit the current folder. The run exits `1` before scanning.

To audit part of a project, give the part as `--path`, relative to the project:

```bash
symfony-security-auditor audit /path/to/project --path src/Command
```

An absolute `--path` inside the project works, even through a symlink (macOS `/tmp` is `/private/tmp`); one outside is refused. `--path` replaces `scan.included_paths` for the run (_since 1.22_), so it reaches folders the configuration leaves out. It must exist and hold PHP, Twig, YAML or XML files. When nothing matches, the warning names the project and the paths: `No files matched under "/home/me" for --path src/Command.`

### `[ERROR] The scan found no file to audit, so the run has no verdict`

No `.php`, `.twig`, `.yaml`, `.yml` or `.xml` file was found in `scan.included_paths` (default: `src/`, `config/`, `templates/`, `public/index.php` and the root dotenv files). Check:

- The project path and any `--path`.
- `scan.included_paths` against a non-standard layout (`app/`, a monorepo). A `No included paths exist in project` warning means no entry exists.
- `scan.respect_gitignore`, which may filter everything out.

Naming a folder of the project as the project (`audit /path/to/project/src`) is fine: it audits the project narrowed to `src` and says so in a `Scope:` line.

### Audit exits with code `1` even though risk is LOW

Exit `1` also means:

- `audit.fail_on` (or `--fail-on`) is `low` or `safe`.
- The score fell below `--min-score` (or `audit.min_score`).
- The run has no verdict: the scan found no file (see above), or no file could be analyzed and nothing was found (`Audit incomplete: none of the N file(s) in scope could be analyzed`, see [`Audit incomplete`](#audit-incomplete-n-files-could-not-be-fully-analyzed)). A `--since` run with no changed file exits `0`.
- The project path or an option is invalid (e.g. `--format`, see [Options](configuration.md#options)), or the pipeline threw (read stderr).

See [Exit codes](configuration.md#exit-codes). In a Symfony application, rerun with `-v` or `-vv` to see more of the log. The standalone binary writes no log: read its `✗ chunk N/M failed` lines and the error it prints.

## LLM & Provider Errors

### `API key not set` / `401 Unauthorized`

The process running the audit has no valid key.

- Check it is exported in the same shell: `echo $ANTHROPIC_API_KEY` must not be empty.
- In Docker, pass it through: `docker compose exec -e ANTHROPIC_API_KEY="$ANTHROPIC_API_KEY" php bin/console audit:run`.
- In the standalone binary, `auth:status` shows which key resolves and `auth:set` stores one. See [Providing the API key](configuration.md#providing-the-api-key).

### `Rate limit exceeded` / `429`

- **Quota used up** (OpenAI's `You exceeded your current quota, please check your plan and billing details.`, `insufficient_quota`): the run stops at once. Add credit or raise the plan's limit, then rerun.
- **Rate limit** (`Please retry in 41.8s.`): retried automatically after the wait the provider names, up to 300 s. To stay under it, set `audit.rate_limit.requests_per_minute`, `audit.rate_limit.input_tokens_per_minute` and `audit.rate_limit.output_tokens_per_minute` to your tier. Otherwise lower `audit.max_iterations`, raise `audit.reviewer_batch_size` to `5`, use a reviewer model with higher limits or run nightly. See [Avoiding rate limits](cost-and-performance.md#avoiding-rate-limits-429).

### `prompt is too long` / `context_length_exceeded` / HTTP `413`

A chunk exceeds the model's input window, `audit.rate_limit.input_tokens_per_minute` or a gateway's body limit (nginx's `client_max_body_size` is 1 MB by default; its `413` may read as `Syntax error` or `Response does not contain choices.`). The run splits the chunk in two until each part fits and logs `Attacker chunk exceeds the model input limit; it is split in two and each half analyzed on its own` (for a reviewer batch: `Reviewer batch exceeds the model input limit; …`). Raise the gateway's limit to avoid the split.

A single file that still does not fit is recorded as errored (`Attacker chunk exceeds the model input limit as a single file; …`), as is a lone finding the reviewer cannot fit. To get it analyzed:

- Turn on `audit.code_slicing.enabled` (the `fast` profile does).
- Use an attacker model with a larger context window (`attacker_model`).
- Leave generated or vendored trees out of `scan.included_paths`.

When even a small file is refused, the run stops: the system prompt and project mapping fill the window.

```text
The audit prompt was refused even with only the 512-byte file "src/Kernel.php" in it (…): the system prompt and the project mapping around it take up the rest, so no file can fit. Use a model with a larger context window for the attacker, raise audit.rate_limit.input_tokens_per_minute when that limit refused it, or narrow scan.included_paths.
```

A tool conversation that outgrows the window after tool results (`Tool-using conversation outgrew the model input limit after tool results were appended; …`) keeps what it recorded and its chunk is errored. Lower `audit.max_tool_iterations`.

### `OpenSSL SSL_read: … unexpected eof while reading` / `Transfer closed with … bytes remaining to read` / `cURL error 56`

The endpoint closed the connection mid-answer. The call is retried on a fresh connection (`audit.retry.max_attempts`, default `3`), as are curl's other wordings: `Transfer closed with outstanding read data remaining`, `Failure when receiving data from the peer`, `OpenSSL SSL_read: SSL_ERROR_SYSCALL, errno 0`, `HTTP/2 stream 1 was not closed cleanly: INTERNAL_ERROR (err 2)`, `Error in the HTTP2 framing layer`. When it keeps happening (most often on a self-hosted endpoint or behind a proxy):

- Raise the endpoint's or proxy's `keepalive_timeout` above the longest gap between calls. Raise `proxy_read_timeout` / `proxy_send_timeout` above the longest generation.
- Set `audit.attacker_max_concurrent` and `audit.reviewer_max_concurrent` to `1` for a server with few workers (the `fast` profile opens four of each).

When every retry fails, the run exits `1` with an incomplete report. Rerun: the cache serves the chunks already analyzed.

### `Idle timeout reached for "…"` / HTTP `499` in the gateway log

Nothing came back before the HTTP client's idle timeout: a slow local model, or a gateway that answers only once done. Answers stream on every platform but Vertex AI, Venice, Cohere, MiniMax, Bedrock and `cli_agent` (_since 1.23_), so this hits those or a gateway that cannot stream. Raise the timeout:

- **Standalone binary** (default 600 s): set `http_timeout`, in seconds.

  ```yaml
  # ~/.config/symfony-security-auditor/config.yaml
  http_timeout: 1800
  ```

- **Symfony bundle**: the platform uses your `http_client` service. Raise its timeout for every request:

  ```yaml
  # config/packages/framework.yaml
  framework:
      http_client:
          default_options:
              timeout: 1800
  ```

  Or only for the LLM platform, with a scoped client named in the platform's `http_client` option:

  ```yaml
  # config/packages/framework.yaml
  framework:
      http_client:
          scoped_clients:
              llm.http_client:
                  base_uri: 'http://localhost:11434'
                  timeout: 1800

  # config/packages/ai.yaml
  ai:
      platform:
          ollama:
              endpoint: 'http://localhost:11434'
              http_client: 'llm.http_client'
  ```

### `Failed to parse attacker agent JSON response` / `Failed to parse reviewer response`

The answer held no JSON the parser could recover. The chunk is skipped and the `error` log entry's `content_preview` shows the first 512 bytes. This happens only on the JSON path (`audit.structured_collection: false`, or for the reviewer `audit.reviewer_structured_collection: false` or `audit.reviewer_tools_enabled: true`). Fix:

- Return to the defaults (`audit.structured_collection: true`, `audit.reviewer_structured_collection: true`, `audit.reviewer_tools_enabled: false`): findings then arrive through schema-checked tool calls, with no JSON to parse. This also fixes findings lost to a JSON summary (`{"total": 1}`) the model writes after its answer.
- If the prompt overflowed, see [`prompt is too long`](#prompt-is-too-long--context_length_exceeded--http-413).
- If the model refuses "hacking" prompts (some small open-weight models do) or fails on every chunk, switch model.

### `Tool-using loop ended with empty content response` warnings

The model answered with nothing usable. Once a tool round has run, this logs at `debug`, so search by message text. A log entry names the cause:

- **`LLM response was truncated by the output token limit`**: raise `max_output_tokens` (default `4096`) or its per-agent variants. Raise `audit.rate_limit.output_tokens_per_minute` with them. A thinking model that spends the limit on reasoning needs the same, or a lower reasoning effort. `max_output_tokens` applies to Claude models; for another model see [Model Options](configuration.md#model-options).
- **`LLM response was suppressed by the provider content filter`** (or Azure's HTTP 400 `content_filter`, `Unsupported finish reason "content_filter".`): try another model or deployment.
- **`LLM response ended abnormally with no content`** (Gemini, Vertex AI: `MALFORMED_FUNCTION_CALL`, `RECITATION`, `OTHER`, … in `finish_reason`): the file is retried on the next run.

```yaml
symfony_security_auditor:
    max_output_tokens: 4096
    attacker_max_output_tokens: 8192 # optional, for chunks with many findings
    reviewer_max_output_tokens: 2048 # optional, reviewer needs less headroom
```

The file or finding is then recorded as errored. The call still counts against `audit.budget`.

### `The provider does not know the model "…"` after `init -n`

`init --no-interaction` without `--model` writes `claude-opus-5-5` as a placeholder for a provider it cannot list models for (a gateway such as LM Studio or vLLM, an Ollama it could not reach or with no model pulled, a provider the price catalog does not list). It warns when it does so and marks the line in `config.yaml` with a comment. `doctor` warns about it too. Set `model:` in `config.yaml` to a model the provider serves, or run `init` again with `--model`. In a Symfony application, set `symfony_security_auditor.model`.

### `Ollama: model not found`

Pull the model, then check it with `ollama list`. The `model` setting must match its name exactly. On Ollama, `audit:run` notes each configured model the server has not pulled before the run starts and `doctor` warns about it.

```bash
ollama pull llama3.3
```

## Empty / Surprising Reports

### `✗ chunk N/M failed` on the progress line

The chunk's files are recorded as errored, left out of the cache and counted under `Audit incomplete`. Fix by the reason on the line:

| Reason | Fix |
| --- | --- |
| `tool-call limit reached (audit.max_tool_iterations)` | Raise `audit.max_tool_iterations` (try `16`) or set `audit.tools_enabled: false`. See [the cost](#attacker-loops-indefinitely-on-tool-calls). |
| `output token limit reached (max_output_tokens)` | Raise `max_output_tokens` or `attacker_max_output_tokens`. |
| `answer withheld by the provider content filter` | Try another model or deployment. |
| `the model returned no content` | Retry; switch model if every chunk fails. |
| `the answer was not valid JSON` | See [`Failed to parse …`](#failed-to-parse-attacker-agent-json-response--failed-to-parse-reviewer-response). |
| `a finding the record tool refused was never recorded again` | The model never repeated a refused `record_vulnerability` call, so that finding is lost. Retry; switch model if every chunk fails. |
| `the file is too large for the model input limit` | See [`prompt is too long`](#prompt-is-too-long--context_length_exceeded--http-413). |
| any other message | An unexpected failure; the run went on. Read the message (also in the Symfony log). |

### `Audit incomplete: N file(s) could not be fully analyzed`

Some file was not fully analyzed, so the report does not call it safe (JSON `complete: false`, SARIF `executionSuccessful: false`). The JSON report's `coverage` array names each file, its stage and its status. Fix by cause, then rerun (the cache serves the files already analyzed):

- **LLM call failed** after the `audit.retry.*` retries: read the `LLM call failed` log entries and fix the cause (see [LLM & Provider Errors](#llm--provider-errors)).
- **`aborted`**: a provider error or a budget cap stopped the run first.
- **`Attacker answer held entries that could not be read as findings`**: the warning names the files; the findings that did read are kept.
- **`secret_scrubbing`**: a `scan.secret_scrubbing.additional_patterns` regex could not be evaluated (catastrophic backtracking, `/u` on invalid UTF-8, or a quoted value of several hundred KB without PCRE JIT). Fix the pattern, or review the file yourself.
- **`reviewer` `errored`**: the reviewer reached no verdict (`Reviewer reached no verdict for the finding; …`). The next run, or a later iteration, reviews it again.
- **`scan` `errored`**: a name or content that is ambiguous once repaired to UTF-8, see [below](#file-content-is-not-valid-utf-8--file-name-is-not-valid-utf-8-warnings).

Files the scan skipped (over `scan.max_file_size_kb`, unreadable, symlinked) are listed as `skipped` under `scan`, with a `The scan left a file out, so it is not analyzed` warning, but keep the report complete: `--fail-on-incomplete` does not fire. Raise `scan.max_file_size_kb` to audit a large one.

When no file was analyzed and nothing was found, the run exits `1` and reads `RISK LEVEL: UNKNOWN  (no file was analyzed)`. Otherwise the risk level covers only the analyzed files. Set `--fail-on-incomplete` (exit `3`) to fail CI on a partial run.

### `File content is not valid UTF-8` / `File name is not valid UTF-8` warnings

Nothing to fix: each invalid byte is read as its Latin-1 character and the file is audited, under its repaired name (`Fo\xFFo.php` as `Foÿo.php`). Re-encode the content or rename the file to see its real name.

Two cases leave the file out as `errored` under `scan`, so the report is incomplete: a repaired name equal to another file's (`caf\xE9.php` beside a UTF-8 `café.php`), or content mixing invalid bytes with the characters they repair into. Rename the file or re-encode it to UTF-8.

### A finding or a file quotes `***REDACTED:secrets_vault_key***`

The file holds a Symfony secrets vault decryption key (`config/secrets/<env>/<env>.decrypt.private.php`, or a key-shaped literal in another file). `scan.secret_scrubbing.enabled` (the default) replaced it before sending. The file is still audited, so a "key committed" finding is genuine:

1. Remove `config/secrets/prod/prod.decrypt.private.php` from the repository (the Symfony Flex `.gitignore` ignores it).
2. Deploy the key through the `SYMFONY_DECRYPTION_SECRET` environment variable.
3. If it was ever pushed, rotate it with `secrets:generate-keys --rotate`.

### Report has zero vulnerabilities but I know there are some

1. Check the file was scanned: `--show-scanned` lists the files in scope. If it is missing, see [A file is not scanned](#a-file-is-not-scanned-or-read_file--grep-returns-nothing-for-it).
2. Lower `audit.min_confidence` from `0.6` to `0.3`.
3. Raise `audit.max_iterations` to `5`.
4. Use a stronger attacker model; see [Which LLM model should I use?](faq.md#which-llm-model-should-i-use).

### Report has too many false positives

- Raise `audit.min_confidence` from `0.6` to `0.8`.
- Give the reviewer a stronger model: it needs accuracy, not speed.
- Read `reviewer_notes` in the `Vulnerability reviewed` log entry (`debug` level): it says why a weak finding was accepted.

### Same code, different findings on each run

LLM output is nondeterministic. Keep `cache.enabled: true` so unchanged code reuses earlier answers. On a model that accepts it, also set `temperature` to `0.0`:

```yaml
symfony_security_auditor:
    model: 'claude-haiku-5-5?temperature=0.0'
```

The current Claude generation (Opus 4.7/4.8, Opus 5, Sonnet 5, Fable 5) rejects `temperature`: rely on the cache alone.

## Performance & Cost

### Audit takes 10+ minutes

Time and cost grow with the files in scope: at least one call per chunk per iteration, plus reviewer calls. Measure first with `--dry-run`, which prints the file count and the estimated tokens and cost without calling the model. Then:

- Audit a slice: `--path src/Controller --path src/Form` (repeatable) or a narrower `scan.included_paths`. On a monorepo, run one audit per bounded context.
- Audit only what changed: `--since main` on a pull request.
- Use `profile: fast` (one iteration, lean pre-scan, code slicing, four concurrent calls per agent), or raise `audit.attacker_max_concurrent` and `audit.reviewer_max_concurrent` within your rate limits.
- Give the reviewer a faster model (`reviewer_model`).
- Raise `audit.reviewer_batch_size` from `1` to `5`.
- Lower `audit.max_iterations` from `3` to `1` or `2`.
- Keep both caches on: `cache.enabled: true` and Anthropic `cache_retention` in `ai.yaml` (default `short`).

See [Cost & Performance](cost-and-performance.md).

### Cost blew past my budget

- Cap the run: `audit.budget.max_tokens` or `audit.budget.max_cost_usd` stops it with exit `2` and still writes the partial report.
- Narrow `scan.included_paths` (the default already skips `vendor/`, `tests/`, `migrations/` and other non-skeleton folders): drop `templates/` or `config/`, or list `src/Controller`, `src/Form` and `src/Voter` instead of `src`.
- Keep `cache.enabled: true` and Anthropic prompt caching (`cache_retention`, about 90% off cached input).
- Lower `audit.max_tool_iterations` from `8` to `4` or `5`.
- Switch to a cheaper Reviewer (`reviewer_model: claude-haiku-5-5` or `deepseek-flash`).
- Set a provider-side cap: see [Set a spend cap](ci.md#set-a-spend-cap).
- Run weekly instead of nightly on a large monorepo.

### `--dry-run` estimate shows `$0.00`

The model has no price in the `symfony/models-dev` catalog. The run warns `No published pricing for the configured model(s): <model>. …`. For a local model (Ollama, LM Studio) `$0.00` is correct. Otherwise:

- Fix a typo in `model`, `attacker_model` or `reviewer_model`. The catalog no longer lists DeepSeek's `deepseek-chat` and `deepseek-reasoner`: use `deepseek-flash` or `deepseek-v4-pro`.
- Refresh the catalog. In a Symfony application, run `composer update symfony/models-dev`. In the standalone binary, run `self-update`: it downloads the current catalog even when the binary is up to date (`doctor`'s `Pricing catalog` line names the copy in use; `self-update --check` and `privacy.offline_only: true` leave it alone).
- Or supply prices with your own `PricingProviderInterface` (see [Extending](extending.md)).

Token counts stay accurate; only the USD figure is missing.

## Cache Issues

### Cache seems stale: old findings persist after fixing code

The cache is keyed by chunk content, so a changed file is re-analyzed. Stale findings mean its bytes did not change: diff to confirm. To force a fresh analysis, run with `--no-cache`, or delete the cache (adjust the path to `cache.dir` if you set it):

```bash
rm -rf var/cache/dev/symfony_security_auditor/attacker
```

### `Permission denied` writing to `cache.dir`

Give the user running the audit write access, or point `cache.dir` elsewhere:

```bash
chown -R www-data:www-data var/cache
```

```yaml
symfony_security_auditor:
    cache:
        dir: '/tmp/symfony-security-auditor/cache'
```

### Every run misses the cache and logs `cache entry path was a symlink`

A symlink below `cache.dir` is refused on read (`Attacker cache entry path was a symlink, ignoring`) and on write (`Failed to write attacker cache entry`). Remove the link, or point `cache.dir` at its target. A symlinked `cache.dir` or parent (`var/`, `~/.cache`) is fine.

### Disable cache for one-off debugging

Run with `--no-cache`: it skips cache reads and writes for that run. To turn the cache off in the configuration:

```yaml
symfony_security_auditor:
    cache:
        enabled: false
```

## Advisory (`composer audit`) Issues

### `lookup_advisory` always returns empty results

The audit goes on without CVE data and logs a `warning`. Fix the cause:

- **`composer` not in `PATH`** (bundle only): install Composer 2.4+ on the audit host. The standalone binary runs the Composer it bundles; `doctor` checks it.
- **`composer.lock` missing, over 8 MiB or a symlink leaving the project**: run `composer install` and keep the lockfile a regular file (a symlink to one inside the project works).
- **Malformed output**: regenerate the corrupted `composer.lock`.
- **Advisories of a private repository missing**: the audited project's `composer.json` and `auth.json` are not read. Configure the repository in the global Composer configuration (`COMPOSER_HOME`) of the user running the audit.
- **Process error** (Packagist unreachable): retry. A lookup reruns `composer audit` five minutes after a failure or once `composer.lock` changes.
- **`privacy.offline_only: true`**: intended. The advisory feed is off and nothing is logged.

### `composer audit` is slow

It runs once per audit (a long-running `mcp:serve` reruns it every 24 h). With `cache.enabled: true`, its result is cached for 24 h per `composer.lock` hash, so an unchanged lockfile skips it. A lockfile over 8 MiB, or a symlink leaving the project, is never cached. Still too slow? Replace the source with your own `AdvisoryDatabaseInterface`, such as an `InMemoryAdvisoryDatabase` snapshot: see [Advisory Source](configuration.md#advisory-source-lookup_advisory-tool).

## Tools (`read_file`, `grep`, `list_files`, `lookup_advisory`)

### Attacker never calls tools

- Check `audit.tools_enabled: true` (the default).
- Check the model supports tool calling: Anthropic, OpenAI, Gemini and Mistral do; some small Ollama models do not.

### Attacker loops indefinitely on tool calls

Lower `audit.max_tool_iterations` (default `8`) to bound the spend. On its last round the model is told to record what it holds. A chunk that still asks to read on the closing request keeps its findings but is recorded as errored and not cached, so the next run pays for it again.

If chunks keep failing that way, or keep reaching the cap without a finding, raise the cap instead (try `16`). Each extra round re-reads the prompt and costs more. The value is part of the attacker cache key, so the next run re-analyzes every chunk once.

### A file is not scanned, or `read_file` / `grep` returns nothing for it

The tools see only the files the scan loaded; `--show-scanned` lists them. A file is left out when:

- It is outside `scan.included_paths` (or `--path`).
- `scan.respect_gitignore: true` matches it, even if git tracks it. Set `scan.include_tracked_ignored: true` to audit tracked files, or `scan.respect_gitignore: false`.
- It is a dot file or sits in a dot directory (`.helpers.php`, `src/.legacy/`). Set `scan.include_dotfiles: true` or list it in `scan.included_paths`. Version-control directories (`CVS`, `_darcs`, `.svn`) always stay out.
- It is larger than `scan.max_file_size_kb` (default `512`). Raise it.
- It, or a directory above it, is a symlink, wherever it points (`Skipped symlinked file`, `Skipped symlinked included path`, `Skipped symlinked directory`).
- Its directory cannot be listed (`Skipped unreadable directory`), or it is a pipe, socket or device (`Skipped a file that is not a regular file`).

Over-size, unreadable and symlinked files are listed as `skipped` in the report's `coverage`; the report stays complete.

`read_file` takes the project-relative path (`src/Controller/UserController.php`). An absolute path returns `Error: file "..." is not part of the audited project.`

## CI Failures

### GitHub Actions: `SARIF upload failed: not authorized`

Grant the workflow `security-events: write`:

```yaml
permissions:
  contents: read
  security-events: write
```

### GitLab CI: SARIF report not visible in Security Dashboard

Upload it as a `sarif` report, not `sast`:

```yaml
artifacts:
  reports:
    sarif: security-audit.sarif
```

It needs GitLab Ultimate 19.2 or later (18.11 with the `sarif_ingestion` feature flag). GitLab ingests it only from a successful job: catch the audit's exit code in the script (`|| audit_exit=$?`), as the [GitLab CI](ci.md#gitlab-ci) recipe does. On another tier or version, use the JUnit report shown there.

### Audit succeeds locally but fails in CI

- The API key secret is not exposed to the job (check its `env` block).
- `lookup_advisory` finds nothing: the runner lacks Composer 2.4+ or `composer.lock` is not committed.
- The model name differs between the local and CI configuration.

## Dev / Quality Gate Failures

### PHPStan max fails on a finding I think is wrong

Fix the underlying type issue. Suppressions (`@phpstan-ignore-*`, a baseline) are forbidden: see [Never Silence Quality Gates](../CLAUDE.md#5-never-silence-quality-gates). A genuine false positive needs a tracking issue and a justification in the PR description.

### Infection MSI is below 100%

Read `infection/infection.log` for the mutator and line, then add a test that tells the mutated behavior apart. Suppression annotations are forbidden.

### PHP CS Fixer / Rector wants to change code I deliberately wrote that way

Run `bin/castor lint:fix` to apply the project style: CI rejects any other. Justify a genuine deviation in the PR.

### Tests pass locally, fail in CI

- PHP version: CI runs 8.3, 8.4, 8.5 and 8.6. Reproduce with Docker.
- File name case: Linux CI is case-sensitive, macOS is not.
- Test order: Infection forces `executionOrder="defects,random"`. Reproduce with `--order-by=defects,random --random-order-seed=<seed>`.
