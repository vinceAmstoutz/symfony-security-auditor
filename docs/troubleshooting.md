# Troubleshooting

Common problems running **symfony-security-auditor** and how to fix them. Found a new gotcha? [Open an issue](https://github.com/vinceamstoutz/symfony-security-auditor/issues) so we can document it.

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

Entries in this section apply only to the standalone binary (`init`, `self-update`, `doctor`) — not to the Symfony bundle, which has no equivalent commands.

### `doctor` reports a Configuration or API key failure

`doctor`'s "Configuration" and "API key" lines surface `StandaloneConfigLoader::load()` failures directly:

- **`No provider is configured — run "init".`** — no `platform:` block in `config.yaml`; run `init`.
- **`No API key available. Your config reads it from "<VAR>", which is not set in the environment and has nothing stored for it. …`** (reported under the `API key` label) — store the key with `auth:set --env-var=<VAR>`, export `<VAR>`, or pass it for one run from a password manager; `auth:status --env-var=<VAR>` shows what resolves. With several platforms configured, only the one `provider:` selects needs its key; without `provider:`, every platform's key is needed, and a bare `auth:set` would store under the first `api_key` in the file, which is why the message names `<VAR>`.
- **`The environment variable "<VAR>", referenced by your config, is not set.`** (reported under the `Configuration` label) — a setting other than the key, such as a `base_url` or `endpoint` written as `%env(VAR)%`, has no value: export the variable.
- **`Config file "<path>" is not valid YAML: <detail>`** — fix the malformed `config.yaml` or `.symfony-security-auditor.yaml` at `<path>`.
- **Cannot resolve the user configuration directory** — set `$HOME`, or set `SYMFONY_SECURITY_AUDITOR_HOME` to the absolute path of a writable directory:

  ```text
  Cannot resolve the user configuration directory: neither the relevant XDG
  base-directory variable nor $HOME holds an absolute path.
  ```

  When it names `SYMFONY_SECURITY_AUDITOR_HOME` instead, the override holds a relative path: give it an absolute one, or unset it.

Running `audit`/`init` directly without `doctor` first hits the same underlying failures.

### `doctor` reports the provider bridge as not installed or unbootable

Two distinct "Provider bridge" failures:

- **`Not installed — run "init --provider=<platform>" to download it.`** — `<data-dir>/vendor/autoload.php` does not exist yet.
- **`Installed, but the audit cannot start with it: <reason>`** — the autoloader exists, but `doctor` also builds the container to confirm it actually boots, not just that the file is present. A bridge left over from a previously configured provider passes the file check but fails here, since the container needs the _currently_ configured provider's classes, not whichever bridge happens to be installed. Re-run `init` for the current provider (`--force` skips the overwrite prompt) to install the matching bridge. A bridge an older version of the binary installed fails here too, whatever the configuration says — see the entry below.

On `1.20.1` and earlier, one reason string came from the binary rather than from the bridge:

```text
Installed, but the audit cannot start with it: The service
"Symfony\AI\Platform\PlatformInterface" has a dependency on a non-existent
service "http_client".
```

The container the binary builds registers the services `symfony/ai-bundle` expects an application to provide, and `http_client` was missing from that list. Three bridges require it outright (`ollama`, `elevenlabs` and `deepgram`), and `ollama` is the only one an audit runs against, so this surfaced as an Ollama-only failure. Upgrade the binary (`symfony-security-auditor self-update`); re-running `init` does not help, since the bridge was never the problem.

### `The provider bridge under "…" was installed for symfony/ai-platform …, but this binary bundles …`

`audit`, `mcp:serve` and `doctor` stop with:

```text
The provider bridge under "/home/you/.local/share/symfony-security-auditor" was
installed for symfony/ai-platform v0.12.0, but this binary bundles v0.14.1:
loaded, its classes would replace the bundled ones and fail every LLM call, so
the binary leaves it unloaded. Rebuild it with "symfony-security-auditor init
--provider=ollama --force" — init rewrites config.yaml, so give it your model
and connection options again.
```

The bridges under the data directory were installed by another version of the binary — 1.20.x resolved `symfony/ai-platform` 0.12 or 0.13 — and the binary loads them ahead of its own classes. Loaded, they failed every LLM call (`Call to undefined method Symfony\AI\Platform\TokenUsage\TokenUsage::getModel()`), which an audit only reported as incomplete, so the binary checks the release in `<data-dir>/vendor/composer/installed.php` before loading anything and leaves a mismatched tree alone. Run the `init` command it names, with the `--model` and connection options you use (`--endpoint`, `--base-url`, `--env-var`, `--no-api-key`): it requires every bridge the tree holds again, pinned to the bundled release. `--force` is what lets it run on a machine that already has a configuration — without it, `init` asks before overwriting `config.yaml`, and `--no-interaction` answers no before any bridge is touched.

### `.symfony-security-auditor.yaml` cannot override `platform`, `provider`, or `scan.import_sarif`

Fixed as a security issue in `1.19.0`. A per-project `.symfony-security-auditor.yaml` ships with the audited repository, so letting it contribute these keys allowed a malicious or compromised repository to redirect your resolved API key — and every prompt, i.e. the source code — to an endpoint of its choosing via `platform:`/`provider:`, or to point the SARIF importer at an arbitrary file via `scan.import_sarif`. Both are now rejected outright before the audit starts:

- Declaring `platform` and/or `provider` aborts with `ProjectConfigPlatformOverrideException`:

  ```text
  The project config "<path>" declares "platform", but LLM connection
  settings are read from your user config only — a repository you audit
  must not be able to point your API credentials at another endpoint.
  Configure the platform in your user config instead.
  ```

- Declaring `scan.import_sarif` aborts with `ProjectConfigScanOverrideException` carrying the equivalent message for that key.

`doctor` reports the same message under a failed `Configuration` check. Per-project overrides of audit settings (chunking strategy, `fail_on`, scan scope, …) are unaffected — move only `platform`/`provider`/`scan.import_sarif` to your user `config.yaml`.

### `self-update` fails

`self-update` exists only in the standalone binary. Failures:

- **Any platform other than Linux or macOS** — `UnsupportedSelfUpdatePlatformException`. There is no Windows `self-update`; reinstall with `install.ps1` or download the new release asset directly:

  ```text
  Self-update does not support the "Windows" / "<machine>" platform;
  download the binary for your platform from the releases page instead.
  ```

- **Cannot reach GitHub** — `SelfUpdateFailedException`: `Failed to download "<url>".` (curl itself failed — offline, DNS, TLS, a redirect off HTTPS, or a response over the size limit: 1 MiB for release metadata, 256 MiB for a download) or `Could not determine the latest released version from "<url>".` (GitHub answered but without a usable `tag_name` — an API outage or rate limit).
- **Checksum mismatch** — the downloaded file is deleted and nothing is replaced; retry, or download the asset manually and verify its `.sha256` yourself:

  ```text
  Checksum verification failed for "<asset>"; the download was not trusted
  and has been discarded.
  ```

- **Directory not writable** — the binary is replaced by renaming a new file over it, so the directory holding it must be writable, whatever the binary's own permissions; nothing is downloaded:

  ```text
  The directory "<dir>" holding the binary is not writable (<reason>), so the
  binary cannot be replaced; re-run the update with the necessary permissions
  (e.g. sudo) or reinstall with the install script.
  ```

- **Replacement failed mid-swap** — `Failed to replace the binary at "<path>": <reason>`, followed by `The update was not applied: the previous version is still installed.`, on stderr, and the command exits `1`. The new binary is moved into place as the command exits, not while it runs — the running process still loads classes from the archive being replaced — so this one surfaces after `Downloaded and verified <new>; it replaces <old> as this command exits.` has printed. The previous binary is left in place, so re-running `self-update` is safe.

### Every command warns `The provider bridge under "…" cannot be loaded by this binary`

The bridge tree under the data directory was resolved for another PHP than the one the binary bundles — typically a `composer.json` written by a release before 1.15, which pinned no PHP version — so Composer's `platform_check.php` refuses it. The binary prints that warning, naming the data directory, on stderr and runs the command without the bridge: `init`, `self-update` and `--version` work, and `audit` stops at the missing bridge with `ProviderBridgeException`. That holds whichever Composer generated the tree: 2.8.10 and later throw the refusal, earlier versions — the one Ubuntu's `apt` installs included — raise it as a fatal `E_USER_ERROR`, which the binary turns into the same warning. Run `init --provider=<platform> --force` again: it rewrites the manifest with the PHP and `symfony/ai-platform` pins and reinstalls the bridge.

### `init` fails to install the provider bridge

`init` always runs `composer require symfony/ai-<slug>-platform` under the data directory before it writes the config file. `BridgeInstallationFailedException`:

- **No `composer` binary reachable**:

  ```text
  Could not run composer to install the "<package>" provider bridge; is
  composer on the PATH?
  ```

- **`composer require` ran but exited non-zero** (no network, or the package does not exist for a misspelled `--provider`):

  ```text
  Installing the "<package>" provider bridge failed: <composer's error output>
  ```

- **`Could not initialize a composer project in "<dir>": <reason>`** — the data directory has no `composer.json` yet and one could not be written there (permissions).
- **The data directory or its `composer.json` is a symlink** — `init` refuses to write through it:

  ```text
  Refusing to initialize a composer project in "<dir>": the target or its
  manifest path is a symlink.
  ```

These surface directly from `init` itself — `doctor`'s "Provider bridge" check only inspects the _result_ of a previous `init` run, so a failed installation never shows up there.

## Installation & Setup

### `Class "Symfony\AI\AiBundle\AiBundle" not found`

`symfony/ai-bundle` isn't installed, or Composer's autoloader hasn't picked it up yet. This is a Composer/autoload issue, not a `config/bundles.php` ordering problem — `AiBundle` and `SymfonySecurityAuditorBundle` can be registered in either order.

```bash
composer require symfony/ai-anthropic-platform  # or any other bridge
```

```php
// config/bundles.php — either order works
Symfony\AI\AiBundle\AiBundle::class => ['all' => true],
VinceAmstoutz\SymfonySecurityAuditor\SymfonySecurityAuditorBundle::class => ['dev' => true, 'test' => true],
```

### `No AI platform is configured`

`audit:run` aborts with this message when no `Symfony\AI\Platform\PlatformInterface` service exists in the container. The `symfony/ai-bundle` recipe ships `config/packages/ai.yaml` with **every platform commented out** — uncomment one (e.g. `anthropic`) and set its API key. See [Configuration → Platform Configuration](configuration.md#platform-configuration).

### `The service "security_auditor.attacker_client" has a dependency on a non-existent service "Symfony\AI\Platform\PlatformInterface"`

Same root cause as above, surfaced at container compile time (`cache:clear`, `cache:warmup`) by versions **≤ 1.7.0**. Upgrade to `1.7.1` or later — the container then compiles without a platform and the actionable error above is raised only when an audit actually runs.

### `Argument #1 ... must be of type Symfony\AI\Platform\PlatformInterface, NULL given`

Same root cause as above — another **≤ 1.7.0** symptom. Since `1.7.1`, `PlatformBinding`'s platform property (and every collaborator built from it) is typed `?PlatformInterface`, so a missing platform can no longer reach a constructor as a hard type error. Upgrade to `1.7.1` or later, or verify `ai.yaml` has a `platform:` block and the corresponding `symfony/ai-*-platform` package is installed.

## Running the Audit

### `audit:run` not registered / unknown command

`SymfonySecurityAuditorBundle` is registered for `dev` and `test` only by default. Run from those environments:

```bash
APP_ENV=dev bin/console audit:run /path/to/project
```

To enable in `prod`, change `config/bundles.php`:

```php
VinceAmstoutz\SymfonySecurityAuditor\SymfonySecurityAuditorBundle::class => ['all' => true],
```

### `[ERROR] Project path "/x" is not a valid directory`

The `project-path` argument must point to a directory that exists. Use an absolute path, or omit the argument to default to the current working directory. A relative one is resolved against the folder you run the command from, so `audit src/Command` run from your home folder looks for `~/src/Command`. _Since 1.22_ the check runs right after the header, before anything is scanned, and fails with exit code `1`.

To audit part of a project, name the project and give the part with `--path`, relative to the project:

```bash
symfony-security-auditor audit /path/to/project --path src/Command
```

An absolute `--path` inside the project is accepted, and one outside it is refused. _Since 1.22_ `--path` replaces `scan.included_paths` for the run, so it reaches a folder the configured scope does not (`--path apps/api` on a monorepo); it still has to exist in the project and hold PHP, Twig, YAML or XML files. If a scan still lists nothing, the warning names the project and the `--path` values it applied: `No files matched under "/home/me" for --path src/Command.`

### `[ERROR] Project does not look like a Symfony app`

The auditor walks the project for `.php`, `.twig`, `.yaml`, `.yml`, `.xml` files inside `scan.included_paths` (default: `src/`, `config/`, `templates/`, `public/index.php`, and the root dotenv files — the Symfony Flex skeleton). If nothing is found, the path is wrong, the layout is non-standard, or `scan.respect_gitignore` is filtering everything out. A log line `No included paths exist in project` at `warning` level confirms the allow-list resolved to nothing.

### Audit exits with code `1` even though risk is LOW

Exit code `1` is also used for:

- Invalid `project-path` argument.
- The scan discovered no file to audit at all — a mistyped path, a `scan.included_paths` entry matching nothing, or an over-narrow `--path` — fails rather than reporting a hollow SAFE result: the command says `The scan found no file to audit, so the run has no verdict` and the reports state no risk level. A `--since` run that finds no _changed_ files still exits `0`.
- No file in scope could be analyzed — a scan or LLM call failed for each of them, or the run stopped before reaching them — and nothing was found, so the run has no verdict (_since 1.21_). The command says `Audit incomplete: none of the N file(s) in scope could be analyzed`; see [`Audit incomplete`](#audit-incomplete-n-files-could-not-be-fully-analyzed) for the cause.
- The normalized score fell below `--min-score`, if set.
- Unhandled exception during pipeline execution (check stderr).
- Validator errors on the input (e.g. `--format` set to a value it does not support — see [Configuration → Options](configuration.md#options)).

In a Symfony application, re-run with `-v` or `-vv` to see more of the application log (`warning` entries and above show by default). The standalone binary writes no log, so `-v` adds nothing there: it names why a chunk failed on its `✗ chunk N/M failed` progress line (see [`✗ chunk N/M failed`](#-chunk-nm-failed-on-the-progress-line)) and prints the error that stopped a run.

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

Configure `audit.rate_limit.requests_per_minute` / `input_tokens_per_minute` / `output_tokens_per_minute` to your provider tier's limits so the auditor throttles proactively instead of hitting a `429`. Otherwise, reduce concurrent load:

- Lower `audit.max_iterations` (default `3`) to `1`.
- Raise `reviewer_batch_size` from `1` to `5` (fewer reviewer calls).
- Use a split-model with a cheaper Reviewer (Haiku, DeepSeek, Mistral) — they have higher rate limits.
- Run nightly, not on every PR.

### `prompt is too long` / `context_length_exceeded` / HTTP `413`

The files of one chunk add up to more than the model's input window (the default `feature` chunking sends up to ten related files per call). The audit does not stop there: the chunk is split in two and each half is analyzed on its own, again until every part fits — a half already in the cache costs no call, and once every part is analyzed the whole chunk is cached too, so the next run does not refuse and split it again. Every split is logged at `warning` level:

```text
Attacker chunk exceeds the model input limit; it is split in two and each half analyzed on its own
```

A gateway in front of the model can refuse the request body before the model sees it — nginx's `client_max_body_size` (1 MB by default), an AI gateway's payload limit. It answers HTTP `413`, often with an HTML page the provider bridge cannot decode (`Syntax error`) or a JSON body it reads as an empty answer (`Response does not contain choices.` for Kong's `{"message":"Request size limit exceeded"}`); the auditor reads the status, splits the chunk the same way and books no spend for the refused request. Raising that limit above the largest prompt avoids the split.

A single file that does not fit on its own is recorded as errored and listed under `Audit incomplete: N file(s) could not be fully analyzed`:

```text
Attacker chunk exceeds the model input limit as a single file; it is recorded as errored and left out of the cache
```

To get it analyzed:

- Turn on `audit.code_slicing.enabled` (the `fast` profile already does): a large file is trimmed to its security-relevant lines before it is sent.
- Give the attacker a model with a larger context window (`attacker_model`).
- Leave generated or vendored trees out of `scan.included_paths`.

When a file refused on its own — measured as the prompt carried it, after code slicing — is under a tenth of that prompt, no split can help: the system prompt and the project mapping around it take up the rest of the model's input window — or of `audit.rate_limit.input_tokens_per_minute` — so the run stops at once instead of recording every file as errored:

```text
The audit prompt was refused even with only the 512-byte file "src/Kernel.php" in it (…): the system prompt and the project mapping around it take up the rest, so no file can fit. Use a model with a larger context window for the attacker, raise audit.rate_limit.input_tokens_per_minute when that limit refused it, or narrow scan.included_paths.
```

A request larger than `audit.rate_limit.input_tokens_per_minute` is handled the same way. A tool-using conversation that only outgrows the model after tool results were appended ends with what it recorded so far, and the chunk is recorded as errored:

```text
Tool-using conversation outgrew the model input limit after tool results were appended; it ends as an empty response and keeps the tool results already recorded
```

The reviewer handles a prompt it cannot fit the same way: a batch of findings (`reviewer_batch_size` above `1`) is split in two until every part fits, and a finding the model cannot review with its whole file in the prompt is recorded as errored while the review goes on with the next one:

```text
Reviewer batch exceeds the model input limit; it is split in two and each half reviewed on its own
```

### `OpenSSL SSL_read: … unexpected eof while reading` / `Transfer closed with … bytes remaining to read` / `cURL error 56`

The peer closed the connection while the response was still being read. `error:0A000126` is `SSL_R_UNEXPECTED_EOF_WHILE_READING` and `errno 0` means no OS-level error — the endpoint hung up without a TLS `close_notify`. This is a transport truncation, so it is classified as transient and the LLM call is retried on a fresh connection (`audit.retry.max_attempts`, default `3`).

Depending on the TLS library and the protocol, curl words the same cut differently, and every wording is retried the same way: `Transfer closed with 512 bytes remaining to read`, `Transfer closed with outstanding read data remaining`, `Failure when receiving data from the peer`, `OpenSSL SSL_read: SSL_ERROR_SYSCALL, errno 0` (OpenSSL 1.1, LibreSSL), `HTTP/2 stream 1 was not closed cleanly: INTERNAL_ERROR (err 2)` and `Error in the HTTP2 framing layer`.

Self-hosted endpoints and proxied APIs produce it most often, in two ways:

- **Stale keep-alive reuse.** Auditor calls are slow and far apart, so the idle gap exceeds the endpoint's or your reverse proxy's `keepalive_timeout`. The server drops the socket; the HTTP client takes the dead one from its pool for the next call. Raise `keepalive_timeout` above the longest gap between calls, and `proxy_read_timeout` / `proxy_send_timeout` above the longest generation time.
- **More concurrent connections than the endpoint serves.** The `fast` profile opens up to four attacker and four reviewer calls (`audit.attacker_max_concurrent` / `audit.reviewer_max_concurrent`). A local model server with a small worker pool drops the excess. Set both to `1`; `balanced` and `thorough` already default to `1`.

When every retry fails, the run still aborts with exit `1` and the report says it is incomplete (#378). That holds with any `audit.attacker_max_concurrent` or `audit.reviewer_max_concurrent`; in the concurrent path the `LLM call failed after N attempts` message counts the first, concurrent dispatch as an attempt too. Running again resumes from the cache (`cache.enabled`, on by default), so only the failed chunks are retried. Streaming, which should remove the problem at its source, is tracked in #379.

### `Idle timeout reached for "…"` / HTTP `499` in the gateway log

The request reached the provider, but nothing came back before the HTTP client's idle timeout, so the client hung up — which an AI gateway logs as `499` (client closed the request). A non-streamed answer arrives only once the model has finished it, so a slow local model, or a self-hosted gateway in front of one, can stay silent for minutes on a long prompt. The call is retried (`audit.retry.max_attempts`), and the same wait fails it again.

- **Standalone binary.** It waits 600 seconds by default. Raise `http_timeout` in `config.yaml`, in seconds:

  ```yaml
  # ~/.config/symfony-security-auditor/config.yaml
  http_timeout: 1800
  ```

  Before 1.21 the binary left the timeout to PHP's `default_socket_timeout`, 60 seconds, and nothing could change it.

- **Symfony bundle.** The platform uses your application's `http_client` service, whose idle timeout is PHP's `default_socket_timeout` unless you set one. Raise it for every request your application makes:

  ```yaml
  # config/packages/framework.yaml
  framework:
      http_client:
          default_options:
              timeout: 1800
  ```

  or only for the LLM platform, with a scoped client named in the platform's `http_client` option:

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

### `LLM response was empty` / `Failed to parse … JSON response`

The model returned blank or non-JSON output. The chunk is skipped automatically and logged at `error` level via `LoggerInterface`. The log entry includes a `content_preview` field with the first 512 bytes of the response — inspect it to see what the model actually emitted. Causes:

- Model context limit reached — see [`prompt is too long`](#prompt-is-too-long--context_length_exceeded--http-413) above; lower `audit.max_tool_iterations` when tool results are what overflow it.
- Model refused the prompt — try a different model (some smaller open-weight models refuse "hacking" prompts).
- Network timeout — retry; check the provider's status page.

The parser tolerates prose wrapped around a balanced JSON block (the model sometimes ignores the "Return ONLY the JSON array" instruction when tools are enabled); when the prose carries several, it takes the last one at the top level that decodes to an object or to a list holding one — the answer that follows the model's reasoning, never JSON it quoted along the way nor a bracket in the prose after it (`[1]` citing a source, `[ ]` in a checklist) — and a JSON array cut off before its closing bracket still gives its first complete object. A JSON object the model writes after its answer, such as a `{"total": 1}` summary, still replaces it: when a JSON-path run loses findings that way, switch back to the default structured collection (`audit.structured_collection: true`, `audit.reviewer_structured_collection: true`). A residual `JsonException: Syntax error` therefore means the response contains no recoverable JSON at all, not just chatty prose.

This error only arises with `audit.structured_collection: false`. In the default (`true`) mode, findings come in via `record_vulnerability` tool calls that the provider validates against the schema, so there is no JSON parsing on the agent side and no `JsonException` can be raised. Switching to the default is the simplest fix when the model repeatedly produces unparseable prose.

If it happens for **every** chunk, the model is unsuitable. Switch model.

### `Tool-using loop ended with empty content response` warnings

Logged at `warning` level when the empty response is the very first LLM call in the loop (no tool round happened yet); once at least one tool round has run, a later empty response logs the same message at `debug` instead — grep by message text rather than filtering on `warning` alone if the loop used tools first. Look at the `output_tokens` field: if it sits near a multiple of ~1000 (e.g. `1971`, `2000`), the model is being truncated by `symfony/ai`'s default `max_tokens = 1000` that ships with the Anthropic bridge. Set `max_output_tokens` in the bundle config (default `4096` since this fix) — or `attacker_max_output_tokens` / `reviewer_max_output_tokens` for per-agent tuning:

```yaml
symfony_security_auditor:
    max_output_tokens: 4096
    attacker_max_output_tokens: 8192 # optional, for chunks with many findings
    reviewer_max_output_tokens: 2048 # optional, reviewer needs less headroom
```

When raising the cap, raise `audit.rate_limit.output_tokens_per_minute` proportionally — otherwise the output-tokens bucket becomes the binding throttle.

When the provider reports why generation stopped (`symfony/ai` ≥ 0.11 exposes a normalized finish reason), the auditor logs an explicit `LLM response was truncated by the output token limit` warning — no output-token forensics needed. A `LLM response was suppressed by the provider content filter` warning likewise flags responses the provider filtered out.

Some provider bridges report the same two outcomes as an error rather than a finish reason: a typed `symfony/ai` exception, a plain one naming the provider's reason (`Unsupported finish reason "content_filter".`, `Responses API response is incomplete (content_filter) and contains no content.`, Cohere's `Unsupported finish reason "MAX_TOKENS".`), or — for a prompt Azure's content filter caught — an HTTP 400 whose `error.code` is `content_filter`. They are handled identically — the call is not retried, and the file or finding it covered is recorded as errored — and the request is booked against `audit.budget`, the report's token totals and the rate-limit window at the usage the provider reported in its answer, or at its estimated input tokens when the answer reports none, since the provider bills it. A tool call the output token limit cut off mid-way through its arguments, which the bridges report as malformed tool-call arguments, is one of these `length` answers and is not retried either; arguments the model finished but garbled are retried, and each attempt is booked the same way under `stop_reason: malformed_tool_call`. The entries that report it carry its `stop_reason` (`length` or `content-filter`): a `debug` entry for the booking, and the warning of the path that ran the call where it logs one:

```text
An answer the provider delivered as an error is booked at the usage it reported, since the provider bills the request it accepted
An answer the provider delivered as an error is booked at its estimated input tokens, since the provider bills the request it accepted
LLM returned a response with no content blocks
Tool-using loop ended with empty content response
Concurrent tool-using conversation ended without usable content; it is answered as a degraded response and keeps the tool results already recorded
```

### `Ollama: model not found`

Pull the model first:

```bash
ollama pull llama3.3
```

Then verify with `ollama list`. The model name in `symfony_security_auditor.yaml` must match exactly.

## Empty / Surprising Reports

### `✗ chunk N/M failed` on the progress line

The attacker's answer for that chunk could not be used, so its files are recorded as errored, left out of the cache and counted in `Audit incomplete: N file(s) could not be fully analyzed`. _Since 1.22_ the line names why; before, it only said `failed`, and the standalone binary — which writes no log — gave no other hint.

| Reason on the line | What happened | What to do |
| --- | --- | --- |
| `tool-call limit reached (audit.max_tool_iterations)` | The model kept calling `read_file`, `grep` or `list_files` and never ended its turn within `audit.max_tool_iterations` rounds. | Raise `audit.max_tool_iterations` (try `16`), or set `audit.tools_enabled: false` to scan each chunk in a single call. See the cost note below. |
| `output token limit reached (max_output_tokens)` | The answer, or a tool call inside it, was cut off by the output limit. | Raise `max_output_tokens` or `attacker_max_output_tokens` (Claude models only). |
| `answer withheld by the provider content filter` | The provider's filter blocked the answer. | Try another model or deployment; see [`Tool-using loop ended with empty content response`](#tool-using-loop-ended-with-empty-content-response-warnings). |
| `the model returned no content` | The call ended with nothing usable. | Retry; if it repeats for every chunk, switch model. |
| `the answer was not valid JSON` | Only with `audit.structured_collection: false`. | See [`LLM response was empty`](#llm-response-was-empty--failed-to-parse--json-response). |
| `the file is too large for the model input limit` | A single file does not fit the model's input window. | See [`prompt is too long`](#prompt-is-too-long--context_length_exceeded--http-413). |
| an error message | An unexpected failure on that chunk's call; the run went on with the next one. | Read it; in a Symfony application the same text is in the log. |

**Raising `audit.max_tool_iterations` costs more.** A chunk that explores until the cap uses up to twice the rounds at `16`, and each round re-reads the prompt, so call time and cost grow with it; a chunk the model never stops exploring can still hit the new cap. The value is also part of the attacker cache key, so changing it re-analyzes every chunk once: a run after the change bills the whole project again, not only the chunks that failed.

### `Audit incomplete: N file(s) could not be fully analyzed`

Some file was never fully analyzed: its LLM call failed even after the retries in `audit.retry.*`, an abort (a provider error, a budget cap) stopped the run before reaching it, the model's answer held an entry that could not be read as a finding (the `Attacker answer held entries that could not be read as findings` warning names the files and the drop reasons; the findings that did read are kept), or secret scrubbing could not scan it and withheld its content (`secret_scrubbing` in the `coverage` array). Every report format says so instead of printing "No validated vulnerabilities found", because a file nobody analyzed can still hold a vulnerability. The JSON report sets `complete: false`, SARIF sets `invocations[0].executionSuccessful: false`, and the `coverage` array in the JSON report lists each file with its `errored` or `aborted` status.

The `coverage` array names, for each file, the stage that failed. For an LLM failure, read the `LLM call failed` warnings in the log for the cause, fix it (see [LLM & Provider Errors](#llm--provider-errors)), and run again. A withheld file is one a `scan.secret_scrubbing.additional_patterns` entry could not evaluate (a catastrophic-backtracking regex, a `/u` pattern meeting invalid UTF-8), or, with the PCRE JIT disabled, a single quoted value of several hundred kilobytes: fix the pattern, or read the file yourself. With `cache.enabled`, the files that were analyzed are served from the cache. A `reviewer` entry with the `errored` status can also mean the reviewer returned no verdict for a finding in the file — an empty answer, a batch answer that left the finding out, or a verdict with no `accepted` flag (the `Reviewer reached no verdict for the finding; it is recorded as errored and left out of the cache` warning names it): the finding is not reported to the attacker as rejected and nothing is cached, so the next run reviews it again.

When **no** file could be analyzed and nothing was found, the run has no verdict: it exits `1` whatever the gates say, and the reports read `RISK LEVEL: UNKNOWN  (no file was analyzed)` on the console — `UNKNOWN (no file was analyzed)` in Markdown and HTML — instead of a SAFE result. When only some files failed, or the run still holds a finding, the risk level and grade cover only the files analyzed, and the reports say so.

### Report has zero vulnerabilities but I know there are some

Diagnostic order:

1. **Lower `audit.min_confidence`** from `0.6` to `0.3` — borderline findings now pass to the Reviewer.
2. **Inspect attacker output before review** — temporarily decorate `ReviewerAgent` to log all incoming candidates, including non-validated ones.
3. **Raise `audit.max_iterations`** to `5` — the loop stops early when no new findings emerge; a stronger pass can surface more.
4. **Switch to a stronger model** — Claude Opus and GPT-5.6 consistently outperform small models.
5. **Check the file actually got scanned** — run with `--show-scanned` to list the files in scope (the progress line `Auditing N file(s)` gives the count, and `chunk i/M` the chunks); in a Symfony application, `-vv` also logs the ingested file and chunk counts.
6. **`scan.respect_gitignore: true`** silently skips files in `.gitignore`. Set to `false` to include them.
7. **`scan.max_file_size_kb`** drops large files. Default `512` KB; raise if your project has bigger files.

### Report has too many false positives

- Raise `audit.min_confidence` from `0.6` to `0.8`.
- Switch Reviewer to a **stronger** model (counterintuitive — Reviewer needs accuracy, not speed).
- Inspect the LLM's `reviewer_notes` (logged at `debug` level in the `Vulnerability reviewed` entry) — the Reviewer often explains why it accepted weak findings.

### Same code, different findings on each run

LLM output is **nondeterministic** by design. Set `temperature: 0.0` (or `0.1`) on the model:

```yaml
symfony_security_auditor:
    model: 'claude-haiku-4-5-20251001?temperature=0.0'
```

With `temperature: 0.0` + `cache.enabled: true`, repeated runs on identical code become deterministic.

The current Claude generation (Opus 4.7/4.8, Opus 5, Sonnet 5, Fable 5) no longer accepts `temperature` and rejects a request that sets it — on those models rely on `cache.enabled: true` alone for run-to-run stability.

## Performance & Cost

### Audit takes 10+ minutes

Expected behavior on large projects. Mitigations:

- Use **split-model** — Opus Attacker + Haiku Reviewer cuts ~50% wall time.
- Raise `reviewer_batch_size` from `1` to `5` — fewer Reviewer round-trips.
- Lower `audit.max_iterations` from `3` to `1` or `2`.
- Tighten `scan.included_paths` to specific sub-directories — e.g. point it at `src/Controller`, `src/Form`, `src/Voter`, `config`, `templates` so high-value surfaces are audited and infrastructure code is dropped.
- Enable both caches: `cache.enabled: true` (default) and Anthropic prompt caching via `cache_retention` in `ai.yaml` (default `short` already on).

### What happens on a very large project (10 000+ files)?

Nothing special happens — and that is the problem. The pipeline is linear in the number of files it keeps, so a 10 000-file repository is not "slow", it is proportionally expensive: the scanner walks the tree once, drops everything outside `scan.included_paths` and every file over `scan.max_file_size_kb` (default `512`), groups what remains into chunks, and spends at least one LLM call per chunk per iteration. Triple that for the default `audit.max_iterations: 3`, then add one reviewer call per surviving finding.

Measure before you spend: `audit:run --dry-run` reports the retained file count and the estimated token/cost total for **your** repository and model without making a single audit call. Treat that number as the decision input; wall-clock and dollar figures quoted for other projects will not transfer.

To bring a repository of that size into a sane envelope, in the order that helps most:

- **Audit a slice, not the monolith.** `--path src/Controller --path src/Form` (repeatable) or a tightened `scan.included_paths` targets the code that actually faces user input. On a monorepo, run one audit per bounded context.
- **Audit only what changed.** `--since main` (or any git ref) restricts the run to files touched since that ref, which is what you want on a PR — cost then tracks the diff, not the repository.
- **Use `profile: fast`.** One iteration, lean pre-scan (marker-free files are dropped), code slicing (large files are trimmed to security-relevant lines) and 4× attacker/reviewer concurrency.
- **Cap the run.** `audit.budget.max_tokens` / `audit.budget.max_cost_usd` abort mid-run and still emit the partial report with exit code `2`, so a misestimated scan cannot run away with your budget.
- **Keep the cache on.** `cache.enabled: true` (default) means the second and later runs pay only for chunks whose content changed.

### Cost blew past my budget

- Confirm `scan.included_paths` matches the deployable code surface. The default (the Flex skeleton plus root dotenv files) already skips every file outside the Symfony skeleton — `vendor/`, `node_modules/`, `var/`, `tests/`, `migrations/`, `translations/`, `bin/`, root scripts, IDE folders, build artefacts — without you having to enumerate them.
- Trim further by tightening `scan.included_paths`: drop `templates/` or `config/` if you only want to audit PHP, or replace `src` with a list of specific sub-directories (e.g. `src/Controller`, `src/Form`, `src/Voter`) to focus the audit on high-value security surfaces.
- Confirm Anthropic prompt caching is on — `cache_retention` in `ai.yaml` (default `short`) gives a ~90% input-token discount on cached prompts.
- Confirm `cache.enabled: true` (default) — repeated chunks skip the LLM entirely.
- Lower `audit.max_tool_iterations` from `8` to `4` or `5` — caps chatty tool-use loops on each chunk at the cost of less cross-file investigation.
- Switch to a cheaper Reviewer (`reviewer_model: claude-haiku-4-5-20251001` or `deepseek-chat`).
- Set a provider-side hard cap. See [CI → Set a spend cap](ci.md#set-a-spend-cap).
- Run weekly instead of nightly for large monorepos.

### `--dry-run` estimate shows `$0.00`

The cost estimate multiplies token counts by per-model prices from the configured `PricingProviderInterface` (the bundled `ModelsDevPricingProvider` reads prices from the `symfony/models-dev` catalog shipped in `vendor/`, the listing of the platform the audit runs against first). When a configured model (`model`, `attacker_model`, or `reviewer_model`) is absent from that catalog — a typo, or a model `symfony/ai` supports but the catalog does not list — its price resolves to `0.0` and the dry run now prints a stderr warning:

```text
No published pricing for the configured model(s): <model>. The dry-run cost
estimate shows $0.00 for these. If you are running a local or self-hosted model
(e.g. Ollama, LM Studio), $0.00 is correct — you can ignore this notice.
Otherwise the name is likely a typo or an unlisted model: check it in your
symfony_security_auditor configuration against the models supported by your
symfony/ai platform.
```

Fix the model identifier if it is a typo. If the name is correct but missing from the catalog, the token counts in the report are still accurate — only the USD figure is unavailable. Run `composer update symfony/models-dev` to pull a fresher catalog, or alias your own `PricingProviderInterface` implementation to supply prices (see [Extending](extending.md)).

**Standalone binary:** `composer update` does not apply — there is no user-facing `vendor/` or `composer.json`; the binary carries the `symfony/models-dev` catalog its release was built with. Run `self-update` to refresh it: even when the binary is already the latest release, it downloads the current catalog into the cache directory, and later runs price from that copy (`doctor`'s `Pricing catalog` check names it). A copy the run cannot use — unreadable, not JSON, or pricing no model — is ignored in favor of the catalog the binary was built with. `self-update --check` and a configuration with `privacy.offline_only: true` leave the catalog as it is.

## Cache Issues

### Cache seems stale — old findings persist after fixing code

The cache is keyed by **chunk content hash**. If your fix changes the file's bytes, the cache key changes and the LLM is re-invoked. If you see stale findings, the file content didn't actually change — diff to confirm.

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

### Every run misses the cache and logs `cache entry path was a symlink`

A symlink below `cache.dir` — a sub-directory or an entry file — is refused, on a read (`Attacker cache entry path was a symlink, ignoring`) as on a write (`Failed to write attacker cache entry`), so a link planted there cannot feed a forged entry to the audit or redirect a write. `cache.dir` itself and the directories above it are taken as you configured them: a symlinked `var/`, `~/.cache` or `$XDG_CACHE_HOME` is fine. Remove the link below the cache directory, or point `cache.dir` at the directory it targets.

### Disable cache for one-off debugging

```yaml
symfony_security_auditor:
    cache:
        enabled: false
```

`AttackerCacheInterface` is aliased to `NullAttackerCache` (and `ReviewerCacheInterface` to `NullReviewerCache`) — every chunk, and every reviewer verdict, hits the LLM.

## Advisory (`composer audit`) Issues

### `lookup_advisory` always returns empty results

Causes (each logs a `warning` via `LoggerInterface`, except the deliberate `offline_only` case below):

- **`composer` not in `PATH`** — install Composer 2.4+ on the audit host.
- **`composer.lock` missing** — run `composer install` first; advisory data comes from the lockfile.
- **Malformed JSON output** — corrupted `composer.lock`. Regenerate it.
- **Process error** — network failure to Packagist. Retry: a lookup after a failed `composer audit` runs it again, and so does one after `composer.lock` changes.
- **`privacy.offline_only: true`** — the advisory feed is intentionally replaced by an empty in-memory database, so `composer audit` never runs; no warning is logged since this is configured behavior, not a failure.

When `lookup_advisory` returns empty, the audit continues without CVE data — no audit failure.

### `composer audit` is slow

Within a run it executes **once** and the result is cached for the lifetime of the request. Across runs, with `cache.enabled: true` (default), `LockfileHashedAdvisoryCache` also persists the JSON payload to disk for 24h, keyed by a SHA-256 hash of `composer.lock` — an unchanged lockfile skips `composer audit` entirely on the next run. A `composer.lock` that is a symlink or larger than 8 MiB is never read for that hash, so its run is not cached, and an output that is not a JSON document with an `advisories` map is never stored. If it's still the bottleneck, you can pre-warm it before the audit or override `AdvisoryDatabaseInterface` with `InMemoryAdvisoryDatabase` containing a baked snapshot.

### Override the advisory source

Implement `Audit/Domain/Port/AdvisoryDatabaseInterface`:

```yaml
# config/services.yaml
services:
    VinceAmstoutz\SymfonySecurityAuditor\Audit\Domain\Port\AdvisoryDatabaseInterface:
        alias: App\Security\MyCustomAdvisoryDatabase
```

See [Configuration → Advisory Source](configuration.md#advisory-source-lookup_advisory-tool).

## Tools (`read_file`, `grep`, `list_files`, `lookup_advisory`)

### Attacker never calls tools

Verify `audit.tools_enabled: true` (the default). With tools disabled, the Attacker uses `LLMClientInterface::complete()` (single-shot) instead of `completeWithTools()`.

Some models do not support tool/function calling — verify your provider's docs. Most major providers (Anthropic, OpenAI, Gemini, Mistral) do; some smaller Ollama models don't.

### Attacker loops indefinitely on tool calls

Lower `audit.max_tool_iterations` from the default `8` to bound the spend. The last round is announced to the model, which is told to record what it holds and stop (_since 1.22_), and a chunk whose last round does is analyzed and cached like any other. A model that asks to read one more file instead ends the conversation: the findings the Attacker already recorded are kept, but the chunk is recorded as errored and not cached, so the run reports `Audit incomplete` and the next run pays for it again. Raise the cap when chunks keep failing that way: it gives the model more rounds to read, at the price of more rounds (each re-reads the prompt) and of a one-time re-analysis, since the value is part of the attacker cache key.

### `lookup_advisory` always returns `[]`

See [Advisory (`composer audit`) Issues](#advisory-composer-audit-issues) above.

### `read_file` / `grep` returns nothing for files I know exist

Both tools only search the files `ProjectFileScanner` already loaded into memory during ingestion — neither touches the filesystem live. Causes:

- The file falls outside `scan.included_paths`, is excluded by `scan.respect_gitignore`, or exceeds `scan.max_file_size_kb`.
- The file, or one of its `scan.included_paths` ancestors, is a symlink. `ProjectFileScanner` skips symlinks unconditionally regardless of where they point (logged as `Skipped symlinked file` / `Skipped symlinked included path`) — a symlink pointing back inside the project is skipped too, not just one pointing outside it.
- `read_file`'s `relative_path` argument must match `ProjectFile::relativePath()` exactly (e.g. `src/Controller/UserController.php`). It has no absolute-path fallback — an absolute path never matches and returns `Error: file "..." is not part of the audited project.`

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

Path can be anything — GitLab parses the file. See [CI → GitLab CI](ci.md#gitlab-ci).

### Audit succeeds locally but fails in CI

Common causes:

- API key secret not exposed to the job (check the workflow `env` block).
- CI runner lacks Composer 2.4+ → `lookup_advisory` reports empty.
- `composer.lock` not committed → `lookup_advisory` reports empty.
- Different model name between local config and CI config.

## Dev / Quality Gate Failures

### PHPStan max fails on a finding I think is wrong

Do **not** silence it. PHPStan suppressions (`@phpstan-ignore-*`, baseline) are forbidden — see [CLAUDE.md → Never Silence Quality Gates](../CLAUDE.md#5-never-silence-quality-gates). Fix the underlying type issue. Genuine PHPStan false positives require a tracking issue and a justification in the PR description.

### Infection MSI is below 100%

A mutation survived your tests. Read the Infection log (`infection/infection.log`) to see which mutator and which line. Add a test that distinguishes the mutated behavior. Suppression annotations are forbidden.

### PHP CS Fixer / Rector wants to change code I deliberately wrote that way

Run `bin/castor lint:fix` to apply the changes. Both tools enforce the project style — diverging styles get rejected in CI. If you genuinely need a deviation, document the reason in the PR.

### Tests pass locally, fail in CI

- Different PHP version — CI matrix runs 8.3, 8.4, 8.5; pin locally with Docker.
- Filesystem case sensitivity — Linux CI is case-sensitive; macOS is not.
- Random test order — Infection rewrites `phpunit.dist.xml` to force `executionOrder="defects,random"` for its own runs; reproduce locally with `--order-by=defects,random --random-order-seed=<seed>`.
