# Versioning & Backward Compatibility

`symfony-security-auditor` follows
[Semantic Versioning 2.0.0](https://semver.org) from `1.0.0` onward.

For its PHP API surface it additionally adheres to the
[Symfony Backward Compatibility promise](https://symfony.com/doc/current/contributing/code/bc.html):
code tagged `@internal` is exempt, and any breaking change to covered API goes
through the [deprecation cycle](#deprecation-policy) below — a deprecated
element keeps working until at least the next `MAJOR`.

> See also: [Configuration](configuration.md) · [Extending](extending.md) ·
> [Architecture](architecture.md) · [CHANGELOG](../CHANGELOG.md)

## Semantic Versioning

| Version bump | Meaning                                                                                  |
| ------------ | ---------------------------------------------------------------------------------------- |
| `MAJOR`      | Removes or changes the contract of any public API element (see "Public API" below).      |
| `MINOR`      | Adds public API in a backward-compatible way (new config keys, new ports, new commands). |
| `PATCH`      | Bug fixes and internal changes only — no public API additions or removals.               |

Every `MAJOR` release ships a migration note in
[`CHANGELOG.md`](../CHANGELOG.md) explaining what changed and how to adapt.

## Public API — what is covered by the BC promise

Everything below is part of the public API and **will not break in a `MINOR` or
`PATCH` release**.

### Bundle configuration

Every key under `symfony_security_auditor:` documented in
[`docs/configuration.md`](configuration.md):

- `model`, `attacker_model`, `reviewer_model`, `max_output_tokens`,
  `attacker_max_output_tokens`, `reviewer_max_output_tokens`,
  `provider_json_mode`
- `scan.included_paths`, `scan.respect_gitignore`, `scan.max_file_size_kb`,
  `scan.secret_scrubbing.enabled`, `scan.secret_scrubbing.additional_patterns`,
  `scan.custom_risk_patterns`
- `profile`
- `audit.max_iterations`, `audit.min_confidence`, `audit.reviewer_batch_size`,
  `audit.tools_enabled`, `audit.structured_collection`,
  `audit.reviewer_structured_collection`, `audit.stable_system_prompt`,
  `audit.max_tool_iterations`, `audit.reviewer_tools_enabled`,
  `audit.reviewer_max_tool_iterations`, `audit.reviewer_max_concurrent`,
  `audit.attacker_max_concurrent`, `audit.static_prescan.enabled`,
  `audit.static_prescan.lean_mode`, `audit.chunking.strategy`,
  `audit.code_slicing.enabled`, `audit.code_slicing.min_lines_before_slicing`,
  `audit.poc_synthesis.enabled`, `audit.poc_synthesis.severity_floor`,
  `audit.escalation.enabled`, `audit.escalation.cheap_model`, `audit.baseline`,
  `audit.fail_on`, `audit.excluded_types`, `audit.included_types`,
  `audit.retry.max_attempts`, `audit.retry.initial_delay_ms`,
  `audit.retry.backoff_multiplier`, `audit.retry.jitter_ratio`,
  `audit.budget.max_tokens`, `audit.budget.max_cost_usd`,
  `audit.rate_limit.requests_per_minute`,
  `audit.rate_limit.input_tokens_per_minute`,
  `audit.rate_limit.output_tokens_per_minute`
- `cache.enabled`, `cache.dir`, `cache.prompt_caching` (the last is **deprecated
  since 1.7** — see [Deprecation policy](#deprecation-policy) — still accepted
  but ignored)

Default values for these keys are also part of the contract. Changing a default
is a `MAJOR` change.

> **Planned default change.** `audit.fail_on` ships with the default `critical`
> (only a `CRITICAL` aggregate risk level fails the build), which preserves the
> historical exit-code behaviour. The default is **planned to become `high`** in
> the next `MAJOR` release so a HIGH-risk audit fails CI by default. Pin
> `audit.fail_on: critical` (or `high`) explicitly now to make your intent
> immune to that change.

### CLI surface

- The command name `audit:run` and its `audit` alias (both the bundle and the
  standalone CLI accept either).
- The `project-path` argument.
- The `--format` (`-f`) and `--output` (`-o`) options, including the values
  accepted by `--format` (`console`, `json`, `sarif`, `html`, `markdown`,
  `junit`, `github`).
- The `--baseline` and `--generate-baseline` options (baseline suppression of
  accepted findings).
- The `--fail-on` option (CI gate threshold; overrides `audit.fail_on`),
  including its accepted values (`safe`, `low`, `medium`, `high`, `critical`).
- Exit codes (see [CLI Reference → Exit codes](configuration.md#exit-codes)):
  - `0` — audit completed; aggregate risk level is below the `fail_on` threshold
    (default `critical`, so `SAFE`/`LOW`/`MEDIUM`/`HIGH` by default).
  - `1` — aggregate risk level is at or above the `fail_on` threshold (default
    `critical`), or the audit itself failed.
  - `2` — the audit budget could not be honored: either it aborted mid-run
    because the configured token or cost budget was exceeded (partial report
    still emitted), or it never started because an unpriced model makes
    `audit.budget.max_cost_usd` unenforceable and either the user declined the
    interactive confirmation or the run is non-interactive (no report emitted
    in that case).
- The command name `audit:diff` (see
  [CLI Reference → `audit:diff`](configuration.md#auditdiff--comparing-two-reports)),
  its `previous-report` and `current-report` arguments, its `--format` option
  (`console` or `json`), and its exit codes (`0` on a successful comparison, `1`
  when a report file is missing or is not valid JSON).

### Standalone executable & XDG configuration

The standalone tool is a supported install method alongside the bundle, and the
following surface is BC-protected:

- The published per-platform binary assets and their release-asset names
  (`symfony-security-auditor-{linux-x86_64,linux-aarch64,darwin-x86_64,darwin-arm64}`
  and `symfony-security-auditor-windows-x86_64.exe`), each accompanied by a
  `.sha256` checksum, plus the `install.sh` (Linux/macOS) and `install.ps1`
  (Windows) installer contracts and their `SSA_VERSION` / `SSA_INSTALL_DIR`
  environment variables.
- The `init` command name. The standalone exposes the **identical** `audit:run`
  command (and its `audit` alias), arguments, options, and exit-code surface
  listed above.
- The configuration path contract. On Linux/macOS the XDG Base Directory spec:
  the config file `$XDG_CONFIG_HOME/symfony-security-auditor/config.yaml`
  (falling back to `~/.config/…`), the cache directory
  `$XDG_CACHE_HOME/symfony-security-auditor` (→ `~/.cache/…`), and the bridge
  data directory `$XDG_DATA_HOME/symfony-security-auditor` (→
  `~/.local/share/…`). On Windows the native app-data directories: `%APPDATA%`
  for config and `%LOCALAPPDATA%` for cache and bridges (XDG variables still win
  when set).
- The standalone `config.yaml` shape: the bundle configuration keys **without**
  the `symfony_security_auditor:` root wrapper, plus the standalone-only
  top-level `platform:` block (passed verbatim to `symfony/ai-bundle`) and the
  optional `provider:` selector. Removing or renaming these keys is a `MAJOR`.

The bundle remains a fully supported install method; neither method is
deprecated by the other.

### GitHub Action

- The composite action defined by `action.yml` at the repository root and its
  input names: `project-path`, `format`, `output`, `baseline`,
  `generate-baseline`, `since`, `extra-args`, `php-version`, `setup-php`,
  `install-dependencies`, `working-directory`. New inputs may be added in a
  `MINOR`; renaming or removing one is a `MAJOR`. The Marketplace `name`
  (`Symfony Security Auditor`) is also stable.
- **Version pinning.** Consumers pin the action to an exact release tag —
  `uses: vinceamstoutz/symfony-security-auditor@1.12.0` — matching the tag
  format used on Packagist. Bump the pin when upgrading. There is intentionally
  no floating `v1` tag: the `uses:` ref and the config-schema URL both point at
  the same release tag, so a given pin always resolves to one immutable release.
  At release time, `bin/castor release:bump X.Y.Z` rewrites every pinned
  location in one shot, and the `Release Guard` workflow fails the tag push if
  any pin does not match the tag.

### Output schemas

- The **JSON report schema** produced by `--format=json`. Keys present today
  remain present; new keys may be added in `MINOR` releases. The `cwe` key on
  each finding (added alongside the pre-existing `owasp` key) is one such
  additive `MINOR` change — no existing key was removed or renamed. Each entry
  in `vulnerabilities[]` also carries a `fingerprint` key (since 1.13) — the
  same stable per-finding identity `Vulnerability::fingerprint()` already used
  by baseline suppression — consumed by `audit:diff` to compare two reports.
- The **SARIF 2.1.0 output** produced by `--format=sarif`. The
  `runs[].tool.driver.name`, `informationUri`, and `version` fields are stable.
  The `version` is sourced dynamically from installed Composer metadata, so it
  tracks the package version automatically. Each rule's `properties.tags` array
  additionally carries a `external/cwe/cwe-<n>` tag.

### Domain ports (extension points)

All interfaces under `src/Audit/Domain/Port/` plus the documented Domain
pipeline interfaces. Implementing one of these in your own application and
overriding the alias in `config/services.yaml` is a supported integration path:

- `LLMClientInterface`
- `BatchCapableLLMClientInterface` — opt-in extension of `LLMClientInterface`
  for clients that resolve several prompts concurrently. Consumers check
  `instanceof` and fall back to looping `complete()`, so it never breaks an
  existing client.
- `AttackerPromptBuilderInterface`, `ReviewerPromptBuilderInterface`
- `ProjectFileScannerInterface`
- `AttackerCacheInterface`
- `ReviewerCacheInterface` — host applications may implement this and alias it
  to back the reviewer-verdict cache with their own store (Redis, a shared
  filesystem, …).
- `StaticPreScannerInterface` — host applications may implement this and alias
  it to supply their own deterministic risk-marker scan.
- `CodeSlicerInterface` — implement and alias to control how files are trimmed
  before reaching the LLM.
- `GitChangedFilesResolverInterface` — implement and alias to change how
  `--since` resolves the changed-file set.
- `AdvisoryDatabaseInterface` — host applications may implement this and alias
  it to swap the CVE feed (Snyk, internal database, …). See
  [`docs/extending.md`](extending.md).
- `SecretScrubberInterface`
- `PricingProviderInterface`
- `CacheAwarePricingProviderInterface` — opt-in extension of
  `PricingProviderInterface` for providers that expose real per-model
  prompt-cache rates. `CostCalculator` checks `instanceof` and falls back to the
  base input rate, so it never breaks an existing pricing provider.
- `TokenEstimatorInterface`
- `RateLimiterInterface` — host applications may implement this and alias it to
  swap the throttling strategy (e.g. cross-process Redis-backed bucket). See
  [`docs/extending.md`](extending.md).
- Configuration value objects in `Audit\Domain\Configuration\*`
  (BundleConfiguration and per-layer VOs)
- Domain models: `AuditBudget`, `AuditCost`, `TokenUsageSnapshot`
- Domain exceptions: `LLMProviderException` (signals non-transient platform
  failure; callers may catch this to detect misconfigured or retired models)
- `Tool\ToolInterface`, `Tool\ToolRegistryFactoryInterface`
- `Pipeline\PipelineInterface`, `Pipeline\StageInterface`,
  `Pipeline\CoverageRecorderInterface`

### Domain models and exceptions

- Value objects and enums under `src/Audit/Domain/Model/` — `Vulnerability`,
  `AuditReport`, `AuditContext`, `VulnerabilitySeverity`, `VulnerabilityType`,
  etc. Their public accessors are stable.
- Domain exception classes — callers may rely on the exception types thrown by
  public methods.

### Programmatic entry point

`Audit\Application\UseCase\RunAuditUseCase` — the documented programmatic entry
point for driving an audit from PHP. Its single public method `execute()` is
BC-protected.

### Bundle class

`VinceAmstoutz\SymfonySecurityAuditor\SymfonySecurityAuditorBundle` — referenced
from `config/bundles.php`. Its existence and FQCN are stable.

## Internal — what is NOT covered

Anything tagged `@internal` may be refactored, renamed, or removed in any
`MINOR` release. This includes:

- All concrete classes under `Audit/Application/Agent/` and
  `Audit/Application/Pipeline/` (`AttackerAgent`, `ReviewerAgent`,
  `EscalatingAttackerAgent`, `AuditOrchestrator`, `VulnerabilityFactory`,
  `PoCSynthesizer`, `AuditPipeline`, `IngestionStage`, `MappingStage`,
  `AuditStage`, `PoCSynthesisStage`).
- All concrete adapters under `Audit/Infrastructure/` — `SymfonyAiLLMClient`,
  `ProjectFileScanner`, `AttackerPromptBuilder`, `ReviewerPromptBuilder`,
  `FilesystemAttackerCache`, `NullAttackerCache`,
  `ComposerAuditAdvisoryDatabase`, `InMemoryAdvisoryDatabase`,
  `SymfonyProcessComposerAuditRunner`, `ReadFileTool`, `GrepTool`,
  `ListFilesTool`, `LookupAdvisoryTool`, `SymfonyToolRegistryFactory`,
  `ReportRenderer`.
- Command-internal collaborators — `AuditCommandInput`, `AuditPresenter`,
  `ReportWriter`, `AuditExitCodeResolver`.
- Prompt template files under `src/Audit/Infrastructure/Prompt/` and
  `src/Audit/Infrastructure/Report/Template/`.
- Private constants and methods on any class.

If you find yourself depending on an internal class, please open an issue — we
will either promote it to public API or provide a stable replacement.

## Deprecation policy

When a public-API element needs to be removed:

1. It is marked as deprecated in a `MINOR` release. The deprecation appears in
   [`CHANGELOG.md`](../CHANGELOG.md) under `### Deprecated`, with a clear
   migration path.
2. The deprecated element keeps working for at least the rest of the current
   `MAJOR` cycle.
3. Removal happens in the next `MAJOR` release at the earliest, listed under
   `### Removed` in the changelog.

Every deprecated public-API element emits a **runtime deprecation** for the rest
of the current `MAJOR` cycle, so callers find it in their deprecation log and CI
(`failOnDeprecation`) before the removal lands — not as a hard fatal on the day
they upgrade. Config keys use the Config component's `setDeprecated()`; PHP
methods, classes, and arguments use
`trigger_deprecation('vinceamstoutz/symfony-security-auditor', '<since>', '<message>')`
(from `symfony/deprecation-contracts`). The `@deprecated` PHPDoc tag is added
alongside it for static analysis and IDE hints. The only deprecations documented
in the changelog _without_ a runtime trigger are those with no runtime call site
to attach one to.

### Currently deprecated

- **`cache.prompt_caching`** (since 1.7) — once set `cache_control: ephemeral`
  on every LLM call, but current `symfony/ai` bridges no longer read that
  option: Anthropic caching is driven by `cache_retention` on the platform in
  `ai.yaml` (default `short`), and OpenAI/Gemini cache automatically. The key is
  still accepted and emits a Symfony deprecation when set; it has no effect.
  Remove it from your config and, if you want a longer Anthropic cache window,
  set `cache_retention: long` on the `anthropic` platform in `ai.yaml`.
  Scheduled for removal in the next `MAJOR`.
- **`Vulnerability::create()`, `SymfonyMapping::create()`, and
  `LLMResponse::create()`** (since 1.13) — superseded by the value-object
  factories `Vulnerability::of()`, `SymfonyMapping::of()`, and
  `LLMResponse::of()` (taking
  `VulnerabilityClassification`/`CodeLocation`/`VulnerabilityNarrative`,
  `ProjectFileInventory`/`AccessControlMap`, and `TokenUsageSnapshot`
  respectively). The old methods still work and delegate to the new factories,
  and emit a runtime deprecation when called. Scheduled for removal in the next
  `MAJOR`.

## LLM model identifiers

Model identifiers passed to `model:`, `attacker_model:`, or `reviewer_model:`
are free-form strings forwarded to `symfony/ai`. Their meaning, behavior,
pricing, and availability are owned by the LLM provider, not by this bundle. If
a provider deprecates a model, this bundle does not consider that a BC break —
pin the identifier you want in your configuration.

## Reporting BC breaks

If you find a change between two `1.x` releases that breaks one of the public
API elements listed above, please
[open an issue](https://github.com/vinceamstoutz/symfony-security-auditor/issues/new)
with a minimal reproduction. It is a bug and will be fixed in a patch release.
