# Versioning & Backward Compatibility

`symfony-security-auditor` follows
[Semantic Versioning 2.0.0](https://semver.org) from `1.0.0` onward.

> See also: [Configuration](configuration.md) · [Extending](extending.md) ·
> [Architecture](architecture.md) · [CHANGELOG](../CHANGELOG.md)

---

## Semantic Versioning

| Version bump | Meaning                                                                                  |
| ------------ | ---------------------------------------------------------------------------------------- |
| `MAJOR`      | Removes or changes the contract of any public API element (see "Public API" below).      |
| `MINOR`      | Adds public API in a backward-compatible way (new config keys, new ports, new commands). |
| `PATCH`      | Bug fixes and internal changes only — no public API additions or removals.               |

Every `MAJOR` release ships a migration note in
[`CHANGELOG.md`](../CHANGELOG.md) explaining what changed and how to adapt.

---

## Public API — what is covered by the BC promise

Everything below is part of the public API and **will not break in a `MINOR` or
`PATCH` release**.

### Bundle configuration

Every key under `symfony_security_auditor:` documented in
[`docs/configuration.md`](configuration.md):

- `model`, `attacker_model`, `reviewer_model`
- `scan.excluded_dirs`, `scan.respect_gitignore`, `scan.max_file_size_kb`,
  `scan.secret_scrubbing.enabled`, `scan.secret_scrubbing.additional_patterns`
- `audit.max_iterations`, `audit.min_confidence`, `audit.reviewer_batch_size`,
  `audit.tools_enabled`, `audit.max_tool_iterations`
- `cache.enabled`, `cache.dir`, `cache.prompt_caching`

Default values for these keys are also part of the contract. Changing a default
is a `MAJOR` change.

### CLI surface

- The command name `audit:run`.
- The `project-path` argument.
- The `--format` (`-f`) and `--output` (`-o`) options, including the values
  accepted by `--format` (`console`, `json`, `sarif`).
- Exit codes (see [CLI Reference → Exit codes](configuration.md#exit-codes)):
  - `0` — audit completed; risk level is `SAFE`, `LOW`, `MEDIUM`, or `HIGH`.
  - `1` — risk level is `CRITICAL`, or the audit itself failed.

### Output schemas

- The **JSON report schema** produced by `--format=json`. Keys present today
  remain present; new keys may be added in `MINOR` releases.
- The **SARIF 2.1.0 output** produced by `--format=sarif`. The
  `runs[].tool.driver.name`, `informationUri`, and `version` fields are stable.
  The `version` is sourced dynamically from installed Composer metadata, so it
  tracks the package version automatically.

### Domain ports (extension points)

All interfaces under `src/Audit/Domain/Port/` plus the documented Domain
pipeline interfaces. Implementing one of these in your own application and
overriding the alias in `config/services.yaml` is a supported integration path:

- `LLMClientInterface`
- `AttackerPromptBuilderInterface`, `ReviewerPromptBuilderInterface`
- `ProjectFileScannerInterface`
- `AttackerCacheInterface`
- `SecretScrubberInterface`
- `Tool\ToolInterface`, `Tool\ToolRegistryFactoryInterface`
- `Pipeline\PipelineInterface`, `Pipeline\StageInterface`,
  `Pipeline\CoverageRecorderInterface`

`Audit\Infrastructure\Advisory\AdvisoryDatabaseInterface` is also part of the
public API even though it lives under `Infrastructure/` — it is documented as an
extension point in [`docs/extending.md`](extending.md).

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

---

## Internal — what is NOT covered

Anything tagged `@internal` may be refactored, renamed, or removed in any
`MINOR` release. This includes:

- All concrete classes under `Audit/Application/Agent/` and
  `Audit/Application/Pipeline/` (`AttackerAgent`, `ReviewerAgent`,
  `AuditOrchestrator`, `VulnerabilityFactory`, `AuditPipeline`,
  `IngestionStage`, `MappingStage`, `AuditStage`).
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

---

## Deprecation policy

When a public-API element needs to be removed:

1. It is marked as deprecated in a `MINOR` release. The deprecation appears in
   [`CHANGELOG.md`](../CHANGELOG.md) under `### Deprecated`, with a clear
   migration path.
2. The deprecated element keeps working for at least the rest of the current
   `MAJOR` cycle.
3. Removal happens in the next `MAJOR` release at the earliest, listed under
   `### Removed` in the changelog.

Triggering `@trigger_error(..., E_USER_DEPRECATED)` at runtime is reserved for
behavior changes that callers may notice; pure naming or signature deprecations
are documented in the changelog only.

---

## LLM model identifiers

Model identifiers passed to `model:`, `attacker_model:`, or `reviewer_model:`
are free-form strings forwarded to `symfony/ai`. Their meaning, behavior,
pricing, and availability are owned by the LLM provider, not by this bundle. If
a provider deprecates a model, this bundle does not consider that a BC break —
pin the identifier you want in your configuration.

---

## Reporting BC breaks

If you find a change between two `1.x` releases that breaks one of the public
API elements listed above, please
[open an issue](https://github.com/vinceamstoutz/symfony-security-auditor/issues/new)
with a minimal reproduction. It is a bug and will be fixed in a patch release.
