# Changelog

All notable changes to `vinceamstoutz/symfony-security-auditor` are documented
in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning 2.0.0](https://semver.org). See
[`docs/versioning.md`](docs/versioning.md) for the backward compatibility policy
— what is public API, what is internal, and how deprecations are handled.

## [Unreleased]

### Added

- **File uploads are now a dedicated attacker skill.** `FormType`s carrying a
  `FileType`/`VichUploaderBundle` field, and the manual `UploadedFile` handling
  built on top of them, were only covered by `FormAttackerSkill`'s general
  mass-assignment/CSRF hunting — extension/MIME spoofing, path traversal via the
  original filename, and web-root RCE via an uploaded `.php` were invisible to
  the attacker. A new `FileUploadAttackerSkill`
  (`src/Audit/Infrastructure/Prompt/Skill/FileUploadAttackerSkill.php`, tagged
  `symfony_security_auditor.attacker_skill`, `priority()` 115 — right after
  `FormAttackerSkill`) targets the existing `ProjectFileType::FORM` case and
  hunts client-trusted `Content-Type`/extension checks, missing size limits,
  `getClientOriginalName()`-derived paths, public-web-root storage without
  execution disabled, predictable stored filenames, missing authorization on the
  upload endpoint, and download routes that don't re-check ownership — with a
  "do NOT flag" section for allow-listed extensions stored outside the web root
  and randomized filenames. `AttackerPromptBuilder::PROMPT_VERSION` bumps to 12,
  invalidating cached attacker responses for chunks containing a form.
- **New `--format junit` output renders findings as JUnit XML for CI test-report
  panels.** SARIF gets findings into GitHub Code Scanning and GitLab's security
  dashboard, but GitLab's dashboard requires the Ultimate tier — free-tier users
  had no way to see findings inline in a merge request.
  `audit:run --format junit` emits one failed `<testcase>` per validated finding
  (classname = vulnerability type, name = `<title> (<file>:<line>)`, `<failure>`
  carrying severity, location, OWASP reference, and remediation), rendered
  natively by GitLab merge-request test widgets on every tier, Jenkins, and any
  other JUnit consumer. New `OutputFormat::Junit` case and a dedicated
  `JunitReportRenderer`
  (`src/Audit/Infrastructure/Report/JunitReportRenderer.php`, one of the
  per-format renderers behind `ReportRendererInterface` — see _Changed_ below);
  a ready-made GitLab job example lives in `docs/ci.md`.
- **New `--format github` output renders findings as GitHub Actions
  workflow-command annotations, so they show up inline on a pull request's Files
  Changed view without a separate SARIF upload step.** SARIF upload to GitHub
  Code Scanning needs `security-events: write` permissions and a dedicated
  upload step whose result only surfaces in the Security tab;
  `audit:run --format github` instead prints one
  `::error`/`::warning`/`::notice` workflow command per validated finding
  straight to the job log (`file`, `line`, and — when the finding spans more
  than one line — `endLine` properties, plus a `title` property and a message
  carrying the description and remediation), which GitHub Actions parses and
  renders as an annotation on the exact changed line. Critical and high severity
  map to `::error`, medium to `::warning`, and low/info to `::notice`, mirroring
  the CRITICAL/HIGH → `error`, MEDIUM → `warning`, LOW/INFO → `note` reasoning
  already used by the SARIF renderer's `level` mapping. Property and message
  text are percent-escaped per GitHub's workflow-command rules (`%`, `\r`, `\n`
  always; `:` and `,` additionally in property values) so a title or description
  containing a comma, colon, or embedded code snippet cannot break the
  annotation syntax. New `OutputFormat::GithubAnnotations` case (value `github`)
  and a dedicated `GithubAnnotationsReportRenderer`
  (`src/Audit/Infrastructure/Report/GithubAnnotationsReportRenderer.php`,
  another `ReportRendererInterface` implementation); a ready-made workflow
  example lives in `docs/ci.md`.
- **API Platform resources are now a first-class attack surface.** Classes
  carrying `#[ApiResource]` declare routeless HTTP endpoints whose entire
  security model lives in attributes — previously they classified as plain
  entities, so operation-level `security:` gaps were invisible to the auditor. A
  new `ProjectFileType::API_RESOURCE` case
  (`src/Audit/Domain/Model/ProjectFile.php` detects `#[ApiResource]` anywhere,
  as well as standalone operation attributes — `#[GetCollection]`, `#[Get]`,
  `#[Post]`, GraphQL `#[QueryCollection]`, … — used without a wrapping
  `#[ApiResource]` when the `ApiPlatform\Metadata` namespace is imported, taking
  precedence over entity classification), a dedicated attacker skill block
  (`AttackerPromptBuilder`, `PROMPT_VERSION` 10) hunting operations without
  `security:`, writes relying on pre-denormalization `security:` instead of
  `securityPostDenormalize:`, unscoped `GetCollection`, sensitive `#[ApiFilter]`
  properties, over-permissive normalization/denormalization groups, and disabled
  pagination; plus an `api_resource` pre-scanner bucket
  (`RegexStaticPreScanner`, `CACHE_VERSION` 4) with `api_pagination_disabled`,
  `api_filter_declared`, and `serializer_groups_attribute` markers, and a
  chunking priority slot right after controllers. Custom markers can target the
  new bucket via `scan.custom_risk_patterns.api_resource`. Attacker cache
  entries are invalidated by the prompt/pre-scan version bumps.
- **Symfony UX Live Components are now a first-class attack surface.** Every
  `#[LiveAction]` method is an HTTP endpoint without a route and every
  `#[LiveProp(writable: true)]` is client-bound state — none of it visible in
  controllers or the access_control map, and previously classified as plain
  `php` files. A new `ProjectFileType::LIVE_COMPONENT` case
  (`src/Audit/Domain/Model/ProjectFile.php` detects `#[AsLiveComponent]`;
  non-live `#[AsTwigComponent]` classes are deliberately left as `php`), a
  dedicated attacker skill block (`AttackerPromptBuilder`, `PROMPT_VERSION` 11)
  hunting unguarded privileged `#[LiveAction]`s, writable props on sensitive
  fields (mass assignment / price manipulation), injection sinks fed by writable
  props, custom hydration `unserialize`, and client-trusted `#[LiveListener]`
  payloads; plus a `live_component` pre-scanner bucket (`RegexStaticPreScanner`,
  `CACHE_VERSION` 5) with `live_prop_writable` and `live_action_endpoint`
  markers, and a chunking priority slot right after controllers. Custom markers
  can target the new bucket via `scan.custom_risk_patterns.live_component`.
- **`security.yaml` is now parsed with `symfony/yaml` instead of single-line
  regexes, so the access-control map the attacker reasons over is finally
  complete.** `MappingStage` previously extracted `access_control` with a
  `path:`/`roles:` two-line regex and firewalls with a bare `pattern:` match
  (`src/Audit/Application/Pipeline/Stage/MappingStage.php`), silently missing
  list-form `roles`, `allow_if` expressions, `methods`/`ips`/ `requires_channel`
  constraints, `when@<env>` overrides, and firewall flags. The new Domain port
  `SecurityConfigParserInterface`
  (`src/Audit/Domain/Port/SecurityConfigParserInterface.php`, default impl
  `SymfonyYamlSecurityConfigParser` in `src/Audit/Infrastructure/Scan/`)
  performs a real YAML parse: every requirement lands in the route map
  (`allow_if: <expr>`, `methods: POST|DELETE`, `ips: …`,
  `requires_channel: https`), firewall rules carry their `security: false` /
  `stateless` flags, `route:`-keyed entries and environment-scoped `when@prod`
  blocks are read, and unparseable YAML degrades to an empty result instead of
  aborting the audit. Adds `symfony/yaml` to the runtime requirements.
- **Baselined findings now skip the reviewer entirely, and the baseline file is
  human-readable.** Previously the baseline was applied _after_ the audit
  (`BaselineProcessor::apply()` in `src/Command/AuditCommand.php`), so every
  accepted finding still paid full attacker _and_ reviewer LLM cost on every run
  before being hidden from the report; the file itself was a flat JSON array of
  opaque fingerprint hashes nobody could review. Accepted fingerprints are now
  threaded into the pipeline (`RunAuditUseCase::execute()` fifth parameter →
  `AuditContext::acceptedFingerprints()`), and `AuditOrchestrator` drops
  matching attacker findings _before_ the review phase — each unique skip
  streams once as `⚖ ⤳ baseline-accepted <type> — file:line (review skipped)`
  on a decorated terminal or `[BASELINE-SKIPPED] <type> — file:line` in plain
  output (new stable progress-event value `baseline.finding.skipped`), and the
  total lands in the `audit.baseline_skipped` context metadata.
  `--generate-baseline` now writes one JSON object per finding — `fingerprint`,
  `type`, `file`, `title`, `added_at` — so a baseline diff in code review shows
  _what_ was accepted; add a free-form `reason` key to any entry for posterity.
  The legacy flat fingerprint array is still read, so existing baseline files
  keep working unchanged. Note: the post-run "N finding(s) suppressed by the
  baseline." console note no longer appears for pipeline-skipped findings — the
  per-finding skip lines replace it.
- **Committed dotenv files are now part of the default scan surface, with
  deterministic secret markers.** `.env`, `.env.local`, `.env.dev`, `.env.test`,
  `.env.prod`, and `.env.dist` were previously invisible to the auditor twice
  over: the default `scan.included_paths` never reached the project root, and
  Symfony Finder's dot-file filtering skipped them even when listed explicitly
  (`src/Audit/Infrastructure/FileSystem/ProjectFileScanner.php`). The root
  dotenv files now ship in `ProjectFileScanner::DEFAULT_INCLUDED_PATHS`
  (gitignored `.env.local` variants stay excluded via the default
  `respect_gitignore: true`), classify as `config` files
  (`ProjectFile::detectType()`), and the deterministic pre-scanner gains two
  markers in the config bucket (`RegexStaticPreScanner`, `CACHE_VERSION` 3):
  `env_credential_assignment` flags non-empty values assigned to
  credential-named keys (`*SECRET*`, `*PASSWORD*`, `*TOKEN*`, `*API_KEY*`,
  `*ACCESS_KEY*`, `*PRIVATE_KEY*`), and `scrubbed_secret` flags every
  `***REDACTED:…***` placeholder the secret scrubber produced — so the attacker
  is pointed at committed credentials while the real values still never reach
  the LLM.
- **`bin/console audit` now works as a shorthand for `audit:run` in the bundle,
  matching the standalone CLI.** The `audit` alias is declared on the command
  itself (`AuditCommand` `#[AsCommand(aliases: ['audit'])]`, exposed as
  `AuditCommand::ALIAS`), so both distributions accept `audit` and `audit:run`
  interchangeably from a single source of truth.
- **The auditor can now run as a standalone executable, configured once at the
  user level instead of being installed into every audited app.** A new entry
  point `bin/symfony-security-auditor` boots a kernel-less Symfony Console
  application that reuses the exact same `audit:run` command (now also reachable
  through the shorter `audit` alias) with its full option surface unchanged —
  `project-path`, `-f/--format`, `-o/--output`, `--dry-run`, `--no-cache`,
  `-p/--path`, `--since`, `--baseline`, `--generate-baseline`, `--fail-on` — and
  the same `ExitCode` contract. Configuration is read from an XDG file
  (`$XDG_CONFIG_HOME/symfony-security-auditor/config.yaml`, falling back to
  `~/.config/…`) and the cache lives under `$XDG_CACHE_HOME/…` (falling back to
  `~/.cache/…`), resolved by `XdgConfigPathResolver`. The config is rootless
  (the bundle keys without the `symfony_security_auditor:` wrapper) plus a
  `platform:` block handed verbatim to `symfony/ai-bundle`, so every provider —
  Anthropic, OpenAI, Gemini, Ollama, a generic OpenAI-compatible endpoint, … —
  is configured the same way; an optional top-level `provider:` selector chooses
  the active platform when several are declared. `%env(VAR)%` placeholders in
  the platform block are resolved from the environment. A guided `init` command
  writes that config file (owner-only `0600` permissions) from interactive
  prompts and then downloads the chosen provider's
  `symfony/ai-<provider>-platform` bridge into the XDG data directory
  (`$XDG_DATA_HOME/symfony-security-auditor`, falling back to
  `~/.local/share/…`) via `composer require`; the executable itself ships no
  provider bridges, and the same pick-and-fetch path applies to every provider.
  A per-project `.symfony-security-auditor.yaml` in the working directory
  (`$PWD`) is layered over the user config, the project values winning, so a
  repo can pin its own audit settings while sharing the user-level credentials.
  New internal composition root under `src/Standalone/`
  (`StandaloneApplicationFactory`, `StandaloneContainerFactory`,
  `StandaloneConsoleCommandFactory`, `BundleExtensionLoader`), the `init`
  command, and config/bridge seams under `src/Audit/Infrastructure/`
  (`StandaloneConfigLoader`, `StandalonePlatformConfigResolver`,
  `StandalonePlatformConfig`, `StandaloneConfig`, `YamlStandaloneConfigWriter`,
  `ComposerBridgeInstaller`). Config paths are resolved natively on every OS —
  the XDG spec on Linux/macOS and `%APPDATA%`/`%LOCALAPPDATA%` on Windows.
  Publishing a GitHub release runs `.github/workflows/release.yaml`, which
  builds the PHAR with `box compile` (see `box.json`) purely as a build input
  and combines it with a `static-php-cli` micro runtime into **self-contained
  native binaries for Linux (x86-64, arm64), macOS (Intel, Apple Silicon), and
  Windows (x86-64)**, attaching each binary and its SHA-256 checksum to the
  release; an `install.sh` script detects the OS/architecture and installs the
  right one (the PHAR is no longer published as a release asset). The Symfony
  bundle remains a fully supported, unchanged install method.
- **A Windows PowerShell installer (`install.ps1`).** Mirrors `install.sh` for
  Windows: `irm …/install.ps1 | iex` detects the architecture, downloads the
  matching binary and its `.sha256`, verifies the checksum with `Get-FileHash`,
  and installs to `%LOCALAPPDATA%\Programs\symfony-security-auditor`
  (overridable via `SSA_INSTALL_DIR`, tag via `SSA_VERSION`).
- **New `--show-scanned` option on `audit:run` lists the exact files an audit
  would ingest, without invoking the LLM.** Answers "did my `included_paths` /
  `--path` configuration match the files I expect?" before paying for a run. The
  files are resolved through the same scanner and scan-path filter a real run
  uses (`ListScannedFilesUseCase`,
  `src/Audit/Application/UseCase/ListScannedFilesUseCase.php`), grouped by
  `ProjectFileType` with a per-type and total count; an empty result prints a
  "No files matched. Check your included_paths configuration and any --path
  filters." hint. Combine with `--dry-run` to print the file list first and the
  cost estimate after. A `--dry-run` run without `--show-scanned` now ends with
  a one-line tip pointing at the new option.
- **Value-object factories `Vulnerability::of()`, `SymfonyMapping::of()`, and
  `LLMResponse::of()` replace the wide positional `create()` signatures.** The
  three public Domain factories each took a long flat argument list (12, 12, and
  7 parameters); the data is now grouped into cohesive, immutable value objects
  so call sites read by meaning rather than by position. New public Domain value
  objects back this: `CodeLocation` (`src/Audit/Domain/Model/CodeLocation.php` —
  `filePath`, `lineStart`, `lineEnd`; reusable wherever a source span is
  described), `VulnerabilityClassification` (type, severity, title, confidence),
  and `VulnerabilityNarrative` (description, attack vector, proof, remediation),
  all passed to `Vulnerability::of()` alongside `string $vulnerableCode`;
  `ProjectFileInventory` (`src/Audit/Domain/Model/ProjectFileInventory.php`,
  which now owns the file-role classification) and `AccessControlMap`
  (`src/Audit/Domain/Model/AccessControlMap.php`) for
  `SymfonyMapping::of(ProjectFileInventory, AccessControlMap)`; and the existing
  `TokenUsageSnapshot` for `LLMResponse::of()` (content, model, stop reason, and
  the usage snapshot). Every public accessor on `Vulnerability`,
  `SymfonyMapping`, and `LLMResponse` is unchanged.
- **Domain exceptions `InvalidCodeLocationException` and
  `InvalidVulnerabilityClassificationException`** (under
  `src/Audit/Domain/Exception/`) for the relocated finding-field validation
  (line range, confidence range, blank title). Both extend
  `\InvalidArgumentException`, so existing `catch (\InvalidArgumentException)` /
  `expectException(\InvalidArgumentException::class)` call sites keep working
  unchanged.
- **The reviewer phase now streams a live verdict line per finding, ending the
  apparent freeze during long reviews.** Previously only the attacker streamed
  per-finding progress (`attacker.finding.recorded`); the reviewer emitted
  `review.started` once and `review.completed` at the end, so a sequential
  review of _N_ findings parked the progress bar on the audit stage with no
  visible movement for minutes — `ConsoleProgressReporter` had nothing to redraw
  between the two events. The reviewer now emits a `review.finding.reviewed`
  progress event per verdict from `VerdictApplier::apply()`, the single
  chokepoint shared by every review mode (sequential, concurrent, structured,
  and batched). A decorated terminal prints `⚖ ✓ validated <type> — file:line`
  (green) and `⚖ ✗ rejected <type> — file:line` (yellow) above the bar and
  ticks the bar suffix `reviewing i/N`; `PlainProgressReporter` appends
  `[VALIDATED]`/`[REJECTED]` lines for non-TTY output. New stable progress-event
  value `review.finding.reviewed`.
- **LLM pricing is now sourced from the daily `symfony/models-dev` catalog
  instead of a hand-maintained price table.** The new `ModelsDevPricingProvider`
  (`src/Audit/Infrastructure/Pricing/ModelsDevPricingProvider.php`) reads
  `vendor/symfony/models-dev/models-dev.json` once from disk (no network call)
  and resolves `cost.input` / `output` / `cache_read` / `cache_write` per model.
  A bare model id (`claude-opus-4-8`, `gpt-5.5`) resolves against official
  first-party providers only (Anthropic, OpenAI, Google, Mistral, Cohere,
  DeepSeek, Perplexity, Cerebras) — a version dot never makes it qualified — so
  aggregator/cloud markups never leak in; a provider-qualified id, namely
  slash-namespaced or one whose dot-delimited prefix is a catalog provider key
  (`anthropic.claude-opus-4-8` and the cloud-region form
  `us.anthropic.claude-opus-4-8`), matches anywhere in the catalog. Unknown
  models still resolve to `$0.00` with a one-time
  `"No pricing entry for LLM model — cost reporting will show zero"` warning,
  and a missing/unreadable/malformed catalog (or an absent `symfony/models-dev`
  install) degrades to zero pricing with a logged warning rather than failing
  the run. Prices now refresh on your own `composer update symfony/models-dev`
  instead of waiting for a bundle release. Adds `symfony/models-dev` (`>=87.0`)
  as a hard runtime dependency.
- **New `CacheAwarePricingProviderInterface` Domain port**
  (`src/Audit/Domain/Port/CacheAwarePricingProviderInterface.php`) — an opt-in
  extension of `PricingProviderInterface` exposing
  `cacheReadPricePerMillionTokens()` and `cacheCreationPricePerMillionTokens()`.
  `CostCalculator` consumes it via `instanceof` and falls back to the base input
  rate for providers that do not implement it, so it never breaks an existing
  pricing provider. Listed under the documented extension points in
  `docs/versioning.md`.
- **`audit:run` now warns up front when a configured model is unpriced, and
  refuses to start a budgeted run whose cost it cannot enforce.** The new
  `UnpricedModelBudgetGuard` (`src/Command/UnpricedModelBudgetGuard.php`) runs
  at the start of a real audit: if any configured model (`model`,
  `attacker_model`, or `reviewer_model`) has no catalog price it prints a
  one-time `$0.00` notice to stderr (so the `--dry-run` warning now also
  surfaces on real runs), and when `audit.budget.max_cost_usd` is additionally
  set — so the budget guard could never trip — it prompts for confirmation on an
  interactive terminal and fails closed with exit code `2` under
  `--no-interaction` / CI. When every configured model is priced the run is
  silent as before.

### Changed

- **`ProjectFile` type detection is now a single source of truth, so its
  `fileType()` and its `is*()` predicates can no longer disagree.**
  `ProjectFile::detectType()` and its private `is*Path()`/`looksLike*()`
  heuristics move verbatim into a new `ProjectFileTypeClassifier`
  (`src/Audit/Domain/Model/ProjectFileTypeClassifier.php`, pure Domain, no I/O);
  `ProjectFile::create()` now calls `ProjectFileTypeClassifier::classify()`.
  Previously `isEntity()`, `isVoter()`, `isRepository()`, `isForm()`,
  `isAuthenticator()`, `isMessengerHandler()`, `isWebhookConsumer()`, and
  `isTemplate()` re-ran the same heuristics independently of `detectType()`'s
  mutually-exclusive `match(true)`, so a file could satisfy more than one
  predicate even though `fileType()` assigned it exactly one type — e.g. an
  entity also carrying `#[ApiResource]` reported both `isEntity() === true` and
  `type() === 'api_resource'`. Every one of those predicates is now a thin
  `ProjectFileType::X === $this->fileType()` comparison, so
  `ProjectFileInventory`'s `entities`/`voters`/`repositories`/`forms`/`services`
  buckets (metadata and summary counts only — LLM scanning is keyed off
  `fileType()` directly and is unaffected) now agree with `type()` in every
  case. `isController()` already matched exactly (it is the first `match(true)`
  arm) so its behavior is unchanged. `isConfiguration()` is deliberately kept
  independent of `fileType()`: it must catch every `.yaml`/`.yml`/`.xml`/dotenv
  file regardless of directory (used by `MappingStage` to extract
  `security:`/firewall config for every config file in the project), which a
  directory-precedence-sensitive comparison against `fileType()` would silently
  narrow.
- **Fixed: `.xml` config files, and non-PHP files living in a `/Webhook/` or
  `/MessageHandler/` directory, are now classified correctly.**
  `ProjectFileTypeClassifier`'s `CONFIG` arm was missing `.xml` (already handled
  by `isConfiguration()`, so XML security config silently fell back to
  `type() === 'other'` and missed `RegexStaticPreScanner`'s `config` risk
  markers and `ConfigAttackerSkill`'s attacker prompt block), and its
  `MESSENGER_HANDLER`/`WEBHOOK_CONSUMER` directory-based arms matched any file
  under `/MessageHandler/`/`/Webhook/` regardless of extension, unlike their
  corresponding `isMessengerHandler()`/`isWebhookConsumer()` predicates which
  always required a `.php` suffix — a non-PHP file in one of those directories
  (e.g. `src/Webhook/config.yaml`) previously had
  `type() === 'webhook_consumer'` while `isWebhookConsumer()` returned `false`.
  Both are fixed in the new classifier.
- **Prompt building is split behind interfaces so neither builder is a
  monolith.** `AttackerPromptBuilder`
  (`src/Audit/Infrastructure/Prompt/AttackerPromptBuilder.php`) held all sixteen
  per-attack-surface skill blocks inline as a ~255-line `SKILLS` constant, and
  `ReviewerPromptBuilder` carried every system-prompt section plus both
  line-numbered user-message templates. Following the same **Strategy +
  Registry** idiom already used for token estimators and report renderers: each
  attacker skill block is now an `AttackerSkillInterface` strategy under
  `src/Audit/Infrastructure/Prompt/Skill/` (one class per surface —
  `ControllerAttackerSkill`, `ApiResourceAttackerSkill`,
  `LiveComponentAttackerSkill`, …), each declaring its `ProjectFileType` and
  emission `priority()`; `AttackerSkillRegistry` collects them via the
  `symfony_security_auditor.attacker_skill` DI tag and emits, in priority order,
  the blocks whose type appears in the chunk. Adding an attack surface is now
  one new tagged class with no edit to the builder. The reviewer's fixed prompt
  text moves to `ReviewerPromptSections` and its two user-message templates to
  `ReviewerMessageRenderer` (both under
  `src/Audit/Infrastructure/Prompt/Reviewer/`, behind interfaces), leaving
  `ReviewerPromptBuilder` as pure per-mode composition. The emitted prompts are
  byte-identical — `PROMPT_VERSION` is unchanged (attacker 11, reviewer 1), so
  no cached responses are invalidated — and all builders were `@internal`, so
  their internals moving is not a BC break.
- **Report rendering is split into one class per output format behind a new
  `ReportRendererInterface`, so no single class carries every format's logic.**
  The `@internal` `ReportRenderer` god class
  (`src/Audit/Infrastructure/Report/ReportRenderer.php`) bundled all six formats
  as `renderConsole()`/`renderJson()`/`renderSarif()`/`renderHtml()`/
  `renderMarkdown()` methods plus `JunitReportRenderer` sitting awkwardly beside
  it. It is removed and replaced by six focused renderers —
  `ConsoleReportRenderer`, `JsonReportRenderer`, `SarifReportRenderer`,
  `HtmlReportRenderer`, `MarkdownReportRenderer`, `JunitReportRenderer` — each
  implementing `ReportRendererInterface` (`format(): string` +
  `render(AuditReport): string`) in `src/Audit/Infrastructure/Report/`. Shared
  pieces move to `ReportPackage` (package name/homepage/version) and
  `TemplateLoader` (template reads). Every renderer is autoconfigured with the
  `symfony_security_auditor.report_renderer` tag; `Command\ReportWriter` now
  takes the tagged iterator, indexes renderers by their `format()` key, and
  dispatches the selected `--format` — throwing the new
  `Command\Exception\UnsupportedOutputFormatException` when no renderer
  advertises that key. All six `--format` values and their output are unchanged;
  `ReportRenderer` was `@internal` so its removal is not a BC break. Adding a
  format is now "new class + service registration", with no `match` arm to edit
  (see [`docs/extending.md`](docs/extending.md)).
- **OWASP references now point at the Top 10:2025 edition instead of 2021.**
  `VulnerabilityType::owaspReference()` and `owaspReferenceUrl()`
  (`src/Audit/Domain/Model/VulnerabilityType.php`) emitted 2021 category ids
  (e.g. `OWASP A03:2021 - Injection`) in the report `owasp` field and SARIF
  `helpUri`, which read as stale against the released OWASP Top 10:2025. Every
  type is remapped to its 2025 category: injection types move to
  `A05:2025 - Injection`, misconfiguration types to
  `A02:2025 - Security Misconfiguration`, cryptographic types to
  `A04:2025 - Cryptographic Failures`, design flaws to
  `A06:2025 - Insecure Design`, integrity types to
  `A08:2025 - Software or Data Integrity Failures` (renamed from "and"),
  `authenticator_bypass` to `A07:2025 - Authentication Failures`, and `ssrf`
  folds into `A01:2025 - Broken Access Control` per the 2025 consolidation. URLs
  now use the `https://owasp.org/Top10/2025/…` category pages. The report schema
  is unchanged — only the `owasp`/`helpUri` values move.

- **Prompt-cache traffic is now priced from each provider's real per-model cache
  rates instead of Anthropic-only multipliers.** `CostCalculator`
  (`src/Audit/Application/Budget/CostCalculator.php`) previously derived cache
  cost from two hardcoded constants (`0.1x` read, `1.25x` write) gated on the
  model id containing `'claude'`, which mispriced every other provider's prompt
  cache at `1.0x`. It now reads `cache_read` / `cache_write` from the catalog
  via `CacheAwarePricingProviderInterface` (e.g. `gemini-2.5-flash` cache reads
  at its real `0.075` rate). Anthropic figures are unchanged — the catalog's
  `0.5` / `6.25` rates for `claude-opus-4-8` equal the old `5×0.1` / `5×1.25`.
  The default `PricingProviderInterface` service alias now points at
  `ModelsDevPricingProvider`.

### Deprecated

- **`Vulnerability::create()`, `SymfonyMapping::create()`, and
  `LLMResponse::create()`.** They remain fully functional for the rest of the
  `1.x` cycle and now delegate to the new `of()` factories; switch to `of()`
  (see Added above). Each now emits a runtime deprecation via
  `trigger_deprecation('vinceamstoutz/symfony-security-auditor', '1.13', …)`
  when called, so usage surfaces in your deprecation log and in CI
  (`failOnDeprecation`) and the removal in the next `MAJOR` does not arrive as
  an unannounced fatal. Scheduled for removal in the next `MAJOR`.

### Removed

- **`StaticPricingProvider` and its hand-maintained 68-model `PRICES` constant**
  (`src/Audit/Infrastructure/Pricing/StaticPricingProvider.php`). The
  catalog-backed `ModelsDevPricingProvider` (see Added) is now the sole pricing
  source, so no hardcoded prices remain. The class was `@internal`, so this is
  not a public-API break. Of the 68 ids it carried, 58 keep identical
  input/output prices from the catalog, 2 move to current provider rates
  (`o4-mini` `0.55/2.20` → `1.1/4.4`, `mistral-medium-2604` `0.40/2.00` →
  `1.5/7.5`), and 8 old/niche ids absent from the catalog (`claude-opus-4`,
  `claude-sonnet-4`, `codestral-2508`, `devstral-{medium,small}-2512`,
  `ministral-{3b,8b,14b}-2512`) now resolve to `$0.00` with a warning. The
  default `claude-opus-4-8` and every current model are catalog-present and
  unchanged.

### Fixed

- **`--since` silently dropped changed dotfiles (`.env`, `.github/...`) from
  incremental audits.** `ProcessGitChangedFilesResolver::mergeAndNormalize()`
  (`src/Audit/Infrastructure/Diff/ProcessGitChangedFilesResolver.php`) used
  `trimStart('./')`, which strips a leading **character mask** (every leading
  `.` and `/`), not the literal prefix `./` — `.env` was mangled to `env` and
  `.github/workflows/ci.yml` to `github/workflows/ci.yml`. The mangled path then
  failed the exact-match lookup against real project files, so a changed `.env`
  (or any dotfile/dot-directory) was excluded from `audit:run --since` scope
  even though it changed. Now uses `trimPrefix('./')`, which strips only the
  literal `./` prefix.
- **Static pre-scan patterns using the `s` (DOTALL) modifier never matched
  anything.** `RegexStaticPreScanner::matchLines()`
  (`src/Audit/Infrastructure/Scan/RegexStaticPreScanner.php`) explodes file
  content into lines and matches each pattern against one line at a time, so the
  two cross-line patterns in the dictionary — `supports_returns_null` (an
  authenticator's `supports()` silently returning `null`, which Symfony treats
  as "supports") and `http_client_request` (an `HttpClient` reference followed
  by `->request(`, an SSRF surface) — could never fire: a real multi-line method
  body never appears on a single line. Patterns carrying the `s` modifier are
  now matched against the full file content instead, with the match offset
  mapped back to a line number; all other (single-line) patterns are unchanged.
  `RegexStaticPreScanner:: CACHE_VERSION` moves to `6` since this alters scan
  output for existing chunk content, invalidating stale attacker cache entries.
- **`--format junit` could emit XML that no consumer could re-parse.**
  `JunitReportRenderer`
  (`src/Audit/Infrastructure/Report/JunitReportRenderer.php`) inserted a
  finding's LLM-produced title, description, and remediation text directly into
  DOM attributes and text nodes. `DOMDocument::saveXML()` escapes XML
  metacharacters (`<`, `&`, `"`) but writes XML-1.0-illegal control bytes
  (`\x00`-`\x08`, `\x0B`, `\x0C`, `\x0E`-`\x1F`) out verbatim, so a finding
  whose narrative happened to reproduce one of those bytes (a plausible outcome
  when the model echoes a raw exploit payload) produced a `.xml` report that
  GitLab, Jenkins, and any standard XML parser rejected outright. Those bytes
  are now stripped before insertion.
- **Retryable LLM failures embedding a non-transient status code as a digit
  substring were misclassified as fatal, aborting the audit instead of
  retrying.** `TransientFailureClassifier::isTransient()`
  (`src/Audit/Infrastructure/LLM/TransientFailureClassifier.php`) checked its
  `400`/`401`/`403`/`404`/`422` "non-transient" hints with a plain substring
  search, so a genuinely retryable message like `"HTTP 500 (request id 400123)"`
  or `"cURL error 28: timed out after 1400 ms"` matched `400` and was rethrown
  as fatal instead of retried. Status-code hints (for `isTransient()` and
  `isRateLimit()`'s `429`) are now matched as word-bounded tokens instead of raw
  substrings; the textual hints (`"rate limit"`, `"timed out"`, …) are
  unchanged.

### Security

- **The install scripts now fail closed on checksum verification.** Previously
  `install.sh` printed a warning and installed anyway when no SHA-256 tool was
  present; it now **aborts** rather than install an unverified binary.
  `install.ps1` verifies with `Get-FileHash` (built into PowerShell). The
  release workflow (`.github/workflows/release.yaml`) also **smoke-tests** every
  binary (`--version`) before publishing, so a broken build never reaches the
  release.

## [1.12.0] — 2026-06-16 — Spotlight

An observability release. The long audit stage is no longer a black box:
`audit:run` now streams each finding the instant the attacker records it, opens
with an attack-surface overview, closes every iteration with a reviewer tally,
and prints per-chunk timing — so slow local-model runs read as working, not
frozen. A new CI-safe `PlainProgressReporter` renders the same narrative as
clean, append-only lines for non-TTY output, and a decorated terminal gets a
severity-colored findings feed above the bar. Reports now link back to the
project across the HTML, Markdown, and console formats; the `--dry-run` "no
pricing data" notice no longer reads like an error for local/self-hosted models;
Symfony component detection recognizes controllers, voters, forms, entities, and
repositories by directory and content, not just filename suffix; and the
`symfony/ai-bundle` requirement moves to `^0.10`.

### Added

- **Live findings feed and a CI-safe progress renderer for `audit:run`.** Early
  users praised the accuracy and remediation quality but reported having "no
  visibility into what the audit is doing" during the long audit stage — the run
  streamed nothing as findings were discovered, and in CI the animated progress
  bar was the wrong tool entirely. The console now narrates the audit as it
  happens: each vulnerability the attacker flags streams out the instant it is
  recorded (e.g.
  `⚔ 🟠 HIGH sql_injection — src/Controller/UserController.php:42`), the audit
  opens with an attack-surface overview that lists only non-empty categories
  (`🔍 Auditing 152 file(s) — 24 controller(s), 5 voter(s), 8 form(s)`), and
  each iteration closes with a reviewer tally
  (`✓ Reviewed: 5 validated, 1 rejected`). Three new wire-format progress events
  back this — `audit.started` and `review.completed` (emitted by
  `AuditOrchestrator`, `src/Audit/Application/Agent/AuditOrchestrator.php`) and
  `attacker.finding.recorded` (emitted per finding by the sequential and
  concurrent chunk analyzers via `ChunkFindingProgress`,
  `src/Audit/Application/Agent/Chunk/ChunkFindingProgress.php`) — all flowing
  through the existing `ProgressReporterInterface` port, additive to the events
  shipped in 1.11.0. A new `PlainProgressReporter`
  (`src/Audit/Infrastructure/Progress/PlainProgressReporter.php`) renders the
  same narrative as plain, append-only lines — no carriage returns, no cursor
  control, no progress bar — for non-interactive output (CI logs, pipes,
  redirected files), keeping the feed clean and greppable and the log alive on
  long runs. `audit:run` selects the renderer automatically from
  `OutputInterface::isDecorated()`: the animated `ConsoleProgressReporter` for a
  TTY, `PlainProgressReporter` otherwise. Machine-readable stdout
  (`--format=json|sarif` without `--output`) stays silent as before. Progress
  reporting adds no measurable runtime cost — events are O(findings)/O(chunks)
  and rendering is local I/O, dwarfed by the LLM calls.
- **Slow and local-model runs no longer look frozen mid-chunk.** A synchronous
  LLM call blocks for its whole duration — minutes at a time on a local model —
  with no chance to repaint, so the line appeared hung. The bar message now
  reads `⏳ querying model · chunk 2/5` while a call is in flight (so the pause
  reads as waiting, not a crash), and each chunk prints a completion line with
  its wall time as it returns (`✓ chunk 2/5 analyzed (47s)`). In a decorated
  terminal the findings feed is now color-coded by severity (red critical,
  bright-red high, yellow medium, green low, blue info — via the new
  `SeverityColor` map), the overview is cyan and the review/chunk lines green;
  these are stripped automatically in non-interactive output. This makes
  progress and per-chunk timing visible between calls. Backed by a new
  `attacker.chunk.completed` wire event (chunk index, total, elapsed seconds)
  emitted by the sequential and concurrent chunk analyzers and rendered by both
  `ConsoleProgressReporter` and `PlainProgressReporter`. (A true mid-call
  animation would require streaming the model response — a larger change to the
  LLM seam — because the global audit total, iterations × chunks, is not known
  ahead of time.)

### Changed

- **The `--dry-run` "no pricing data" warning no longer reads like an error for
  local models.** When a configured model is absent from the bundled
  `StaticPricingProvider` price table,
  `AuditPresenter::unsupportedModelWarnings()`
  (`src/Command/AuditPresenter.php`) prints a stderr notice and the estimate
  shows `$0.00`. The previous copy — _"No pricing data for the configured
  model(s): … and may be inaccurate. Check the model name(s) …"_ — framed the
  legitimate local/self-hosted case (Ollama, LM Studio), where `$0.00` is the
  correct estimate, as a likely misconfiguration. The notice now states that
  `$0.00` is correct for a local or self-hosted model and can be ignored, and
  only flags a typo or an unlisted model as the problem case. Unchanged: the
  notice stays stderr-only (so `--format=json` / `--format=sarif` stdout is
  untouched) and token counts remain accurate.
- **Report attribution now links back to the project across the HTML, Markdown,
  and console formats.** The HTML footer in
  `src/Audit/Infrastructure/Report/Template/report.html` previously rendered
  `Generated by vinceamstoutz/symfony-security-auditor.` as plain text; it is
  now a hyperlink to
  <https://github.com/vinceamstoutz/symfony-security-auditor>. The Markdown
  report (`ReportRenderer::renderMarkdown()`) gained a
  `Generated by [vinceamstoutz/symfony-security-auditor](…)` footer, and the
  console header (`src/Audit/Infrastructure/Report/Template/console.txt`) now
  prints the project URL beneath the package name. SARIF already exposed the URL
  as the tool driver's `informationUri`; it is now sourced from the shared
  `ReportRenderer::HOMEPAGE_URL` constant (value unchanged), and the JSON report
  is untouched.

- **The console progress bar no longer renders in non-interactive output.**
  `audit:run` previously drove a Symfony `ProgressBar` regardless of whether the
  output was a terminal, so CI logs and redirected files accumulated bar redraws
  that read as noise. Non-decorated runs now use the new `PlainProgressReporter`
  (one clean line per event); decorated terminals keep the animated bar — now
  with an elapsed-time counter and the live findings feed printed above it. The
  human-readable console output is not part of the BC promise (see
  `docs/versioning.md`); the JSON, SARIF, HTML, and Markdown reports are
  unchanged.
- **`audit:run` prints the resolved project directory and a lighter heads-up.**
  The header and report showed the path exactly as given — `.` when run from the
  project root — which read poorly; `AuditCommandInput::resolvedProjectPath()`
  now resolves `.` and relative paths to an absolute directory (via
  `Path::makeAbsolute`, trimming surrounding whitespace). The long-run heads-up
  is now a dim one-line message instead of a boxed `[NOTE]` block.
- **Minimum `symfony/ai-bundle` requirement raised from `^0.9` to `^0.10`.**
  `composer.json` now requires `symfony/ai-bundle: ^0.10`. `symfony/ai-platform`
  0.10 widened `PlatformInterface::invoke()`'s first parameter from
  `string $model` to `Model|string $model`; the bundle's production code is
  unaffected (it calls `invoke()` with a string, still valid under the widened
  signature), so existing runs behave identically. Consumers pinning
  `symfony/ai-bundle: ^0.9` must allow `^0.10` to upgrade.

### Fixed

- **Symfony component detection now recognizes controllers, voters, forms,
  entities, and repositories by directory and content — not just by filename
  suffix.** `ProjectFile` (`src/Audit/Domain/Model/ProjectFile.php`) classified
  a controller only when its path ended in `Controller.php`, so a project of
  invokable/action-style controllers under `src/Controller/` (e.g.
  `src/Controller/Homepage.php`) reported a single controller in the audit
  overview — and, worse, only that one received controller-aware analysis:
  `MappingStage` parses route/access-control and form bindings exclusively from
  recognized controllers, and the feature chunker groups context around them.
  Detection now also matches the canonical directories (`/Controller/`,
  `/Voter/`, `/Repository/`, `/Entity/`, `/Entities/`, and `/Form/` with a
  `Type.php` suffix) and telltale content (`extends AbstractController` or
  `#[Route]`; `implements VoterInterface` or `extends Voter`;
  `extends AbstractType`; `#[ORM\Entity]`; `extends ServiceEntityRepository` or
  `EntityRepository`) — for both the `is*()` predicates and the
  `ProjectFileType` classification, so the mapping counts, feature chunking, and
  route/form analysis all see the full set. Plain `.php` services without these
  signals stay classified as services.

## [1.11.0] — 2026-06-15 — Tracer

A gating, suppression, reporting, and detection release. Audits can now fail CI
at a chosen severity (`audit.fail_on` / `--fail-on`, default `critical`) and
mute whole finding classes without per-finding baselines (`audit.excluded_types`
/ `audit.included_types`). SARIF output gained stable `partialFingerprints` so
GitHub Code Scanning tracks findings across runs, plus per-rule OWASP `helpUri`s
(with `authenticator_bypass` and `missing_signature_verification` re-mapped to
A07/A08), and a new `--format=markdown` renders a report for pull-request
comments and job summaries. The attacker prompt now traces each finding
source→sink, sweeps the STRIDE categories per entry point, and weights severity
by exposure.

### Added

- **Type-level finding suppression — the `audit.excluded_types` and
  `audit.included_types` config keys.** Muting a whole noisy class of finding
  (e.g. `missing_rate_limiting`) previously required enumerating every finding's
  baseline fingerprint; there was no way to say "never report this type."
  `audit.excluded_types` now drops findings of the listed `VulnerabilityType`
  values from the report **and** the exit code, and `audit.included_types` is an
  allowlist that, when non-empty, keeps only the listed types (exclusions still
  win). Both are validated against the `VulnerabilityType` enum at
  config-compile time. A new `AuditReport::filteredByTypes()` (Domain,
  copy-on-write like `withoutFingerprints()`) does the filtering and a
  `FindingTypeFilter` (`src/Command/FindingTypeFilter.php`, behind
  `FindingTypeFilterInterface`) applies the configured lists in `AuditCommand`
  right after the audit runs — before baseline suppression, rendering, and
  exit-code resolution — so muted types never appear, never fail CI, and are
  absent from a generated baseline. Both default to `[]` (no filtering), so
  existing runs are unchanged. Public API per `docs/versioning.md`.
- **Configurable CI gate severity — the `audit.fail_on` config key and the
  `--fail-on` CLI option.** `audit:run` hardcoded its failing exit code to a
  `CRITICAL` aggregate risk level: `AuditExitCodeResolver::resolve()`
  (`src/Command/AuditExitCodeResolver.php`) returned `1` only when
  `AuditReport::riskLevel()` was exactly `CRITICAL`, so a HIGH-risk audit always
  exited `0` and there was no way to fail a pull request on HIGH/MEDIUM/LOW
  findings. A new ordered `RiskLevel` value object
  (`src/Audit/Domain/Model/RiskLevel.php`, `safe` < `low` < `medium` < `high` <
  `critical`, with `RiskLevel::isAtLeast()`) now backs the comparison:
  `AuditReport::riskLevelEnum()` exposes the report's aggregate level and the
  resolver exits `1` when it is **at or above** the configured threshold. The
  threshold is set with `audit.fail_on` (`safe`|`low`|`medium`|`high`|
  `critical`) and overridden per run with `audit:run --fail-on=<level>` (a
  budget abort still exits `2`). The default is `critical`, so existing exit
  codes are byte-identical on upgrade. **The default is planned to become `high`
  in the next major** (see `docs/versioning.md`); pin `audit.fail_on` explicitly
  to be immune to that change — `high` is recommended for CI gating. Public API
  per `docs/versioning.md` (new config key, new CLI option, and the `RiskLevel`
  Domain model).
- **SARIF results now carry a stable `partialFingerprints` value, and each rule
  links to its specific OWASP Top 10 page.** GitHub Code Scanning correlates
  findings across runs by `partialFingerprints`; without one it could not track
  a finding's fixed/reopened state and re-surfaced duplicates. Each SARIF result
  emitted by `ReportRenderer::renderSarif()`
  (`src/Audit/Infrastructure/Report/ReportRenderer.php`) now includes
  `partialFingerprints: { "symfonySecurityAuditor/v1": "<fingerprint>" }` using
  the same stable `Vulnerability::fingerprint()` that backs baselines. Each
  rule's `helpUri` — previously the generic `https://owasp.org/Top10/` for every
  rule — now points at the finding's actual OWASP 2021 category page via the new
  `VulnerabilityType::owaspReferenceUrl()`. Both are additive to the SARIF 2.1.0
  output (public API per `docs/versioning.md`).
- **New `--format=markdown` output — a GitHub-flavored report for PR comments
  and job summaries.** `audit:run` emitted `console`, `json`, `sarif`, and
  `html`; teams not using Code Scanning had no concise report to post to a pull
  request or write to `$GITHUB_STEP_SUMMARY`. The new `markdown` value renders a
  heading, a severity summary table, and one section per finding (type + OWASP,
  location, confidence, description, attack vector, proof, remediation), via
  `ReportRenderer::renderMarkdown()`. `OutputFormat` gains a `Markdown` case and
  `ReportWriter` a `markdown` arm. Public API per `docs/versioning.md` (the
  `--format` value `markdown`).

### Changed

- **The attacker prompt now applies an explicit source→sink methodology, a
  STRIDE sweep, and exposure-weighted severity.** `AttackerPromptBuilder`
  (`src/Audit/Infrastructure/Prompt/AttackerPromptBuilder.php`) gained an
  "Analysis methodology" section that tells the model to trace each
  attacker-controlled value from its trust-boundary source through to a
  dangerous sink and to verify that no guard, validator, parameterization,
  escaping, `access_control`, or voter neutralizes the path before recording a
  finding; to sweep the STRIDE categories (Spoofing, Tampering, Repudiation,
  Information disclosure, Denial of service, Elevation of privilege) per entry
  point so no class is skipped; and to calibrate severity by reachability and
  exposure (risk ≈ likelihood × impact) rather than bug class alone. Informed by
  standard threat-modeling practice (STRIDE, trust boundaries, risk-based
  prioritization). `PROMPT_VERSION` is bumped `8` → `9`, invalidating
  previously-cached attacker responses so the new guidance takes effect.

### Fixed

- **Corrected two OWASP Top 10 categorizations surfaced by the new per-rule
  `helpUri`.** `VulnerabilityType::owaspReference()` (and the new
  `owaspReferenceUrl()`) mis-filed two types: `authenticator_bypass` was under
  `A01:2021 - Broken Access Control` and `missing_signature_verification` under
  `A02:2021 - Cryptographic Failures`. They now map to the canonical categories
  — **`authenticator_bypass` →
  `A07:2021 - Identification and Authentication Failures`** (the textbook A07
  case) and **`missing_signature_verification` →
  `A08:2021 - Software and Data Integrity Failures`** (accepting unverified
  payloads is an integrity failure, not a cryptographic one). This changes the
  SARIF `ruleId` and `helpUri` for findings of those two types. The internal
  `category()` grouping is unchanged (it has no auth/integrity bucket).

## [1.10.1] — 2026-06-15 — Encore

A packaging-only republish of **1.10.0 — Lookout**. The `1.10.0` tag was first
pushed to an incomplete commit and indexed by Packagist; moving the tag to the
finished release commit was then refused by
[Packagist's stable-version immutability rule](https://packagist.org/about#version-immutability)
("Upstream re-tag blocked — Packagist's stored snapshot may no longer match what
is currently in git"), which locks a published version's source/dist reference
forever. This release republishes the full, intended Lookout contents under a
fresh, unblocked version so
`composer require vinceamstoutz/symfony-security-auditor` resolves the complete
release. **There are no source changes relative to the intended 1.10.0** — see
the [1.10.0](#1100--2026-06-15--lookout) entry below for the actual features and
fixes. The config-schema URL and GitHub Action `uses:` pins move from `1.10.0`
to `1.10.1` accordingly.

## [1.10.0] — 2026-06-15 — Lookout

A reporting-and-CI release. Audits gain a self-contained, HTML-escaped report
(`--format=html`) and baseline suppression of accepted findings (`--baseline` /
`--generate-baseline` / `audit.baseline`) so only new findings fail CI. The
bundle now ships as a reusable, Marketplace-publishable GitHub Action and a JSON
Schema that drives editor autocompletion for
`config/packages/symfony_security_auditor.yaml`. The reviewer-verdict cache
finally covers batched reviews, and the stale model hints in the Composer
`suggest` block are refreshed.

### Added

- **JSON Schema for editor autocompletion of the bundle configuration.** A
  schema describing every `symfony_security_auditor:` key ships at
  `resources/schema.json`. Editors backed by the YAML Language Server pick it up
  from a `# yaml-language-server: $schema=…` modeline (added to the
  `examples/configs/*.yaml` samples and documented in `docs/configuration.md`),
  giving key completion, type checking, and inline docs while editing
  `config/packages/symfony_security_auditor.yaml`.
- **New `--format=html` output — a self-contained, HTML-escaped audit report.**
  `audit:run` previously emitted only `console`, `json`, and `sarif`. The new
  `html` value renders a standalone HTML document (inline CSS, severity-colored
  summary table, one card per finding) suitable for sharing or archiving as a CI
  artifact — `bin/console audit:run . --format=html --output=report.html`.
  Implemented by `ReportRenderer::renderHtml()`
  (`src/Audit/Infrastructure/Report/ReportRenderer.php`) against new
  `Template/report.html` + `Template/vulnerability.html` stubs; every dynamic
  value (titles, descriptions, code, file paths) is escaped with
  `htmlspecialchars(…, ENT_QUOTES | ENT_SUBSTITUTE)` so a finding containing
  `<script>` cannot inject markup into the report itself. `OutputFormat` gains a
  `Html` case and `ReportWriter` an `html` arm. Public API per
  `docs/versioning.md` (the `--format` value `html`).
- **Baseline suppression of accepted findings — `--baseline`,
  `--generate-baseline`, and the `audit.baseline` config key.** There was no way
  to accept a known finding so it stopped failing CI. A finding now has a stable
  `Vulnerability::fingerprint()` (`SSA-` + SHA-1 of type + file path + title —
  deliberately independent of line numbers and the non-deterministic `id`).
  `audit:run --generate-baseline=<file>` runs the audit, writes every current
  finding's fingerprint to a JSON file, and exits `0`;
  `audit:run --baseline=<file>` (or the `audit.baseline` default path) drops
  findings whose fingerprint is listed from the report **and** from the
  exit-code calculation, so previously-accepted findings no longer fail CI.
  Backed by `AuditReport::fingerprints()` / `AuditReport::withoutFingerprints()`
  (Domain) and the `Baseline` file gateway (`src/Command/Baseline.php`); a
  malformed baseline file raises `MalformedBaselineFileException`. Public API
  per `docs/versioning.md`.
- **A reusable, Marketplace-publishable GitHub Action.** The repository now
  ships a composite action (`action.yml` at the repo root) so consumers can run
  an audit with `uses: vinceamstoutz/symfony-security-auditor@v1` instead of
  scripting the steps. It sets up PHP, installs Composer dependencies, and runs
  `audit:run`, exposing inputs for `project-path`, `format`, `output`,
  `baseline`, `generate-baseline`, `since`, `extra-args`, `php-version`,
  `setup-php`, `install-dependencies`, and `working-directory` (the provider key
  is passed via `env:`). Documented in `docs/ci.md` (Reusable GitHub Action).

### Changed

- **The reviewer-verdict cache now covers batched reviews
  (`audit.reviewer_batch_size > 1`).** Batched reviews used to always call the
  LLM — the cache only applied to one-finding-per-call modes — and `audit:run`
  printed a pre-flight stderr notice whenever batching ran with the cache
  enabled. `BatchReviewAnalyzer`
  (`src/Audit/Application/Agent/Review/BatchReviewAnalyzer.php`) now mirrors
  `ConcurrentReviewAnalyzer`: it resolves each finding's code context, serves
  cache hits through `ReviewOutcomeRecorder::recordVerdict()`, and batches only
  the cache-miss findings to the LLM (preserving the original finding order).
  Matched verdicts from a miss batch are persisted via `BatchVerdictApplier`,
  keyed by the finding's code context; a `--no-cache`/bypassed run reads and
  writes nothing. The now-obsolete "batching disables the reviewer-verdict
  cache" notice is removed from `ConfigurationNotices` (whose unused
  `CacheConfiguration` parameter is dropped).
- **The pre-flight token estimator is now one implementation per LLM provider.**
  The monolithic `CharacterBasedTokenEstimator` (a single class holding a prefix
  → chars-per-token lookup table for every vendor) is replaced by a
  `ResolvingTokenEstimator` that dispatches each model to a dedicated
  `ProviderTokenEstimatorInterface` implementation — `AnthropicTokenEstimator`,
  `OpenAiTokenEstimator`, `GeminiTokenEstimator`, `MistralTokenEstimator`,
  `LlamaTokenEstimator`, `DeepSeekTokenEstimator` — each owning its own
  model-name matching and character-to-token ratio, with a shared
  `CharacterRatioCounter` doing the arithmetic
  (`src/Audit/Infrastructure/LLM/TokenEstimator/`). The estimates are unchanged
  (identical ratios, prefixes, and unknown-model fallback), so reported
  `--dry-run` costs stay the same; the win is that adding or tuning a provider
  is now a small, isolated class tagged
  `symfony_security_auditor.token_estimator` rather than an edit to a shared
  table. `CharacterBasedTokenEstimator` was `@internal`, so this is not a BC
  break (the public `TokenEstimatorInterface` port is untouched).

### Fixed

- **Corrected stale Mistral list prices in the built-in cost table.** Six
  entries in `StaticPricingProvider::PRICES`
  (`src/Audit/Infrastructure/Pricing/StaticPricingProvider.php`) overstated
  Mistral's current per-million-token rates, inflating the estimated/actual cost
  reported for those models. Reconciled against
  [models.dev](https://models.dev):
  `mistral-medium-latest`/`mistral-medium-2604` `$1.50/$7.50` → `$0.40/$2.00`,
  `mistral-small-latest`/`mistral-small-2603` `$0.10/$0.30` → `$0.15/$0.60`,
  `ministral-3b-2512` `$0.10/$0.10` → `$0.04/$0.04`, and `ministral-8b-2512`
  `$0.15/$0.15` → `$0.10/$0.10`. All other providers were spot-checked and left
  unchanged; cost reporting for the affected Mistral models is now accurate.

## [1.9.0] — 2026-06-12 — Slipstream

A config-less performance and reviewer-trust release. The zero-configuration
path is now also the cheap and fast one: `claude-opus-4-8` and a byte-stable
attacker system prompt (provider prompt-cache friendly on Anthropic, OpenAI,
Gemini, and DeepSeek) by default, a one-knob `profile` preset for everything
else, caches that finally cover iterations 2+ and concurrent reviews, and
reviewer verdicts recorded through a schema-enforced `record_review` tool by
default — cached across runs and fed back to the attacker when findings are
rejected. The long audit stage shows live progress in the console, prompt-cache
tokens are priced into the reported cost, reports lead with their most severe
findings, and the attacker's route map stops mislabelling firewall-covered
routes.

### Added

- **`audit:run` warns when cheap-then-expensive escalation can't save money.**
  `audit.escalation.cheap_model` falls back to the reviewer model when unset,
  which on a single-model config resolves to the attacker model — so the cheap
  sweep costs as much as the expensive pass and escalation saves nothing,
  silently. `ConfigurationNotices` now emits a pre-flight stderr notice when
  escalation is enabled and the resolved cheap model equals the attacker model,
  pointing at `audit.escalation.cheap_model`. Two further notices cover the
  silent no-op cases where a concurrency knob is set but ignored:
  `reviewer_max_concurrent` > 1 with `reviewer_tools_enabled: true`, and
  `attacker_max_concurrent` > 1 without the structured-collection-and-no-tools
  mode it requires.
- **The `--dry-run` note now states that real runs typically cost less.** The
  estimate excludes provider prompt-cache discounts and warm attacker/reviewer
  caches; the dry-run output now says so explicitly instead of only the docs
  mentioning it.
- **New `audit.attacker_max_concurrent` config key — concurrent attacker chunk
  analysis.** The attacker analysed chunks strictly sequentially, so the longest
  audit phase paid one full LLM round trip per chunk back-to-back. In the
  default structured-collection mode, when the configured platform exposes an
  async transport, cache-miss chunks are now resolved concurrently through the
  new `ToolBatchCapableLLMClientInterface` wavefront — each chunk keeps its own
  `record_vulnerability` registry and `VulnerabilityCollector`, so findings
  never cross-contaminate. Cache hits short-circuit first; chunk order,
  coverage, caching, and drop accounting are byte-identical to the sequential
  path. Defaults to the active profile (`fast`: `4`, `balanced`/`thorough`:
  `1`); ignored when `audit.tools_enabled` gives the attacker a cross-file tool
  registry or `audit.structured_collection` is off. Public API per
  `docs/versioning.md`.
- **Live audit-stage progress and an upfront long-run notice in the console.**
  During the audit stage — by far the longest — the progress bar sat frozen at
  the same percentage with no sign the run was still alive, sometimes for 20+
  minutes
  ([#39](https://github.com/vinceAmstoutz/symfony-security-auditor/issues/39)).
  `audit:run` (console format only) now prints a note above the progress bar
  warning that the audit typically takes several minutes, and the bar message
  updates continuously with the current activity, e.g.
  `audit · iteration 1/3 · attacker chunk 4/12` and
  `audit · iteration 1/3 · reviewing 4 finding(s)`. Three new wire-format
  progress events back this: `audit.iteration.started` and `review.started`
  (emitted by `AuditOrchestrator`) and `attacker.chunk.started` (emitted by
  `AttackerAgent`), all flowing through the existing `ProgressReporterInterface`
  port and rendered by `ConsoleProgressReporter`
  (`src/Audit/Infrastructure/Progress/ConsoleProgressReporter.php`).
  Machine-readable stdout (`--format=json|sarif` without `--output`) stays clean
  — neither the notice nor the bar is emitted there.
- **The attacker now learns which findings the reviewer already rejected.**
  After the first iteration, `AuditOrchestrator`
  (`src/Audit/Application/Agent/AuditOrchestrator.php`) collected only the
  reviewer-_validated_ findings to feed back to the attacker; rejected findings
  were invisible, so every subsequent iteration re-reported them, the confidence
  filter let them through, and the reviewer re-rejected them — burning attacker
  tool-call and reviewer budget each round before the deduplication step finally
  discarded them. The orchestrator now also gathers reviewer-rejected findings
  and passes them through a new `AttackerAnalysisRequest::$rejectedFindings`
  field; `AttackerContextPromptRenderer::renderRejectedFindings()` injects a
  `Findings Already Rejected by the Reviewer` preamble instructing the model not
  to re-report those locations. Chunks carrying rejected-finding context are not
  served from the attacker cache (the same rule already applied to validated
  prior findings), so the new context always reaches the model.
- **New `audit.reviewer_structured_collection` config key — provider-validated
  reviewer verdicts, on by default.** The reviewer returned its verdicts as a
  hand-parsed JSON array; a malformed response was discarded (after being fully
  billed) and every finding in the call degraded to rejected. The reviewer now
  records each verdict by calling a schema-enforced `record_review` tool
  (`src/Audit/Infrastructure/Tool/RecordReviewTool.php`) — mirroring the
  attacker's `record_vulnerability` seam: the provider validates every call
  against the tool's JSON schema (`id` + `accepted` required,
  `adjusted_severity` / `corrected_type` constrained to their enums), so a
  malformed verdict is structurally impossible. Verdicts flow through a new
  `ReviewCollector` (Application) and are re-keyed by `id` exactly like the JSON
  batch path. Defaults to `true` — matching the attacker's
  `structured_collection` default, so the schema-safe (and cheaper: no
  billed-but-discarded responses) path needs no configuration. The released
  explicit opt-in `reviewer_tools_enabled: true` takes precedence and keeps the
  JSON path; `reviewer_max_concurrent` > 1 composes with the structured mode on
  platforms with an async transport and falls back to the JSON path otherwise —
  in both cases behaving at least as well as before the upgrade. Set
  `reviewer_structured_collection: false` to force JSON-array output (the safety
  net for models without tool-use support).
- **New `audit.stable_system_prompt` config key — a byte-stable attacker system
  prompt for provider cache reuse, on by default.** The attacker used to emit
  only the expert skill blocks matching a chunk's file types, so its system
  prompt differed chunk-to-chunk and provider prompt caching rarely got a hit on
  it — Anthropic (`cache_retention` in `ai.yaml`, default `short`), OpenAI,
  Gemini, and DeepSeek all cache prompt prefixes that this defeated. With
  `stable_system_prompt: true` (the default), `AttackerPromptBuilder`
  (`src/Audit/Infrastructure/Prompt/AttackerPromptBuilder.php`) emit the full
  skill set for every chunk, so the system-prompt prefix is byte-identical
  across chunks: the first chunk pays a cache write and every subsequent chunk
  reads the prefix at the provider's discounted cache-read rate. The trade-off
  is a larger prompt when caching is off, so the key defaults to `false`
  (relevance-only skills, the previous behaviour). Both this flag and
  `structured_collection` are folded into the attacker cache key salt, so
  toggling either invalidates cached responses produced under the other prompt
  shape instead of replaying them.
- **Reviewer verdicts are now cached across runs, skipping redundant reviewer
  LLM calls.** A new filesystem cache
  (`src/Audit/Infrastructure/Cache/FilesystemReviewerCache.php`, behind the
  Domain port `src/Audit/Domain/Port/ReviewerCacheInterface.php`) stores each
  reviewer verdict keyed by the SHA-256 of the finding's stable content (its
  `Vulnerability::toArray()` minus the non-deterministic `id`) plus the reviewed
  code context, folded behind a salt of
  `{reviewer_model}|reviewer-v{N}|prompt-v{M}`. When the attacker re-surfaces a
  finding with identical content against unchanged code — the common case on
  repeated CI/PR scans — `ReviewerAgent::review()` reuses the stored verdict
  instead of calling the LLM again. The cache reuses the existing
  `cache.enabled` switch (when `false`, a `NullReviewerCache` no-op is wired)
  and lives in a `reviewer` subdirectory alongside the attacker cache under
  `cache.dir`. The cache applies to one-finding-per-call reviews — the default,
  in the structured `record_review` mode, the JSON mode, and the concurrent
  paths (cached verdicts are served first and only the misses are dispatched);
  batched (`reviewer_batch_size > 1`) reviews always call the LLM, and
  `audit:run` prints a one-shot stderr notice when that combination is
  configured so the disabled cache is never silent. The `--no-cache` flag
  bypasses it for the run (no reads, no writes), mirroring the attacker cache. A
  reviewer-prompt change invalidates the cache automatically via
  `ReviewerPromptBuilder::PROMPT_VERSION` in the salt; a storage-format or
  verdict-contract change is invalidated by bumping
  `FilesystemReviewerCache::CACHE_VERSION`.
- **Prompt-cache tokens are now priced into the audit cost.** Providers that
  report prompt caching (Anthropic's `cache_read_input_tokens` /
  `cache_creation_input_tokens`) were previously invisible to cost accounting:
  `SymfonyAiLLMClient` only read `getPromptTokens()` / `getCompletionTokens()`,
  so cache reads and writes contributed `$0.00` to the budget tracker and the
  final `AuditCost`. The client now also reads
  `TokenUsageInterface::getCacheReadTokens()` and `getCacheCreationTokens()`,
  carries them on `LLMResponse` (new `cacheReadTokens()` /
  `cacheCreationTokens()` accessors, defaulting to `0`) and accumulates them in
  `TokenUsageRecorder` / `TokenUsageSnapshot`. `CostCalculator::costForCall()`
  prices them against the model's input rate — for Claude models at Anthropic's
  published multipliers (cache reads at `0.1x`, cache writes at `1.25x` for the
  default 5-minute cache); for any other model that reports these fields, cache
  tokens are conservatively priced at the plain input rate rather than asserting
  Anthropic's economics — so both the live budget enforcement (`BudgetTracker`)
  and the reported `estimated_cost_usd` reflect real cache spend. Runs against
  providers that do not report cache tokens are unaffected (the new counts
  default to `0`).

- **New top-level `profile` config key — one knob instead of ten.**
  `symfony_security_auditor.profile` accepts `fast`, `balanced` (default), or
  `thorough` and pre-sets the cost/speed/depth levers (`audit.max_iterations`,
  `audit.static_prescan.lean_mode`, `audit.code_slicing.enabled`,
  `audit.poc_synthesis.enabled`, `audit.reviewer_max_concurrent`) through the
  new Domain enum `src/Audit/Domain/Configuration/AuditProfile.php`. A profile
  only fills the keys you left unset — any explicitly configured key always
  wins. `fast` runs a single attacker iteration over marker-bearing files with
  code slicing and four concurrent reviewer calls; `balanced` is byte-identical
  to configuring nothing; `thorough` adds PoC synthesis. Public API per
  `docs/versioning.md`.
- **Concurrent structured reviews — `reviewer_max_concurrent` now composes with
  `record_review` instead of disabling it.** A new opt-in Domain port
  (`src/Audit/Domain/Port/ToolBatchCapableLLMClientInterface.php`) lets a client
  resolve several independent tool-using conversations concurrently;
  `SymfonyAiLLMClient` implements it as a wavefront — each round dispatches the
  next platform invocation for every still-pending conversation without
  blocking, then executes the requested tools against that conversation's own
  registry, so on an async transport the rounds overlap on the wire. A
  conversation that fails before any tool ran falls back to the proven
  sequential path; one that fails after a tool produced side effects finalizes
  as an empty response so tools never execute twice. With
  `reviewer_max_concurrent` > 1 the reviewer now reviews findings concurrently
  in the structured mode (each finding records through its own `record_review`
  tool) and only falls back to the JSON concurrent path on clients without the
  capability.
- **The attacker cache now covers iterations 2+.** Chunks carrying
  cross-iteration context (prior validated findings, reviewer-rejected findings)
  used to bypass the attacker cache entirely, so every multi-pass audit re-paid
  for those chunks even on unchanged code. A new opt-in Domain port
  (`src/Audit/Domain/Port/ContextAwareAttackerCacheInterface.php`) keys an entry
  by chunk + a SHA-256 of the rendered context preambles;
  `FilesystemAttackerCache` and `NullAttackerCache` implement it, and an empty
  context key addresses the same entry as the context-free `get()`/`store()`
  pair so existing on-disk entries stay readable. A cache that does not
  implement the port keeps the previous skip-on-context behaviour.
- **`audit:run` now surfaces configuration combinations that silently disable a
  cost saver.** The bundle computes a list of config notices at compile time
  (currently: the reviewer-verdict cache not applying when
  `audit.reviewer_batch_size > 1` while `cache.enabled` is on) and
  `AuditPresenter` prints each one to stderr before the run, alongside the
  existing secret-scrubbing warning — visible in every output format without
  polluting machine-readable stdout.

### Changed

- **The default model is now `claude-opus-4-8`.** The `model` key defaulted to
  `claude-opus-4-7`; Anthropic lists Opus 4.8 at the same `$5/$25` per-MTok
  price with higher capability, and the FAQ already recommended it — so a
  zero-config install now gets the better model at unchanged cost. Pin
  `model: 'claude-opus-4-7'` to keep the previous default.
- **Reports now list vulnerabilities most-severe-first.** `AuditReport`
  (`src/Audit/Domain/Model/AuditReport.php`) kept vulnerabilities in discovery
  order, so a lone high-severity finding could sit buried between medium and low
  ones and readers had to scroll the whole list to find it
  ([#40](https://github.com/vinceAmstoutz/symfony-security-auditor/issues/40)).
  The report now orders findings by descending `VulnerabilitySeverity::score()`
  — critical → high → medium → low → info, ties keeping discovery order — so the
  console listing, the `--format=json` `vulnerabilities` array, and the SARIF
  `results` array all lead with the most severe findings.
- **Reviewer no longer drops real-but-hard-to-prove findings.** The reviewer
  decision rules in `ReviewerPromptBuilder`
  (`src/Audit/Infrastructure/Prompt/ReviewerPromptBuilder.php`) opened with
  `Be strict: reject any finding where exploitation is not clearly demonstrated`
  — and current models follow that literally, silently discarding the very class
  of issues the auditor exists to surface (race conditions, business-logic
  flaws, context-dependent access control). The rules now invert the default:
  reject only when a specific mitigating control can be named (a guard clause, a
  parameterized query, an `access_control` rule, a framework default) or the
  pattern is absent; when the pattern is present but exploitability is
  uncertain, the reviewer accepts it with a downgraded severity (down to `info`)
  and records the missing evidence in `reviewer_notes` instead of rejecting. The
  false-positive playbook — which rejects against concrete Symfony mitigations —
  is unchanged, so precision on known-safe patterns is preserved.
- **The attacker's Route Access-Control Map now flags firewall-covered routes
  instead of mislabelling them as unprotected.** `AttackerPromptBuilder`
  (`src/Audit/Infrastructure/Prompt/AttackerPromptBuilder.php`) rendered every
  controller action with no `#[IsGranted]` / `denyAccessUnlessGranted()` as
  `LACKS_ACCESS_CHECK`, even when a `security.yaml` `access_control` rule
  already gated the route path — so the attacker flagged it as
  `broken_access_control` and the reviewer then spent tool calls (or, in batch
  mode, lacked the tools) rediscovering the firewall rule. The map now
  cross-references each route path against the `access_control` patterns already
  parsed into `SymfonyMapping::routeAccessMap()` and, on a match, tags the line
  `COVERED_BY access_control[…]` with the gating roles, telling the model the
  firewall protects it (unless the role is too permissive). This removes a whole
  class of false positive at zero extra LLM cost. The attacker `PROMPT_VERSION`
  is bumped `7` → `8`, invalidating previously cached responses.

### Fixed

- **Attacker prompt no longer contradicts itself in the default
  structured-collection mode.** `AttackerPromptBuilder::buildUserMessage()`
  (`src/Audit/Infrastructure/Prompt/AttackerPromptBuilder.php`) always closed
  the user message with `Return a JSON array of all vulnerabilities found.`,
  even when `audit.structured_collection` is enabled (the default), where the
  system prompt forbids JSON-array output and mandates `record_vulnerability`
  tool calls. The conflicting instruction could push the model to emit a stray
  JSON array that the pipeline then discards as malformed. The closing line is
  now conditional: structured mode tells the model to record findings via the
  `record_vulnerability` tool, and only the opt-out
  (`structured_collection: false`) path keeps the JSON-array wording. The
  attacker `PROMPT_VERSION` is bumped `6` → `7`, invalidating previously cached
  attacker responses so the corrected prompt takes effect.
- **Reviewer can now relabel a finding to `over_permissive_serializer_group`.**
  The `corrected_type` enum advertised to the reviewer in
  `ReviewerPromptBuilder`
  (`src/Audit/Infrastructure/Prompt/ReviewerPromptBuilder.php`) listed 39 of the
  40 `VulnerabilityType` cases — `over_permissive_serializer_group`, which the
  attacker can already emit, was missing, so the reviewer could neither correct
  a mislabelled finding to it nor recognise it as a valid type. The value is now
  listed, and a regression test asserts every `VulnerabilityType` case appears
  in both the attacker and reviewer prompts so the two enumerations cannot drift
  apart again.
- **`audit:run --dry-run` no longer undercounts tokens for Claude Fable 5 /
  Mythos 5.** `CharacterBasedTokenEstimator`
  (`src/Audit/Infrastructure/LLM/CharacterBasedTokenEstimator.php`) matched
  `claude-fable-5` and `claude-mythos-5` against the generic `claude-` prefix
  (3.5 characters per token), but those models ship a new tokenizer that emits
  roughly 30% more tokens for the same text. The estimate was therefore about a
  third too low, which flows straight into the dry-run cost figure. Two
  more-specific prefixes (`claude-fable`, `claude-mythos`) are now matched ahead
  of `claude-` with a denser 2.7-characters-per-token ratio, so the dry-run
  estimate reflects the real token count. Non-Fable Claude models are unchanged.

## [1.8.0] — 2026-06-11 — Fable

A model-coverage release. Anthropic's Claude Fable 5 — released the day before —
is now priced in the cost estimator, so `audit:run --dry-run` reports a real
figure for it instead of a misleading `$0.00`.

### Added

- **Cost estimates now cover Claude Fable 5 (`claude-fable-5`).**
  `StaticPricingProvider`
  (`src/Audit/Infrastructure/Pricing/StaticPricingProvider.php`) gained the
  entry `'claude-fable-5' => [10.00, 50.00]` (USD per million input/output
  tokens, Anthropic list price). Before this, configuring `claude-fable-5` made
  `PricingProviderInterface::hasModel()` return `false`, so a dry run estimated
  `$0.00` and logged a `No pricing entry for LLM model` warning (and, since
  1.7.2, the `AuditPresenter` stderr notice). The pricing table's source-date
  comment is bumped to `2026-06-11`. Every provider's entries (Anthropic,
  OpenAI, Google, Mistral, Cohere, DeepSeek, Perplexity, Cerebras) were
  re-verified against current published list prices on 2026-06-11; two stale
  entries were corrected (see _Fixed_ below), the rest are unchanged.

### Changed

- **`docs/faq.md` documents Claude Fable 5.** The Model Selection table gains a
  "Most demanding" row (`attacker_model: claude-fable-5` +
  `reviewer_model: claude-haiku-4-5-20251001`), and the cost table gains a
  "Claude Fable 5 only" row (≈ `$6 – $16` per run — roughly 2× Claude Opus, in
  line with the `$10/$50` vs `$5/$25` per-MTok pricing).

### Fixed

- **Corrected stale list prices for two non-Anthropic models in the cost
  estimator.** During the 2026-06-11 re-verification of every provider's pricing
  in `StaticPricingProvider`, two entries no longer matched the provider's
  published list price and were producing inaccurate `audit:run --dry-run`
  estimates:
  - `mistral-small-latest` / `mistral-small-2603`: `$0.15/$0.60` → `$0.10/$0.30`
    per million input/output tokens.
  - `deepseek-v4-pro`: `$1.74/$3.48` → `$0.435/$0.87` per million input/output
    tokens.

  All other entries across Anthropic, OpenAI, Google, Cohere, Perplexity, and
  Cerebras matched their current list prices and are unchanged.

## [1.7.2] — 2026-06-07 — Lighthouse

A dry-run transparency release. `audit:run --dry-run` no longer hides an
unsupported model behind a silent `$0.00` estimate: it now warns, on stderr,
whenever a configured model has no pricing data, so a typo or an as-yet-unpriced
model can no longer masquerade as free.

### Fixed

- **`audit:run --dry-run` now warns when a configured model has no pricing
  data.** A dry run estimates cost via `EstimateAuditCostUseCase` →
  `CostCalculator` → `StaticPricingProvider`. For a model absent from the
  provider's price table (a typo, or a model `symfony/ai` supports but the table
  does not yet list), `StaticPricingProvider` returns `0.0` and logs a
  `No pricing entry for LLM model` warning to the PSR logger only — invisible on
  the console. The dry run therefore reported `Cost : $0.0000 (estimate)` with
  no hint that the figure was unreliable, so an unsupported `model` /
  `attacker_model` / `reviewer_model` looked free. `AuditPresenter`
  (`src/Command/AuditPresenter.php`) now inspects the per-role models of the
  estimate against `PricingProviderInterface::hasModel()` and emits a stderr
  warning before the cost block:

  ```text
  No pricing data for the configured model(s): <model>. The dry-run cost
  estimate shows $0.00 for these and may be inaccurate. Check the model name(s)
  in your symfony_security_auditor configuration against the models supported by
  your symfony/ai platform.
  ```

  The warning is written to `getErrorStyle()`, so it surfaces even for
  `--format=json` / `--format=sarif` without polluting machine-readable stdout.

## [1.7.1] — 2026-06-04 — Parachute

A bare-install resilience release. Installing the bundle into a fresh Symfony
skeleton — where the `symfony/ai-bundle` recipe ships `config/packages/ai.yaml`
with every platform commented out — no longer breaks container compilation.

### Fixed

- **`cache:clear` no longer crashes when no AI platform is configured.** The
  bundle's three `SymfonyAiLLMClient` service definitions
  (`src/SymfonySecurityAuditorBundle.php`) hard-referenced
  `Symfony\AI\Platform\PlatformInterface`. On a bare skeleton the
  `symfony/ai-bundle` recipe registers no platform, so the alias never exists
  and `CheckExceptionOnInvalidReferenceBehaviorPass` aborted **every** console
  command (`cache:clear`, `cache:warmup`, recipe CI installs) with:

  ```text
  The service "security_auditor.attacker_client" has a dependency on a
  non-existent service "Symfony\AI\Platform\PlatformInterface"
  ```

  The references are now declared `nullOnInvalid()` and the client constructor
  accepts `?PlatformInterface`, so the container compiles without a platform.
  The first actual LLM call raises the new `MissingAiPlatformException` (extends
  `LLMProviderException`, so agents rethrow it instead of swallowing it into a
  false-negative SAFE report) with an actionable message:

  ```text
  No AI platform is configured. Enable a platform (e.g. "anthropic") in
  config/packages/ai.yaml and set its API key — the symfony/ai-bundle recipe
  ships with every platform commented out.
  ```

  Every other console command keeps working; only `audit:run` needs a platform.

## [1.7.0] — 2026-05-29 — Polyglot

### Fixed

- **Non-Anthropic providers no longer crash on `cache_control` / `max_tokens`.**
  `SymfonyAiLLMClient::baseOptions()` sent Anthropic-dialect options on every
  call regardless of the configured provider. The `symfony/ai` Gemini bridge
  forwards unrecognized options verbatim into `generationConfig`, so a normal
  run on a `gemini-*` model aborted with
  `Invalid JSON payload received. Unknown name "cache_control" at 'generation_config'`
  / `Unknown name "max_tokens" at 'generation_config'`. The OpenAI Responses
  bridge (which expects `max_output_tokens`) was hit by the same `max_tokens`
  leak. Provider-specific options (`max_tokens`, `response_format`) are now
  gated to Claude models; every other provider receives only `temperature` and
  uses its own native (large) output limit, so long findings are no longer
  truncated.

### Added

- **Pricing coverage for every commercial platform shipped by `symfony/ai`.**
  `StaticPricingProvider` now carries current standard-tier prices for Anthropic
  (including `claude-opus-4-8`), OpenAI (including the GPT-5 family), Google
  Gemini (including `gemini-3.1-pro-preview`), Mistral, Cohere, DeepSeek,
  Perplexity, and Cerebras — with dated-snapshot aliases where providers pin
  them. Prompt-size-tiered models (Gemini `*-pro`, GPT-5.x) are listed at their
  base tier. Self-hosted platforms (Ollama, LM Studio, Docker Model Runner,
  TransformersPHP) stay absent — they bill no per-token cost. This clears the
  `No pricing entry for LLM model — cost reporting will show zero` warning for
  current models.

### Deprecated

- **`cache.prompt_caching`** no longer has any effect and emits a deprecation
  notice when set. It previously put `cache_control: ephemeral` on every LLM
  call, but current `symfony/ai` bridges no longer read that option. Configure
  prompt caching on the platform instead: set `cache_retention` (`none` |
  `short` | `long`) on the `anthropic` platform in `ai.yaml` (default `short`
  already enables the ~90% input-token discount); OpenAI and Gemini cache
  automatically. The key stays accepted for backward compatibility until the
  next major. See [`docs/versioning.md`](docs/versioning.md).

## [1.6.4] — 2026-05-29 — Hush

A log-hygiene release. `audit:run` no longer emits a `warning` when the
attacker's structured-collection tool loop ends with empty content after at
least one tool-using iteration — that is the intended termination signal in
structured-collection mode, not an error.

### Fixed

- **`Tool-using loop ended with empty content response` no longer fires at
  `warning` level for normal-flow completions.** In structured-collection mode
  (default since 1.6.0), the attacker emits findings via `record_vulnerability`
  tool calls and is contracted to return no final prose — the empty content
  block is how the model says "I'm done."
  `SymfonyAiLLMClient::emptyToolLoopResponseAndLog()`
  (`src/Audit/Infrastructure/LLM/SymfonyAiLLMClient.php`) was logging at
  `warning` level regardless of iteration count, spamming the audit output once
  per chunk on healthy runs (typical signature:
  `iterations: 1, output_tokens: 1485, error: "Response does not contain any content."`).
  The log now routes through `debug` when at least one tool-using iteration has
  produced findings before the empty turn, and only stays at `warning` when the
  very first call returns empty (genuine anomaly — refusal, content filter, or
  provider quirk before any work was done). The message string and payload shape
  are unchanged so existing log scrapers / dashboards continue to match.
- **Cost line removed from the real-run console report.**
  `ReportRenderer::renderConsole()`
  (`src/Audit/Infrastructure/Report/ReportRenderer.php`) used to print
  `Cost    : $X.XXXX` and a per-role breakdown after every audit. The number
  comes from a static `PricingProvider` table multiplied against actual token
  usage, so it's a rough estimate that diverges from real provider invoices
  (volume discounts, contract pricing, prompt-cache rebates) and operators
  shouldn't anchor on it. The tokens line still prints (factual, model-tagged),
  and the dry-run path (`AuditPresenter::dryRunResult()`) is unchanged —
  estimating cost is its whole point. JSON and SARIF outputs still carry
  `estimated_cost_usd` for downstream parsers / dashboards.

## [1.6.3] — 2026-05-28 — Watertight

A bug-fix release closing a credential-leak gap in the secret scrubber. URIs
with embedded credentials — the canonical Symfony `DATABASE_URL` / `REDIS_URL`
shape — were sent verbatim to the LLM provider because no pattern matched them.
The scrubber now redacts connection-string credentials before any content leaves
the machine.

### Fixed

- **Connection-string credentials leaked to the LLM.** `RegexSecretScrubber`
  (`src/Audit/Infrastructure/FileSystem/RegexSecretScrubber.php`) had no pattern
  for URIs with embedded credentials, so values like
  `DATABASE_URL=postgres://user:s3cret@host` or `REDIS_URL=redis://:pass@host`
  were sent verbatim to the LLM provider — the env-assignment pattern only
  matches names ending in `_TOKEN`/`_SECRET`/`_PASSWORD`/`_KEY`/`_DSN`, never
  `_URL`. A new `connection_uri` pattern surgically redacts the `user:pass@`
  segment while preserving the scheme and host
  (`postgres://***REDACTED:connection_uri***@host`).

## [1.6.2] — 2026-05-28 — Headroom

A bug-fix release. The audit was silently truncating every LLM call at ~1000
output tokens because `symfony/ai`'s Anthropic bridge defaults `max_tokens` to
`1000` when callers don't supply one, and the bundle never did. The bundle now
sets `max_tokens` explicitly on every platform request and exposes the value as
a public configuration key.

### Fixed

- **Silent 1000-token output cap.** `SymfonyAiLLMClient::baseOptions()`
  (`src/Audit/Infrastructure/LLM/SymfonyAiLLMClient.php`) never set `max_tokens`
  on platform invocations. `symfony/ai`'s Claude bridge then applied its
  built-in `max_tokens = 1000` default, capping every attacker / reviewer /
  cheap-attacker call. In structured-collection mode this cut off
  `record_vulnerability` tool-call arguments mid-finding (severity, location,
  proof, remediation fields), inflated tool-loop iteration counts, and most
  visibly surfaced as
  `WARNING [app] Tool-using loop ended with empty content response` log lines
  with cumulative `output_tokens` clustering at ~1000 × `iterations`.
  `baseOptions()` now sets `max_tokens` from the new
  `LLMConfiguration::maxOutputTokens` / `attackerMaxOutputTokens` /
  `reviewerMaxOutputTokens` accessors so the value is bounded by bundle
  configuration rather than the upstream default.

### Added

- **`max_output_tokens` configuration key** — top-level `int`, default `4096`.
  Sets `max_tokens` on every LLM call. The new default is enough headroom for
  detailed `record_vulnerability` tool-call arguments on a typical chunk while
  staying well inside provider per-response ceilings. Public API per
  `docs/versioning.md`.
- **`attacker_max_output_tokens` / `reviewer_max_output_tokens`** — optional
  per-role overrides (`int|null`, default `null`). Fall back to
  `max_output_tokens` when null. Mirrors the existing `attacker_model` /
  `reviewer_model` split, so split-model setups can give the attacker more
  headroom for detailed findings (e.g. `8192`) while leaving the reviewer on a
  tighter cap (e.g. `2048`).

### Notes

- This release sets `max_tokens` explicitly on every request where it previously
  omitted the option. Existing audits will see longer (untruncated) completions,
  fewer tool-loop iterations per chunk, and an effectively higher output-token
  spend per call.
- When raising `max_output_tokens` substantially, consider raising
  `audit.rate_limit.output_tokens_per_minute` proportionally — see
  [`docs/configuration.md`](docs/configuration.md). With the default `4096` cap
  and an `80_000` OTPM ceiling the limiter trips after ~19 calls/min; doubling
  the cap halves that.

## [1.6.1] — 2026-05-28 — Soft Landing

A resilience release. The LLM client now treats truly empty model responses as a
graceful drop instead of a fatal abort, and the mutation gate becomes
deterministic on `AuditContext::auditId` so the test matrix stops flapping on
randomness.

### Fixed

- **Empty-content LLM responses no longer abort the audit.** Anthropic (and
  other providers) occasionally return a successful response with zero content
  blocks — refusal-style stops, content-filter hits, or quirks under heavy
  prompt-cache pressure. `symfony/ai`'s converter then throws "Response does not
  contain any content." from `DeferredResult::getResult()`. Previously that
  bubbled through `SymfonyAiLLMClient::invokeWithRetry()` →
  `TransientFailureClassifier` (no transient match) →
  `NonTransientLLMFailureException`, aborting the entire audit mid-run — most
  visibly at ~50% on a long `audit.structured_collection: true` run where the
  attacker had already recorded findings via `record_vulnerability` tool calls.
  `TransientFailureClassifier` now exposes `isEmptyContent()`; the client
  rethrows those as the new internal `EmptyLLMResponseException`, and
  `complete()` / `completeWithTools()` catch and translate into an empty
  `LLMResponse` with `stopReason: 'empty_content'`. The attacker chunk records
  as `analyzed`, the `VulnerabilityCollector` still drains any
  `record_vulnerability` calls that preceded the empty turn, and the pipeline
  continues. The retry classifier is unchanged for transport / auth / rate-limit
  failures — only the framework-level "no content blocks" signature is reclassed
  out of the non-transient path.

### Tooling

- Mutation gate now deterministically kills the `UnwrapStrToUpper` mutant on
  `AuditContext::forProject()`'s `auditId` formatting. The single-draw assertion
  let the mutant escape whenever `bin2hex(random_bytes(4))` rolled all digits
  (~2.33% per Infection run, ~19% across the 9-cell PHP × Symfony matrix) — the
  source of the matrix-cell-specific escapes recently observed on `main`. The
  test now loops 64 draws, dropping the escape probability to ~10⁻¹⁰⁴.

## [1.6.0] — 2026-05-28 — Sentinel

A correctness release. The attacker now records findings through a strict
JSON-Schema tool call validated by the provider, replacing the JSON-array parse
path as the default. Bundle-level switch keeps the legacy path available for
environments without tool-use support.

### Added

- **Schema-enforced finding collection.** New `RecordVulnerabilityTool` exposes
  a `record_vulnerability` tool with a strict JSON-Schema input mirroring the
  `Vulnerability` shape. The attacker now calls this tool once per finding
  instead of returning a JSON array; the provider validates each call against
  the schema before the agent ever sees it, making bare-string drift (`"dev"`,
  `"test"`) and wrapper-object drift (`{"vulnerabilities": [...]}`) structurally
  impossible across Anthropic, OpenAI, Mistral, and tool-capable Ollama models.
- **`audit.structured_collection` config key** — `true` by default. Set to
  `false` to fall back to the tightened JSON-array prompt path, which remains as
  the safety net for models without tool-use support. Public API per
  `docs/versioning.md`.
- **`VulnerabilityCollector` and `RecordVulnerabilityToolFactoryInterface`**
  (Application). The collector is the documented mutable context carrier the
  tool writes into; the factory is the seam Infrastructure plugs into so the
  agent can build a fresh collector + tool pair per chunk without importing
  Infrastructure types. The bundle wires `RecordVulnerabilityToolFactory`
  (Infrastructure) at the composition root.
- **Tightened JSON-array safety net.** When `audit.structured_collection` is set
  to `false`, the prompt explicitly forbids non-object array elements,
  environment-keyed wrapper objects, and bare environment-name strings — the
  failure modes that previously slipped past the parser and were silently
  dropped by `VulnerabilityFactory::fromList()`. Both paths ship in this
  release; the JSON-array path is now opt-in.

### Changed

- **Default attacker collection mechanism is now the `record_vulnerability` tool
  call.** Existing audits that did not pin `audit.structured_collection` will
  switch to the tool-call path on upgrade and benefit from provider-side schema
  validation. Behavior is preserved for opt-out users: set
  `audit.structured_collection: false` in
  `config/packages/symfony_security_auditor.yaml` to keep the JSON array path.

## [1.5.0] — 2026-05-28 — Cartographer

A visibility, hardening, and coverage release. The auditor now reports how much
LLM output it had to drop on the floor, warns operators on stderr when sensitive
content will be sent to the cloud unscrubbed, looks for over-permissive
serializer groups on entities, and parses controller routes and access-control
attributes into a graph fed to the attacker prompt. Every change is backward
compatible — no existing key, default, exit code, JSON/SARIF schema field, or
Domain port signature changed.

### Added

- **Visible hydration drops.** `VulnerabilityFactory::fromList()` now returns a
  `VulnerabilityHydrationResult` value object (vulnerabilities + drop counts
  bucketed by `VulnerabilityDropReason`: `non_array_entry`, `validation_failed`,
  `hydration_failed`). Each drop is logged with a structured `reason` code, and
  per-audit totals appear on the `Attacker agent complete` info log line under
  `total_dropped_entries` / `dropped_by_reason` — so silent loss of an LLM-
  proposed vulnerability is no longer invisible to operators.
- **`symfony/validator` constraints on hydrated findings.** The factory now
  validates raw LLM payloads against `Assert\Collection` constraints (non-blank
  `title` / `description` / `file_path`, sane length bounds on all free-text
  fields) and drops violators under the new `validation_failed` reason, with the
  structured violation messages in the log payload. Catches pathological LLM
  output (empty file paths, 100 KB descriptions) that previously slipped through
  `Vulnerability::create`'s coarser guards.
- **Secret-scrubbing pre-flight warning.** `audit:run` now emits a one-shot
  warning on **stderr** after the header when `scan.secret_scrubbing.enabled` is
  set to `false`, explaining that file contents will be sent verbatim to the
  configured LLM provider. Routing to stderr means the warning always surfaces
  (including when `--format=json|sarif` writes to stdout) without polluting the
  parseable machine-readable payload. The default (`true`) is unchanged.
- **`over_permissive_serializer_group` coverage.** New
  `VulnerabilityType::OVER_PERMISSIVE_SERIALIZER_GROUP` (category
  Symfony-Specific, OWASP A05:2021) plus a `RegexStaticPreScanner` marker for
  the PHP-attribute and annotation forms of `#[Groups(...)]` / `@Groups({...})`
  on entities. The attacker entity skill block now flags privileged fields
  (`roles`, `isAdmin`, `passwordHash`, `apiToken`) landing in write-side groups
  (`*:write`) and sensitive fields leaking via read-side groups (`*:read`,
  `public`).
- **Full route → controller → voter → form semantic graph.** Three new Domain
  ports (`ControllerAccessControlParserInterface`,
  `VoterCapabilityParserInterface`, `FormBindingParserInterface`) with AST-based
  default implementations (backed by `nikic/php-parser`):
  - `PhpParserControllerAccessControlParser` walks every controller and emits
    one `RouteAccessControl` per public action, capturing the
    `#[Route(path:, methods:)]` attribute, both class- and method-level
    `#[IsGranted(...)]`, and `denyAccessUnlessGranted()` call sites.
  - `PhpParserVoterCapabilityParser` walks every voter file and emits a
    `VoterCapability` describing the attribute strings and `instanceof` subject
    types referenced inside its `supports()` body.
  - `PhpParserFormBindingParser` walks every controller and emits one
    `FormBinding` per `$this->createForm(SomeFormType::class)` call site.

  `SymfonyMapping` gains `routeAccessControls()`,
  `controllersWithoutAccessCheck()`, `voterCapabilities()`, `votersFor()`,
  `formBindings()`, and `formBindingsForController()` accessors. `MappingStage`
  populates the graph and surfaces `mapping.routes`,
  `mapping.routes_without_access_check`, `mapping.voter_capabilities`, and
  `mapping.form_bindings` metadata on `AuditContext`. The attacker prompt now
  ships three new context blocks — `Route Access-Control Map`, `Voter Coverage`,
  and `Form Bindings` — so the LLM can cross-reference an
  `#[IsGranted('ATTR', $subject)]` against the voters that actually accept that
  attribute on that subject (a `missing_voter` finding when nothing matches),
  and cross-reference `createForm()` call sites against the form types involved
  (mass-assignment / CSRF surface).

### Changed

- `AttackerPromptBuilder::PROMPT_VERSION` bumped to **5** and
  `RegexStaticPreScanner::CACHE_VERSION` bumped to **2** so cached attacker
  responses invalidate automatically against the new prompt and pattern.
- `VulnerabilityFactory` now takes a
  `Symfony\Component\Validator\Validator\ValidatorInterface` as a constructor
  argument (autowired via a private inline factory in `config/services.php`).
  The factory is `@internal`, so this is a non-BC change for end users;
  downstream custom-agent code that constructs the factory manually must pass a
  `ValidatorInterface` (typically `Validation::createValidator()`).
- `MappingStage` now takes three optional parser arguments
  (`ControllerAccessControlParserInterface`, `VoterCapabilityParserInterface`,
  `FormBindingParserInterface`); each defaults to a no-op parser, preserving the
  previous shape. The DI wiring binds the real parsers in production.
- `nikic/php-parser ^5.3` is now a runtime dependency (previously transitive via
  `phpunit/php-code-coverage`); used by the three AST parsers.

## [1.4.0] — 2026-05-27 — Bloodhound

A detection-and-cost release. The auditor now covers the modern Symfony 7.x/8.x
attack surface, follows data flow across files, and gives operators several
opt-in levers to cut token spend. Every addition is backward compatible — new
configuration keys, new Domain ports, a new `audit:run` option, new
`VulnerabilityType` cases, and additive JSON/SARIF fields. No existing key,
default, exit code, or schema field changed meaning.

### Added

- **Symfony 7.x/8.x attack surface.** Six new file-type detectors
  (Authenticator, Messenger handler, Webhook consumer, EventSubscriber,
  Normalizer, Scheduler) each get a dedicated attacker skill block hunting
  modern failure modes: `SelfValidatingPassport` misuse, missing/`==`-based
  webhook HMAC verification, `php_serialize` Messenger transports,
  mass-assignment via Serializer denormalizers, lock-less recurring tasks, and
  Live Components leaking writable props. Existing
  controller/template/config/php blocks now also cover `#[MapRequestPayload]`,
  Twig Components/Live Components, `html_sanitizer`, mailer header injection,
  cache poisoning, `RateLimiterFactory` scope confusion, and `HttpClient`
  redirect-host bypass. Seven new `VulnerabilityType` cases back this surface:
  `missing_signature_verification`, `messenger_handler_unsafe`,
  `missing_rate_limiting`, `cache_poisoning`, `mailer_header_injection`,
  `webhook_replay`, `authenticator_bypass`.
- **Static pre-scanner** (`StaticPreScannerInterface` →
  `RegexStaticPreScanner`). A deterministic, zero-token pass tags files with ~30
  risk markers (unserialize, shell exec, `|raw`, `csrf_protection: false`,
  hardcoded secrets, Doctrine string concatenation, …) that are injected into
  the attacker prompt so the LLM focuses on concrete locations. New keys
  `audit.static_prescan.enabled` (default `true`) and
  `audit.static_prescan.lean_mode` (default `false`; drops marker-free files to
  slash token spend).
- **Custom risk patterns** (`scan.custom_risk_patterns`). Project-specific regex
  markers merged into the pre-scanner dictionary, keyed by file-type bucket.
- **Feature-based chunking** (`audit.chunking.strategy`, default `feature`).
  Groups a controller with its entity, repository, form, voter, and templates in
  one chunk so the LLM can follow cross-file data flow. `type` restores the
  legacy priority-window chunking.
- **Cross-iteration finding propagation.** Iterations 2+ receive a compact
  summary of already-validated findings so the attacker generalizes patterns to
  uncovered files instead of re-discovering the same bugs.
- **Reviewer tools** (`audit.reviewer_tools_enabled`, default `false`). The
  reviewer can use the same `read_file`/`grep`/`list_files`/`lookup_advisory`
  registry as the attacker to verify cross-file mitigations, with its own
  `audit.reviewer_max_tool_iterations` cap.
- **PoC synthesis stage** (`audit.poc_synthesis.enabled`, default `false`;
  `audit.poc_synthesis.severity_floor`, default `high`). Generates a concrete,
  copy-pasteable reproduction artifact (curl, console invocation, payload) for
  validated findings at or above the floor, exposed as the additive
  `synthesized_poc` report field.
- **Code slicing** (`audit.code_slicing.enabled`, default `false`;
  `audit.code_slicing.min_lines_before_slicing`, default `80`). Trims large PHP
  files to security-relevant lines (structure, signatures, token-bearing lines),
  eliding the rest one-for-one so line numbers stay accurate. New
  `CodeSlicerInterface` port with `RegexCodeSlicer` / `NullCodeSlicer`.
- **Diff mode** (`audit:run --since=<ref>`). Audits only files changed against a
  git ref (committed `ref...HEAD` delta plus uncommitted working-tree changes),
  for fast pull-request scans. New `GitChangedFilesResolverInterface` port with
  a `symfony/process`-based adapter.
- **Cheap→expensive escalation** (`audit.escalation.enabled`, default `false`;
  `audit.escalation.cheap_model`). A cheap-model sweep runs first; the expensive
  model only re-analyses files the sweep flagged, with the cheap findings fed in
  as context.
- **Concurrent reviewer calls** (`audit.reviewer_max_concurrent`, default `1`).
  When reviewing one finding per call with tools off, the new opt-in
  `BatchCapableLLMClientInterface` resolves reviews concurrently (real I/O
  overlap on async transports, safe sequential fallback otherwise), cutting the
  reviewer phase wall-clock.

### Changed

- `AttackerPromptBuilder` prompt bumped to version 4 (modern-Symfony skill
  blocks + expanded type list); the cache-key fold invalidates stale v3
  payloads.
- Default file chunking is now `feature` (was an internal priority-window
  scheme). Set `audit.chunking.strategy: type` to restore the previous
  behaviour.
- The attacker cache key now folds in the pre-scanner version and a hash of
  `scan.custom_risk_patterns`, so changing custom patterns invalidates stale
  entries. Empty LLM responses are now persisted as negative-cache entries.
- **File-type vocabulary is now a `ProjectFileType` enum** (Domain). The
  detector, chunk-priority ordering, pre-scanner pattern buckets, and attacker
  skill-block ordering all reference the enum instead of duplicated magic
  strings. `ProjectFile::type()` still returns the string value (no schema
  change); a new `ProjectFile::fileType()` exposes the typed case.
- **`symfony/string` and `symfony/filesystem` adopted** across the Application,
  Infrastructure, and Command layers (string manipulation and filesystem access)
  per `.claude/rules/php-classes.md`. The Domain layer intentionally stays
  dependency-free native PHP (documented carve-out). Adds `symfony/string` as a
  runtime dependency.
- **`AttackerAgent` slimmed** — `analyze()` takes an immutable
  `AttackerAnalysisRequest` value object (was five positional parameters), and
  risk-marker indexing and prompt-context rendering moved to dedicated
  `RiskMarkerIndex` and `AttackerContextPromptRenderer` collaborators.
  `AttackerAgentInterface` is `@internal`, so this is not a public API change.
- **Internal cleanup** — `FileChunker` feature/priority logic split into smaller
  predicates to cut cyclomatic complexity, and the unused `SEVERITY_FLOOR_*`
  constants on `PoCSynthesizer` (superseded by the `VulnerabilitySeverity` enum)
  were removed.

## [1.3.3] — 2026-05-26 — Mesh

### Changed

- `AttackerPromptBuilder` prompt bumped to version 3: the attacker is now
  explicitly forbidden from emitting bare strings, numbers, booleans, or `null`
  as JSON array elements, and is told to return `[]` rather than
  `["no findings"]` or any prose substitute. Audits against vulnerability-free
  projects previously logged a handful of `warning`-level
  `Skipping non-array vulnerability entry from LLM` records per run because the
  model occasionally interleaved prose entries with the expected vulnerability
  dicts. Bumping the cache-key fold prevents stale v2 payloads — which may
  already contain stray strings — from being replayed and re-triggering the
  warning on a cache hit.
- `VulnerabilityFactory` warning payload now carries an `entry_preview` field —
  the first 120 bytes of the skipped value when it is a string, `null` otherwise
  — so operators can see what the model emitted instead of a vulnerability dict
  without having to enable debug logging.

### Fixed

- `AttackerAgent::analyzeChunk()` now filters non-array entries out of the raw
  LLM payload before handing it to `AttackerCacheInterface::store()` and re-keys
  the survivors as a list. Previously, any stray string, number, or `null` from
  a chatty model was persisted to the filesystem cache as a gapped numeric-keyed
  array, and the same warning re-fired on every subsequent cache hit. Only the
  cache write path is affected; `VulnerabilityFactory::fromList()` still
  receives the full unfiltered payload so the diagnostic warning continues to
  surface model drift.

## [1.3.2] — 2026-05-26 — Sieve

### Fixed

- `VulnerabilityFactory::fromList()` now silently drops non-array entries from
  the decoded LLM payload (with a `warning`-level log carrying the offender's
  `get_debug_type`). The attacker chunk-analysis path previously assumed
  `LLMResponse::parseJson()` always returned a list of dicts; when the
  tool-using loop exhausted its iteration cap or the model emitted a malformed
  payload, scalar entries (string, int, null) interleaved with the expected
  vulnerability dicts surfaced as a `TypeError` from `fromArray()` and aborted
  the entire chunk. The guard now matches the `fromList silently drops nulls`
  contract documented in `.claude/rules/llm-seam.md`. Phpdoc on `fromArray`
  relaxed from `array<string, mixed>` to `array<array-key, mixed>` and on
  `fromList` from `list<array<string, mixed>>` to `list<mixed>` so the static
  type matches the runtime tolerance.
- `RegexSecretScrubber::scrub()` no longer redacts Symfony configuration
  indirections inside otherwise-credentialed assignments. Quoted values matching
  a Symfony parameter reference (`%env(ANTHROPIC_API_KEY)%`,
  `%env(string:DB_PASSWORD)%`, `%kernel.secret%`) or a shell-style env expansion
  (`$NAME`, `${NAME}`) are now passed through unmodified by the
  `inline_assignment` pattern, while literal secrets and the other pattern
  families (AWS, GitHub, Stripe, Slack, Google, JWT, PEM, `env_assignment`) keep
  their existing behavior. Previously, code following the recommended Symfony
  secrets workflow (`api_key: '%env(ANTHROPIC_API_KEY)%'`) was reported to the
  LLM as `api_key: '***REDACTED:inline_assignment***'`, which the attacker then
  escalated to a CRITICAL "hardcoded credential" finding — a false positive on
  the documented best practice. Implementation switched the `inline_assignment`
  arm from `preg_replace` to `preg_replace_callback` so the placeholder check
  can short-circuit per match without affecting the other patterns.
- `AttackerPromptBuilder::basePrompt()` now carries a "Tool Usage Discipline"
  section instructing the model that (1) it has a limited, finite tool-call
  budget per chunk, (2) it must stop using tools and emit the final JSON the
  moment evidence is sufficient, (3) it must emit `[]` immediately when the
  initial scan surfaces no findings rather than continuing to call tools "just
  to be thorough", and (4) any prose, reasoning, or further tool call emitted
  after the answer-decision causes the response to be discarded as malformed.
  Real-world audits were exhausting the `max_tool_iterations` budget (default
  `8`) on Read/Grep/ListFiles/LookupAdvisory calls without ever emitting a final
  answer, leaving downstream consumers with reasoning prose instead of a
  vulnerability list. `PROMPT_VERSION` bumped from `1` to `2` so the attacker
  cache key (which folds in the prompt version) invalidates previously-cached
  responses produced under the old prompt.
- `LLMResponse::parseJson()` JSON-block recovery no longer locks on the first
  `[`/`{` it sees. The new algorithm iterates every opener position outside JSON
  string literals, attempts `scanBalancedBlockFrom` + `json_decode` at each, and
  returns the first block that decodes successfully; the original
  `JsonException` is rethrown only when no candidate block decodes. Recovery is
  skipped entirely when the trimmed content is itself a single balanced block,
  preserving the depth-limit semantics of the top-level decode (which already
  attempted exactly that payload) and preventing silent acceptance of shallower
  inner sub-blocks inside malformed top-level JSON. Models that wrap their final
  answer in prose containing PHP-style array access (e.g.
  `recommendation.contents[locale]`) followed by a trailing `[]` previously had
  the answer dropped — the first `[` was extracted as `[locale]`, failed to
  decode, and the recovery never tried the actual JSON tail.
- `audit:run --dry-run` no longer shows
  `RISK LEVEL: SAFE / No validated vulnerabilities found / Audit complete` —
  output that implied a real audit had run and found nothing. Dry-run is a
  **cost estimate only**: no LLM calls, no vulnerability scan. The new output
  shows the estimated token counts and cost, followed by
  `Dry run — no LLM calls were made. This is a cost estimate only.` /
  `Dry run complete.`. For `--format=json/sarif --output=<file>` the structured
  report is still written to disk so cost data is machine-readable; the human
  summary is shown alongside. For `--format=json/sarif` piped to stdout, only
  the machine-readable output is emitted.

### Added

- `audit:run` now renders a live **console progress bar** while the pipeline
  runs. Each of the three stages (Ingestion → Mapping → Audit) advances the bar
  by one step; the stage name appears as the bar message. The bar is suppressed
  automatically for `--format=json/sarif` piped to stdout and for `--dry-run`.
  Implemented via a new `ConsoleProgressReporter` (Infrastructure) driven by the
  existing
  `pipeline.started / stage.started / stage.completed / pipeline.completed`
  events that `AuditPipeline` already emits, and wired through a new
  `ProgressReporterHolder` mutable delegate so the live `SymfonyStyle` output
  handle can be injected at invocation time without changing
  `PipelineInterface`.

### Refactored

- Removed multi-line `//` comment blocks from `src/` and `tests/` that explained
  what self-evident code does. A new `.claude/rules/no-comments.md` rule
  codifies the policy: comments signal poorly written code; fix the code
  instead.
- Replaced duplicated string literals on four hot paths with `@internal`
  backed-string enums under `Audit\Domain\Model\`: `ProgressEvent`
  (`pipeline.started` / `stage.started` / `stage.completed` /
  `pipeline.completed`) used by `AuditPipeline` and `ConsoleProgressReporter`;
  `AgentRole` (`attacker` / `reviewer`) used by `AttackerAgent`, `ReviewerAgent`
  and `EstimateAuditCostUseCase`'s by-role cost breakdown; `BuiltInStageName`
  (`ingestion` / `mapping` / `audit`) used by the three built-in
  `StageInterface::name()` returns; and `SecretPatternLabel` (`aws_access_key` /
  … / `inline_assignment`) used as the key set of
  `RegexSecretScrubber::DEFAULT_PATTERNS` and its `replacementFor()` match arm.
  Enum values stay equal to the previously hard-coded strings so every
  wire-format contract — `ProgressReporterInterface::report()`,
  `CoverageRecorderInterface::recordCoverage()`, JSON/SARIF `cost.by_role` keys,
  the `***REDACTED:<label>***` placeholder — is byte-identical; the enums are
  not exposed on any public port signature.

### Tooling

- Mutation gate now kills the five escaped mutants on the new progress-bar /
  dry-run path (`ConsoleProgressReporter::onPipelineStarted`,
  `onStageCompleted`, `onPipelineCompleted` and `AuditCommand`'s
  `estimatingSection` call + `isMachineReadableToStdout` negation). Added
  targeted unit tests pinning the `starting…` initial message, the intermediate
  `1/3` advance frame visible between `stage.completed` and the next
  `stage.started`, and the `3/3` snap-to-max forced by `finish()`; the E2E suite
  now wires the shared `ProgressReporterHolder` into both `AuditPipeline` and
  `AuditCommand` so it can assert the bar renders in `--format=console` and
  stays suppressed in `--format=json` to stdout, plus the dry-run path now
  asserts the `Estimating audit cost` section header.

## [1.3.1] — 2026-05-26 — Watertight

### Tooling

- Mutation gate now kills the `UnwrapTrim` and `ArrayOneItem` mutants escaping
  the LLM seam (`LLMResponse::parseJson()` markdown-fence stripping path). Added
  targeted unit tests that pin the trimmed payload around the JSON block and
  that the recovery path returns the decoded array (not the wrapping list) after
  stripping fences. No production code change.

## [1.3.0] — 2026-05-26 — Bonsaï

### Added

- New `scan.included_paths` configuration key (`string[]`, default
  `['src', 'config', 'templates', 'public/index.php']`) is the **sole scoping
  knob** for the audit. Only the listed project-relative directories and files
  are inspected; everything else — `vendor/`, `node_modules/`, `var/`, `tests/`,
  `migrations/`, `translations/`, `bin/`, root scripts, IDE folders, build
  artefacts, monorepo siblings — is silently skipped. Symfony Finder is invoked
  with the resolved directories as its `in()` roots so it never traverses
  outside the allow-list. If none of the entries resolve in the project root the
  scanner logs `No included paths exist in project` at `warning` level and
  returns an empty result.

### Changed

- The explicit-file leg of `ProjectFileScanner` now routes through Symfony
  Finder (`->in(dirname)->depth('== 0')->name(basename)->size('<= NKi')`)
  instead of a hand-rolled `filesize() > kb * 1024` check, so both legs of the
  scanner share a single size-comparison implementation.

### Removed

- **Breaking:** `scan.excluded_dirs` configuration key. The previous deny-list
  mechanism (hard defaults plus user-supplied exclusions) has been replaced by
  `scan.included_paths`. To prune a sub-tree inside an included path (e.g. drop
  `src/Migrations`), tighten `included_paths` to specific sub-directories:

  ```yaml
  symfony_security_auditor:
      scan:
          included_paths: ['src/Controller', 'src/Form', 'src/Voter']
  ```

- **Breaking:** the internal `HARD_EXCLUDED_DIRS` list on `ProjectFileScanner`
  and its `additionalExcludedDirs` constructor parameter are gone. With Finder
  scanning only included paths, walking into `vendor/` or `node_modules/` no
  longer happens, so the prune list is unnecessary.

### Fixed

- `scan.max_file_size_kb` now interprets the unit as kibibytes (`1024`-byte
  blocks) for both directory-scanned and explicitly-listed paths. The previous
  implementation routed the directory scan through Symfony Finder's `K` suffix
  (`1000`-byte kilobytes) while the explicit-file path used `*1024`, so files
  between `1000 * N` and `1024 * N` bytes were treated differently depending on
  which leg of the scanner saw them. Both paths now share the `Ki` suffix.
- `LLMResponse::parseJson()` now recovers from conversational prose around a
  balanced JSON block. With `audit.tools_enabled: true` (the default), the
  attacker model sometimes ignores the "Return ONLY the JSON array" prompt
  instruction and wraps its answer in commentary, which previously caused a
  whole chunk's findings to be dropped with `JsonException: Syntax error`.
- `AttackerAgent` / `ReviewerAgent` parse-failure error logs now include a
  512-byte `content_preview` of the LLM response so the actual shape of an
  unrecoverable payload is diagnosable without re-running the audit.

## [1.2.1] — 2026-05-25 — High Temperature

### Fixed

- `SymfonyAiLLMClient` now omits the `temperature` option from the platform
  invocation unless the host has explicitly configured one. Forwarding the
  default `temperature: 1.0` was rejected by reasoning-only models (notably
  GPT-5) which require the platform's own default, surfacing as a
  `temperature does not support` provider error before any chunk could be
  analyzed. The option is still forwarded verbatim when set, so existing
  configurations keep their previous behavior.

## [1.2.0] — 2026-05-25

### Added

- `audit:run --path=<subdir>` (repeatable, shortcut `-p`) restricts the scan to
  one or several project-relative subdirectories. The project root remains the
  argument (or working directory), so advisory lookups still see
  `composer.lock`. Useful for monorepos where only a single app needs to be
  audited.
- `audit:run --no-cache` bypasses the attacker cache for the run: every chunk
  hits the LLM and no cache entries are written or read. Existing cache stays on
  disk untouched.
- New `Audit\Domain\Port\ProgressReporterInterface` plus two ready-to-use
  implementations (`NullProgressReporter`, `LoggerProgressReporter`). The audit
  pipeline now emits `pipeline.started`, `stage.started`, `stage.completed`, and
  `pipeline.completed` events so hosts can render progress without polling.
  Default is `NullProgressReporter` — silent unless the host wires another
  implementation.
- `CharacterBasedTokenEstimator` now covers Mistral / Codestral, Llama
  (`llama-*`, `llama3*`, `llama4*`, `meta-llama/*`), and DeepSeek model families
  in addition to Claude / GPT (incl. `o3` / `o4`) / Gemini. The constructor
  accepts an optional `$charsPerTokenByPrefix` map so hosts can add or override
  ratios for fine-tuned or self-hosted models without subclassing.
- `AuditCost` carries an optional per-role breakdown (`byRole()`, also surfaced
  under `by_role` in `toArray()`). `EstimateAuditCostUseCase` now computes
  attacker and reviewer cost separately and populates the breakdown, so
  `audit:run --dry-run` reports show `$X for the attacker model` and
  `$Y for the reviewer model` instead of a single bundled total. The console
  template renders the breakdown automatically when present.
- New `Audit\Domain\Port\RateLimiterInterface` plus two ready-to-use
  implementations (`NullRateLimiter`, `TokenBucketRateLimiter`). Wrapped around
  every LLM call, the limiter blocks ahead of time so the audit stays inside the
  provider's per-minute quota instead of relying on reactive 429 retries. Three
  independent dimensions track requests-per-minute, input-tokens-per-minute and
  output-tokens-per-minute; each is independently nullable.
- New
  `audit.rate_limit.{requests_per_minute, input_tokens_per_minute, output_tokens_per_minute}`
  configuration keys (all `int|null`, default `null`). When every dimension is
  `null` (the default) the bundle wires `NullRateLimiter` and behavior matches
  the pre-existing retry-only path; setting any dimension wires
  `TokenBucketRateLimiter` keyed by the configured limits. Recommended starting
  point for Anthropic Tier 1 is `requests_per_minute: 50`,
  `input_tokens_per_minute: 500_000`, `output_tokens_per_minute: 80_000` on
  Opus, scaled down for Haiku/Sonnet.
- `RetryAfterHeaderParser` reads the server-issued `Retry-After` hint from
  `Symfony\AI\Platform\Exception\RateLimitExceededException::getRetryAfter()`
  (or a `retry-after: <int>` substring in the chained messages) and feeds it
  into `RetryPolicy::rateLimitDelayMs()` plus
  `RateLimiterInterface::pauseUntil()`. Chunks scheduled after a 429 share the
  freeze instead of stampeding the provider.
- `RetryPolicy::rateLimitDelayMs()` now accepts an optional
  `?int $serverHintSeconds`. When set and positive, the hint wins over the local
  exponential schedule; the result is clamped to `rateLimitMaxDelayMs` (default
  `300_000`) so a hostile provider cannot push the wait past a sane ceiling.
  `null` hints preserve the existing exponential behavior.
- README now opens with a 30-second quick-start section above the full Getting
  Started guide.

### Changed

- The attacker cache key now folds in the configured attacker model name and a
  prompt-builder version constant (`AttackerPromptBuilder::PROMPT_VERSION`).
  Switching models or bumping the prompt automatically invalidates
  previously-cached LLM responses; identical configuration across instances
  still hits the cache as before.
- `composer audit` results are now persisted to disk across runs, keyed by a
  SHA-256 of the project's `composer.lock`. Re-running the audit (CI, repeated
  `--dry-run`) reuses the cached advisory data instead of spawning composer
  again. Projects without a lockfile transparently fall back to running the
  underlying audit on every call; cache I/O failures are logged and swallowed.
- `SymfonyAiLLMClient::invokeWithRetry()` now eagerly resolves the
  `Symfony\AI\Platform\Result\DeferredResult` returned by `platform->invoke()`
  before exiting the retry block. Previously the wrapped HTTP body was read
  lazily by `asText()` / `getResult()` in `complete()` / `completeWithTools()`,
  so transient failures emitted by `symfony/http-client`'s deferred body read
  escaped the retry classifier — most visibly, `HTTP 429` responses bypassed the
  rate-limit-specific backoff. Eager resolution surfaces those failures inside
  the retry loop so backoff, retry-after hints, and budget enforcement all
  behave as documented.

### Fixed

- `audit:run` no longer crashes on the first chunk that draws a `429`. The
  combination of eager `DeferredResult` resolution plus the new rate-limit
  pipeline (`RateLimiterInterface`, server-hint backoff) means rate-limited
  responses now flow through retry + pause instead of escaping as a raw
  `\Throwable` to the agent layer.

### Tooling

- Dev dependency `phpunit/phpunit` bumped from `^11.5` to `^12.5`. PHPUnit 12
  drops the abandoned `sebastian/code-unit` and
  `sebastian/code-unit-reverse-lookup` transitives so `composer audit` no longer
  reports abandoned-package warnings on a fresh install. Supported PHP range is
  unchanged (`>=8.3`); test runner setup is otherwise compatible.
- New runtime dependency `psr/clock` (the abstract `ClockInterface` the bucket
  consumes). New dev dependency `symfony/clock` (provides `MockClock` for the
  time-driven `TokenBucketRateLimiter` tests).
- `castor.php` PHPUnit step drops the legacy `-d --min-coverage=100` PHPUnit CLI
  flag — PHPUnit 12 no longer accepts the unknown option; coverage enforcement
  is delegated to `robiningelbrecht/phpunit-coverage-tools` (already wired in
  `phpunit.dist.xml`). The Infection step now passes `-d memory_limit=1G` to
  clear the 128 MB default on the larger mutant tree.

### Notes

- All changes in this release are additive — existing public APIs (configuration
  keys, `audit:run` arguments / options / exit codes, JSON and SARIF schemas,
  Domain ports) keep their previous signatures. New optional constructor
  parameters on `AuditCost`, `AuditContext::forProject()`,
  `EstimateAuditCostUseCase`, `RunAuditUseCase::execute()`,
  `FilesystemAttackerCache`, and `SymfonyAiLLMClient` all default to their
  previous behavior.
- `ProgressReporterInterface` and `RateLimiterInterface` are Domain ports
  covered by the BC promise (see `docs/versioning.md`). For
  `ProgressReporterInterface`, host implementations should expect new event
  names to be added in `MINOR` releases (additive) but never have their payload
  schemas changed without a `MAJOR`. `TokenBucketRateLimiter` state is
  per-process: multi-process audits sharing one API key (parallel CI matrices)
  still race on the provider window — out-of-process coordination (Redis/file
  lock) can be added by implementing `RateLimiterInterface` and aliasing it in
  `config/services.yaml`.

## [1.1.1] — 2026-05-24

### Fixed

- Mutation gate now kills the `MethodCallRemoval` mutant on the
  `logReviewDecision()` call inside the rejected-finding early-return branch of
  `ReviewerAgent::applyReview()`. Existing tests covered the accepted /
  severity-elevated paths but left the rejection-path debug log unasserted, so
  removing the call escaped Infection — added a targeted unit test that
  exercises a rejected review and asserts the `'Vulnerability reviewed'` debug
  entry is emitted with `accepted => false`. No production code change.

## [1.1.0] — 2026-05-24

### Added

- `Vulnerability::withCorrectedType()` — copy-on-write reclassification when the
  reviewer determines the attacker mislabelled the finding's type. The original
  `id` is preserved so downstream consumers can still correlate the corrected
  record with its pre-correction source.
- Reviewer prompt accepts a `corrected_type` field (nullable string) per
  finding; `ReviewerAgent` parses it, validates against `VulnerabilityType`, and
  applies it via `withCorrectedType()`. Invalid values are logged and ignored —
  original type is preserved.
- New configuration key `symfony_security_auditor.provider_json_mode` (boolean,
  default `false`). When `true`, every LLM call carries
  `response_format: {type: json_object}` to the underlying provider — honored by
  OpenAI / Mistral / Ollama (provider-enforced JSON output), silently ignored by
  Anthropic and any provider without an equivalent knob. The prompt contract
  (_"Return ONLY the JSON array"_) remains authoritative; this is a
  belt-and-braces opt-in for providers that support it.

### Changed

- Prompt builders restructured for accuracy: source files are now wrapped as
  `<file path="…" type="…">…</file>` with each line prefixed by its line number
  in the form `` `NNN | ` ``. The attacker prompt instructs the model to use
  those exact line numbers for `line_start` / `line_end` instead of counting
  manually. Skill blocks switched from `### Heading` to
  `<skills role="…">…</skills>` form and are emitted in attack-surface priority
  order rather than alphabetically.
- Attacker base prompt now includes a severity rubric, a confidence rubric (with
  a hard `< 0.6` filter threshold), a single canonical few-shot example with
  concrete line numbers, and an explicit scope exclusion for `vendor/`,
  `var/cache/`, `var/log/`, `.generated.*`, and `.cache.*` paths.
- Each per-artifact skill block now lists both attack patterns to hunt and
  patterns explicitly NOT to flag — reduces false positives from the attacker
  agent before the reviewer ever sees them.
- Reviewer prompts (single and batch) now share a common core-instructions block
  to prevent drift, include the same severity rubric as the attacker, and embed
  a Symfony-specific false-positive playbook (Doctrine `setParameter()`, default
  CSRF, `mapped: false` form fields, hardcoded-argv `Process` invocations,
  `_profiler` gated by `when@dev`, etc.). Batch mode no longer requires findings
  to be returned in input order — entries are re-keyed by `id` on parse.

---

## [1.0.0] — 2026-05-24

First stable release.

### Added

#### Core audit pipeline

- **Multi-agent security audit pipeline**: Ingestion → Mapping → Audit, driven
  by an adversarial **Attacker** agent and a skeptical **Reviewer** agent (up to
  3 iterations; stops early when no new findings emerge).
- **Provider-agnostic LLM backend** via
  [`symfony/ai`](https://symfony.com/doc/current/ai/index.html): works out of
  the box with Anthropic (Claude), OpenAI, Azure OpenAI, Google Gemini, Google
  Vertex AI, AWS Bedrock, DeepSeek, Mistral, Meta (Llama), and Ollama (local).
  Swapping providers requires only `config/packages/ai.yaml` changes.
- **32 vulnerability types** across 6 OWASP-aligned categories: Injection,
  Broken Access Control, Logic Flaws, Symfony-specific, Data Exposure,
  Cryptographic.
- **Split-model support** — pair a larger model for attack discovery with a
  faster, cheaper model for review (e.g. `attacker_model: claude-opus-4-7` +
  `reviewer_model: claude-haiku-4-5-20251001`).

#### `audit:run` console command

- Three output formats: `console` (human-readable), `json` (machine-readable),
  `sarif` (SARIF 2.1.0 for GitHub Code Scanning and GitLab Security Dashboard).
- `--output` option writes JSON or SARIF to a file path.
- `--dry-run` flag estimates token usage and cost without invoking the LLM.
  Exits `0` with zero findings and a populated `cost` block.
- Exit codes: `0` audit complete (SAFE/LOW/MEDIUM/HIGH), `1` CRITICAL risk or
  invalid project path, `2` token or cost budget exceeded (partial report
  emitted).

#### Token & cost tracking

- Real token usage (input, output, cached tokens) recorded from platform
  response metadata on every LLM call.
- `AuditReport` carries a `cost` block: total tokens and estimated USD cost.
- Character-based token estimator (`CharacterBasedTokenEstimator`) using
  `mb_strlen` for correct multibyte handling on providers without token counts.

#### Budget cap

- Hard token and cost budget enforced via `audit.budget.max_tokens` and
  `audit.budget.max_cost_usd`. Audit aborts cleanly with exit code `2` and emits
  a partial report when either limit is exceeded. Both default to `null`
  (unlimited).

#### Resilience — retry with exponential backoff

- Jittered exponential backoff around every LLM call. Transient errors (HTTP
  429, 5xx, network blips) are retried; non-transient errors (auth, validation)
  fail fast. Configurable: `audit.retry.max_attempts` (3),
  `audit.retry.initial_delay_ms` (500), `audit.retry.backoff_multiplier` (2.0),
  `audit.retry.jitter_ratio` (0.2).

#### Security — credential scrubbing

- Credential-shaped strings (AWS/GitHub/Stripe/Slack/Google API keys, JWTs, PEM
  private keys, env-style assignments) are redacted from file content before
  reaching any LLM provider. Enabled by default
  (`scan.secret_scrubbing.enabled: true`); extensible via
  `scan.secret_scrubbing.additional_patterns`.

#### Attacker tools

- `read_file`, `grep`, `list_files` — cross-file investigation tools.
- `lookup_advisory` — live CVE feed via `composer audit --format=json --locked`.
  Degrades gracefully (empty database + `warning` log) when `composer` or
  `composer.lock` is absent.

#### Caching

- Content-hash filesystem cache for attacker chunks (`cache.enabled: true`);
  skips the LLM call entirely when an identical chunk was analyzed before.
- Provider-side prompt caching via `cache_control: ephemeral`
  (`cache.prompt_caching: true`); honored by Anthropic (~90% input-token
  discount), silently ignored by others.

#### Bundle configuration

- Typed Configuration value objects for all bundle settings (replaces raw array
  access throughout the bundle).
- Full YAML configuration surface under `symfony_security_auditor:`:
  - `model` / `attacker_model` / `reviewer_model`
  - `scan.*`: `excluded_dirs`, `respect_gitignore`, `max_file_size_kb`,
    `secret_scrubbing.*`
  - `audit.*`: `max_iterations`, `min_confidence`, `reviewer_batch_size`,
    `tools_enabled`, `max_tool_iterations`, `budget.*`, `retry.*`
  - `cache.*`: `enabled`, `dir`, `prompt_caching`

#### Architecture

- Strict DDD layering: `Command → Application → Domain ← Infrastructure`.
  `LLMClientInterface` is the sole seam between Application and `symfony/ai`; no
  agent imports any `symfony/ai` type directly.
- Domain ports (`LLMClientInterface`, `AttackerCacheInterface`,
  `ProjectFileScannerInterface`, `*PromptBuilderInterface`, `Tool/*`) live in
  `src/Audit/Domain/Port/`.
- All non-extension-point classes tagged `@internal`.

#### Extension points

`LLMClientInterface`, `AdvisoryDatabaseInterface`,
`AttackerPromptBuilderInterface`, `ReviewerPromptBuilderInterface`,
`ProjectFileScannerInterface`, `AttackerCacheInterface`, `ToolInterface`,
`PipelineInterface`, `StageInterface`. See
[`docs/extending.md`](docs/extending.md).

#### Documentation

- [`docs/architecture.md`](docs/architecture.md) — layer overview, data flow,
  domain model, extension points.
- [`docs/configuration.md`](docs/configuration.md) — full bundle configuration
  reference.
- [`docs/extending.md`](docs/extending.md) — how to plug in custom advisory
  sources, tools, prompt builders, and pipeline stages.
- [`docs/ci.md`](docs/ci.md) — CI pipeline documentation (PHP matrix, Infection,
  PHPStan max).
- [`docs/diagrams.md`](docs/diagrams.md) — architecture and data-flow diagrams.
- [`docs/faq.md`](docs/faq.md) — cost, accuracy, model selection, privacy,
  comparisons.
- [`docs/troubleshooting.md`](docs/troubleshooting.md) — empty reports, LLM
  errors, advisory issues, cache, CI failures.
- [`docs/versioning.md`](docs/versioning.md) — semantic versioning policy and
  public API surface.

### Changed

- `AdvisoryDatabaseInterface` moved from `Audit\Infrastructure\Advisory\` to
  `Audit\Domain\Port\`. The interface is a public extension point, so its
  canonical home is the Domain port namespace alongside `LLMClientInterface`,
  `AttackerCacheInterface`, etc. Host applications aliasing the interface in
  `config/services.yaml` must update the FQCN; concrete implementations
  (`ComposerAuditAdvisoryDatabase`, `InMemoryAdvisoryDatabase`) keep their
  existing FQCNs in `Infrastructure\`.
- Default model updated from `claude-opus-4-5` (retired) to `claude-opus-4-7`.
- Default reviewer model updated from `claude-haiku-4-5` (retired) to
  `claude-haiku-4-5-20251001`.
- **Pricing table corrected**: Anthropic Claude 4 Opus prices were set to the
  Claude 3 Opus rate (`$15.00 / $75.00` per MTok) — corrected to the actual
  Claude 4 Opus rate (`$5.00 / $25.00` per MTok input/output). Haiku and Sonnet
  entries unchanged. Existing cost estimates in CI reports will recalculate at
  the correct rate once updated.
- Pricing table extended with additional current and legacy model entries:
  `claude-opus-4-7`, `claude-sonnet-4-6`, `claude-haiku-4-5-20251001`,
  `claude-opus-4-6`, `claude-opus-4-1`, `claude-opus-4` (deprecated alias),
  `claude-sonnet-4` (deprecated alias), `gpt-4.1`, `o3`, `o4-mini`,
  `gemini-2.0-flash`, `mistral-large`. Legacy `claude-opus-4-5` /
  `claude-haiku-4-5` entries retained for cost reporting on existing
  configurations.

### Fixed

- Budget exceptions now rethrown from `AttackerAgent` so abort propagates to the
  pipeline and triggers exit code `2`.
- SARIF `tool.driver.version` previously hardcoded; now resolved from installed
  Composer metadata at runtime.
- `RegexSecretScrubber` replaced `set_error_handler`/`try-finally` around PCRE
  calls with a leading `@` suppressor — eliminates `UnwrapFinally`/`TrueValue`
  mutation escapes and removes dead early-return path.
- Non-transient LLM failures (missing platform configuration, auth errors,
  retired model names) now abort the audit with exit code `1` and a clear error
  message instead of silently producing a false-negative SAFE result. Introduced
  `Audit\Domain\Exception\LLMProviderException` as the catchable Domain type;
  `AttackerAgent` and `ReviewerAgent` rethrow it rather than swallowing it.

### Compatibility

| Axis                | Requirement      |
| ------------------- | ---------------- |
| PHP                 | `^8.3`           |
| Symfony             | `^7.4 \|\| ^8.0` |
| `symfony/ai-bundle` | `^0.9`           |

CI test matrix: PHP 8.3 / 8.4 / 8.5 × Symfony 7.4 / 8.0 / 8.1.

### Notes

- Default model is `claude-opus-4-7`. Change via `model:`, `attacker_model:`, or
  `reviewer_model:`.
- Register bundle in `dev` and `test` environments only (per
  `config/bundles.php` guidance in the README).

[1.12.0]:
  https://github.com/vinceAmstoutz/symfony-security-auditor/releases/tag/1.12.0
[1.11.0]:
  https://github.com/vinceAmstoutz/symfony-security-auditor/releases/tag/1.11.0
[1.10.1]:
  https://github.com/vinceAmstoutz/symfony-security-auditor/releases/tag/1.10.1
[1.10.0]:
  https://github.com/vinceAmstoutz/symfony-security-auditor/releases/tag/1.10.0
[1.9.0]:
  https://github.com/vinceAmstoutz/symfony-security-auditor/releases/tag/1.9.0
[1.8.0]:
  https://github.com/vinceAmstoutz/symfony-security-auditor/releases/tag/1.8.0
[1.7.2]:
  https://github.com/vinceAmstoutz/symfony-security-auditor/releases/tag/1.7.2
[1.7.1]:
  https://github.com/vinceAmstoutz/symfony-security-auditor/releases/tag/1.7.1
[1.7.0]:
  https://github.com/vinceAmstoutz/symfony-security-auditor/releases/tag/1.7.0
[1.6.4]:
  https://github.com/vinceAmstoutz/symfony-security-auditor/releases/tag/1.6.4
[1.6.3]:
  https://github.com/vinceAmstoutz/symfony-security-auditor/releases/tag/1.6.3
[1.6.2]:
  https://github.com/vinceAmstoutz/symfony-security-auditor/releases/tag/1.6.2
[1.6.1]:
  https://github.com/vinceAmstoutz/symfony-security-auditor/releases/tag/1.6.1
[1.6.0]:
  https://github.com/vinceAmstoutz/symfony-security-auditor/releases/tag/1.6.0
[1.5.0]:
  https://github.com/vinceAmstoutz/symfony-security-auditor/releases/tag/1.5.0
[1.4.0]:
  https://github.com/vinceAmstoutz/symfony-security-auditor/releases/tag/1.4.0
[1.3.3]:
  https://github.com/vinceAmstoutz/symfony-security-auditor/releases/tag/1.3.3
[1.3.2]:
  https://github.com/vinceAmstoutz/symfony-security-auditor/releases/tag/1.3.2
[1.3.1]:
  https://github.com/vinceAmstoutz/symfony-security-auditor/releases/tag/1.3.1
[1.3.0]:
  https://github.com/vinceAmstoutz/symfony-security-auditor/releases/tag/1.3.0
[1.2.1]:
  https://github.com/vinceAmstoutz/symfony-security-auditor/releases/tag/1.2.1
[1.2.0]:
  https://github.com/vinceAmstoutz/symfony-security-auditor/releases/tag/1.2.0
[1.1.1]:
  https://github.com/vinceAmstoutz/symfony-security-auditor/releases/tag/1.1.1
[1.1.0]:
  https://github.com/vinceAmstoutz/symfony-security-auditor/releases/tag/1.1.0
[1.0.0]:
  https://github.com/vinceAmstoutz/symfony-security-auditor/releases/tag/1.0.0
