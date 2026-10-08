# CLAUDE.md

## Keeping This File Up to Date

Update the relevant section in the same commit/PR whenever the project evolves. Rules scoped to specific paths live in `.claude/rules/` — update them too. Never leave this file describing a state that no longer exists.

---

## Project Overview

**symfony-security-auditor** — AI-powered multi-agent security auditor for Symfony applications. Distributed as a **Symfony bundle** (`symfony-bundle` package type). Uses a dual-agent attacker/reviewer loop backed by `symfony/ai` to detect vulnerabilities and produce structured reports.

> Always check `composer.json` for authoritative dependency versions — never rely on version numbers written here.

## Tech Stack

| Layer | Technology |
| --- | --- |
| Language | PHP (see `composer.json` → `require.php`) |
| Framework | Symfony (see `composer.json`) |
| LLM | symfony/ai (provider-agnostic: Anthropic, OpenAI, Mistral, Ollama, …) |
| Packaging | symfony-bundle + Flex recipe; standalone self-contained native binary (`box` + `static-php-cli` micro) for Linux/macOS/Windows |
| Tests | PHPUnit (Unit / Integration / EndToEnd); 100% line coverage enforced via the custom `MinimumLineCoverageExtension` (`tools/PHPUnit/`); the report-only `ergebnis/phpunit-slow-test-detector` surfaces tests over its `maximum-duration` (500 ms), and `SlowTestGuardExtension` (`tools/PHPUnit/`) derives its gate from that same threshold — read straight from the detector's config, single source of truth — multiplying it by `GUARD_HEADROOM_FACTOR` (3, i.e. 1500 ms) before failing the run, because one wall-clock sample on a shared CI runner can push a 3 ms test past a 500 ms bar; the report still surfaces everything over 500 ms and per-test `#[MaximumDuration]` overrides replace the bar outright — which is why overrides only ever _raise_ it (every one in the suite is 4000 or 8000 ms): an override below the shared bar opts that test out of the headroom and turns one unlucky wall-clock sample into a red build |
| Mutation | Infection (100% MSI required); `infection.json5` sets `testFrameworkOptions: "--no-extensions"` because Infection decides kill-vs-escape by parsing PHPUnit's stdout, and `ergebnis/phpunit-agent-reporter` replaces that stdout with a JSON report whenever it detects a coding-agent environment variable (`CLAUDECODE`, `AI_AGENT`, `CURSOR_AGENT`, …) — Infection then reads every mutant as killed and reports 100% MSI unconditionally, so a run inside an agent session silently proves nothing. `--no-extensions` also keeps the coverage and slow-test gates out of per-mutant runs, where they never belonged |
| Static analysis | PHPStan max + phpstan-strict-rules + custom rules (`FinalRule`, `MaxParameterCountRule`, `NoEmptyCatchRule`, `NoSilencingErrorHandlerRule`, `ForbiddenTestAttributeRule`, `SprintfOverConcatRule` — in `tools/PHPStan/`) + spaze rules + hand-picked symplify rules (`composer.json` keeps `symplify/phpstan-rules` out of `phpstan/extension-installer`, which from 14.14 would register every symplify rule set; `phpstan.dist.neon` includes only its `services.neon` and lists each rule) + Rector |
| Layer conformance | deptrac (DDD layer rules + the `SymfonyProfile` framework boundary — `deptrac.yaml`) |
| Complexity | tomasvotruba/cognitive-complexity (function ≤ 7, class ≤ 40) |
| Dead code | rector/swiss-knife (`check-commented-code`, `check-conflicts`) |
| Style | PHP CS Fixer (@PER-CS3x0, @Symfony rulesets); Prettier for Markdown, one line per paragraph and list item, never hard-wrapped (`proseWrap: never`, checked by the Prettier Check job) |
| CI/CD security | zizmor (static analysis for GitHub Actions — scans `.github/workflows/` + `action.yml`) |

## Build, Test & Lint Commands

```bash
bin/castor up
```

| Task | Command |
| --- | --- |
| Install dependencies | `bin/castor up` (runs `docker compose up --wait`) |
| Stop containers | `bin/castor down` |
| Lint (check only) | `bin/castor lint` |
| Lint + auto-fix | `bin/castor lint:fix` |
| Markdown check only | `bin/castor lint:docs` (fast pre-push check) |
| Run PHP tests | `docker compose exec php vendor/bin/phpunit` |
| Run mutation tests | `bin/castor lint` (its Infection step mirrors CI's flags — see below) |
| Score detection quality | `bin/castor eval` (audits a ground-truth fixture, reports precision/recall) |
| Symfony console | `docker compose exec php bin/console <command>` |

`bin/castor lint` runs sequentially: Prettier (check) → Markdown lint (markdownlint-cli2) → Composer Normalize → PHP CS Fixer → Rector → PHPStan (max, 500M) → Deptrac (DDD layers) → Swiss Knife (commented-code + merge-conflict scan) → Install script tests (`tests/Shell/install_script_test.sh`) → Pull request check tests (`tests/Shell/pull_request_check_test.sh`) → PHPUnit → Infection. `bin/castor lint:fix` auto-fixes steps 1–3 (Prettier, Markdown lint, Composer Normalize); the remaining steps are check-only.

Run Infection **through `bin/castor lint`**, never as a bare `bin/infection`. The task's PHPUnit step emits the `--coverage-clover`/`--coverage-xml`/`--log-junit` set that its Infection step then reuses via `--coverage=build/coverage --skip-initial-tests --min-msi=100 --min-covered-msi=100`, matching `.github/workflows/ci.yaml`; invoking `bin/infection` with ad-hoc flags has twice reported a green 100% MSI on a commit CI then rejected. Note that a single green run is still not proof of CI parity: Infection rewrites `phpunit.dist.xml` to force `executionOrder="defects,random"` while disabling result caching, so test order is effectively random per invocation — see #275.

Commit messages are validated separately in CI via [commitlint](https://commitlint.js.org/) (`commitlint.config.mjs`) — see [Commit Messages](#commit-messages).

## Project Structure

```text
src/
  Audit/
    Domain/          # Pure PHP — no framework, no I/O
      Configuration/ # Typed config VOs (BundleConfiguration, AuditProfile, LLMConfiguration, PrivacyConfiguration, CustomAttackerSkill, …)
      Model/         # Value objects and enums (Vulnerability [+ `of()` factory + CodeLocation/VulnerabilityClassification/VulnerabilityNarrative], SymfonyMapping [+ `of()` + ProjectFileInventory/AccessControlMap], AuditReport [+ ReportIdentity (which marks a dry run's cost estimate); `unanalyzedFiles()`/`isComplete()` read the coverage ledger through UnanalyzedFiles — the attacker's last status per file, any other stage's failure — which ReportFindingsLoader reuses for `audit:diff`/`audit:trend`], ExecutiveSummary (stakeholder view: risk level + severity/type/file distributions), ProjectFile, ProjectFileType [+ `archetype()`], SurfaceArchetype (framework-neutral file shape), FrameworkVocabulary (framework name/template language/idiomatic fixes for the synthesizer prompts), ProjectFileTypeClassifier (+ ProjectFileContentSignatures: what a PHP file's source declares), CvssEstimate (heuristic CVSS v4.0 per finding), RouteAccessControl, VoterCapability, FormBinding, TokenUsageSnapshot, VulnerabilityHydrationResult, VulnerabilityDropReason, ReviewerFeedback/AcceptedFindingFeedback, UnanalyzedFiles/AnalyzedFiles (what a coverage ledger says was or was not analyzed), …) — public factories use `of()`; the wide `create()` is `@deprecated`
      Exception/     # Domain exceptions (LLMProviderException [+ LLMRequestTooLargeException, the one subclass an agent recovers from: the chunk is split, the run goes on; LLMFixedPromptTooLargeException when even a small single file is refused, so the prompt's fixed part is what does not fit and the run stops], GitChangedFilesUnavailableException, InvalidCodeLocationException, InvalidVulnerabilityClassificationException)
      Pipeline/      # PipelineInterface, StageInterface, CoverageRecorderInterface (ports) + RejectedFindingRecorderInterface + FailureReasonRecorderInterface (opt-in companions of CoverageRecorderInterface, `@internal`: the rejected findings the reviewer reached a verdict on, and why an attacker chunk ended errored)
      Port/          # Cross-layer ports (LLMClientInterface, BatchCapableLLMClientInterface, ToolBatchCapableLLMClientInterface, LLMResponse [+ `isDegraded()` — an answer cut short by the token limit, a content filter, the tool-loop cap, no content or a request the model could not take in is never cached or counted as a verdict; `isRequestTooLarge()` — the `request_too_large` answer a batch client gives per request where a single call throws `LLMRequestTooLargeException`, so the caller can split the work; `parseJson()` reads the answer through LLMAnswerJsonDecoder, which finds the blocks of a text with BalancedBlockScanner], *PromptBuilderInterface, ProjectFileScannerInterface [+ opt-in ScopedProjectFileScannerInterface: scans the `--path` values in place of the configured `scan.included_paths`], AttackerCacheInterface, ContextAwareAttackerCacheInterface, ReviewerCacheInterface, AdvisoryDatabaseInterface, SecretScrubberInterface, TokenEstimatorInterface, PricingProviderInterface (+ opt-in CacheAwarePricingProviderInterface, ServingPlatformPricingProviderInterface), RateLimiterInterface, ProgressReporterInterface, StaticPreScannerInterface, CodeSlicerInterface, ControllerAccessControlParserInterface, VoterCapabilityParserInterface, FormBindingParserInterface, SecurityConfigParserInterface [+ opt-in ProductionAwareSecurityConfigParserInterface: which config files the production kernel loads], GitChangedFilesResolverInterface, ReviewerFeedbackProviderInterface, AttackerSkillPromptRendererInterface) + null-object port defaults (NullStaticPreScanner, NullReviewerFeedbackProvider, NullCodeSlicer, NullControllerAccessControlParser, NullVoterCapabilityParser, NullFormBindingParser, NullSecurityConfigParser, NullProgressReporter — all `@internal`)
        Tool/        # ToolInterface, RecordingToolInterface (marker: a tool that records the model's answer — a last tool round that calls one concludes the conversation), ToolDefinition, ToolRegistry, ToolRegistryFactoryInterface
    Application/     # Orchestration — no I/O, depends only on Domain
      UseCase/       # RunAuditUseCase, EstimateAuditCostUseCase (entry points)
      Scan/          # ScanPathFilter (narrows a file list to paths), ScopedScan (the files a run covers: the `--path` values replace the configured scan surface when the scanner can take them, else narrow its result)
      Pipeline/      # AuditPipeline + Stage/{IngestionStage, MappingStage, DependencyExpansionStage, AuditStage, PoCSynthesisStage, FixSynthesisStage}
      Agent/         # AttackerAgent (+ AttackerLlmCollaborators, AttackerScanCollaborators, AttackerAnalysisSettings, AttackerAnalysisRequest, RiskMarkerIndex, AttackerContextPromptRenderer, Chunk/{ChunkContext, ChunkContextFactory, AttackerChunkCache, ChunkCoverageRecorder, ChunkOutcomeRecorder (settles an answered chunk: `analyzed` and cached, or `errored` and left out of the cache when an entry of the answer could not be read as a finding), ChunkFindingProgress, ChunkCompletionContext (the `attacker.chunk.completed` event's context, with the `reason` of an errored chunk), ChunkFailureReason (names that reason in words a person can act on), SequentialChunkAnalyzer, ConcurrentChunkAnalyzer, OversizedChunkRecovery (splits a chunk the model cannot fit in two, records a single oversized file as errored, and once every half is analyzed caches the whole chunk under its own key so it is not re-sent next run), ChunkAnalysisScope, StructuredVulnerabilityCollectionSession}), ReviewerAgent (+ ReviewerAgentCollaborators, ReviewerModeConfiguration, Review/{VerdictApplier, BatchVerdictApplier, OversizedReviewBatchRecovery (splits a review batch the model cannot fit in two, records a lone finding that still does not fit as errored), ReviewOutcomeRecorder, ReviewerVerdictCache, CodeContextResolver, SequentialReviewAnalyzer, StructuredReviewAnalyzer, ConcurrentReviewAnalyzer, ConcurrentStructuredReviewAnalyzer, BatchReviewAnalyzer, ReviewBatchSettings, ReviewCacheBuckets, CachePartition, ConcurrentReviewBatch, StructuredReviewCollectionSession}), EscalatingAttackerAgent (+ StatusTrackingCoverageRecorder — which files the deep pass judged, so its silence on a cheap finding is a discard; EchoedFilePath — names a finding by the chunk file its echoed path denotes, whether the model spelled it absolute, with a leading `/` or `./`, or with backslashes), so its silence on a cheap finding is a discard; EchoedFilePath — the `./` a model may prepend to a path), AuditOrchestrator (+ AuditLoopSettings, FindingPrecedence — which of two findings that collapse is kept: validated, then higher severity, then higher confidence, else the earlier), so its silence on a cheap finding is a discard, and why a file ended errored; EchoedFilePath — the `./` a model may prepend to a path), AuditOrchestrator (+ AuditLoopSettings), VulnerabilityFactory, VulnerabilityCollector, RecordVulnerabilityToolFactoryInterface, ReviewCollector, RecordReviewToolFactoryInterface, PoCSynthesizer, FixSynthesizer, Chunking/{ChunkingStrategy, FileChunker}
    Infrastructure/  # I/O adapters
      LLM/           # SymfonyAiLLMClient (ctor takes PlatformBinding + PlatformRequestConfig + PlatformResilienceConfig + PlatformAccountingConfig; builds RetryingPlatformInvoker, SequentialToolLoop, BatchWindowResolver, ToolConversationWavefront, InFlightRequestCanceller (cancels and books a request a failed window leaves in flight, for both windows), FinalRound (the notice, carried by the tool result before it, that a tool conversation's last allowed round is its last, and whether a round that recorded concluded it — both tool loops apply it, so a chunk that explored up to `audit.max_tool_iterations` records what it holds instead of failing), DispatchedRequest (a batch window's dispatched request with its estimated input tokens), DegradedAnswerBooker (books every failed call the provider answered — a degraded answer or a malformed tool call — at the usage it reported, else at its estimated input tokens), ToolIterationBooker (books each answered tool round's usage on the rate-limit window and the budget, for both tool paths), ConversionFailureExplainer (reads the raw answer of a failed conversion for what the bridge's exception lost: Azure's HTTP 400 `content_filter`, a tool call the output limit cut off, or a gateway's HTTP 413), PlatformResultExtractor, PlatformOptionsFactory, PlatformToolsMapper, PromptTokenEstimator), RetryPolicy (+ BackoffSchedule, RateLimitBackoff, Exception/InvalidRetryConfigurationException), TransientFailureClassifier, TokenEstimator/{ProviderTokenEstimatorInterface, ResolvingTokenEstimator, CharacterRatioCounter, AnthropicTokenEstimator, OpenAiTokenEstimator, GeminiTokenEstimator, MistralTokenEstimator, LlamaTokenEstimator, DeepSeekTokenEstimator, MiniMaxTokenEstimator}, Delay/, RateLimit/{NullRateLimiter, TokenBucketRateLimiter, RetryAfterHeaderParser}
      FileSystem/    # ProjectFileScanner (returns files in relative-path order, each once; `scanWithin()` scans the `--path` values in place of `scan.included_paths`), RegexSecretScrubber (a file it cannot evaluate comes back as the `unscannable` placeholder, which `ProjectFile::isWithheld()` recognizes and `IngestionStage` records as `errored`), NullSecretScrubber, SymlinkGuard (refuses a symlink on the file, its directory or any directory between a trusted root and the file — the working directory and the audited project root for the report/baseline writers, the configured `cache.dir` for the filesystem caches)
      Scan/          # RegexStaticPreScanner, SarifImportingPreScanner (merges scan.import_sarif SARIF results as risk markers), RegexCodeSlicer, PhpParserControllerAccessControlParser, PhpParserVoterCapabilityParser, PhpParserFormBindingParser (all three ask NestingDepthGuard first, which skips and warns about a file whose brackets nest more than 200 levels, since php-parser exhausts memory or crashes on it), SymfonyYamlSecurityConfigParser
      Diff/          # ProcessGitChangedFilesResolver (git diff for --since)
      Prompt/        # AttackerPromptBuilder (+ SymfonyMappingContextRenderer [+ AccessControlRuleMatcher: which `access_control` rule governs a route], NumberedFileContextRenderer, Skill/{AttackerSkillInterface, AttackerSkillRegistry, one *AttackerSkill per attack surface, ConfiguredAttackerSkill for config-driven audit.custom_skills}), ReviewerPromptBuilder (+ Reviewer/{ReviewerPromptSectionsInterface, ReviewerPromptSections, ReviewerMessageRendererInterface, ReviewerMessageRenderer, ReviewerFeedbackHolder})
      Cache/         # FilesystemAttackerCache, NullAttackerCache, FilesystemReviewerCache, NullReviewerCache
      Advisory/      # ComposerAuditAdvisoryDatabase (default; also reads Composer's ignored-advisories, so the audited project's config.audit.ignore cannot hide an advisory) + LockfileHashedAdvisoryCache (TTL-bounded lockfile-hash cache in front of it, wired when cache.enabled; stores only a payload AdvisoryPayload accepts, the shape the database reads), LockfileHasher (the `composer.lock` hash both key on; refuses a symlinked lockfile or one over 8 MiB), DeferredAdvisoryDatabase (lazy wrapper; memoizes per path and lockfile hash, never a failed load), InMemoryAdvisoryDatabase (fallback), ComposerAuditRunnerInterface + SymfonyProcessComposerAuditRunner
      Pricing/       # ModelsDevPricingProvider (default; prices from the serving platform's listing first, bills a reported model only when that platform prices it, memoizes each model's price, reads the packaged catalog when a refreshed one is unusable), ModelsDevCatalog (what a catalog must hold to price a call — an `input` rate and finite, non-negative rates — shared with the catalog refresher), PlatformCatalogProviders (symfony/ai platform → models.dev provider key, + the Bedrock bridge's id forms), ModelPrice
      Progress/      # ConsoleProgressReporter (decorated TTY), PlainProgressReporter (CI/non-TTY), LoggerProgressReporter, ProgressReporterHolder, ProgressContext, AuditOverviewLine
      Tool/          # ReadFileTool, GrepTool, ListFilesTool, LookupAdvisoryTool, SymfonyToolRegistryFactory, RecordVulnerabilityTool, RecordVulnerabilityToolFactory, RecordReviewTool, RecordReviewToolFactory (both refuse a call missing a required key through RequiredArguments, which reads the tool's own schema)
      Config/        # Standalone configuration: XdgConfigPathResolver, StandaloneConfigFileReader (reads one config file, refusing one that holds 10,000 values or more once its YAML aliases are expanded), HttpTimeout (the standalone-only `http_timeout` — the HTTP client's idle timeout, default 600 s — which a project file may raise, never lower), StandaloneConfigLoader (rejects the six user-only keys a project file may not set — `cache`, `privacy`, `audit.custom_skills`, `audit.output`, `scan.secret_scrubbing`, `scan.custom_risk_patterns` — an `audit.budget` that would loosen the user's caps, a non-map value that would replace a whole section of the user config, a value that is not plain text, a value or key holding a container reference such as `%env()%`, a double colon or a legacy `##[` (keys checked before any other guard), and a model name that is not a bare model id, via ProjectConfigValueGuard, and refuses a project config that is a symlink; folds hyphenated keys to their underscore form first, as `symfony/config` does, and escapes their control characters), StandalonePlatformConfigResolver (a whole-value placeholder is read only as `%env(VAR)%` or `%env(file:VAR)%`, any other spelling throws UnsupportedEnvPlaceholderException; with a `provider:` set, every block it does not select is resolved as a dry run resolves it; + EnvPlaceholder, PlatformApiKey — `names()` tells the one credential key apart from plain settings, `valueForProvider()` scopes the lookup to the selected `provider:`; only `api_key` placeholders fall back to the store), EnvironmentVariableName (the one rule for a name a `%env()%` placeholder can read back, shared by `init`, the `auth:*` commands and the store), TerminalText (escapes the ASCII and eight-bit control characters, the line and paragraph separators and the bidirectional overrides of text quoted back to a terminal — config keys and YAML errors — and leaves other UTF-8 as written; `isPlain()` is the rule a project-config value and `init`'s provider and model must meet), WorkflowCommandText (defuses `::` and the legacy `##[` for a CI runner's log — in a line, a wrapped message, a document or JSON), and the per-user credential store — CredentialStoreInterface + FilesystemCredentialStore (0600 credentials.json, refuses a group/world-readable file on read, refuses an invalid variable name, and replaces content it cannot parse on write) / NullCredentialStore, CredentialIdentity (masked preview + SHA-256 fingerprint), ConfiguredCredentialVariable; plus what `init` may write per platform — DeclaredPlatforms (the platforms the bundled `symfony/ai-bundle` declares; `init` refuses any other), BaseUrlPlatforms (the six whose connection node declares a `base_url`), EndpointPlatforms (those naming it `endpoint`, and `ollama`, the one with no default), OptionalApiKeyPlatforms (the writable ones whose `api_key` is optional), BedrockMantleRoute (the Mantle `api` route and companion bridge `init` writes Bedrock with, read from the model's vendor prefix), HandWrittenPlatforms (the six `init` refuses because they reject `api_key` or need a field it never asks for; HandWrittenPlatformBlock holds the block it prints for them instead, with a `<placeholder>` per missing value, written through RoundTripYaml so every value reads back as the string it was), CompoundPlatforms (`cache` and `failover`, refused outright: they wrap other platforms through services only a Symfony application defines) and InstanceKeyedPlatforms (the six declared with `useAttributeAsKey`, whose provider must name an instance), all seven read back from `symfony/ai-bundle`'s own definitions by PlatformShapeKnowledgeTest, plus PricingPlatformPass (publishes the `ai.platform.<name>` `PlatformInterface` resolves to, so pricing reads that platform's rates) and the three that refuse a name or value the run could not use: ConfigKeyInstanceName (folds an instance name the way `symfony/config` will, and refuses one the config file could not be read back with), PlatformServiceId (refuses one `ContainerBuilder::setDefinition()` cannot name a service by) and ContainerParameterSyntax (refuses an instance or base URL the container would read as a `%parameter%`; `holdsReference()` and `holdsEnvPlaceholder()` also tell ProjectConfigValueGuard which project values the container would resolve; `literal()` writes a percent-encoded URL escaped so it reaches the container as typed)
      Bridge/        # ComposerBridgeInstaller (installs every bridge a platform needs — and every bridge the manifest already requires, `--with-dependencies` — in one `composer require` into the bridge tree's composer.json under the standalone data directory, pinned to the binary's PHP and to the symfony/ai-platform release BundledAiPlatformVersion reads from the binary's own installed-package data — both refreshed on every install), BridgeTree (that tree; refuses it with StaleBridgeTreeException when its `vendor/composer/installed.php` records another symfony/ai-platform release than the bundled one), ProviderKey
      SelfUpdate/    # SelfUpdater, ProcessReleaseClient, RunningBinaryLocator, ThrottledUpdateAvailabilityNotifier, FilesystemUpdateCheckStore, ModelsDevCatalogRefresher, ReleaseTag (the only release tag shape the updater trusts: `X.Y.Z`, an optional pre-release, an optional leading `v` — a tag is pasted into download URLs and printed, so anything else is refused)
      Report/        # ReportRendererInterface (format/render) + one class per format ({Console,ExecutiveSummary,Json,Sarif,Html,Markdown,Junit,GithubAnnotations,GithubComment}ReportRenderer) + MarkdownTextEscaper (shared Markdown-injection defenses) + IncompleteAuditNotice/RiskHeadline (how the human formats state an incomplete run, and give no risk level to one with no verdict — the scan found no file, or no file was analyzed and nothing found) + DistributionBarChart/ChartBar (inline-SVG charts in the HTML report) + ReportPackage + TemplateLoader; + Template/*.txt + *.html stubs
  Command/           # AuditCommand (Symfony Console: audit:run, alias audit; refuses a project that is not a directory right after the header) + AuditCommandInput (+ `applyDefaults()`: what a flag left unset comes from the configuration, so a flag always wins), AuditCommandDefaults (the `audit.min_score`, `audit.fail_on_incomplete`, `audit.format` and `audit.output` settings the command applies), alias audit; refuses a project that is not a directory right after the header) + AuditCommandInput, ScanPathResolver (makes an absolute `--path` inside the project relative to its root, a Windows drive path included on every platform, and refuses one outside it with ScanPathOutsideProjectException), AuditPresenter (+ `noFilesMatched()`, which names the project and the `--path` values a scan listed nothing under), ConsoleBanner (the identity banner, also rendered by StandaloneApplication for every non-audit command), ReportWriter (+ `assertWritable()` refuses an unusable `--output` before the audit runs, as `Baseline::assertWritable()` does an unusable `--generate-baseline`, both through WritableFilePath; a report that fails to save is kept on the console; WorkflowCommandNeutralizer(Interface) defuses the workflow commands a report or an error printed on a GitHub Actions runner could carry, as each format allows), AuditExitCodeResolver, ExitCode enum, AuditCommandHelp, OutputFormat enum (console|executive|json|sarif|html|markdown|junit|github|github-comment), Baseline (accepted-finding suppression); DiffCommand (audit:diff — compares two JSON reports by finding fingerprint) + ReportDiffer (a finding gone from a file the later run did not analyze is `unverified`, not fixed, unless a complete run over its recorded `scope` no longer lists the file — `LoadedReport`, which carries a report's findings, unanalyzed and analyzed files, ledger files and that scope, and whose `vouchesForAbsenceIn()` `audit:baseline --prune` shares), ReportDiff/DiffFinding, ReportFindingsLoader → LoadedReport (findings, the files the run did and did not analyze, and the scope of a complete run that analyzed one), DiffPresenter, DiffOutputFormat enum (console|json); TrendCommand (audit:trend — tracks finding counts across two or more JSON reports) + ReportTrendAnalyzer, ReportTrend/TrendPoint, TrendPresenter, TrendOutputFormat enum (console|json|html); AuthSetCommand / AuthStatusCommand / AuthRemoveCommand (auth:set, auth:status, auth:remove — the standalone per-user API-key store; exit `2` for a name no placeholder can read, via EnvironmentVariableRefusal; a relative `SYMFONY_SECURITY_AUDITOR_HOME` is refused first, via ApplicationHomeRefusal) + CredentialPromptInterface/HiddenCredentialPrompt (the hidden prompt `auth:set` and `init` share — no echo fallback, EOF is no answer; HiddenInputUnavailableException when the terminal cannot hide input) + CredentialConsoleBanner (names the key a run spends, masked, in the audit header); Mcp/{McpServeCommand (mcp:serve — stdio MCP server exposing the `audit` tool, in the bundle and the standalone binary), McpServerFactory, AuditTool (rethrows every failure as `Mcp\Exception\ToolCallException` so the reason reaches the client; asks `UnpricedModelBudgetGuard::assertBudgetEnforceable()` first, so a cost budget on an unpriced model is refused as `audit:run --no-interaction` refuses it), StdioMcpTransportFactory}
  Standalone/        # The standalone binary: StandaloneApplication (identity banner; a help, listing or completion run — abbreviations included — describes the config-built commands instead of building them; masks the `--env-var` value of the command line it echoes under an error; `projectPathGivenTo()` reads the `project-path` the command line names by binding a copy of it to the audit command's own definition, so `StandaloneApplicationFactory` builds the container with that project's `.symfony-security-auditor.yaml` through `StandaloneConfigLoader::withProjectConfigFile()`, and with the working directory's when the line names none), StandaloneApplicationFactory (registers `audit:diff`, `audit:trend` and `audit:baseline` as plain objects, with no container), BridgeTreeLoader (registers the bridge tree's autoloader unless it is stale, reporting a platform check that refuses this PHP — thrown, or raised as `E_USER_ERROR` and converted by PlatformCheckErrorConverter — instead of dying), StandaloneContainerFactory, StandaloneConsoleCommandFactory (+ `describe()`), StandaloneAuditPreflight, BundleExtensionLoader, UpdateAvailabilityConsoleListener, PendingBinarySwapCommitter (commits the swap `self-update` deferred to shutdown and reports a failed one with exit `1`), Exception/{ProviderBridgeException, AmbiguousPlatformException, MissingBundleExtensionException, UnknownPlatformProviderException, UnloadableBridgeTreeException, UnresolvableAuditCommandException, UnresolvableMcpServeCommandException}
  SymfonySecurityAuditorBundle.php  # Bundle class (configure + loadExtension)
tests/Phpunit/
  Unit/              # Isolated class tests (stub/mock collaborators)
  Integration/       # Wire real classes, no LLM calls
  EndToEnd/          # Full pipeline, uses stub LLM client; StandaloneAuditFromOutsideProjectEndToEndTest runs the real bin/symfony-security-auditor in a process of its own, from a folder that is not the audited project, to pin how the project argument and `--path` resolve
tests/Shell/         # POSIX shell tests (install_script_test.sh — covers install.sh; pull_request_check_test.sh — covers .github/scripts/check-pull-request.sh)
config/services.php  # DI wiring for all bundle services
docs/
  architecture.md    # Layer overview, data flow, domain model details
  configuration.md   # Bundle config reference
  cost-and-performance.md # Profiles, split-model, concurrency, caching, budgets, rate limits
  extending.md       # Extension point guide
  ci.md              # CI pipeline documentation
  diagrams.md        # Mermaid diagrams
  faq.md             # Common questions: cost, accuracy, comparisons, model picks, privacy
  troubleshooting.md # Empty reports, LLM errors, advisory issues, cache, CI failures
```

## Architecture: DDD Layers

Strict DDD layering under `src/Audit/`. Infrastructure never leaks into Domain or Application.

```text
Command → Application → Domain ← Infrastructure (implements ports)
```

**`LLMClientInterface`** is the sole seam between Application and LLM I/O. `AttackerAgent` and `ReviewerAgent` never import any `symfony/ai` type directly.

**Dual-agent loop** (up to 3 iterations, stops earlier when no new findings):

1. (optional) `StaticPreScanner` tags files with deterministic risk markers; (optional) `CodeSlicer` trims large files to security-relevant lines
2. `AttackerAgent` — chunks files (default `feature` strategy: a controller with its entity/repository/form/voter/templates together; `type` for the legacy priority window; API Platform `#[ApiResource]` classes classify as `api_resource` with their own skill block), injects markers + prior-iteration findings, calls LLM. By default (`audit.structured_collection: true`), findings come in through `record_vulnerability` tool calls validated by the provider against the tool's JSON schema; with the flag off, the attacker parses a JSON array from the response. With `audit.attacker_max_concurrent` > 1 (the `fast` profile sets 4) and a tool-batch-capable client, cache-miss chunks are analyzed concurrently. Optional `EscalatingAttackerAgent` runs a cheap model first and only escalates flagged files to the expensive model, which receives the cheap findings on each chunk's own files as unverified `candidateFindings` to confirm, refine or discard — never as reviewer-validated context; a cheap finding on a file the deep pass judged and did not re-report is dropped.
3. Filter — confidence ≥ 0.6
4. `ReviewerAgent` — validates each finding, may adjust severity. By default (`audit.reviewer_structured_collection: true`), verdicts come in through schema-enforced `record_review` tool calls; the explicit opt-in `reviewer_tools_enabled` keeps the JSON path, and `reviewer_max_concurrent`
   > 1 reviews findings concurrently (structured when the client supports tool batching, JSON otherwise). Verdicts are cached across runs (`FilesystemReviewerCache`) when `cache.enabled` is on; every review mode — concurrent and batched (`reviewer_batch_size > 1`) alike — serves cached verdicts first and dispatches/batches only the misses.
5. Deduplicate → persist to `AuditContext`

After the loop, the optional `PoCSynthesisStage` runs (concrete reproduction artifacts for high-severity findings).

Full details: [`docs/architecture.md`](docs/architecture.md)

## Bundle Configuration

Minimal:

```yaml
symfony_security_auditor:
    model: 'claude-opus-5'
```

One-knob preset (`fast` | `balanced` | `thorough`; explicit keys always win):

```yaml
symfony_security_auditor:
    profile: 'fast'
```

Split-model (larger attacker, faster reviewer):

```yaml
symfony_security_auditor:
    attacker_model: 'claude-opus-5'
    reviewer_model: 'claude-haiku-4-5-20251001'
```

Swapping LLM providers requires only `config/packages/ai.yaml` changes — no code changes.

Full reference: [`docs/configuration.md`](docs/configuration.md)

## Commit Messages

Format: `<type>[optional scope]: <description>` — [Conventional Commits](https://www.conventionalcommits.org/)

| Type       | When                    |
| ---------- | ----------------------- |
| `feat`     | New user-facing feature |
| `fix`      | Bug fix                 |
| `refactor` | Neither fix nor feature |
| `test`     | Adding/fixing tests     |
| `docs`     | Documentation only      |
| `chore`    | Maintenance/tooling     |
| `build`    | Build system/deps       |
| `ci`       | CI configuration        |
| `perf`     | Performance improvement |

Common scopes: `agent`, `pipeline`, `domain`, `llm`, `command`, `bundle`, `standalone`, `scan`, `deps`, `ci`, `rate-limit`, `release`. Breaking changes: `feat!:` with `BREAKING CHANGE:` footer.

## Pull Requests

Fill in [`.github/PULL_REQUEST_TEMPLATE.md`](.github/PULL_REQUEST_TEMPLATE.md) and keep the top of the PR short:

- **Title: 50 characters or fewer**, same [Conventional Commits](https://www.conventionalcommits.org/) format as a commit subject.
- **Four sections, in this order:** `## Summary`, `## Type of change`, `## Target branch`, `## Checklist`. No other sections: the CHANGELOG entry and the commit body carry the implementation, compatibility and upgrade notes.
- **`## Summary`: 500 characters or fewer.** State the user-visible outcome and stop, then add a `Closes #N` or `Refs #N` line when an issue is involved — the summary is the part everyone reads, so it must stay skimmable.
- **Only the ticked boxes** under Type of change, Target branch and Checklist: delete the others and every template instruction. The Checklist lists only what CI cannot check, and its license box is always ticked.
- **Label** the PR `bug` or `enhancement` and assign it to the maintainer.

**Stack as little as possible.** Open every PR against its release branch, and stack it on another open PR only when it needs code that PR adds — never because both touch `CHANGELOG.md`, `CLAUDE.md` or the docs, whose conflicts are resolved by updating the branch once the first one merges. When splitting work into several PRs, cut along code dependencies so each builds and passes on the release branch alone. A stacked PR ticks `stacked` and ends its Summary with `Stacked on #N` and the code it needs from it. Once the parent merges, retarget it, untick `stacked`, drop the `Stacked on` line and update the branch — the squash-merge left it carrying commits the base no longer has, and its CI ran on top of unmerged code.

On every edit, the `Pull request target` check ([`.github/scripts/check-pull-request.sh`](.github/scripts/check-pull-request.sh)) fails the PR on a title over 50 characters, a missing, extra or misplaced section, a Summary over 500 characters, an unticked box, leftover template text or a missing license box, a base that does not match the ticked branch, and a stacked PR that does not name its parent — or still does once unstacked. Run it before opening or editing a PR:

```bash
PR_TITLE='fix(scan): …' PR_BODY="$(cat body.md)" BASE_REF=1.x \
  sh .github/scripts/check-pull-request.sh
```

**Always squash-merge, never rebase-merge.** Every PR becomes exactly one commit on its base branch. Rebase-merging replays each of the PR's commits individually — with a fresh SHA apiece, even when nothing about them changed.

**Exception: the `chore: release X.Y.Z` PR that merges `<N>.x` into `main`.** Use a regular merge (a merge commit) there instead, never squash and never rebase. `main` is supposed to end up with the exact same commit SHAs as `<N>.x` — that's how every release before this one actually happened (PR #226, for 1.18.0). Squashing collapses `<N>.x`'s commits into one new SHA that doesn't exist on `<N>.x`, so the two branches permanently diverge in commit identity and need a cherry-pick-back reconciliation after every single release. Rebase-merging is worse: it replays every commit `<N>.x` has accumulated since it last diverged from `main` with a fresh SHA apiece — which is how PR #305 quietly turned a one-commit release into ~40 replayed commits landing on `main` and broke `Commit Lint` (see [Branches & maintenance](docs/versioning.md#branches--maintenance)).

## CI Pipeline

Seven jobs must all pass before merging: **Prettier Check** (markdown formatting) → **Markdown Lint** (markdownlint-cli2 semantics) → **Commit Lint** (commitlint, conventional commits) → **Lint** (Composer Normalize, PHP CS Fixer, Rector, PHPStan max, Deptrac, Swiss Knife, `composer audit`, install-script and pull-request-check shell tests) → **zizmor** (GitHub Actions security scan via [`zizmorcore/zizmor-action`](https://github.com/zizmorcore/zizmor-action), SARIF uploaded to Code Scanning) → **Tests + Mutation** (PHPUnit matrix on PHP 8.3/8.4/8.5 × Symfony 7.4/8.0/8.1 with 100% coverage, then Infection 100% MSI; coverage uploads to Codecov and the mutation report uploads to the Stryker dashboard via Infection's `stryker` logger — the badge tracks `main`, and same-repo branches publish their own report). Every pull request also runs **Pull request target** (`.github/workflows/pr-target.yaml`), which fails on a title, description or base branch that breaks [Pull Requests](#pull-requests).

Details: [`docs/ci.md`](docs/ci.md)

## Security Posture

This project is itself a security tool — it must not ship the vulnerability classes it hunts. Command and code execution is therefore banned at the static-analysis level: `phpstan.dist.neon` explicitly `includes:` the `spaze/phpstan-disallowed-calls` `disallowed-execution-calls.neon` ruleset, forbidding raw execution sinks (`exec`, `shell_exec`, `system`, `passthru`, `proc_open`, `popen`, `pcntl_exec`, backtick operator, `eval`). `eval` is double-locked — also forbidden via the `ForbiddenNodeRule` `Eval_` entry.

**This ban is a deliberate manual opt-in, not a freebie.** Although `phpstan/extension-installer` is installed, it only auto-loads the package's `extension.neon`, which registers the rule engine with **every** `disallowed*` array empty (zero bans by default). The curated `disallowed-execution-calls.neon` set is wired in by hand on line 2 of `phpstan.dist.neon` — delete that line and the ban silently disappears with no error. Keep it.

Consequences for contributors:

- **All subprocess work routes through Symfony `Process`** (e.g. `ProcessGitChangedFilesResolver`, `SymfonyProcessComposerAuditRunner`), never a raw exec call — `Process` does not invoke a shell by default, so there is no argument-interpolation command-injection surface.
- Never satisfy a disallowed-call error with an `allowIn`/exclusion entry; route through `Process` instead. Suppressing this gate is covered by the [Never Silence Quality Gates](#5-never-silence-quality-gates) rule.

The same "don't ship what we hunt" posture applies to the project's own GitHub Actions: a dedicated **zizmor** job scans `.github/workflows/` and `action.yml` on every push and pull request, and every third-party `uses:` — including `zizmor-action` itself — is pinned to a commit SHA (never a mutable tag) for the same reason `Process` is required over raw exec: a moving reference is an unreviewed-code-execution surface. These pins aren't manually-maintained dead weight — the existing `github-actions` entry in `.github/dependabot.yaml` recognizes the `# vX.Y.Z` trailing-comment convention and opens a PR bumping both the SHA and the comment whenever a pinned action releases. Both `dependabot.yaml` update entries also carry a 7-day `cooldown` (`default-days: 7`), so Dependabot never opens a bump PR for a release younger than a week — the window in which a compromised or yanked supply-chain release is typically caught — which also clears zizmor's `dependabot-cooldown` audit.

## Behavioral Guidelines

### 1. Think Before Coding

Before implementing: state assumptions explicitly, surface tradeoffs, present multiple interpretations rather than picking silently. If unclear, stop and ask.

### 2. Simplicity First

Minimum code that solves the problem. No speculative features, no abstractions for single-use code, no error handling for impossible scenarios.

### 3. Surgical Changes

Touch only what the request requires. Don't improve adjacent code. Match existing style. If you notice unrelated dead code, mention it — don't delete it. Remove only imports/variables that YOUR changes made unused.

### 4. Goal-Driven Execution

Transform tasks into verifiable goals. For multistep tasks, state a brief plan with a verify step for each.

### 5. Never Silence Quality Gates

Never bypass static analysis or mutation testing via suppression annotations or config opt-outs. **Forbidden** (non-exhaustive):

- PHPStan — `@phpstan-ignore`, `@phpstan-ignore-line`, `@phpstan-ignore-next-line`, `ignoreErrors` entries in `phpstan.dist.neon`, baseline files.
- Infection — `@infection-ignore-all`, `@infection-ignore-all-for`, per-mutator `ignore` entries in `infection.json5`, `ignoreSourceCodeByRegex`.
- PHPUnit / coverage — `@codeCoverageIgnore*`, `@requires`/`markTestSkipped` used to dodge a failing test, `@group` used to exclude from CI.
- PHP CS Fixer / Rector — `@phpcs:ignore`, `// @phpstan-ignore`, `\Rector\Skip`, blanket `--no-check`.

If a tool flags something, **fix the underlying code**. Genuine exceptions (a real false positive, a library bug) require a PR-description justification and a linked issue tracking removal — never silent suppression.

### 6. Backward Compatibility

The project follows [Semantic Versioning 2.0.0](https://semver.org) and, for its PHP API surface, the [Symfony Backward Compatibility promise](https://symfony.com/doc/current/contributing/code/bc.html) (`@internal` code is exempt). Treat every public-API element as load-bearing: configuration keys (and their defaults), the `audit:run` command (and its `audit` alias) arguments/options/exit codes, JSON and SARIF output schemas, Domain ports under `src/Audit/Domain/Port/` (including `AdvisoryDatabaseInterface`), Domain models/enums/exceptions, `RunAuditUseCase`, and the Bundle class. A change that removes or alters any of these is a `MAJOR` and requires a deprecation cycle.

Internal classes (`@internal` PHPDoc tag) — concrete agents, pipeline stages, infrastructure adapters, Command collaborators — may be refactored freely in a `MINOR`. When you add a class that is **not** an extension point, add the `@internal` tag. When you add a public configuration key, list it in `docs/versioning.md` and add it to `resources/schema.json` (the JSON Schema that powers editor autocompletion for `symfony_security_auditor.yaml`).

Canonical policy: [`docs/versioning.md`](docs/versioning.md).

## Path-Scoped Rules

Rules scoped to specific paths live in `.claude/rules/`:

- [`changelog.md`](.claude/rules/changelog.md) — classify every change (major/minor/patch or Unreleased) and update `CHANGELOG.md` in the same commit; release-notes format.
- [`ddd-layers.md`](.claude/rules/ddd-layers.md) — dependency direction across layers.
- [`domain-models.md`](.claude/rules/domain-models.md) — immutability, copy-on-write, deterministic IDs in `src/Audit/Domain/**`.
- [`llm-seam.md`](.claude/rules/llm-seam.md) — `LLMClientInterface` boundary between Application and `symfony/ai`.
- [`php-classes.md`](.claude/rules/php-classes.md) — `final readonly`, interfaces/SOLID, single responsibility, Symfony components in `src/**`.
- [`testing.md`](.claude/rules/testing.md) — TDD red/green/refactor, stub vs mock, suite layout, mutation score.
- [`no-comments.md`](.claude/rules/no-comments.md) — no multi-line comment blocks; comments signal poorly-written code; fix the code instead.
