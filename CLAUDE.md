# CLAUDE.md

## Keeping This File Up to Date

Update the relevant section in the same commit/PR whenever the project evolves.
Rules scoped to specific paths live in `.claude/rules/` — update them too. Never
leave this file describing a state that no longer exists.

---

## Project Overview

**symfony-security-auditor** — AI-powered multi-agent security auditor for
Symfony applications. Distributed as a **Symfony bundle** (`symfony-bundle`
package type). Uses a dual-agent attacker/reviewer loop backed by `symfony/ai`
to detect vulnerabilities and produce structured reports.

> Always check `composer.json` for authoritative dependency versions — never
> rely on version numbers written here.

## Tech Stack

| Layer             | Technology                                                                                                                                                                                                                                               |
| ----------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Language          | PHP (see `composer.json` → `require.php`)                                                                                                                                                                                                                |
| Framework         | Symfony (see `composer.json`)                                                                                                                                                                                                                            |
| LLM               | symfony/ai (provider-agnostic: Anthropic, OpenAI, Mistral, Ollama, …)                                                                                                                                                                                    |
| Packaging         | symfony-bundle + Flex recipe; standalone self-contained native binary (`box` + `static-php-cli` micro) for Linux/macOS/Windows                                                                                                                           |
| Tests             | PHPUnit (Unit / Integration / EndToEnd); 100% line coverage enforced via the custom `MinimumLineCoverageExtension` (`tools/PHPUnit/`)                                                                                                                    |
| Mutation          | Infection (100% MSI required)                                                                                                                                                                                                                            |
| Static analysis   | PHPStan max + phpstan-strict-rules + custom rules (`FinalRule`, `MaxParameterCountRule`, `NoEmptyCatchRule`, `NoSilencingErrorHandlerRule`, `ForbiddenTestAttributeRule`, `SprintfOverConcatRule` — in `tools/PHPStan/`) + symplify/spaze rules + Rector |
| Layer conformance | deptrac (DDD layer rules — `deptrac.yaml`)                                                                                                                                                                                                               |
| Complexity        | tomasvotruba/cognitive-complexity (function ≤ 7, class ≤ 40)                                                                                                                                                                                             |
| Dead code         | rector/swiss-knife (`check-commented-code`, `check-conflicts`)                                                                                                                                                                                           |
| Style             | PHP CS Fixer (@PER-CS3x0, @Symfony rulesets)                                                                                                                                                                                                             |

## Build, Test & Lint Commands

```bash
bin/castor up
```

| Task                    | Command                                                                     |
| ----------------------- | --------------------------------------------------------------------------- |
| Install dependencies    | `bin/castor up` (runs `docker compose up --wait`)                           |
| Stop containers         | `bin/castor down`                                                           |
| Lint (check only)       | `bin/castor lint`                                                           |
| Lint + auto-fix         | `bin/castor lint:fix`                                                       |
| Markdown check only     | `bin/castor lint:docs` (fast pre-push check)                                |
| Run PHP tests           | `docker compose exec php vendor/bin/phpunit`                                |
| Run mutation tests      | `docker compose exec php bin/infection`                                     |
| Score detection quality | `bin/castor eval` (audits a ground-truth fixture, reports precision/recall) |
| Symfony console         | `docker compose exec php bin/console <command>`                             |

`bin/castor lint` runs sequentially: Prettier (check) → Markdown lint
(markdownlint-cli2) → Composer Normalize → PHP CS Fixer → Rector → PHPStan (max,
500M) → Deptrac (DDD layers) → Swiss Knife (commented-code + merge-conflict
scan) → Install script tests (`tests/Shell/install_script_test.sh`) → PHPUnit →
Infection. `bin/castor lint:fix` auto-fixes steps 1–3 (Prettier, Markdown lint,
Composer Normalize); the remaining steps are check-only.

Commit messages are validated separately in CI via
[commitlint](https://commitlint.js.org/) (`commitlint.config.js`) — see
[Commit Messages](#commit-messages).

## Project Structure

```text
src/
  Audit/
    Domain/          # Pure PHP — no framework, no I/O
      Configuration/ # Typed config VOs (BundleConfiguration, AuditProfile, LLMConfiguration, …)
      Model/         # Value objects and enums (Vulnerability [+ `of()` factory + CodeLocation/VulnerabilityClassification/VulnerabilityNarrative], SymfonyMapping [+ `of()` + ProjectFileInventory/AccessControlMap], AuditReport [+ ReportIdentity], ProjectFile, ProjectFileType, ProjectFileTypeClassifier, RouteAccessControl, VoterCapability, FormBinding, TokenUsageSnapshot, VulnerabilityHydrationResult, VulnerabilityDropReason, ReviewerFeedback/AcceptedFindingFeedback, …) — public factories use `of()`; the wide `create()` is `@deprecated`
      Exception/     # Domain exceptions (LLMProviderException, GitChangedFilesUnavailableException, InvalidCodeLocationException, InvalidVulnerabilityClassificationException)
      Pipeline/      # PipelineInterface, StageInterface, CoverageRecorderInterface (ports)
      Port/          # Cross-layer ports (LLMClientInterface, BatchCapableLLMClientInterface, ToolBatchCapableLLMClientInterface, LLMResponse, *PromptBuilderInterface, ProjectFileScannerInterface, AttackerCacheInterface, ContextAwareAttackerCacheInterface, ReviewerCacheInterface, AdvisoryDatabaseInterface, SecretScrubberInterface, TokenEstimatorInterface, PricingProviderInterface, RateLimiterInterface, ProgressReporterInterface, StaticPreScannerInterface, CodeSlicerInterface, ControllerAccessControlParserInterface, VoterCapabilityParserInterface, FormBindingParserInterface, SecurityConfigParserInterface, GitChangedFilesResolverInterface, ReviewerFeedbackProviderInterface) + null-object port defaults (NullStaticPreScanner, NullReviewerFeedbackProvider, NullCodeSlicer, NullControllerAccessControlParser, NullVoterCapabilityParser, NullFormBindingParser, NullSecurityConfigParser, NullProgressReporter — all `@internal`)
        Tool/        # ToolInterface, ToolDefinition, ToolRegistry, ToolRegistryFactoryInterface
    Application/     # Orchestration — no I/O, depends only on Domain
      UseCase/       # RunAuditUseCase, EstimateAuditCostUseCase (entry points)
      Pipeline/      # AuditPipeline + Stage/{IngestionStage, MappingStage, AuditStage, PoCSynthesisStage}
      Agent/         # AttackerAgent (+ AttackerLlmCollaborators, AttackerScanCollaborators, AttackerAnalysisSettings, AttackerAnalysisRequest, RiskMarkerIndex, AttackerContextPromptRenderer, Chunk/{ChunkContext, ChunkContextFactory, AttackerChunkCache, ChunkCoverageRecorder, ChunkFindingProgress, SequentialChunkAnalyzer, ConcurrentChunkAnalyzer, StructuredVulnerabilityCollectionSession}), ReviewerAgent (+ ReviewerAgentCollaborators, ReviewerModeConfiguration, Review/{VerdictApplier, BatchVerdictApplier, ReviewOutcomeRecorder, ReviewerVerdictCache, CodeContextResolver, SequentialReviewAnalyzer, StructuredReviewAnalyzer, ConcurrentReviewAnalyzer, ConcurrentStructuredReviewAnalyzer, BatchReviewAnalyzer, ReviewBatchSettings, ReviewCacheBuckets, CachePartition, ConcurrentReviewBatch, StructuredReviewCollectionSession}), EscalatingAttackerAgent, AuditOrchestrator (+ AuditLoopSettings), VulnerabilityFactory, VulnerabilityCollector, RecordVulnerabilityToolFactoryInterface, ReviewCollector, RecordReviewToolFactoryInterface, PoCSynthesizer, Chunking/{ChunkingStrategy, FileChunker}
    Infrastructure/  # I/O adapters
      LLM/           # SymfonyAiLLMClient (ctor takes PlatformBinding + PlatformRequestConfig + PlatformResilienceConfig + PlatformAccountingConfig; builds RetryingPlatformInvoker, SequentialToolLoop, BatchWindowResolver, ToolConversationWavefront, PlatformResultExtractor, PlatformOptionsFactory, PlatformToolsMapper, PromptTokenEstimator), RetryPolicy (+ BackoffSchedule, RateLimitBackoff, Exception/InvalidRetryConfigurationException), TransientFailureClassifier, TokenEstimator/{ProviderTokenEstimatorInterface, ResolvingTokenEstimator, CharacterRatioCounter, AnthropicTokenEstimator, OpenAiTokenEstimator, GeminiTokenEstimator, MistralTokenEstimator, LlamaTokenEstimator, DeepSeekTokenEstimator}, Delay/, RateLimit/{NullRateLimiter, TokenBucketRateLimiter, RetryAfterHeaderParser}
      FileSystem/    # ProjectFileScanner, RegexSecretScrubber, NullSecretScrubber
      Scan/          # RegexStaticPreScanner, RegexCodeSlicer, PhpParserControllerAccessControlParser, PhpParserVoterCapabilityParser, PhpParserFormBindingParser, SymfonyYamlSecurityConfigParser
      Diff/          # ProcessGitChangedFilesResolver (git diff for --since)
      Prompt/        # AttackerPromptBuilder (+ SymfonyMappingContextRenderer, NumberedFileContextRenderer, Skill/{AttackerSkillInterface, AttackerSkillRegistry, one *AttackerSkill per attack surface}), ReviewerPromptBuilder (+ Reviewer/{ReviewerPromptSectionsInterface, ReviewerPromptSections, ReviewerMessageRendererInterface, ReviewerMessageRenderer, ReviewerFeedbackHolder})
      Cache/         # FilesystemAttackerCache, NullAttackerCache, FilesystemReviewerCache, NullReviewerCache
      Advisory/      # ComposerAuditAdvisoryDatabase (default) + LockfileHashedAdvisoryCache (TTL-bounded lockfile-hash cache in front of it, wired when cache.enabled), DeferredAdvisoryDatabase (lazy wrapper), InMemoryAdvisoryDatabase (fallback), ComposerAuditRunnerInterface + SymfonyProcessComposerAuditRunner
      Pricing/       # ModelsDevPricingProvider (default), ModelPrice
      Progress/      # ConsoleProgressReporter (decorated TTY), PlainProgressReporter (CI/non-TTY), LoggerProgressReporter, ProgressReporterHolder, ProgressContext, AuditOverviewLine
      Tool/          # ReadFileTool, GrepTool, ListFilesTool, LookupAdvisoryTool, SymfonyToolRegistryFactory, RecordVulnerabilityTool, RecordVulnerabilityToolFactory, RecordReviewTool, RecordReviewToolFactory
      Report/        # ReportRendererInterface (format/render) + one class per format ({Console,Json,Sarif,Html,Markdown,Junit,GithubAnnotations}ReportRenderer) + ReportPackage + TemplateLoader; + Template/*.txt + *.html stubs
  Command/           # AuditCommand (Symfony Console: audit:run, alias audit) + AuditCommandInput, AuditPresenter, ReportWriter, AuditExitCodeResolver, ExitCode enum, AuditCommandHelp, OutputFormat enum (console|json|sarif|html|markdown|junit|github), Baseline (accepted-finding suppression); DiffCommand (audit:diff — compares two JSON reports by finding fingerprint) + ReportDiffer, ReportDiff/DiffFinding, DiffPresenter, DiffOutputFormat enum (console|json); TrendCommand (audit:trend — tracks finding counts across two or more JSON reports) + ReportTrendAnalyzer, ReportTrend/TrendPoint, TrendPresenter, TrendOutputFormat enum (console|json)
  SymfonySecurityAuditorBundle.php  # Bundle class (configure + loadExtension)
tests/Phpunit/
  Unit/              # Isolated class tests (stub/mock collaborators)
  Integration/       # Wire real classes, no LLM calls
  EndToEnd/          # Full pipeline, uses stub LLM client
tests/Shell/         # POSIX shell tests (install_script_test.sh — covers install.sh)
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

Strict DDD layering under `src/Audit/`. Infrastructure never leaks into Domain
or Application.

```text
Command → Application → Domain ← Infrastructure (implements ports)
```

**`LLMClientInterface`** is the sole seam between Application and LLM I/O.
`AttackerAgent` and `ReviewerAgent` never import any `symfony/ai` type directly.

**Dual-agent loop** (up to 3 iterations, stops earlier when no new findings):

1. (optional) `StaticPreScanner` tags files with deterministic risk markers;
   (optional) `CodeSlicer` trims large files to security-relevant lines
2. `AttackerAgent` — chunks files (default `feature` strategy: a controller with
   its entity/repository/form/voter/templates together; `type` for the legacy
   priority window; API Platform `#[ApiResource]` classes classify as
   `api_resource` with their own skill block), injects markers + prior-iteration
   findings, calls LLM. By default (`audit.structured_collection: true`),
   findings come in through `record_vulnerability` tool calls validated by the
   provider against the tool's JSON schema; with the flag off, the attacker
   parses a JSON array from the response. With `audit.attacker_max_concurrent` >
   1 (the `fast` profile sets 4) and a tool-batch-capable client, cache-miss
   chunks are analyzed concurrently. Optional `EscalatingAttackerAgent` runs a
   cheap model first and only escalates flagged files to the expensive model.
3. Filter — confidence ≥ 0.6
4. `ReviewerAgent` — validates each finding, may adjust severity. By default
   (`audit.reviewer_structured_collection: true`), verdicts come in through
   schema-enforced `record_review` tool calls; the explicit opt-in
   `reviewer_tools_enabled` keeps the JSON path, and `reviewer_max_concurrent`
   > 1 reviews findings concurrently (structured when the client supports tool
   > batching, JSON otherwise). Verdicts are cached across runs
   > (`FilesystemReviewerCache`) when `cache.enabled` is on; every review mode —
   > concurrent and batched (`reviewer_batch_size > 1`) alike — serves cached
   > verdicts first and dispatches/batches only the misses.
5. Deduplicate → persist to `AuditContext`

After the loop, the optional `PoCSynthesisStage` runs (concrete reproduction
artifacts for high-severity findings).

Full details: [`docs/architecture.md`](docs/architecture.md)

## Bundle Configuration

Minimal:

```yaml
symfony_security_auditor:
    model: 'claude-opus-4-8'
```

One-knob preset (`fast` | `balanced` | `thorough`; explicit keys always win):

```yaml
symfony_security_auditor:
    profile: 'fast'
```

Split-model (larger attacker, faster reviewer):

```yaml
symfony_security_auditor:
    attacker_model: 'claude-opus-4-8'
    reviewer_model: 'claude-haiku-4-5-20251001'
```

Swapping LLM providers requires only `config/packages/ai.yaml` changes — no code
changes.

Full reference: [`docs/configuration.md`](docs/configuration.md)

## Commit Messages

Format: `<type>[optional scope]: <description>` —
[Conventional Commits](https://www.conventionalcommits.org/)

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

Common scopes: `agent`, `pipeline`, `domain`, `llm`, `command`, `bundle`,
`standalone`, `scan`, `deps`, `ci`, `rate-limit`. Breaking changes: `feat!:`
with `BREAKING CHANGE:` footer.

## CI Pipeline

Six jobs must all pass before merging: **Prettier Check** (markdown formatting)
→ **Markdown Lint** (markdownlint-cli2 semantics) → **Commit Lint** (commitlint,
conventional commits) → **Lint** (Composer Normalize, PHP CS Fixer, Rector,
PHPStan max, Deptrac, Swiss Knife, `composer audit`, install-script shell tests)
→ **Tests + Mutation** (PHPUnit matrix on PHP 8.3/8.4/8.5 × Symfony 7.4/8.0/8.1
with 100% coverage, then Infection 100% MSI; coverage uploads to Codecov and the
mutation report uploads to the Stryker dashboard via Infection's `stryker`
logger — the badge tracks `main`, and same-repo branches publish their own
report).

Details: [`docs/ci.md`](docs/ci.md)

## Security Posture

This project is itself a security tool — it must not ship the vulnerability
classes it hunts. Command and code execution is therefore banned at the
static-analysis level: `phpstan.dist.neon` explicitly `includes:` the
`spaze/phpstan-disallowed-calls` `disallowed-execution-calls.neon` ruleset,
forbidding raw execution sinks (`exec`, `shell_exec`, `system`, `passthru`,
`proc_open`, `popen`, `pcntl_exec`, backtick operator, `eval`). `eval` is
double-locked — also forbidden via the `ForbiddenNodeRule` `Eval_` entry.

**This ban is a deliberate manual opt-in, not a freebie.** Although
`phpstan/extension-installer` is installed, it only auto-loads the package's
`extension.neon`, which registers the rule engine with **every** `disallowed*`
array empty (zero bans by default). The curated
`disallowed-execution-calls.neon` set is wired in by hand on line 2 of
`phpstan.dist.neon` — delete that line and the ban silently disappears with no
error. Keep it.

Consequences for contributors:

- **All subprocess work routes through Symfony `Process`** (e.g.
  `ProcessGitChangedFilesResolver`, `SymfonyProcessComposerAuditRunner`), never
  a raw exec call — `Process` does not invoke a shell by default, so there is no
  argument-interpolation command-injection surface.
- Never satisfy a disallowed-call error with an `allowIn`/exclusion entry; route
  through `Process` instead. Suppressing this gate is covered by the
  [Never Silence Quality Gates](#5-never-silence-quality-gates) rule.

## Behavioral Guidelines

### 1. Think Before Coding

Before implementing: state assumptions explicitly, surface tradeoffs, present
multiple interpretations rather than picking silently. If unclear, stop and ask.

### 2. Simplicity First

Minimum code that solves the problem. No speculative features, no abstractions
for single-use code, no error handling for impossible scenarios.

### 3. Surgical Changes

Touch only what the request requires. Don't improve adjacent code. Match
existing style. If you notice unrelated dead code, mention it — don't delete it.
Remove only imports/variables that YOUR changes made unused.

### 4. Goal-Driven Execution

Transform tasks into verifiable goals. For multistep tasks, state a brief plan
with a verify step for each.

### 5. Never Silence Quality Gates

Never bypass static analysis or mutation testing via suppression annotations or
config opt-outs. **Forbidden** (non-exhaustive):

- PHPStan — `@phpstan-ignore`, `@phpstan-ignore-line`,
  `@phpstan-ignore-next-line`, `ignoreErrors` entries in `phpstan.dist.neon`,
  baseline files.
- Infection — `@infection-ignore-all`, `@infection-ignore-all-for`, per-mutator
  `ignore` entries in `infection.json5`, `ignoreSourceCodeByRegex`.
- PHPUnit / coverage — `@codeCoverageIgnore*`, `@requires`/`markTestSkipped`
  used to dodge a failing test, `@group` used to exclude from CI.
- PHP CS Fixer / Rector — `@phpcs:ignore`, `// @phpstan-ignore`, `\Rector\Skip`,
  blanket `--no-check`.

If a tool flags something, **fix the underlying code**. Genuine exceptions (a
real false positive, a library bug) require a PR-description justification and a
linked issue tracking removal — never silent suppression.

### 6. Backward Compatibility

The project follows [Semantic Versioning 2.0.0](https://semver.org) and, for its
PHP API surface, the
[Symfony Backward Compatibility promise](https://symfony.com/doc/current/contributing/code/bc.html)
(`@internal` code is exempt). Treat every public-API element as load-bearing:
configuration keys (and their defaults), the `audit:run` command (and its
`audit` alias) arguments/options/exit codes, JSON and SARIF output schemas,
Domain ports under `src/Audit/Domain/Port/` (including
`AdvisoryDatabaseInterface`), Domain models/enums/exceptions, `RunAuditUseCase`,
and the Bundle class. A change that removes or alters any of these is a `MAJOR`
and requires a deprecation cycle.

Internal classes (`@internal` PHPDoc tag) — concrete agents, pipeline stages,
infrastructure adapters, Command collaborators — may be refactored freely in a
`MINOR`. When you add a class that is **not** an extension point, add the
`@internal` tag. When you add a public configuration key, list it in
`docs/versioning.md` and add it to `resources/schema.json` (the JSON Schema that
powers editor autocompletion for `symfony_security_auditor.yaml`).

Canonical policy: [`docs/versioning.md`](docs/versioning.md).

## Path-Scoped Rules

Rules scoped to specific paths live in `.claude/rules/`:

- [`changelog.md`](.claude/rules/changelog.md) — classify every change
  (major/minor/patch or Unreleased) and update `CHANGELOG.md` in the same
  commit; release-notes format.
- [`ddd-layers.md`](.claude/rules/ddd-layers.md) — dependency direction across
  layers.
- [`domain-models.md`](.claude/rules/domain-models.md) — immutability,
  copy-on-write, deterministic IDs in `src/Audit/Domain/**`.
- [`llm-seam.md`](.claude/rules/llm-seam.md) — `LLMClientInterface` boundary
  between Application and `symfony/ai`.
- [`php-classes.md`](.claude/rules/php-classes.md) — `final readonly`,
  interfaces/SOLID, single responsibility, Symfony components in `src/**`.
- [`testing.md`](.claude/rules/testing.md) — TDD red/green/refactor, stub vs
  mock, suite layout, mutation score.
- [`no-comments.md`](.claude/rules/no-comments.md) — no multi-line comment
  blocks; comments signal poorly-written code; fix the code instead.
