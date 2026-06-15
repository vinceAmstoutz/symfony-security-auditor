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

| Layer           | Technology                                                            |
| --------------- | --------------------------------------------------------------------- |
| Language        | PHP (see `composer.json` → `require.php`)                             |
| Framework       | Symfony (see `composer.json`)                                         |
| LLM             | symfony/ai (provider-agnostic: Anthropic, OpenAI, Mistral, Ollama, …) |
| Packaging       | symfony-bundle + Flex recipe                                          |
| Tests           | PHPUnit (Unit / Integration / EndToEnd)                               |
| Mutation        | Infection (100% MSI required)                                         |
| Static analysis | PHPStan max + Rector                                                  |
| Style           | PHP CS Fixer (@PER-CS3x0, @Symfony rulesets)                          |

## Build, Test & Lint Commands

```bash
bin/castor up
```

| Task                 | Command                                           |
| -------------------- | ------------------------------------------------- |
| Install dependencies | `bin/castor up` (runs `docker compose up --wait`) |
| Stop containers      | `bin/castor down`                                 |
| Lint (check only)    | `bin/castor lint`                                 |
| Lint + auto-fix      | `bin/castor lint:fix`                             |
| Run PHP tests        | `docker compose exec php vendor/bin/phpunit`      |
| Run mutation tests   | `docker compose exec php bin/infection`           |
| Symfony console      | `docker compose exec php bin/console <command>`   |

`bin/castor lint` runs sequentially: Prettier (check) → Markdown lint
(markdownlint-cli2) → Composer Normalize → PHP CS Fixer → Rector → PHPStan (max,
500M) → PHPUnit → Infection. `bin/castor lint:fix` auto-fixes Prettier +
Markdown lint + steps 1–3; remaining steps are check-only.

Commit messages are validated separately in CI via
[commitlint](https://commitlint.js.org/) (`commitlint.config.js`) — see
[Commit Messages](#commit-messages).

## Project Structure

```text
src/
  Audit/
    Domain/          # Pure PHP — no framework, no I/O
      Configuration/ # Typed config VOs (BundleConfiguration, AuditProfile, LLMConfiguration, …)
      Model/         # Value objects and enums (Vulnerability, AuditReport, ProjectFile, ProjectFileType, RouteAccessControl, VoterCapability, FormBinding, VulnerabilityHydrationResult, VulnerabilityDropReason, …)
      Pipeline/      # PipelineInterface, StageInterface, CoverageRecorderInterface (ports)
      Port/          # Cross-layer ports (LLMClientInterface, BatchCapableLLMClientInterface, ToolBatchCapableLLMClientInterface, LLMResponse, *PromptBuilderInterface, ProjectFileScannerInterface, AttackerCacheInterface, ContextAwareAttackerCacheInterface, ReviewerCacheInterface, AdvisoryDatabaseInterface, SecretScrubberInterface, TokenEstimatorInterface, PricingProviderInterface, RateLimiterInterface, ProgressReporterInterface, StaticPreScannerInterface, CodeSlicerInterface, ControllerAccessControlParserInterface, VoterCapabilityParserInterface, FormBindingParserInterface, GitChangedFilesResolverInterface)
        Tool/        # ToolInterface, ToolDefinition, ToolRegistry, ToolRegistryFactoryInterface
    Application/     # Orchestration — no I/O, depends only on Domain
      UseCase/       # RunAuditUseCase, EstimateAuditCostUseCase (entry points)
      Pipeline/      # AuditPipeline + Stage/{IngestionStage, MappingStage, AuditStage, PoCSynthesisStage}
      Agent/         # AttackerAgent (+ AttackerAnalysisRequest, RiskMarkerIndex, AttackerContextPromptRenderer, Chunk/{ChunkContext, ChunkContextFactory, AttackerChunkCache, ChunkCoverageRecorder, SequentialChunkAnalyzer, ConcurrentChunkAnalyzer}), ReviewerAgent (+ Review/{VerdictApplier, BatchVerdictApplier, ReviewOutcomeRecorder, ReviewerVerdictCache, CodeContextResolver, SequentialReviewAnalyzer, StructuredReviewAnalyzer, ConcurrentReviewAnalyzer, ConcurrentStructuredReviewAnalyzer, BatchReviewAnalyzer}), EscalatingAttackerAgent, AuditOrchestrator, VulnerabilityFactory, VulnerabilityCollector, RecordVulnerabilityToolFactoryInterface, ReviewCollector, RecordReviewToolFactoryInterface, PoCSynthesizer, Chunking/{ChunkingStrategy, FileChunker}
    Infrastructure/  # I/O adapters
      LLM/           # SymfonyAiLLMClient (+ RetryingPlatformInvoker, SequentialToolLoop, BatchWindowResolver, ToolConversationWavefront, PlatformResultExtractor, PlatformOptionsFactory, PlatformToolsMapper, PromptTokenEstimator), RetryPolicy, TransientFailureClassifier, CharacterBasedTokenEstimator, Delay/, RateLimit/{NullRateLimiter, TokenBucketRateLimiter, RetryAfterHeaderParser}
      FileSystem/    # ProjectFileScanner, RegexSecretScrubber, NullSecretScrubber
      Scan/          # RegexStaticPreScanner, NullStaticPreScanner, RegexCodeSlicer, NullCodeSlicer, PhpParserControllerAccessControlParser, NullControllerAccessControlParser, PhpParserVoterCapabilityParser, NullVoterCapabilityParser, PhpParserFormBindingParser, NullFormBindingParser
      Diff/          # ProcessGitChangedFilesResolver (git diff for --since)
      Prompt/        # AttackerPromptBuilder (+ SymfonyMappingContextRenderer, NumberedFileContextRenderer), ReviewerPromptBuilder
      Cache/         # FilesystemAttackerCache, NullAttackerCache, FilesystemReviewerCache, NullReviewerCache
      Advisory/      # ComposerAuditAdvisoryDatabase (default), InMemoryAdvisoryDatabase (fallback), SymfonyProcessComposerAuditRunner
      Pricing/       # StaticPricingProvider
      Progress/      # ConsoleProgressReporter, LoggerProgressReporter, NullProgressReporter, ProgressReporterHolder
      Tool/          # ReadFileTool, GrepTool, ListFilesTool, LookupAdvisoryTool, SymfonyToolRegistryFactory, RecordVulnerabilityTool, RecordVulnerabilityToolFactory, RecordReviewTool, RecordReviewToolFactory
      Report/        # ReportRenderer (console/json/sarif/html; + Template/*.txt + *.html stubs)
  Command/           # AuditCommand (Symfony Console: audit:run) + AuditCommandInput, AuditPresenter, ReportWriter, AuditExitCodeResolver, OutputFormat enum (console|json|sarif|html), Baseline (accepted-finding suppression)
  SymfonySecurityAuditorBundle.php  # Bundle class (configure + loadExtension)
tests/Phpunit/
  Unit/              # Isolated class tests (stub/mock collaborators)
  Integration/       # Wire real classes, no LLM calls
  EndToEnd/          # Full pipeline, uses stub LLM client
config/services.php  # DI wiring for all bundle services
docs/
  architecture.md    # Layer overview, data flow, domain model details
  configuration.md   # Bundle config reference
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
   priority window), injects markers + prior-iteration findings, calls LLM. By
   default (`audit.structured_collection: true`), findings come in through
   `record_vulnerability` tool calls validated by the provider against the
   tool's JSON schema; with the flag off, the attacker parses a JSON array from
   the response. With `audit.attacker_max_concurrent` > 1 (the `fast` profile
   sets 4) and a tool-batch-capable client, cache-miss chunks are analyzed
   concurrently. Optional `EscalatingAttackerAgent` runs a cheap model first and
   only escalates flagged files to the expensive model.
3. Filter — confidence ≥ 0.6
4. `ReviewerAgent` — validates each finding, may adjust severity. By default
   (`audit.reviewer_structured_collection: true`), verdicts come in through
   schema-enforced `record_review` tool calls; the explicit opt-in
   `reviewer_tools_enabled` keeps the JSON path, and `reviewer_max_concurrent`
   > 1 reviews findings concurrently (structured when the client supports tool
   > batching, JSON otherwise). Verdicts are cached across runs
   > (`FilesystemReviewerCache`) when `cache.enabled` is on; concurrent reviews
   > serve cached verdicts first and dispatch only the misses.
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
    attacker_model: 'claude-opus-4-7'
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
`scan`, `deps`, `ci`, `rate-limit`. Breaking changes: `feat!:` with
`BREAKING CHANGE:` footer.

## CI Pipeline

Six jobs must all pass before merging: **Prettier Check** (markdown formatting)
→ **Markdown Lint** (markdownlint-cli2 semantics) → **Commit Lint** (commitlint,
conventional commits) → **Lint** (Composer Normalize, PHP CS Fixer, Rector,
PHPStan max) → **Tests** (PHPUnit matrix on PHP 8.3/8.4/8.5 × Symfony
7.4/8.0/8.1) → **Mutation** (Infection, 100% MSI).

Details: [`docs/ci.md`](docs/ci.md)

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

The project follows [Semantic Versioning 2.0.0](https://semver.org). Treat every
public-API element as load-bearing: configuration keys (and their defaults),
`audit:run` arguments/options/exit codes, JSON and SARIF output schemas, Domain
ports under `src/Audit/Domain/Port/` (including `AdvisoryDatabaseInterface`),
Domain models/enums/exceptions, `RunAuditUseCase`, and the Bundle class. A
change that removes or alters any of these is a `MAJOR` and requires a
deprecation cycle.

Internal classes (`@internal` PHPDoc tag) — concrete agents, pipeline stages,
infrastructure adapters, Command collaborators — may be refactored freely in a
`MINOR`. When you add a class that is **not** an extension point, add the
`@internal` tag. When you add a public configuration key, list it in
`docs/versioning.md`.

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
