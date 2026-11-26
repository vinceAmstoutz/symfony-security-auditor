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
| Packaging | symfony-bundle + Flex recipe; standalone self-contained native binary (`box` + `static-php-cli` micro) for Linux/macOS/Windows; every push to `1.x` republishes the `snapshot` pre-release (`.github/workflows/snapshot.yaml`, building through `release.yaml` as a reusable workflow) |
| Tests | PHPUnit (Unit / Integration / EndToEnd), plus the compatibility checks (`phpunit.compat.xml`, `tests/Phpunit/Compat/`), which compare this tree with fixtures recorded from the last release and fail on any difference not accepted with its `## [Unreleased]` CHANGELOG bullet; 100% line coverage enforced via the custom `MinimumLineCoverageExtension` (`tools/PHPUnit/`); the report-only `ergebnis/phpunit-slow-test-detector` surfaces tests over its `maximum-duration` (500 ms), and `SlowTestGuardExtension` (`tools/PHPUnit/`) derives its gate from that same threshold — read straight from the detector's config, single source of truth — multiplying it by `GUARD_HEADROOM_FACTOR` (3, i.e. 1500 ms) before failing the run, because one wall-clock sample on a shared CI runner can push a 3 ms test past a 500 ms bar; the report still surfaces everything over 500 ms and per-test `#[MaximumDuration]` overrides replace the bar outright — which is why overrides only ever _raise_ it (every one in the suite is 4000 or 8000 ms): an override below the shared bar opts that test out of the headroom and turns one unlucky wall-clock sample into a red build |
| Mutation | Infection (100% MSI required); `infection.json5` sets `testFrameworkOptions: "--no-extensions"` because Infection decides kill-vs-escape by parsing PHPUnit's stdout, and `ergebnis/phpunit-agent-reporter` replaces that stdout with a JSON report whenever it detects a coding-agent environment variable (`CLAUDECODE`, `AI_AGENT`, `CURSOR_AGENT`, …) — Infection then reads every mutant as killed and reports 100% MSI unconditionally, so a run inside an agent session silently proves nothing. `--no-extensions` also keeps the coverage and slow-test gates out of per-mutant runs, where they never belonged |
| Static analysis | PHPStan max + phpstan-strict-rules + custom rules (`FinalRule`, `MaxParameterCountRule`, `NoEmptyCatchRule`, `NoSilencingErrorHandlerRule`, `ForbiddenTestAttributeRule`, `SprintfOverConcatRule` — in `tools/PHPStan/`) + spaze rules + hand-picked symplify rules (`composer.json` keeps `symplify/phpstan-rules` out of `phpstan/extension-installer`, which from 14.14 would register every symplify rule set; `phpstan.dist.neon` includes only its `services.neon` and lists each rule) + Rector |
| API compatibility | roave/backward-compatibility-check against the last release of the line (`tools/bc-check/`, its own Composer project installing into `var/bc-check/vendor`; accepted breaks in `.roave-backward-compatibility-check.xml`) |
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
| Run the compatibility checks | `docker compose exec php vendor/bin/phpunit -c phpunit.compat.xml` (see [CONTRIBUTING.md → Compatibility Checks](CONTRIBUTING.md#compatibility-checks)) |
| Record their fixtures from a release | `bin/castor compat:record X.Y.Z` (checks the tag out under `var/compat/`, runs the recorders in `tools/Compat/`) |
| Draft accepted differences after 1.x moved | `bin/castor compat:draft` (replays every scenario, prints a draft entry per difference not yet accepted) |
| Refresh the compatibility job's lock | `bin/castor compat:lock` (after a `composer.json` change) |
| Symfony console | `docker compose exec php bin/console <command>` |

`bin/castor lint` runs sequentially: Prettier (check) → Markdown lint (markdownlint-cli2) → Composer Normalize → PHP CS Fixer → Rector → PHPStan (max, 500M) → Deptrac (DDD layers) → Swiss Knife (commented-code + merge-conflict scan) → Install script tests (`tests/Shell/install_script_test.sh`) → Pull request check tests (`tests/Shell/pull_request_check_test.sh`) → Changelog check (`tests/Shell/changelog_check_test.sh`, then `.github/scripts/check-changelog.sh` on `CHANGELOG.md`) → PHPUnit → Infection. `bin/castor lint:fix` auto-fixes steps 1–3 (Prettier, Markdown lint, Composer Normalize); the remaining steps are check-only.

Run Infection **through `bin/castor lint`**, never as a bare `bin/infection`. The task's PHPUnit step emits the `--coverage-clover`/`--coverage-xml`/`--log-junit` set that its Infection step then reuses via `--coverage=build/coverage --skip-initial-tests --min-msi=100 --min-covered-msi=100`, matching `.github/workflows/ci.yaml`; invoking `bin/infection` with ad-hoc flags has twice reported a green 100% MSI on a commit CI then rejected. Note that a single green run is still not proof of CI parity: Infection rewrites `phpunit.dist.xml` to force `executionOrder="defects,random"` while disabling result caching, so test order is effectively random per invocation — see #275.

Commit messages are validated separately in CI via [commitlint](https://commitlint.js.org/) (`commitlint.config.mjs`) — see [Commit Messages](#commit-messages).

## Project Structure

Condensed map; the full annotated tree (every class and its role) is in [`docs/project-structure.md`](docs/project-structure.md) — update it when classes move or are added.

```text
src/
  Audit/
    Domain/          # Pure PHP
      Configuration/ # Typed config VOs
      Model/         # Value objects and enums
      Exception/     # Domain exceptions
      Pipeline/      # PipelineInterface, StageInterface, CoverageRecorderInterface
      Port/          # Cross-layer ports
        Tool/        # ToolInterface, RecordingToolInterface
    Application/     # Orchestration
      UseCase/       # RunAuditUseCase, EstimateAuditCostUseCase
      Scan/          # ScanPathFilter
      Pipeline/      # AuditPipeline + Stage/{IngestionStage, MappingStage, DependencyExpansionStage,…
      Agent/         # AttackerAgent
    Infrastructure/  # I/O adapters
      LLM/           # SymfonyAiLLMClient
      FileSystem/    # ProjectFileScanner
      Scan/          # RegexStaticPreScanner, SarifImportingPreScanner
      Diff/          # ProcessGitChangedFilesResolver
      Prompt/        # AttackerPromptBuilder
      Cache/         # FilesystemAttackerCache, NullAttackerCache, FilesystemReviewerCache, NullReviewerCache
      Advisory/      # ComposerAuditAdvisoryDatabase
      Pricing/       # ModelsDevPricingProvider
      Progress/      # ConsoleProgressReporter
      Tool/          # ReadFileTool, GrepTool, ListFilesTool, LookupAdvisoryTool, SymfonyToolRegistryFactory,…
      Config/        # Standalone configuration: XdgConfigPathResolver, StandaloneConfigFileReader
      Bridge/        # ComposerBridgeInstaller
      Report/        # ReportRendererInterface
      SelfUpdate/    # SelfUpdater, ProcessReleaseClient, RunningBinaryLocator,…
  Command/           # AuditCommand
  Standalone/        # The standalone binary: StandaloneApplication
  SymfonySecurityAuditorBundle.php  # Bundle class
tests/Phpunit/
  Unit/              # Isolated class tests
  Integration/       # Wire real classes, no LLM calls
  EndToEnd/          # Full pipeline, uses stub LLM client
  Compat/            # Compatibility checks
tests/Shell/         # POSIX shell tests
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

1. (optional) `StaticPreScanner` tags files with deterministic risk markers (the prompt lists the first 20 of a pattern per file and counts the rest); (optional) `CodeSlicer` trims large files to security-relevant lines
2. `AttackerAgent` — chunks files (default `feature` strategy: a controller with its entity/repository/form/voter/templates together; `type` for the legacy priority window; API Platform `#[ApiResource]` classes classify as `api_resource` with their own skill block), injects markers + prior-iteration findings, calls LLM. By default (`audit.structured_collection: true`), findings come in through `record_vulnerability` tool calls validated by the provider against the tool's JSON schema; with the flag off, the attacker parses a JSON array from the response. With `audit.attacker_max_concurrent` > 1 (the `fast` profile sets 4) and a tool-batch-capable client, cache-miss chunks are analyzed concurrently. Optional `EscalatingAttackerAgent` runs a cheap model first and only escalates flagged files to the expensive model, which receives the cheap findings on each chunk's own files as unverified `candidateFindings` to confirm, refine or discard — never as reviewer-validated context; a cheap finding on a file the deep pass judged and did not re-report is dropped.
3. Filter — confidence ≥ 0.6
4. `ReviewerAgent` — validates each finding, may adjust severity. By default (`audit.reviewer_structured_collection: true`), verdicts come in through schema-enforced `record_review` tool calls; the explicit opt-in `reviewer_tools_enabled` keeps the JSON path, and `reviewer_max_concurrent`
   > 1 reviews findings concurrently (structured when the client supports tool batching, JSON otherwise). Verdicts are cached across runs (`FilesystemReviewerCache`) when `cache.enabled` is on, except one given at the tool-call limit after reading files, which triage memory leaves out too; every review mode — concurrent and batched (`reviewer_batch_size > 1`) alike — serves cached verdicts first and dispatches/batches only the misses.
5. Deduplicate → persist to `AuditContext`

After the loop, the optional `PoCSynthesisStage` runs (concrete reproduction artifacts for high-severity findings).

Full details: [`docs/architecture.md`](docs/architecture.md)

## Bundle Configuration

Minimal:

```yaml
symfony_security_auditor:
    model: 'claude-opus-5-5'
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
    reviewer_model: 'claude-haiku-5-5'
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

Eight jobs must all pass before merging: **Prettier Check** (markdown formatting) → **Markdown Lint** (markdownlint-cli2 semantics) → **Commit Lint** (commitlint, conventional commits) → **Lint** (Composer Normalize, PHP CS Fixer, Rector, PHPStan max, Deptrac, Swiss Knife, `composer audit`, install-script, pull-request-check and changelog-check shell tests, plus the changelog check itself) → **zizmor** (GitHub Actions security scan via [`zizmorcore/zizmor-action`](https://github.com/zizmorcore/zizmor-action), SARIF uploaded to Code Scanning) → **Tests + Mutation** (PHPUnit matrix on PHP 8.3/8.4/8.5 × Symfony 7.4/8.1, 8.1 on PHP 8.4+ only, with 100% coverage, then Infection 100% MSI; coverage uploads to Codecov and the mutation report uploads to the Stryker dashboard via Infection's `stryker` logger — the badge tracks `main`, and same-repo branches publish their own report; when a leg fails, its escaped and timed-out mutants are printed in the job log and its Infection logs (`infection/`) are kept as a 7-day `infection-logs-*` artifact) → **Compatibility** (`phpunit.compat.xml` on PHP 8.3 and Symfony 7.4: this tree against the fixtures recorded from the last release, see [CONTRIBUTING.md → Compatibility Checks](CONTRIBUTING.md#compatibility-checks)) → **API compatibility** (roave/backward-compatibility-check, from `tools/bc-check/`, `--from` the newest `X.Y.Z` tag of the line the change is headed for; accepted breaks in `.roave-backward-compatibility-check.xml`, each tied to its `## [Unreleased]` CHANGELOG bullet). On a push, a newer commit to the same branch cancels the run of the one before it, so only the latest `1.x` or `main` commit gets the full-codebase mutation run; pull request runs are never cancelled. Every pull request also runs **Pull request target** (`.github/workflows/pr-target.yaml`), which fails on a title, description or base branch that breaks [Pull Requests](#pull-requests).

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

- [`changelog.md`](.claude/rules/changelog.md) — classify every change (major/minor/patch or Unreleased) and update `CHANGELOG.md` in the same commit; the end-user entry format and sections (`Security 🔒` only for a CVE/GHSA fix, enforced by `check-changelog.sh`); GitHub release notes are generated from the changelog.
- [`ddd-layers.md`](.claude/rules/ddd-layers.md) — dependency direction across layers.
- [`domain-models.md`](.claude/rules/domain-models.md) — immutability, copy-on-write, deterministic IDs in `src/Audit/Domain/**`.
- [`llm-seam.md`](.claude/rules/llm-seam.md) — `LLMClientInterface` boundary between Application and `symfony/ai`.
- [`php-classes.md`](.claude/rules/php-classes.md) — `final readonly`, interfaces/SOLID, single responsibility, Symfony components in `src/**`.
- [`testing.md`](.claude/rules/testing.md) — TDD red/green/refactor, stub vs mock, suite layout, mutation score.
- [`no-comments.md`](.claude/rules/no-comments.md) — no multi-line comment blocks; comments signal poorly-written code; fix the code instead.
