# CLAUDE.md

## Keeping This File Up to Date

Update this file in the same commit/PR only when something it states changes: a command, a gate, a layer rule, a directory added, moved or removed. What a class does belongs in its code and in `docs/architecture.md`, never here. Keep this file under 200 lines: Claude Code loads it in every session and every subagent, so adherence drops as it grows. Rules live in `.claude/rules/` and procedures in `.claude/skills/`: update them too. Never leave this file describing a state that no longer exists.

---

## Project Overview

**symfony-security-auditor**: AI-powered multi-agent security auditor for Symfony applications. Distributed as a **Symfony bundle** (`symfony-bundle` package type). Uses a dual-agent attacker/reviewer loop backed by `symfony/ai` to detect vulnerabilities and produce structured reports.

> Always check `composer.json` for authoritative dependency versions. Never rely on version numbers written here.

## Tech Stack

| Layer | Technology |
| --- | --- |
| Language | PHP (see `composer.json` → `require.php`) |
| Framework | Symfony (see `composer.json`) |
| LLM | symfony/ai (provider-agnostic: Anthropic, OpenAI, Mistral, Ollama, …) |
| Packaging | symfony-bundle + Flex recipe; standalone self-contained native binary (`box` + `static-php-cli` micro) for Linux/macOS/Windows; every push to `1.x` republishes the `snapshot` pre-release (`.github/workflows/snapshot.yaml`, building through `release.yaml` as a reusable workflow); a pull request that changes the binary's inputs runs `release.yaml`'s build matrix and smoke tests (`--version`, then `init` with an empty `PATH`, `doctor` and the bundled Composer's `composer audit`, whose output must open with its JSON) on all five targets without publishing anything, unless it changes only `composer.json`'s `require-dev` or the comments and whitespace of PHP files (the `plan` job skips the build then, through `.github/scripts/plan-binary-build.sh`, which compares each changed PHP file's code tokens) |
| Tests | PHPUnit (Unit / Integration / EndToEnd), plus the compatibility checks (`phpunit.compat.xml`, `tests/Phpunit/Compat/`): this tree against fixtures recorded from the last release, where a difference passes only once accepted with its `## [Unreleased]` CHANGELOG bullet. 100% line coverage (`MinimumLineCoverageExtension`, `tools/PHPUnit/`). The slow-test detector reports any test over 500 ms; `SlowTestGuardExtension` fails the run only past 3 × that bar (1500 ms), since one wall-clock sample on a shared CI runner is noisy. A per-test `#[MaximumDuration]` replaces the bar and loses that headroom, so use it only to raise the bar (4000 or 8000 ms) |
| Mutation | Infection (100% MSI required). `infection.json5` passes `--no-extensions`: in a coding-agent session (`CLAUDECODE`, `AI_AGENT`, …) `ergebnis/phpunit-agent-reporter` replaces PHPUnit's stdout with JSON, which Infection would read as every mutant killed, a fake 100% MSI. It also keeps the coverage and slow-test gates out of per-mutant runs |
| Static analysis | PHPStan max + phpstan-strict-rules + custom rules (`FinalRule`, `MaxParameterCountRule`, `NoEmptyCatchRule`, `NoSilencingErrorHandlerRule`, `ForbiddenTestAttributeRule`, `SprintfOverConcatRule`, in `tools/PHPStan/`) + spaze rules + hand-picked symplify rules (`composer.json` keeps `symplify/phpstan-rules` out of `phpstan/extension-installer`, which from 14.14 would register every symplify rule set; `phpstan.dist.neon` includes only its `services.neon` and lists each rule) + Rector |
| API compatibility | roave/backward-compatibility-check against the last release of the line (`tools/bc-check/`, its own Composer project installing into `var/bc-check/vendor`; accepted breaks in `.roave-backward-compatibility-check.xml`); its install runs `tools/BcCheck/RoaveEnumCaseAdditions`, which removes the cases added to an enum from the changes Roave's enum check returns, as `docs/versioning.md` allows. It fails when a Roave release no longer returns them the way it expects |
| Layer conformance | deptrac (DDD layer rules + the `SymfonyProfile` framework boundary, in `deptrac.yaml`) |
| Complexity | tomasvotruba/cognitive-complexity (function ≤ 7, class ≤ 40) |
| Dead code | rector/swiss-knife (`check-commented-code`, `check-conflicts`) |
| Style | PHP CS Fixer (@PER-CS3x0, @Symfony rulesets); Prettier for Markdown, one line per paragraph and list item, never hard-wrapped (`proseWrap: never`, checked by the Prettier Check job); no em dash and no comma before "and" in Markdown prose, PHP comments and docblocks (`.claude/rules/prose-style.md`), no multi-line `//` block, history or first person in PHP comments (`.claude/rules/no-comments.md`), both checked by `.github/scripts/check-prose.sh` in the Lint job |
| CI/CD security | zizmor (static analysis for GitHub Actions: scans `.github/workflows/` + `action.yml`) |

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
| Markdown check only | `bin/castor lint:docs` (formatting and prose of Markdown and PHP comments, fast pre-push check) |
| Run PHP tests | `docker compose exec php vendor/bin/phpunit` |
| Run mutation tests | `bin/castor lint` (its Infection step mirrors CI's flags; see below) |
| Score detection quality | `bin/castor eval` (audits a ground-truth fixture, reports precision/recall) |
| Run the compatibility checks | `docker compose exec php vendor/bin/phpunit -c phpunit.compat.xml` (see [CONTRIBUTING.md → Compatibility Checks](CONTRIBUTING.md#compatibility-checks)) |
| Prepare a release | `bin/castor release:prepare X.Y.Z Codename` (changelog promotion and every version pin), then `bin/castor release:check X.Y.Z`, which Release Guard also runs on the tag. See `/release` |
| Record their fixtures from a release | `bin/castor compat:record X.Y.Z` (checks the tag out under `var/compat/`, runs the recorders in `tools/Compat/`) |
| Draft accepted differences after 1.x moved | `bin/castor compat:draft` (replays every scenario, prints a draft entry per difference not yet accepted) |
| Refresh the compatibility job's lock | `bin/castor compat:lock` (after a `composer.json` change) |
| Symfony console | `docker compose exec php bin/console <command>` |

In a Claude Code cloud session there is no Docker and the GitHub proxy refuses API downloads for any repository not attached to the session, so a plain `composer install` fails with `Could not authenticate against github.com`. Install from git instead, seeding the one dist-only package, `phpstan/phpstan`, into Composer's cache from a git fetch first, then run `vendor/bin/phpunit` directly:

```bash
REF=$(php -r '$l = json_decode(file_get_contents("composer.lock"), true); foreach (array_merge($l["packages"], $l["packages-dev"]) as $p) { if ("phpstan/phpstan" === $p["name"]) { echo $p["dist"]["reference"]; } }') && TMP=$(mktemp -d) && git -C "$TMP" init -q && git -C "$TMP" fetch -q --depth 1 https://github.com/phpstan/phpstan "$REF" && CACHE="$(composer config cache-files-dir)/phpstan/phpstan" && mkdir -p "$CACHE" && git -C "$TMP" archive --format=zip --prefix=phpstan/ -o "$CACHE/$(php -r "echo sha1('https://api.github.com/repos/phpstan/phpstan/zipball/$REF');").zip" FETCH_HEAD && COMPOSER_ALLOW_SUPERUSER=1 composer install --prefer-source --no-interaction
```

`bin/castor lint` runs sequentially: Prettier (check) → Markdown lint (markdownlint-cli2) → Composer Normalize → PHP CS Fixer → Rector → PHPStan (max, 500M) → Deptrac (DDD layers) → Swiss Knife (commented-code + merge-conflict scan) → Install script tests (`tests/Shell/install_script_test.sh`) → Pull request check tests (`tests/Shell/pull_request_check_test.sh`) → Review suggestion tests (`tests/Shell/review_suggestions_test.sh`) → Binary build plan tests (`tests/Shell/plan_binary_build_test.sh`) → Release script tests (`tests/Shell/release_script_test.sh`) → Claude hook tests (`tests/Shell/claude_hooks_test.sh`) → Changelog check (`tests/Shell/changelog_check_test.sh`, then `.github/scripts/check-changelog.sh` on `CHANGELOG.md`) → Prose check (`tests/Shell/prose_check_test.sh`, then `.github/scripts/check-prose.sh` on every tracked Markdown file and the comments of every tracked PHP file) → PHPUnit → Infection. `bin/castor lint:fix` auto-fixes steps 1-5 (Prettier, Markdown lint, Composer Normalize, PHP CS Fixer, Rector); the remaining steps are check-only.

Run Infection **through `bin/castor lint`**, never as a bare `bin/infection`. The task's PHPUnit step emits the `--coverage-clover`/`--coverage-xml`/`--log-junit` set that its Infection step then reuses via `--coverage=build/coverage --skip-initial-tests --min-msi=100 --min-covered-msi=100`, matching `.github/workflows/ci.yaml`; invoking `bin/infection` with ad-hoc flags has twice reported a green 100% MSI on a commit CI then rejected. Note that a single green run is still not proof of CI parity: Infection rewrites `phpunit.dist.xml` to force `executionOrder="defects,random"` while disabling result caching, so test order is effectively random per invocation (see #275).

Commit messages are validated separately in CI via [commitlint](https://commitlint.js.org/) (`commitlint.config.mjs`). See [Commit Messages](#commit-messages).

## Project Structure

```text
src/
  Audit/
    Domain/            # Pure PHP: no framework, no I/O
      Configuration/   # Typed configuration value objects
      Model/           # Value objects and enums (Vulnerability, AuditReport, SymfonyMapping, …); public factories use `of()`, the wide `create()` is `@deprecated`
      Exception/       # Domain exceptions
      Pipeline/        # Pipeline, stage and coverage-recorder ports
      Port/            # Cross-layer ports (LLMClientInterface, LLMResponse, scanners, caches, parsers, …) + `@internal` null-object defaults
        Tool/          # Tool ports (ToolInterface, RecordingToolInterface, ToolRegistry)
    Application/       # Orchestration: no I/O, depends only on Domain
      UseCase/         # RunAuditUseCase, EstimateAuditCostUseCase (entry points)
      Scan/            # Narrowing the scanned surface to the `--path` values
      Pipeline/        # AuditPipeline + its stages
      Agent/           # AttackerAgent, ReviewerAgent, EscalatingAttackerAgent, AuditOrchestrator, chunking, collectors, PoC/fix synthesizers
    Infrastructure/    # I/O adapters implementing Domain ports
      LLM/             # SymfonyAiLLMClient (the only namespace importing symfony/ai), retries, rate limits, token estimators
        WorkloadIdentity/ # Anthropic workload identity federation
      FileSystem/      # Project file scanner, secret scrubber, symlink-safe file writers
      Scan/            # Static pre-scanner, SARIF import, code slicer, Symfony source and security-config parsers
      Diff/            # git diff for `--since`
      Prompt/          # Attacker and reviewer prompt builders, attacker skills
      Cache/           # Attacker and reviewer caches
      Advisory/        # composer audit advisory database
      Pricing/         # models.dev pricing
      Progress/        # Progress reporters
      Tool/            # File tools, advisory lookup, record_vulnerability / record_review tools
      Config/          # Standalone configuration, credential store, platform and project-config guards, bundle config nodes
      Bridge/          # Provider bridge installer of the standalone binary
      Patch/           # Suggested fixes read as unified diffs
      Report/          # One renderer per output format + templates
      SelfUpdate/      # self-update and release channels
  Command/             # audit:run (alias audit), audit:diff, audit:trend, audit:baseline, auth:*, init, doctor, self-update, mcp:serve: thin commands + their collaborators
  Standalone/          # The standalone binary: application, container, bridge-tree loading
  SymfonySecurityAuditorBundle.php
tests/Phpunit/         # Unit/, Integration/, EndToEnd/ (see .claude/rules/testing.md); Compat/ (phpunit.compat.xml, see CONTRIBUTING.md)
tests/Shell/           # POSIX shell tests for install.sh, .github/scripts and .claude/hooks
tools/                 # Custom PHPStan rules, PHPUnit extensions, compatibility recorders, eval, bc-check project
config/services.php    # DI wiring for all bundle services
docs/                  # architecture.md, configuration.md, cost-and-performance.md, extending.md, ci.md, diagrams.md, faq.md, switching-standalone-bundle.md, troubleshooting.md, versioning.md
```

What each class does lives in its code and in [`docs/architecture.md`](docs/architecture.md): find a class with Grep or Glob instead of listing it here.

## Architecture: DDD Layers

Strict DDD layering under `src/Audit/`. Infrastructure never leaks into Domain or Application.

```text
Command → Application → Domain ← Infrastructure (implements ports)
```

**`LLMClientInterface`** is the sole seam between Application and LLM I/O. `AttackerAgent` and `ReviewerAgent` never import any `symfony/ai` type directly.

**Dual-agent loop** (up to 3 iterations, stops earlier when no new findings):

1. (optional) `StaticPreScanner` tags files with deterministic risk markers (the prompt lists the first 20 of a pattern per file and counts the rest); (optional) `CodeSlicer` trims large files to security-relevant lines
2. `AttackerAgent`: chunks files (default `feature` strategy: a controller with its entity/repository/form/voter/templates together; `type` for the legacy priority window; API Platform `#[ApiResource]` classes classify as `api_resource` with their own skill block), injects markers + prior-iteration findings, calls LLM. By default (`audit.structured_collection: true`), findings come in through `record_vulnerability` tool calls validated by the provider against the tool's JSON schema; with the flag off, the attacker parses a JSON array from the response. With `audit.attacker_max_concurrent` > 1 (the `fast` profile sets 4) and a tool-batch-capable client, cache-miss chunks are analyzed concurrently. Optional `EscalatingAttackerAgent` runs a cheap model first and only escalates flagged files to the expensive model, which receives the cheap findings on each chunk's own files as unverified `candidateFindings` to confirm, refine or discard, never as reviewer-validated context; a cheap finding on a file the deep pass judged and did not re-report is dropped.
3. Filter: confidence ≥ 0.6
4. `ReviewerAgent`: validates each finding, may adjust severity. By default (`audit.reviewer_structured_collection: true`), verdicts come in through schema-enforced `record_review` tool calls; the explicit opt-in `reviewer_tools_enabled` keeps the JSON path and `reviewer_max_concurrent`
   > 1 reviews findings concurrently (structured when the client supports tool batching, JSON otherwise). Verdicts are cached across runs (`FilesystemReviewerCache`) when `cache.enabled` is on, except one given at the tool-call limit after reading files, which triage memory leaves out too; every review mode, concurrent and batched (`reviewer_batch_size > 1`) alike, serves cached verdicts first and dispatches/batches only the misses.
5. Deduplicate → persist to `AuditContext`

After the loop, the optional `PoCSynthesisStage` runs (concrete reproduction artifacts for high-severity findings).

Full details: [`docs/architecture.md`](docs/architecture.md)

## Bundle Configuration

One key is enough (`model: 'claude-opus-5-5'` under `symfony_security_auditor:`). `profile: fast | balanced | thorough` sets every cost knob at once, explicit keys always winning; `attacker_model` and `reviewer_model` split the two agents across models. Swapping LLM providers takes only a `config/packages/ai.yaml` change, no code change. Full reference: [`docs/configuration.md`](docs/configuration.md).

## Commit Messages

Format: `<type>[optional scope]: <description>` ([Conventional Commits](https://www.conventionalcommits.org/)), checked by commitlint. Types: `feat` (new user-facing feature), `fix`, `refactor` (neither fix nor feature), `test`, `docs`, `chore` (maintenance, tooling), `build` (build system, dependencies), `ci`, `perf`. Common scopes: `agent`, `pipeline`, `domain`, `llm`, `command`, `bundle`, `standalone`, `scan`, `deps`, `ci`, `rate-limit`, `release`. Breaking changes: `feat!:` with a `BREAKING CHANGE:` footer.

## Pull Requests

Open or edit a pull request with the [`pull-request`](.claude/skills/pull-request/SKILL.md) skill: it fills in the template, keeps the title to 50 characters and the Summary to 750, then runs `.github/scripts/check-pull-request.sh` (the `Pull request target` check) before anything is sent. Every PR is squash-merged, except the `chore: release X.Y.Z` merge of `<N>.x` into `main`, which takes a merge commit (see the [`release`](.claude/skills/release/SKILL.md) skill).

## CI Pipeline

Eight jobs must all pass before merging: **Prettier Check** (markdown formatting) → **Markdown Lint** (markdownlint-cli2 semantics) → **Commit Lint** (commitlint, conventional commits) → **Lint** (Composer Normalize, PHP CS Fixer, Rector, PHPStan max, Deptrac, Swiss Knife, `composer audit`, install-script, pull-request-check, review-suggestion, binary-build-plan, release-script, Claude-hook, changelog-check and prose-check shell tests, plus the changelog and prose checks themselves) → **zizmor** (GitHub Actions security scan via [`zizmorcore/zizmor-action`](https://github.com/zizmorcore/zizmor-action), SARIF uploaded to Code Scanning) → **Tests + Mutation** (PHPUnit matrix on PHP 8.3/8.4/8.5/8.6 × Symfony 7.4/8.1, 8.1 on PHP 8.4+ only, with 100% coverage, then Infection 100% MSI; coverage uploads to Codecov and the mutation report uploads to the Stryker dashboard via Infection's `stryker` logger; the badge tracks `main` and same-repo branches publish their own report; when a leg fails, its escaped and timed-out mutants are printed in the job log and its Infection logs (`infection/`) are kept as a 7-day `infection-logs-*` artifact) → **Compatibility** (`phpunit.compat.xml` on PHP 8.3 and Symfony 7.4: this tree against the fixtures recorded from the last release, see [CONTRIBUTING.md → Compatibility Checks](CONTRIBUTING.md#compatibility-checks)) → **API compatibility** (roave/backward-compatibility-check, from `tools/bc-check/`, `--from` the newest `X.Y.Z` tag of the line the change is headed for; accepted breaks in `.roave-backward-compatibility-check.xml`, each tied to its `## [Unreleased]` CHANGELOG bullet; a case added to an enum does not fail it). On a push, a newer commit to the same branch cancels the run of the one before it, so only the latest `1.x` or `main` commit gets the full-codebase mutation run; pull request runs are never cancelled. Every pull request also runs **Pull request target** (`.github/workflows/pr-target.yaml`), which fails on a title, description or base branch that breaks [Pull Requests](#pull-requests). A pull request into a `*.x` branch also runs **Merge guard** (`.github/workflows/merge-guard.yaml`): **Signed commits** fails on a commit GitHub did not verify. **Base branch is green** waits for the pull request's CI run to finish, then fails while the base branch's latest completed, non-cancelled push run of CI did not succeed, unless the pull request is labelled `fixes-<base branch>` (`fixes-1.x`, `fixes-2.x`) and its own CI passes. Neither re-runs when the base branch changes state: push again or re-run the job.

Details: [`docs/ci.md`](docs/ci.md)

## Security Posture

This project is itself a security tool: it must not ship the vulnerability classes it hunts. Command and code execution is therefore banned at the static-analysis level: `phpstan.dist.neon` explicitly `includes:` the `spaze/phpstan-disallowed-calls` `disallowed-execution-calls.neon` ruleset, forbidding raw execution sinks (`exec`, `shell_exec`, `system`, `passthru`, `proc_open`, `popen`, `pcntl_exec`, backtick operator, `eval`). `eval` is double-locked: also forbidden via the `ForbiddenNodeRule` `Eval_` entry.

**This ban is a deliberate manual opt-in, not a freebie.** Although `phpstan/extension-installer` is installed, it only auto-loads the package's `extension.neon`, which registers the rule engine with **every** `disallowed*` array empty (zero bans by default). The curated `disallowed-execution-calls.neon` set is wired in by hand on line 2 of `phpstan.dist.neon`: delete that line and the ban silently disappears with no error. Keep it.

Consequences for contributors:

- **All subprocess work routes through Symfony `Process`** (e.g. `ProcessGitChangedFilesResolver`, `SymfonyProcessComposerAuditRunner`), never a raw exec call: `Process` does not invoke a shell by default, so there is no argument-interpolation command-injection surface.
- Never satisfy a disallowed-call error with an `allowIn`/exclusion entry; route through `Process` instead. Suppressing this gate is covered by the [Never Silence Quality Gates](#5-never-silence-quality-gates) rule.

The same "don't ship what we hunt" posture applies to the project's own GitHub Actions: a dedicated **zizmor** job scans `.github/workflows/` and `action.yml` on every push and pull request; every third-party `uses:` (including `zizmor-action` itself) is pinned to a commit SHA (never a mutable tag) for the same reason `Process` is required over raw exec: a moving reference is an unreviewed-code-execution surface. These pins aren't manually-maintained dead weight: the existing `github-actions` entry in `.github/dependabot.yaml` recognizes the `# vX.Y.Z` trailing-comment convention and opens a PR bumping both the SHA and the comment whenever a pinned action releases. Both `dependabot.yaml` update entries also carry a 7-day `cooldown` (`default-days: 7`), so Dependabot never opens a bump PR for a release younger than a week (the window in which a compromised or yanked supply-chain release is typically caught), which also clears zizmor's `dependabot-cooldown` audit.

## Behavioral Guidelines

### 1. Think Before Coding

Before implementing: state assumptions explicitly, surface tradeoffs, present multiple interpretations rather than picking silently. When something is unclear and neither the code, the docs nor the history settles it, note the question, carry on with what is clear and ask the open questions together. Ask before writing code only when the answer changes the public API (§6).

### 2. Simplicity First

Minimum code that solves the problem. No speculative features, no abstractions for single-use code, no error handling for impossible scenarios.

### 3. Surgical Changes

Touch only what the request requires. Don't improve adjacent code. Match existing style. If you notice unrelated dead code, mention it; don't delete it. Remove only imports/variables that YOUR changes made unused.

### 4. Goal-Driven Execution

Transform tasks into verifiable goals. For multistep tasks, state a brief plan with a verify step for each.

### 5. Never Silence Quality Gates

Never bypass static analysis or mutation testing via suppression annotations or config opt-outs. **Forbidden** (non-exhaustive):

- PHPStan: `@phpstan-ignore`, `@phpstan-ignore-line`, `@phpstan-ignore-next-line`, `ignoreErrors` entries in `phpstan.dist.neon`, baseline files.
- Infection: `@infection-ignore-all`, `@infection-ignore-all-for`, per-mutator `ignore` entries in `infection.json5`, `ignoreSourceCodeByRegex`.
- PHPUnit / coverage: `@codeCoverageIgnore*`, `@requires`/`markTestSkipped` used to dodge a failing test, `@group` used to exclude from CI.
- PHP CS Fixer / Rector: `@phpcs:ignore`, `// @phpstan-ignore`, `\Rector\Skip`, blanket `--no-check`.

The `.claude/hooks/block-quality-gate-suppressions.sh` hook (it needs `jq`) refuses an Edit or Write that adds `@phpstan-ignore`, `@infection-ignore`, `@codeCoverageIgnore`, `markTestSkipped(` or `expectNotToPerformAssertions(` to a PHP file. If a tool flags something, **fix the underlying code**. Genuine exceptions (a real false positive, a library bug) require a PR-description justification and a linked issue tracking removal, never silent suppression.

### 6. Backward Compatibility

The project follows [Semantic Versioning 2.0.0](https://semver.org) and, for its PHP API surface, the [Symfony Backward Compatibility promise](https://symfony.com/doc/current/contributing/code/bc.html) (`@internal` code is exempt). Treat every public-API element as load-bearing: configuration keys (and their defaults), the `audit:run` command (and its `audit` alias) arguments/options/exit codes, JSON and SARIF output schemas, Domain ports under `src/Audit/Domain/Port/` (including `AdvisoryDatabaseInterface`), Domain models/enums/exceptions, `RunAuditUseCase` and the Bundle class. A change that removes or alters any of these is a `MAJOR` and requires a deprecation cycle.

Internal classes (`@internal` PHPDoc tag: concrete agents, pipeline stages, infrastructure adapters, Command collaborators) may be refactored freely in a `MINOR`. When you add a class that is **not** an extension point, add the `@internal` tag. When you add a public configuration key, list it in `docs/versioning.md` and add it to `resources/schema.json` (the JSON Schema that powers editor autocompletion for `symfony_security_auditor.yaml`).

Canonical policy: [`docs/versioning.md`](docs/versioning.md). To change any of it, follow the [`public-api-change`](.claude/skills/public-api-change/SKILL.md) skill.

## Rules and Skills

Rules in `.claude/rules/` load on their own. All but `ddd-layers.md` and `prose-style.md` are scoped to paths: they load only when the Read, Edit or Write tool opens a matching file, while a Bash `sed`, `cat` or `grep` and the Grep tool load nothing. **Open a file under `src/`, `tests/` or `CHANGELOG.md` with the Read tool (`offset`/`limit` keeps it short) before changing it.**

| Rule | Loads for | Covers |
| --- | --- | --- |
| [`ddd-layers.md`](.claude/rules/ddd-layers.md) | every session | dependency direction across layers, the `SymfonyProfile` boundary |
| [`prose-style.md`](.claude/rules/prose-style.md) | every session | no em dash and no comma before `and` in anything written here, checked by `.github/scripts/check-prose.sh` |
| [`no-comments.md`](.claude/rules/no-comments.md) | `src/**`, `tests/**`, `tools/**` | no comment blocks, fix the code instead; a docblock states only the contract |
| [`php-classes.md`](.claude/rules/php-classes.md) | `src/**` | `final readonly` and its opt-outs, interfaces/SOLID, one file one thing, the 5-parameter cap, custom exceptions, Symfony components first |
| [`domain-models.md`](.claude/rules/domain-models.md) | `src/Audit/Domain/**` | immutability, copy-on-write, deterministic IDs and fingerprints, what adding an enum case requires |
| [`llm-seam.md`](.claude/rules/llm-seam.md) | agents, Domain ports, `Infrastructure/LLM/` | the `LLMClientInterface` boundary and how agents treat provider failures |
| [`testing.md`](.claude/rules/testing.md) | `src/**`, `tests/**` | TDD, stubs vs mocks, suite layout, forbidden test attributes, mutation score |
| [`changelog.md`](.claude/rules/changelog.md) | `CHANGELOG.md` | classifying a change, the sections, the one-line entry format |

Every behavior-affecting change updates `CHANGELOG.md` in the same commit; docs-only, CI-only and pure-tooling changes are exempt.

Skills in `.claude/skills/` hold the procedures. Claude loads one when its task comes up, or you invoke it by name:

| Skill | Use it to |
| --- | --- |
| [`/pull-request`](.claude/skills/pull-request/SKILL.md) | open or edit a PR that passes the `Pull request target` check |
| [`/public-api-change`](.claude/skills/public-api-change/SKILL.md) | add or change a configuration key, a command option or exit code, a report field, a Domain port or model |
| [`/triage-findings`](.claude/skills/triage-findings/SKILL.md) | process an external review or audit report: turn each finding into a failing test or reject it |
| [`/release`](.claude/skills/release/SKILL.md) | cut release X.Y.Z, only when asked: it never loads on its own |
