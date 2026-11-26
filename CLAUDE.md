# CLAUDE.md

## Keeping This File Up to Date

Update the relevant section in the same commit/PR whenever the project evolves. Rules scoped to specific paths live in `.claude/rules/` — update them too. Never leave this file describing a state that no longer exists.

---

## Project Overview

**symfony-security-auditor** — AI-powered multi-agent security auditor for Symfony applications. Distributed as a **Symfony bundle** (`symfony-bundle` package type). Uses a dual-agent attacker/reviewer loop backed by `symfony/ai` to detect vulnerabilities and produce structured reports.

> Always check `composer.json` for authoritative dependency versions — never rely on version numbers written here.

## Tech Stack

PHP and Symfony (versions in `composer.json`), provider-agnostic `symfony/ai`, packaged as a Symfony bundle plus a standalone binary. Quality gates: PHPUnit 100% line coverage, Infection 100% MSI, PHPStan max, deptrac, Rector, PHP CS Fixer, Prettier. Tool-by-tool reference: [`docs/tooling.md`](docs/tooling.md).

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
| Run mutation tests | `bin/castor lint` (its Infection step mirrors CI's flags; see the rule below) |
| Score detection quality | `bin/castor eval` (audits a ground-truth fixture, reports precision/recall) |
| Run the compatibility checks | `docker compose exec php vendor/bin/phpunit -c phpunit.compat.xml` (see [CONTRIBUTING.md → Compatibility Checks](CONTRIBUTING.md#compatibility-checks)) |
| Record their fixtures from a release | `bin/castor compat:record X.Y.Z` (checks the tag out under `var/compat/`, runs the recorders in `tools/Compat/`) |
| Draft accepted differences after 1.x moved | `bin/castor compat:draft` (replays every scenario, prints a draft entry per difference not yet accepted) |
| Refresh the compatibility job's lock | `bin/castor compat:lock` (after a `composer.json` change) |
| Symfony console | `docker compose exec php bin/console <command>` |

`bin/castor lint` runs every check in CI order (Prettier, markdownlint, Composer Normalize, PHP CS Fixer, Rector, PHPStan, Deptrac, Swiss Knife, shell tests, changelog check, PHPUnit, Infection); `lint:fix` auto-fixes the first three. Step list: [`docs/tooling.md`](docs/tooling.md#lint-pipeline).

Run Infection **only through `bin/castor lint`**, never as a bare `bin/infection`: inside a coding-agent session a bare run reports a false 100% MSI (see `docs/tooling.md`).

Commit messages are validated in CI via commitlint (`commitlint.config.mjs`) — see [Commit Messages](#commit-messages).

## Project Structure

Map only; the full annotated tree is in [`docs/project-structure.md`](docs/project-structure.md) (update it when classes move or are added).

```text
src/Audit/
  Domain/          # Pure PHP, no framework, no I/O; immutable value objects
    Configuration/ #   typed config VOs
    Model/         #   value objects and enums (Vulnerability, SymfonyMapping, AuditReport, …)
    Exception/     #   domain exceptions
    Pipeline/      #   pipeline and coverage-recorder ports
    Port/          #   cross-layer ports; opt-in companion interfaces; `@internal` null-object defaults
      Tool/        #   tool ports (RecordingToolInterface marks a tool that records the model's answer)
  Application/     # Orchestration, depends only on Domain
    UseCase/       #   RunAuditUseCase, EstimateAuditCostUseCase
    Scan/          #   scan-scope narrowing for `--path`
    Pipeline/      #   AuditPipeline and its stages
    Budget/ Telemetry/  #   cost caps and usage accounting
    Agent/         #   AttackerAgent, ReviewerAgent, EscalatingAttackerAgent, AuditOrchestrator, synthesizers
  Infrastructure/  # I/O adapters implementing Domain ports
    LLM/           #   SymfonyAiLLMClient: the only place `symfony/ai` is used
    FileSystem/    #   project scanner, secret scrubbing
    Prompt/, parts of Scan/ and Config/  # SymfonyProfile layer (see `deptrac.yaml`): portable Infrastructure may not depend on it
    Cache/ Advisory/ Pricing/ Progress/ Tool/ Report/ SelfUpdate/ Bridge/ Diff/
src/Command/       # thin console adapters (audit:run, audit:diff, audit:trend, audit:baseline, auth:*, init, doctor, mcp:serve)
src/Standalone/    # standalone binary: application and container factories, bridge-tree loader
tests/Phpunit/     # Unit, Integration, EndToEnd, Compat (`phpunit.compat.xml`, recorded release fixtures)
tests/Shell/       # POSIX shell tests for install.sh and the CI scripts
config/services.php  # DI wiring
docs/              # architecture, configuration, tooling, pull-requests, project-structure, versioning, ci, …
```

## Architecture: DDD Layers

Strict DDD layering under `src/Audit/`: `Command → Application → Domain ← Infrastructure (implements ports)`. Infrastructure never leaks into Domain or Application.

**`LLMClientInterface`** is the sole seam between Application and LLM I/O. `AttackerAgent` and `ReviewerAgent` never import any `symfony/ai` type directly.

**Dual-agent loop** (up to 3 iterations): optional pre-scan and slicing → `AttackerAgent` (chunks files, calls the LLM) → confidence ≥ 0.6 filter → `ReviewerAgent` (validates, may adjust severity) → deduplicate and persist to `AuditContext`; then an optional `PoCSynthesisStage`. Details: [`docs/architecture.md`](docs/architecture.md#dual-agent-loop-in-detail).

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

Split-model (`attacker_model` / `reviewer_model`) and the rest: see the reference below.

Swapping LLM providers requires only `config/packages/ai.yaml` changes — no code changes.

Full reference: [`docs/configuration.md`](docs/configuration.md)

## Commit Messages

Format: `<type>[optional scope]: <description>` — [Conventional Commits](https://www.conventionalcommits.org/)

Types: `feat` (new user-facing feature), `fix`, `refactor`, `test`, `docs`, `chore`, `build`, `ci`, `perf`.

Common scopes: `agent`, `pipeline`, `domain`, `llm`, `command`, `bundle`, `standalone`, `scan`, `deps`, `ci`, `rate-limit`, `release`. Breaking changes: `feat!:` with `BREAKING CHANGE:` footer.

## Pull Requests

Follow [`.github/PULL_REQUEST_TEMPLATE.md`](.github/PULL_REQUEST_TEMPLATE.md); the `Pull request target` check enforces the rules. Full rules and the pre-flight command: [`docs/pull-requests.md`](docs/pull-requests.md).

- Title 50 characters or fewer, Conventional Commits format; Summary 500 characters or fewer; four sections only, in template order.
- Open against the release branch; stack on another PR only when it needs that PR's code.
- Always squash-merge (the `main` release merge is the one exception, a regular merge commit); label `bug` or `enhancement`.

## CI Pipeline and Security Posture

All CI jobs must pass before merging; the list is in [`docs/tooling.md`](docs/tooling.md#ci-pipeline) and [`docs/ci.md`](docs/ci.md).

This project must not ship the vulnerability classes it hunts. **All subprocess work routes through Symfony `Process`**, never a raw exec call: `phpstan.dist.neon` line 2 includes the `disallowed-execution-calls.neon` ban by hand, so never delete it and never satisfy a violation with an `allowIn` entry. Third-party GitHub Actions are pinned to commit SHAs. Rationale: [`docs/tooling.md`](docs/tooling.md#security-posture).

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
