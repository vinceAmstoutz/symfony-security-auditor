# Contributing

Thanks for considering a contribution. This guide walks through the dev setup,
expected workflow, and PR checklist. New to the codebase? Start with the
[Architecture overview](docs/architecture.md) — it explains the DDD layering and
the dual-agent loop before you touch code.

## Table of Contents

- [Requirements](#requirements)
- [Setup](#setup)
- [Project Tour for New Contributors](#project-tour-for-new-contributors)
- [Daily Dev Loop](#daily-dev-loop)
- [Running Tests](#running-tests)
- [Mutation Testing](#mutation-testing)
- [Evaluating Detection Quality](#evaluating-detection-quality)
- [Code Quality](#code-quality)
- [Writing Tests](#writing-tests)
- [Common Tasks](#common-tasks)
- [Submitting a Pull Request](#submitting-a-pull-request)
- [Commit Style](#commit-style)
- [Code of Conduct](#code-of-conduct)
- [Security](#security)

## Requirements

- Docker & Docker Compose
- PHP 8.3+ (for running tools locally without Docker)
- [Castor](https://castor.jolicode.com/) task runner

## Setup

```bash
git clone https://github.com/vinceamstoutz/symfony-security-auditor.git
cd symfony-security-auditor
bin/castor up           # docker compose up --wait
docker compose exec php composer install
```

Stop containers later with `bin/castor down`.

## Project Tour for New Contributors

```text
src/
  Audit/
    Domain/          # Pure PHP — no framework, no I/O. Value objects, enums, ports.
    Application/     # Orchestration — depends only on Domain. RunAuditUseCase, AuditPipeline, agents.
    Infrastructure/  # I/O adapters — symfony/ai bridge, file scanner, prompt builders, cache, report renderer.
  Command/           # Symfony Console adapter (`audit:run`).
config/services.php  # DI wiring.
tests/Phpunit/
  Unit/              # Isolated tests (stub/mock collaborators).
  Integration/       # Real classes wired together, no LLM calls.
  EndToEnd/          # Full pipeline with stubbed LLM responses.
```

Strict dependency direction: `Command → Application → Domain ← Infrastructure`.
Infrastructure never leaks into Domain or Application. The sole LLM seam is
`LLMClientInterface` — Application agents never import `symfony/ai` types
directly.

Read more:

- [Architecture](docs/architecture.md) — layers, data flow, domain model, design
  decisions.
- [Extending](docs/extending.md) — extension points (custom LLM client, agent,
  stage, report format).
- [`.claude/rules/`](.claude/rules/) — path-scoped rules (DDD boundaries,
  immutability, LLM seam, testing).

## Daily Dev Loop

```bash
# Spin up containers
bin/castor up

# Make changes, then run the full QA chain (composer normalize → CS Fixer → Rector → PHPStan → PHPUnit → Infection)
bin/castor lint           # check-only
bin/castor lint:fix       # auto-fix what's fixable

# Run a single suite while iterating
docker compose exec php vendor/bin/phpunit --testsuite Unit
```

## Running Tests

```bash
# All suites
docker compose exec php vendor/bin/phpunit

# Unit only (fast — no I/O or LLM calls)
docker compose exec php vendor/bin/phpunit --testsuite Unit

# Integration only (real filesystem, stub LLM)
docker compose exec php vendor/bin/phpunit --testsuite Integration

# End-to-end (full workflow, fixture LLM)
docker compose exec php vendor/bin/phpunit --testsuite EndToEnd
```

| Suite       | Path                         | What it tests                            |
| ----------- | ---------------------------- | ---------------------------------------- |
| Unit        | `tests/Phpunit/Unit/`        | Isolated logic, all I/O mocked           |
| Integration | `tests/Phpunit/Integration/` | Real filesystem + stub LLM               |
| EndToEnd    | `tests/Phpunit/EndToEnd/`    | Full workflow with fixture LLM responses |

> End-to-end tests replace the LLM boundary with deterministic fixture
> responses. No API credentials are required to run any test suite.

## Mutation Testing

```bash
docker compose exec php bin/infection
```

**100% MSI (Mutation Score Indicator) is required.** Every mutation must be
killed. Suppression directives (`@infection-ignore-all`,
`ignoreSourceCodeByRegex`, …) are not allowed — fix the underlying test gap
instead. See
[CLAUDE.md → Never Silence Quality Gates](CLAUDE.md#5-never-silence-quality-gates).

## Evaluating Detection Quality

Unit and mutation tests prove the code behaves as written; they say nothing
about whether the auditor actually _finds vulnerabilities_. The eval harness
closes that gap: it audits a fixture whose vulnerabilities are known ahead of
time and scores the run against that ground truth.

```bash
bin/castor eval
```

This audits `examples/vulnerable-app` (real LLM calls, so it costs tokens), then
scores the JSON report against
[`examples/vulnerable-app/ground-truth.json`](examples/vulnerable-app/ground-truth.json)
— a manifest of `{"file", "type"}` seeds. Scoring is at `(file, type)`
granularity: a seed the run reproduced is a true positive, a seed it missed a
false negative, and a reported finding with no matching seed a false positive
(so a safe decoy file the auditor flags lowers precision). Precision, recall,
and F1 are printed overall and per vulnerability class.

Point it at another fixture and gate a run on minimum quality:

```bash
bin/castor eval --target=path/to/app --ground-truth=path/to/manifest.json \
    --min-precision=0.8 --min-recall=0.9
```

The harness lives in [`tools/Eval/`](tools/Eval/) (namespace `Tooling\Eval`) —
`GroundTruthManifest` loads and validates the manifest, `EvalScorer` computes
the `EvalReport`. It is a maintainer tool, not part of the shipped bundle, so it
is excluded from coverage and mutation scope like the rest of `tools/`.

## Code Quality

```bash
# Check everything (dry-run)
bin/castor lint

# Fix formatting + apply refactors
bin/castor lint:fix
```

This runs: **Prettier** ([prettier](https://prettier.io/)) → **Markdown lint**
([markdownlint-cli2](https://github.com/DavidAnson/markdownlint-cli2)) →
`composer normalize` → PHP CS Fixer (@PER-CS3x0, @Symfony) → Rector → PHPStan
max → PHPUnit → Infection.

Prettier and Markdown lint both run via Docker (`tmknom/prettier`,
`davidanson/markdownlint-cli2`) so no local Node installation is required.
Configs: [`.prettierrc.json`](.prettierrc.json),
[`.markdownlint-cli2.jsonc`](.markdownlint-cli2.jsonc).

- Prettier handles **formatting** (line wrap to 80, table alignment, list/fence
  style).
- markdownlint handles **semantics** (heading hierarchy, broken anchors, missing
  image alt text).

**Commit messages are linted separately** in CI via
[commitlint](https://commitlint.js.org/) (Conventional Commits). Config:
[`commitlint.config.js`](commitlint.config.js). Run locally:

```bash
npx --yes @commitlint/cli --from=origin/main --to=HEAD --config commitlint.config.js
```

**No silent suppressions allowed.** PHPStan `@phpstan-ignore*`, baseline files,
Rector skips, `@codeCoverageIgnore`, `markTestSkipped` used to dodge failures —
all forbidden. If a tool flags something, fix the code. Genuine false positives
require a PR-description justification and a linked tracking issue.

## Writing Tests

**Mock vs Stub rule:**

- Use `createStub()` when the test only needs a return value (method-not-called
  → test still fails via assertions).
- Use `createMock()` only when the test must fail if the method is not called
  (`expects(self::never())`, `expects(self::once())`, etc.).

**TDD red/green/refactor.** Write the failing test first whenever practical. See
[`.claude/rules/testing.md`](.claude/rules/testing.md) for the full convention.

**Domain models** (`src/Audit/Domain/Model/`) are immutable. State changes
return new instances. See
[`.claude/rules/domain-models.md`](.claude/rules/domain-models.md).

## Common Tasks

### Add a new vulnerability type

1. Add a case to `Audit/Domain/Model/VulnerabilityType`.
2. Extend `category()` and `owaspReference()` with the new case.
3. Update `AttackerPromptBuilder` to mention the new type so the LLM emits it.
4. Add a fixture in `tests/Phpunit/Fixtures/` that exercises the new case.
5. Update the type list in
   [`docs/architecture.md`](docs/architecture.md#vulnerabilitytype--backed-enum-with-owasp-references).

### Add a new pipeline stage

Implement `Audit/Domain/Pipeline/StageInterface`. Stages are auto-tagged via
`symfony_security_auditor.pipeline_stage` in `config/services.php`. See
[Extending → Custom Pipeline Stage](docs/extending.md#2-custom-pipeline-stage).

### Add a new output format

1. Add a case to `Command/OutputFormat`.
2. Add a `render<Name>(AuditReport): string` method to
   `Audit/Infrastructure/Report/ReportRenderer`.
3. Add the matching arm in `Command/ReportWriter::write()`.

### Add a new advisory source (CVE feed)

Implement `Audit/Domain/Port/AdvisoryDatabaseInterface` and alias
`AdvisoryDatabaseInterface` to your service in `config/services.yaml`. See
[Configuration → Advisory Source](docs/configuration.md#advisory-source-lookup_advisory-tool).

### Swap the LLM provider

`config/packages/ai.yaml` change only — no PHP edits. See
[Configuration → Platform Configuration](docs/configuration.md#platform-configuration).

For a custom client implementation (direct HTTP, retry logic, …) see
[Extending → Custom LLM Client](docs/extending.md#1-custom-llm-client).

## Submitting a Pull Request

1. Fork the repository.
2. Create a feature branch: `git checkout -b feat/my-feature`.
3. Write tests for your change (unit + integration where applicable).
4. Mind backward compatibility — the project follows
   [Semantic Versioning 2.0.0](https://semver.org); any change that affects the
   public API surface listed in [`docs/versioning.md`](docs/versioning.md) needs
   a deprecation cycle and a `feat!:` commit.
5. Ensure all checks pass: `bin/castor lint`.
6. Open a pull request — the [PR template](.github/PULL_REQUEST_TEMPLATE.md)
   will guide you.

The CI pipeline runs six jobs: **Prettier Check** → **Markdown Lint** → **Commit
Lint** → **Lint** (Composer Normalize, PHP CS Fixer, Rector, PHPStan max) →
**Tests** (PHPUnit matrix on PHP 8.3/8.4/8.5 × Symfony 7.4/8.0/8.1) →
**Mutation** (Infection 100% MSI). All six must pass before merging.

Details: [`docs/ci.md`](docs/ci.md).

## Commit Style

Follow [Conventional Commits](https://www.conventionalcommits.org/):

```text
feat(agent): add IDOR detection to attacker agent
fix(pipeline): handle empty LLM response in reviewer
test(infrastructure): add integration test for ProjectFileScanner
docs(configuration): document dry-run CI usage
chore(deps): bump symfony/ai to 0.10
```

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
`deps`, `ci`. Breaking changes: `feat!:` with a `BREAKING CHANGE:` footer.

## Code of Conduct

Be respectful and constructive. Personal attacks, harassment, or dismissive
behavior are not tolerated. Report problems privately to the maintainer (see
[`composer.json`](composer.json) → `authors.email`).

## Security

Report vulnerabilities **in the auditor itself** privately via
[GitHub Security Advisories](https://github.com/vinceamstoutz/symfony-security-auditor/security/advisories/new)
— not in a public issue. See [SECURITY.md](SECURITY.md) for the full policy.

Issues with audit output (false positives, missed vulnerabilities, weird LLM
behavior) are not security issues — open them as normal GitHub issues with a
reproducer, or check [Troubleshooting](docs/troubleshooting.md) first.
