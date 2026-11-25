# Contributing

Set up the project, run the checks and open a pull request that can merge. New to the code? Read the [Architecture overview](docs/architecture.md) first.

## Table of Contents

- [Requirements](#requirements)
- [Setup](#setup)
- [Project Tour for New Contributors](#project-tour-for-new-contributors)
- [Daily Dev Loop](#daily-dev-loop)
- [Running Tests](#running-tests)
- [Mutation Testing](#mutation-testing)
- [Compatibility Checks](#compatibility-checks)
- [Evaluating Detection Quality](#evaluating-detection-quality)
- [Code Quality](#code-quality)
- [Writing Tests](#writing-tests)
- [Which Branch to Target](#which-branch-to-target)
- [Documenting Additions](#documenting-additions)
- [Common Tasks](#common-tasks)
- [Submitting a Pull Request](#submitting-a-pull-request)
- [Commit Style](#commit-style)
- [Code of Conduct](#code-of-conduct)
- [Security](#security)

## Requirements

- Docker and Docker Compose
- [Castor](https://castor.jolicode.com/) task runner
- PHP 8.3+, only to run tools outside Docker

## Setup

```bash
git clone https://github.com/vinceamstoutz/symfony-security-auditor.git
cd symfony-security-auditor
bin/castor up           # docker compose up --wait
docker compose exec php composer install
```

Stop the containers with `bin/castor down`.

## Project Tour for New Contributors

- `src/Audit/` holds `Domain/` (pure PHP: no framework, no I/O), `Application/` (orchestration) and `Infrastructure/` (I/O adapters). `src/Command/` holds the console commands and `config/services.php` the DI wiring.
- Dependencies point one way: `Command → Application → Domain ← Infrastructure`.
- `LLMClientInterface` is the only LLM seam: Application agents never import `symfony/ai` types.
- Follow the path-scoped rules in [`.claude/rules/`](.claude/rules/).

## Daily Dev Loop

1. Start the containers: `bin/castor up`.
2. Run one suite while you iterate: `docker compose exec php vendor/bin/phpunit --testsuite Unit`.
3. Run the whole chain before you push: `bin/castor lint`.

## Running Tests

```bash
docker compose exec php vendor/bin/phpunit                          # all suites
docker compose exec php vendor/bin/phpunit --testsuite Unit         # isolated logic, I/O mocked
docker compose exec php vendor/bin/phpunit --testsuite Integration  # real filesystem, stub LLM
docker compose exec php vendor/bin/phpunit --testsuite EndToEnd     # full workflow, fixture LLM
```

No suite needs API credentials.

## Mutation Testing

- Run Infection through `bin/castor lint`, never as a bare `bin/infection`: the task mirrors CI's flags.
- Kill every mutant: 100% MSI is required.

## Compatibility Checks

A `1.x` upgrade must not break what users built against the last release. This suite compares this tree with fixtures recorded from the last release tag and fails on any difference not accepted. CI runs it as the **Compatibility** job (PHP 8.3, Symfony 7.4).

```bash
docker compose exec php vendor/bin/phpunit -c phpunit.compat.xml
```

- Accept a difference only with the pull request (`'#123'`) that a `CHANGELOG.md` bullet under `## [Unreleased]` links. Between a release's promotion and its new recordings, a bullet of that release counts too.
- Remove an accepted difference once it no longer shows: it fails.
- Never edit a fixture by hand: the recorders seal them. Record again.

### Configuration Snapshot

`tests/Phpunit/Compat/Configuration/` compares each configuration path with the last release's snapshot (kind, default, choices, bounds, required, accepted values, `%env()%` support, whether a project's `.symfony-security-auditor.yaml` may set it) plus the container parameters of the default configuration and of each `profile`.

- A narrowed path is a `MAJOR` change ([Versioning](docs/versioning.md)): restore the released contract.
- A parameter changed on purpose (such as a cache key salt after a prompt change): add it to `tests/Phpunit/Compat/Configuration/accepted-differences.php` with its `parameters` (`*` matches any run of characters), a one-line `reason` and its `changelog` bullet.
- A changed default the maintainer rules is no break (such as a newer default `model` priced no higher): add it to the same file with the `paths` it changes, the exact `narrowings` the test reports, a `reason` and its `changelog` bullet.
- A key added since the release: list it in `docs/versioning.md` and describe it in `resources/schema.json`.

### Public API

The **API compatibility** job runs [roave/backward-compatibility-check](https://github.com/Roave/BackwardCompatibilityCheck) against the newest `X.Y.Z` tag of the target line (`1.*.*` for a pull request on `1.x`; a stacked one takes the release branch ticked in its description, else the one its commits are closest to).

- It fails on a removed or changed class, method, property, constant or enum case, a narrowed type or an added required parameter. It skips `@internal` code.
- An added enum case passes ([versioning policy](docs/versioning.md#domain-models-and-exceptions)): `tools/BcCheck/RoaveEnumCaseAdditions.php` filters it out and fails once a Roave release no longer returns added cases the way it expects.

Run it in a full clone that holds the tag (not a `git worktree`), with the `bcmath` and `intl` extensions:

```bash
docker compose exec php composer install --working-dir=tools/bc-check
docker compose exec php var/bc-check/vendor/bin/roave-backward-compatibility-check --from=X.Y.Z  # the newest X.Y.Z tag of the target line
```

To accept a break, add the reported line to `.roave-backward-compatibility-check.xml` as an `ignored-regex` with every metacharacter escaped, right after a `<!-- CHANGELOG: "#123" -->` comment naming the pull request its `## [Unreleased]` bullet links. `RoaveBaselineTest` refuses a wildcard and an entry no bullet announces.

### Behaviour Replay

`tests/Phpunit/Compat/` replays a few hundred scenarios recorded from the last release (`audit:run` options, formats and exit codes, the report commands, the standalone binary, `mcp:serve`, the public PHP API) against a scripted provider. Each runs in an isolated temporary workspace with no network and no API key.

- The recordings are one normalized JSON file per scenario in `tests/Phpunit/Compat/Fixture/<release>/`.
- Keep `TMPDIR` at 22 characters or fewer: the suite refuses a longer one.
- The suite replays only on the PHP and package minor versions in `environment.json`, so CI installs `tests/Phpunit/Compat/composer.lock`. Refresh it with `bin/castor compat:lock` when `composer.json` changes.

**When a scenario fails**, the message lists each difference by its recording path (such as `runs.0.stdout.json.vulnerabilities.1.severity`) or, for text, by the line lost (`-`) or gained (`+`). A key a JSON report gained is not a difference ([Versioning](docs/versioning.md)). Restore the released behaviour, or accept an approved change with an entry in `tests/Phpunit/Compat/accepted-differences.php`:

- `scenarios`: names or patterns (`*` matches any run of characters). Each must show the difference in every scenario it names.
- `path`: `*` matches one segment, `**` any number.
- `match`: a pattern on the `-line` or `+line` of a text, or on `recorded -> replayed` of a value, as JSON.
- `reason`: one line.
- `changelog`: the pull request (`'#123'`) its `## [Unreleased]` bullet links. A difference only in what the scripted provider received (`llm.*`, such as a tool added to a request or files grouped differently) sets `'internal' => true` instead.

Keep `path` and `match` as narrow as the change: an entry covering a whole scenario stops it from guarding anything else. Pin a broad new behaviour in an ordinary test instead. A difference with no bullet to cite is a break to fix.

### Keeping Up With 1.x

The recordings stay those of the last release until the next tag. Only the accepted differences follow the branch. When `1.x` moves and the suite reports differences, run:

```bash
bin/castor compat:draft
```

It replays every scenario and prints a draft entry per difference not yet accepted, grouped by path and change, plus the entries that no longer show. Give each draft a reason and its bullet, widen a path only where every difference under it is the same change and fix what is a break.

### Recording From a New Release

Once a release is tagged, open a pull request on its `<N>.x` branch:

1. Run `bin/castor compat:record X.Y.Z`. It checks the tag out under `var/compat/X.Y.Z`, installs its dependencies and runs the recorders (the behaviour one as your own user, so the scenarios writing to the discard device are recorded too).
2. Empty both `accepted-differences.php` files and the `<baseline>` of `.roave-backward-compatibility-check.xml`: their entries described the previous release.

Record a scenario added since with `docker compose exec --user "$(id -u):$(id -g)" php php tools/Compat/record.php var/compat/X.Y.Z X.Y.Z <scenario>`.

A bump that moves a recorded package (`symfony/ai-platform`, `symfony/ai-bundle`, `mcp/sdk`, Symfony) to another minor version cannot replay the last recordings: its pull request records the last release again from its tag with only the bump applied. Release the bump quickly and record from that release once tagged. The edited recording must not outlive the next release.

## Evaluating Detection Quality

`bin/castor eval` audits `examples/vulnerable-app` with real LLM calls (it costs tokens) and scores the report against the `{"file", "type"}` seeds of [`examples/vulnerable-app/ground-truth.json`](examples/vulnerable-app/ground-truth.json).

1. Install the demo's dependencies once: `docker compose exec php composer install -d examples/vulnerable-app`.
2. Export the key of the platform its [`ai.yaml`](examples/vulnerable-app/config/packages/ai.yaml) configures (`ANTHROPIC_API_KEY` by default): the task passes it into the container. For another platform, edit that `ai.yaml`, `composer require` its bridge in the demo and name its variable with `--api-key-env` (for example `--api-key-env=OPENAI_API_KEY`).
3. Run `bin/castor eval`.

It prints precision, recall and F1 per vulnerability class and overall. The JSON report is kept as `var/ssa-eval-<id>.json`.

Score another fixture and gate on minimum quality:

```bash
bin/castor eval --target=path/to/app --ground-truth=path/to/manifest.json \
    --min-precision=0.8 --min-recall=0.9
```

The harness lives in [`tools/Eval/`](tools/Eval/), outside the shipped bundle and the coverage and mutation scope.

## Code Quality

Run `bin/castor lint` to check everything, or `bin/castor lint:fix` to fix what it can first. It runs, in order: Prettier, markdownlint, Composer Normalize, PHP CS Fixer, Rector, PHPStan max, Deptrac, Swiss Knife, the `tests/Shell/` tests, the changelog and prose checks, PHPUnit and Infection. Prettier and markdownlint run in Docker: no local Node is needed.

- Write Markdown with one line per paragraph and list item, never hard-wrapped (`bin/castor lint:fix` rejoins one). Follow the [prose rule](.claude/rules/prose-style.md) in Markdown, comments and docblocks: no em dash, no comma before "and". `bin/castor lint:docs` checks Markdown and comments alone.
- Never silence a gate (`@phpstan-ignore*`, baseline files, Rector skips, `@infection-ignore-all`, `ignoreSourceCodeByRegex`, `@codeCoverageIgnore`, `markTestSkipped` to dodge a failure): fix the code. A genuine false positive needs a justification in the PR description and a linked tracking issue ([CLAUDE.md → Never Silence Quality Gates](CLAUDE.md#5-never-silence-quality-gates)).

## Writing Tests

- Use `createStub()` when the test only needs a return value.
- Use `createMock()` only when the test must fail if the method is not called (`expects(self::never())`, `expects(self::once())`, etc.).
- Write the failing test first (TDD red/green/refactor). Full convention: [`.claude/rules/testing.md`](.claude/rules/testing.md).
- Keep domain models (`src/Audit/Domain/Model/`) immutable: a state change returns a new instance. See [`.claude/rules/domain-models.md`](.claude/rules/domain-models.md).

## Which Branch to Target

`main` holds exactly the latest release. Target a version branch:

| Change                                    | Base   |
| ----------------------------------------- | ------ |
| Bug fix or new feature for the next minor | `1.x`  |
| Breaking change, for the next major       | `2.x`  |
| Release merge                             | `main` |

- A pull request opens against `main` by default: **retarget the base**.
- Tick the same branch under `## Target branch`: the `Pull request target` check fails when the two disagree ([Branches & maintenance](docs/versioning.md#branches--maintenance)).
- Stack on another open pull request's branch only when you need code it adds, never because both edit `CHANGELOG.md`, `CLAUDE.md` or the docs. Tick `stacked` and end the Summary with `Stacked on #123` and the code you need from it.
- Once the parent merges, retarget, untick `stacked`, drop the `Stacked on` line and update the branch.

## Documenting Additions

Mark each new config key, CLI option or output format with the release that will carry it:

```markdown
| `audit.new_key` | `bool` | `false` | _Since 1.19._ What it does. |
```

- Use the next unreleased version: the one your `CHANGELOG.md` entry sits under.
- Never point docs or examples at a `raw.githubusercontent.com/.../main/` URL. Use `releases/latest/download/`, which resolves to the newest release's assets.

## Common Tasks

### Add a new vulnerability type

1. Add a case to `Audit/Domain/Model/VulnerabilityType` and handle it in `category()`, `owaspReference()`, `owaspReferenceUrl()` and `cwe()`.
2. Add its value to the type lists of `AttackerPromptBuilder` and `ReviewerPromptSections` so the LLM can emit it. Bump `PROMPT_VERSION` in `AttackerPromptBuilder` and `ReviewerPromptBuilder`.
3. Add it to `audit.included_types` and `audit.excluded_types` in `resources/schema.json`.
4. Cover it in `tests/Phpunit/Unit/Domain/Model/VulnerabilityTypeTest.php`.
5. Update the type list in [`docs/architecture.md`](docs/architecture.md#vulnerabilitytype-backed-enum-with-owasp-and-cwe-references).

### Add a new pipeline stage

Implement `Audit/Domain/Pipeline/StageInterface`: autoconfiguration tags it `symfony_security_auditor.pipeline_stage`. See [Extending → Custom Pipeline Stage](docs/extending.md#2-custom-pipeline-stage).

### Add a new output format

Follow [Extending → Adding a new format](docs/extending.md#adding-a-new-format).

### Extend an application's audit

A custom LLM client, advisory source or provider is wired in the audited application, not here: see [Extending](docs/extending.md), [Advisory Source](docs/configuration.md#advisory-source-lookup_advisory-tool) and [Platform Configuration](docs/configuration.md#platform-configuration).

## Submitting a Pull Request

1. Fork the repository and branch off your [target branch](#which-branch-to-target): `git checkout -b feat/my-feature`.
2. Write tests (unit, plus integration where applicable).
3. Keep backward compatibility ([Semantic Versioning 2.0.0](https://semver.org)): a change to the public API listed in [`docs/versioning.md`](docs/versioning.md) needs a deprecation cycle and a `feat!:` commit.
4. For a behavior change, add one line to `CHANGELOG.md` under `## [Unreleased]`, following [`.claude/rules/changelog.md`](.claude/rules/changelog.md). `sh .github/scripts/check-changelog.sh` checks it.
5. Make `bin/castor lint` pass.
6. Fill in the [PR template](.github/PULL_REQUEST_TEMPLATE.md):
   - a title of 50 characters or fewer, in the [commit format](#commit-style);
   - only its four sections, in order: `## Summary`, `## Type of change`, `## Target branch`, `## Checklist`;
   - a Summary of 750 characters or fewer, then a `Closes #N` or `Refs #N` line when an issue is involved;
   - only the boxes you tick (the license box always) and no leftover template text.
7. Run the `Pull request target` check before you open it:

   ```bash
   PR_TITLE='fix(scan): …' PR_BODY="$(cat body.md)" BASE_REF=1.x \
     sh .github/scripts/check-pull-request.sh
   ```

All eight CI jobs must pass before merging ([`docs/ci.md`](docs/ci.md)).

## Commit Style

Use [Conventional Commits](https://www.conventionalcommits.org/): `<type>[optional scope]: <description>`, such as `fix(pipeline): handle empty LLM response in reviewer`.

- Types: `feat` (user-facing feature), `fix`, `refactor`, `test`, `docs`, `chore`, `build`, `ci`, `perf`. Scopes: see [`commitlint.config.mjs`](commitlint.config.mjs).
- Breaking change: `feat!:` with a `BREAKING CHANGE:` footer.

The Commit Lint job checks every commit. Run it locally:

```bash
npx --yes @commitlint/cli --from=origin/1.x --to=HEAD --config commitlint.config.mjs
```

## Code of Conduct

Be respectful and constructive. Personal attacks, harassment or dismissive behavior are not tolerated. Report problems privately to the maintainer ([`composer.json`](composer.json) → `authors.email`).

## Security

Report a vulnerability **in the auditor itself** privately through [GitHub Security Advisories](https://github.com/vinceamstoutz/symfony-security-auditor/security/advisories/new), never in a public issue ([SECURITY.md](SECURITY.md)).

Audit output problems (false positives, missed findings, odd LLM behavior) are normal issues: check [Troubleshooting](docs/troubleshooting.md), then open one with a reproducer.
