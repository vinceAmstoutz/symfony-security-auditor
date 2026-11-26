---
name: release
description: Cut release X.Y.Z of symfony-security-auditor with `.github/scripts/release.sh`. Promotes the changelog, bumps every version pin, checks that everything points at the new version, prepares the `chore: release X.Y.Z` pull request from `<N>.x` to `main`, then records the compatibility fixtures once the tag exists. Only when the maintainer asks for a release.
disable-model-invocation: true
argument-hint: X.Y.Z Codename
---

# Release $ARGUMENTS

`$ARGUMENTS` is `X.Y.Z Codename`: ask for the codename, one capitalized word, if it is missing. `<N>.x` is the release branch of `X` (`1.x` for `1.*`).

[`.github/scripts/release.sh`](../../../.github/scripts/release.sh) does every mechanical step and checks the result. Never edit a changelog heading, a link reference or a version pin by hand: run the script again.

## Phase 1: the release pull request

1. Start from an up-to-date `<N>.x` with a clean working tree.
2. Run `sh .github/scripts/release.sh prepare X.Y.Z Codename` (or `bin/castor release:prepare X.Y.Z Codename`). It refuses a malformed version or codename, a version that is not newer than the last release and an empty `## [Unreleased]`. Then it promotes `## [Unreleased]` to `## [X.Y.Z] — <today, UTC> — Codename` under a fresh empty `## [Unreleased]`, adds the `[X.Y.Z]:` link reference, points every version pin (the schema `$id`, the `uses:` examples) at `X.Y.Z` and ends with `check`.
3. Until `sh .github/scripts/release.sh check X.Y.Z` exits `0`, fix what each `::error::` line names (usually an entry without its pull request link) and run it again. `check` fails on any tracked file that still pins another version, so a pin added since the last release cannot slip through.
4. Show the maintainer `git diff --stat` and the new release heading, then commit as `chore: release X.Y.Z`. Ask whether that commit goes through a pull request on `<N>.x` first or straight into the release pull request, unless they have said.
5. Prepare the `chore: release X.Y.Z` pull request from `<N>.x` into `main` with the [`pull-request`](../pull-request/SKILL.md) skill. Never merge it yourself: the maintainer merges it.

**Exception: the `chore: release X.Y.Z` PR that merges `<N>.x` into `main`.** Use a regular merge (a merge commit) there instead, never squash and never rebase. `main` is supposed to end up with the exact same commit SHAs as `<N>.x`: that's how every release before this one actually happened (PR #226, for 1.18.0). Squashing collapses `<N>.x`'s commits into one new SHA that doesn't exist on `<N>.x`, so the two branches permanently diverge in commit identity and need a cherry-pick-back reconciliation after every single release. Rebase-merging is worse: it replays every commit `<N>.x` has accumulated since it last diverged from `main` with a fresh SHA apiece, which is how PR #305 quietly turned a one-commit release into ~40 replayed commits landing on `main` and broke `Commit Lint` (see [Branches & maintenance](../../../docs/versioning.md#branches--maintenance)).

## Phase 2: after the merge

`Auto Release` tags the release once the maintainer merges and drafts its GitHub Release from the changelog section: headings promoted to `##`, followed by the `**Full Changelog**` compare link, with each entry credited to its pull request authors. To preview it: `PREVIOUS_TAG=<prev> sh .github/scripts/release-notes.sh X.Y.Z` (`CREDIT_AUTHORS=0` skips the author lookup). The `Release Guard` workflow runs the same `release.sh check` on the tag.

Once the tag exists, record the compatibility fixtures from it in a pull request on `<N>.x`, as [CONTRIBUTING.md → Compatibility Checks](../../../CONTRIBUTING.md#compatibility-checks) describes:

- run `bin/castor compat:record X.Y.Z`, which replaces the configuration snapshot under `tests/Phpunit/Compat/Configuration/Fixture/` and the scenario recordings under `tests/Phpunit/Compat/Fixture/`;
- empty `tests/Phpunit/Compat/Configuration/accepted-differences.php` and `tests/Phpunit/Compat/accepted-differences.php`: their entries described differences from the previous release.
- empty the `<baseline>` of `.roave-backward-compatibility-check.xml`: the API compatibility job now compares with the new tag. The breaks it accepted were against the previous one.
