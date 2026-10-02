## Summary

<!--
The user-visible outcome, in 500 characters or fewer, under a title of 50 or
fewer. Then a "Closes #123" or "Refs #123" line when an issue is involved, and
for a stacked pull request a "Stacked on #123" line with the code this one needs
from it. The CHANGELOG entry carries the details. CI checks this description:
run .github/scripts/check-pull-request.sh before opening the pull request (see
CONTRIBUTING.md).
-->

## Type of change

<!-- Keep only the boxes you tick. -->

- [ ] Bug fix
- [ ] New feature
- [ ] Refactor / internal improvement
- [ ] Documentation
- [ ] Tests only

## Target branch

<!--
Tick the release branch this is ultimately headed for, and open the pull request
against it — CI fails if they disagree. The default base `main` is almost never
right (docs/versioning.md#branches--maintenance).

Tick `stacked` too only when this pull request needs code from another open one
and is based on its branch. Keep only the boxes you tick.
-->

- [ ] `1.x` — anything for the next minor release: bug fixes and new features
- [ ] `2.x` — breaking changes, for the next major release
- [ ] `main` — release merges only, nothing else
- [ ] `stacked` — based on another open PR; retarget to the release branch
      ticked above once that PR merges

## Checklist

<!--
CI already runs the linters, the tests at 100% coverage, mutation testing and
commit lint, so only what it cannot check is listed. Tick what applies and
delete the rest; the license box is required.
-->

- [ ] I license this contribution under the project's MIT License (`LICENSE`)
- [ ] A bug fix comes with a test that fails without it
- [ ] `CHANGELOG.md` has an `## [Unreleased]` entry for any behavior change
- [ ] No public API change without a deprecation cycle (`docs/versioning.md`)
- [ ] User-facing additions are documented and marked _Since X.Y_
