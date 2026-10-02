## Summary

<!--
The user-visible outcome, in 500 characters or fewer. Add a "Closes #123" or
"Refs #123" line when an issue is involved, and keep the title to 50 characters
or fewer. CI checks this description: run .github/scripts/check-pull-request.sh
before opening the pull request (see CONTRIBUTING.md).
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
and is based on its branch. Then name it under "## Details" — "Stacked on #123"
and the code this one needs from it. Keep only the boxes you tick.
-->

- [ ] `1.x` — anything for the next minor release: bug fixes and new features
- [ ] `2.x` — breaking changes, for the next major release
- [ ] `main` — release merges only, nothing else
- [ ] `stacked` — based on another open PR; retarget to the release branch
      ticked above once that PR merges

<!--
Optional "## Details" section here: implementation notes, backward
compatibility, upgrade steps. No other sections.
-->

## Checklist

<!-- Tick what you did; delete what does not apply. -->

- [ ] Tests added or updated (unit + integration where applicable)
- [ ] All checks pass: `bin/castor lint`
- [ ] 100% MSI maintained: `docker compose exec php bin/infection`
- [ ] No `createMock` without a matching `expects()` (use `createStub`
      otherwise)
- [ ] Commit messages follow
      [Conventional Commits](https://www.conventionalcommits.org/)
