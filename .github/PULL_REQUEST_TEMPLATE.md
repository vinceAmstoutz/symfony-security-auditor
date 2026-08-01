## Summary

<!-- What does this PR do and why? One or two sentences. -->

<!-- Closes #xxx -->

## Type of change

- [ ] Bug fix
- [ ] New feature
- [ ] Refactor / internal improvement
- [ ] Documentation
- [ ] Tests only

## Target branch

Tick one and open the pull request against it — CI fails if they disagree. The
default base `main` is almost never right
([why](docs/versioning.md#branches--maintenance)).

- [ ] `1.x` — anything for the next minor release: bug fixes and new features
- [ ] `2.x` — breaking changes, for the next major release
- [ ] `main` — release merges only, nothing else

## Checklist

- [ ] Tests added or updated (unit + integration where applicable)
- [ ] All checks pass: `bin/castor lint`
- [ ] 100% MSI maintained: `docker compose exec php bin/infection`
- [ ] No `createMock` without a matching `expects()` (use `createStub`
      otherwise)
- [ ] Commit messages follow
      [Conventional Commits](https://www.conventionalcommits.org/)
