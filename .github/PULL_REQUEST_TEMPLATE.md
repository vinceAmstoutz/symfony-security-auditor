## Summary

<!-- What does this PR do and why? One or two sentences. -->

<!-- Closes #xxx -->

## Type of change

- [ ] Bug fix
- [ ] New feature
- [ ] Refactor / internal improvement
- [ ] Documentation
- [ ] Tests only

## Checklist

- [ ] Tests added or updated (unit + integration where applicable)
- [ ] All checks pass: `bin/castor lint`
- [ ] 100% MSI maintained: `docker compose exec php bin/infection`
- [ ] No `createMock` without a matching `expects()` (use `createStub` otherwise)
- [ ] Commit messages follow [Conventional Commits](https://www.conventionalcommits.org/)
