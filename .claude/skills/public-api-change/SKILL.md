---
name: public-api-change
description: Checklist for adding, changing, deprecating or removing anything on the public API of this bundle: a configuration key or its default, an `audit:run` argument, option or exit code, a JSON or SARIF report field, a Domain port, model, enum or exception, `RunAuditUseCase` or the bundle class. Use before editing any of them.
---

# Public API change

The policy is in [`docs/versioning.md`](../../../docs/versioning.md) and `CLAUDE.md` → Backward Compatibility. Code tagged `@internal` is outside it: refactor it freely and stop here.

## 1. Classify

| Change | Class | Commit |
| --- | --- | --- |
| Something added: a key, an option, a report key, a port method on a new interface, an enum case a consumer need not handle | `MINOR` | `feat:` |
| Something changed or removed | `MAJOR`: needs a deprecation cycle on the current line first | `feat!:` + `BREAKING CHANGE:` footer, only on the next major line |
| A deprecation (the old path still works and warns) | `MINOR` | `feat:` |

When unsure, ask the maintainer before writing code.

## 2. Make the change, test first

- A deprecation calls `trigger_deprecation('vinceamstoutz/symfony-security-auditor', 'X.Y', '…')` and its test pairs `#[IgnoreDeprecations('vinceamstoutz/symfony-security-auditor')]` with an `expectUserDeprecationMessage*()` assertion.
- A public factory past the 5-parameter cap gets an `of()` value-object factory; the wide `create()` is marked `@deprecated` and delegates to it.

## 3. Update every place that publishes it

- **Configuration key**: `docs/configuration.md`, the list in `docs/versioning.md` and `resources/schema.json` (editor autocompletion for `symfony_security_auditor.yaml`).
- **Report field or format**: every doc that describes it (search `docs/` and `README.md` for the field name); the golden-master snapshots under `tests/Phpunit/EndToEnd/__snapshots__/` change in the same commit. Review their diff.
- **`CHANGELOG.md`**: one line under `## [Unreleased]`, in `New Features ✨`, `Deprecations 💀` (since which version, what replaces it) or `Breaking Changes 💥` (with the migration path).

## 4. Pass the compatibility gates

Details: [CONTRIBUTING.md → Compatibility Checks](../../../CONTRIBUTING.md#compatibility-checks).

1. `docker compose exec php vendor/bin/phpunit -c phpunit.compat.xml`. Each difference it reports is either a break to restore, or a change the maintainer accepts: then add an entry to `tests/Phpunit/Compat/Configuration/accepted-differences.php` (configuration) or `tests/Phpunit/Compat/accepted-differences.php` (behaviour) with `'changelog' => '#<PR>'`, the pull request the `CHANGELOG.md` bullet links. `bin/castor compat:draft` prints draft entries.
2. The **API compatibility** job (roave/backward-compatibility-check) fails on a changed PHP signature. An accepted break goes into `.roave-backward-compatibility-check.xml` as an escaped `ignored-regex`, right after a `<!-- CHANGELOG: "#<PR>" -->` comment.
