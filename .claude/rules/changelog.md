# Changelog Rules

Every behavior-affecting change updates `CHANGELOG.md` **in the same commit/PR**. Docs-only, CI-only, and pure-tooling changes are exempt.

`CHANGELOG.md` is written for the people who run the auditor, not for those who read its code: one plain line per change, grouped by kind of change like a release page. The GitHub Release body is generated from the matching section (`.github/scripts/release-notes.sh`), so the changelog and the release page cannot drift apart. [`.github/scripts/check-changelog.sh`](../../.github/scripts/check-changelog.sh) enforces everything below in CI and in `bin/castor lint`.

## Step 1 — Classify the change first

Before writing the entry, decide the SemVer impact against [`docs/versioning.md`](../../docs/versioning.md):

| Class | Criteria |
| --- | --- |
| **MAJOR** | Removes/alters public API (config keys, `audit:run` surface, JSON/SARIF schemas, Domain ports, models, `RunAuditUseCase`, Bundle class). Requires deprecation cycle. |
| **MINOR** | New user-facing feature, new config key, `@internal` refactor with visible benefit. |
| **PATCH** | Bug fix, no API surface change. |

If the release vehicle is not yet decided, file the entry under `## [Unreleased]` (pending) — never leave a shipped change undocumented.

## Step 2 — Pick the section

A release holds only these `###` sections, in this order, each at most once and omitted when empty:

| Section | What goes in it |
| --- | --- |
| `New Features ✨` | A capability, option, command, report field or visible behaviour a user can use or will notice — hardening a user notices included |
| `Security 🔒` | The fix of a published vulnerability. **Every entry cites its `CVE-YYYY-NNNN` or `GHSA-xxxx-xxxx-xxxx` id.** Nothing else |
| `Breaking Changes 💥` | A removal or an incompatible change; the migration path in the same line |
| `Deprecations 💀` | What is deprecated, since which version, what replaces it |
| `Bugfixes 🐛` | A defect fixed |
| `Performance Improvements 🚀` | Faster, leaner, fewer LLM calls |
| `Core 🧱` | Dependencies, supported PHP/Symfony versions, cache-version bumps, defensive hardening nobody notices, refactors, build and tooling |

### `Security 🔒` is not a place for hardening

A change that makes the auditor harder to abuse is **not** a security entry unless it fixes a vulnerability that has a published advisory. Without a CVE or GHSA id it goes under `New Features ✨` (when users notice or can use it) or `Core 🧱` (when they do not). The check fails a `Security 🔒` entry without an id, and an entry that cites an id outside `Security 🔒`.

**When in doubt about where an entry belongs — above all anything that sounds like a vulnerability fix — ask the maintainer. Never decide silently.**

## Step 3 — Write the entry

One line, one change, in the voice of a release note:

- Say what the user gets or no longer suffers, in the present tense: `` `audit:run --fail-on-incomplete` exits `3` when some file could not be fully analyzed ``. A bugfix may read `` `Thing`: what now happens ``.
- Keep what an upgrader needs: command names, options, config keys (full dotted path), exit codes, finding types, report fields, versions, and for a deprecation the replacement.
- Leave out the root cause, file paths, `Class::method()` internals, quoted error strings, test and CI details, issue numbers. The pull request and the commit body carry them.
- End with the pull request that shipped it: `([#123](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/123))`. Several pull requests are comma-separated inside one pair of parentheses. Under `## [Unreleased]` the link may wait until the pull request exists; the release requires it.
- No bold lead, no wrapped line, no sub-list, no code block, no paragraph, at most 500 characters.
- The compatibility suite cites the bullet that announces an accepted API or configuration difference by one of its pull requests (`'changelog' => '#123'`, see [CONTRIBUTING.md → Compatibility Checks](../../CONTRIBUTING.md#compatibility-checks)): when you reword or merge such a bullet, keep that link.

```markdown
### New Features ✨

- `init` configures AWS Bedrock through its Mantle routes ([#386](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/386))
```

## Step 4 — At release time

1. Rename `## [Unreleased]` to `## [X.Y.Z] — YYYY-MM-DD — Codename` (one-word codename: Polyglot, Hush, Watertight, …) and re-create an empty `## [Unreleased]` above it. There is no introduction paragraph.
2. Add the link reference at the bottom block: `[X.Y.Z]: https://github.com/vinceAmstoutz/symfony-security-auditor/releases/tag/X.Y.Z`.
3. Make sure every entry of the release has its pull request link: `CHANGELOG_REQUIRE_LINKS=all sh .github/scripts/check-changelog.sh` must pass (the `Auto Release` workflow runs it too).
4. Bump the version pins to `X.Y.Z`: run `bin/castor release:bump X.Y.Z`. It rewrites every pinned location — the config-schema `$id` in `resources/schema.json` and the GitHub Action `uses:` examples in `README.md`, `docs/ci.md`, and `docs/versioning.md` — and fails loudly if a pin goes missing. The `Release Guard` workflow (`.github/workflows/release-guard.yaml`) re-checks the pins against the tag on every tag push. (The `# $schema:` modelines in `examples/configs/*.yaml`, `examples/vulnerable-app/…`, and `docs/configuration.md` track `main` and need no per-release bump.)
5. Merge. `Auto Release` tags the release and drafts its GitHub Release from the changelog section — headings promoted to `##`, followed by the `**Full Changelog**` compare link. To preview it: `PREVIOUS_TAG=<prev> sh .github/scripts/release-notes.sh X.Y.Z`.
6. Once the tag exists, record the compatibility fixtures from it in a pull request on `<N>.x`, as [CONTRIBUTING.md → Compatibility Checks](../../CONTRIBUTING.md#compatibility-checks) describes:
   - run `bin/castor compat:record X.Y.Z`, which replaces the configuration snapshot under `tests/Phpunit/Compat/Configuration/Fixture/` and the scenario recordings under `tests/Phpunit/Compat/Fixture/`;
   - empty `tests/Phpunit/Compat/Configuration/accepted-differences.php` and `tests/Phpunit/Compat/accepted-differences.php`: their entries described differences from the previous release.
   - empty the `<baseline>` of `.roave-backward-compatibility-check.xml`: the API compatibility job now compares with the new tag, and the breaks it accepted were against the previous one.
