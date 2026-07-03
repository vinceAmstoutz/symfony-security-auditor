# Changelog Rules

Every behavior-affecting change updates `CHANGELOG.md` **in the same
commit/PR**. Docs-only, CI-only, and pure-tooling changes are exempt.

## Step 1 — Classify the change first

Before writing the entry, decide the SemVer impact against
[`docs/versioning.md`](../../docs/versioning.md):

| Class     | Criteria                                                                                                                                                             |
| --------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **MAJOR** | Removes/alters public API (config keys, `audit:run` surface, JSON/SARIF schemas, Domain ports, models, `RunAuditUseCase`, Bundle class). Requires deprecation cycle. |
| **MINOR** | New user-facing feature, new config key, `@internal` refactor with visible benefit.                                                                                  |
| **PATCH** | Bug fix, no API surface change.                                                                                                                                      |

If the release vehicle is not yet decided, file the entry under
`## [Unreleased]` (pending) — never leave a shipped change undocumented.

## Step 2 — Write the entry

Place it under the correct Keep-a-Changelog subsection (`### Added`,
`### Changed`, `### Deprecated`, `### Removed`, `### Fixed`, `### Security`)
following the established entry style:

- **Bold one-line summary stating the user-visible outcome.** Then: root cause
  with file paths in backticks, exact error strings quoted verbatim, what
  changed, and what the user observes now.
- Reference classes/methods as `` `Class::method()` `` and files as
  `` `src/...` ``.

## Step 3 — At release time

1. Rename `## [Unreleased]` content to `## [X.Y.Z] — YYYY-MM-DD — Codename`
   (one-word codename: Polyglot, Hush, Watertight, …) and re-create an empty
   `## [Unreleased]` above it.
2. Add a short intro paragraph summarizing the release theme.
3. Add the link reference at the bottom block:
   `[X.Y.Z]: https://github.com/vinceAmstoutz/symfony-security-auditor/releases/tag/X.Y.Z`.
4. Bump the version pins to `X.Y.Z`: the config-schema `$id` in
   `resources/schema.json` and the GitHub Action `uses:` examples in
   `docs/ci.md` and `README.md`. These point at the release tag, so they must
   move every release. (The `# $schema:` modelines in `examples/configs/*.yaml`,
   `examples/vulnerable-app/…`, and `docs/configuration.md` track `main` and
   need no per-release bump.)
5. Prepare GitHub release notes in this exact format:

   ```markdown
   ## What's Changed

   - <type>(<scope>): <description> by @vinceAmstoutz in https://github.com/vinceAmstoutz/symfony-security-auditor/pull/<N>

   **Full Changelog**: https://github.com/vinceAmstoutz/symfony-security-auditor/compare/<prev>...<X.Y.Z>
   ```

   One bullet per conventional-commit-typed change, linked to its PR.
