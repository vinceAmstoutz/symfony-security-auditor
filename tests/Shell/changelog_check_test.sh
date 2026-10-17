#!/bin/sh
#
# POSIX tests for .github/scripts/check-changelog.sh, the CHANGELOG.md check run
# by CI, and for .github/scripts/release-notes.sh, which turns one of its
# sections into the GitHub release notes.
#
# Run with any POSIX shell: sh tests/Shell/changelog_check_test.sh

set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
check="$script_dir/.github/scripts/check-changelog.sh"
notes="$script_dir/.github/scripts/release-notes.sh"

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
changelog="$work/CHANGELOG.md"

failures=0

pull='https://github.com/vinceAmstoutz/symfony-security-auditor/pull'

valid_changelog() {
  cat <<EOF
# Changelog

All notable changes are documented here.

## [Unreleased]

### New Features ✨

- Add a flag that is still waiting for its pull request

## [1.2.0] — 2026-05-25 — Cartographer

### New Features ✨

- Map every controller route and flag the ones that check nothing ([#28]($pull/28))

### Bugfixes 🐛

- \`audit\`: keep a finding on its exact file ([#29]($pull/29), [#30]($pull/30))

### Core 🧱

- Cached answers refresh once after upgrading ([#28]($pull/28))

## [1.1.0] — 2026-05-24

### Bugfixes 🐛

- Stop a crash on an empty project ([#12]($pull/12))

[1.2.0]: https://github.com/vinceAmstoutz/symfony-security-auditor/releases/tag/1.2.0
[1.1.0]: https://github.com/vinceAmstoutz/symfony-security-auditor/releases/tag/1.1.0
EOF
}

run_check() {
  status=0
  output=$(sh "$check" "$changelog" 2>&1) || status=$?
}

expect_pass() {
  run_check
  if [ "$status" -eq 0 ] && ! printf '%s\n' "$output" | grep -q '::error'; then
    echo "ok - $1"
  else
    echo "NOT OK - $1: expected a pass, got status $status [$output]"
    failures=$((failures + 1))
  fi
}

expect_error() {
  run_check
  if [ "$status" -ne 0 ] && printf '%s\n' "$output" | grep -qF -- "$2"; then
    echo "ok - $1"
  else
    echo "NOT OK - $1: expected [$2], got status $status [$output]"
    failures=$((failures + 1))
  fi
}

replace() {
  valid_changelog | sed "s|$1|$2|" >"$changelog"
}

valid_changelog >"$changelog"
expect_pass 'a well-formed changelog passes'

replace '^### Core 🧱$' '### Chores'
expect_error 'a section outside the allowed set is refused' 'is not a changelog section'

valid_changelog | sed 's|^### Core 🧱$|### Bugfixes 🐛|' >"$changelog"
expect_error 'a section appearing twice in a release is refused' 'appears twice'

valid_changelog | sed -e 's|^### Bugfixes 🐛$|### TMP|' -e 's|^### New Features ✨$|### Bugfixes 🐛|' -e 's|^### TMP$|### New Features ✨|' >"$changelog"
expect_error 'sections out of order are refused' 'is out of order'

valid_changelog | sed 's|^## \[1.2.0\] — 2026-05-25 — Cartographer$|&\
\
A release about knowing the route graph.|' >"$changelog"
expect_error 'an introduction paragraph is refused' 'Text between a release heading and its first section'

valid_changelog | sed 's|^- Map every controller route.*|&\
  and a wrapped second line|' >"$changelog"
expect_error 'a wrapped entry is refused' 'one-line entries starting with'

valid_changelog | sed 's|^- Map every controller route|- **Map every controller route.** Map every controller route|' >"$changelog"
expect_error 'a bold lead is refused' 'does not open with a bold summary'

valid_changelog | sed "s|(\[#12\]($pull/12))|([\`abc1234\`](https://github.com/vinceAmstoutz/symfony-security-auditor/commit/abc1234abc1234abc1234abc1234abc1234abcd))|" >"$changelog"
expect_pass 'a commit link stands in for a pull request that never existed'

valid_changelog | sed "s|^- Stop a crash on an empty project (\[#12\]($pull/12))|- Stop a crash on an empty project|" >"$changelog"
expect_error 'a released entry without its pull request link is refused' 'ends with the pull request that shipped it'

valid_changelog >"$changelog"
status=0
output=$(CHANGELOG_REQUIRE_LINKS=all sh "$check" "$changelog" 2>&1) || status=$?
if [ "$status" -ne 0 ] && printf '%s\n' "$output" | grep -qF -- 'ends with the pull request that shipped it'; then
  echo "ok - CHANGELOG_REQUIRE_LINKS=all requires the link in Unreleased too"
else
  echo "NOT OK - CHANGELOG_REQUIRE_LINKS=all requires the link in Unreleased too: got status $status [$output]"
  failures=$((failures + 1))
fi

valid_changelog | sed 's|^- Cached answers refresh once after upgrading|- Open `src/Audit/Domain/Foo.php` and refresh|' >"$changelog"
expect_error 'a source path in an entry is refused' 'names a source path'

long=$(printf 'word %.0s' $(seq 1 120))
valid_changelog | sed "s|^- Cached answers refresh once after upgrading|- $long|" >"$changelog"
expect_error 'an entry over 500 characters is refused' 'keep it to 500 or fewer'

valid_changelog | sed 's|^### Core 🧱$|### Core 🧱\
\
### Deprecations 💀|' >"$changelog"
expect_error 'a heading without an entry is refused' 'has no entry'

valid_changelog | sed 's|^## \[1.1.0\] — 2026-05-24$|## [1.1.0] - 2026-05-24|' >"$changelog"
expect_error 'a malformed release heading is refused' 'A release heading reads'

valid_changelog | sed 's|^### Core 🧱$|### 100% Core|' >"$changelog"
expect_error 'a % in a heading is escaped in the annotation' '100%25 Core'

valid_changelog | sed 's|^### Bugfixes 🐛$|### Security 🔒|' >"$changelog"
expect_error 'a Security entry without a CVE or GHSA id is refused' 'must cite the CVE or GHSA id'

valid_changelog | sed -e "s|^- Stop a crash on an empty project (\[#12\]($pull/12))|- Fix a path traversal, CVE-2026-12345 ([#12]($pull/12))|" -e '/^## \[1.1.0\]/,$ s|^### Bugfixes 🐛$|### Security 🔒|' >"$changelog"
expect_pass 'a Security entry citing a CVE id passes'

valid_changelog | sed -e "s|^- Stop a crash on an empty project (\[#12\]($pull/12))|- Fix a path traversal, GHSA-abcd-ef12-3456 ([#12]($pull/12))|" -e '/^## \[1.1.0\]/,$ s|^### Bugfixes 🐛$|### Security 🔒|' >"$changelog"
expect_pass 'a Security entry citing a GHSA id passes'

valid_changelog | sed "s|^- Stop a crash on an empty project|- Fix a path traversal, CVE-2026-12345|" >"$changelog"
expect_error 'an entry citing a CVE outside Security is refused' 'belongs under "Security 🔒"'

valid_changelog >"$changelog"
printf '\n## [1.0.0] — 2026-05-20\n' >>"$changelog"
{
  valid_changelog | sed '/^\[1.2.0\]: /,$d'
  printf '### Core 🧱\n\n- Late entry after the references ([#1](%s/1))\n' "$pull"
  printf '\n[1.2.0]: https://github.com/vinceAmstoutz/symfony-security-auditor/releases/tag/1.2.0\n'
} >"$changelog"
expect_pass 'link references at the bottom are not entries'

valid_changelog >"$changelog"
printf '\n## [1.0.0] — 2026-05-20\n' >>"$changelog"
expect_error 'a release heading after the link references is refused' 'follows the link references'

valid_changelog >"$changelog"
if sh "$check" "$work/missing.md" >/dev/null 2>&1; then
  echo "NOT OK - a missing file is refused"
  failures=$((failures + 1))
else
  echo "ok - a missing file is refused"
fi

valid_changelog >"$changelog"
output=$(REPO=owner/name PREVIOUS_TAG=1.1.0 sh "$notes" 1.2.0 "$changelog" 2>&1) || true
expected="## New Features ✨

- Map every controller route and flag the ones that check nothing ([#28]($pull/28))

## Bugfixes 🐛

- \`audit\`: keep a finding on its exact file ([#29]($pull/29), [#30]($pull/30))

## Core 🧱

- Cached answers refresh once after upgrading ([#28]($pull/28))

**Full Changelog**: https://github.com/owner/name/compare/1.1.0...1.2.0"
if [ "$output" = "$expected" ]; then
  echo "ok - release notes are the version's section with promoted headings and the compare link"
else
  echo "NOT OK - release notes differ:"
  printf '%s\n' "$output"
  failures=$((failures + 1))
fi

output=$(sh "$notes" 1.1.0 "$changelog" 2>&1) || true
if printf '%s\n' "$output" | grep -qF 'Full Changelog'; then
  echo "NOT OK - no previous tag, no compare link: [$output]"
  failures=$((failures + 1))
elif printf '%s\n' "$output" | grep -qF -- '- Stop a crash on an empty project' && ! printf '%s\n' "$output" | grep -qF 'releases/tag'; then
  echo "ok - the last release stops at the link references and has no compare link without a previous tag"
else
  echo "NOT OK - the last release leaks past its section: [$output]"
  failures=$((failures + 1))
fi

status=0
output=$(sh "$notes" 9.9.9 "$changelog" 2>&1) || status=$?
if [ "$status" -ne 0 ] && printf '%s\n' "$output" | grep -qF 'no release section with entries for 9.9.9'; then
  echo "ok - an unknown version is refused"
else
  echo "NOT OK - an unknown version is refused: got status $status [$output]"
  failures=$((failures + 1))
fi

output=$(sh "$notes" 1.1 "$changelog" 2>&1) || true
if printf '%s\n' "$output" | grep -qF 'no release section'; then
  echo "ok - a version is matched exactly, never as a prefix"
else
  echo "NOT OK - a version is matched exactly: [$output]"
  failures=$((failures + 1))
fi

if [ "$failures" -eq 0 ]; then
  echo "All changelog check tests passed."
  exit 0
fi

echo "$failures changelog check test(s) failed."
exit 1
