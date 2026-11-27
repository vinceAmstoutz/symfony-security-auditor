#!/bin/sh
#
# POSIX tests for .github/scripts/release.sh, which prepares a release
# (changelog promotion, version pins) and checks that everything a release
# publishes points at its version.
#
# Run with any POSIX shell and git: sh tests/Shell/release_script_test.sh

set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
release="$script_dir/.github/scripts/release.sh"

failures=0
workspaces=''
trap 'for w in $workspaces; do rm -rf "$w"; done' EXIT

link() {
  printf '([#%s](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/%s))' "$1" "$1"
}

write_pins() {
  mkdir -p docs resources
  printf 'Pin the action: `uses: vinceamstoutz/symfony-security-auditor@%s`\n' "$1" >README.md
  printf '        uses: vinceamstoutz/symfony-security-auditor@%s\n' "$1" >docs/ci.md
  printf -- '- Pin `uses: vinceamstoutz/symfony-security-auditor@%s`.\n' "$1" >docs/versioning.md
  printf '{\n  "$id": "https://raw.githubusercontent.com/vinceamstoutz/symfony-security-auditor/%s/resources/schema.json"\n}\n' "$1" >resources/schema.json
}

release_ready_repo() {
  workspace=$(mktemp -d)
  workspaces="$workspaces $workspace"
  cd "$workspace"
  git init -q .
  cat >CHANGELOG.md <<CHANGELOG
# Changelog

Notable changes.

## [Unreleased]

## [1.1.0] — 2026-02-01 — Second

### Bugfixes 🐛

- A thing is fixed $(link 2)

## [1.0.0] — 2026-01-01 — First

### New Features ✨

- A thing exists $(link 1)

[1.1.0]: https://github.com/vinceAmstoutz/symfony-security-auditor/releases/tag/1.1.0
[1.0.0]: https://github.com/vinceAmstoutz/symfony-security-auditor/releases/tag/1.0.0
CHANGELOG
  write_pins 1.1.0
  git add -A
}

unreleased_repo() {
  release_ready_repo
  awk -v entry="- Another thing is fixed $(link 3)" '{ print } /^## \[Unreleased\]$/ { print ""; print "### Bugfixes 🐛"; print ""; print entry }' CHANGELOG.md >CHANGELOG.tmp && mv CHANGELOG.tmp CHANGELOG.md
}

run_release() {
  status=0
  output=$(sh "$release" "$@" 2>&1) || status=$?
  cd "$script_dir"
}

expect_pass() {
  if [ "$status" -eq 0 ]; then
    echo "ok - $1"
  else
    echo "NOT OK - $1: expected a pass, got status $status [$output]"
    failures=$((failures + 1))
  fi
}

expect_error() {
  if [ "$status" -ne 0 ] && printf '%s\n' "$output" | grep -F -- "$2" | grep -qF '::error'; then
    echo "ok - $1"
  else
    echo "NOT OK - $1: expected an ::error:: naming [$2], got status $status [$output]"
    failures=$((failures + 1))
  fi
}

expect_pins() {
  stale=$(grep -rnoE 'symfony-security-auditor[@/][0-9]+\.[0-9]+\.[0-9]+' "$workspace/README.md" "$workspace/docs" "$workspace/resources" | grep -vE "symfony-security-auditor[@/]$2\$" || true)
  pinned=$(grep -rlE "symfony-security-auditor[@/]$2" "$workspace/README.md" "$workspace/docs" "$workspace/resources" | wc -l)
  if [ "$status" -eq 0 ] && [ -z "$stale" ] && [ "$pinned" -eq 4 ]; then
    echo "ok - $1"
  else
    echo "NOT OK - $1: status $status, $pinned of 4 files pin $2, stale [$stale] [$output]"
    failures=$((failures + 1))
  fi
}

release_ready_repo
run_release check 1.1.0
expect_pass 'a repository whose changelog and pins name the version passes the check'

release_ready_repo
printf 'Pin the action: `uses: vinceamstoutz/symfony-security-auditor@%s`\n' 1.0.0 >README.md
run_release check 1.1.0
expect_error 'a pin left at the previous version fails' 'README.md:1 pins 1.0.0, not 1.1.0'

release_ready_repo
printf '{}\n' >resources/schema.json
run_release check 1.1.0
expect_error 'a pinned file that lost its pin fails' 'resources/schema.json holds no version pin'

release_ready_repo
write_pins 1.2.0
run_release check 1.2.0
expect_error 'a changelog whose newest release is another version fails' 'CHANGELOG.md: the newest release is 1.1.0, not 1.2.0'

release_ready_repo
grep -v '^\[1\.1\.0\]: ' CHANGELOG.md >CHANGELOG.tmp && mv CHANGELOG.tmp CHANGELOG.md
run_release check 1.1.0
expect_error 'a release without its link reference fails' 'CHANGELOG.md has no [1.1.0]: link reference'

release_ready_repo
awk '{ print } /^## \[Unreleased\]$/ { print ""; print "### Bugfixes 🐛"; print ""; print "- A pending fix" }' CHANGELOG.md >CHANGELOG.tmp && mv CHANGELOG.tmp CHANGELOG.md
run_release check 1.1.0
expect_error 'an entry without its pull request link fails, even under Unreleased' 'ends with the pull request that shipped it'

release_ready_repo
run_release check v1.1
expect_error 'a version that is not X.Y.Z is refused' '"v1.1" is not an X.Y.Z version'

release_ready_repo
run_release bump 1.2.0
expect_pins 'bump points every pin at the new version' 1.2.0

unreleased_repo
run_release prepare 1.2.0 Third
expected_head="## [Unreleased]

## [1.2.0] — $(date -u +%Y-%m-%d) — Third

### Bugfixes 🐛"
actual_head=$(sed -n '/^## \[Unreleased\]$/,/^### /p' "$workspace/CHANGELOG.md")
if [ "$status" -eq 0 ] && [ "$actual_head" = "$expected_head" ]; then
  echo "ok - prepare promotes Unreleased to the dated, named release and passes the check"
else
  echo "NOT OK - prepare promotes Unreleased: status $status, head [$actual_head] [$output]"
  failures=$((failures + 1))
fi

unreleased_repo
run_release prepare 1.0.9 Third
expect_error 'prepare refuses a version that is not newer than the last release' '1.0.9 is not newer than the last release, 1.1.0'

release_ready_repo
run_release prepare 1.2.0 Third
expect_error 'prepare refuses a release with nothing under Unreleased' 'CHANGELOG.md has no entry under ## [Unreleased]: nothing to release.'

unreleased_repo
run_release prepare 1.2.0 'two words'
expect_error 'prepare refuses a codename that is not one capitalized word' '"two words" is not a one-word codename such as Waypoint.'

if [ "$failures" -eq 0 ]; then
  echo "All release script tests passed."
  exit 0
fi

echo "$failures release script test(s) failed."
exit 1
