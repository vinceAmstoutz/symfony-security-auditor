#!/bin/sh
#
# POSIX tests for .github/scripts/check-prose.sh, the prose style check CI runs
# on the Markdown files (.claude/rules/prose-style.md).
#
# Run with any POSIX shell: sh tests/Shell/prose_check_test.sh

set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
check="$script_dir/.github/scripts/check-prose.sh"

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
doc="$work/doc.md"

failures=0

run_check() {
  status=0
  output=$(sh "$check" "$@" 2>&1) || status=$?
}

expect_pass() {
  if [ "$status" -eq 0 ] && [ -z "$output" ]; then
    echo "ok - $1"
  else
    echo "NOT OK - $1: expected a pass, got status $status [$output]"
    failures=$((failures + 1))
  fi
}

expect_error() {
  if [ "$status" -ne 0 ] && printf '%s\n' "$output" | grep -qF -- "$2"; then
    echo "ok - $1"
  else
    echo "NOT OK - $1: expected [$2], got status $status [$output]"
    failures=$((failures + 1))
  fi
}

printf '# Title\n\nThe audit runs \342\200\224 in the bundle and the binary.\n' >"$doc"
run_check "$doc"
expect_error 'an em dash in prose is refused' "::error file=$doc,line=3::"

printf 'The progress line reads `chunk 6/12 failed \342\200\224 tool-call limit reached`.\n' >"$doc"
run_check "$doc"
expect_pass 'an em dash inside inline code passes'

printf 'Run it:\n\n```text\nchunk 6/12 failed \342\200\224 limit reached\n```\n\n~~~\nA \342\200\224 B\n~~~\n' >"$doc"
run_check "$doc"
expect_pass 'a fenced code block passes'

printf 'It scans, filters, and reports.\n' >"$doc"
run_check "$doc"
expect_error 'a comma before and is refused' 'no comma before'

printf 'A score from 0 \342\200\223 100.\n' >"$doc"
run_check "$doc"
expect_error 'an en dash is refused' 'instead of a dash'

changelog="$work/CHANGELOG.md"
printf '# Changelog\n\n## [Unreleased]\n\n- Add a flag\n\n## [1.2.0] \342\200\224 2026-05-25 \342\200\224 Cartographer\n\n- Map routes \342\200\224 all of them, and fast\n' >"$changelog"
run_check "$changelog"
expect_pass 'a released section of the changelog passes'

printf '# Changelog\n\n## [Unreleased]\n\n- Add a flag \342\200\224 for CI\n' >"$changelog"
run_check "$changelog"
expect_error 'the unreleased section of the changelog is checked' "::error file=$changelog,line=5::"

printf '| Example | `` `audit:diff` compares reports \342\200\224 in the bundle. `` |\n' >"$doc"
run_check "$doc"
expect_pass 'an em dash inside a double-backtick code span passes'

run_check "$work/missing.md"
expect_error 'a missing file is refused' "$work/missing.md does not exist."

if [ "$failures" -eq 0 ]; then
  echo "All prose check tests passed."
  exit 0
fi

echo "$failures prose check test(s) failed."
exit 1
