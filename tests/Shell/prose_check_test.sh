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

php_file="$work/Example.php"
printf '<?php\n\nfinal class Example\n{\n    // Runs once \342\200\224 then caches.\n    public function run(): void {}\n}\n' >"$php_file"
run_check "$php_file"
expect_error 'an em dash in a PHP comment is refused' "::error file=$php_file,line=5::"

printf '<?php\n\necho "chunk failed \342\200\224 limit reached, and retried";\n' >"$php_file"
run_check "$php_file"
expect_pass 'an em dash or a comma before and in a PHP string passes'

printf '<?php\n\n/**\n * Reads the file.\n *\n * It scans, filters, and reports.\n */\nfunction read(): void {}\n' >"$php_file"
run_check "$php_file"
expect_error 'a comma before and in a docblock is refused at its own line' "::error file=$php_file,line=6::"

printf '<?php\n\n/**\n * It scans, filters,\n * and reports.\n */\nfunction scan(): void {}\n' >"$php_file"
run_check "$php_file"
expect_error 'a comma before and wrapped over two docblock lines is refused' "::error file=$php_file,line=5::"

printf '<?php\n\n/**\n * It scans, filters, and\n * reports.\n */\nfunction scan(): void {}\n' >"$php_file"
run_check "$php_file"
expect_error 'a comment line ending with a comma and and is refused' "::error file=$php_file,line=4::"

printf '<?php\n\n/**\n * Requirements: roles, `methods`,\n * `ips` and `requires_channel`.\n */\nfunction scan(): void {}\n' >"$php_file"
run_check "$php_file"
expect_pass 'a wrapped list whose next line opens with inline code passes'

printf '<?php\n\n/**\n * Kept since 1.21 for old baselines.\n */\nfunction keep(): void {}\n' >"$php_file"
run_check "$php_file"
expect_error 'a version history in a PHP comment is refused' "::error file=$php_file,line=4::State the current contract"

printf '<?php\n\n/**\n * Reads the lockfile PHP 8.4 writes.\n *\n * @deprecated since 1.22, use read() instead\n */\nfunction old(): void {}\n' >"$php_file"
run_check "$php_file"
expect_pass 'a deprecation tag and a third-party version in a PHP comment pass'

printf '_Since 1.22._ The option is read before 1.23 ships.\n' >"$doc"
run_check "$doc"
expect_pass 'a version history in Markdown passes'

printf '<?php\n\n// Reads the file as earlier releases did.\nfunction cache(): void {}\n' >"$php_file"
run_check "$php_file"
expect_error 'a history word in a PHP comment is refused' "::error file=$php_file,line=3::State the current contract"

printf '<?php\n\n// Splits the chunk, see #378.\nfunction split(): void {}\n' >"$php_file"
run_check "$php_file"
expect_error 'an issue number in a PHP comment is refused' "::error file=$php_file,line=3::State the current contract"

printf '<?php\n\n/**\n * Here we retry once.\n */\nfunction retry(): void {}\n' >"$php_file"
run_check "$php_file"
expect_error 'a first-person narrative in a PHP comment is refused' "::error file=$php_file,line=4::State the contract without"

printf '<?php\n\n// Reads the file once.\n// Then caches it.\nfunction read(): void {}\n' >"$php_file"
run_check "$php_file"
expect_error 'a comment block of several // lines is refused' "::error file=$php_file,line=4::Keep a comment to one line"

printf '<?php\n\n$width = 2; // in characters\n$height = 4; // in lines\n' >"$php_file"
run_check "$php_file"
expect_pass 'trailing comments on consecutive code lines pass'

repo="$work/repo"
mkdir -p "$repo/src" "$repo/tests/Fixture" "$repo/examples"
printf '<?php\n// Clean comment.\n' >"$repo/src/Clean.php"
printf '<?php\n// Sample \342\200\224 kept as test data.\n' >"$repo/tests/Fixture/Sample.php"
printf '<?php\n// Example \342\200\224 app.\n' >"$repo/examples/App.php"
printf 'Fine prose.\n' >"$repo/README.md"
printf '<?php\n// Untracked \342\200\224 file.\n' >"$repo/src/Untracked.php"
git -C "$repo" init -q
git -C "$repo" add src/Clean.php tests/Fixture/Sample.php examples/App.php README.md
status=0
output=$(cd "$repo" && sh "$check" 2>&1) || status=$?
expect_pass 'without arguments, the tracked Markdown and PHP files outside fixtures and examples pass'

printf '<?php\n// Tracked \342\200\224 code.\n' >"$repo/src/Clean.php"
status=0
output=$(cd "$repo" && sh "$check" 2>&1) || status=$?
expect_error 'without arguments, a tracked PHP file is checked' "::error file=src/Clean.php,line=2::"

if [ "$failures" -eq 0 ]; then
  echo "All prose check tests passed."
  exit 0
fi

echo "$failures prose check test(s) failed."
exit 1
