#!/bin/sh
#
# POSIX tests for .claude/hooks/block-quality-gate-suppressions.sh, the
# Claude Code PreToolUse hook that refuses an edit adding a quality-gate
# suppression to a PHP file.
#
# Run with any POSIX shell and jq: sh tests/Shell/claude_hooks_test.sh

set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
hook="$script_dir/.claude/hooks/block-quality-gate-suppressions.sh"

failures=0

run_hook() {
  status=0
  output=$(printf '%s' "$1" | sh "$hook" 2>&1) || status=$?
}

edit_payload() {
  jq -cn --arg path "$1" --arg new "$2" \
    '{tool_name: "Edit", tool_input: {file_path: $path, old_string: "return 1;", new_string: $new}}'
}

replace_payload() {
  jq -cn --arg path "$1" --arg old "$2" --arg new "$3" \
    '{tool_name: "Edit", tool_input: {file_path: $path, old_string: $old, new_string: $new}}'
}

write_payload() {
  jq -cn --arg path "$1" --arg content "$2" \
    '{tool_name: "Write", tool_input: {file_path: $path, content: $content}}'
}

expect_blocked() {
  run_hook "$3"
  if [ "$status" -eq 2 ] && printf '%s\n' "$output" | grep -qF -- "$2"; then
    echo "ok - $1"
  else
    echo "NOT OK - $1: expected exit 2 naming [$2], got status $status [$output]"
    failures=$((failures + 1))
  fi
}

expect_allowed() {
  run_hook "$2"
  if [ "$status" -eq 0 ]; then
    echo "ok - $1"
  else
    echo "NOT OK - $1: expected exit 0, got status $status [$output]"
    failures=$((failures + 1))
  fi
}

expect_blocked 'an edit adding @phpstan-ignore to a PHP file is refused' '@phpstan-ignore' \
  "$(edit_payload src/Foo.php '// @phpstan-ignore-next-line
return 1;')"

expect_blocked 'a new PHP file holding @phpstan-ignore is refused' '@phpstan-ignore' \
  "$(write_payload src/Foo.php '<?php /** @phpstan-ignore argument.type */')"

for marker in '@infection-ignore' '@codeCoverageIgnore' 'markTestSkipped(' 'expectNotToPerformAssertions('; do
  expect_blocked "an edit adding $marker to a PHP file is refused" "$marker" \
    "$(edit_payload tests/FooTest.php "/** $marker */")"
done

expect_allowed 'an edit keeping a suppression already in the file is allowed' \
  "$(replace_payload tests/FooTest.php 'self::expectNotToPerformAssertions();
$a = 1;' 'self::expectNotToPerformAssertions();
$a = 2;')"

existing_dir=$(mktemp -d)
trap 'rm -rf "$existing_dir"' EXIT
printf '%s\n' '<?php self::expectNotToPerformAssertions();' >"$existing_dir/FooTest.php"
expect_allowed 'rewriting a file that already holds a suppression is allowed' \
  "$(write_payload "$existing_dir/FooTest.php" '<?php self::expectNotToPerformAssertions(); $a = 2;')"

expect_allowed 'a Markdown file may name a suppression' \
  "$(edit_payload CLAUDE.md 'Forbidden: `@phpstan-ignore`.')"

if [ "$failures" -eq 0 ]; then
  echo "All Claude hook tests passed."
  exit 0
fi

echo "$failures Claude hook test(s) failed."
exit 1
