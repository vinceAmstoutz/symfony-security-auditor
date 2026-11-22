#!/bin/sh
#
# POSIX tests for .github/scripts/plan-binary-build.sh, which tells the release
# workflow whether a pull request must build the binary.
#
# Run with any POSIX shell: sh tests/Shell/plan_binary_build_test.sh

set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
plan="$script_dir/.github/scripts/plan-binary-build.sh"

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

failures=0

new_repo() {
  repo="$work/repo-$1"
  mkdir -p "$repo/src/Standalone"
  printf '<?php\n\n// Boots the binary.\nfunction boot(): int { return 1; }\n' >"$repo/src/Standalone/Boot.php"
  printf '{"require": {"php": ">=8.3"}, "require-dev": {"phpunit/phpunit": "^12"}}\n' >"$repo/composer.json"
  printf '{"main": "bin/app"}\n' >"$repo/box.json"
  git -C "$repo" init -q
  git -C "$repo" add .
  git -C "$repo" -c user.name=t -c user.email=t@t commit -qm base
}

commit() {
  git -C "$repo" add -A
  git -C "$repo" -c user.name=t -c user.email=t@t commit -qm change
}

expect_build() {
  status=0
  output=$(cd "$repo" && sh "$plan" HEAD^1 HEAD 2>&1) || status=$?
  if [ "$status" -eq 0 ] && [ "$output" = "$2" ]; then
    echo "ok - $1"
  else
    echo "NOT OK - $1: expected [$2], got status $status [$output]"
    failures=$((failures + 1))
  fi
}

new_repo comment
printf '<?php\n\n// Starts the binary.\nfunction boot(): int { return 1; }\n' >"$repo/src/Standalone/Boot.php"
commit
expect_build 'a change to a PHP comment alone skips the build' false

new_repo code
printf '<?php\n\n// Boots the binary.\nfunction boot(): int { return 2; }\n' >"$repo/src/Standalone/Boot.php"
commit
expect_build 'a change to PHP code builds' true

new_repo require_dev
printf '{"require": {"php": ">=8.3"}, "require-dev": {"phpunit/phpunit": "^13"}}\n' >"$repo/composer.json"
commit
expect_build 'a change to require-dev alone skips the build' false

new_repo require
printf '{"require": {"php": ">=8.4"}, "require-dev": {"phpunit/phpunit": "^12"}}\n' >"$repo/composer.json"
commit
expect_build 'a change to require builds' true

new_repo box
printf '{"main": "bin/other"}\n' >"$repo/box.json"
commit
expect_build 'a change to a binary input that is not PHP builds' true

new_repo added
printf '<?php\n\n// New.\n' >"$repo/src/Standalone/Added.php"
commit
expect_build 'a new PHP file builds' true

new_repo mixed
printf '<?php\n\n// Starts the binary.\nfunction boot(): int { return 1; }\n' >"$repo/src/Standalone/Boot.php"
printf '{"require": {"php": ">=8.3"}, "require-dev": {"phpunit/phpunit": "^13"}}\n' >"$repo/composer.json"
commit
expect_build 'a PHP comment and require-dev changed together skip the build' false

new_repo deleted
rm "$repo/src/Standalone/Boot.php"
commit
expect_build 'a deleted PHP file builds' true

if [ "$failures" -eq 0 ]; then
  echo "All binary build plan tests passed."
  exit 0
fi

echo "$failures binary build plan test(s) failed."
exit 1
