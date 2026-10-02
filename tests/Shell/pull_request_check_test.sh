#!/bin/sh
#
# POSIX tests for .github/scripts/check-pull-request.sh, the title and
# description check run by the "Pull request target" workflow.
#
# Run with any POSIX shell: sh tests/Shell/pull_request_check_test.sh

set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
check="$script_dir/.github/scripts/check-pull-request.sh"

failures=0

valid_parts() {
  title='fix(scan): stop following symlinks'
  base='1.x'
  summary='A symlink can no longer redirect a write.

Closes #12'
  type_of_change='- [x] Bug fix'
  target_branch='- [x] `1.x` — anything for the next minor release: bug fixes and new features'
  details=''
  checklist='- [x] Tests added or updated (unit + integration where applicable)
- [x] All checks pass: `bin/castor lint` (CI)'
}

body() {
  printf '## Summary\n\n%s\n\n## Type of change\n\n%s\n\n## Target branch\n\n%s\n\n' "$summary" "$type_of_change" "$target_branch"
  if [ -n "$details" ]; then
    printf '## Details\n\n%s\n\n' "$details"
  fi
  printf '## Checklist\n\n%s\n' "$checklist"
}

run_check() {
  status=0
  output=$(PR_TITLE=$title PR_BODY=$1 BASE_REF=$base sh "$check" 2>&1) || status=$?
}

expect_pass() {
  run_check "$2"
  if [ "$status" -eq 0 ] && ! printf '%s\n' "$output" | grep -q '::error::'; then
    echo "ok - $1"
  else
    echo "NOT OK - $1: expected a pass, got status $status [$output]"
    failures=$((failures + 1))
  fi
}

expect_error() {
  run_check "$3"
  if [ "$status" -ne 0 ] && printf '%s\n' "$output" | grep -qF -- "::error::$2"; then
    echo "ok - $1"
  else
    echo "NOT OK - $1: expected [::error::$2], got status $status [$output]"
    failures=$((failures + 1))
  fi
}

repeat() {
  count=$1
  text=''
  while [ "$count" -gt 0 ]; do
    text="$text$2"
    count=$((count - 1))
  done
  printf '%s' "$text"
}

valid_parts
expect_pass 'a description that follows the template passes' "$(body)"

valid_parts
details='- `SymlinkGuard` walks every directory between the root and the file.'
expect_pass 'an optional Details section before the Checklist passes' "$(body)"

valid_parts
title="fix: $(repeat 45 '…')"
expect_pass 'a 50-character title passes, counting characters rather than bytes' "$(body)"

valid_parts
title="fix: $(repeat 46 a)"
expect_error 'a 51-character title fails' 'The title is 51 characters; keep it to 50 or fewer.' "$(body)"

valid_parts
summary=$(repeat 500 é)
expect_pass 'a 500-character Summary passes, counting characters rather than bytes' "$(body)"

valid_parts
summary=$(repeat 501 a)
expect_error 'a 501-character Summary fails' "'## Summary' is 501 characters; keep it to 500 or fewer" "$(body)"

valid_parts
summary='<!-- What does this PR do and why? -->'
expect_error 'a Summary holding only the template comment fails' "Fill in '## Summary'" "$(body)"

valid_parts
type_of_change='- [x] Bug fix
- [ ] New feature'
expect_error 'an unticked box under Type of change fails' "Keep only the boxes you tick under '## Type of change': delete '- [ ] New feature'." "$(body)"

valid_parts
checklist='- [x] Tests added or updated (unit + integration where applicable)
- [ ] All checks pass: `bin/castor lint`'
expect_error 'an unticked box under Checklist fails' "Keep only the boxes you tick under '## Checklist': delete '- [ ] All checks pass: \`bin/castor lint\`'." "$(body)"

valid_parts
target_branch='Tick the release branch this is ultimately headed for.

- [x] `1.x` — anything for the next minor release: bug fixes and new features'
expect_error 'template instructions left under Target branch fail' "'## Target branch' holds ticked boxes only: delete 'Tick the release branch this is ultimately headed for.'." "$(body)"

valid_parts
type_of_change='<!-- Keep only the boxes you tick. -->

- [x] Bug fix'
target_branch='<!--
Tick the release branch this is ultimately headed for.
-->

- [x] `1.x` — anything for the next minor release: bug fixes and new features'
expect_pass 'instructions inside HTML comments are ignored' "$(body)"

valid_parts
checklist='- [x] No `createMock` without a matching `expects()` (use `createStub`
      otherwise)'
expect_pass 'a box wrapped over an indented line passes' "$(body)"

valid_parts
type_of_change='- [x] Bug fix'
expect_error 'no ticked box under Type of change fails' "Tick at least one box under '## Type of change'." "$(body | sed 's/^- \[x\] Bug fix$//')"

valid_parts
expect_pass 'CRLF line endings pass' "$(body | sed 's/$/\r/')"

valid_parts
expect_error 'a missing Checklist section fails' "The description is missing the '## Checklist' section from .github/PULL_REQUEST_TEMPLATE.md." "$(body | sed '/^## Checklist$/,$d')"

valid_parts
details='Verified by hand.'
expect_error 'a section outside the template fails' "'## Verification' is not a section of .github/PULL_REQUEST_TEMPLATE.md; put anything else under '## Details'." "$(body | sed 's/^## Details$/## Verification/')"

valid_parts
expect_error 'a level-one heading fails' "'# Notes' is not a section of .github/PULL_REQUEST_TEMPLATE.md" "$(body; printf '\n# Notes\n\nMore.\n')"

valid_parts
expect_error 'a section appearing twice fails' "'## Summary' appears more than once." "$(body; printf '\n## Summary\n\nAgain.\n')"

valid_parts
expect_error 'Details after the Checklist fails' 'Keep the sections in the order of .github/PULL_REQUEST_TEMPLATE.md' "$(body; printf '\n## Details\n\nLate.\n')"

valid_parts
expect_error 'text above the Summary fails' "Start the description with '## Summary': delete 'Hello reviewers' above it." "$(printf 'Hello reviewers\n\n'; body)"

valid_parts
details='```markdown
## Not a section
```'
expect_pass 'a heading inside a fenced code block is not a section' "$(body)"

valid_parts
base='claude/feature-1'
target_branch='- [x] `1.x` — anything for the next minor release: bug fixes and new features
- [x] `stacked` — based on another open PR; retarget to the release branch
      ticked above once that PR merges'
details='Stacked on #41: needs `SymlinkGuard` from it.'
expect_pass 'a stacked pull request naming its parent passes' "$(body)"

valid_parts
base='claude/feature-1'
target_branch='- [x] `1.x` — anything for the next minor release: bug fixes and new features
- [x] `stacked` — based on another open PR; retarget once that PR merges'
expect_error 'a stacked pull request that does not name its parent fails' "A stacked pull request names the one it builds on: add 'Stacked on #<number>'" "$(body)"

valid_parts
details='Stacked on #41: needs `SymlinkGuard` from it.'
expect_error 'a parent named on a pull request that is not stacked fails' "This pull request is not stacked: remove 'Stacked on #…' from the description." "$(body)"

valid_parts
target_branch='- [x] `1.x` — anything for the next minor release: bug fixes and new features
- [x] `stacked` — based on another open PR; retarget once that PR merges'
details='Stacked on #41: needs `SymlinkGuard` from it.'
expect_error 'stacked on a release branch fails' "You ticked 'stacked', which means the base should be another PR's feature branch — but this pull request is based on '1.x'." "$(body)"

valid_parts
base='main'
expect_error 'a base that differs from the ticked release branch fails' "You ticked '1.x' but opened this pull request against 'main'." "$(body)"

valid_parts
target_branch='- [x] `main` — release merges only, nothing else'
expect_error 'main ticked on another base fails' "'main' takes release merges only, but this pull request is based on '1.x'." "$(body)"

valid_parts
base='main'
target_branch='- [x] `main` — release merges only, nothing else'
expect_pass 'a release merge into main passes' "$(body)"

valid_parts
target_branch='- [x] `1.x` — anything for the next minor release: bug fixes and new features
- [x] `2.x` — breaking changes, for the next major release'
expect_error 'two release branches ticked fails' "Tick exactly one release branch under '## Target branch' (found 2)." "$(body)"

valid_parts
target_branch='- [x] `develop` — not a release branch'
expect_error 'an unknown target fails' "'develop' is not one of the targets in .github/PULL_REQUEST_TEMPLATE.md." "$(body)"

valid_parts
title="fix: $(repeat 46 a)"
type_of_change='- [x] Bug fix
- [ ] New feature'
run_check "$(body)"
if [ "$status" -ne 0 ] && [ "$(printf '%s\n' "$output" | grep -c '::error::')" -eq 2 ]; then
  echo "ok - every problem is reported in one run"
else
  echo "NOT OK - every problem is reported in one run: got status $status [$output]"
  failures=$((failures + 1))
fi

valid_parts
type_of_change='- [x] Bug fix
::add-mask::100%'
run_check "$(body)"
if printf '%s\n' "$output" | grep -q '^::add-mask::'; then
  echo "NOT OK - quoted description text never starts a workflow command: [$output]"
  failures=$((failures + 1))
elif printf '%s\n' "$output" | grep -qF -- "delete '::add-mask::100%25'"; then
  echo "ok - quoted description text never starts a workflow command and its % is escaped"
else
  echo "NOT OK - quoted description text is reported escaped: [$output]"
  failures=$((failures + 1))
fi

if [ "$failures" -eq 0 ]; then
  echo "All pull request check tests passed."
  exit 0
fi

echo "$failures pull request check test(s) failed."
exit 1
