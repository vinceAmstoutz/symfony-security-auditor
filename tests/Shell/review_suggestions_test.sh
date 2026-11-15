#!/bin/sh
#
# POSIX tests for resources/action/post-review-suggestions.sh, which the
# GitHub Action runs to post the suggested fixes of a github-comment report
# as one pull-request review. A fake `gh` on PATH serves the pull request.
#
# Run with any POSIX shell: sh tests/Shell/review_suggestions_test.sh

set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
post="$script_dir/resources/action/post-review-suggestions.sh"

failures=0
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

mkdir -p "$work/bin"
cat > "$work/bin/gh" <<'GH'
#!/bin/sh
endpoint='' input='' method=GET
while [ $# -gt 0 ]; do
  case "$1" in
    -X) method=$2; shift ;;
    --input) input=$2; shift ;;
    -H|--jq) shift ;;
    repos/*) endpoint=$1 ;;
  esac
  shift
done
case "$method $endpoint" in
  'POST repos/acme/shop/pulls/7/reviews')
    [ -f "$FAKE_GH/post-fails" ] && { echo 'HTTP 422: Unprocessable Entity' >&2; exit 1; }
    cp "$input" "$FAKE_GH/posted.json"
    echo 'https://github.com/acme/shop/pull/7#pullrequestreview-1' ;;
  'GET repos/acme/shop/pulls/7/files') cat "$FAKE_GH/files.json" ;;
  'GET repos/acme/shop/pulls/7/comments') cat "$FAKE_GH/comments.json" ;;
  'GET repos/acme/shop/contents/'*) cat "$FAKE_GH/head/$(printf '%s' "${endpoint#repos/acme/shop/contents/}" | sed 's/?ref=.*//')" ;;
  *) echo "unexpected gh call: $method $endpoint" >&2; exit 1 ;;
esac
GH
chmod +x "$work/bin/gh"

suggestion() {
  printf '{"key":"%s","path":"%s","start_line":%s,"line":%s,"expected":%s,"body":"%s"}' "$1" "$2" "$3" "$4" "$5" "$6"
}

reset_pull_request() {
  rm -rf "$work/gh"
  mkdir -p "$work/gh/head/src"
  printf '<?php\n$id = $request->get("id");\n$sql = "SELECT $id";\nreturn $sql;\n// end\n' > "$work/gh/head/src/Repo.php"
  printf '[{"filename":"src/Repo.php","status":"modified","patch":"@@ -1,2 +1,4 @@\\n <?php\\n+$id = $request->get(\\"id\\");\\n+$sql = \\"SELECT $id\\";\\n+return $sql;"}]' > "$work/gh/files.json"
  printf '[]' > "$work/gh/comments.json"
}

write_comment() {
  printf '<!-- symfony-security-auditor:pr-comment -->\n\n## Security audit\n\n---\n\nGenerated.\n\n<!-- symfony-security-auditor:review-suggestions:%s -->\n' "$(printf '[%s]' "$1" | base64 | tr -d '\n')" > "$work/comment.md"
}

run_post() {
  status=0
  output=$(PATH="$work/bin:$PATH" FAKE_GH="$work/gh" SSA_COMMENT_FILE="$work/comment.md" SSA_REPOSITORY=acme/shop SSA_PULL_NUMBER=7 SSA_HEAD_SHA=abc123 sh "$post" 2>&1) || status=$?
}

posted() {
  if [ -f "$work/gh/posted.json" ]; then jq -c "$1" "$work/gh/posted.json"; else echo 'nothing posted'; fi
}

expect() {
  if [ "$2" = "$3" ]; then
    echo "ok - $1"
  else
    echo "NOT OK - $1: expected [$3], got [$2] (status $status, output: $output)"
    failures=$((failures + 1))
  fi
}

reset_pull_request
write_comment "$(suggestion 'fp1:3-3' src/Repo.php 3 3 '["$sql = \"SELECT $id\";"]' 'Fix it')"
run_post
expect 'a suggestion on lines of the diff that the head commit still holds is posted as a review' \
  "$status $(posted '[.commit_id, .event, .comments]')" \
  '0 ["abc123","COMMENT",[{"path":"src/Repo.php","body":"Fix it","line":3,"side":"RIGHT"}]]'

reset_pull_request
write_comment "$(suggestion 'fp1:2-3' src/Repo.php 2 3 '["$id = $request->get(\"id\");","$sql = \"SELECT $id\";"]' 'Fix both')"
run_post
expect 'a suggestion over several lines names the first and the last' \
  "$(posted '.comments[0] | [.start_line, .start_side, .line, .side]')" \
  '[2,"RIGHT",3,"RIGHT"]'

reset_pull_request
write_comment "$(suggestion 'fp1:5-5' src/Repo.php 5 5 '["// end"]' 'Outside')"
run_post
expect 'a suggestion on a line outside every hunk of the diff is not posted' "$status $(posted '.')" '0 nothing posted'

reset_pull_request
write_comment "$(suggestion 'fp1:2-4' src/Repo.php 2 4 '["a","b","c"]' 'Too long')"
run_post
expect 'a suggestion reaching past the diff is not posted' "$status $(posted '.')" '0 nothing posted'

reset_pull_request
write_comment "$(suggestion 'fp1:3-3' src/Other.php 3 3 '["x"]' 'Elsewhere')"
run_post
expect 'a suggestion for a file the pull request does not touch is not posted' "$status $(posted '.')" '0 nothing posted'

reset_pull_request
write_comment "$(suggestion 'fp1:3-3' src/Repo.php 3 3 '["$sql = \"SELECT 1\";"]' 'Stale')"
run_post
expect 'a suggestion whose lines the head commit no longer holds is not posted' "$status $(posted '.')" '0 nothing posted'

reset_pull_request
printf '[{"user":{"login":"github-actions[bot]"},"body":"Fix it\\n\\n<!-- symfony-security-auditor:suggestion:fp1:3-3 -->"}]' > "$work/gh/comments.json"
write_comment "$(suggestion 'fp1:3-3' src/Repo.php 3 3 '["$sql = \"SELECT $id\";"]' 'Fix it')"
run_post
expect 'a suggestion an earlier run posted is not posted again' "$status $(posted '.')" '0 nothing posted'

reset_pull_request
printf '[{"user":{"login":"mallory"},"body":"<!-- symfony-security-auditor:suggestion:fp1:3-3 -->"}]' > "$work/gh/comments.json"
write_comment "$(suggestion 'fp1:3-3' src/Repo.php 3 3 '["$sql = \"SELECT $id\";"]' 'Fix it')"
run_post
expect 'a marker someone else posted does not hold a suggestion back' "$(posted '.comments | length')" '1'

reset_pull_request
printf '<!-- symfony-security-auditor:pr-comment -->\n\nNo fix.\n' > "$work/comment.md"
run_post
expect 'a report without suggestions posts nothing' "$status $(posted '.')" '0 nothing posted'

reset_pull_request
printf '<!-- symfony-security-auditor:review-suggestions:bm90IGpzb24= -->\n' > "$work/comment.md"
run_post
expect 'suggestions it cannot read post nothing and warn' "$status $(posted '.') $(printf '%s' "$output" | grep -c '::warning::')" '0 nothing posted 1'

reset_pull_request
touch "$work/gh/post-fails"
write_comment "$(suggestion 'fp1:3-3' src/Repo.php 3 3 '["$sql = \"SELECT $id\";"]' 'Fix it')"
run_post
expect 'a review GitHub refuses warns without failing the job' "$status $(printf '%s' "$output" | grep -c '::warning::GitHub refused the review')" '0 1'

if [ "$failures" -gt 0 ]; then
  echo "$failures test(s) failed"
  exit 1
fi
