#!/bin/sh
#
# Posts the suggested fixes a github-comment report carries as one
# pull-request review, so each becomes a one-click GitHub suggestion.
#
# A suggestion is posted only when GitHub will take it and it still fits the
# code: every line it replaces is a line of the pull request's diff, the head
# commit holds exactly the lines it was written for, and no earlier run of this
# script posted it. Nothing here fails the job: a review GitHub refuses is a
# warning, and the summary comment still lists every suggestion.
#
# Environment: SSA_COMMENT_FILE (the github-comment report), SSA_REPOSITORY
# (owner/name), SSA_PULL_NUMBER, SSA_HEAD_SHA, and optionally SSA_BOT_LOGIN
# (the account the job's token posts as, github-actions[bot] by default).

set -eu

bot_login=${SSA_BOT_LOGIN:-github-actions[bot]}
pull="repos/$SSA_REPOSITORY/pulls/$SSA_PULL_NUMBER"

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

encoded=$(sed -n 's/^<!-- symfony-security-auditor:review-suggestions:\([A-Za-z0-9+/=]*\) -->$/\1/p' "$SSA_COMMENT_FILE" | head -n 1)
if [ -z "$encoded" ]; then
  echo 'The report carries no suggested fix to post as a review.'
  exit 0
fi

if ! printf '%s' "$encoded" | base64 -d > "$work/suggestions.json" 2> /dev/null \
  || ! jq -e 'type == "array" and all(.[]; (.key | type) == "string" and (.path | type) == "string" and (.start_line | type) == "number" and (.line | type) == "number" and (.expected | type) == "array" and (.body | type) == "string")' "$work/suggestions.json" > /dev/null 2>&1; then
  echo '::warning::The suggested fixes of the report could not be read. No review was posted.'
  exit 0
fi

gh api --paginate "$pull/files" | jq -s '
  def right_lines:
    reduce (split("\n")[]) as $line ({next: 0, lines: []};
      if ($line | startswith("@@")) then .next = ($line | capture("\\+(?<start>[0-9]+)") | .start | tonumber)
      elif ($line | startswith("-")) or ($line | startswith("\\")) then .
      else .lines += [.next] | .next += 1
      end)
    | .lines;
  add // [] | map({key: .filename, value: ((.patch // "") | right_lines)}) | from_entries
' > "$work/diff-lines.json"

gh api --paginate "$pull/comments" | jq -s --arg bot "$bot_login" '
  add // [] | map(select(.user.login == $bot) | .body | capture("<!-- symfony-security-auditor:suggestion:(?<key>[^ ]+) -->") | .key)
' > "$work/posted-keys.json"

jq --slurpfile diff "$work/diff-lines.json" --slurpfile posted "$work/posted-keys.json" '
  map(select(
    (.key | IN($posted[0][]) | not)
    and ([range(.start_line; .line + 1)] - ($diff[0][.path] // []) == [])
  ))
' "$work/suggestions.json" > "$work/candidates.json"

printf '[]' > "$work/comments.json"
count=$(jq 'length' "$work/candidates.json")
index=0
while [ "$index" -lt "$count" ]; do
  jq ".[$index]" "$work/candidates.json" > "$work/candidate.json"
  path=$(jq -r '.path | split("/") | map(@uri) | join("/")' "$work/candidate.json")
  if gh api -H 'Accept: application/vnd.github.raw+json' "repos/$SSA_REPOSITORY/contents/$path?ref=$SSA_HEAD_SHA" > "$work/head-file" 2> /dev/null \
    && jq -e --rawfile content "$work/head-file" '($content | gsub("\r\n"; "\n") | split("\n"))[.start_line - 1:.line] == .expected' "$work/candidate.json" > /dev/null; then
    jq --slurpfile candidate "$work/candidate.json" '
      . + [$candidate[0] | {path, body, line, side: "RIGHT"} + (if .start_line < .line then {start_line, start_side: "RIGHT"} else {} end)]
    ' "$work/comments.json" > "$work/comments.next.json"
    mv "$work/comments.next.json" "$work/comments.json"
  fi
  index=$((index + 1))
done

posting=$(jq 'length' "$work/comments.json")
if [ "$posting" -eq 0 ]; then
  echo 'No suggested fix falls on lines of this pull request that still hold the code it was written for, or each was posted already.'
  exit 0
fi

jq -n --arg sha "$SSA_HEAD_SHA" --slurpfile comments "$work/comments.json" \
  '{commit_id: $sha, event: "COMMENT", body: "Suggested fixes from the security audit.", comments: $comments[0]}' > "$work/review.json"

if ! url=$(gh api -X POST "$pull/reviews" --input "$work/review.json" --jq '.html_url' 2> "$work/error"); then
  echo "::warning::GitHub refused the review of suggested fixes: $(head -n 1 "$work/error"). The summary comment still lists them."
  exit 0
fi

echo "Posted $posting suggested fix(es) as a review: $url"
