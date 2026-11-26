#!/bin/sh
#
# Claude Code PreToolUse hook: refuses an Edit or Write that adds a
# quality-gate suppression, which CLAUDE.md → Never Silence Quality Gates
# forbids. Exit 2 blocks the tool call and shows Claude the reason.

set -eu

payload=$(cat)

file=$(printf '%s' "$payload" | jq -r '.tool_input.file_path // ""')

case $file in
  *.php) ;;
  *) exit 0 ;;
esac

after=$(printf '%s' "$payload" | jq -r '.tool_input.new_string // .tool_input.content // ""')
before=$(printf '%s' "$payload" | jq -r '.tool_input.old_string // ""')

if printf '%s' "$payload" | jq -e '.tool_input | has("content")' >/dev/null && [ -f "$file" ]; then
  before=$(cat -- "$file")
fi

occurrences() {
  printf '%s' "$1" | grep -oF -- "$2" | wc -l
}

for marker in '@phpstan-ignore' '@infection-ignore' '@codeCoverageIgnore' 'markTestSkipped(' 'expectNotToPerformAssertions('; do
  if [ "$(occurrences "$after" "$marker")" -gt "$(occurrences "$before" "$marker")" ]; then
    echo "Refused: $marker silences a quality gate. Fix the code it flags instead (CLAUDE.md → Never Silence Quality Gates)." >&2
    exit 2
  fi
done
