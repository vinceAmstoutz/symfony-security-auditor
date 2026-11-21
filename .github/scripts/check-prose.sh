#!/bin/sh
#
# Checks Markdown files against .claude/rules/prose-style.md. CI runs it on
# every pull request; run it yourself before pushing:
#
#   sh .github/scripts/check-prose.sh file.md...
#
# The released sections of a CHANGELOG.md are left as they were published.
#
# Prints one ::error:: annotation per problem and exits 1 when there is any.

set -eu

LC_ALL=C
export LC_ALL

status=0
for file in "$@"; do
  if [ ! -f "$file" ]; then
    echo "::error::$file does not exist."
    status=1
    continue
  fi

  changelog=0
  case "$file" in
    CHANGELOG.md | */CHANGELOG.md) changelog=1 ;;
  esac

  tr -d '\r' <"$file" | awk -v file="$file" -v changelog="$changelog" '
function fail(message) {
  printf "::error file=%s,line=%d::%s (.claude/rules/prose-style.md)\n", file, NR, message
  errors++
}

changelog && /^## \[/ && !/^## \[Unreleased\]/ { released = 1 }

released { next }

/^[ \t]*(```|~~~)/ {
  fenced = !fenced
  next
}

fenced { next }

{
  text = $0
  gsub(/``([^`]|`[^`])*``/, "", text)
  gsub(/`[^`]*`/, "", text)
}

text ~ /\342\200(\224|\223)/ {
  fail("Write a period, a colon, a comma or parentheses instead of a dash.")
}

text ~ /, and / {
  fail("Write no comma before \"and\": \"A, B and C\", or split the sentence.")
}

END { exit errors > 0 }
' || status=1
done

exit "$status"
