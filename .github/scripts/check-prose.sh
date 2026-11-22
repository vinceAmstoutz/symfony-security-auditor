#!/bin/sh
#
# Checks Markdown files, and the comments and docblocks of PHP files, against
# .claude/rules/prose-style.md. CI runs it on every pull request; run it
# yourself before pushing:
#
#   sh .github/scripts/check-prose.sh              # every tracked .md and .php file
#   sh .github/scripts/check-prose.sh file.md...   # the files given
#
# Without arguments it skips fixture directories and the PHP of examples/,
# whose text is test data. The released sections of a CHANGELOG.md are left as
# they were published.
#
# Prints one ::error:: annotation per problem and exits 1 when there is any.

set -eu

LC_ALL=C
export LC_ALL

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)

numbered_lines() {
  case "$1" in
    *.php) php "$script_dir/prose-comments.php" "$1" ;;
    *) awk '{ print NR "\t" $0 }' "$1" ;;
  esac
}

if [ "$#" -eq 0 ] && [ -z "${PROSE_FILES_LISTED:-}" ]; then
  PROSE_FILES_LISTED=1
  export PROSE_FILES_LISTED
  git ls-files -z -- '*.md' '*.php' \
    ':(exclude,glob)**/Fixture/**' ':(exclude,glob)**/Fixtures/**' \
    ':(exclude,glob)examples/**/*.php' ':(exclude).castor.stub.php' |
    xargs -0 sh "$0"
  exit
fi

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

  numbered_lines "$file" | tr -d '\r' | awk -v file="$file" -v changelog="$changelog" '
function fail(message) {
  printf "::error file=%s,line=%d::%s (.claude/rules/prose-style.md)\n", file, line, message
  errors++
}

{
  tab = index($0, "\t")
  line = substr($0, 1, tab - 1)
  $0 = substr($0, tab + 1)
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

  prose = $0
  gsub(/``([^`]|`[^`])*``/, "code", prose)
  gsub(/`[^`]*`/, "code", prose)
  sub(/^[ \t]*(\/\*\*|\/\*|\*\/|\*|\/\/|#)?[ \t]*/, "", prose)
}

text ~ /\342\200(\224|\223)/ {
  fail("Write a period, a colon, a comma or parentheses instead of a dash.")
}

text ~ /, and( |$)/ || (line == previous_line + 1 && previous ~ /,[ \t]*$/ && prose ~ /^and /) {
  fail("Write no comma before \"and\": \"A, B and C\", or split the sentence.")
}

{
  previous = prose
  previous_line = line
}

END { exit errors > 0 }
' || status=1
done

exit "$status"
