#!/bin/sh
#
# Prints the GitHub release notes of one version: its CHANGELOG.md section, with
# the "###" headings promoted to "##", each entry credited to the authors of the
# pull requests it links, then the compare link. The "Auto Release" workflow
# publishes this output, so the release page and the changelog can never drift
# apart.
#
#   REPO=owner/name PREVIOUS_TAG=1.20.1 sh .github/scripts/release-notes.sh 1.21.0 [CHANGELOG.md]
#
# Without PREVIOUS_TAG (the very first release) the compare link is left out.
# Exits 1 when the version has no section or the section holds no entry.
#
# Credits come from the GitHub API through `gh` (set GH_TOKEN, or log in): an
# entry that ends with pull request or commit links gets ` by @author` appended
# (`by @a and @b` for two, `by @a, @b and @c` for more, in the order the links
# come), leaving out a bot (a login ending in `[bot]`). An author that cannot be
# looked up leaves the entry as it is with a
# ::warning::, since a missing credit must never block a release. Set
# CREDIT_AUTHORS=0 to print the notes without any lookup.

set -eu

LC_ALL=C
export LC_ALL

version=${1:-}
file=${2:-CHANGELOG.md}
repo=${REPO:-vinceAmstoutz/symfony-security-auditor}
previous=${PREVIOUS_TAG:-}
credit=${CREDIT_AUTHORS:-1}

if [ -z "$version" ]; then
  echo "::error::Usage: release-notes.sh <X.Y.Z> [CHANGELOG.md]"
  exit 1
fi

if [ ! -f "$file" ]; then
  echo "::error::$file does not exist."
  exit 1
fi

credit_authors() {
  if ! command -v gh >/dev/null 2>&1; then
    echo "::warning::gh is not installed: the entries are left uncredited." >&2
    cat
    return 0
  fi

  work=$(mktemp -d)
  trap 'rm -rf "$work"' EXIT

  cat >"$work/notes"
  : >"$work/authors"

  grep -oE '\[#[0-9]+\]\(' "$work/notes" | tr -dc '0-9\n' | sort -u >"$work/pulls" || true
  grep -oE '/commit/[0-9a-f]+' "$work/notes" | cut -d/ -f3 | sort -u >"$work/commits" || true

  while IFS= read -r number; do
    [ -n "$number" ] || continue
    if login=$(gh api "repos/$repo/issues/$number" --jq '.user.login // empty' 2>/dev/null); then
      printf 'pr:%s\t%s\n' "$number" "$login" >>"$work/authors"
    else
      echo "::warning::Could not look up the author of #$number: its entry is left uncredited." >&2
    fi
  done <"$work/pulls"

  while IFS= read -r sha; do
    [ -n "$sha" ] || continue
    if login=$(gh api "repos/$repo/commits/$sha" --jq '.author.login // empty' 2>/dev/null); then
      printf 'commit:%s\t%s\n' "$sha" "$login" >>"$work/authors"
    else
      echo "::warning::Could not look up the author of commit $sha: its entry is left uncredited." >&2
    fi
  done <"$work/commits"

  awk '
  FNR == NR {
    who[$1] = $2
    next
  }

  /^- / && /\)$/ {
    line = $0
    rest = line
    count = 0
    delete seen
    delete names
    while (match(rest, /\[#[0-9]+\]\(|\/commit\/[0-9a-f]+/)) {
      token = substr(rest, RSTART, RLENGTH)
      rest = substr(rest, RSTART + RLENGTH)
      if (substr(token, 1, 2) == "[#") {
        key = "pr:" substr(token, 3, length(token) - 4)
      } else {
        key = "commit:" substr(token, 9)
      }
      login = who[key]
      if (login == "" || login ~ /\[bot\]$/ || (login in seen)) {
        continue
      }
      seen[login] = 1
      names[++count] = "@" login
    }
    if (count > 0) {
      credit = names[1]
      for (i = 2; i <= count; i++) {
        credit = credit (i == count ? " and " : ", ") names[i]
      }
      line = line " by " credit
    }
    print line
    next
  }

  {
    print
  }
  ' "$work/authors" "$work/notes"
}

notes=$(tr -d '\r' <"$file" | awk -v version="$version" '
$0 ~ /^## \[/ {
  if (inside) {
    exit
  }
  inside = (index($0, "## [" version "]") == 1)
  next
}

/^\[[^]]+\]: https?:\/\// {
  if (inside) {
    exit
  }
}

inside {
  if ($0 ~ /^### /) {
    sections++
    sub(/^### /, "## ")
  }
  lines[++count] = $0
}

END {
  if (sections == 0) {
    exit 1
  }
  while (count > 0 && lines[count] == "") {
    count--
  }
  first = 1
  while (first <= count && lines[first] == "") {
    first++
  }
  for (i = first; i <= count; i++) {
    print lines[i]
  }
}
') || {
  echo "::error::$file has no release section with entries for $version."
  exit 1
}

if [ "$credit" != "0" ]; then
  notes=$(printf '%s\n' "$notes" | credit_authors)
fi

printf '%s\n' "$notes"

if [ -n "$previous" ]; then
  printf '\n**Full Changelog**: https://github.com/%s/compare/%s...%s\n' "$repo" "$previous" "$version"
fi
