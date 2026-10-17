#!/bin/sh
#
# Prints the GitHub release notes of one version: its CHANGELOG.md section, with
# the "###" headings promoted to "##", followed by the compare link. The "Auto
# Release" workflow publishes this output, so the release page and the
# changelog can never drift apart.
#
#   REPO=owner/name PREVIOUS_TAG=1.20.1 sh .github/scripts/release-notes.sh 1.21.0 [CHANGELOG.md]
#
# Without PREVIOUS_TAG (the very first release) the compare link is left out.
# Exits 1 when the version has no section or the section holds no entry.

set -eu

LC_ALL=C
export LC_ALL

version=${1:-}
file=${2:-CHANGELOG.md}
repo=${REPO:-vinceAmstoutz/symfony-security-auditor}
previous=${PREVIOUS_TAG:-}

if [ -z "$version" ]; then
  echo "::error::Usage: release-notes.sh <X.Y.Z> [CHANGELOG.md]"
  exit 1
fi

if [ ! -f "$file" ]; then
  echo "::error::$file does not exist."
  exit 1
fi

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

printf '%s\n' "$notes"

if [ -n "$previous" ]; then
  printf '\n**Full Changelog**: https://github.com/%s/compare/%s...%s\n' "$repo" "$previous" "$version"
fi
