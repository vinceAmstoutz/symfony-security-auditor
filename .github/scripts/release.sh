#!/bin/sh
#
# Prepares a release and checks that everything it publishes points at its
# version. Run it from the repository root:
#
#   sh .github/scripts/release.sh prepare X.Y.Z Codename
#     promotes "## [Unreleased]" to "## [X.Y.Z] — <today> — Codename", adds the
#     link reference, bumps every version pin, then checks
#   sh .github/scripts/release.sh bump X.Y.Z
#     points every version pin at X.Y.Z
#   sh .github/scripts/release.sh check X.Y.Z
#     the changelog releases X.Y.Z with every pull request link, and no tracked
#     file pins another version (the Release Guard workflow runs it on the tag)
#
# Prints one ::error:: annotation per problem and exits 1 when there is any.

set -eu

LC_ALL=C
export LC_ALL

scripts_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)

command=${1:-}
version=${2:-}
codename=${3:-}
status=0

releases_url='https://github.com/vinceAmstoutz/symfony-security-auditor/releases/tag'
pinned_files='resources/schema.json README.md docs/ci.md docs/versioning.md'
pin_pattern='symfony-security-auditor[@/][0-9]+\.[0-9]+\.[0-9]+'

fail() {
  echo "::error::$1"
  status=1
}

newest_release() {
  awk '/^## \[[0-9]+\.[0-9]+\.[0-9]+\]/ { release = $2; gsub(/[][]/, "", release); print release; exit }' CHANGELOG.md
}

check_changelog() {
  if ! CHANGELOG_REQUIRE_LINKS=all sh "$scripts_dir/check-changelog.sh" CHANGELOG.md; then
    status=1
  fi
  newest=$(newest_release)
  if [ "$newest" != "$version" ]; then
    fail "CHANGELOG.md: the newest release is $newest, not $version"
  fi
  if ! grep -qxF "[$version]: $releases_url/$version" CHANGELOG.md; then
    fail "CHANGELOG.md has no [$version]: link reference to $releases_url/$version"
  fi
}

check_pins() {
  for file in $pinned_files; do
    if ! grep -qE "$pin_pattern" "$file"; then
      fail "$file holds no version pin"
    fi
  done

  mismatches=$(git grep -noE "$pin_pattern" -- . |
    awk -F: -v version="$version" '{
      pin = $3
      sub(/^symfony-security-auditor[@\/]/, "", pin)
      if (pin != version) print $1 ":" $2 " pins " pin ", not " version
    }')
  if [ -n "$mismatches" ]; then
    while IFS= read -r mismatch; do
      fail "$mismatch"
    done <<MISMATCHES
$mismatches
MISMATCHES
  fi
}

require_version() {
  if ! printf '%s\n' "$version" | grep -qxE '[0-9]+\.[0-9]+\.[0-9]+'; then
    echo "::error::\"$version\" is not an X.Y.Z version."
    exit 1
  fi
}

bump_pins() {
  for file in $pinned_files; do
    if ! grep -qE "$pin_pattern" "$file"; then
      fail "$file holds no version pin"
      continue
    fi
    sed -E "s#(symfony-security-auditor[@/])[0-9]+\.[0-9]+\.[0-9]+#\1$version#g" "$file" >"$file.release-tmp"
    mv "$file.release-tmp" "$file"
    echo "$file now pins $version"
  done
}

require_codename() {
  if ! printf '%s\n' "$codename" | grep -qxE '[A-Z][^[:space:]]*'; then
    echo "::error::\"$codename\" is not a one-word codename such as Waypoint."
    exit 1
  fi
}

require_newer_than_last_release() {
  last=$(newest_release)
  if ! awk -v next_version="$version" -v last="$last" 'BEGIN {
    split(next_version, n, "."); split(last, l, ".")
    for (i = 1; i <= 3; i++) {
      if (n[i] + 0 > l[i] + 0) exit 0
      if (n[i] + 0 < l[i] + 0) exit 1
    }
    exit 1
  }'; then
    echo "::error::$version is not newer than the last release, $last."
    exit 1
  fi
}

require_unreleased_entries() {
  if ! awk '/^## \[Unreleased\]$/ { open = 1; next } /^## \[/ { open = 0 } open && /^- / { found = 1 } END { exit !found }' CHANGELOG.md; then
    echo "::error::CHANGELOG.md has no entry under ## [Unreleased]: nothing to release."
    exit 1
  fi
}

promote_unreleased() {
  awk -v heading="## [$version] — $(date -u +%Y-%m-%d) — $codename" -v reference="[$version]: $releases_url/$version" '
    /^## \[Unreleased\]$/ && !promoted { print; print ""; print heading; promoted = 1; next }
    /^\[[0-9]+\.[0-9]+\.[0-9]+\]: / && !referenced { print reference; referenced = 1 }
    { print }
  ' CHANGELOG.md >CHANGELOG.md.release-tmp
  mv CHANGELOG.md.release-tmp CHANGELOG.md
  echo "CHANGELOG.md now releases $version — $codename"
}

case $command in
  prepare)
    require_version
    require_codename
    require_newer_than_last_release
    require_unreleased_entries
    promote_unreleased
    bump_pins
    check_changelog
    check_pins
    exit "$status"
    ;;
  bump)
    require_version
    bump_pins
    exit "$status"
    ;;
  check)
    require_version
    check_changelog
    check_pins
    exit "$status"
    ;;
  *)
    echo "::error::Usage: sh .github/scripts/release.sh prepare X.Y.Z Codename | bump X.Y.Z | check X.Y.Z"
    exit 1
    ;;
esac
