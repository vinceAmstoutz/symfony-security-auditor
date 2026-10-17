#!/bin/sh
#
# Checks CHANGELOG.md against .claude/rules/changelog.md: every release is a
# list of one-line, end-user entries under a fixed set of headings, each entry
# ends with the pull request that shipped it, and "Security" is reserved for the
# fix of a published vulnerability (a CVE or GHSA id). CI runs it on every pull
# request; run it yourself before pushing a changelog edit:
#
#   sh .github/scripts/check-changelog.sh [path/to/CHANGELOG.md]
#
# An entry under "## [Unreleased]" may omit its pull request link, because the
# number is unknown until the pull request is open; set
# CHANGELOG_REQUIRE_LINKS=all to require it there too (the release does).
#
# Prints one ::error:: annotation per problem and exits 1 when there is any.

set -eu

LC_ALL=C
export LC_ALL

file=${1:-CHANGELOG.md}

if [ ! -f "$file" ]; then
  echo "::error::$file does not exist."
  exit 1
fi

status=0
tr -d '\r' <"$file" | awk -v file="$file" -v require_all="${CHANGELOG_REQUIRE_LINKS:-}" '
function escape(text) {
  gsub(/%/, "%25", text)
  return text
}

function fail(message) {
  printf "::error file=%s,line=%d::%s\n", file, NR, escape(message)
  errors++
}

function characters(text,   copy) {
  copy = text
  return length(text) - gsub(/[\200-\277]/, "", copy)
}

function rank(heading,   i) {
  for (i = 1; i <= section_count; i++) {
    if (sections[i] == heading) {
      return i
    }
  }
  return 0
}

function close_section() {
  if (current != "" && current != "?" && bullets == 0) {
    fail("The \"" current "\" section of " release " has no entry: delete the heading.")
  }
  current = ""
  bullets = 0
}

function check_bullet(line,   mentions_advisory) {
  bullets++
  if (line ~ /^- \*\*/) {
    fail("An entry does not open with a bold summary: write one plain line, the way a release note reads (see .claude/rules/changelog.md).")
  }
  if (characters(line) > 500) {
    fail("An entry is " characters(line) " characters; keep it to 500 or fewer and let the pull request carry the details.")
  }
  if (line ~ /`(src|tests|tools|config)\//) {
    fail("An entry names a source path: describe what changed for the user, not where in the code.")
  }
  mentions_advisory = (line ~ advisory)
  if (current == "Security 🔒" && !mentions_advisory) {
    fail("An entry under \"Security 🔒\" must cite the CVE or GHSA id of the published advisory it fixes. Without one it is hardening: file it under \"New Features ✨\" or \"Core 🧱\" instead.")
  }
  if (current != "Security 🔒" && mentions_advisory) {
    fail("An entry citing a CVE or GHSA id belongs under \"Security 🔒\", not under \"" current "\".")
  }
  if (line !~ linked && (require_all == "all" || release != "[Unreleased]")) {
    fail("An entry in " release " ends with the pull request that shipped it, as ([#123](https://github.com/vinceAmstoutz/symfony-security-auditor/pull/123)), or with its commit when it had no pull request.")
  }
}

BEGIN {
  section_count = split("New Features ✨|Security 🔒|Breaking Changes 💥|Deprecations 💀|Bugfixes 🐛|Performance Improvements 🚀|Core 🧱", sections, "|")
  pull = "\\[#[0-9]+\\]\\(https://github\\.com/vinceAmstoutz/symfony-security-auditor/pull/[0-9]+\\)"
  commit = "\\[`[0-9a-f]+`\\]\\(https://github\\.com/vinceAmstoutz/symfony-security-auditor/commit/[0-9a-f]+\\)"
  reference = "(" pull "|" commit ")"
  linked = " \\(" reference "(, " reference ")*\\)$"
  advisory = "(CVE-[0-9][0-9][0-9][0-9]-[0-9][0-9][0-9][0-9]+|GHSA-[0-9a-z][0-9a-z][0-9a-z][0-9a-z]-[0-9a-z][0-9a-z][0-9a-z][0-9a-z]-[0-9a-z][0-9a-z][0-9a-z][0-9a-z])"
}

/^\[[^]]+\]: https?:\/\// {
  close_section()
  in_references = 1
  next
}

/^## / {
  close_section()
  if (in_references) {
    fail("A release heading follows the link references: keep them at the bottom.")
  }
  if ($0 !~ /^## \[(Unreleased|[0-9]+\.[0-9]+\.[0-9]+)\]( — [0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]( — .+)?)?$/) {
    fail("A release heading reads \"## [X.Y.Z] — YYYY-MM-DD — Codename\" (or \"## [Unreleased]\").")
  }
  release = $0
  sub(/^## /, "", release)
  sub(/\] .*/, "]", release)
  last_rank = 0
  delete seen
  in_release = 1
  next
}

in_references {
  if ($0 != "") {
    fail("Only link references may follow the last release.")
  }
  next
}

!in_release {
  next
}

/^### / {
  close_section()
  heading = $0
  sub(/^### /, "", heading)
  current_rank = rank(heading)
  if (current_rank == 0) {
    fail("\"" heading "\" is not a changelog section. Use, in this order: New Features ✨, Security 🔒, Breaking Changes 💥, Deprecations 💀, Bugfixes 🐛, Performance Improvements 🚀, Core 🧱.")
    current = "?"
    next
  }
  if (heading in seen) {
    fail("\"" heading "\" appears twice in " release ".")
  } else if (current_rank < last_rank) {
    fail("\"" heading "\" is out of order in " release ": New Features ✨, Security 🔒, Breaking Changes 💥, Deprecations 💀, Bugfixes 🐛, Performance Improvements 🚀, Core 🧱.")
  }
  seen[heading] = 1
  last_rank = current_rank
  current = heading
  next
}

$0 == "" {
  next
}

current == "" {
  fail("Text between a release heading and its first section: a release is a list of sections, with no introduction.")
  next
}

current == "?" {
  next
}

/^- / {
  check_bullet($0)
  next
}

{
  fail("A section holds one-line entries starting with \"- \": no paragraph, code block, sub-list or wrapped line.")
}

END {
  close_section()
  if (errors > 0) {
    exit 1
  }
}
' || status=$?

exit "$status"
