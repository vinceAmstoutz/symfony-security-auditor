#!/bin/sh
#
# Checks a pull request's title and description against CLAUDE.md → "Pull
# Requests" and .github/PULL_REQUEST_TEMPLATE.md. The "Pull request target"
# workflow runs it on every edit; run it yourself before opening or editing one:
#
#   PR_TITLE='fix(scan): …' PR_BODY="$(cat body.md)" BASE_REF=1.x \
#     sh .github/scripts/check-pull-request.sh
#
# Prints one ::error:: annotation per problem and exits 1 when there is any.

set -eu

LC_ALL=C
export LC_ALL

TITLE_LIMIT=50

title_errors=0
title_length=$(printf '%s' "${PR_TITLE:-}" | tr -d '\200-\277' | wc -c | tr -d ' ')
if [ "$title_length" -gt "$TITLE_LIMIT" ]; then
  echo "::error::The title is ${title_length} characters; keep it to ${TITLE_LIMIT} or fewer. It becomes the squash-merge commit subject."
  title_errors=1
fi

body_status=0
printf '%s\n' "${PR_BODY:-}" | tr -d '\r' | awk '
function escape(text) {
  gsub(/%/, "%25", text)
  return text
}

function fail(message) {
  printf "::error::%s\n", escape(message)
  errors++
}

function characters(text,   copy) {
  copy = text
  return length(text) - gsub(/[\200-\277]/, "", copy)
}

function trim(text) {
  sub(/^[ \t]+/, "", text)
  sub(/[ \t]+$/, "", text)
  return text
}

function without_comments(text,   kept, at) {
  kept = ""
  while (text != "") {
    if (in_comment) {
      at = index(text, "-->")
      if (at == 0) {
        return kept
      }
      text = substr(text, at + 3)
      in_comment = 0
    } else {
      at = index(text, "<!--")
      if (at == 0) {
        return kept text
      }
      kept = kept substr(text, 1, at - 1)
      text = substr(text, at + 4)
      in_comment = 1
    }
  }
  return kept
}

function heading_of(text,   level) {
  level = text ~ /^##/ ? "##" : "#"
  sub(/^##?[ \t]*/, "", text)
  sub(/[ \t]+#+[ \t]*$/, "", text)
  return level " " trim(text)
}

function is_box_section(name) {
  return name == "## Type of change" || name == "## Target branch" || name == "## Checklist"
}

function inspect_box_line(text,   label) {
  if (trim(text) == "") {
    return
  }
  if (text ~ /^[ \t]*[-*+][ \t]+\[[xX]\]/) {
    ticked[section]++
    if (section == "## Target branch") {
      label = text
      sub(/^[ \t]*[-*+][ \t]+\[[xX]\][ \t]*/, "", label)
      if (label ~ /^`[^`]+`/) {
        label = substr(label, 2)
        targets[++ticked_targets] = substr(label, 1, index(label, "`") - 1)
      }
    }
    return
  }
  if (text ~ /^[ \t]*[-*+][ \t]+\[ \]/) {
    fail("Keep only the boxes you tick under '\''" section "'\'': delete '\''" trim(text) "'\''.")
    return
  }
  if (text !~ /^[ \t]/) {
    fail("'\''" section "'\'' holds ticked boxes only: delete '\''" trim(text) "'\''.")
  }
}

BEGIN {
  base = ENVIRON["BASE_REF"]
  section = ""
}

{
  line = without_comments($0)

  if (line ~ /^[ \t]*(```|~~~)/) {
    in_fence = !in_fence
  } else if (!in_fence && line ~ /^##?([ \t]|$)/) {
    section = heading_of(line)
    headings[++heading_count] = section
    next
  }

  if (line ~ /Stacked on #[0-9]/) {
    names_parent = 1
  }

  if (heading_count == 0) {
    if (trim(line) != "" && !preamble_reported) {
      fail("Start the description with '\''## Summary'\'': delete '\''" trim(line) "'\'' above it.")
      preamble_reported = 1
    }
  } else if (section == "## Summary") {
    summary = summary line "\n"
  } else if (is_box_section(section) && !in_fence) {
    inspect_box_line(line)
  }
}

END {
  check_sections()
  check_summary()
  check_boxes()
  check_target()
  exit (errors > 0 ? 1 : 0)
}

function check_sections(   order, i, name, allowed, seen, broken) {
  order = ""
  for (i = 1; i <= heading_count; i++) {
    order = order (i > 1 ? "|" : "") headings[i]
  }
  if (order == "## Summary|## Type of change|## Target branch|## Checklist" || order == "## Summary|## Type of change|## Target branch|## Details|## Checklist") {
    return
  }

  allowed["## Summary"] = 1
  allowed["## Type of change"] = 1
  allowed["## Target branch"] = 1
  allowed["## Details"] = 1
  allowed["## Checklist"] = 1
  broken = 0
  for (i = 1; i <= heading_count; i++) {
    name = headings[i]
    if (!(name in allowed)) {
      fail("'\''" name "'\'' is not a section of .github/PULL_REQUEST_TEMPLATE.md; put anything else under '\''## Details'\''.")
      broken = 1
    } else if (++seen[name] == 2) {
      fail("'\''" name "'\'' appears more than once.")
      broken = 1
    }
  }
  split("## Summary|## Type of change|## Target branch|## Checklist", required, "|")
  for (i = 1; i <= 4; i++) {
    if (!(required[i] in seen)) {
      fail("The description is missing the '\''" required[i] "'\'' section from .github/PULL_REQUEST_TEMPLATE.md. Restore the template and fill it in.")
      broken = 1
    }
  }
  if (!broken) {
    fail("Keep the sections in the order of .github/PULL_REQUEST_TEMPLATE.md: '\''## Summary'\'', '\''## Type of change'\'', '\''## Target branch'\'', the optional '\''## Details'\'', then '\''## Checklist'\'' last.")
  }
}

function check_summary(   length_in_characters) {
  if (!seen_section("## Summary")) {
    return
  }
  sub(/^[ \t\n]+/, "", summary)
  sub(/[ \t\n]+$/, "", summary)
  length_in_characters = characters(summary)
  if (length_in_characters == 0) {
    fail("Fill in '\''## Summary'\'': the user-visible outcome, in 500 characters or fewer.")
  } else if (length_in_characters > 500) {
    fail("'\''## Summary'\'' is " length_in_characters " characters; keep it to 500 or fewer and move the rest under '\''## Details'\''.")
  }
}

function check_boxes(   i, name) {
  split("## Type of change|## Target branch|## Checklist", box_sections, "|")
  for (i = 1; i <= 3; i++) {
    name = box_sections[i]
    if (seen_section(name) && ticked[name] == 0) {
      fail("Tick at least one box under '\''" name "'\''.")
    }
  }
}

function check_target(   i, target, stacked, release_count) {
  if (!seen_section("## Target branch")) {
    return
  }
  stacked = 0
  release_count = 0
  for (i = 1; i <= ticked_targets; i++) {
    if (targets[i] == "stacked") {
      stacked = 1
    } else {
      target = release_count == 0 ? targets[i] : target
      release_count++
    }
  }

  if (stacked && !names_parent) {
    fail("A stacked pull request names the one it builds on: add '\''Stacked on #<number>'\'' under '\''## Details'\'', with the code it needs from it.")
  }
  if (!stacked && names_parent) {
    fail("This pull request is not stacked: remove '\''Stacked on #…'\'' from the description.")
  }

  if (release_count != 1) {
    fail("Tick exactly one release branch under '\''## Target branch'\'' (found " release_count ").")
    return
  }
  if (target != "main" && target !~ /\.x$/) {
    fail("'\''" target "'\'' is not one of the targets in .github/PULL_REQUEST_TEMPLATE.md.")
    return
  }

  if (stacked) {
    if (base == "main" || base ~ /\.x$/) {
      fail("You ticked '\''stacked'\'', which means the base should be another PR'\''s feature branch — but this pull request is based on '\''" base "'\''.")
    } else {
      print "Ticked '\''stacked'\'' + '\''" target "'\'' — based on feature branch '\''" base "'\''; retarget to '\''" target "'\'' once that PR merges."
    }
  } else if (target == "main" && base != "main") {
    fail("'\''main'\'' takes release merges only, but this pull request is based on '\''" base "'\''.")
  } else if (target != "main" && base != target) {
    fail("You ticked '\''" target "'\'' but opened this pull request against '\''" base "'\''. Retarget the base to '\''" target "'\'', or tick the branch you actually want.")
  } else {
    print "Ticked '\''" target "'\'', based on '\''" base "'\'' — consistent."
  }
}

function seen_section(name,   i) {
  for (i = 1; i <= heading_count; i++) {
    if (headings[i] == name) {
      return 1
    }
  }
  return 0
}
' || body_status=$?

if [ "$title_errors" -ne 0 ] || [ "$body_status" -ne 0 ]; then
  exit 1
fi
