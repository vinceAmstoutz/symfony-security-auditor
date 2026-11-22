#!/bin/sh
#
# Tells the release workflow whether a pull request must build the binary:
# prints "true" unless every binary input the change touches is either
# composer.json with only its require-dev changed, or a PHP file whose code
# stayed the same (only its comments or whitespace changed).
#
#   sh .github/scripts/plan-binary-build.sh <base> <head>

set -eu

base=$1
head=$2
script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

changed=$(git diff --name-only "$base" "$head" -- \
  .github/workflows/release.yaml bin box.json composer.json \
  src/Audit/Infrastructure/Bridge src/Audit/Infrastructure/SelfUpdate src/Standalone)

if [ -z "$changed" ]; then
  echo true
  exit 0
fi

for file in $changed; do
  case "$file" in
    composer.json)
      if [ "$(git show "$base:composer.json" | jq -S 'del(."require-dev")')" != "$(git show "$head:composer.json" | jq -S 'del(."require-dev")')" ]; then
        echo true
        exit 0
      fi
      ;;
    *.php)
      if ! git show "$base:$file" >"$work/before" 2>/dev/null \
        || ! git show "$head:$file" >"$work/after" 2>/dev/null \
        || ! php "$script_dir/same-code.php" "$work/before" "$work/after"; then
        echo true
        exit 0
      fi
      ;;
    *)
      echo true
      exit 0
      ;;
  esac
done

echo false
