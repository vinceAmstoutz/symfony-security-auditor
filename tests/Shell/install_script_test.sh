#!/bin/sh
#
# POSIX unit tests for install.sh — sources the installer with SSA_INSTALL_SOURCED=1
# so main() is not invoked, then exercises its pure functions.
#
# Run with any POSIX shell: sh tests/Shell/install_script_test.sh

set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
SSA_INSTALL_SOURCED=1
export SSA_INSTALL_SOURCED
# shellcheck source=/dev/null
. "$script_dir/install.sh"

failures=0

expect_equals() {
  if [ "$2" = "$3" ]; then
    echo "ok - $1"
  else
    echo "NOT OK - $1: expected [$2], got [$3]"
    failures=$((failures + 1))
  fi
}

expect_failure() {
  label=$1
  shift
  if output=$("$@" 2>&1); then
    echo "NOT OK - $label: expected failure, succeeded with [$output]"
    failures=$((failures + 1))
  else
    echo "ok - $label"
  fi
}

uname() {
  case "$1" in
    -s) printf '%s\n' "$FAKE_OS" ;;
    -m) printf '%s\n' "$FAKE_ARCH" ;;
    *) printf '%s\n' 'unexpected uname flag' >&2; return 1 ;;
  esac
}

assert_asset() {
  FAKE_OS=$1
  FAKE_ARCH=$2
  expect_equals "detect_asset $1/$2" "$3" "$(detect_asset)"
}

assert_asset Linux x86_64 symfony-security-auditor-linux-x86_64
assert_asset Linux amd64 symfony-security-auditor-linux-x86_64
assert_asset Linux aarch64 symfony-security-auditor-linux-aarch64
assert_asset Linux arm64 symfony-security-auditor-linux-aarch64
assert_asset Darwin x86_64 symfony-security-auditor-macos-x86_64
assert_asset Darwin arm64 symfony-security-auditor-macos-arm64
assert_asset Darwin aarch64 symfony-security-auditor-macos-arm64

FAKE_OS=Windows_NT FAKE_ARCH=x86_64
expect_failure "detect_asset rejects an unsupported OS" detect_asset
FAKE_OS=Linux FAKE_ARCH=riscv64
expect_failure "detect_asset rejects an unsupported architecture" detect_asset

FAKE_OS=MINGW64_NT-10.0-19045 FAKE_ARCH=x86_64
if windows_shell_message=$(detect_asset 2>&1); then
  echo "NOT OK - detect_asset should fail in a Windows POSIX shell (Git Bash/MSYS)"
  failures=$((failures + 1))
elif printf '%s' "$windows_shell_message" | grep -q 'install.ps1'; then
  echo "ok - detect_asset points a Windows POSIX shell to the PowerShell installer"
else
  echo "NOT OK - detect_asset failed without pointing to the PowerShell installer: [$windows_shell_message]"
  failures=$((failures + 1))
fi

SSA_INSTALL_DIR=/opt/tools/bin
expect_equals "resolve_install_dir honours SSA_INSTALL_DIR" /opt/tools/bin "$(resolve_install_dir)"
unset SSA_INSTALL_DIR

resolved=$(resolve_install_dir)
case "$resolved" in
  /usr/local/bin | "$HOME/.local/bin") echo "ok - resolve_install_dir falls back to a system directory" ;;
  *)
    echo "NOT OK - resolve_install_dir fell back to an unexpected directory: [$resolved]"
    failures=$((failures + 1))
    ;;
esac

checksum_dir=$(mktemp -d)
trap 'rm -rf "$checksum_dir"' EXIT
printf 'binary-payload' >"$checksum_dir/artifact"
if command -v sha256sum >/dev/null 2>&1; then
  (cd "$checksum_dir" && sha256sum artifact >artifact.sha256)
else
  (cd "$checksum_dir" && shasum -a 256 artifact >artifact.sha256)
fi

if verify_checksum "$checksum_dir/artifact" "$checksum_dir/artifact.sha256" >/dev/null 2>&1; then
  echo "ok - verify_checksum accepts a matching digest"
else
  echo "NOT OK - verify_checksum rejected a matching digest"
  failures=$((failures + 1))
fi

printf '%s  artifact\n' 0000000000000000000000000000000000000000000000000000000000000000 >"$checksum_dir/artifact.sha256"
expect_failure "verify_checksum rejects a mismatching digest" \
  verify_checksum "$checksum_dir/artifact" "$checksum_dir/artifact.sha256"

if (PATH= verify_checksum "$checksum_dir/artifact" "$checksum_dir/artifact.sha256" 2>&1); then
  echo "NOT OK - verify_checksum should fail closed with no digest tool"
  failures=$((failures + 1))
else
  echo "ok - verify_checksum fails closed when no digest tool is available"
fi

init_stub_dir=$(mktemp -d)
trap 'rm -rf "$checksum_dir" "$init_stub_dir"' EXIT
init_log="$init_stub_dir/args"
cat >"$init_stub_dir/bin" <<STUB
#!/bin/sh
printf '%s' "\$*" >"$init_log"
STUB
chmod +x "$init_stub_dir/bin"

unset SSA_INIT 2>/dev/null || true
rm -f "$init_log"
run_init "$init_stub_dir/bin" >/dev/null 2>&1
if [ -f "$init_log" ]; then
  echo "NOT OK - run_init invoked init without SSA_INIT=1"
  failures=$((failures + 1))
else
  echo "ok - run_init is a no-op unless SSA_INIT=1"
fi

SSA_INIT=1
init_can_prompt() { return 1; }
rm -f "$init_log"
run_init "$init_stub_dir/bin" >/dev/null 2>&1
expect_equals "run_init passes --no-interaction when no terminal is attached" "init --no-interaction" "$(cat "$init_log")"
unset SSA_INIT

if command -v setsid >/dev/null 2>&1; then
  probe_script='SSA_INSTALL_SOURCED=1; export SSA_INSTALL_SOURCED; . "$1"; if init_can_prompt; then echo tty; else echo no-tty; fi; echo survived'
  probe_output=$(setsid --wait sh -c "$probe_script" probe "$script_dir/install.sh" </dev/null 2>/dev/null || true)
  case "$probe_output" in
    *survived*) echo "ok - init_can_prompt returns instead of aborting the shell without a controlling terminal" ;;
    *)
      echo "NOT OK - init_can_prompt aborted the shell without a controlling terminal: [$probe_output]"
      failures=$((failures + 1))
      ;;
  esac
else
  echo "ok - init_can_prompt no-terminal probe skipped (setsid unavailable)"
fi

if [ "$failures" -eq 0 ]; then
  echo "All install.sh tests passed."
  exit 0
fi

echo "$failures install.sh test(s) failed."
exit 1
