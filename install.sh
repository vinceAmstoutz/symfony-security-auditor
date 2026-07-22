#!/bin/sh
#
# Installer for the symfony-security-auditor standalone binary.
#
# Detects the OS and architecture, downloads the matching binary from the
# GitHub release, verifies its SHA-256 checksum, and installs it.
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/vinceAmstoutz/symfony-security-auditor/main/install.sh | sh
#
# Environment variables:
#   SSA_VERSION      release tag to install (default: latest)
#   SSA_INSTALL_DIR  target directory (default: /usr/local/bin, else ~/.local/bin)
#
# The SHA-256 checksum is always verified; the install aborts if no checksum
# tool is available.

set -eu

REPO="vinceAmstoutz/symfony-security-auditor"
BINARY_NAME="symfony-security-auditor"
VERSION="${SSA_VERSION:-latest}"

fail() {
  echo "error: $1" >&2
  exit 1
}

need() {
  command -v "$1" >/dev/null 2>&1 || fail "required command '$1' not found"
}

detect_asset() {
  os="$(uname -s)"
  arch="$(uname -m)"

  case "$os" in
    Linux) os_slug="linux" ;;
    Darwin) os_slug="macos" ;;
    *) fail "unsupported OS '$os' — on Windows download symfony-security-auditor-windows-x86_64.exe from the releases page" ;;
  esac

  case "$arch" in
    x86_64 | amd64) arch_slug="x86_64" ;;
    aarch64 | arm64) [ "$os_slug" = "macos" ] && arch_slug="arm64" || arch_slug="aarch64" ;;
    *) fail "unsupported architecture '$arch'" ;;
  esac

  echo "${BINARY_NAME}-${os_slug}-${arch_slug}"
}

download() {
  if command -v curl >/dev/null 2>&1; then
    curl -fSL "$1" -o "$2"
  elif command -v wget >/dev/null 2>&1; then
    wget -O "$2" "$1"
  else
    fail "need either 'curl' or 'wget'"
  fi
}

verify_checksum() {
  if command -v sha256sum >/dev/null 2>&1; then
    expected="$(cut -d' ' -f1 "$2")"
    actual="$(sha256sum "$1" | cut -d' ' -f1)"
  elif command -v shasum >/dev/null 2>&1; then
    expected="$(cut -d' ' -f1 "$2")"
    actual="$(shasum -a 256 "$1" | cut -d' ' -f1)"
  else
    fail "no SHA-256 tool (sha256sum or shasum) found — refusing to install an unverified binary"
  fi
  [ "$expected" = "$actual" ] || fail "checksum mismatch (expected $expected, got $actual)"
}

resolve_install_dir() {
  if [ -n "${SSA_INSTALL_DIR:-}" ]; then
    echo "$SSA_INSTALL_DIR"
  elif [ -w /usr/local/bin ] 2>/dev/null; then
    echo "/usr/local/bin"
  else
    echo "${HOME}/.local/bin"
  fi
}

main() {
  need uname

  asset="$(detect_asset)"
  if [ "$VERSION" = "latest" ]; then
    base="https://github.com/${REPO}/releases/latest/download"
  else
    base="https://github.com/${REPO}/releases/download/${VERSION}"
  fi

  tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp"' EXIT

  echo "Downloading ${asset} (${VERSION})…"
  download "${base}/${asset}" "${tmp}/${asset}"
  download "${base}/${asset}.sha256" "${tmp}/${asset}.sha256"
  verify_checksum "${tmp}/${asset}" "${tmp}/${asset}.sha256"

  install_dir="$(resolve_install_dir)"
  mkdir -p "$install_dir"
  chmod +x "${tmp}/${asset}"
  mv "${tmp}/${asset}" "${install_dir}/${BINARY_NAME}"

  echo "Installed ${BINARY_NAME} to ${install_dir}/${BINARY_NAME}"
  case ":${PATH}:" in
    *":${install_dir}:"*) ;;
    *) echo "note: ${install_dir} is not on your PATH — add it to run '${BINARY_NAME}' directly" ;;
  esac
}

[ "${SSA_INSTALL_SOURCED:-0}" = "1" ] || main
