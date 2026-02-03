#!/usr/bin/env bash
# zkPoEX one-line installer (source-only).
#
# Common usage:
#   curl -fsSL https://raw.githubusercontent.com/zkoranges/zkPoEX/main/install.sh | bash
#
# Pinned:
#   curl -fsSL https://raw.githubusercontent.com/zkoranges/zkPoEX/vX.Y.Z/install.sh | bash -s -- --version vX.Y.Z
#
# Notes:
# - By default we install to ~/.local/bin (or $XDG_BIN_HOME if set).
# - Requires git and cargo (Rust toolchain).
# - On Apple Silicon, Metal GPU acceleration is enabled automatically.
set -euo pipefail

REPO_DEFAULT="zkoranges/zkPoEX"
REPO="${ZKPOEX_REPO:-$REPO_DEFAULT}"
VERSION="${ZKPOEX_VERSION:-latest}"   # "latest" or a tag like "v0.1.0"
INSTALL_DIR="${ZKPOEX_INSTALL_DIR:-}"
QUIET="${ZKPOEX_QUIET:-0}"

usage() {
  cat <<'USAGE'
zkPoEX installer (builds from source)

Usage:
  install.sh [--version <tag|latest>] [--install-dir <dir>] [--repo <owner/name>] [--quiet]

Env vars:
  ZKPOEX_REPO         GitHub repo (default: zkoranges/zkPoEX)
  ZKPOEX_VERSION      "latest" or tag like "v0.1.0"
  ZKPOEX_INSTALL_DIR  Install directory (default: $XDG_BIN_HOME or ~/.local/bin)
  ZKPOEX_QUIET        1 to reduce output

Examples:
  curl -fsSL https://raw.githubusercontent.com/zkoranges/zkPoEX/main/install.sh | bash

  curl -fsSL https://raw.githubusercontent.com/zkoranges/zkPoEX/main/install.sh | bash -s -- \
    --version v0.1.0 --install-dir ~/.local/bin
USAGE
}

log() {
  if [[ "$QUIET" != "1" ]]; then
    printf '%s\n' "$*" >&2
  fi
}

die() {
  printf 'error: %s\n' "$*" >&2
  exit 1
}

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "missing required command: $1"
}

detect_target() {
  local os arch
  os="$(uname -s)"
  arch="$(uname -m)"

  case "$os" in
    Darwin) os="darwin" ;;
    Linux) os="linux" ;;
    *) die "unsupported OS: $os" ;;
  esac

  case "$arch" in
    x86_64|amd64) arch="x86_64" ;;
    arm64|aarch64) arch="aarch64" ;;
    *) die "unsupported arch: $arch" ;;
  esac

  printf '%s-%s' "$os" "$arch"
}

default_install_dir() {
  if [[ -n "${XDG_BIN_HOME:-}" ]]; then
    printf '%s' "$XDG_BIN_HOME"
    return 0
  fi
  if [[ -n "${HOME:-}" ]]; then
    printf '%s' "$HOME/.local/bin"
    return 0
  fi
  return 1
}

install_from_source() {
  local target="$1"
  local tmpdir="$2"

  need_cmd git
  need_cmd cargo

  local clone_dir="${tmpdir}/src"
  if [[ "$VERSION" == "latest" ]]; then
    log "Cloning ${REPO} (default branch)"
    git clone --depth 1 "https://github.com/${REPO}.git" "$clone_dir" >/dev/null
  else
    log "Cloning ${REPO} (${VERSION})"
    git clone --depth 1 --branch "$VERSION" "https://github.com/${REPO}.git" "$clone_dir" >/dev/null
  fi

  local features=()
  if [[ "$target" == "darwin-aarch64" ]]; then
    # Enable Metal acceleration on Apple Silicon by default.
    features+=(--features metal)
  fi

  log "Building from source (this can take a while)"
  (cd "$clone_dir" && cargo build -p zkpoex-cli --release --locked "${features[@]}" >/dev/null)

  local bin_path="${clone_dir}/target/release/zkpoex"
  [[ -x "$bin_path" ]] || die "build completed but binary not found at ${bin_path}"
  printf '%s' "$bin_path"
}

main() {
  if [[ "${EUID:-0}" -eq 0 ]]; then
    log "Warning: running as root is not recommended; installing into a user directory is safer."
  fi

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --repo) REPO="$2"; shift 2 ;;
      --version) VERSION="$2"; shift 2 ;;
      --install-dir) INSTALL_DIR="$2"; shift 2 ;;
      --quiet) QUIET="1"; shift ;;
      -h|--help) usage; exit 0 ;;
      *) die "unknown argument: $1 (use --help)" ;;
    esac
  done

  if [[ -z "$INSTALL_DIR" ]]; then
    INSTALL_DIR="$(default_install_dir)" || die "failed to determine default install dir"
  fi

  local target tmpdir bin_src
  target="$(detect_target)"
  tmpdir="$(mktemp -d)"
  trap 'rm -rf "$tmpdir"' EXIT

  log "Installing zkpoex (${VERSION}) for ${target} into ${INSTALL_DIR}"

  bin_src="$(install_from_source "$target" "$tmpdir")"

  mkdir -p "$INSTALL_DIR"
  cp "$bin_src" "${INSTALL_DIR}/zkpoex"
  chmod +x "${INSTALL_DIR}/zkpoex"

  log "Installed: ${INSTALL_DIR}/zkpoex"

  if command -v zkpoex >/dev/null 2>&1; then
    log "zkpoex is on PATH: $(command -v zkpoex)"
  else
    log "Note: ${INSTALL_DIR} is not on your PATH."
    log "Add this to your shell profile:"
    log "  export PATH=\"${INSTALL_DIR}:\$PATH\""
  fi
}

main "$@"
