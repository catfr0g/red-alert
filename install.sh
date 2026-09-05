#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

if [[ ! -f pyproject.toml || ! -f requirements.txt || ! -f .env.example ]]; then
  echo "install.sh: run this script from the Red Alert repository root." >&2
  exit 1
fi

PBS_RELEASE="20260901"
PBS_VERSION="3.14.7"
DATA_HOME="${XDG_DATA_HOME:-${HOME}/.local/share}"
PYTHON_CACHE="${DATA_HOME}/red-alert/python-${PBS_VERSION}"
STANDALONE_PYTHON="${PYTHON_CACHE}/python/bin/python3"

is_python_314() {
  local file="$1"
  shift
  "$file" "$@" -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 14) else 1)' \
    >/dev/null 2>&1
}

pick_python() {
  local candidate
  for candidate in python3.14 python3 python; do
    if command -v "$candidate" >/dev/null 2>&1 && is_python_314 "$candidate"; then
      printf '%s\n' "$candidate"
      return 0
    fi
  done
  if [[ -x "$STANDALONE_PYTHON" ]] && is_python_314 "$STANDALONE_PYTHON"; then
    printf '%s\n' "$STANDALONE_PYTHON"
    return 0
  fi
  return 1
}

pbs_target() {
  local os arch libc
  os="$(uname -s)"
  arch="$(uname -m)"
  case "$arch" in
    x86_64 | amd64) arch="x86_64" ;;
    aarch64 | arm64) arch="aarch64" ;;
    *)
      echo "install.sh: unsupported architecture: ${arch}" >&2
      return 1
      ;;
  esac
  case "$os" in
    Darwin)
      printf '%s\n' "${arch}-apple-darwin"
      ;;
    Linux)
      libc="gnu"
      if [[ -e /lib/ld-musl-x86_64.so.1 || -e /lib/ld-musl-aarch64.so.1 ]] \
        || ldd --version 2>&1 | grep -qi musl; then
        libc="musl"
      fi
      printf '%s\n' "${arch}-unknown-linux-${libc}"
      ;;
    *)
      echo "install.sh: unsupported OS: ${os}" >&2
      return 1
      ;;
  esac
}

download_file() {
  local url="$1"
  local dest="$2"
  if command -v curl >/dev/null 2>&1; then
    curl -fL --progress-bar -o "$dest" "$url"
  elif command -v wget >/dev/null 2>&1; then
    wget -O "$dest" "$url"
  else
    echo "install.sh: need curl or wget to download Python." >&2
    return 1
  fi
}

install_standalone_python() {
  local target name url archive
  target="$(pbs_target)"
  name="cpython-${PBS_VERSION}+${PBS_RELEASE}-${target}-install_only_stripped.tar.gz"
  url="https://github.com/astral-sh/python-build-standalone/releases/download/${PBS_RELEASE}/${name}"
  archive="$(mktemp)"
  echo "install.sh: downloading Python ${PBS_VERSION}..."
  download_file "$url" "$archive"
  mkdir -p "$PYTHON_CACHE"
  rm -rf "${PYTHON_CACHE}/python"
  tar -xzf "$archive" -C "$PYTHON_CACHE"
  rm -f "$archive"
  if [[ ! -x "$STANDALONE_PYTHON" ]]; then
    echo "install.sh: standalone Python is missing after extract." >&2
    return 1
  fi
  if ! "$STANDALONE_PYTHON" -m pip --version >/dev/null 2>&1; then
    "$STANDALONE_PYTHON" -m ensurepip --default-pip
  fi
}

if ! PYTHON="$(pick_python)"; then
  install_standalone_python
  PYTHON="$STANDALONE_PYTHON"
  if ! is_python_314 "$PYTHON"; then
    echo "install.sh: failed to install Python 3.14+." >&2
    exit 1
  fi
fi

if [[ -d .venv ]]; then
  if [[ ! -x .venv/bin/python ]] || ! is_python_314 .venv/bin/python; then
    rm -rf .venv
  fi
fi

if [[ ! -d .venv ]]; then
  "$PYTHON" -m venv .venv
fi

.venv/bin/python -m pip install -r requirements.txt

if [[ ! -f .env ]]; then
  cp .env.example .env
fi

BIN_DIR="${HOME}/.local/bin"
mkdir -p "$BIN_DIR"
ln -sfn "$ROOT/.venv/bin/red-alert" "$BIN_DIR/red-alert"
export PATH="${BIN_DIR}:${PATH}"

path_line='export PATH="$HOME/.local/bin:$PATH"'
ensure_path_file() {
  local file="$1"
  if [[ -f "$file" ]] && grep -Fq '.local/bin' "$file"; then
    return
  fi
  printf '\n# red-alert\n%s\n' "$path_line" >> "$file"
}

ensure_path_file "${HOME}/.profile"
if [[ "${SHELL:-}" == *zsh ]] || [[ -f "${HOME}/.zprofile" ]]; then
  ensure_path_file "${HOME}/.zprofile"
fi

echo "Red Alert is ready. Next: red-alert --help"
