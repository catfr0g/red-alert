#!/bin/sh
set -eu

mkdir -p "$CODEX_HOME" "$HOME"
cp /opt/red-alert-codex/red-alert-harness.config.toml \
    "$CODEX_HOME/red-alert-harness.config.toml"

exec codex "$@"
