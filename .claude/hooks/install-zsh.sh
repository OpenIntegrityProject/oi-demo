#!/bin/bash
# SessionStart hook: install zsh when missing so the repo's zsh scripts
# (verify_commit_signatures.sh and its tests) can run. No-op on macOS,
# which ships zsh, and anywhere zsh is already on PATH.
set -euo pipefail

command -v zsh >/dev/null 2>&1 && exit 0
[ "$(uname -s)" = "Darwin" ] && exit 0

if ! command -v apt-get >/dev/null 2>&1; then
  echo "install-zsh: zsh missing and apt-get unavailable; install zsh manually" >&2
  exit 0
fi

SUDO=""
[ "$(id -u)" -ne 0 ] && SUDO="sudo"

$SUDO apt-get update -qq </dev/null
$SUDO env DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \
  -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold \
  zsh </dev/null
