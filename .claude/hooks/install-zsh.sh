#!/bin/bash
# SessionStart hook: install zsh when missing so the repo's zsh scripts
# (verify_commit_signatures.sh and its tests) can run. No-op on macOS,
# which ships zsh, and anywhere zsh is already on PATH. Never blocks or
# fails session start: on any problem it warns and exits 0.
set -uo pipefail

command -v zsh >/dev/null 2>&1 && exit 0
[ "$(uname -s)" = "Darwin" ] && exit 0

warn() {
  echo "install-zsh: $1; install zsh manually" >&2
  exit 0
}

command -v apt-get >/dev/null 2>&1 || warn "zsh missing and apt-get unavailable"

SUDO=""
if [ "$(id -u)" -ne 0 ]; then
  command -v sudo >/dev/null 2>&1 || warn "zsh missing, not root, and sudo unavailable"
  # -n: fail instead of prompting for a password, which would hang session start
  SUDO="sudo -n"
fi

$SUDO apt-get update -qq </dev/null || warn "apt-get update failed"
$SUDO env DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \
  -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold \
  zsh </dev/null || warn "apt-get install zsh failed"
