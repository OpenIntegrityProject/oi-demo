#!/bin/bash
# PreToolUse hook entry point: run guard-git-push.pl, failing closed when
# perl is missing. A hook that can't start doesn't block anything, so
# without this a missing perl would let every push through.
hook_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
command -v perl >/dev/null 2>&1 && exec perl "$hook_dir/guard-git-push.pl"

if grep -qE 'push|merge_pr' ; then
  echo "guard-git-push: blocked: perl is missing, so this command can't be checked. Install perl." >&2
  exit 2
fi
exit 0
