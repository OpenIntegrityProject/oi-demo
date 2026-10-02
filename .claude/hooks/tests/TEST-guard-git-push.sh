#!/bin/bash
# Regression tests for guard-git-push.pl. Runs in a throwaway repo so the
# "current branch" cases don't depend on this checkout.
set -euo pipefail

Hook="$(cd "$(dirname "$0")/.." && pwd)/guard-git-push.pl"
Repo="$(mktemp -d)"
trap 'rm -rf "$Repo"' EXIT
git -C "$Repo" init -q -b claude/work

Run=0 Failed=0

check() {  # check <allow|block> <command>
  local want="$1" cmd="$2" got json
  json=$(perl -MJSON::PP -e 'print encode_json({tool_name=>"Bash",tool_input=>{command=>$ARGV[0]}})' "$cmd")
  if (cd "$Repo" && printf '%s' "$json" | perl "$Hook" 2>/dev/null); then got=allow; else got=block; fi
  Run=$((Run + 1))
  if [ "$got" = "$want" ]; then echo "PASS  $want: $cmd"
  else echo "FAIL  want $want, got $got: $cmd"; Failed=$((Failed + 1)); fi
}

# Allowed: normal agent pushes and unrelated commands
check allow 'git push -u origin claude/work'
check allow 'git push origin HEAD'
check allow 'git push'
check allow 'git push origin claude/maintenance'
check allow 'git push origin claude/x:claude/x'
check allow 'git status && git log --oneline -3'
check allow 'echo "remember: never git push origin main"'
check allow 'git push origin v1.0'
check allow 'git commit -m "docs: never git push origin main"'
check block 'timeout 60 git push origin main'
check block 'bash -lc "git push --force"'

check allow "git commit -F - <<'EOF'
Explain why \`git push origin x --force\` and \$(git push origin main) got past
EOF"
check allow "cat > notes.md <<EOF
git push origin main
EOF
git push -u origin claude/work"
check allow "git commit -m 'blocks \`git push --force\` now'"

# Blocked: substitution and shells reading a heredoc
check block 'git commit -m "x \`git push --force\`"'
check block 'echo $(git push origin main)'
check block "bash <<'EOF'
git push origin main
EOF"
check block "cat > x <<'EOF'
text
EOF
git push origin main"

# Blocked: force in any position or form
check block 'git push --force origin claude/work'
check block 'git push origin claude/work --force'
check block 'git push -u origin claude/work -f'
check block 'git push -uf origin claude/work'
check block 'git push origin claude/work --force-with-lease'
check block 'git push origin +claude/work'
check block 'git push --mirror origin'
check block 'git push --all origin'

# Blocked: protected destinations in any refspec form
check block 'git push origin main'
check block 'git push origin main --no-verify'
check block 'git push origin main:main'
check block 'git push origin claude/work:main'
check block 'git push origin HEAD:refs/heads/main'
check block 'git push origin x:staging/foo'
check block 'git push origin --delete main'
check block 'git push origin :staging/old'

# Blocked: other spellings of git push
check block 'git -C . push origin main'
check block 'git -c push.default=current push origin main'
check block '/usr/bin/git push origin main'
check block 'sh -c "git push origin main"'
check block 'cd . && git push origin main'
check block 'FOO=1 git push --force origin claude/work'

# Blocked: bare push or HEAD while on a protected branch
git -C "$Repo" checkout -q -b main
check block 'git push'
check block 'git push origin HEAD'
check allow 'git push origin claude/work'
git -C "$Repo" checkout -q -b staging/rc
check block 'git push -u origin HEAD'

echo "$((Run - Failed)) of $Run tests passed"
[ "$Failed" -eq 0 ]
