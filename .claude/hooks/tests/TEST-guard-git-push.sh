#!/bin/bash
# Regression tests for the git push guard (guard-git-push.sh and .pl). Runs
# in throwaway repos so the "current branch" and alias cases don't depend on
# this checkout.
set -euo pipefail

Hook="$(cd "$(dirname "$0")/.." && pwd)/guard-git-push.sh"
Tmp="$(mktemp -d)"
trap 'rm -rf "$Tmp"' EXIT
Repo="$Tmp/repo"
git init -q -b claude/work "$Repo"
git -C "$Repo" config alias.p push
git -C "$Repo" config alias.pm 'push origin main'
git -C "$Repo" config alias.sp '!git push origin main'
git -C "$Repo" config alias.st status
git init -q -b main "$Tmp/onmain"

Run=0 Failed=0

check() {  # check <allow|block> <command> [PATH for the hook]
  local want="$1" cmd="$2" path="${3:-$PATH}" got json
  json=$(perl -MJSON::PP -e 'print encode_json({tool_name=>"Bash",tool_input=>{command=>$ARGV[0]}})' "$cmd")
  if (cd "$Repo" && printf '%s' "$json" | PATH="$path" "$Hook" 2>/dev/null); then got=allow; else got=block; fi
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
check allow 'git push origin HEAD:heads/claude/x'
check allow 'git status && git log --oneline -3'
check allow 'git st'
check allow 'git p origin claude/work'
check allow 'echo "remember: never git push origin main"'
check allow 'git push origin v1.0'
check allow 'git commit -m "docs: never git push origin main"'
check allow 'B=claude/work; git push origin "$B"'
check allow 'for b in claude/a claude/b; do git push origin $b; done'
check allow 'if git push -u origin claude/work; then echo ok; fi'

# Allowed: text that only mentions git push
check allow "git commit -F - <<'EOF'
Explain why \`git push origin x --force\` and \$(git push origin main) got past
EOF"
check allow "cat > notes.md <<EOF
git push origin main
EOF
git push -u origin claude/work"
check allow "git commit -m 'blocks \`git push --force\` now'"
check allow 'cat <<< "git push origin main"'

# Blocked: substitution and shells reading a heredoc or here-string
check block 'git commit -m "x `git push --force`"'
check block 'echo $(git push origin main)'
check block "bash <<'EOF'
git push origin main
EOF"
check block "cat > x <<'EOF'
text
EOF
git push origin main"
check block 'bash <<< "git push origin main"'

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
check block 'git push origin HEAD:heads/main'
check block 'git push origin x:staging/foo'
check block 'git push origin --delete main'
check block 'git push origin :staging/old'
check block "git push origin 'refs/heads/*:refs/heads/*'"
check block "git push origin 'claude/*:staging/*'"

# Blocked: other spellings of git push
check block 'git -C . push origin main'
check block 'git -c push.default=current push origin main'
check block '/usr/bin/git push origin main'
check block 'sh -c "git push origin main"'
check block 'bash -lc "git push --force"'
check block 'cd . && git push origin main'
check block 'FOO=1 git push --force origin claude/work'
check block 'timeout 60 git push origin main'
check block 'timeout -s KILL 60 git push origin main'
check block 'sudo -u nobody git push origin main'
check block 'git push \
  origin main'
check block 'if git push origin main; then echo ok; fi'
check block '! git push origin main'
check block '{ git push origin main; }'
check block 'while true; do git push origin main; done'
check block 'git push origin ma\in'
check block 'git push origin "m"ain'

# Blocked: destinations from variables, loops and xargs
check block 'B=main; git push origin $B'
check block 'B=main; git push origin "${B}"'
check block 'for b in claude/a main; do git push origin $b; done'
check block 'git push origin $UNKNOWN_BRANCH'
check block 'echo main | xargs git push origin'

# Blocked: git aliases for push
check block 'git p origin main'
check block 'git p --force origin claude/work'
check block 'git pm'
check block 'git sp'

# Blocked: merge_pr.sh in any spelling
check block '.repo/scripts/merge_pr.sh 1'
check block './.repo/scripts/merge_pr.sh 1'
check block 'zsh .repo/scripts/merge_pr.sh 1'
check block 'bash ./.repo/scripts/merge_pr.sh 1'

# Blocked: bare push or HEAD while on a protected branch, here or via -C
check block "git -C $Tmp/onmain push"
check block "git -C $Tmp/onmain push origin HEAD"
git -C "$Repo" checkout -q -b main
check block 'git push'
check block 'git push origin HEAD'
check allow 'git push origin claude/work'
git -C "$Repo" checkout -q -b staging/rc
check block 'git push -u origin HEAD'

# Second local review: substitutions, variable command words, -c aliases,
# $'...' quoting, eval, send-pack, combined wrapper flags, merge_pr.sh forms
git -C "$Repo" symbolic-ref HEAD refs/heads/claude/work
check block 'git push origin HEAD:$(echo main)'
check block 'git push origin "HEAD:`echo main`"'
check block 'eval "git $(echo push) origin HEAD:main"'
check block 'P=push; git $P origin HEAD:main'
check block 'G=git; $G push origin HEAD:main'
check block 'git $UNSET_SUBCOMMAND origin HEAD:main'
check block 'git -c alias.p=push p origin HEAD:main'
check block "git -c 'alias.x=!git push origin main' x"
check block "git push origin \$'HEAD:\\x6dain'"
check block "git push origin \$'HEAD:\\155ain'"
check block 'git send-pack https://example.com/r.git HEAD:main'
check block 'sudo -iu nobody git push origin main'
check block 'xargs -t git push origin main </dev/null'
check block 'source .repo/scripts/merge_pr.sh 1'
check block '. .repo/scripts/merge_pr.sh 1'
check block '.repo/scripts/merge_pr*.sh 1'
check block 'bash -x .repo/scripts/merge_pr.sh 1'
check allow 'git push -u origin "$(git branch --show-current)"'
check allow 'git push origin HEAD:$(git rev-parse --abbrev-ref HEAD)'
check allow 'git -c alias.p=push p origin claude/work'
check allow 'git stash push -m wip'
check allow 'git log --format=%s $(git merge-base HEAD origin/main)..HEAD'
check allow 'bash -c "echo git push origin main"'
check allow "cat > notes.md <<'EOF'
git push origin main
path is C:\\temp\\
EOF"
check allow 'git commit -m "$(cat <<'"'"'EOF'"'"'
Explain git push origin main
EOF
)"'

# Fails closed when perl is missing
NoPerl="$Tmp/noperl"
mkdir "$NoPerl"
for tool in bash dirname grep; do ln -s "$(command -v $tool)" "$NoPerl/$tool"; done
check block 'git push -u origin claude/work' "$NoPerl"
check allow 'git status' "$NoPerl"

echo "$((Run - Failed)) of $Run tests passed"
[ "$Failed" -eq 0 ]
