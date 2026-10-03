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
git -C "$Repo" config alias.co checkout
git init -q -b main "$Tmp/onmain"

# Repos whose config picks the destination of a bare push
cfg_repo() {  # cfg_repo <name> [key value]...
  local r="$Tmp/$1"; shift
  git init -q -b claude/work "$r"
  git -C "$r" remote add origin https://example.com/r.git
  while [ $# -gt 0 ]; do git -C "$r" config "$1" "$2"; shift 2; done
}
cfg_repo pushspec remote.origin.push HEAD:main
cfg_repo upstream push.default upstream branch.claude/work.remote origin branch.claude/work.merge refs/heads/main
cfg_repo upstream-ok push.default upstream branch.claude/work.remote origin branch.claude/work.merge refs/heads/claude/work
cfg_repo matching push.default matching
cfg_repo mirror remote.origin.mirror true
printf '[alias]\n\tq = push\n' > "$Tmp/aliases.cfg"

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

# Third review: a branch switch earlier in the command makes the current
# branch unknown, so HEAD, @ and a bare push are blocked after it
check block 'git checkout main && git merge --ff-only claude/x && git push'
check block 'git checkout main && git merge --ff-only claude/x && git push origin HEAD'
check block 'git switch main; git push origin @'
check block 'git rebase origin/main claude/x && git push origin HEAD'
check block 'git worktree add ../w main && cd ../w && git push'
check block 'git checkout main && git push -u origin "$(git branch --show-current)"'
check block 'git co main && git push'
check block 'git branch -m main && git push'
check block 'git symbolic-ref HEAD refs/heads/main && git push'
check block "cd $Tmp/onmain && git push"
check block 'cd "$SOMEWHERE" && git push origin HEAD'
check allow 'git checkout claude/y && git push origin claude/y'
check allow 'git checkout -b claude/new && git push -u origin claude/new'
check allow 'git switch -c claude/new; git push origin claude/new:claude/new'
check allow 'git checkout -- README.md && git push'
check allow 'git worktree list && git push'
check allow "cd $Repo && git push"
check allow "cd $Tmp/onmain && git push origin claude/work"

# Third review: config that picks the destination, inline or in the repo
check block 'git -c push.default=upstream push'
check block 'git -c remote.origin.push=HEAD:main push origin'
check block 'git -c remote.origin.push=HEAD:main push'
check block 'git config remote.origin.push HEAD:main && git push'
check block 'git config push.default upstream'
check block 'git config --local branch.claude/work.merge refs/heads/main'
check block 'git remote add --mirror=push backup https://example.com/r.git'
check block 'P=upstream git --config-env=push.default=P push'
check block 'GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=push.default GIT_CONFIG_VALUE_0=upstream git push'
check block 'git -c remote.origin.mirror=true push origin'
check block 'git push origin :'
check block "git -C $Tmp/pushspec push"
check block "git -C $Tmp/pushspec push origin"
check block "git -C $Tmp/pushspec push origin claude/work"
check block "git -C $Tmp/upstream push"
check block "git -C $Tmp/matching push origin"
check block "git -C $Tmp/mirror push origin"
check allow "git -C $Tmp/upstream-ok push"
check block "git -C $Tmp/upstream push origin claude/work"
check block "git -C $Tmp/upstream push origin refs/heads/claude/work"
check allow "git -C $Tmp/upstream push origin claude/work:claude/work"
check allow "git -C $Tmp/upstream-ok push origin claude/work"
check block "cd $Tmp/upstream-ok && git checkout -b claude/n origin/main && git push origin claude/n"
check allow "cd $Tmp/upstream-ok && git checkout -b claude/n origin/main && git push origin claude/n:claude/n"
check allow 'git config --get push.default'
check allow 'git config user.name "A B"'
check allow 'git -c core.quotepath=off push origin claude/work'
check allow 'git -c user.signingkey=x commit -S -m x && git push origin claude/work'

# Third review: more wrappers and shells
check block 'arch -arm64 git push origin HEAD:main'
check block 'xcrun git push origin HEAD:main'
check block 'caffeinate -i git push origin HEAD:main'
check block 'script -q /dev/null git push origin HEAD:main'
check block 'script /dev/null git push origin HEAD:main'
check block 'find . -maxdepth 0 -exec git push origin HEAD:main \;'
check block "tcsh -c 'git push origin HEAD:main'"
check block "csh -c 'git push origin HEAD:main'"
check allow 'caffeinate -i git push origin claude/work'
check allow 'script -q /dev/null git status'
check allow 'find . -name "*.md" -exec grep -l push {} +'

# Third review: alias spellings. q is not an alias in $Repo, so these pass
# only if the hook resolves the alias from the command itself.
check block 'P=push git --config-env=alias.q=P q origin HEAD:main'
check block 'git -c alias.Q=push q origin HEAD:main'
check block "git -c include.path=$Tmp/aliases.cfg q origin HEAD:main"
check block "GIT_CONFIG_GLOBAL=$Tmp/aliases.cfg git q origin HEAD:main"
check allow "GIT_CONFIG_GLOBAL=$Tmp/aliases.cfg git status"
check allow 'H=x git --config-env=http.extraHeader=H fetch origin'

# Round 3 self-review: checkout -b and switch -c name the new branch
check allow 'git checkout -b claude/new && git push -u origin HEAD'
check allow 'git checkout -qb claude/new && git push origin @'
check allow 'git switch -c claude/new && git push -u origin "$(git branch --show-current)"'
check allow 'git switch --create=claude/new && git push -u origin HEAD'
check allow 'git checkout -b claude/new origin/main && git push'
check block 'git checkout -b main && git push'
check block 'git checkout -B staging/x && git push origin HEAD'
check block 'git switch -c claude/new && git checkout main && git push origin HEAD'
check block "git -C $Tmp/onmain checkout -b claude/z && git push origin HEAD"
check block "cd $Tmp/upstream-ok && git checkout -b claude/n origin/main && git push"
check block 'git checkout -b "$NAME" && git push origin HEAD'

# Third review: quotes, comments and heredocs read as the shell reads them
check block 'git push origin HEAD:$( (echo main) )'
check block "echo \"'\"; git push origin HEAD:\$(printf ma)in #'"
check block "echo '<<EOF'
git push origin HEAD:main
EOF"
check block '# <<EOF
git push origin HEAD:main
EOF'
check block "cat <<EOF | bash
git push origin main
EOF"
check block 'echo $((1<<2))
git push origin main'
check block "bash -c \"echo it's\"; git push origin main"
check block "bash -c 'echo \$(git push origin main)'"
check block 'echo "$'"'"'"; git push origin main; echo "'"'"'"'
check block 'sh -c "git status
git push origin main"'
check allow 'git commit -m "Fix the guard

git push origin main is still blocked"'
check allow 'gh pr create --title x --body "Steps:
git push origin HEAD:main (blocked)
git push origin claude/x; then merge"'
check allow 'git push origin claude/work # never push main'
check allow 'echo "(git push origin main)"'
check allow "git commit -m 'one; git push origin main'"

# Fails closed when perl is missing
NoPerl="$Tmp/noperl"
mkdir "$NoPerl"
for tool in bash dirname grep; do ln -s "$(command -v $tool)" "$NoPerl/$tool"; done
check block 'git push -u origin claude/work' "$NoPerl"
check allow 'git status' "$NoPerl"

echo "$((Run - Failed)) of $Run tests passed"
[ "$Failed" -eq 0 ]
