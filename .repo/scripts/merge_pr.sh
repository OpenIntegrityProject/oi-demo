#!/usr/bin/env zsh
########################################################################
## Script:        merge_pr.sh
## Version:       0.1.00 (2026-10-02)
## Origin:        https://github.com/OpenIntegrityProject/openintegrityproject-dev/blob/main/.repo/scripts/merge_pr.sh
## Description:   Approves and merges a pull request the Open Integrity
##                way: verifies the PR's commits locally, shows what will
##                be merged, merges with the human's signing key (the
##                Touch ID prompt is the approval), pushes the merge to
##                staging/main, waits for the "verify" check, then moves
##                main to it. GitHub marks the PR merged once its commits
##                are on main. Replaces "gh pr merge", whose commits are
##                signed by GitHub's key rather than a repository signer.
## License:       BSD-2-Clause-Patent (https://spdx.org/licenses/BSD-2-Clause-Patent.html)
## Copyright:     (c) 2026 Blockchain Commons LLC (https://www.BlockchainCommons.com)
## Attribution:   Christopher Allen <ChristopherA@LifeWithAlacrity.com>
## Usage:         merge_pr.sh [-y|--yes] [--dry-run] <pr-number>
## Examples:      merge_pr.sh 3
########################################################################

# Reset the shell environment to a known state
emulate -LR zsh

# Safe shell scripting options
setopt errexit nounset pipefail localoptions warncreateglobal

# Script-scoped exit status codes
typeset -r Exit_Status_Success=0            # Merged
typeset -r Exit_Status_General=1            # General error (unspecified)
typeset -r Exit_Status_Usage=2              # Invalid usage or arguments
typeset -r Exit_Status_IO=3                 # Git, GitHub, or network error
typeset -r Exit_Status_Verification=4       # PR or merge failed verification
typeset -r Exit_Status_Declined=5           # The human declined the merge

typeset -r Script_Name="${0:t}"
typeset -r Verifier="${0:A:h}/verify_commit_signatures.sh"
typeset -r Staging_Ref="refs/heads/staging/main"
typeset -ri Run_Wait_Seconds=90             # How long to wait for CI to start

#----------------------------------------------------------------------#
# Function: show_Usage
#----------------------------------------------------------------------#
# Description:
#   Prints usage instructions to stderr
# Parameters:
#   None
# Returns:
#   Does not return - exits with Exit_Status_Usage
#----------------------------------------------------------------------#
show_Usage() {
    print -u2 "Usage: $Script_Name [-y|--yes] [--dry-run] <pr-number>
Options:
  -y, --yes   Merge without asking for confirmation (Touch ID still prompts)
  --dry-run   Verify and show the PR, but do not merge or push"
    exit $Exit_Status_Usage
}

#----------------------------------------------------------------------#
# Function: say / die
#----------------------------------------------------------------------#
# Description:
#   Progress and error output
# Parameters:
#   $1 - Message; $2 - exit status for die (default Exit_Status_General)
# Returns:
#   say: Exit_Status_Success; die: does not return
#----------------------------------------------------------------------#
say() { print -- "==> $*"; }
die() { print -u2 -- "Error: $1"; exit ${2:-$Exit_Status_General}; }

#----------------------------------------------------------------------#
# Function: wait_For_Check
#----------------------------------------------------------------------#
# Description:
#   Waits for the workflow run on a commit pushed to staging/main to
#   appear and complete
# Parameters:
#   $1 - Commit ID
# Returns:
#   Exit_Status_Success if the run succeeded; exits otherwise
#----------------------------------------------------------------------#
wait_For_Check() {
    typeset Commit_Id="$1" Run_Id=""
    typeset -i Waited=0
    say "Waiting for the verify check on staging/main"
    while [[ -z "$Run_Id" ]]; do
        Run_Id=$(gh run list --branch staging/main --commit "$Commit_Id" --limit 1 \
            --json databaseId --jq '.[0].databaseId // empty' 2>/dev/null) || Run_Id=""
        [[ -n "$Run_Id" ]] && break
        (( Waited < Run_Wait_Seconds )) || die "no CI run appeared for $Commit_Id after ${Run_Wait_Seconds}s" $Exit_Status_IO
        sleep 5
        (( Waited += 5 ))
    done
    gh run watch "$Run_Id" --exit-status --interval 5 >/dev/null \
        || die "verify failed on staging/main (run $Run_Id); main was not changed. Local main holds the unpushed merge; discard it with: git reset --hard origin/main" $Exit_Status_Verification
    say "verify passed (run $Run_Id)"
}

#----------------------------------------------------------------------#
# Function: core_Logic
#----------------------------------------------------------------------#
# Description:
#   Verifies, shows, merges, stages, and lands one pull request
# Parameters:
#   $1 - PR number
#   $2 - "true" to skip the confirmation prompt
#   $3 - "true" for a dry run
# Returns:
#   Exit_Status_Success when main has moved; exits otherwise
#----------------------------------------------------------------------#
core_Logic() {
    typeset Number="$1" Yes="$2" Dry_Run="$3"
    typeset Info Head_Oid Head_Ref Base_Ref Title State Answer Merge_Id

    git rev-parse --show-toplevel >/dev/null 2>&1 || die "not in a Git repository" $Exit_Status_IO
    cd "$(git rev-parse --show-toplevel)"
    [[ -z "$(git status --porcelain --untracked-files=no)" ]] || die "working tree has uncommitted changes" $Exit_Status_IO

    Info=$(gh pr view "$Number" --json headRefOid,headRefName,baseRefName,title,state \
        --jq '[.headRefOid, .headRefName, .baseRefName, .state, .title] | @tsv') \
        || die "cannot read PR #$Number" $Exit_Status_IO
    IFS=$'\t' read -r Head_Oid Head_Ref Base_Ref State Title <<< "$Info"
    [[ "$State" == OPEN ]] || die "PR #$Number is $State" $Exit_Status_Usage
    [[ "$Base_Ref" == main ]] || die "PR #$Number targets $Base_Ref, not main" $Exit_Status_Usage

    say "PR #$Number: $Title ($Head_Ref)"
    git fetch -q origin main || die "fetch of main failed" $Exit_Status_IO
    git fetch -q origin "pull/$Number/head" || die "fetch of PR #$Number failed" $Exit_Status_IO
    [[ "$(git rev-parse FETCH_HEAD)" == "$Head_Oid" ]] || die "fetched head does not match PR head $Head_Oid" $Exit_Status_IO

    git switch -q main
    git merge -q --ff-only origin/main || die "local main has diverged from origin/main" $Exit_Status_IO

    say "Verifying the PR's commits"
    zsh "$Verifier" -q -r "$Head_Oid" --protected origin/main \
        || die "PR #$Number does not verify; not merging" $Exit_Status_Verification

    say "Commits to merge:"
    git log --format='    %h %an: %s' "main..$Head_Oid"
    say "Changes:"
    git diff --stat "main...$Head_Oid" | sed 's/^/    /'

    if [[ "$Dry_Run" == true ]]; then
        say "Dry run: not merging"
        return $Exit_Status_Success
    fi
    if [[ "$Yes" != true ]]; then
        print -n -- "Merge PR #$Number into main, signed with your key? [y/N] "
        read -r Answer
        [[ "$Answer" == [yY]* ]] || die "declined" $Exit_Status_Declined
    fi

    say "Merging (Touch ID)"
    git merge -q --no-ff -S --signoff "$Head_Oid" \
        -m "Merge pull request #$Number from $Head_Ref" -m "$Title" \
        || { git merge --abort 2>/dev/null; die "merge failed; resolve on a branch and update the PR" $Exit_Status_General; }
    Merge_Id=$(git rev-parse HEAD)

    if ! zsh "$Verifier" -q --protected HEAD; then
        git reset -q --hard origin/main
        die "the merge commit does not verify; it was discarded" $Exit_Status_Verification
    fi

    say "Pushing to staging/main"
    git push -q --force origin "HEAD:$Staging_Ref" || die "push to staging/main failed" $Exit_Status_IO
    wait_For_Check "$Merge_Id"

    say "Moving main"
    git push -q origin HEAD:main || die "push to main refused; the merge is on staging/main" $Exit_Status_IO
    say "Merged PR #$Number as $(git rev-parse --short "$Merge_Id")"
    return $Exit_Status_Success
}

#----------------------------------------------------------------------#
# Function: main
#----------------------------------------------------------------------#
# Description:
#   Parses arguments and runs the merge
# Parameters:
#   $@ - Command line arguments
# Returns:
#   Exit status from core_Logic, or Exit_Status_Usage
#----------------------------------------------------------------------#
main() {
    typeset Number="" Yes=false Dry_Run=false Tool
    while (( $# > 0 )); do
        case "$1" in
            -y|--yes) Yes=true; shift ;;
            --dry-run) Dry_Run=true; shift ;;
            -h|--help) show_Usage ;;
            <->) Number="$1"; shift ;;
            *) print -u2 "Error: Unknown argument '$1'"; show_Usage ;;
        esac
    done
    [[ -n "$Number" ]] || show_Usage
    for Tool in git gh ssh-keygen; do
        command -v $Tool >/dev/null || die "$Tool not found" $Exit_Status_IO
    done
    core_Logic "$Number" "$Yes" "$Dry_Run"
}

main "$@"
