#!/usr/bin/env zsh
########################################################################
## Script:        TEST-verify_commit_signatures.sh
## Version:       0.1.00 (2026-10-02)
## Origin:        https://github.com/OpenIntegrityProject/openintegrityproject-dev/blob/main/.repo/scripts/tests/TEST-verify_commit_signatures.sh
## Description:   Regression tests for verify_commit_signatures.sh. Builds
##                throwaway repositories signed with throwaway keys and
##                checks that valid trust chains pass and each kind of
##                broken chain fails.
## License:       BSD-2-Clause-Patent (https://spdx.org/licenses/BSD-2-Clause-Patent.html)
## Copyright:     (c) 2026 Blockchain Commons LLC (https://www.BlockchainCommons.com)
## Attribution:   Christopher Allen <ChristopherA@LifeWithAlacrity.com>
## Usage:         TEST-verify_commit_signatures.sh
########################################################################

# Reset the shell environment to a known state
emulate -LR zsh

# Safe shell scripting options
setopt errexit nounset pipefail localoptions warncreateglobal

typeset -r Exit_Status_Success=0
typeset -r Exit_Status_General=1

typeset -r Verifier="${0:A:h:h}/verify_commit_signatures.sh"
typeset -r Verification_Dir=".repo/config/verification"
typeset -r Signers_Path="$Verification_Dir/allowed_commit_signers"
typeset -g Test_Root=""
typeset -gi Tests_Run=0 Tests_Failed=0

#----------------------------------------------------------------------#
# Function: make_Key
#----------------------------------------------------------------------#
# Description:
#   Creates an unencrypted throwaway ed25519 key in the test root
# Parameters:
#   $1 - Key name
# Returns:
#   Exit_Status_Success
#----------------------------------------------------------------------#
make_Key() {
    ssh-keygen -q -t ed25519 -N '' -C "$1" -f "$Test_Root/keys/$1"
}

#----------------------------------------------------------------------#
# Function: key_Fingerprint
#----------------------------------------------------------------------#
# Description:
#   Prints the SHA256 fingerprint of a throwaway key
# Parameters:
#   $1 - Key name
# Returns:
#   Exit_Status_Success
#----------------------------------------------------------------------#
key_Fingerprint() {
    ssh-keygen -lf "$Test_Root/keys/$1.pub" | awk '{print $2}'
}

#----------------------------------------------------------------------#
# Function: signers_Line
#----------------------------------------------------------------------#
# Description:
#   Prints an allowed signers line for a throwaway key
# Parameters:
#   $1 - Key name (also used as the principal)
#   $2 - Optional extra options, comma-prefixed (e.g. ',valid-before="2020"')
# Returns:
#   Exit_Status_Success
#----------------------------------------------------------------------#
signers_Line() {
    print -r -- "@$1 namespaces=\"git\"${2-} $(<"$Test_Root/keys/$1.pub")"
}

#----------------------------------------------------------------------#
# Function: signed_Commit
#----------------------------------------------------------------------#
# Description:
#   Commits staged changes in the current repository, SSH-signed by a
#   throwaway key (or unsigned when the key name is "none")
# Parameters:
#   $1 - Key name, or "none"
#   $2 - Commit message
#   $@ - Extra arguments for git commit
# Returns:
#   Exit status of git commit
#----------------------------------------------------------------------#
signed_Commit() {
    typeset Key="$1" Message="$2"
    shift 2
    if [[ "$Key" == none ]]; then
        git -c commit.gpgsign=false commit -q --allow-empty -m "$Message" "$@"
    else
        git -c gpg.format=ssh -c gpg.ssh.program=ssh-keygen \
            -c user.signingkey="$Test_Root/keys/$Key" \
            commit -q -S --allow-empty -m "$Message" "$@"
    fi
}

#----------------------------------------------------------------------#
# Function: new_Repo
#----------------------------------------------------------------------#
# Description:
#   Creates a repository with an Open Integrity inception commit (empty,
#   committer named by key fingerprint) and cds into it
# Parameters:
#   $1 - Repository name
#   $2 - Inception key name
# Returns:
#   Exit_Status_Success
#----------------------------------------------------------------------#
new_Repo() {
    typeset Name="$1" Key="$2"
    git init -q -b main "$Test_Root/$Name"
    cd "$Test_Root/$Name"
    git config user.name "Test User"
    git config user.email "test@example.com"
    GIT_COMMITTER_NAME="$(key_Fingerprint "$Key")" signed_Commit "$Key" "Inception"
}

#----------------------------------------------------------------------#
# Function: add_Signers
#----------------------------------------------------------------------#
# Description:
#   Writes the allowed signers file and commits it, signed by a key
# Parameters:
#   $1 - Signing key name
#   $2 - File contents
# Returns:
#   Exit_Status_Success
#----------------------------------------------------------------------#
add_Signers() {
    add_Trust_File "$1" allowed_commit_signers "$2"
}

#----------------------------------------------------------------------#
# Function: add_Trust_File
#----------------------------------------------------------------------#
# Description:
#   Writes a file in the verification directory and commits it, signed
#   by a key
# Parameters:
#   $1 - Signing key name
#   $2 - File name within the verification directory
#   $3 - File contents
# Returns:
#   Exit_Status_Success
#----------------------------------------------------------------------#
add_Trust_File() {
    typeset Key="$1" File="$Verification_Dir/$2" Contents="$3"
    mkdir -p "$Verification_Dir"
    print -r -- "$Contents" > "$File"
    git add "$File"
    signed_Commit "$Key" "Update ${File:t}"
}

#----------------------------------------------------------------------#
# Function: signed_Tag
#----------------------------------------------------------------------#
# Description:
#   Creates an annotated tag on HEAD, SSH-signed by a throwaway key
# Parameters:
#   $1 - Key name
#   $2 - Tag name
# Returns:
#   Exit status of git tag
#----------------------------------------------------------------------#
signed_Tag() {
    git -c gpg.format=ssh -c gpg.ssh.program=ssh-keygen \
        -c user.signingkey="$Test_Root/keys/$1" \
        tag -s "$2" -m "Release $2"
}

#----------------------------------------------------------------------#
# Function: expect
#----------------------------------------------------------------------#
# Description:
#   Runs the verifier in the current repository and checks its exit
#   status and, optionally, that its output contains a string
# Parameters:
#   $1 - Test name
#   $2 - Expected exit status
#   $3 - Optional expected output substring
#   $@ - Optional further arguments for the verifier
# Returns:
#   Exit_Status_Success always (failures are counted)
#----------------------------------------------------------------------#
expect() {
    typeset Name="$1" Expected_Status="$2" Expected_Text="${3-}" Output
    typeset -i Status=0
    shift $(( $# < 3 ? $# : 3 ))
    Output=$(zsh "$Verifier" "$@" 2>&1) || Status=$?
    (( Tests_Run += 1 ))
    if (( Status == Expected_Status )) && [[ -z "$Expected_Text" || "$Output" == *"$Expected_Text"* ]]; then
        print -- "PASS  $Name"
    else
        (( Tests_Failed += 1 ))
        print -- "FAIL  $Name (exit $Status, expected $Expected_Status${Expected_Text:+, text \"$Expected_Text\"})"
        print -- "$Output" | sed 's/^/      /'
    fi
    return $Exit_Status_Success
}

#----------------------------------------------------------------------#
# Function: run_Tests
#----------------------------------------------------------------------#
# Description:
#   Runs every test case
# Parameters:
#   None
# Returns:
#   Exit_Status_Success always
#----------------------------------------------------------------------#
run_Tests() {
    typeset Name
    for Name in root human alice mallory; do make_Key $Name; done

    new_Repo valid root
    add_Signers root "$(signers_Line root)
$(signers_Line alice)"
    signed_Commit alice "Alice's work"
    expect "valid chain: inception, signers file, approved signer" 0 "Verified 3 of 3"

    new_Repo unsigned root
    add_Signers root "$(signers_Line root)"
    signed_Commit none "Unsigned work"
    expect "unsigned commit fails" 4 "unsigned or not SSH-signed"

    new_Repo unknown root
    add_Signers root "$(signers_Line root)"
    signed_Commit mallory "Mallory's work"
    expect "unlisted signer fails" 4 "not authorized"

    new_Repo self_approval root
    add_Signers root "$(signers_Line root)"
    add_Signers mallory "$(signers_Line root)
$(signers_Line mallory)"
    expect "signer cannot approve itself in the same commit" 4 "not authorized"

    new_Repo before_signers root
    signed_Commit alice "Before any signers file"
    expect "only the inception key signs before the signers file exists" 4 "is not the inception key"

    git init -q -b main "$Test_Root/nonempty_inception"
    cd "$Test_Root/nonempty_inception"
    git config user.name "Test User"; git config user.email "test@example.com"
    print data > file.txt; git add file.txt
    GIT_COMMITTER_NAME="$(key_Fingerprint root)" signed_Commit root "Inception with content"
    expect "non-empty inception fails" 4 "inception commit is not empty"

    git init -q -b main "$Test_Root/wrong_committer"
    cd "$Test_Root/wrong_committer"
    git config user.name "Test User"; git config user.email "test@example.com"
    GIT_COMMITTER_NAME="$(key_Fingerprint alice)" signed_Commit root "Inception"
    expect "inception key must match committer fingerprint" 4 "committer names"

    new_Repo expiry root
    add_Signers root "$(signers_Line root)
$(signers_Line alice ',valid-before="20200101"')"
    GIT_COMMITTER_DATE="2019-06-01T00:00:00Z" signed_Commit alice "Before expiry"
    expect "valid-before honors the commit date, not today" 0
    GIT_COMMITTER_DATE="2021-06-01T00:00:00Z" signed_Commit alice "After expiry"
    expect "commit after valid-before fails" 4 "not authorized"

    new_Repo two_roots root
    Name=$(git symbolic-ref --short HEAD)
    git checkout -q --orphan other
    GIT_COMMITTER_NAME="$(key_Fingerprint alice)" signed_Commit alice "Second inception"
    git checkout -q "$Name"
    git -c gpg.format=ssh -c gpg.ssh.program=ssh-keygen \
        -c user.signingkey="$Test_Root/keys/root" \
        merge -q -S --allow-unrelated-histories -m "Merge" other
    expect "a second root commit fails" 4 "found 2"

    new_Repo source_for_shallow root
    add_Signers root "$(signers_Line root)"
    signed_Commit root "More"
    git clone -q --depth 1 "file://$Test_Root/source_for_shallow" "$Test_Root/shallow" 2>/dev/null
    cd "$Test_Root/shallow"
    expect "shallow clone is refused" 3 "shallow clone"

    run_Role_Tests
    return $Exit_Status_Success
}

#----------------------------------------------------------------------#
# Function: new_Role_Repo
#----------------------------------------------------------------------#
# Description:
#   Creates a repository where root and human may sign anything,
#   alice (standing in for an agent key) may sign commits, and only
#   human may sign main and tags
# Parameters:
#   $1 - Repository name
# Returns:
#   Exit_Status_Success
#----------------------------------------------------------------------#
new_Role_Repo() {
    new_Repo "$1" root
    add_Signers root "$(signers_Line root)
$(signers_Line human)
$(signers_Line alice)"
    add_Trust_File root allowed_main_signers "$(signers_Line human)"
    add_Trust_File human allowed_tag_signers "$(signers_Line human)"
}

#----------------------------------------------------------------------#
# Function: run_Role_Tests
#----------------------------------------------------------------------#
# Description:
#   Tests for main signers, trust-file protection, and tag signers
# Parameters:
#   None
# Returns:
#   Exit_Status_Success always
#----------------------------------------------------------------------#
run_Role_Tests() {
    new_Role_Repo roles_valid
    git checkout -q -b feature
    signed_Commit alice "Agent work on a branch"
    git checkout -q main
    git -c gpg.format=ssh -c gpg.ssh.program=ssh-keygen \
        -c user.signingkey="$Test_Root/keys/human" \
        merge -q --no-ff -S -m "Merge agent work" feature
    expect "agent commits on a branch, merged to main by a main signer" 0 "main:@human"

    new_Role_Repo roles_direct
    signed_Commit alice "Agent commit directly on main"
    expect "commit signer alone cannot sign on main" 4 "(protected branch)"
    expect "same commit passes when no branch is protected" 0 "" --protected ''

    new_Role_Repo roles_trust
    git checkout -q -b feature
    add_Signers alice "$(signers_Line root)
$(signers_Line human)
$(signers_Line alice)
$(signers_Line mallory)"
    expect "commit signer cannot change trust files, even off main" 4 "changes $Verification_Dir" --rev feature

    new_Role_Repo roles_merge_trust
    git checkout -q -b feature
    add_Signers human "$(signers_Line root)
$(signers_Line human)"
    git checkout -q main
    git -c gpg.format=ssh -c gpg.ssh.program=ssh-keygen \
        -c user.signingkey="$Test_Root/keys/human" \
        merge -q --no-ff -S -m "Merge trust change" feature
    expect "main signer may change trust files" 0

    new_Role_Repo roles_staging
    git checkout -q -b staging
    signed_Commit alice "Agent commit about to become main"
    expect "--protected HEAD applies main rules to a staging branch" 4 "(protected branch)" --protected HEAD

    new_Role_Repo tags_valid
    signed_Tag human v1.0
    expect "tag signed by a tag signer" 0 "tag v1.0 OK @human"

    new_Role_Repo tags_wrong_signer
    signed_Tag alice v1.0
    expect "tag signed by a non-tag signer fails" 4 "not in"

    new_Role_Repo tags_lightweight
    git tag v1.0
    expect "lightweight tag fails" 4 "lightweight tag"

    new_Repo tags_no_file root
    add_Signers root "$(signers_Line root)"
    signed_Tag root v1.0
    expect "tag fails when the tagged commit has no tag signers file" 4 "no $Verification_Dir/allowed_tag_signers"

    return $Exit_Status_Success
}

#----------------------------------------------------------------------#
# Function: main
#----------------------------------------------------------------------#
# Description:
#   Sets up an isolated test root and Git environment, runs the tests,
#   and reports a summary
# Parameters:
#   None
# Returns:
#   Exit_Status_Success if all tests pass, Exit_Status_General otherwise
#----------------------------------------------------------------------#
main() {
    Test_Root=$(mktemp -d)
    mkdir -p "$Test_Root/keys"
    trap 'rm -rf -- "$Test_Root"' EXIT

    # Isolate from the user's Git configuration and signing setup
    export GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_NOSYSTEM=1
    unset SSH_AUTH_SOCK

    run_Tests
    print -- "$(( Tests_Run - Tests_Failed )) of $Tests_Run tests passed"
    (( Tests_Failed == 0 )) || return $Exit_Status_General
    return $Exit_Status_Success
}

main "$@"
