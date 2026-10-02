#!/usr/bin/env zsh
########################################################################
## Script:        verify_commit_signatures.sh
## Version:       0.2.00 (2026-10-02)
## Origin:        https://github.com/OpenIntegrityProject/openintegrityproject-dev/blob/main/.repo/scripts/verify_commit_signatures.sh
## Description:   Verifies every commit reachable from a revision against
##                the Open Integrity trust chain: the inception commit is
##                signed by the key named in its committer field, and each
##                later commit is signed by a key listed in the
##                allowed_commit_signers file of its first parent (or by
##                the inception key, before that file exists). Once a
##                parent defines allowed_main_signers, commits on the
##                protected branch's first-parent chain and commits that
##                change the verification files must also be signed by a
##                main signer. Signed tags are checked against the tagged
##                commit's allowed_tag_signers. Reports security-key flags
##                (user presence / verification) for sk-* signatures.
##                Requires only git and OpenSSH.
## License:       BSD-2-Clause-Patent (https://spdx.org/licenses/BSD-2-Clause-Patent.html)
## Copyright:     (c) 2026 Blockchain Commons LLC (https://www.BlockchainCommons.com)
## Attribution:   Christopher Allen <ChristopherA@LifeWithAlacrity.com>
## Usage:         verify_commit_signatures.sh [-C <dir>] [-r|--rev <revision>]
##                    [-p|--protected <ref>] [-q|--quiet]
## Examples:      verify_commit_signatures.sh
##                verify_commit_signatures.sh -r origin/main
##                verify_commit_signatures.sh --protected HEAD
##                verify_commit_signatures.sh -C ../other-repo -q
########################################################################

# Reset the shell environment to a known state
emulate -LR zsh

# Safe shell scripting options
setopt errexit nounset pipefail localoptions warncreateglobal

zmodload zsh/datetime

# Script-scoped exit status codes
typeset -r Exit_Status_Success=0            # All commits verified
typeset -r Exit_Status_General=1            # General error (unspecified)
typeset -r Exit_Status_Usage=2              # Invalid usage or arguments
typeset -r Exit_Status_IO=3                 # Input/output error
typeset -r Exit_Status_Verification=4       # One or more commits failed

# Script name for messages ($0 becomes the function name inside functions)
typeset -r Script_Name="${0:t}"

# Repository-relative paths of the verification (trust) files. Each
# role's file is read from the parent commit (or tagged commit), so a
# change to a file is always judged by the version before it.
typeset -r Verification_Dir=".repo/config/verification"
typeset -r Commit_Signers_Path="$Verification_Dir/allowed_commit_signers"
typeset -r Main_Signers_Path="$Verification_Dir/allowed_main_signers"
typeset -r Tag_Signers_Path="$Verification_Dir/allowed_tag_signers"

# SHA-1 of Git's empty tree; Open Integrity inception commits are empty
typeset -r Empty_Tree="4b825dc642cb6eb9a060e54bf8d69288fbee4904"

#----------------------------------------------------------------------#
# Function: show_Usage
#----------------------------------------------------------------------#
# Description:
#   Prints usage instructions and examples to stderr
# Parameters:
#   None
# Returns:
#   Does not return - exits with Exit_Status_Usage
#----------------------------------------------------------------------#
show_Usage() {
    print -u2 "Usage: $Script_Name [-C <dir>] [-r|--rev <revision>] [-p|--protected <ref>] [-q|--quiet]
Options:
  -C <dir>               Run in this repository (default: current directory)
  -r, --rev <revision>   Verify all commits reachable from this revision,
                         and all signed tags (default: HEAD)
  -p, --protected <ref>  Branch whose first-parent chain requires main
                         signers (default: origin/main, else main; pass
                         HEAD when verifying a commit about to become main;
                         pass '' for none)
  -q, --quiet            Print only failures and the summary
Exit status:
  0 all commits verified, 4 one or more failed, 2 usage, 3 I/O error"
    exit $Exit_Status_Usage
}

#----------------------------------------------------------------------#
# Function: extract_Signature
#----------------------------------------------------------------------#
# Description:
#   Writes a commit's armored SSH signature (from its gpgsig header) to
#   one file and the signed payload (the commit object without that
#   header) to another, exactly as git reconstructs them for verification
# Parameters:
#   $1 - Commit ID
#   $2 - Output path for the signature
#   $3 - Output path for the payload
# Returns:
#   Exit_Status_Success if the commit carries an SSH signature
#   Exit_Status_General if it is unsigned or not SSH-signed
#----------------------------------------------------------------------#
extract_Signature() {
    typeset Commit_Id="$1" Signature_File="$2" Payload_File="$3"
    git cat-file commit "$Commit_Id" | awk -v sig="$Signature_File" '
        BEGIN { in_header = 1 }
        in_header && /^$/ { in_header = 0 }
        in_header && /^gpgsig / { in_sig = 1; print substr($0, 8) > sig; next }
        in_header && in_sig && /^ / { print substr($0, 2) > sig; next }
        { in_sig = 0; print }
    ' > "$Payload_File"
    [[ -s "$Signature_File" ]] && grep -q -- '-----BEGIN SSH SIGNATURE-----' "$Signature_File"
}

#----------------------------------------------------------------------#
# Function: read_Uint32_At
#----------------------------------------------------------------------#
# Description:
#   Reads a big-endian uint32 from the caller's Bytes array (hex byte
#   strings, as produced by od -tx1)
# Parameters:
#   $1 - 1-based index of the first byte in Bytes
# Returns:
#   Prints the decimal value; Exit_Status_Success always
#----------------------------------------------------------------------#
read_Uint32_At() {
    typeset -i Index="$1"
    print $(( 16#${Bytes[Index]}${Bytes[Index+1]}${Bytes[Index+2]}${Bytes[Index+3]} ))
}

#----------------------------------------------------------------------#
# Function: read_Signature_Flags
#----------------------------------------------------------------------#
# Description:
#   Decodes an SSHSIG signature and, for security-key (sk-*) signatures,
#   prints the authenticator flags and counter. Other signature types
#   print nothing.
# Parameters:
#   $1 - Path to the armored signature
# Returns:
#   Prints "flags=0xNN UP=0|1 UV=0|1 counter=N" for sk signatures
#   (UP = user presence, UV = user verification)
#   Exit_Status_Success always
#----------------------------------------------------------------------#
read_Signature_Flags() {
    typeset Signature_File="$1"
    typeset -a Bytes
    typeset -i Pos Len Inner Flags Counter Skip

    Bytes=(${=$(grep -v -- '-----' "$Signature_File" | tr -d '\n' \
        | base64 -d 2>/dev/null | od -An -v -tx1)})
    (( ${#Bytes} > 10 )) || return $Exit_Status_Success

    # SSHSIG layout: magic(6) version(4) then strings: publickey,
    # namespace, reserved, hash_algorithm, signature
    Pos=11
    for Skip in {1..4}; do
        Len=$(read_Uint32_At $Pos)
        Pos=$(( Pos + 4 + Len ))
    done
    # Signature blob: string type, string signature, [byte flags, uint32 counter]
    Pos=$(( Pos + 4 ))
    Len=$(read_Uint32_At $Pos)
    # Only sk-* signature types ("sk-" is 73 6b 2d) carry flags
    [[ "${Bytes[Pos+4]}${Bytes[Pos+5]}${Bytes[Pos+6]}" == 736b2d ]] || return $Exit_Status_Success
    Inner=$(( Pos + 4 + Len ))
    Len=$(read_Uint32_At $Inner)
    Inner=$(( Inner + 4 + Len ))
    Flags=$(( 16#${Bytes[Inner]} ))
    Counter=$(read_Uint32_At $(( Inner + 1 )))
    print -- "flags=0x${(l:2::0:)$(( [##16] Flags ))} UP=$(( Flags & 1 )) UV=$(( (Flags & 4) >> 2 )) counter=$Counter"
    return $Exit_Status_Success
}

#----------------------------------------------------------------------#
# Function: check_Signature_Key
#----------------------------------------------------------------------#
# Description:
#   Checks a signature is cryptographically valid for its payload in the
#   "git" namespace, without consulting any allowed signers file, and
#   prints the signing key's type and fingerprint
# Parameters:
#   $1 - Path to the armored signature
#   $2 - Path to the payload
# Returns:
#   Prints "<KEYTYPE> SHA256:<fingerprint>"
#   Exit_Status_Success if valid, Exit_Status_General otherwise
#----------------------------------------------------------------------#
check_Signature_Key() {
    typeset Signature_File="$1" Payload_File="$2" Output
    typeset -a match mbegin mend
    Output=$(ssh-keygen -Y check-novalidate -n git -s "$Signature_File" \
        < "$Payload_File" 2>&1) || return $Exit_Status_General
    [[ "$Output" =~ 'with ([A-Z0-9-]+) key (SHA256:[A-Za-z0-9+/]+)' ]] \
        || return $Exit_Status_General
    print -- "$match[1] $match[2]"
}

#----------------------------------------------------------------------#
# Function: verify_Against_Signers
#----------------------------------------------------------------------#
# Description:
#   Verifies a signature against an allowed signers file as of a given
#   time (so valid-after/valid-before apply to the commit's date, not
#   today), and prints the matching principal
# Parameters:
#   $1 - Path to the armored signature
#   $2 - Path to the payload
#   $3 - Path to the allowed signers file
#   $4 - Verification time, YYYYMMDDHHMMSSZ
# Returns:
#   Prints the principal on success
#   Exit_Status_Success if a listed principal verifies,
#   Exit_Status_General otherwise
#----------------------------------------------------------------------#
verify_Against_Signers() {
    typeset Signature_File="$1" Payload_File="$2" Signers_File="$3" Verify_Time="$4"
    typeset Principals Principal
    Principals=$(ssh-keygen -Y find-principals -O verify-time="$Verify_Time" \
        -f "$Signers_File" -s "$Signature_File" 2>/dev/null) || return $Exit_Status_General
    for Principal in "${(@f)Principals}"; do
        if ssh-keygen -Y verify -O verify-time="$Verify_Time" -f "$Signers_File" \
            -I "$Principal" -n git -s "$Signature_File" < "$Payload_File" >/dev/null 2>&1; then
            print -- "$Principal"
            return $Exit_Status_Success
        fi
    done
    return $Exit_Status_General
}

#----------------------------------------------------------------------#
# Function: verify_Commit
#----------------------------------------------------------------------#
# Description:
#   Verifies one commit under the Open Integrity rules and prints a
#   result line: "<short-id> OK <signer> <keytype> <fingerprint> [flags]"
#   or "<short-id> FAIL <reason>"
# Parameters:
#   $1 - Commit ID
#   $2 - Inception commit ID
#   $3 - Inception key fingerprint (from the inception committer field)
#   $4 - Working directory for temporary files
#   $5 - "true" if the commit is on the protected branch's first-parent
#        chain
# Returns:
#   Exit_Status_Success if the commit verifies
#   Exit_Status_Verification otherwise
#----------------------------------------------------------------------#
verify_Commit() {
    typeset Commit_Id="$1" Inception_Id="$2" Inception_Fingerprint="$3" Work_Dir="$4"
    typeset Protected="$5"
    typeset Short_Id Signature_File="$Work_Dir/sig" Payload_File="$Work_Dir/payload"
    typeset Signers_File="$Work_Dir/allowed_signers" Key_Info Key_Fingerprint
    typeset Flags Parent Signer Verify_Time Main_Reason="" Main_Signer
    typeset -i Commit_Time

    Short_Id=$(git rev-parse --short "$Commit_Id")
    rm -f -- "$Signature_File" "$Payload_File" "$Signers_File"

    if ! extract_Signature "$Commit_Id" "$Signature_File" "$Payload_File"; then
        print -- "$Short_Id FAIL unsigned or not SSH-signed"
        return $Exit_Status_Verification
    fi
    if ! Key_Info=$(check_Signature_Key "$Signature_File" "$Payload_File"); then
        print -- "$Short_Id FAIL signature does not verify"
        return $Exit_Status_Verification
    fi
    Key_Fingerprint="${Key_Info#* }"
    Flags=$(read_Signature_Flags "$Signature_File")
    Commit_Time=$(git show -s --format=%ct "$Commit_Id")
    TZ=UTC strftime -s Verify_Time '%Y%m%d%H%M%SZ' $Commit_Time

    Parent=$(git rev-parse -q --verify "$Commit_Id^1" 2>/dev/null) || Parent=""
    if [[ -z "$Parent" ]]; then
        # Inception: signed by the key its committer field names, empty tree
        if [[ "$Commit_Id" != "$Inception_Id" ]]; then
            print -- "$Short_Id FAIL second root commit; only one inception is allowed"
            return $Exit_Status_Verification
        fi
        if [[ "$Key_Fingerprint" != "$Inception_Fingerprint" ]]; then
            print -- "$Short_Id FAIL inception signed by $Key_Fingerprint, committer names $Inception_Fingerprint"
            return $Exit_Status_Verification
        fi
        if [[ "$(git rev-parse "$Commit_Id^{tree}")" != "$Empty_Tree" ]]; then
            print -- "$Short_Id FAIL inception commit is not empty"
            return $Exit_Status_Verification
        fi
        Signer="inception"
    elif git cat-file -e "$Parent:$Commit_Signers_Path" 2>/dev/null; then
        # Authorized by the signers file as of the first parent
        git show "$Parent:$Commit_Signers_Path" > "$Signers_File"
        if ! Signer=$(verify_Against_Signers "$Signature_File" "$Payload_File" \
            "$Signers_File" "$Verify_Time"); then
            print -- "$Short_Id FAIL $Key_Fingerprint not authorized by $Commit_Signers_Path at $(git rev-parse --short "$Parent")"
            return $Exit_Status_Verification
        fi
    else
        # Before the signers file exists, only the inception key may sign
        if [[ "$Key_Fingerprint" != "$Inception_Fingerprint" ]]; then
            print -- "$Short_Id FAIL $Key_Fingerprint is not the inception key, and no signers file exists yet"
            return $Exit_Status_Verification
        fi
        Signer="inception"
    fi

    # Once the first parent defines main signers, commits on the protected
    # branch and commits changing the verification files need one too.
    # For a merge, the change is measured against the first parent, so a
    # merge that brings in trust-file changes needs a main signer.
    if [[ -n "$Parent" ]] && git cat-file -e "$Parent:$Main_Signers_Path" 2>/dev/null; then
        [[ "$Protected" == true ]] && Main_Reason="protected branch"
        git diff --quiet "$Parent" "$Commit_Id" -- "$Verification_Dir" \
            || Main_Reason="${Main_Reason:+$Main_Reason, }changes $Verification_Dir"
        if [[ -n "$Main_Reason" ]]; then
            git show "$Parent:$Main_Signers_Path" > "$Signers_File"
            if ! Main_Signer=$(verify_Against_Signers "$Signature_File" "$Payload_File" \
                "$Signers_File" "$Verify_Time"); then
                print -- "$Short_Id FAIL $Key_Fingerprint not in $Main_Signers_Path at $(git rev-parse --short "$Parent") ($Main_Reason)"
                return $Exit_Status_Verification
            fi
            Signer="$Signer main:$Main_Signer"
        fi
    fi

    print -- "$Short_Id OK $Signer $Key_Info${Flags:+ $Flags}"
    return $Exit_Status_Success
}

#----------------------------------------------------------------------#
# Function: verify_Tag
#----------------------------------------------------------------------#
# Description:
#   Verifies one tag: it must be an annotated tag with an SSH signature
#   by a key listed in the allowed_tag_signers file of the tagged commit,
#   as of the tagger date. Prints "tag <name> OK <signer> <keytype>
#   <fingerprint> [flags]" or "tag <name> FAIL <reason>".
# Parameters:
#   $1 - Tag name
#   $2 - Working directory for temporary files
# Returns:
#   Exit_Status_Success if the tag verifies
#   Exit_Status_Verification otherwise
#----------------------------------------------------------------------#
verify_Tag() {
    typeset Tag="$1" Work_Dir="$2"
    typeset Signature_File="$Work_Dir/sig" Payload_File="$Work_Dir/payload"
    typeset Signers_File="$Work_Dir/allowed_signers"
    typeset Key_Info Flags Target Signer Verify_Time
    typeset -i Tag_Time

    rm -f -- "$Signature_File" "$Payload_File" "$Signers_File"
    if [[ "$(git cat-file -t "refs/tags/$Tag")" != tag ]]; then
        print -- "tag $Tag FAIL lightweight tag (cannot be signed)"
        return $Exit_Status_Verification
    fi
    # The signature is appended to the tag message; the payload is
    # everything before it
    git cat-file tag "refs/tags/$Tag" | awk -v sig="$Signature_File" '
        /^-----BEGIN SSH SIGNATURE-----$/ { in_sig = 1 }
        in_sig { print > sig; next }
        { print }
    ' > "$Payload_File"
    if [[ ! -s "$Signature_File" ]]; then
        print -- "tag $Tag FAIL unsigned or not SSH-signed"
        return $Exit_Status_Verification
    fi
    if ! Key_Info=$(check_Signature_Key "$Signature_File" "$Payload_File"); then
        print -- "tag $Tag FAIL signature does not verify"
        return $Exit_Status_Verification
    fi
    Flags=$(read_Signature_Flags "$Signature_File")

    Target=$(git rev-parse "refs/tags/$Tag^{commit}")
    if ! git cat-file -e "$Target:$Tag_Signers_Path" 2>/dev/null; then
        print -- "tag $Tag FAIL no $Tag_Signers_Path at tagged commit $(git rev-parse --short "$Target")"
        return $Exit_Status_Verification
    fi
    git show "$Target:$Tag_Signers_Path" > "$Signers_File"
    Tag_Time=$(sed -n 's/^tagger .* \([0-9][0-9]*\) [-+][0-9][0-9]*$/\1/p' "$Payload_File" | head -n 1)
    TZ=UTC strftime -s Verify_Time '%Y%m%d%H%M%SZ' $Tag_Time
    if ! Signer=$(verify_Against_Signers "$Signature_File" "$Payload_File" \
        "$Signers_File" "$Verify_Time"); then
        print -- "tag $Tag FAIL ${Key_Info#* } not in $Tag_Signers_Path at $(git rev-parse --short "$Target")"
        return $Exit_Status_Verification
    fi

    print -- "tag $Tag OK $Signer $Key_Info${Flags:+ $Flags}"
    return $Exit_Status_Success
}

#----------------------------------------------------------------------#
# Function: core_Logic
#----------------------------------------------------------------------#
# Description:
#   Finds the single inception commit, verifies every commit reachable
#   from the revision (oldest first), then every tag
# Parameters:
#   $1 - Revision
#   $2 - "true" for quiet output
#   $3 - Protected branch ref, or empty for none
# Returns:
#   Exit_Status_Success if all commits verify
#   Exit_Status_Verification if any fail
#   Exit_Status_IO on repository errors
#----------------------------------------------------------------------#
core_Logic() {
    typeset Revision="$1" Quiet="$2" Protected_Ref="$3"
    typeset -a Roots Commits Tags
    typeset -A Protected_Commits
    typeset Inception_Id Inception_Fingerprint Commit_Id Result Work_Dir Tag
    typeset -i Checked=0 Failed=0 Tags_Checked=0 Tags_Failed=0

    git rev-parse --verify -q "$Revision^{commit}" >/dev/null || {
        print -u2 "Error: '$Revision' is not a commit"
        return $Exit_Status_IO
    }
    if [[ "$(git rev-parse --is-shallow-repository)" == true ]]; then
        print -u2 "Error: shallow clone; fetch full history (e.g. actions/checkout fetch-depth: 0)"
        return $Exit_Status_IO
    fi

    Roots=(${(f)"$(git rev-list --max-parents=0 "$Revision")"})
    if (( ${#Roots} != 1 )); then
        print -u2 "Error: expected exactly one inception (root) commit, found ${#Roots}"
        return $Exit_Status_Verification
    fi
    Inception_Id="$Roots[1]"
    Inception_Fingerprint=$(git show -s --format=%cn "$Inception_Id")
    if [[ "$Inception_Fingerprint" != SHA256:* ]]; then
        print -u2 "Error: inception committer '$Inception_Fingerprint' is not a key fingerprint"
        return $Exit_Status_Verification
    fi

    if [[ -n "$Protected_Ref" ]]; then
        git rev-parse --verify -q "$Protected_Ref^{commit}" >/dev/null || {
            print -u2 "Error: protected ref '$Protected_Ref' is not a commit"
            return $Exit_Status_IO
        }
        for Commit_Id in ${(f)"$(git rev-list --first-parent "$Protected_Ref")"}; do
            Protected_Commits[$Commit_Id]=1
        done
    fi

    Work_Dir=$(mktemp -d) || return $Exit_Status_IO
    Commits=(${(f)"$(git rev-list --reverse --topo-order "$Revision")"})
    for Commit_Id in "${Commits[@]}"; do
        (( Checked += 1 ))
        if Result=$(verify_Commit "$Commit_Id" "$Inception_Id" "$Inception_Fingerprint" \
            "$Work_Dir" "${${Protected_Commits[$Commit_Id]-}:+true}"); then
            [[ "$Quiet" == true ]] || print -- "$Result"
        else
            (( Failed += 1 ))
            print -- "$Result"
        fi
    done

    Tags=(${(f)"$(git for-each-ref --format='%(refname:short)' refs/tags)"})
    for Tag in "${Tags[@]}"; do
        [[ -n "$Tag" ]] || continue
        (( Tags_Checked += 1 ))
        if Result=$(verify_Tag "$Tag" "$Work_Dir"); then
            [[ "$Quiet" == true ]] || print -- "$Result"
        else
            (( Tags_Failed += 1 ))
            print -- "$Result"
        fi
    done
    rm -rf -- "$Work_Dir"

    print -- "Verified $(( Checked - Failed )) of $Checked commits from inception $(git rev-parse --short "$Inception_Id") ($Inception_Fingerprint)${Protected_Ref:+, protected branch $Protected_Ref}"
    (( Tags_Checked == 0 )) || print -- "Verified $(( Tags_Checked - Tags_Failed )) of $Tags_Checked tags"
    (( Failed == 0 && Tags_Failed == 0 )) || return $Exit_Status_Verification
    return $Exit_Status_Success
}

#----------------------------------------------------------------------#
# Function: main
#----------------------------------------------------------------------#
# Description:
#   Parses arguments and runs verification
# Parameters:
#   $@ - Command line arguments
# Returns:
#   Exit status from core_Logic, or Exit_Status_Usage
#----------------------------------------------------------------------#
main() {
    typeset Revision="HEAD" Quiet=false Protected_Ref Protected_Set=false

    while (( $# > 0 )); do
        case "$1" in
            -C)
                (( $# > 1 )) || show_Usage
                cd -- "$2" || return $Exit_Status_IO
                shift 2 ;;
            -r|--rev)
                (( $# > 1 )) || show_Usage
                Revision="$2"; shift 2 ;;
            -p|--protected)
                (( $# > 1 )) || show_Usage
                Protected_Ref="$2"; Protected_Set=true; shift 2 ;;
            -q|--quiet)
                Quiet=true; shift ;;
            -h|--help)
                show_Usage ;;
            *)
                print -u2 "Error: Unknown argument '$1'"
                show_Usage ;;
        esac
    done

    command -v ssh-keygen >/dev/null || {
        print -u2 "Error: ssh-keygen not found"
        return $Exit_Status_IO
    }
    if [[ "$Protected_Set" == false ]]; then
        Protected_Ref=""
        for Protected_Ref in origin/main main ""; do
            [[ -z "$Protected_Ref" ]] && break
            git rev-parse --verify -q "$Protected_Ref^{commit}" >/dev/null && break
        done
    fi
    core_Logic "$Revision" "$Quiet" "$Protected_Ref"
}

main "$@"
