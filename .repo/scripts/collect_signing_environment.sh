#!/usr/bin/env zsh
########################################################################
## Script:        collect_signing_environment.sh
## Version:       0.1.00 (2026-10-02)
## Origin:        https://github.com/OpenIntegrityProject/openintegrityproject-dev/blob/main/.repo/scripts/collect_signing_environment.sh
## Description:   Collects public information about this device's SSH
##                signing setup (OS, OpenSSH, Secure Enclave support,
##                public keys, Git signing config, GitHub signing keys)
##                into a Markdown report, to plan Open Integrity key
##                setup. Never reads private key material.
## License:       BSD-2-Clause-Patent (https://spdx.org/licenses/BSD-2-Clause-Patent.html)
## Copyright:     (c) 2026 Blockchain Commons LLC (https://www.BlockchainCommons.com)
## Attribution:   Christopher Allen <ChristopherA@LifeWithAlacrity.com>
## Usage:         collect_signing_environment.sh [-o|--output <file>]
##                    [-u|--github-user <user>] [-s|--sign-test]
## Examples:      collect_signing_environment.sh
##                collect_signing_environment.sh --sign-test
##                collect_signing_environment.sh -u ChristopherA -o /tmp/report.md
########################################################################

# Reset the shell environment to a known state
emulate -LR zsh

# Safe shell scripting options
setopt errexit nounset pipefail localoptions warncreateglobal

# Script-scoped exit status codes
typeset -r Exit_Status_Success=0            # Successful execution
typeset -r Exit_Status_General=1            # General error (unspecified)
typeset -r Exit_Status_Usage=2              # Invalid usage or arguments
typeset -r Exit_Status_IO=3                 # Input/output error

# Namespace for the optional test signature. Deliberately not "git", so
# the test signature can never be replayed as a commit signature.
typeset -r Test_Sign_Namespace="oi-signing-environment-test"

# Script name for messages ($0 becomes the function name inside functions)
typeset -r Script_Name="${0:t}"

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
    print -u2 "Usage: $Script_Name [-o|--output <file>] [-u|--github-user <user>] [-s|--sign-test]
Options:
  -o, --output <file>       Report path (default:
                            .repo/reports/signing-environment-<host>.md)
  -u, --github-user <user>  GitHub user whose public signing keys to list
                            (default: git config github.user, else ChristopherA)
  -s, --sign-test           Make one test signature with the configured
                            Git signing key (may prompt for Touch ID),
                            namespace \"$Test_Sign_Namespace\"
Examples:
  $Script_Name
  $Script_Name --sign-test"
    exit $Exit_Status_Usage
}

#----------------------------------------------------------------------#
# Function: emit_Command
#----------------------------------------------------------------------#
# Description:
#   Runs a command and prints it with its combined output as a fenced
#   Markdown block. A failing command is reported, never fatal.
# Parameters:
#   $@ - Command and arguments
# Returns:
#   Exit_Status_Success always
#----------------------------------------------------------------------#
emit_Command() {
    typeset Output
    typeset -i Status=0
    Output=$("$@" 2>&1) || Status=$?
    print -- '```'
    print -- "\$ ${(j: :)${(q-)@}}"
    [[ -n "$Output" ]] && print -- "$Output"
    (( Status == 0 )) || print -- "[exit status $Status]"
    print -- '```'
    print
    return $Exit_Status_Success
}

#----------------------------------------------------------------------#
# Function: emit_Key_Fingerprints
#----------------------------------------------------------------------#
# Description:
#   Prints a fingerprint line for each public key read from stdin
#   (one OpenSSH public key per line), via ssh-keygen -lf -
# Parameters:
#   stdin - OpenSSH public keys, one per line
# Returns:
#   Exit_Status_Success always
#----------------------------------------------------------------------#
emit_Key_Fingerprints() {
    typeset Line
    while IFS= read -r Line; do
        [[ -z "$Line" || "$Line" == \#* ]] && continue
        print -r -- "$Line" | ssh-keygen -lf - 2>&1 || print -- "[unparseable key line]"
    done
    return $Exit_Status_Success
}

#----------------------------------------------------------------------#
# Function: section_System
#----------------------------------------------------------------------#
# Description:
#   Reports OS, hardware, and tool versions
# Parameters:
#   None
# Returns:
#   Exit_Status_Success always
#----------------------------------------------------------------------#
section_System() {
    print "## System"
    print
    if [[ "$OSTYPE" == darwin* ]]; then
        emit_Command sw_vers
        emit_Command sysctl -n hw.model machdep.cpu.brand_string
    else
        emit_Command uname -a
    fi
    emit_Command ssh -V
    emit_Command git --version
    emit_Command zsh --version
    print -r -- "- ssh-keygen: \`$(command -v ssh-keygen || print 'not found')\`"
    print -r -- "- SSH_AUTH_SOCK: \`${SSH_AUTH_SOCK:-unset}\`"
    print -r -- "- SSH_SK_PROVIDER: \`${SSH_SK_PROVIDER:-unset}\`"
    print
    return $Exit_Status_Success
}

#----------------------------------------------------------------------#
# Function: section_Secure_Enclave
#----------------------------------------------------------------------#
# Description:
#   Reports which Secure Enclave signing routes appear available:
#   Apple's built-in OpenSSH security-key provider, CryptoTokenKit
#   identities (sc_auth), and the Secretive app
# Parameters:
#   None
# Returns:
#   Exit_Status_Success always
#----------------------------------------------------------------------#
section_Secure_Enclave() {
    print "## Secure Enclave support"
    print
    if [[ "$OSTYPE" != darwin* ]]; then
        print "Not macOS; skipped."
        print
        return $Exit_Status_Success
    fi

    typeset Path_Name
    for Path_Name in /usr/lib/ssh-keychain.dylib /Applications/Secretive.app \
        "$HOME/Library/Containers/com.maxgoedjen.Secretive.SecretAgent/Data/socket.ssh"; do
        if [[ -e "$Path_Name" ]]; then
            print -r -- "- present: \`$Path_Name\`"
        else
            print -r -- "- absent: \`$Path_Name\`"
        fi
    done
    print

    if command -v sc_auth >/dev/null 2>&1; then
        print "sc_auth subcommands mentioning ctk-identity (built-in SE key support):"
        print
        typeset Sc_Auth_Help Ctk_Lines
        Sc_Auth_Help=$(sc_auth 2>&1) || true
        Ctk_Lines=$(print -r -- "$Sc_Auth_Help" | grep -i 'ctk-identity') || Ctk_Lines="(none listed)"
        print '```'
        print -r -- "$Ctk_Lines"
        print '```'
        print
        emit_Command sc_auth list-ctk-identities
    else
        print "sc_auth not found."
        print
    fi
    return $Exit_Status_Success
}

#----------------------------------------------------------------------#
# Function: section_Public_Keys
#----------------------------------------------------------------------#
# Description:
#   Lists public keys in the SSH agent and *.pub files in ~/.ssh,
#   with full public key text so they can be matched against
#   allowed_signers entries. Private key files are never opened.
# Parameters:
#   None
# Returns:
#   Exit_Status_Success always
#----------------------------------------------------------------------#
section_Public_Keys() {
    typeset Agent_Keys Pub_File
    print "## Public keys on this device"
    print
    print "### SSH agent"
    print
    print '```'
    Agent_Keys=$(ssh-add -L 2>&1) || true
    print -r -- "$Agent_Keys"
    print
    print -r -- "$Agent_Keys" | { grep -E '^(ssh-|ecdsa-|sk-)' || true } | emit_Key_Fingerprints
    print '```'
    print
    print "### ~/.ssh/*.pub"
    print
    print '```'
    for Pub_File in "$HOME"/.ssh/*.pub(N); do
        print -r -- "# ${Pub_File/#$HOME/~}"
        print -r -- "$(<"$Pub_File")"
        emit_Key_Fingerprints < "$Pub_File"
        print
    done
    print '```'
    print
    return $Exit_Status_Success
}

#----------------------------------------------------------------------#
# Function: section_Git_Config
#----------------------------------------------------------------------#
# Description:
#   Reports signing-related Git configuration (global, and local when
#   run inside a repository) and the global allowed signers file
# Parameters:
#   None
# Returns:
#   Exit_Status_Success always
#----------------------------------------------------------------------#
section_Git_Config() {
    typeset Allowed_File
    print "## Git signing configuration"
    print
    print '```'
    git config --show-origin --get-regexp \
        '^(user\.(name|email|signingkey)|gpg\..*|commit\.gpgsign|tag\.gpgsign|tag\.forcesignannotated|github\.user)$' \
        2>&1 || print "(no matching settings)"
    print '```'
    print
    Allowed_File=$(git config --global --get gpg.ssh.allowedSignersFile 2>/dev/null) || true
    if [[ -n "$Allowed_File" ]]; then
        Allowed_File="${Allowed_File/#\~/$HOME}"
        print "### Global allowed signers file (\`${Allowed_File/#$HOME/~}\`)"
        print
        print '```'
        if [[ -r "$Allowed_File" ]]; then
            print -r -- "$(<"$Allowed_File")"
        else
            print "(not readable)"
        fi
        print '```'
        print
    fi
    return $Exit_Status_Success
}

#----------------------------------------------------------------------#
# Function: section_GitHub_Keys
#----------------------------------------------------------------------#
# Description:
#   Lists the public SSH signing and authentication keys registered on
#   a GitHub account, as fetched by fetch_GitHub_Keys
# Parameters:
#   $1 - GitHub username
#   $2 - Signing keys JSON (or fetch error text)
#   $3 - Authentication keys, one per line (or fetch error text)
# Returns:
#   Exit_Status_Success always
#----------------------------------------------------------------------#
section_GitHub_Keys() {
    typeset User="$1" Signing_Json="$2" Auth_Keys="$3"
    print "## GitHub signing keys for @$User"
    print
    print '```'
    print -r -- "$Signing_Json"
    print '```'
    print
    print "## GitHub authentication keys for @$User"
    print
    print '```'
    print -r -- "$Auth_Keys"
    print
    print -r -- "$Auth_Keys" | { grep -E '^(ssh-|ecdsa-|sk-)' || true } | emit_Key_Fingerprints
    print '```'
    print
    return $Exit_Status_Success
}

#----------------------------------------------------------------------#
# Function: classify_Key_Type
#----------------------------------------------------------------------#
# Description:
#   Describes where a key of the given type can live. A P-256 key is
#   only *possibly* in the Secure Enclave: the type alone cannot prove
#   hardware storage.
# Parameters:
#   $1 - OpenSSH key type
# Returns:
#   Prints a short description; Exit_Status_Success always
#----------------------------------------------------------------------#
classify_Key_Type() {
    case "$1" in
        ecdsa-sha2-nistp256)
            print "P-256: possibly Secure Enclave (e.g. Secretive), or software" ;;
        sk-ecdsa-sha2-nistp256@openssh.com)
            print "P-256 security key: Secure Enclave via ssh-keychain.dylib, or FIDO token" ;;
        sk-ssh-ed25519@openssh.com)
            print "Ed25519 FIDO token (not Secure Enclave)" ;;
        ssh-ed25519)
            print "Ed25519 software key (cannot be Secure Enclave)" ;;
        ssh-rsa)
            print "RSA software key (cannot be Secure Enclave)" ;;
        *)
            print "other: $1" ;;
    esac
    return $Exit_Status_Success
}

#----------------------------------------------------------------------#
# Function: section_Key_Summary
#----------------------------------------------------------------------#
# Description:
#   Cross-references every public key found locally, on GitHub, and in
#   allowed signers files, showing each key's type, likely storage, and
#   where it appears
# Parameters:
#   $1 - SSH agent public keys (ssh-add -L output)
#   $2 - Contents of ~/.ssh/*.pub
#   $3 - GitHub authentication keys
#   $4 - GitHub signing keys JSON
#   $5 - Repository allowed_commit_signers contents
#   $6 - Global allowed signers file contents
# Returns:
#   Exit_Status_Success always
#----------------------------------------------------------------------#
section_Key_Summary() {
    typeset -A Key_Sources
    typeset -a Labels Key_Order match mbegin mend
    typeset -i Index
    typeset Key Line Type Fingerprint Row Label
    typeset -r Key_Pattern='(ssh-ed25519|ssh-rsa|ecdsa-sha2-nistp(256|384|521)|sk-ecdsa-sha2-nistp256@openssh\.com|sk-ssh-ed25519@openssh\.com)[[:space:]]+(AAAA[A-Za-z0-9+/=]+)'
    Labels=(agent "~/.ssh" "GH auth" "GH sign" "repo signers" "global signers")

    for Index in {1..6}; do
        for Line in "${(@f)${(P)Index}}"; do
            [[ "$Line" =~ $Key_Pattern ]] || continue
            Key="$match[1] $match[3]"
            [[ -n "${Key_Sources[$Key]-}" ]] || Key_Order+=("$Key")
            [[ "${Key_Sources[$Key]-}" == *"|$Index|"* ]] || Key_Sources[$Key]+="|$Index|"
        done
    done

    print "## Key summary"
    print
    if (( ${#Key_Order} == 0 )); then
        print "No public keys found."
        print
        return $Exit_Status_Success
    fi
    print "| Fingerprint | Type | ${(j: | :)Labels} |"
    print "|---|---|${(j::)${(@)Labels/*/---|}}"
    for Key in "${Key_Order[@]}"; do
        Type="${Key%% *}"
        Fingerprint=$(print -r -- "$Key" | ssh-keygen -lf - 2>/dev/null | awk '{print $2}') || Fingerprint="?"
        Row="| \`$Fingerprint\` | $(classify_Key_Type "$Type") |"
        for Index in {1..6}; do
            if [[ "${Key_Sources[$Key]}" == *"|$Index|"* ]]; then
                Row+=" yes |"
            else
                Row+=" |"
            fi
        done
        print -r -- "$Row"
    done
    print
    return $Exit_Status_Success
}

#----------------------------------------------------------------------#
# Function: section_Sign_Test
#----------------------------------------------------------------------#
# Description:
#   Signs a fixed test message with the configured Git signing key and
#   includes the signature, so its key type and any security-key flags
#   (user presence / user verification) can be examined. Uses a
#   non-"git" namespace so the signature cannot pass as a commit
#   signature.
# Parameters:
#   None
# Returns:
#   Exit_Status_Success always
#----------------------------------------------------------------------#
section_Sign_Test() {
    typeset Signing_Key Key_File Work_Dir Message
    typeset -i Status=0
    print "## Test signature"
    print
    Signing_Key=$(git config --get user.signingkey 2>/dev/null) || true
    if [[ -z "$Signing_Key" ]]; then
        print "No user.signingkey configured; skipped."
        print
        return $Exit_Status_Success
    fi

    Work_Dir=$(mktemp -d)
    Message="Open Integrity signing environment test $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    print -r -- "$Message" > "$Work_Dir/message.txt"
    if [[ "$Signing_Key" == key::* ]]; then
        print -r -- "${Signing_Key#key::}" > "$Work_Dir/key.pub"
        Key_File="$Work_Dir/key.pub"
    else
        Key_File="${Signing_Key/#\~/$HOME}"
    fi

    print "Signing with \`${Key_File/#$HOME/~}\`, namespace \`$Test_Sign_Namespace\`."
    print "Touch ID or a passphrase prompt may appear now." >&2
    print
    print '```'
    print -r -- "$Message"
    ssh-keygen -Y sign -n "$Test_Sign_Namespace" -f "$Key_File" "$Work_Dir/message.txt" 2>&1 || Status=$?
    if (( Status == 0 )) && [[ -r "$Work_Dir/message.txt.sig" ]]; then
        print -r -- "$(<"$Work_Dir/message.txt.sig")"
    else
        print "[signing failed, exit status $Status]"
    fi
    print '```'
    print
    rm -rf -- "$Work_Dir"
    return $Exit_Status_Success
}

#----------------------------------------------------------------------#
# Function: core_Logic
#----------------------------------------------------------------------#
# Description:
#   Writes the full report to the output file
# Parameters:
#   $1 - Output file path
#   $2 - GitHub username
#   $3 - "true" to include the test signature
# Returns:
#   Exit_Status_Success on success
#   Exit_Status_IO if the report cannot be written
#----------------------------------------------------------------------#
core_Logic() {
    typeset Output_File="$1" GitHub_User="$2" Sign_Test="$3"
    typeset Agent_Keys="" Pub_Keys="" GitHub_Signing="" GitHub_Auth=""
    typeset Repo_Signers="" Global_Signers="" Signers_File Pub_File

    # Gather key sources once; every value here is public
    Agent_Keys=$(ssh-add -L 2>&1) || true
    for Pub_File in "$HOME"/.ssh/*.pub(N); do
        Pub_Keys+="$(<"$Pub_File")"$'\n'
    done
    GitHub_Signing=$(curl -fsS "https://api.github.com/users/$GitHub_User/ssh_signing_keys" 2>&1) || true
    GitHub_Auth=$(curl -fsS "https://github.com/$GitHub_User.keys" 2>&1) || true
    Signers_File="$(git rev-parse --show-toplevel 2>/dev/null)/.repo/config/verification/allowed_commit_signers" || true
    [[ -r "$Signers_File" ]] && Repo_Signers="$(<"$Signers_File")"
    Signers_File=$(git config --global --get gpg.ssh.allowedSignersFile 2>/dev/null) || true
    Signers_File="${Signers_File/#\~/$HOME}"
    [[ -n "$Signers_File" && -r "$Signers_File" ]] && Global_Signers="$(<"$Signers_File")"

    mkdir -p -- "${Output_File:h}" || return $Exit_Status_IO
    {
        print "# Signing environment: $(hostname -s)"
        print
        print "Generated $(date -u +%Y-%m-%dT%H:%M:%SZ) by \`collect_signing_environment.sh\`."
        print "Contains public information only. Review before committing."
        print
        section_Key_Summary "$Agent_Keys" "$Pub_Keys" "$GitHub_Auth" \
            "$GitHub_Signing" "$Repo_Signers" "$Global_Signers"
        section_System
        section_Secure_Enclave
        section_Public_Keys
        section_Git_Config
        section_GitHub_Keys "$GitHub_User" "$GitHub_Signing" "$GitHub_Auth"
        [[ "$Sign_Test" == true ]] && section_Sign_Test
        true
    } > "$Output_File" || return $Exit_Status_IO

    print -u2 "Wrote $Output_File"
    print -u2 "Review it, then commit and push it for analysis."
    return $Exit_Status_Success
}

#----------------------------------------------------------------------#
# Function: main
#----------------------------------------------------------------------#
# Description:
#   Parses arguments and runs the report
# Parameters:
#   $@ - Command line arguments
# Returns:
#   Exit status from core_Logic, or Exit_Status_Usage
#----------------------------------------------------------------------#
main() {
    typeset Output_File="" GitHub_User="" Sign_Test=false

    while (( $# > 0 )); do
        case "$1" in
            -o|--output)
                (( $# > 1 )) || show_Usage
                Output_File="$2"; shift 2 ;;
            -u|--github-user)
                (( $# > 1 )) || show_Usage
                GitHub_User="$2"; shift 2 ;;
            -s|--sign-test)
                Sign_Test=true; shift ;;
            -h|--help)
                show_Usage ;;
            *)
                print -u2 "Error: Unknown argument '$1'"
                show_Usage ;;
        esac
    done

    if [[ -z "$GitHub_User" ]]; then
        GitHub_User=$(git config --get github.user 2>/dev/null) || GitHub_User="ChristopherA"
    fi
    if [[ -z "$Output_File" ]]; then
        typeset Repo_Root
        Repo_Root=$(git rev-parse --show-toplevel 2>/dev/null) || Repo_Root="$PWD"
        Output_File="$Repo_Root/.repo/reports/signing-environment-$(hostname -s).md"
    fi

    core_Logic "$Output_File" "$GitHub_User" "$Sign_Test"
}

main "$@"
