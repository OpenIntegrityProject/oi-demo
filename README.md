# oi-demo

A demonstration of an [Open Integrity](https://github.com/OpenIntegrityProject/core) repository: every commit since the inception commit is SSH-signed, and who may sign what is recorded in the repository itself.

- **Humans** sign with Secure Enclave keys (Touch ID). Only they may sign commits on `main`, tags, and changes to `.repo/config/verification/`.
- **Claude Code**, running locally or on the web, signs with its own keys and works on `claude/*` branches.
- **CI** checks every commit and tag against these rules: `.repo/scripts/verify_commit_signatures.sh`.

Verify it yourself:

```sh
git clone https://github.com/OpenIntegrityProject/oi-demo && cd oi-demo
zsh .repo/scripts/verify_commit_signatures.sh
```

## GitHub's Verified badge

GitHub marks a commit Verified only when it can match the signing key to the GitHub account that owns the committer's email address. That is a check on GitHub accounts, not on this repository's rules, and the two can disagree: commits signed with the local Claude Code key (`@claude-local/chryseikori`) show as Unverified on GitHub, although that key is an allowed commit signer here. Whether a commit is valid in this repository is decided by `verify_commit_signatures.sh` against the signers in `.repo/config/verification/`, which CI runs on every push and pull request.
