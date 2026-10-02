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
