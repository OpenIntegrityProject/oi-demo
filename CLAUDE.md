# CLAUDE.md

This is an Open Integrity repository. Every commit must be SSH-signed by a key listed in `.repo/config/verification/`.

- Work only on `claude/*` branches. Never push to `main` or `staging/*`.
- Never edit files in `.repo/config/verification/`; the verifier rejects agent changes to them.
- Before pushing, run `zsh .repo/scripts/verify_commit_signatures.sh --protected origin/main` and `zsh .repo/scripts/tests/TEST-verify_commit_signatures.sh`.
- A human merges with `.repo/scripts/merge_pr.sh <number>`, signing the merge with a Secure Enclave key.

## Why `.claude/settings.json` denies push, merge, and admin commands

Local Claude Code sessions run with the human's own GitHub credentials, which have admin rights on this repo, so a mistaken `git push`, `gh api`, or ruleset edit would succeed with full authority. The deny rules keep agents off `main`, `staging/*`, force pushes, repo settings, and merging. Merging stays the human's step: `merge_pr.sh`, signed with a Touch ID–gated Secure Enclave key.
