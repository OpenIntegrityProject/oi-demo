# AGENTS.md

This is an Open Integrity repository. Every commit must be SSH-signed by a key listed in `.repo/config/verification/`.

- Sign every commit with your own key (`git commit -S`). Your key may sign commits on your branch or fork; it may not sign `main` or tags.
- Never edit files in `.repo/config/verification/`. The verifier rejects any change to them that is not signed by a key in `allowed_main_signers`, so an agent cannot authorize itself.
- Before pushing, run `npm test` and `zsh .repo/scripts/verify_commit_signatures.sh --protected main`.
- A human reviews your work and merges it into `main` with a commit signed by a Secure Enclave key.
