# oi-demo

A small JavaScript library of text utilities, kept as an [Open Integrity](https://github.com/OpenIntegrityProject/core) repository. Every commit since the inception commit is SSH-signed, and who may sign what is recorded in the repository itself, in `.repo/config/verification/`.

- **Humans** sign with Secure Enclave keys that require Touch ID. Only their keys may sign commits on `main`, tags, and changes to the files that say who may sign.
- **Agents** sign with their own keys, listed in `allowed_commit_signers`. Their commits reach `main` only through a merge that a human signs.
- **CI** checks every commit and tag against these rules with `.repo/scripts/verify_commit_signatures.sh`.

## Verify it yourself

```sh
git clone https://github.com/OpenIntegrityProject/oi-demo && cd oi-demo
zsh .repo/scripts/verify_commit_signatures.sh --protected main
```

The verifier needs zsh, git and OpenSSH 8.9 or later (`ssh-keygen -Y verify`).

## The library

`src/text.js` exports `slugify`, `titleCase`, `wordCount` and `truncate`. Run the tests with Node 22 or later:

```sh
npm test
```

## Open tasks

- `slugify('Café au lait')` returns `caf-au-lait`: accented letters are dropped instead of folded to their base letter.
- `truncate('😀abc', 2)` cuts the emoji in half and returns a lone surrogate followed by the ellipsis.

## License

BSD-2-Clause-Patent; see `LICENSE.md`.
