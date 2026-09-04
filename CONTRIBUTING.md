# Contributing

## Development

```console
cargo test
cargo test --no-default-features
cargo test --features verify
cargo fmt --all --check
cargo clippy --all-targets -- -D warnings
```

The `fips` feature links the FIPS validated AWS-LC module and needs CMake
and Go; CI does not build it.

## Rules of the road

- **The spec is normative.** Behavior follows the
  [did:bio method specification](https://github.com/ekayana-labs/did-bio-spec).
  A change that alters what a DID resolves to needs a spec change first,
  and a golden vector in `tests/`.
- **Constants mirror the registry program.** `account.rs` pins the program
  ID, seeds, discriminator, and caps. The program is the source of truth;
  do not edit them here without the matching program change.
- **Untrusted input never panics.** Identifiers, account bytes, keys, and
  signatures all come from the network. Return `Error`, and add the hostile
  case to the tests.
- **Keep the dependency tree small.** Default features are pure Rust. New
  dependencies need a reason in the PR description.
- **No `unsafe`, every public item documented.** The crate enforces both.

## Commit messages

Short, capitalized, imperative subject with no trailing period:
`Add Multikey decoding`, `Reject fragments over 32 characters`. Use a
`ci:`, `docs:`, `deps:`, or `chore:` prefix only for mechanical changes.
Explain why in the body when the diff does not make it obvious.
