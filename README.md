# did-bio-core

[![CI](https://github.com/ekayana-labs/did-bio-core/actions/workflows/main.yml/badge.svg)](https://github.com/ekayana-labs/did-bio-core/actions/workflows/main.yml)
[![crates.io](https://img.shields.io/crates/v/did-bio-core.svg)](https://crates.io/crates/did-bio-core)
[![docs.rs](https://img.shields.io/docsrs/did-bio-core)](https://docs.rs/did-bio-core)
[![MSRV](https://img.shields.io/crates/msrv/did-bio-core)](Cargo.toml)
[![license](https://img.shields.io/crates/l/did-bio-core)](LICENSE)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/ekayana-labs/did-bio-core/badge)](https://scorecard.dev/viewer/?uri=github.com/ekayana-labs/did-bio-core)

Data model and resolution for the `did:bio` DID method, a
[W3C DID 1.0](https://www.w3.org/TR/did-1.0/) conformant method for
biological research data, anchored on the Solana blockchain by the
[`bio-did-registry`](https://github.com/ekayana-labs/bio-did-registry)
program.

This crate is the transport free core shared by resolvers, backends, and
tooling. It implements the
[did:bio method specification](https://github.com/ekayana-labs/bio-did-spec)
directly, with golden tests against the spec's own vectors.

## What's inside

| Module | Spec | Contents |
|---|---|---|
| `did` | Section 4 | `BioDid` / `DidUrl` parsing and validation (ABNF, base58btc, network segments), key vs owned subjects |
| `multikey` | Section 5.2 | Multikey encode/decode (Ed25519 `z6Mk...`, X25519 `z6LS...`, secp256k1 `zQ3s...`) |
| `document` | Section 5 | `DidDocument`, verification methods, services, resolution metadata |
| `account` | Section 5-6 | Registry constants and a dependency free deserializer for the on chain `DidAccount` |
| `resolve` | Section 6.2 | The resolution algorithm as a pure function, generative fallback included, sync and async `RegistryReader` drivers, and DID URL dereferencing |
| `pda` | Section 4.2, 6.2(4) | `find_program_address`, DID account, key buffer and owned subject derivation without a Solana SDK dependency, behind the default `pda` feature |
| `verify` | Section 5.2 | Ed25519, ES256K (secp256k1) and ML-DSA-87 (FIPS 204) signature verification via aws-lc-rs, behind the `verify` and `fips` features |

The post quantum ML-DSA-87 verification method type is supported end to
end, from the on chain type tag and the JWK mapping to key length
validation and signature verification. It is a `JsonWebKey` with
`kty "AKP"` and `alg "ML-DSA-87"`, per draft-ietf-cose-dilithium.

## Example

A subject is either an Ed25519 key or an owned subject, a program derived
address bound to the wallet that created it (`BioDid::owned`,
`find_owned_subject`). Every key subject resolves. Without on chain state,
resolution yields the deterministic generative document, while an owned
subject without an account resolves to `notFound`.

```rust
use did_bio_core::{resolve_from_account, BioDid};

let did: BioDid = "did:bio:devnet:2T6zLFvMx7NJac5qQtiKTaPhMwHLkwKETWjUK1yKv4tc"
    .parse()?;

// Step 6 falls back to the generative document when no registry account
// exists.
let resolution = resolve_from_account(&did, None);
let document = resolution.document.unwrap();
assert_eq!(document.id, did.to_string());
assert!(did.is_key_subject());
# Ok::<(), did_bio_core::Error>(())
```

Resolution against a live cluster plugs any account fetcher into the
`RegistryReader` or `AsyncRegistryReader` trait, or into
`LocalAsyncRegistryReader` when its futures are not `Send`. The crate derives the PDA
and applies steps 6-9, which cover the ownership and discriminator checks,
deactivation and materialization. A fetcher must report a transport failure
as an error and never as a missing account. Spec Section 7 describes the
withholding attack this prevents.

## Features

| Feature | Default | Adds |
|---|---|---|
| `pda` | yes | PDA derivation (`sha2`) and the resolution drivers |
| `verify` | no | Ed25519, ES256K and ML-DSA-87 signature verification via `aws-lc-rs` |
| `fips` | no | `verify`, linked against the FIPS validated AWS-LC module, whose build needs CMake and Go |

With default features the dependency tree is pure Rust. It holds `serde`,
`bs58`, `base64`, `sha2` and `curve25519-dalek`.

## Consumers

- [`bio-did-resolver`](https://github.com/ekayana-labs/bio-did-resolver) is
  the reference CLI resolver.
- `bio-did-seq` is the Ekayaan research data backend.

## License

MIT
