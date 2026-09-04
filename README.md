# did-bio-core

Data model and resolution for the **`did:bio`** DID method - a
[W3C DID 1.0](https://www.w3.org/TR/did-1.0/) conformant method for
biological research data, anchored on the Solana blockchain by the
[`bio-did-registry`](https://github.com/ekayana-labs/bio-did-registry)
program.

This crate is the transport free core shared by resolvers, backends, and
tooling. It implements the
[did:bio method specification](https://github.com/ekayana-labs/did-bio-spec)
directly, with golden tests against the spec's own vectors.

## What's inside

| Module | Spec | Contents |
|---|---|---|
| `did` | Section 4 | `BioDid` / `DidUrl` parsing and validation (ABNF, base58btc, network segments) |
| `multikey` | Section 5.2 | Multikey encode/decode (Ed25519 `z6Mk...`, X25519 `z6LS...`, secp256k1 `zQ3s...`) |
| `document` | Section 5 | `DidDocument`, verification methods, services, resolution metadata |
| `account` | Section 5-6 | Registry constants and a dependency free deserializer for the on chain `DidAccount` |
| `resolve` | Section 6.2 | The resolution algorithm as a pure function, generative fallback included, plus sync/async `RegistryReader` drivers |
| `pda` | Section 6.2(4) | `find_program_address` without a Solana SDK dependency *(feature `pda`, default)* |
| `verify` | Section 5.2 | Ed25519 + **ML-DSA-87 (FIPS 204)** signature verification via aws-lc-rs *(features `verify` / `fips`)* |

The post quantum **ML-DSA-87** verification method type (`JsonWebKey`,
`kty "AKP"`, `alg "ML-DSA-87"` per draft-ietf-cose-dilithium) is
supported end to end: on chain type tag, JWK mapping, key length
validation, and signature verification.

## Example

Every syntactically valid `did:bio` DID resolves. Without on chain state,
resolution yields the deterministic *generative* document:

```rust
use did_bio_core::{resolve_from_account, BioDid};

let did: BioDid = "did:bio:devnet:2T6zLFvMx7NJac5qQtiKTaPhMwHLkwKETWjUK1yKv4tc"
    .parse()?;

// Step 6 fallback: no registry account -> generative document.
let resolution = resolve_from_account(&did, None);
let document = resolution.document.unwrap();
assert_eq!(document.id, did.to_string());
# Ok::<(), did_bio_core::Error>(())
```

Resolution against a live cluster plugs any account fetcher into the
`RegistryReader` / `AsyncRegistryReader` traits; the crate derives the PDA
and applies steps 6-9 (ownership + discriminator checks, deactivation,
materialization). A fetcher **must** report transport failures as errors,
never as "account missing" - see the withholding attack in spec Section 7.

## Features

| Feature | Default | Adds |
|---|---|---|
| `pda` | yes | PDA derivation (`sha2`, `curve25519-dalek`) and the resolution drivers |
| `verify` | - | Ed25519 + ML-DSA-87 signature verification via `aws-lc-rs` |
| `fips` | - | `verify`, linked against the FIPS validated AWS-LC module (build needs CMake + Go) |

With default features the dependency tree is pure Rust: `serde`,
`serde_json`, `bs58`, `base64`, `sha2`, `curve25519-dalek`.

## Consumers

- `bio-did-registry/clients/resolver` - the reference CLI resolver.
- `bio-did-seq` - the Ekayaan research data backend.

## License

MIT
