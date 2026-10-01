# Changelog

All notable changes to this crate are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the crate
adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Changed

- Decoding refuses account states the registry never writes, such as
  trailing bytes, invalid fragments or unknown flag bits.

### Fixed

- Decoding caps each vector at the registry's limit before allocating.

## [0.1.2] - 2026-09-16

### Added

- Owned subjects are supported. `BioDid::is_key_subject` tells an Ed25519
  key subject from a program derived one, and `is_on_curve` is exported.
  With the `pda` feature, `find_owned_subject` and `BioDid::owned` derive
  the subject that the registry's `initialize_owned(nonce)` creates for an
  authority, using the `OWNED_SUBJECT_SEED` constant.
- `resolution_error::NOT_FOUND` reports an owned subject with no registry
  account.

### Changed

- `resolve_from_account` and `resolve_str` resolve an owned subject
  without an account to a `notFound` error instead of a generative
  document, and `generative_document` now returns `Option<DidDocument>`,
  which is `None` for owned subjects.
- `curve25519-dalek` is a required dependency, because the curve check is
  part of the resolution algorithm as well as of PDA derivation.

## [0.1.1] - 2026-09-09

### Added

- `KeyBufferState` decodes the registry's `KeyBuffer` staging account,
  through which keys larger than one transaction, such as ML-DSA-87 keys,
  are uploaded in chunks. It comes with the `KEY_BUFFER_SEED`,
  `KEY_BUFFER_DISCRIMINATOR` and `KEY_BUFFER_HEADER_LEN` constants.
- `find_key_buffer_address`, under the `pda` feature, gives the staging
  account address for an authority uploading a large key into a DID
  account.

## [0.1.0] - 2026-09-05

### Added

- `did:bio` identifier and DID URL parsing per the method ABNF, with
  network segments for devnet, testnet, and localnet.
- Multikey encoding and decoding for Ed25519, X25519, and secp256k1 keys.
- The DID document data model, including the ML-DSA-87 `JsonWebKey`
  verification method type.
- A dependency free decoder for the registry's `DidAccount` layout.
- The resolution algorithm as a pure function, with the generative
  fallback, plus sync and async `RegistryReader` drivers.
- PDA derivation without a Solana SDK dependency (`pda` feature).
- Ed25519 and ML-DSA-87 signature verification (`verify` and `fips`
  features).

[Unreleased]: https://github.com/ekayana-labs/did-bio-core/compare/v0.1.2...HEAD
[0.1.2]: https://github.com/ekayana-labs/did-bio-core/releases/tag/v0.1.2
[0.1.1]: https://github.com/ekayana-labs/did-bio-core/releases/tag/v0.1.1
[0.1.0]: https://github.com/ekayana-labs/did-bio-core/releases/tag/v0.1.0
