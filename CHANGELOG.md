# Changelog

All notable changes to this crate are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the crate
adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.1.0] - 2026-08-16

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

[Unreleased]: https://github.com/ekayana-labs/did-bio-core/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/ekayana-labs/did-bio-core/releases/tag/v0.1.0
