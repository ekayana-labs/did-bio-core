//! Data model and resolution for the **`did:bio`** DID method - a W3C
//! DID 1.0 conformant method for biological research data, anchored on
//! the Solana blockchain by the `bio-did-registry` program.
//!
//! This crate is the transport free core shared by resolvers, backends,
//! and tooling:
//!
//! - [`BioDid`] / [`DidUrl`] - identifier parsing and validation against
//!   the method ABNF (spec Section 4).
//! - [`multikey`] - Multikey encoding/decoding (Controlled Identifiers
//!   v1.0) for Ed25519, X25519, and secp256k1 keys.
//! - [`DidDocument`] and friends - the DID document data model (spec Section 5),
//!   including the post quantum **ML-DSA-87** (FIPS 204) verification
//!   method type (`JsonWebKey` / `AKP`).
//! - [`DidAccountState`] - a dependency free deserializer for the
//!   registry's on chain account format.
//! - [`KeyBufferState`] - the staging account through which keys larger
//!   than one transaction (ML-DSA-87) are uploaded in chunks.
//! - [`resolve_from_account`] - steps 6-9 of the resolution algorithm
//!   (spec Section 6.2) as a pure function, with the generative fallback;
//!   [`resolve_with`] / [`resolve_with_async`] drive it through a
//!   pluggable [`RegistryReader`].
//! - [`find_did_account_address`], [`find_key_buffer_address`] and
//!   [`find_owned_subject`] (feature `pda`) - PDA derivation without a
//!   Solana SDK dependency.
//!
//! # Resolution without a network
//!
//! A subject is either an Ed25519 key or an *owned* subject, a program
//! derived address that `initialize_owned` binds to the wallet that signed
//! for it ([`BioDid::is_key_subject`] tells them apart). Every key subject
//! resolves; absent on chain state yields the deterministic *generative*
//! document containing the key itself, while an owned subject without an
//! account resolves to `notFound`:
//!
//! ```
//! use did_bio_core::{resolve_from_account, BioDid};
//!
//! let did: BioDid = "did:bio:devnet:2T6zLFvMx7NJac5qQtiKTaPhMwHLkwKETWjUK1yKv4tc"
//!     .parse()
//!     .unwrap();
//!
//! // No registry account fetched -> generative document, versionId "0".
//! let resolution = resolve_from_account(&did, None);
//! let document = resolution.document.unwrap();
//! assert_eq!(document.id, did.to_string());
//! assert_eq!(
//!     document.verification_method[0].id,
//!     did.default_verification_method_id(),
//! );
//! assert_eq!(resolution.document_metadata.version_id.as_deref(), Some("0"));
//! ```
//!
//! # Features
//!
//! - `pda` *(default)* - PDA derivation ([`find_did_account_address`])
//!   and the [`resolve_with`] / [`resolve_with_async`] drivers. Pure
//!   Rust (`sha2`, `curve25519-dalek`).
//! - `verify` - signature verification for Ed25519 and ML-DSA-87
//!   verification methods via `aws-lc-rs`.
//! - `fips` - like `verify`, but binds the FIPS validated AWS-LC
//!   module.
//!
//! Spec: *The `did:bio` DID Method Specification v1.0*
//! (<https://github.com/ekayana-labs/did-bio-spec>). Section references
//! throughout this crate point there.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod account;
pub mod datetime;
pub mod did;
pub mod document;
pub mod error;
pub mod multikey;
#[cfg(feature = "pda")]
pub mod pda;
pub mod resolve;
#[cfg(feature = "verify")]
pub mod verify;

pub use account::{
    DidAccountState, KeyBufferState, KeyType, StoredService, StoredVerificationMethod,
};
pub use did::is_on_curve;
pub use did::{BioDid, DidUrl, Network};
pub use document::{
    AkpPublicJwk, DidDocument, DidDocumentMetadata, DidResolution, DidResolutionMetadata,
    ServiceMap, VerificationMaterial, VerificationMethodMap, VerificationRelationship,
};
pub use error::{resolution_error, Error};
#[cfg(feature = "pda")]
pub use pda::{
    find_did_account_address, find_key_buffer_address, find_owned_subject, find_program_address,
};
pub use resolve::{
    deactivated_document, generative_document, materialize_document, resolve_from_account,
    resolve_str, AsyncRegistryReader, RawAccount, RegistryReader,
};
#[cfg(feature = "pda")]
pub use resolve::{resolve_with, resolve_with_async};
