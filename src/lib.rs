//! Data model and resolution for the `did:bio` DID method, a W3C DID 1.0
//! conformant method for biological research data, anchored on the Solana
//! blockchain by the `bio-did-registry` program.
//!
//! This crate is the transport free core shared by resolvers, backends,
//! and tooling. It provides the pieces below.
//!
//! - [`BioDid`] and [`DidUrl`] parse identifiers and validate them against
//!   the method ABNF (spec Section 4).
//! - [`multikey`] encodes and decodes Multikey values (Controlled
//!   Identifiers v1.0) for Ed25519, X25519, and secp256k1 keys.
//! - [`DidDocument`] and its related types are the DID document data model
//!   (spec Section 5). It includes the post quantum ML-DSA-87 (FIPS 204)
//!   verification method type, a `JsonWebKey` with the `AKP` key type.
//! - [`DidAccountState`] is a dependency free deserializer for the
//!   registry's on chain account format.
//! - [`KeyBufferState`] decodes the staging account through which keys
//!   larger than one transaction, such as ML-DSA-87 keys, are uploaded in
//!   chunks.
//! - [`resolve_from_account`] runs steps 6-9 of the resolution algorithm
//!   (spec Section 6.2) as a pure function, with the generative fallback.
//!   [`resolve_with`], [`resolve_with_async`] and
//!   [`resolve_with_async_local`] drive it through a pluggable
//!   [`RegistryReader`], and [`dereference`] finds what a DID URL names.
//! - [`Quorum`] reads through several readers and accepts an account only
//!   when a majority agree, against an RPC node that withholds one.
//! - [`find_did_account_address`], [`find_key_buffer_address`] and
//!   [`find_owned_subject`] derive PDAs without a Solana SDK dependency,
//!   under the `pda` feature.
//!
//! # Resolution without a network
//!
//! A subject is either an Ed25519 key or an owned subject, a program
//! derived address that `initialize_owned` binds to the wallet that signed
//! for it. [`BioDid::is_key_subject`] tells them apart. Every key subject
//! resolves. Without on chain state it yields the deterministic generative
//! document containing the key itself, while an owned subject without an
//! account resolves to `notFound`.
//!
//! ```
//! use did_bio_core::{resolve_from_account, BioDid};
//!
//! let did: BioDid = "did:bio:devnet:2T6zLFvMx7NJac5qQtiKTaPhMwHLkwKETWjUK1yKv4tc"
//!     .parse()
//!     .unwrap();
//!
//! // Without a registry account the result is the generative document
//! // with versionId "0".
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
//! - `pda` is on by default. It adds PDA derivation
//!   ([`find_did_account_address`]) and the [`resolve_with`] and
//!   [`resolve_with_async`] drivers, in pure Rust with `sha2`.
//! - `verify` adds signature verification for Ed25519, ES256K and ML-DSA-87
//!   verification methods via `aws-lc-rs`.
//! - `fips` is like `verify`, but binds the FIPS validated AWS-LC module.
//!
//! The spec is the `did:bio` DID Method Specification v1.2
//! (<https://github.com/ekayana-labs/bio-did-spec>). Section references
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
pub mod quorum;
pub mod resolve;
#[cfg(feature = "verify")]
pub mod verify;

pub use account::{
    DidAccountState, KeyBufferState, KeyType, StoredService, StoredVerificationMethod,
};
pub use did::is_on_curve;
pub use did::{BioDid, DidUrl, Network};
pub use document::{
    AkpPublicJwk, Dereferenced, DidDocument, DidDocumentMetadata, DidResolution,
    DidResolutionMetadata, ServiceMap, VerificationMaterial, VerificationMethodMap,
    VerificationRelationship,
};
pub use error::{resolution_error, Error};
#[cfg(feature = "pda")]
pub use pda::{
    find_did_account_address, find_key_buffer_address, find_owned_subject, find_program_address,
    try_find_program_address,
};
pub use quorum::{Quorum, QuorumError};
pub use resolve::{
    deactivated_document, dereference, generative_document, materialize_document,
    resolve_from_account, resolve_str, AsyncRegistryReader, LocalAsyncRegistryReader, RawAccount,
    RegistryReader,
};
#[cfg(feature = "pda")]
pub use resolve::{resolve_with, resolve_with_async, resolve_with_async_local};
