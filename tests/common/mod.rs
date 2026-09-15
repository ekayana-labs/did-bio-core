//! Shared fixtures: the spec's example DID and a Borsh writer for building
//! registry account images.
#![allow(dead_code)]

use did_bio_core::account::{vm_flags, ACCOUNT_DISCRIMINATOR, DEFAULT_FRAGMENT, PROGRAM_ID};
use did_bio_core::document::ML_DSA_87_PUBLIC_KEY_LEN;
use did_bio_core::{BioDid, RawAccount};

/// Spec Section 4.2 / Section 5.6 example DID (devnet).
pub const EXAMPLE_DID: &str = "did:bio:devnet:2T6zLFvMx7NJac5qQtiKTaPhMwHLkwKETWjUK1yKv4tc";
pub const EXAMPLE_IDSTRING: &str = "2T6zLFvMx7NJac5qQtiKTaPhMwHLkwKETWjUK1yKv4tc";
/// Spec Section 5.6: the example subject's Multikey form.
pub const EXAMPLE_MULTIKEY: &str = "z6MkfuN2vWAoHermh6vY6TgAJfwhBWZCApZb9XeQ9HwLqHfz";

pub fn example_did() -> BioDid {
    BioDid::parse(EXAMPLE_DID).unwrap()
}

/// Borsh writer mirroring the on chain layout, for building test images.
#[derive(Default)]
pub struct AccountImage {
    pub bytes: Vec<u8>,
}

impl AccountImage {
    pub fn new() -> Self {
        AccountImage {
            bytes: ACCOUNT_DISCRIMINATOR.to_vec(),
        }
    }

    pub fn u8(mut self, v: u8) -> Self {
        self.bytes.push(v);
        self
    }
    pub fn u16(mut self, v: u16) -> Self {
        self.bytes.extend_from_slice(&v.to_le_bytes());
        self
    }
    pub fn u32(mut self, v: u32) -> Self {
        self.bytes.extend_from_slice(&v.to_le_bytes());
        self
    }
    pub fn u64(mut self, v: u64) -> Self {
        self.bytes.extend_from_slice(&v.to_le_bytes());
        self
    }
    pub fn i64(self, v: i64) -> Self {
        self.u64(v as u64)
    }
    pub fn raw(mut self, v: &[u8]) -> Self {
        self.bytes.extend_from_slice(v);
        self
    }
    pub fn string(self, v: &str) -> Self {
        self.u32(v.len() as u32).raw(v.as_bytes())
    }
    pub fn byte_vec(self, v: &[u8]) -> Self {
        self.u32(v.len() as u32).raw(v)
    }
}

/// A full account image: subject with two controllers, all four key
/// types, and one service. updated_at = 2025-07-23T00:00:00Z.
pub fn rich_account_image(subject: &[u8; 32]) -> Vec<u8> {
    let other_key = [9u8; 32];
    AccountImage::new()
        .u64(7) // version
        .u8(254) // bump
        .raw(subject)
        .u8(0) // deactivated = false
        .i64(1_753_228_800) // updated_at
        // native_controllers: [other_key]
        .u32(1)
        .raw(&other_key)
        // other_controllers: ["did:key:z6MkExample"]
        .u32(1)
        .string("did:key:z6MkExample")
        // verification_methods: 4 entries
        .u32(4)
        .string(DEFAULT_FRAGMENT) // ed25519, all rels + protected
        .u8(0)
        .u16(vm_flags::DEFAULT)
        .byte_vec(subject)
        .string("agreement") // x25519, keyAgreement only
        .u8(1)
        .u16(vm_flags::KEY_AGREEMENT)
        .byte_vec(&[2u8; 32])
        .string("evm") // secp256k1, assertion
        .u8(2)
        .u16(vm_flags::ASSERTION)
        .byte_vec(&[3u8; 33])
        .string("pq") // ML-DSA-87, assertion
        .u8(3)
        .u16(vm_flags::ASSERTION)
        .byte_vec(&[4u8; ML_DSA_87_PUBLIC_KEY_LEN])
        // services: 1 entry
        .u32(1)
        .string("metadata")
        .string("BioMetadata")
        .string("ipfs://bafybeigdyrexampleexampleexampleexampleexample")
        .bytes
}

/// Pinned across the registry program and the backend: the owned subject
/// of authority `[0x11; 32]` and nonce 42.
pub const OWNED_AUTHORITY: [u8; 32] = [0x11; 32];
pub const OWNED_NONCE: u64 = 42;
pub const OWNED_SUBJECT: [u8; 32] = [
    176, 5, 37, 51, 53, 114, 109, 56, 180, 140, 48, 89, 115, 119, 13, 138, 192, 54, 110, 20, 205,
    247, 212, 197, 39, 52, 9, 159, 203, 10, 250, 28,
];

/// The image `initialize_owned` writes: version 1, the authority's key as
/// the protected default method, nothing else.
pub fn owned_account_image(subject: &[u8; 32], authority: &[u8; 32]) -> Vec<u8> {
    AccountImage::new()
        .u64(1)
        .u8(255)
        .raw(subject)
        .u8(0)
        .i64(1_753_228_800)
        .u32(0)
        .u32(0)
        .u32(1)
        .string(DEFAULT_FRAGMENT)
        .u8(0)
        .u16(vm_flags::DEFAULT)
        .byte_vec(authority)
        .u32(0)
        .bytes
}

pub fn registry_account(data: Vec<u8>) -> RawAccount {
    RawAccount {
        owner: PROGRAM_ID,
        data,
    }
}
