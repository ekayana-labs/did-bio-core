//! Program derived address computation (spec Section 6.2 step 4), without a
//! Solana SDK dependency.
//!
//! `find_program_address` mirrors the Solana runtime's derivation: try
//! bump seeds from 255 downward, hashing
//! `seeds ||s [bump] || program_id || "ProgramDerivedAddress"` with SHA-256,
//! and return the first digest that is **not** a valid Ed25519 curve
//! point (PDAs must have no private key).

use sha2::{Digest, Sha256};

use crate::account::{DID_SEED, KEY_BUFFER_SEED, OWNED_SUBJECT_SEED, PROGRAM_ID};
use crate::did::is_on_curve;

const PDA_MARKER: &[u8] = b"ProgramDerivedAddress";

/// Find the program derived address and bump seed for `seeds` under
/// `program_id`, exactly as `Pubkey::find_program_address` does.
pub fn find_program_address(seeds: &[&[u8]], program_id: &[u8; 32]) -> ([u8; 32], u8) {
    for bump in (0..=255u8).rev() {
        let mut hasher = Sha256::new();
        for seed in seeds {
            hasher.update(seed);
        }
        hasher.update([bump]);
        hasher.update(program_id);
        hasher.update(PDA_MARKER);
        let candidate: [u8; 32] = hasher.finalize().into();
        if !is_on_curve(&candidate) {
            return (candidate, bump);
        }
    }
    panic!("unable to find a viable program address bump seed");
}

/// The registry account address for a subject key:
/// `find_program_address(["bio-did", subject], PROGRAM_ID)`
/// (spec Section 4.4, Section 6.2 step 4).
pub fn find_did_account_address(subject: &[u8; 32]) -> ([u8; 32], u8) {
    find_program_address(&[DID_SEED, subject], &PROGRAM_ID)
}

/// The owned subject that `initialize_owned(nonce)` signed by `authority`
/// creates: `find_program_address(["bio-did-owned", authority, nonce_le],
/// PROGRAM_ID)` (spec Section 4.2). Off the curve by construction, so the
/// DID has no generative document.
pub fn find_owned_subject(authority: &[u8; 32], nonce: u64) -> ([u8; 32], u8) {
    find_program_address(
        &[OWNED_SUBJECT_SEED, authority, &nonce.to_le_bytes()],
        &PROGRAM_ID,
    )
}

/// The key buffer address for `authority` uploading a large key into the
/// registry account `did_account`:
/// `find_program_address(["bio-did-key", did_account, authority], PROGRAM_ID)`
/// (spec Section 6.3).
pub fn find_key_buffer_address(did_account: &[u8; 32], authority: &[u8; 32]) -> ([u8; 32], u8) {
    find_program_address(&[KEY_BUFFER_SEED, did_account, authority], &PROGRAM_ID)
}
