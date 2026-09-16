//! Program derived address vectors (spec Section 6.2 step 4).
#![cfg(feature = "pda")]

mod common;

use common::{example_did, OWNED_AUTHORITY, OWNED_NONCE, OWNED_SUBJECT};
use did_bio_core::account::{KEY_BUFFER_SEED, OWNED_SUBJECT_SEED, PROGRAM_ID};
use did_bio_core::{
    find_did_account_address, find_key_buffer_address, find_owned_subject, find_program_address,
    is_on_curve, BioDid, Network,
};

#[test]
fn spec_example_pda() {
    // Cross computed vector (solana-pubkey vs this crate) for the spec
    // Section 5.6 example subject.
    let did = example_did();
    let (address, bump) = find_did_account_address(&did.subject);
    assert_eq!(
        bs58::encode(address).into_string(),
        "9qXXepf3sXfmbgzYjYr22QrS84Lmij4G9EPJC7Ge8phx"
    );
    assert_eq!(bump, 255);
}

#[test]
fn low_bump_pda_exercises_curve_rejection() {
    // The [16u8; 32] subject's first two candidates are on curve; the
    // derivation must walk down to bump 253.
    let (address, bump) = find_did_account_address(&[16u8; 32]);
    assert_eq!(
        bs58::encode(address).into_string(),
        "Fp1okLp5zejTMBhYxABqenQy3Tf8SVTpikTCTVcPSZFG"
    );
    assert_eq!(bump, 253);
}

#[test]
fn key_buffer_pda_for_the_spec_example() {
    // The subject uploading a key into its own registry account. Cross
    // computed with solana-pubkey; the resolver's parity tests check it
    // against the SDK on every run.
    let did = example_did();
    let (did_account, _) = find_did_account_address(&did.subject);
    let (address, bump) = find_key_buffer_address(&did_account, &did.subject);
    assert_eq!(
        (address, bump),
        find_program_address(&[KEY_BUFFER_SEED, &did_account, &did.subject], &PROGRAM_ID)
    );
    assert_eq!(
        bs58::encode(address).into_string(),
        "2DLfor8ZYBiiGt6MMDhPB6tnDUKejkkotHfMG6xFDcnh"
    );
    assert_eq!(bump, 254);
}

#[test]
fn owned_subject_matches_the_program() {
    // The same vector is pinned in the registry crate's unit tests.
    let (subject, _bump) = find_owned_subject(&OWNED_AUTHORITY, OWNED_NONCE);
    assert_eq!(subject, OWNED_SUBJECT);
    assert!(!is_on_curve(&subject), "an owned subject is never a key");
    assert_eq!(
        find_program_address(
            &[
                OWNED_SUBJECT_SEED,
                &OWNED_AUTHORITY,
                &OWNED_NONCE.to_le_bytes()
            ],
            &PROGRAM_ID
        )
        .0,
        subject
    );
    assert_ne!(
        find_owned_subject(&OWNED_AUTHORITY, OWNED_NONCE + 1).0,
        subject
    );
    assert_ne!(find_owned_subject(&[0x12; 32], OWNED_NONCE).0, subject);

    let did = BioDid::owned(Network::Devnet, &OWNED_AUTHORITY, OWNED_NONCE);
    assert_eq!(did.subject, subject);
    assert!(!did.is_key_subject());
    assert_eq!(did.to_string().parse::<BioDid>().unwrap(), did);
}
