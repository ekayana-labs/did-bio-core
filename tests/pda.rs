//! Program derived address vectors (spec Section 6.2 step 4).
#![cfg(feature = "pda")]

mod common;

use common::{example_did, OWNED_AUTHORITY, OWNED_NONCE, OWNED_SUBJECT};
use did_bio_core::account::{KEY_BUFFER_SEED, OWNED_SUBJECT_SEED, PROGRAM_ID};
use did_bio_core::{
    find_did_account_address, find_key_buffer_address, find_owned_subject, find_program_address,
    is_on_curve, try_find_program_address, BioDid, Network,
};

#[test]
fn spec_example_pda() {
    // A vector cross computed between solana-pubkey and this crate, for the
    // example subject of spec Section 5.6.
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
    // The [16u8; 32] subject's first two candidates are on curve, so the
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
    // computed with solana-pubkey, and the resolver's parity tests check it
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

#[test]
fn seeds_the_runtime_refuses_find_no_address() {
    let long = [1u8; 33];
    assert_eq!(try_find_program_address(&[&long], &PROGRAM_ID), None);
    assert!(try_find_program_address(&[&long[..32]], &PROGRAM_ID).is_some());

    // Sixteen seeds leave no room for the bump.
    let seeds = [b"s".as_slice(); 16];
    assert_eq!(try_find_program_address(&seeds, &PROGRAM_ID), None);
    assert!(try_find_program_address(&seeds[..15], &PROGRAM_ID).is_some());
}

#[test]
#[should_panic(expected = "Unable to find a viable program address bump seed")]
fn find_program_address_panics_where_the_sdk_does() {
    find_program_address(&[&[1u8; 33]], &PROGRAM_ID);
}
