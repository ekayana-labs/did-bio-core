//! Program derived address vectors (spec Section 6.2 step 4).
#![cfg(feature = "pda")]

mod common;

use common::example_did;
use did_bio_core::find_did_account_address;

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
