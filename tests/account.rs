//! Registry account decoding and constants (spec Section 6.2 step 7).

mod common;

use common::{example_did, rich_account_image, AccountImage};
use did_bio_core::account::{
    DidAccountState, KeyType, ACCOUNT_DISCRIMINATOR, DEFAULT_FRAGMENT, PROGRAM_ID, PROGRAM_ID_STR,
};
use did_bio_core::document::ML_DSA_87_PUBLIC_KEY_LEN;
use did_bio_core::Error;

#[test]
fn deserializes_rich_account() {
    let did = example_did();
    let state = DidAccountState::from_account_data(&rich_account_image(&did.subject)).unwrap();

    assert_eq!(state.version, 7);
    assert_eq!(state.bump, 254);
    assert_eq!(state.subject, did.subject);
    assert!(!state.deactivated);
    assert_eq!(state.updated_at, 1_753_228_800);
    assert_eq!(state.native_controllers, vec![[9u8; 32]]);
    assert_eq!(
        state.other_controllers,
        vec!["did:key:z6MkExample".to_string()]
    );
    assert_eq!(state.verification_methods.len(), 4);
    assert_eq!(state.verification_methods[0].fragment, DEFAULT_FRAGMENT);
    assert_eq!(state.verification_methods[1].method_type, KeyType::X25519);
    assert_eq!(state.verification_methods[3].method_type, KeyType::MlDsa87);
    assert_eq!(
        state.verification_methods[3].key_data.len(),
        ML_DSA_87_PUBLIC_KEY_LEN
    );
    assert_eq!(state.services.len(), 1);

    // authorization helpers (spec Section 6)
    assert!(state.is_authority(&did.subject));
    assert!(!state.is_authority(&[2u8; 32]));
    assert_eq!(state.authority_count(), 1);
}

#[test]
fn rejects_malformed_account_data() {
    let did = example_did();
    let good = rich_account_image(&did.subject);

    // wrong discriminator
    let mut wrong_disc = good.clone();
    wrong_disc[0] ^= 0xff;
    assert!(matches!(
        DidAccountState::from_account_data(&wrong_disc),
        Err(Error::InvalidAccountData("discriminator mismatch"))
    ));

    // truncations at every prefix length must error, never panic
    for len in 0..good.len().min(96) {
        assert!(DidAccountState::from_account_data(&good[..len]).is_err());
    }

    // hostile length prefix (4 GiB of controllers) must not allocate
    let hostile = AccountImage::new()
        .u64(1)
        .u8(255)
        .raw(&did.subject)
        .u8(0)
        .i64(0)
        .u32(u32::MAX)
        .bytes;
    assert!(matches!(
        DidAccountState::from_account_data(&hostile),
        Err(Error::InvalidAccountData("length prefix exceeds data"))
    ));

    // invalid bool byte
    let mut bad_bool = good.clone();
    bad_bool[8 + 8 + 1 + 32] = 2;
    assert!(DidAccountState::from_account_data(&bad_bool).is_err());

    // unknown verification method type tag: patch the default VM's tag,
    // located right after its fragment string.
    let mut bad_tag = good;
    let vm_tag_offset = 8 // discriminator
        + 8 + 1 + 32 + 1 + 8 // scalars
        + 4 + 32 // native_controllers
        + 4 + 4 + "did:key:z6MkExample".len() // other_controllers
        + 4 // vm vec len
        + 4 + DEFAULT_FRAGMENT.len();
    assert_eq!(bad_tag[vm_tag_offset], 0);
    bad_tag[vm_tag_offset] = 9;
    assert!(matches!(
        DidAccountState::from_account_data(&bad_tag),
        Err(Error::InvalidAccountData(
            "unknown verification method type tag"
        ))
    ));
}

#[test]
fn program_id_bytes_match_base58_form() {
    assert_eq!(bs58::encode(PROGRAM_ID).into_string(), PROGRAM_ID_STR);
}

#[test]
fn discriminator_is_sha256_of_account_name() {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(b"account:DidAccount");
    assert_eq!(ACCOUNT_DISCRIMINATOR, digest[..8]);
}
