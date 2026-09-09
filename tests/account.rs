//! Registry account decoding and constants (spec Section 6.2 step 7).

mod common;

use common::{example_did, rich_account_image, AccountImage};
use did_bio_core::account::{
    DidAccountState, KeyBufferState, KeyType, ACCOUNT_DISCRIMINATOR, DEFAULT_FRAGMENT,
    KEY_BUFFER_DISCRIMINATOR, KEY_BUFFER_HEADER_LEN, KEY_BUFFER_SEED, PROGRAM_ID, PROGRAM_ID_STR,
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

// ---------------------------------------------------------------------------
// Key buffers (spec Section 6.3, large keys)
// ---------------------------------------------------------------------------

fn pq_key() -> Vec<u8> {
    (0..ML_DSA_87_PUBLIC_KEY_LEN as u32)
        .map(|i| (i % 251) as u8)
        .collect()
}

/// A key buffer for an ML-DSA-87 assertion method `#pq`, with `written`
/// bytes of the key received so far and zeros after them.
fn key_buffer_image(written: usize) -> Vec<u8> {
    let mut fragment = [0u8; 32];
    fragment[..2].copy_from_slice(b"pq");
    let mut image = AccountImage::default()
        .raw(&KEY_BUFFER_DISCRIMINATOR)
        .raw(&[3u8; 32]) // did_account
        .raw(&[4u8; 32]) // authority
        .u8(254) // bump
        .u8(3) // ML-DSA-87 tag
        .u16(0b10) // assertion
        .u32(ML_DSA_87_PUBLIC_KEY_LEN as u32)
        .u32(written as u32)
        .u32(2)
        .raw(&fragment)
        .bytes;
    image.extend_from_slice(&pq_key()[..written]);
    image.resize(KEY_BUFFER_HEADER_LEN + ML_DSA_87_PUBLIC_KEY_LEN, 0);
    image
}

#[test]
fn decodes_key_buffer_header_and_written_prefix() {
    let image = key_buffer_image(900);
    assert_eq!(
        image.len(),
        KEY_BUFFER_HEADER_LEN + ML_DSA_87_PUBLIC_KEY_LEN
    );
    let state = KeyBufferState::from_account_data(&image).unwrap();

    assert_eq!(state.did_account, [3u8; 32]);
    assert_eq!(state.authority, [4u8; 32]);
    assert_eq!(state.bump, 254);
    assert_eq!(state.method_type, KeyType::MlDsa87);
    assert_eq!(state.flags, 0b10);
    assert_eq!(state.key_len, ML_DSA_87_PUBLIC_KEY_LEN);
    assert_eq!(state.fragment, "pq");
    assert_eq!(state.written(), 900);
    assert!(!state.is_complete());
    assert_eq!(state.key_data, pq_key()[..900]);

    let empty = KeyBufferState::from_account_data(&key_buffer_image(0)).unwrap();
    assert_eq!(empty.written(), 0);
    let full =
        KeyBufferState::from_account_data(&key_buffer_image(ML_DSA_87_PUBLIC_KEY_LEN)).unwrap();
    assert!(full.is_complete());
    assert_eq!(full.key_data, pq_key());
}

#[test]
fn rejects_malformed_key_buffers() {
    let good = key_buffer_image(0);

    // wrong discriminator, including a DID account passed by mistake
    let mut wrong_disc = good.clone();
    wrong_disc[0] ^= 0xff;
    assert!(matches!(
        KeyBufferState::from_account_data(&wrong_disc),
        Err(Error::InvalidAccountData("discriminator mismatch"))
    ));
    let did = example_did();
    assert!(KeyBufferState::from_account_data(&rich_account_image(&did.subject)).is_err());

    // truncations must error, never panic
    for len in 0..KEY_BUFFER_HEADER_LEN {
        assert!(KeyBufferState::from_account_data(&good[..len]).is_err());
    }

    // the account must be exactly header + key_len
    assert!(KeyBufferState::from_account_data(&good[..good.len() - 1]).is_err());

    // written past the declared key length
    let mut over = good.clone();
    over[80..84].copy_from_slice(&(ML_DSA_87_PUBLIC_KEY_LEN as u32 + 1).to_le_bytes());
    assert!(KeyBufferState::from_account_data(&over).is_err());

    // fragment length past its 32 byte field
    let mut long_fragment = good.clone();
    long_fragment[84..88].copy_from_slice(&33u32.to_le_bytes());
    assert!(KeyBufferState::from_account_data(&long_fragment).is_err());

    // unknown key type tag
    let mut bad_tag = good;
    bad_tag[73] = 9;
    assert!(matches!(
        KeyBufferState::from_account_data(&bad_tag),
        Err(Error::InvalidAccountData(
            "unknown verification method type tag"
        ))
    ));
}

#[test]
fn key_buffer_constants_match_the_program() {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(b"account:KeyBuffer");
    assert_eq!(KEY_BUFFER_DISCRIMINATOR, digest[..8]);
    assert_eq!(KEY_BUFFER_SEED, b"bio-did-key");
    assert_eq!(KEY_BUFFER_HEADER_LEN, 120);
}
