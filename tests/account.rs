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

    // a hostile length prefix, 4 GiB of controllers, must not allocate
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

    // a count the bytes could hold but the registry never writes
    let header = || {
        AccountImage::new()
            .u64(1)
            .u8(255)
            .raw(&did.subject)
            .u8(0)
            .i64(0)
    };
    let mut over = header().u32(0).u32(0).u32(0).u32(17).bytes;
    over.resize(over.len() + 17 * 12, 0);
    assert!(matches!(
        DidAccountState::from_account_data(&over),
        Err(Error::InvalidAccountData(
            "more services than the registry allows"
        ))
    ));
    let mut over = header().u32(9).bytes;
    over.resize(over.len() + 9 * 32 + 12, 0);
    assert!(matches!(
        DidAccountState::from_account_data(&over),
        Err(Error::InvalidAccountData(
            "more native controllers than the registry allows"
        ))
    ));

    // invalid bool byte
    let mut bad_bool = good.clone();
    bad_bool[8 + 8 + 1 + 32] = 2;
    assert!(DidAccountState::from_account_data(&bad_bool).is_err());

    // unknown verification method type tag, patched into the default VM
    // right after its fragment string
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

    // capabilityInvocation on an ML-DSA-87 method
    let mut capability = good.clone();
    capability[74..76].copy_from_slice(&(1u16 << 3).to_le_bytes());
    assert!(matches!(
        KeyBufferState::from_account_data(&capability),
        Err(Error::InvalidAccountData(
            "capabilityInvocation on a method that is not Ed25519"
        ))
    ));

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

/// One change to the rich image, the description of the field it breaks,
/// and the error the decoder must give.
fn refused(image: Vec<u8>, reason: &'static str) {
    assert_eq!(
        DidAccountState::from_account_data(&image),
        Err(Error::InvalidAccountData(reason)),
    );
}

#[test]
fn rejects_states_the_registry_never_writes() {
    let did = example_did();
    let header = || {
        AccountImage::new()
            .u64(3)
            .u8(255)
            .raw(&did.subject)
            .u8(0)
            .i64(0)
    };
    let method = |image: AccountImage, fragment: &str, tag: u8, flags: u16, key: &[u8]| {
        image.string(fragment).u8(tag).u16(flags).byte_vec(key)
    };

    let mut trailing = rich_account_image(&did.subject);
    trailing.push(0);
    refused(trailing, "trailing bytes after the account state");

    refused(
        method(header().u32(0).u32(0).u32(1), "has space", 0, 1, &[1; 32])
            .u32(0)
            .bytes,
        "fragment is not valid",
    );
    refused(
        method(header().u32(0).u32(0).u32(1), "k", 0, 1 << 12, &[1; 32])
            .u32(0)
            .bytes,
        "unknown verification method flag bits",
    );
    refused(
        method(header().u32(0).u32(0).u32(1), "k", 3, 1 << 3, &[1; 2592])
            .u32(0)
            .bytes,
        "capabilityInvocation on a method that is not Ed25519",
    );
    refused(
        method(header().u32(0).u32(0).u32(1), "k", 1, 1 << 2 | 1, &[1; 32])
            .u32(0)
            .bytes,
        "X25519 method outside keyAgreement",
    );
    refused(
        method(header().u32(0).u32(0).u32(1), "k", 0, 1, &[1; 3])
            .u32(0)
            .bytes,
        "key length does not match its type",
    );
    refused(
        header()
            .u32(0)
            .u32(0)
            .u32(0)
            .u32(1)
            .string("s")
            .string("T")
            .string("not a uri")
            .bytes,
        "service endpoint is not valid",
    );
    refused(
        header()
            .u32(0)
            .u32(0)
            .u32(0)
            .u32(1)
            .string("s")
            .string("")
            .string("x")
            .bytes,
        "service type is not valid",
    );
    for controller in [
        "web:lab",
        "did:bio:5FHneW46xGXgs5mUiveU4sbTyGBzmstUspZC92UhjJM694ty",
    ] {
        refused(
            header()
                .u32(0)
                .u32(1)
                .string(controller)
                .u32(0)
                .u32(0)
                .bytes,
            "external controller is not a DID of another method",
        );
    }
    refused(
        method(header().u32(0).u32(0).u32(1), "dup", 0, 1, &[1; 32])
            .u32(1)
            .string("dup")
            .string("T")
            .string("x")
            .bytes,
        "fragment used twice",
    );
    refused(
        AccountImage::new()
            .u64(4)
            .u8(255)
            .raw(&did.subject)
            .u8(1)
            .i64(0)
            .u32(0)
            .u32(0)
            .u32(0)
            .u32(1)
            .string("s")
            .string("T")
            .string("x")
            .bytes,
        "deactivated account holds entries",
    );
}

/// Every account the deployed devnet program had written when this test was
/// added, fetched with `getProgramAccounts`. Strict decoding must accept all
/// of them and resolve each to its stored version.
#[test]
fn decodes_every_account_the_devnet_program_wrote() {
    use base64::Engine as _;
    let accounts: Vec<serde_json::Value> =
        serde_json::from_str(include_str!("fixtures/devnet-accounts.json")).unwrap();
    assert_eq!(accounts.len(), 21);
    for account in accounts {
        let data = base64::engine::general_purpose::STANDARD
            .decode(account["data"].as_str().unwrap())
            .unwrap();
        let state = DidAccountState::from_account_data(&data)
            .unwrap_or_else(|e| panic!("{}: {e}", account["address"]));
        let did = did_bio_core::BioDid::new(did_bio_core::Network::Devnet, state.subject);
        let resolution = did_bio_core::resolve_from_account(
            &did,
            Some(&did_bio_core::RawAccount {
                owner: PROGRAM_ID,
                data,
            }),
        );
        assert_eq!(
            resolution.document_metadata.version_id,
            Some(state.version.to_string())
        );
        assert_eq!(
            resolution.document_metadata.deactivated,
            Some(state.deactivated)
        );
    }
}
