//! Property tests over identifiers, Multikey and the account decoder.

mod common;

use common::AccountImage;
use did_bio_core::account::{
    vm_flags, DidAccountState, KeyType, StoredService, StoredVerificationMethod,
    MAX_CONTROLLER_LEN, MAX_ENDPOINT_LEN, MAX_NATIVE_CONTROLLERS, MAX_OTHER_CONTROLLERS,
    MAX_SERVICES, MAX_SERVICE_TYPE_LEN, MAX_VERIFICATION_METHODS, PROGRAM_ID,
};
use did_bio_core::multikey::{self, KeyCodec};
use did_bio_core::{materialize_document, BioDid, DidUrl, Network, RawAccount};
use proptest::prelude::*;

fn network() -> impl Strategy<Value = Network> {
    prop_oneof![
        Just(Network::Mainnet),
        Just(Network::Devnet),
        Just(Network::Testnet),
        Just(Network::Localnet),
    ]
}

fn fragment() -> impl Strategy<Value = String> {
    "[A-Za-z0-9_-]{1,32}"
}

fn printable(max: usize) -> impl Strategy<Value = String> {
    proptest::collection::vec(0x21u8..=0x7e, 1..=max)
        .prop_map(|bytes| String::from_utf8(bytes).unwrap())
}

fn key_type() -> impl Strategy<Value = KeyType> {
    prop_oneof![
        Just(KeyType::Ed25519),
        Just(KeyType::X25519),
        Just(KeyType::Secp256k1),
        Just(KeyType::MlDsa87),
    ]
}

/// The bits of `flags` that every registry version accepts on `method_type`.
fn allowed_flags(method_type: KeyType, flags: u16) -> u16 {
    match method_type {
        KeyType::Ed25519 => flags & vm_flags::VALID_MASK,
        KeyType::X25519 => flags & (vm_flags::KEY_AGREEMENT | vm_flags::PROTECTED),
        _ => flags & vm_flags::VALID_MASK & !vm_flags::CAPABILITY_INVOCATION,
    }
}

/// A state the registry could hold, with unique fragments and every field
/// in its form.
fn state() -> impl Strategy<Value = DidAccountState> {
    let vm = (fragment(), key_type(), any::<u16>(), any::<u8>()).prop_map(
        |(fragment, method_type, flags, fill)| StoredVerificationMethod {
            fragment,
            method_type,
            flags: allowed_flags(method_type, flags),
            key_data: vec![fill; method_type.expected_key_len()],
        },
    );
    let service = (
        fragment(),
        printable(MAX_SERVICE_TYPE_LEN),
        printable(MAX_ENDPOINT_LEN),
    )
        .prop_map(|(fragment, service_type, endpoint)| StoredService {
            fragment,
            service_type,
            endpoint,
        });
    (
        any::<u64>(),
        any::<u8>(),
        any::<[u8; 32]>(),
        any::<i64>(),
        proptest::collection::vec(any::<[u8; 32]>(), 0..=MAX_NATIVE_CONTROLLERS),
        proptest::collection::vec(
            printable(MAX_CONTROLLER_LEN - 8).prop_map(|id| format!("did:web:{id}")),
            0..=MAX_OTHER_CONTROLLERS,
        ),
        proptest::collection::vec(vm, 0..=MAX_VERIFICATION_METHODS),
        proptest::collection::vec(service, 0..=MAX_SERVICES),
    )
        .prop_map(
            |(version, bump, subject, updated_at, natives, others, mut vms, mut services)| {
                let mut seen = std::collections::HashSet::new();
                vms.retain(|vm| seen.insert(vm.fragment.clone()));
                services.retain(|s| seen.insert(s.fragment.clone()));
                DidAccountState {
                    version,
                    bump,
                    subject,
                    deactivated: false,
                    updated_at,
                    native_controllers: natives,
                    other_controllers: others,
                    verification_methods: vms,
                    services,
                }
            },
        )
}

fn encode(state: &DidAccountState) -> Vec<u8> {
    let mut image = AccountImage::new()
        .u64(state.version)
        .u8(state.bump)
        .raw(&state.subject)
        .u8(state.deactivated as u8)
        .i64(state.updated_at)
        .u32(state.native_controllers.len() as u32);
    for key in &state.native_controllers {
        image = image.raw(key);
    }
    image = image.u32(state.other_controllers.len() as u32);
    for controller in &state.other_controllers {
        image = image.string(controller);
    }
    image = image.u32(state.verification_methods.len() as u32);
    for vm in &state.verification_methods {
        image = image
            .string(&vm.fragment)
            .u8(vm.method_type as u8)
            .u16(vm.flags)
            .byte_vec(&vm.key_data);
    }
    image = image.u32(state.services.len() as u32);
    for service in &state.services {
        image = image
            .string(&service.fragment)
            .string(&service.service_type)
            .string(&service.endpoint);
    }
    image.bytes
}

proptest! {
    #[test]
    fn dids_round_trip_through_their_string(network in network(), subject in any::<[u8; 32]>()) {
        let did = BioDid::new(network, subject);
        let text = did.to_string();
        prop_assert_eq!(BioDid::parse(&text).unwrap(), did);
        prop_assert!(regex_free_match(&text));
    }

    #[test]
    fn did_urls_round_trip(network in network(), subject in any::<[u8; 32]>(), fragment in proptest::option::of(fragment())) {
        let did = BioDid::new(network, subject);
        let text = match &fragment {
            Some(f) => did.url(f),
            None => did.to_string(),
        };
        let url = DidUrl::parse(&text).unwrap();
        prop_assert_eq!(url.did, did);
        prop_assert_eq!(url.to_string(), text);
        prop_assert_eq!(url.fragment, fragment);
    }

    #[test]
    fn parsers_never_panic(text in ".{0,80}", near in "did:bio:[a-z]{0,8}:?[1-9A-HJ-NP-Za-km-z]{0,46}(#.{0,40})?") {
        for input in [&text, &near] {
            let _ = BioDid::parse(input);
            let _ = DidUrl::parse(input);
            let _ = did_bio_core::resolve_str(input, None);
        }
    }

    #[test]
    fn multikeys_round_trip(codec in prop_oneof![Just(KeyCodec::Ed25519Pub), Just(KeyCodec::X25519Pub), Just(KeyCodec::Secp256k1Pub)], fill in any::<u8>()) {
        let mut key = vec![fill; codec.key_len()];
        if codec == KeyCodec::Secp256k1Pub {
            // A compressed point, the only form `zQ3s` describes.
            key[0] = 2 + (fill & 1);
        }
        let encoded = multikey::encode(codec, &key).unwrap();
        prop_assert!(encoded.starts_with(codec.multibase_prefix()));
        prop_assert_eq!(multikey::decode(&encoded).unwrap(), (codec, key));
    }

    #[test]
    fn every_accepted_multikey_is_canonical(
        prefix in prop_oneof![
            Just(vec![0xed, 0x01]),
            Just(vec![0xec, 0x01]),
            Just(vec![0xe7, 0x01]),
            Just(vec![0xed, 0x81, 0x00]),
            Just(vec![0xe7, 0x81, 0x80, 0x00]),
            proptest::collection::vec(any::<u8>(), 1..4),
        ],
        key in proptest::collection::vec(any::<u8>(), 31..35),
    ) {
        let mut bytes = prefix;
        bytes.extend_from_slice(&key);
        let text = format!("z{}", bs58::encode(&bytes).into_string());
        if let Ok((codec, key)) = multikey::decode(&text) {
            prop_assert_eq!(multikey::encode(codec, &key).unwrap(), text);
        }
    }

    #[test]
    fn the_decoder_never_panics(data in proptest::collection::vec(any::<u8>(), 0..512)) {
        let _ = DidAccountState::from_account_data(&data);
        let _ = did_bio_core::KeyBufferState::from_account_data(&data);
        let mut prefixed = did_bio_core::account::ACCOUNT_DISCRIMINATOR.to_vec();
        prefixed.extend_from_slice(&data);
        let _ = DidAccountState::from_account_data(&prefixed);
    }

    #[test]
    fn states_round_trip_and_materialize(state in state(), network in network()) {
        let image = encode(&state);
        prop_assert_eq!(&DidAccountState::from_account_data(&image).unwrap(), &state);

        let did = BioDid::new(network, state.subject);
        let document = materialize_document(&did, &state).unwrap();
        prop_assert_eq!(document.verification_method.len(), state.verification_methods.len());
        prop_assert_eq!(document.service.len(), state.services.len());
        prop_assert_eq!(
            document.controller.len(),
            state.native_controllers.len() + state.other_controllers.len()
        );
        let resolution = did_bio_core::resolve_from_account(
            &did,
            Some(&RawAccount { owner: PROGRAM_ID, data: image }),
        );
        prop_assert_eq!(resolution.document, Some(document));
    }
}

/// The informative `DID_REGEX`, checked by hand so the test needs no regex
/// engine.
fn regex_free_match(text: &str) -> bool {
    let Some(rest) = text.strip_prefix("did:bio:") else {
        return false;
    };
    let id = match rest.split_once(':') {
        Some((network, id)) if ["devnet", "testnet", "localnet"].contains(&network) => id,
        Some(_) => return false,
        None => rest,
    };
    (32..=44).contains(&id.len())
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() && !b"0OIl".contains(&b))
}
