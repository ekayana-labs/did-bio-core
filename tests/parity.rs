//! The constants this crate mirrors, checked against the registry program
//! crate, which is their source of truth.

use bio_did_registry::state as program;
use did_bio_core::account::{self, vm_flags, KeyType};

#[test]
fn account_constants_match_the_program() {
    assert_eq!(account::PROGRAM_ID, *bio_did_registry::ID.as_array());
    assert_eq!(account::DID_SEED, program::DID_SEED);
    assert_eq!(account::OWNED_SUBJECT_SEED, program::OWNED_SUBJECT_SEED);
    assert_eq!(account::KEY_BUFFER_SEED, program::KEY_BUFFER_SEED);
    assert_eq!(
        account::DEFAULT_FRAGMENT.as_bytes(),
        program::DEFAULT_FRAGMENT
    );
    assert_eq!(
        account::ACCOUNT_DISCRIMINATOR,
        program::ACCOUNT_DISCRIMINATOR
    );
    assert_eq!(
        account::KEY_BUFFER_DISCRIMINATOR,
        program::KEY_BUFFER_DISCRIMINATOR
    );
    assert_eq!(account::KEY_BUFFER_HEADER_LEN, program::KEY_BUFFER_HEADER);
}

#[test]
fn limits_match_the_program() {
    assert_eq!(
        account::MAX_VERIFICATION_METHODS,
        program::MAX_VERIFICATION_METHODS
    );
    assert_eq!(account::MAX_SERVICES, program::MAX_SERVICES);
    assert_eq!(
        account::MAX_NATIVE_CONTROLLERS,
        program::MAX_NATIVE_CONTROLLERS
    );
    assert_eq!(
        account::MAX_OTHER_CONTROLLERS,
        program::MAX_OTHER_CONTROLLERS
    );
    assert_eq!(account::MAX_FRAGMENT_LEN, program::MAX_FRAGMENT_LEN);
    assert_eq!(account::MAX_SERVICE_TYPE_LEN, program::MAX_SERVICE_TYPE_LEN);
    assert_eq!(account::MAX_ENDPOINT_LEN, program::MAX_ENDPOINT_LEN);
    assert_eq!(account::MAX_CONTROLLER_LEN, program::MAX_CONTROLLER_LEN);
}

#[test]
fn flags_and_key_types_match_the_program() {
    assert_eq!(vm_flags::AUTHENTICATION, program::VM_FLAG_AUTHENTICATION);
    assert_eq!(vm_flags::ASSERTION, program::VM_FLAG_ASSERTION);
    assert_eq!(vm_flags::KEY_AGREEMENT, program::VM_FLAG_KEY_AGREEMENT);
    assert_eq!(
        vm_flags::CAPABILITY_INVOCATION,
        program::VM_FLAG_CAPABILITY_INVOCATION
    );
    assert_eq!(
        vm_flags::CAPABILITY_DELEGATION,
        program::VM_FLAG_CAPABILITY_DELEGATION
    );
    assert_eq!(vm_flags::PROTECTED, program::VM_FLAG_PROTECTED);
    assert_eq!(vm_flags::RELATIONSHIP_MASK, program::VM_RELATIONSHIP_MASK);
    assert_eq!(vm_flags::VALID_MASK, program::VM_VALID_MASK);
    assert_eq!(vm_flags::DEFAULT, program::VM_FLAGS_DEFAULT);
    for tag in 0..=u8::MAX {
        assert_eq!(
            KeyType::from_tag(tag).map(KeyType::expected_key_len),
            program::expected_key_len(tag),
            "tag {tag}"
        );
    }
}

#[cfg(feature = "pda")]
#[test]
fn derivations_match_the_program() {
    for (authority, nonce) in [
        ([0x11u8; 32], 42u64),
        ([7u8; 32], 0),
        ([0xff; 32], u64::MAX),
    ] {
        assert_eq!(
            did_bio_core::find_owned_subject(&authority, nonce).0,
            program::owned_subject(&authority, nonce)
        );
    }
}
