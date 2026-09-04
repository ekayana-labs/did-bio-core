//! Resolution steps 6-9 and the reader drivers (spec Section 6.2).

mod common;

use common::{
    example_did, registry_account, rich_account_image, AccountImage, EXAMPLE_DID, EXAMPLE_MULTIKEY,
};
use did_bio_core::account::PROGRAM_ID;
use did_bio_core::document::{ML_DSA_87_PUBLIC_KEY_LEN, VM_TYPE_JSON_WEB_KEY, VM_TYPE_MULTIKEY};
use did_bio_core::{resolve_from_account, RawAccount, VerificationMaterial};

#[test]
fn materializes_rich_document() {
    let did = example_did();
    let resolution = resolve_from_account(
        &did,
        Some(&registry_account(rich_account_image(&did.subject))),
    );
    let document = resolution.document.unwrap();

    // Section 5.5 controllers: native key mapped into the DID's own network.
    assert_eq!(
        document.controller,
        vec![
            format!("did:bio:devnet:{}", bs58::encode([9u8; 32]).into_string()),
            "did:key:z6MkExample".to_string(),
        ]
    );

    // Section 5.2 materialization by type
    let default_vm = document.verification_method_by_fragment("default").unwrap();
    assert_eq!(default_vm.method_type, VM_TYPE_MULTIKEY);
    assert!(matches!(
        &default_vm.material,
        VerificationMaterial::PublicKeyMultibase(mb) if mb == EXAMPLE_MULTIKEY
    ));

    let agreement = document
        .verification_method_by_fragment("agreement")
        .unwrap();
    assert!(matches!(
        &agreement.material,
        VerificationMaterial::PublicKeyMultibase(mb) if mb.starts_with("z6LS")
    ));

    let evm = document.verification_method_by_fragment("evm").unwrap();
    assert!(matches!(
        &evm.material,
        VerificationMaterial::PublicKeyMultibase(mb) if mb.starts_with("zQ3s")
    ));

    let pq = document.verification_method_by_fragment("pq").unwrap();
    assert_eq!(pq.method_type, VM_TYPE_JSON_WEB_KEY);
    match &pq.material {
        VerificationMaterial::PublicKeyJwk(jwk) => {
            assert_eq!(jwk.kty, "AKP");
            assert_eq!(jwk.alg, "ML-DSA-87");
            assert_eq!(
                jwk.decode_public_key().unwrap(),
                vec![4u8; ML_DSA_87_PUBLIC_KEY_LEN]
            );
        }
        other => panic!("expected JWK material, got {other:?}"),
    }

    // Section 5.3 relationships: PROTECTED not expressed; flags map to arrays.
    let default_id = did.default_verification_method_id();
    assert_eq!(document.authentication, vec![default_id.clone()]);
    assert_eq!(
        document.assertion_method,
        vec![default_id.clone(), did.url("evm"), did.url("pq")]
    );
    assert_eq!(
        document.key_agreement,
        vec![default_id.clone(), did.url("agreement")]
    );
    assert_eq!(document.capability_invocation, vec![default_id.clone()]);
    assert_eq!(document.capability_delegation, vec![default_id]);

    // Section 5.4 services
    assert_eq!(document.service.len(), 1);
    assert_eq!(document.service[0].id, did.url("metadata"));
    assert_eq!(document.service[0].service_type, "BioMetadata");

    // Section 6.2 step 9 metadata
    assert_eq!(
        resolution.document_metadata.version_id.as_deref(),
        Some("7")
    );
    assert_eq!(
        resolution.document_metadata.updated.as_deref(),
        Some("2025-07-23T00:00:00Z")
    );
}

#[test]
fn wrong_owner_or_empty_account_resolves_generatively() {
    let did = example_did();
    let data = rich_account_image(&did.subject);

    // Section 6.2 step 6: lamport only (system owned) account at the PDA.
    let foreign = RawAccount {
        owner: [0u8; 32],
        data: data.clone(),
    };
    let resolution = resolve_from_account(&did, Some(&foreign));
    assert_eq!(
        resolution.document_metadata.version_id.as_deref(),
        Some("0")
    );
    assert_eq!(resolution.document.unwrap().verification_method.len(), 1);

    let empty = RawAccount {
        owner: PROGRAM_ID,
        data: Vec::new(),
    };
    let resolution = resolve_from_account(&did, Some(&empty));
    assert_eq!(
        resolution.document_metadata.version_id.as_deref(),
        Some("0")
    );
}

#[test]
fn corrupt_registry_account_is_internal_error_not_fallback() {
    let did = example_did();
    let mut data = rich_account_image(&did.subject);
    data.truncate(40); // valid discriminator, garbage body
    let resolution = resolve_from_account(&did, Some(&registry_account(data)));
    assert_eq!(
        resolution.resolution_metadata.error.as_deref(),
        Some("internalError")
    );
    assert_eq!(resolution.document, None);
}

#[test]
fn subject_mismatch_is_internal_error() {
    let did = example_did();
    let other_subject = [7u8; 32];
    let resolution = resolve_from_account(
        &did,
        Some(&registry_account(rich_account_image(&other_subject))),
    );
    assert_eq!(
        resolution.resolution_metadata.error.as_deref(),
        Some("internalError")
    );
}

#[test]
fn deactivated_resolves_to_tombstone_document() {
    let did = example_did();
    // Section 6.4: tombstone - all vecs empty, deactivated = true.
    let data = AccountImage::new()
        .u64(9)
        .u8(254)
        .raw(&did.subject)
        .u8(1)
        .i64(1_753_228_800)
        .u32(0)
        .u32(0)
        .u32(0)
        .u32(0)
        .bytes;
    let resolution = resolve_from_account(&did, Some(&registry_account(data)));
    assert_eq!(resolution.document_metadata.deactivated, Some(true));
    assert_eq!(
        resolution.document_metadata.version_id.as_deref(),
        Some("9")
    );

    // Section 5.7: minimal document.
    let document = resolution.document.unwrap();
    assert_eq!(
        serde_json::to_value(&document).unwrap(),
        serde_json::json!({
            "@context": ["https://www.w3.org/ns/did/v1", "https://www.w3.org/ns/cid/v1"],
            "id": EXAMPLE_DID,
        })
    );
}

#[cfg(feature = "pda")]
struct MapReader {
    address: [u8; 32],
    account: Option<RawAccount>,
}

#[cfg(feature = "pda")]
impl did_bio_core::RegistryReader for MapReader {
    type Error = String;

    fn fetch_account(&self, address: &[u8; 32]) -> Result<Option<RawAccount>, String> {
        if *address == self.address {
            Ok(self.account.clone())
        } else {
            Err("fetched unexpected address".to_string())
        }
    }
}

#[cfg(feature = "pda")]
impl did_bio_core::AsyncRegistryReader for MapReader {
    type Error = String;

    async fn fetch_account(&self, address: &[u8; 32]) -> Result<Option<RawAccount>, String> {
        did_bio_core::RegistryReader::fetch_account(self, address)
    }
}

#[cfg(feature = "pda")]
#[test]
fn sync_driver_fetches_the_did_pda() {
    let did = example_did();
    let (address, _) = did_bio_core::find_did_account_address(&did.subject);
    let reader = MapReader {
        address,
        account: Some(registry_account(rich_account_image(&did.subject))),
    };
    let resolution = did_bio_core::resolve_with(&reader, &did).unwrap();
    assert_eq!(
        resolution.document_metadata.version_id.as_deref(),
        Some("7")
    );
}

#[cfg(feature = "pda")]
#[test]
fn async_driver_fetches_the_did_pda() {
    let did = example_did();
    let (address, _) = did_bio_core::find_did_account_address(&did.subject);
    let reader = MapReader {
        address,
        account: None,
    };
    let resolution = block_on(did_bio_core::resolve_with_async(&reader, &did)).unwrap();
    assert_eq!(
        resolution.document_metadata.version_id.as_deref(),
        Some("0")
    );
}

/// Minimal executor for a future that never actually suspends.
#[cfg(feature = "pda")]
fn block_on<F: core::future::Future>(future: F) -> F::Output {
    use core::pin::pin;
    use core::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};

    fn noop_raw_waker() -> RawWaker {
        const VTABLE: RawWakerVTable =
            RawWakerVTable::new(|_| noop_raw_waker(), |_| {}, |_| {}, |_| {});
        RawWaker::new(core::ptr::null(), &VTABLE)
    }

    let waker = unsafe { Waker::from_raw(noop_raw_waker()) };
    let mut context = Context::from_waker(&waker);
    let mut future = pin!(future);
    match future.as_mut().poll(&mut context) {
        Poll::Ready(output) => output,
        Poll::Pending => unreachable!("test future never suspends"),
    }
}
