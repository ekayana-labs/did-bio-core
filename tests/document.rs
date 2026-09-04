//! Multikey and generative document vectors (spec Section 5).

mod common;

use common::{example_did, EXAMPLE_MULTIKEY};
use did_bio_core::multikey::KeyCodec;
use did_bio_core::{generative_document, multikey, resolve_from_account, resolve_str};

#[test]
fn spec_example_multikey() {
    let did = example_did();
    let encoded = multikey::encode(KeyCodec::Ed25519Pub, &did.subject).unwrap();
    assert_eq!(encoded, EXAMPLE_MULTIKEY);
    let (codec, key) = multikey::decode(EXAMPLE_MULTIKEY).unwrap();
    assert_eq!(codec, KeyCodec::Ed25519Pub);
    assert_eq!(key, did.subject);
}

// --------------------------------------------------- Section 5.6 generative document

/// The complete example document from spec Section 5.6, verbatim.
const SPEC_GENERATIVE_DOCUMENT: &str = r#"{
  "@context": ["https://www.w3.org/ns/did/v1", "https://www.w3.org/ns/cid/v1"],
  "id": "did:bio:devnet:2T6zLFvMx7NJac5qQtiKTaPhMwHLkwKETWjUK1yKv4tc",
  "verificationMethod": [{
    "id": "did:bio:devnet:2T6zLFvMx7NJac5qQtiKTaPhMwHLkwKETWjUK1yKv4tc#default",
    "type": "Multikey",
    "controller": "did:bio:devnet:2T6zLFvMx7NJac5qQtiKTaPhMwHLkwKETWjUK1yKv4tc",
    "publicKeyMultibase": "z6MkfuN2vWAoHermh6vY6TgAJfwhBWZCApZb9XeQ9HwLqHfz"
  }],
  "authentication": ["did:bio:devnet:2T6zLFvMx7NJac5qQtiKTaPhMwHLkwKETWjUK1yKv4tc#default"],
  "assertionMethod": ["did:bio:devnet:2T6zLFvMx7NJac5qQtiKTaPhMwHLkwKETWjUK1yKv4tc#default"],
  "keyAgreement": ["did:bio:devnet:2T6zLFvMx7NJac5qQtiKTaPhMwHLkwKETWjUK1yKv4tc#default"],
  "capabilityInvocation": ["did:bio:devnet:2T6zLFvMx7NJac5qQtiKTaPhMwHLkwKETWjUK1yKv4tc#default"],
  "capabilityDelegation": ["did:bio:devnet:2T6zLFvMx7NJac5qQtiKTaPhMwHLkwKETWjUK1yKv4tc#default"]
}"#;

#[test]
fn generative_document_matches_spec_verbatim() {
    let document = generative_document(&example_did());
    let produced = serde_json::to_value(&document).unwrap();
    let expected: serde_json::Value = serde_json::from_str(SPEC_GENERATIVE_DOCUMENT).unwrap();
    assert_eq!(produced, expected);
}

#[test]
fn generative_resolution_metadata() {
    let resolution = resolve_from_account(&example_did(), None);
    assert_eq!(
        resolution.resolution_metadata.content_type.as_deref(),
        Some("application/did+ld+json")
    );
    assert_eq!(resolution.resolution_metadata.error, None);
    assert_eq!(
        resolution.document_metadata.version_id.as_deref(),
        Some("0")
    );
    assert_eq!(resolution.document_metadata.deactivated, Some(false));
    assert_eq!(resolution.document_metadata.updated, None);
}

#[test]
fn invalid_did_resolves_to_error_result() {
    let resolution = resolve_str("did:bio:devnet:notavalidkey", None);
    assert_eq!(
        resolution.resolution_metadata.error.as_deref(),
        Some("invalidDid")
    );
    assert_eq!(resolution.document, None);
    // Unsuccessful resolution: didDocumentMetadata is the empty structure.
    assert_eq!(
        serde_json::to_value(&resolution.document_metadata).unwrap(),
        serde_json::json!({})
    );
}
