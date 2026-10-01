//! Signature verification for `did:bio` verification methods, under the
//! `verify` and `fips` features.
//!
//! Backed by [aws-lc-rs]. The `fips` feature links the FIPS validated
//! AWS-LC module instead, with an identical API. Call [`fips_mode`] to
//! confirm at runtime.
//!
//! Supported algorithms follow the method's verification material types
//! (spec Section 5.2). They are Ed25519, a `Multikey` starting `z6Mk`,
//! ES256K, ECDSA over secp256k1 with SHA-256 for a `Multikey` starting
//! `zQ3s`, and ML-DSA-87 (FIPS 204), a `JsonWebKey` with `kty "AKP"` and
//! `alg "ML-DSA-87"`. X25519 is a key agreement type and cannot verify
//! signatures. ES256K is not a FIPS approved algorithm.
//!
//! [aws-lc-rs]: https://docs.rs/aws-lc-rs

use aws_lc_rs::signature::{UnparsedPublicKey, ECDSA_P256K1_SHA256_FIXED, ED25519, ML_DSA_87};

use crate::document::{
    VerificationMaterial, VerificationMethodMap, JWK_ALG_ML_DSA_87, JWK_KTY_AKP,
    ML_DSA_87_PUBLIC_KEY_LEN, ML_DSA_87_SIGNATURE_LEN,
};
use crate::error::Error;
use crate::multikey::{self, KeyCodec};

/// Byte length of an Ed25519 signature.
pub const ED25519_SIGNATURE_LEN: usize = 64;

/// Byte length of an ES256K signature, `r || s`.
pub const SECP256K1_SIGNATURE_LEN: usize = 64;

/// True when the linked AWS-LC module is operating in FIPS mode
/// (feature `fips`).
pub fn fips_mode() -> bool {
    aws_lc_rs::try_fips_mode().is_ok()
}

/// Verify an Ed25519 signature over `message` with a raw 32 byte public
/// key.
pub fn verify_ed25519(
    public_key: &[u8; 32],
    message: &[u8],
    signature: &[u8],
) -> Result<(), Error> {
    if signature.len() != ED25519_SIGNATURE_LEN {
        return Err(Error::SignatureVerification);
    }
    UnparsedPublicKey::new(&ED25519, public_key)
        .verify(message, signature)
        .map_err(|_| Error::SignatureVerification)
}

/// Verify an ES256K signature over `message`, ECDSA over secp256k1 with
/// SHA-256 in the fixed `r || s` form, with a 33 byte compressed public key.
pub fn verify_secp256k1(
    public_key: &[u8; 33],
    message: &[u8],
    signature: &[u8],
) -> Result<(), Error> {
    if signature.len() != SECP256K1_SIGNATURE_LEN {
        return Err(Error::SignatureVerification);
    }
    UnparsedPublicKey::new(&ECDSA_P256K1_SHA256_FIXED, public_key)
        .verify(message, signature)
        .map_err(|_| Error::SignatureVerification)
}

/// Verify an ML-DSA-87 (FIPS 204) signature over `message` with a raw
/// 2592 byte public key.
pub fn verify_ml_dsa_87(public_key: &[u8], message: &[u8], signature: &[u8]) -> Result<(), Error> {
    if public_key.len() != ML_DSA_87_PUBLIC_KEY_LEN {
        return Err(Error::InvalidKeyLength {
            expected: ML_DSA_87_PUBLIC_KEY_LEN,
            actual: public_key.len(),
        });
    }
    if signature.len() != ML_DSA_87_SIGNATURE_LEN {
        return Err(Error::SignatureVerification);
    }
    UnparsedPublicKey::new(&ML_DSA_87, public_key)
        .verify(message, signature)
        .map_err(|_| Error::SignatureVerification)
}

/// Verify `signature` over `message` against a verification method map,
/// dispatching on its material type.
///
/// Returns [`Error::UnsupportedKeyType`] for X25519, which is key agreement
/// only, and for JWKs other than `AKP` with `ML-DSA-87`. Returns
/// [`Error::SignatureVerification`] when the signature does not verify.
pub fn verify_with_method(
    method: &VerificationMethodMap,
    message: &[u8],
    signature: &[u8],
) -> Result<(), Error> {
    match &method.material {
        VerificationMaterial::PublicKeyMultibase(encoded) => {
            let (codec, key) = multikey::decode(encoded)?;
            match codec {
                KeyCodec::Ed25519Pub => {
                    let key: [u8; 32] =
                        key.as_slice()
                            .try_into()
                            .map_err(|_| Error::InvalidKeyLength {
                                expected: 32,
                                actual: key.len(),
                            })?;
                    verify_ed25519(&key, message, signature)
                }
                KeyCodec::X25519Pub => Err(Error::UnsupportedKeyType(
                    "X25519 is a key-agreement type and cannot verify signatures",
                )),
                KeyCodec::Secp256k1Pub => {
                    let key: [u8; 33] =
                        key.as_slice()
                            .try_into()
                            .map_err(|_| Error::InvalidKeyLength {
                                expected: 33,
                                actual: key.len(),
                            })?;
                    verify_secp256k1(&key, message, signature)
                }
            }
        }
        VerificationMaterial::PublicKeyJwk(jwk) => {
            if jwk.kty != JWK_KTY_AKP || jwk.alg != JWK_ALG_ML_DSA_87 {
                return Err(Error::UnsupportedKeyType(
                    "only AKP/ML-DSA-87 JWKs are defined for did:bio",
                ));
            }
            verify_ml_dsa_87(&jwk.decode_public_key()?, message, signature)
        }
    }
}

/// Verify `signature` over `message` against the verification method
/// `vm_id`, a full DID URL or a bare fragment. The method must be listed by
/// reference under `relationship` in `document`.
///
/// A capability consumer performs this check to learn whether the DID's
/// document authorizes the key for the purpose and whether that key signed
/// the message.
pub fn verify_for_relationship(
    document: &crate::document::DidDocument,
    relationship: crate::document::VerificationRelationship,
    vm_id: &str,
    message: &[u8],
    signature: &[u8],
) -> Result<(), Error> {
    let method = document
        .verification_method_by_id(vm_id)
        .or_else(|| document.verification_method_by_fragment(vm_id))
        .ok_or(Error::VerificationMethodNotFound)?;
    if !document
        .relationship(relationship)
        .iter()
        .any(|reference| reference == &method.id)
    {
        return Err(Error::RelationshipNotGranted);
    }
    verify_with_method(method, message, signature)
}

#[cfg(test)]
mod tests {
    use aws_lc_rs::rand::SystemRandom;
    use aws_lc_rs::signature::{
        EcdsaKeyPair, Ed25519KeyPair, KeyPair, PqdsaKeyPair, ECDSA_P256K1_SHA256_FIXED_SIGNING,
        ML_DSA_87_SIGNING,
    };

    use super::*;
    use crate::document::{DidDocument, VerificationRelationship};
    use crate::resolve::generative_document;
    use crate::BioDid;

    #[test]
    fn ml_dsa_87_roundtrip() {
        let key_pair = PqdsaKeyPair::generate(&ML_DSA_87_SIGNING).unwrap();
        let public_key = key_pair.public_key().as_ref().to_vec();
        assert_eq!(public_key.len(), ML_DSA_87_PUBLIC_KEY_LEN);

        let message = b"post-quantum assertion for did:bio";
        let mut signature = vec![0u8; ML_DSA_87_SIGNATURE_LEN];
        let written = key_pair.sign(message, &mut signature).unwrap();
        assert_eq!(written, ML_DSA_87_SIGNATURE_LEN);

        let method = VerificationMethodMap::ml_dsa_87(
            "did:bio:devnet:test#pq".to_string(),
            "did:bio:devnet:test".to_string(),
            &public_key,
        )
        .unwrap();

        verify_with_method(&method, message, &signature).unwrap();
        assert_eq!(
            verify_with_method(&method, b"tampered", &signature),
            Err(Error::SignatureVerification)
        );
        let mut bad_signature = signature.clone();
        bad_signature[0] ^= 1;
        assert_eq!(
            verify_with_method(&method, message, &bad_signature),
            Err(Error::SignatureVerification)
        );
    }

    #[test]
    fn ed25519_roundtrip_through_generative_document() {
        let key_pair = Ed25519KeyPair::generate().unwrap();
        let subject: [u8; 32] = key_pair.public_key().as_ref().try_into().unwrap();
        let did = BioDid::new(crate::Network::Devnet, subject);
        let document: DidDocument = generative_document(&did).unwrap();

        let message = b"authenticate as the subject key";
        let signature = key_pair.sign(message);

        verify_for_relationship(
            &document,
            VerificationRelationship::Authentication,
            "default",
            message,
            signature.as_ref(),
        )
        .unwrap();
        verify_for_relationship(
            &document,
            VerificationRelationship::CapabilityInvocation,
            &did.default_verification_method_id(),
            message,
            signature.as_ref(),
        )
        .unwrap();
        assert!(verify_for_relationship(
            &document,
            VerificationRelationship::Authentication,
            "default",
            b"different message",
            signature.as_ref(),
        )
        .is_err());
        assert_eq!(
            verify_for_relationship(
                &document,
                VerificationRelationship::Authentication,
                "missing",
                message,
                signature.as_ref(),
            ),
            Err(Error::VerificationMethodNotFound)
        );

        // A document whose only method holds no authentication.
        let mut narrowed = document.clone();
        narrowed.authentication.clear();
        assert_eq!(
            verify_for_relationship(
                &narrowed,
                VerificationRelationship::Authentication,
                "default",
                message,
                signature.as_ref(),
            ),
            Err(Error::RelationshipNotGranted)
        );
    }

    #[test]
    fn es256k_roundtrip_with_a_compressed_key() {
        let key_pair = EcdsaKeyPair::generate(&ECDSA_P256K1_SHA256_FIXED_SIGNING).unwrap();
        let uncompressed = key_pair.public_key().as_ref();
        assert_eq!(uncompressed.len(), 65);
        let mut compressed = vec![2 + (uncompressed[64] & 1)];
        compressed.extend_from_slice(&uncompressed[1..33]);
        let method = VerificationMethodMap::multikey(
            "did:bio:devnet:test#evm".to_string(),
            "did:bio:devnet:test".to_string(),
            KeyCodec::Secp256k1Pub,
            &compressed,
        )
        .unwrap();

        let message = b"an assertion signed by an Ethereum style key";
        let signature = key_pair.sign(&SystemRandom::new(), message).unwrap();
        verify_with_method(&method, message, signature.as_ref()).unwrap();
        assert_eq!(
            verify_with_method(&method, b"tampered", signature.as_ref()),
            Err(Error::SignatureVerification)
        );
        assert_eq!(
            verify_with_method(&method, message, &signature.as_ref()[..63]),
            Err(Error::SignatureVerification)
        );
    }

    #[test]
    fn unsupported_key_types_are_rejected() {
        let x25519 = VerificationMethodMap::multikey(
            "did:bio:devnet:test#agree".to_string(),
            "did:bio:devnet:test".to_string(),
            KeyCodec::X25519Pub,
            &[1u8; 32],
        )
        .unwrap();
        assert!(matches!(
            verify_with_method(&x25519, b"m", &[0u8; 64]),
            Err(Error::UnsupportedKeyType(_))
        ));
    }
}
