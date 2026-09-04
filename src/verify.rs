//! Signature verification for `did:bio` verification methods
//! (features `verify` / `fips`).
//!
//! Backed by [aws-lc-rs]. With the `fips` feature the FIPS validated
//! AWS-LC module is linked instead; the API is identical. Call
//! [`fips_mode`] to confirm at runtime.
//!
//! Supported algorithms follow the method's verification material types
//! (spec Section 5.2): **Ed25519** (`Multikey`, `z6Mk...`) and **ML-DSA-87**
//! (FIPS 204; `JsonWebKey` with `kty "AKP"`, `alg "ML-DSA-87"`).
//! X25519 is a key agreement type and cannot verify signatures;
//! secp256k1 verification is out of scope for this crate.
//!
//! [aws-lc-rs]: https://docs.rs/aws-lc-rs

use aws_lc_rs::signature::{UnparsedPublicKey, ED25519, ML_DSA_87};

use crate::document::{
    VerificationMaterial, VerificationMethodMap, JWK_ALG_ML_DSA_87, JWK_KTY_AKP,
    ML_DSA_87_PUBLIC_KEY_LEN, ML_DSA_87_SIGNATURE_LEN,
};
use crate::error::Error;
use crate::multikey::{self, KeyCodec};

/// Byte length of an Ed25519 signature.
pub const ED25519_SIGNATURE_LEN: usize = 64;

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
/// Errors with [`Error::UnsupportedKeyType`] for X25519 (key agreement
/// only), secp256k1 (not provided by this crate), and JWKs other than
/// `AKP`/`ML-DSA-87`; with [`Error::SignatureVerification`] when the
/// signature does not verify.
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
                KeyCodec::Secp256k1Pub => Err(Error::UnsupportedKeyType(
                    "secp256k1 signature verification is not provided by this crate",
                )),
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
/// `vm_id` (a full DID URL or bare fragment), requiring that the method
/// is listed in `relationship` (by reference) in `document`.
///
/// This is the check a capability consumer performs: "does this DID's
/// document authorize this key for this purpose, and did that key sign
/// this message?"
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
        .ok_or(Error::UnsupportedKeyType(
            "verification method not found in document",
        ))?;
    if !document
        .relationship(relationship)
        .iter()
        .any(|reference| reference == &method.id)
    {
        return Err(Error::UnsupportedKeyType(
            "verification method is not authorized for this relationship",
        ));
    }
    verify_with_method(method, message, signature)
}

#[cfg(test)]
mod tests {
    use aws_lc_rs::signature::{Ed25519KeyPair, KeyPair, PqdsaKeyPair, ML_DSA_87_SIGNING};

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
        let document: DidDocument = generative_document(&did);

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

        let secp = VerificationMethodMap::multikey(
            "did:bio:devnet:test#evm".to_string(),
            "did:bio:devnet:test".to_string(),
            KeyCodec::Secp256k1Pub,
            &[2u8; 33],
        )
        .unwrap();
        assert!(matches!(
            verify_with_method(&secp, b"m", &[0u8; 64]),
            Err(Error::UnsupportedKeyType(_))
        ));
    }
}
