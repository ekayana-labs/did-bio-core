//! W3C DID document data model for `did:bio` (spec Section 5) and the DID
//! Resolution result envelope (spec Section 6.2).

use serde::{Deserialize, Serialize};

use crate::error::Error;
use crate::multikey::{self, KeyCodec};

/// JSON-LD context: W3C DID v1.0 core.
pub const CONTEXT_DID_V1: &str = "https://www.w3.org/ns/did/v1";
/// JSON-LD context: Controlled Identifiers v1.0 (defines `Multikey` and
/// `JsonWebKey`).
pub const CONTEXT_CID_V1: &str = "https://www.w3.org/ns/cid/v1";

/// Media type of the JSON-LD representation (DID 1.0).
pub const MEDIA_TYPE_DID_LD_JSON: &str = "application/did+ld+json";
/// Media type of the plain JSON representation (DID 1.0).
pub const MEDIA_TYPE_DID_JSON: &str = "application/did+json";
/// Media type registered by DID 1.1, replacing both of the above; carries
/// the same JSON-LD serialization (spec Section 2).
pub const MEDIA_TYPE_DID: &str = "application/did";

/// Verification method `type` for Multikey encoded keys.
pub const VM_TYPE_MULTIKEY: &str = "Multikey";
/// Verification method `type` for JWK encoded keys (ML-DSA-87).
pub const VM_TYPE_JSON_WEB_KEY: &str = "JsonWebKey";

/// JWK `kty` for ML-DSA keys per draft-ietf-cose-dilithium (provisional,
/// spec Section 5.2).
pub const JWK_KTY_AKP: &str = "AKP";
/// JWK `alg` for ML-DSA-87 (FIPS 204).
pub const JWK_ALG_ML_DSA_87: &str = "ML-DSA-87";

/// Byte length of an ML-DSA-87 public key (FIPS 204).
pub const ML_DSA_87_PUBLIC_KEY_LEN: usize = 2592;
/// Byte length of an ML-DSA-87 signature (FIPS 204).
pub const ML_DSA_87_SIGNATURE_LEN: usize = 4627;

/// The default `@context` array of every `did:bio` document (spec Section 5.1).
pub fn default_context() -> Vec<String> {
    vec![CONTEXT_DID_V1.to_string(), CONTEXT_CID_V1.to_string()]
}

fn base64url(bytes: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

/// An `AKP` public JWK carrying an ML-DSA public key
/// (draft-ietf-cose-dilithium; provisional until IETF registration is
/// final - spec Section 5.2).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AkpPublicJwk {
    /// Key type; always `"AKP"`.
    pub kty: String,
    /// Algorithm; `"ML-DSA-87"` for this method.
    pub alg: String,
    /// Public key bytes, base64url without padding.
    #[serde(rename = "pub")]
    pub public_key: String,
}

impl AkpPublicJwk {
    /// Build the JWK for an ML-DSA-87 public key.
    pub fn ml_dsa_87(public_key: &[u8]) -> Result<Self, Error> {
        if public_key.len() != ML_DSA_87_PUBLIC_KEY_LEN {
            return Err(Error::InvalidKeyLength {
                expected: ML_DSA_87_PUBLIC_KEY_LEN,
                actual: public_key.len(),
            });
        }
        Ok(AkpPublicJwk {
            kty: JWK_KTY_AKP.to_string(),
            alg: JWK_ALG_ML_DSA_87.to_string(),
            public_key: base64url(public_key),
        })
    }

    /// Decode the `pub` member to raw key bytes.
    pub fn decode_public_key(&self) -> Result<Vec<u8>, Error> {
        use base64::Engine as _;
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(&self.public_key)
            .map_err(|_| Error::InvalidMultikey("JWK `pub` is not valid base64url"))
    }
}

/// The single verification material property of a verification method
/// (spec Section 5.2: exactly one per method).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum VerificationMaterial {
    /// `publicKeyMultibase` - Multikey encoded key material.
    #[serde(rename = "publicKeyMultibase")]
    PublicKeyMultibase(String),
    /// `publicKeyJwk` - JWK key material (ML-DSA-87).
    #[serde(rename = "publicKeyJwk")]
    PublicKeyJwk(AkpPublicJwk),
}

/// A verification method map (spec Section 5.2).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VerificationMethodMap {
    /// DID URL of this method: `<did>#<fragment>`.
    pub id: String,
    /// `Multikey` or `JsonWebKey`.
    #[serde(rename = "type")]
    pub method_type: String,
    /// The DID that controls this method.
    pub controller: String,
    /// The verification material property.
    #[serde(flatten)]
    pub material: VerificationMaterial,
}

impl VerificationMethodMap {
    /// Build a `Multikey` verification method from raw key bytes.
    pub fn multikey(
        id: String,
        controller: String,
        codec: KeyCodec,
        key: &[u8],
    ) -> Result<Self, Error> {
        Ok(VerificationMethodMap {
            id,
            method_type: VM_TYPE_MULTIKEY.to_string(),
            controller,
            material: VerificationMaterial::PublicKeyMultibase(multikey::encode(codec, key)?),
        })
    }

    /// Build the `JsonWebKey` verification method for an ML-DSA-87 key.
    pub fn ml_dsa_87(id: String, controller: String, key: &[u8]) -> Result<Self, Error> {
        Ok(VerificationMethodMap {
            id,
            method_type: VM_TYPE_JSON_WEB_KEY.to_string(),
            controller,
            material: VerificationMaterial::PublicKeyJwk(AkpPublicJwk::ml_dsa_87(key)?),
        })
    }

    /// The fragment of this method's `id` (text after `#`), if any.
    pub fn fragment(&self) -> Option<&str> {
        self.id.split_once('#').map(|(_, fragment)| fragment)
    }

    /// Decode this method's public key to raw bytes, regardless of
    /// encoding.
    pub fn decode_key(&self) -> Result<Vec<u8>, Error> {
        match &self.material {
            VerificationMaterial::PublicKeyMultibase(mb) => Ok(multikey::decode(mb)?.1),
            VerificationMaterial::PublicKeyJwk(jwk) => jwk.decode_public_key(),
        }
    }
}

/// A service map (spec Section 5.4).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceMap {
    /// DID URL of this service: `<did>#<fragment>`.
    pub id: String,
    /// Service type, e.g. `BioMetadata`.
    #[serde(rename = "type")]
    pub service_type: String,
    /// Service endpoint URI.
    #[serde(rename = "serviceEndpoint")]
    pub service_endpoint: String,
}

/// A `did:bio` DID document (spec Section 5).
///
/// Field order matches the serialization shown in the spec. Empty arrays
/// are omitted from serialization; a deactivated document (spec Section 5.7)
/// therefore serializes as `{"@context": [...], "id": "<did>"}`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct DidDocument {
    /// JSON-LD contexts (spec Section 5.1).
    #[serde(rename = "@context")]
    pub context: Vec<String>,
    /// The DID this document describes.
    pub id: String,
    /// Controller DIDs (spec Section 5.5).
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub controller: Vec<String>,
    /// Verification methods (spec Section 5.2).
    #[serde(
        rename = "verificationMethod",
        skip_serializing_if = "Vec::is_empty",
        default
    )]
    pub verification_method: Vec<VerificationMethodMap>,
    /// `authentication` relationship (by reference).
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub authentication: Vec<String>,
    /// `assertionMethod` relationship (by reference).
    #[serde(
        rename = "assertionMethod",
        skip_serializing_if = "Vec::is_empty",
        default
    )]
    pub assertion_method: Vec<String>,
    /// `keyAgreement` relationship (by reference).
    #[serde(
        rename = "keyAgreement",
        skip_serializing_if = "Vec::is_empty",
        default
    )]
    pub key_agreement: Vec<String>,
    /// `capabilityInvocation` relationship (by reference).
    #[serde(
        rename = "capabilityInvocation",
        skip_serializing_if = "Vec::is_empty",
        default
    )]
    pub capability_invocation: Vec<String>,
    /// `capabilityDelegation` relationship (by reference).
    #[serde(
        rename = "capabilityDelegation",
        skip_serializing_if = "Vec::is_empty",
        default
    )]
    pub capability_delegation: Vec<String>,
    /// Services (spec Section 5.4).
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub service: Vec<ServiceMap>,
}

/// The five W3C DID verification relationships (spec Section 5.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum VerificationRelationship {
    /// `authentication`.
    Authentication,
    /// `assertionMethod`.
    AssertionMethod,
    /// `keyAgreement`.
    KeyAgreement,
    /// `capabilityInvocation`.
    CapabilityInvocation,
    /// `capabilityDelegation`.
    CapabilityDelegation,
}

impl DidDocument {
    /// The references listed under a verification relationship.
    pub fn relationship(&self, relationship: VerificationRelationship) -> &[String] {
        match relationship {
            VerificationRelationship::Authentication => &self.authentication,
            VerificationRelationship::AssertionMethod => &self.assertion_method,
            VerificationRelationship::KeyAgreement => &self.key_agreement,
            VerificationRelationship::CapabilityInvocation => &self.capability_invocation,
            VerificationRelationship::CapabilityDelegation => &self.capability_delegation,
        }
    }

    /// Find a verification method by its full DID URL `id`.
    pub fn verification_method_by_id(&self, id: &str) -> Option<&VerificationMethodMap> {
        self.verification_method.iter().find(|vm| vm.id == id)
    }

    /// Find a verification method by bare fragment (without `#`).
    pub fn verification_method_by_fragment(
        &self,
        fragment: &str,
    ) -> Option<&VerificationMethodMap> {
        self.verification_method
            .iter()
            .find(|vm| vm.fragment() == Some(fragment))
    }

    /// Find a service by bare fragment (without `#`).
    pub fn service_by_fragment(&self, fragment: &str) -> Option<&ServiceMap> {
        self.service
            .iter()
            .find(|s| s.id.split_once('#').map(|(_, f)| f) == Some(fragment))
    }
}

/// `didDocumentMetadata` (spec Section 6.2).
///
/// All members are optional so that the unsuccessful resolution case
/// serializes as the empty structure required by DID Resolution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct DidDocumentMetadata {
    /// Whether the DID is permanently deactivated (spec Section 5.7).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub deactivated: Option<bool>,
    /// The registry `version` counter as a decimal string; `"0"` for a
    /// generative document.
    #[serde(rename = "versionId", skip_serializing_if = "Option::is_none", default)]
    pub version_id: Option<String>,
    /// XML datetime of the last registry update; absent for generative
    /// documents.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub updated: Option<String>,
}

impl DidDocumentMetadata {
    /// Metadata of a generative document: `versionId "0"`, not deactivated
    /// (spec Section 6.2 step 6).
    pub fn generative() -> Self {
        DidDocumentMetadata {
            deactivated: Some(false),
            version_id: Some("0".to_string()),
            updated: None,
        }
    }

    /// Metadata of a materialized registry backed document (spec Section 6.2
    /// steps 8-9).
    pub fn registered(deactivated: bool, version: u64, updated_at: i64) -> Self {
        DidDocumentMetadata {
            deactivated: Some(deactivated),
            version_id: Some(version.to_string()),
            updated: Some(crate::datetime::xml_datetime(updated_at)),
        }
    }
}

/// `didResolutionMetadata` (spec Section 6.2).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct DidResolutionMetadata {
    /// Media type of the returned representation.
    #[serde(
        rename = "contentType",
        skip_serializing_if = "Option::is_none",
        default
    )]
    pub content_type: Option<String>,
    /// DID Resolution error code, present only on failure.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub error: Option<String>,
}

/// A complete DID Resolution result: resolution metadata, document, and
/// document metadata.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DidResolution {
    /// Metadata about the resolution process.
    #[serde(rename = "didResolutionMetadata")]
    pub resolution_metadata: DidResolutionMetadata,
    /// The resolved document; `null` on failure.
    #[serde(rename = "didDocument")]
    pub document: Option<DidDocument>,
    /// Metadata about the document; the empty structure on failure.
    #[serde(rename = "didDocumentMetadata")]
    pub document_metadata: DidDocumentMetadata,
}

impl DidResolution {
    /// A successful resolution carrying the JSON-LD content type.
    pub fn success(document: DidDocument, document_metadata: DidDocumentMetadata) -> Self {
        DidResolution {
            resolution_metadata: DidResolutionMetadata {
                content_type: Some(MEDIA_TYPE_DID_LD_JSON.to_string()),
                error: None,
            },
            document: Some(document),
            document_metadata,
        }
    }

    /// A failed resolution carrying a DID Resolution error code (e.g.
    /// [`crate::resolution_error::INVALID_DID`]).
    pub fn error(code: &str) -> Self {
        DidResolution {
            resolution_metadata: DidResolutionMetadata {
                content_type: None,
                error: Some(code.to_string()),
            },
            document: None,
            document_metadata: DidDocumentMetadata::default(),
        }
    }
}
