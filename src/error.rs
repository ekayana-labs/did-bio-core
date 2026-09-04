//! Crate error type and W3C DID Resolution error codes.

use core::fmt;

/// Errors produced by parsing, encoding, and account deserialization.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// The DID does not conform to the `did:bio` ABNF (spec Section 4.1) or its
    /// `idstring` does not decode to a 32 byte key (spec Section 6.2 step 3).
    InvalidDid(&'static str),
    /// The DID URL is not a `did:bio` DID with an optional valid fragment.
    InvalidDidUrl(&'static str),
    /// A `publicKeyMultibase` value is not a well formed Multikey.
    InvalidMultikey(&'static str),
    /// Key material length does not match the verification method type.
    InvalidKeyLength {
        /// Length required by the key type.
        expected: usize,
        /// Length actually supplied.
        actual: usize,
    },
    /// Registry account bytes failed the discriminator check or Borsh
    /// deserialization (spec Section 6.2 step 7).
    InvalidAccountData(&'static str),
    /// The operation is not defined for this verification method type
    /// (e.g. signature verification with an X25519 key agreement key).
    UnsupportedKeyType(&'static str),
    /// A signature did not verify against the given key and message.
    SignatureVerification,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::InvalidDid(reason) => write!(f, "invalid did:bio DID: {reason}"),
            Error::InvalidDidUrl(reason) => write!(f, "invalid did:bio DID URL: {reason}"),
            Error::InvalidMultikey(reason) => write!(f, "invalid Multikey: {reason}"),
            Error::InvalidKeyLength { expected, actual } => {
                write!(
                    f,
                    "invalid key length: expected {expected} bytes, got {actual}"
                )
            }
            Error::InvalidAccountData(reason) => {
                write!(f, "invalid registry account data: {reason}")
            }
            Error::UnsupportedKeyType(reason) => {
                write!(f, "unsupported key type for this operation: {reason}")
            }
            Error::SignatureVerification => write!(f, "signature verification failed"),
        }
    }
}

impl std::error::Error for Error {}

/// Registered DID Resolution error codes used by this method.
pub mod resolution_error {
    /// The input DID violates the method syntax.
    pub const INVALID_DID: &str = "invalidDid";
    /// The input DID URL violates DID URL syntax.
    pub const INVALID_DID_URL: &str = "invalidDidUrl";
    /// An unexpected internal condition (e.g. undecodable registry state).
    pub const INTERNAL_ERROR: &str = "internalError";
}

impl Error {
    /// The DID Resolution `didResolutionMetadata.error` code corresponding to
    /// this error when it occurs during resolution.
    pub fn resolution_error_code(&self) -> &'static str {
        match self {
            Error::InvalidDid(_) => resolution_error::INVALID_DID,
            Error::InvalidDidUrl(_) => resolution_error::INVALID_DID_URL,
            _ => resolution_error::INTERNAL_ERROR,
        }
    }
}
