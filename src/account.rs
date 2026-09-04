//! The `bio-did-registry` on chain account model (spec Section 5, Section 6) and a
//! dependency free decoder for its Borsh account format.
//!
//! Constants here mirror the registry program, which is the source of
//! truth; parity is enforced by tests in the registry repository.

use crate::error::Error;

/// The registry program ID, base58 (spec Section 6.2 step 4).
pub const PROGRAM_ID_STR: &str = "H1gnV4GjNT3UV7AgGNUCkSaciuVVtM7hKb8JhPV3Xxy6";

/// The registry program ID as raw bytes.
pub const PROGRAM_ID: [u8; 32] = [
    237, 231, 249, 151, 37, 50, 249, 249, 121, 199, 216, 89, 60, 64, 106, 126, 73, 234, 235, 163,
    34, 110, 199, 209, 203, 31, 235, 20, 60, 254, 180, 65,
];

/// PDA seed prefix for DID accounts: `["bio-did", subject]` (spec Section 4.4).
pub const DID_SEED: &[u8] = b"bio-did";

/// Reserved fragment of the subject key's verification method (spec Section 5.6).
pub const DEFAULT_FRAGMENT: &str = "default";

/// Account discriminator: `sha256("account:DidAccount")[..8]`
/// (spec Section 6.2 step 7).
pub const ACCOUNT_DISCRIMINATOR: [u8; 8] = [77, 88, 239, 141, 251, 29, 237, 243];

/// Maximum number of verification methods per DID (spec Section 6.3).
pub const MAX_VERIFICATION_METHODS: usize = 16;
/// Maximum number of services per DID (spec Section 6.3).
pub const MAX_SERVICES: usize = 16;
/// Maximum number of native (Solana key) controllers (spec Section 6.3).
pub const MAX_NATIVE_CONTROLLERS: usize = 8;
/// Maximum number of external controller DID strings (spec Section 6.3).
pub const MAX_OTHER_CONTROLLERS: usize = 8;
/// Maximum fragment length, without the leading `#` (spec Section 6.3).
pub const MAX_FRAGMENT_LEN: usize = 32;
/// Maximum service type length (spec Section 6.3).
pub const MAX_SERVICE_TYPE_LEN: usize = 64;
/// Maximum service endpoint length (spec Section 6.3).
pub const MAX_ENDPOINT_LEN: usize = 512;
/// Maximum external controller DID string length (spec Section 6.3).
pub const MAX_CONTROLLER_LEN: usize = 128;
/// Maximum verification key material size (fits ML-DSA-87).
pub const MAX_KEY_DATA_LEN: usize = 2592;

/// Verification method flag bits (spec Section 5.3).
pub mod vm_flags {
    /// Listed in `authentication`.
    pub const AUTHENTICATION: u16 = 1 << 0;
    /// Listed in `assertionMethod`.
    pub const ASSERTION: u16 = 1 << 1;
    /// Listed in `keyAgreement`.
    pub const KEY_AGREEMENT: u16 = 1 << 2;
    /// Listed in `capabilityInvocation`; grants on chain update authority
    /// (Ed25519 methods only).
    pub const CAPABILITY_INVOCATION: u16 = 1 << 3;
    /// Listed in `capabilityDelegation`.
    pub const CAPABILITY_DELEGATION: u16 = 1 << 4;
    /// Method internal: only the method's own key may add it, change its
    /// flags, or remove it. Not expressed in the DID document.
    pub const PROTECTED: u16 = 1 << 8;

    /// The five W3C verification relationship bits.
    pub const RELATIONSHIP_MASK: u16 =
        AUTHENTICATION | ASSERTION | KEY_AGREEMENT | CAPABILITY_INVOCATION | CAPABILITY_DELEGATION;
    /// Every bit the registry accepts.
    pub const VALID_MASK: u16 = RELATIONSHIP_MASK | PROTECTED;
    /// Flags of the subject's initial `#default` method: all five
    /// relationships, protected.
    pub const DEFAULT: u16 = RELATIONSHIP_MASK | PROTECTED;
}

/// On chain verification key algorithm (spec Section 5.2).
///
/// Discriminant values are the on chain Borsh enum tags.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum KeyType {
    /// 32 byte Ed25519 public key -> `Multikey` (`z6Mk...`).
    Ed25519 = 0,
    /// 32 byte X25519 key agreement key -> `Multikey` (`z6LS...`).
    X25519 = 1,
    /// 33 byte compressed secp256k1 key -> `Multikey` (`zQ3s...`).
    Secp256k1 = 2,
    /// 2592 byte ML-DSA-87 (FIPS 204) public key -> `JsonWebKey`.
    ///
    /// Stored on chain under the legacy name `Dilithium5` (the parameter
    /// set ML-DSA-87 derives from). Final ML-DSA-87 is **not**
    /// interoperable with the earlier round 3 Dilithium5.
    MlDsa87 = 3,
}

impl KeyType {
    /// Decode an on chain Borsh enum tag.
    pub fn from_tag(tag: u8) -> Option<KeyType> {
        match tag {
            0 => Some(KeyType::Ed25519),
            1 => Some(KeyType::X25519),
            2 => Some(KeyType::Secp256k1),
            3 => Some(KeyType::MlDsa87),
            _ => None,
        }
    }

    /// Required key material length in bytes.
    pub const fn expected_key_len(self) -> usize {
        match self {
            KeyType::Ed25519 | KeyType::X25519 => 32,
            KeyType::Secp256k1 => 33,
            KeyType::MlDsa87 => crate::document::ML_DSA_87_PUBLIC_KEY_LEN,
        }
    }

    /// The identifier used by the on chain program for this type.
    pub const fn on_chain_name(self) -> &'static str {
        match self {
            KeyType::Ed25519 => "Ed25519",
            KeyType::X25519 => "X25519",
            KeyType::Secp256k1 => "Secp256k1",
            KeyType::MlDsa87 => "Dilithium5",
        }
    }

    /// The DID document verification method `type` this key materializes
    /// as (spec Section 5.2).
    pub const fn document_type(self) -> &'static str {
        match self {
            KeyType::MlDsa87 => crate::document::VM_TYPE_JSON_WEB_KEY,
            _ => crate::document::VM_TYPE_MULTIKEY,
        }
    }

    /// The Multikey codec for this key type; `None` for ML-DSA-87, which
    /// uses a JWK.
    pub const fn key_codec(self) -> Option<crate::multikey::KeyCodec> {
        match self {
            KeyType::Ed25519 => Some(crate::multikey::KeyCodec::Ed25519Pub),
            KeyType::X25519 => Some(crate::multikey::KeyCodec::X25519Pub),
            KeyType::Secp256k1 => Some(crate::multikey::KeyCodec::Secp256k1Pub),
            KeyType::MlDsa87 => None,
        }
    }
}

/// A stored verification method record (spec Section 5.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredVerificationMethod {
    /// Fragment identifier without the leading `#`.
    pub fragment: String,
    /// Key algorithm.
    pub method_type: KeyType,
    /// Bitwise OR of [`vm_flags`] values.
    pub flags: u16,
    /// Raw public key bytes; length matches `method_type`.
    pub key_data: Vec<u8>,
}

impl StoredVerificationMethod {
    /// True when `flag` (a [`vm_flags`] constant) is set.
    pub const fn has_flag(&self, flag: u16) -> bool {
        self.flags & flag != 0
    }
}

/// A stored service record (spec Section 5.4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredService {
    /// Fragment identifier without the leading `#`.
    pub fragment: String,
    /// Service type, e.g. `BioMetadata`.
    pub service_type: String,
    /// Service endpoint URI.
    pub endpoint: String,
}

/// Deserialized state of a `DidAccount` registry entry.
///
/// Mirrors the on chain `DidAccount` struct of the registry program.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DidAccountState {
    /// Monotonic update counter; reported as `versionId`.
    pub version: u64,
    /// PDA bump seed.
    pub bump: u8,
    /// The Ed25519 subject key (the DID's method specific id).
    pub subject: [u8; 32],
    /// True once permanently deactivated (tombstone, spec Section 6.4).
    pub deactivated: bool,
    /// Unix timestamp of the last update.
    pub updated_at: i64,
    /// `did:bio` controllers as raw Solana keys (spec Section 5.5).
    pub native_controllers: Vec<[u8; 32]>,
    /// Controllers from other DID methods, verbatim DID strings.
    pub other_controllers: Vec<String>,
    /// Verification method records.
    pub verification_methods: Vec<StoredVerificationMethod>,
    /// Service records.
    pub services: Vec<StoredService>,
}

impl DidAccountState {
    /// The generative default state for a subject key: exactly what
    /// `initialize` writes on chain, except `version` is 0 (spec Section 5.6,
    /// Section 6.1). Used to materialize the generative document.
    pub fn generative(subject: [u8; 32]) -> Self {
        DidAccountState {
            version: 0,
            bump: 0,
            subject,
            deactivated: false,
            updated_at: 0,
            native_controllers: Vec::new(),
            other_controllers: Vec::new(),
            verification_methods: vec![StoredVerificationMethod {
                fragment: DEFAULT_FRAGMENT.to_string(),
                method_type: KeyType::Ed25519,
                flags: vm_flags::DEFAULT,
                key_data: subject.to_vec(),
            }],
            services: Vec::new(),
        }
    }

    /// Decode registry account data: verify the 8 byte discriminator, then
    /// read the Borsh encoded state (spec Section 6.2 step 7).
    ///
    /// Trailing bytes after the state are ignored.
    pub fn from_account_data(data: &[u8]) -> Result<Self, Error> {
        if data.len() < ACCOUNT_DISCRIMINATOR.len() {
            return Err(Error::InvalidAccountData("shorter than the discriminator"));
        }
        let (disc, body) = data.split_at(ACCOUNT_DISCRIMINATOR.len());
        if disc != ACCOUNT_DISCRIMINATOR {
            return Err(Error::InvalidAccountData("discriminator mismatch"));
        }
        let mut cursor = Cursor { data: body, pos: 0 };
        let state = DidAccountState {
            version: cursor.read_u64()?,
            bump: cursor.read_u8()?,
            subject: cursor.read_array32()?,
            deactivated: cursor.read_bool()?,
            updated_at: cursor.read_i64()?,
            native_controllers: cursor.read_vec(Cursor::read_array32)?,
            other_controllers: cursor.read_vec(Cursor::read_string)?,
            verification_methods: cursor.read_vec(Cursor::read_verification_method)?,
            services: cursor.read_vec(Cursor::read_service)?,
        };
        Ok(state)
    }

    /// True when `key` may authorize updates: it matches an Ed25519 method
    /// carrying `CAPABILITY_INVOCATION`, and the DID is not deactivated
    /// (spec Section 6 Authorization).
    pub fn is_authority(&self, key: &[u8; 32]) -> bool {
        !self.deactivated
            && self.verification_methods.iter().any(|vm| {
                vm.method_type == KeyType::Ed25519
                    && vm.has_flag(vm_flags::CAPABILITY_INVOCATION)
                    && vm.key_data.as_slice() == key
            })
    }

    /// Number of Ed25519 methods holding `CAPABILITY_INVOCATION` (the
    /// last authority invariant counts these, spec Section 6).
    pub fn authority_count(&self) -> usize {
        self.verification_methods
            .iter()
            .filter(|vm| {
                vm.method_type == KeyType::Ed25519 && vm.has_flag(vm_flags::CAPABILITY_INVOCATION)
            })
            .count()
    }

    /// Find a verification method by fragment.
    pub fn find_verification_method(&self, fragment: &str) -> Option<&StoredVerificationMethod> {
        self.verification_methods
            .iter()
            .find(|vm| vm.fragment == fragment)
    }

    /// Find a service by fragment.
    pub fn find_service(&self, fragment: &str) -> Option<&StoredService> {
        self.services.iter().find(|s| s.fragment == fragment)
    }
}

/// Minimal Borsh reader over the account body. Every length prefix is
/// validated against the remaining input before any allocation, so
/// malformed or hostile data fails fast instead of over allocating.
struct Cursor<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn remaining(&self) -> usize {
        self.data.len() - self.pos
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], Error> {
        if self.remaining() < n {
            return Err(Error::InvalidAccountData("truncated account data"));
        }
        let slice = &self.data[self.pos..self.pos + n];
        self.pos += n;
        Ok(slice)
    }

    fn read_u8(&mut self) -> Result<u8, Error> {
        Ok(self.take(1)?[0])
    }

    fn read_bool(&mut self) -> Result<bool, Error> {
        match self.read_u8()? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(Error::InvalidAccountData("invalid boolean byte")),
        }
    }

    fn read_u16(&mut self) -> Result<u16, Error> {
        let b = self.take(2)?;
        Ok(u16::from_le_bytes([b[0], b[1]]))
    }

    fn read_u32(&mut self) -> Result<u32, Error> {
        let b = self.take(4)?;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }

    fn read_u64(&mut self) -> Result<u64, Error> {
        let b = self.take(8)?;
        Ok(u64::from_le_bytes(b.try_into().expect("8 bytes")))
    }

    fn read_i64(&mut self) -> Result<i64, Error> {
        Ok(self.read_u64()? as i64)
    }

    fn read_array32(&mut self) -> Result<[u8; 32], Error> {
        Ok(self.take(32)?.try_into().expect("32 bytes"))
    }

    /// Read a `u32` length prefix, bounded by the remaining bytes divided
    /// by the minimum encoded size of one element.
    fn read_len(&mut self, min_element_size: usize) -> Result<usize, Error> {
        let len = self.read_u32()? as usize;
        if len > self.remaining() / min_element_size.max(1) {
            return Err(Error::InvalidAccountData("length prefix exceeds data"));
        }
        Ok(len)
    }

    fn read_byte_vec(&mut self) -> Result<Vec<u8>, Error> {
        let len = self.read_len(1)?;
        Ok(self.take(len)?.to_vec())
    }

    fn read_string(&mut self) -> Result<String, Error> {
        String::from_utf8(self.read_byte_vec()?)
            .map_err(|_| Error::InvalidAccountData("string is not valid UTF-8"))
    }

    fn read_vec<T>(
        &mut self,
        mut read_element: impl FnMut(&mut Self) -> Result<T, Error>,
    ) -> Result<Vec<T>, Error> {
        // Minimum element size 1 keeps the bound conservative for
        // variable size elements.
        let len = self.read_len(1)?;
        let mut out = Vec::with_capacity(len);
        for _ in 0..len {
            out.push(read_element(self)?);
        }
        Ok(out)
    }

    fn read_verification_method(&mut self) -> Result<StoredVerificationMethod, Error> {
        Ok(StoredVerificationMethod {
            fragment: self.read_string()?,
            method_type: KeyType::from_tag(self.read_u8()?).ok_or(Error::InvalidAccountData(
                "unknown verification method type tag",
            ))?,
            flags: self.read_u16()?,
            key_data: self.read_byte_vec()?,
        })
    }

    fn read_service(&mut self) -> Result<StoredService, Error> {
        Ok(StoredService {
            fragment: self.read_string()?,
            service_type: self.read_string()?,
            endpoint: self.read_string()?,
        })
    }
}
