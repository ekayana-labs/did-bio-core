//! The `bio-did-registry` on chain account model (spec Section 5, Section 6)
//! and a dependency free decoder for its Borsh account format.
//!
//! Constants here mirror the registry program, which is the source of
//! truth. The parity tests in the resolver repository check them against
//! the program crate.

use crate::error::Error;

/// The registry program ID, base58 (spec Section 6.2 step 4).
pub const PROGRAM_ID_STR: &str = "H1gnV4GjNT3UV7AgGNUCkSaciuVVtM7hKb8JhPV3Xxy6";

/// The registry program ID as raw bytes.
pub const PROGRAM_ID: [u8; 32] = [
    237, 231, 249, 151, 37, 50, 249, 249, 121, 199, 216, 89, 60, 64, 106, 126, 73, 234, 235, 163,
    34, 110, 199, 209, 203, 31, 235, 20, 60, 254, 180, 65,
];

/// PDA seed prefix for DID accounts, whose seeds are `["bio-did", subject]`
/// (spec Section 4.4).
pub const DID_SEED: &[u8] = b"bio-did";

/// Seed prefix of an owned subject, which `initialize_owned` derives from
/// its authority as
/// `find_program_address(["bio-did-owned", authority, nonce_le])`
/// (spec Section 4.2).
pub const OWNED_SUBJECT_SEED: &[u8] = b"bio-did-owned";

/// Reserved fragment of the subject key's verification method (spec Section 5.6).
pub const DEFAULT_FRAGMENT: &str = "default";

/// Account discriminator, `sha256("account:DidAccount")[..8]`
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
/// Maximum verification key material size, which fits ML-DSA-87.
pub const MAX_KEY_DATA_LEN: usize = 2592;

/// PDA seed prefix for key buffers, whose seeds are
/// `["bio-did-key", did_account, authority]` (spec Section 6.3).
pub const KEY_BUFFER_SEED: &[u8] = b"bio-did-key";

/// Key buffer discriminator, `sha256("account:KeyBuffer")[..8]`
/// (spec Section 6.3).
pub const KEY_BUFFER_DISCRIMINATOR: [u8; 8] = [150, 138, 44, 35, 255, 159, 45, 0];

/// Size of a key buffer's fixed header. The key bytes follow it.
pub const KEY_BUFFER_HEADER_LEN: usize = 8 + 32 + 32 + 1 + 1 + 2 + 4 + 4 + 4 + MAX_FRAGMENT_LEN;

/// Verification method flag bits (spec Section 5.3).
pub mod vm_flags {
    /// Listed in `authentication`.
    pub const AUTHENTICATION: u16 = 1 << 0;
    /// Listed in `assertionMethod`.
    pub const ASSERTION: u16 = 1 << 1;
    /// Listed in `keyAgreement`.
    pub const KEY_AGREEMENT: u16 = 1 << 2;
    /// Listed in `capabilityInvocation`. It grants on chain update
    /// authority, on Ed25519 methods only.
    pub const CAPABILITY_INVOCATION: u16 = 1 << 3;
    /// Listed in `capabilityDelegation`.
    pub const CAPABILITY_DELEGATION: u16 = 1 << 4;
    /// Internal to the method. Only the method's own key may add it, change
    /// its flags, or remove it. It is not expressed in the DID document.
    pub const PROTECTED: u16 = 1 << 8;

    /// The five W3C verification relationship bits.
    pub const RELATIONSHIP_MASK: u16 =
        AUTHENTICATION | ASSERTION | KEY_AGREEMENT | CAPABILITY_INVOCATION | CAPABILITY_DELEGATION;
    /// Every bit the registry accepts.
    pub const VALID_MASK: u16 = RELATIONSHIP_MASK | PROTECTED;
    /// Flags of the subject's initial `#default` method, which holds all
    /// five relationships and is protected.
    pub const DEFAULT: u16 = RELATIONSHIP_MASK | PROTECTED;
}

/// On chain verification key algorithm (spec Section 5.2).
///
/// Discriminant values are the on chain Borsh enum tags.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum KeyType {
    /// A 32 byte Ed25519 public key, materialized as a `Multikey`
    /// (`z6Mk...`).
    Ed25519 = 0,
    /// A 32 byte X25519 key agreement key, materialized as a `Multikey`
    /// (`z6LS...`).
    X25519 = 1,
    /// A 33 byte compressed secp256k1 key, materialized as a `Multikey`
    /// (`zQ3s...`).
    Secp256k1 = 2,
    /// A 2592 byte ML-DSA-87 (FIPS 204) public key, materialized as a
    /// `JsonWebKey`.
    ///
    /// It is stored on chain under the legacy name `Dilithium5`, the
    /// parameter set ML-DSA-87 derives from. Final ML-DSA-87 is not
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

    /// The Multikey codec for this key type, or `None` for ML-DSA-87, which
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
    /// Raw public key bytes, whose length matches `method_type`.
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
    /// Service type, such as `BioMetadata`.
    pub service_type: String,
    /// Service endpoint URI.
    pub endpoint: String,
}

/// Deserialized state of a `DidAccount` registry entry.
///
/// Mirrors the on chain `DidAccount` struct of the registry program.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DidAccountState {
    /// Monotonic update counter, reported as `versionId`.
    pub version: u64,
    /// PDA bump seed.
    pub bump: u8,
    /// The subject, which is the DID's method specific id.
    pub subject: [u8; 32],
    /// True once permanently deactivated into a tombstone (spec Section 6.4).
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
    /// The generative default state for a subject key. It is exactly what
    /// `initialize` writes on chain, except that `version` is 0 (spec
    /// Section 5.6, Section 6.1). It is used to materialize the generative
    /// document.
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

    /// Decode registry account data by verifying the 8 byte discriminator
    /// and then reading the Borsh encoded state (spec Section 6.2 step 7).
    ///
    /// The decoding is strict. It refuses anything the registry never
    /// writes, such as bytes past the state, an invalid fragment, unknown
    /// flag bits, a key whose length does not match its type, a service
    /// value or external controller outside its form, a fragment used twice,
    /// or entries left in a deactivated tombstone.
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
            native_controllers: cursor.read_vec(
                MAX_NATIVE_CONTROLLERS,
                "more native controllers than the registry allows",
                Cursor::read_array32,
            )?,
            other_controllers: cursor.read_vec(
                MAX_OTHER_CONTROLLERS,
                "more external controllers than the registry allows",
                Cursor::read_external_controller,
            )?,
            verification_methods: cursor.read_vec(
                MAX_VERIFICATION_METHODS,
                "more verification methods than the registry allows",
                Cursor::read_verification_method,
            )?,
            services: cursor.read_vec(
                MAX_SERVICES,
                "more services than the registry allows",
                Cursor::read_service,
            )?,
        };
        if cursor.remaining() != 0 {
            return Err(Error::InvalidAccountData(
                "trailing bytes after the account state",
            ));
        }
        state.check()?;
        Ok(state)
    }

    /// The rules of a whole document that no single field can check.
    fn check(&self) -> Result<(), Error> {
        let fragments = self
            .verification_methods
            .iter()
            .map(|vm| &vm.fragment)
            .chain(self.services.iter().map(|s| &s.fragment));
        for (i, fragment) in fragments.clone().enumerate() {
            if fragments.clone().take(i).any(|seen| seen == fragment) {
                return Err(Error::InvalidAccountData("fragment used twice"));
            }
        }
        if self.deactivated
            && !(self.native_controllers.is_empty()
                && self.other_controllers.is_empty()
                && self.verification_methods.is_empty()
                && self.services.is_empty())
        {
            return Err(Error::InvalidAccountData(
                "deactivated account holds entries",
            ));
        }
        Ok(())
    }

    /// True when `key` may authorize updates. It must match an Ed25519
    /// method carrying `CAPABILITY_INVOCATION`, and the DID must not be
    /// deactivated (spec Section 6 Authorization).
    pub fn is_authority(&self, key: &[u8; 32]) -> bool {
        !self.deactivated
            && self.verification_methods.iter().any(|vm| {
                vm.method_type == KeyType::Ed25519
                    && vm.has_flag(vm_flags::CAPABILITY_INVOCATION)
                    && vm.key_data.as_slice() == key
            })
    }

    /// Number of Ed25519 methods holding `CAPABILITY_INVOCATION`, which the
    /// last authority invariant counts (spec Section 6).
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

/// Deserialized state of a `KeyBuffer` staging account. It holds a
/// verification method whose key is too large for one transaction and
/// arrives in chunks (spec Section 6.3). Clients read it to resume an
/// interrupted upload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyBufferState {
    /// The DID account the pending method is destined for.
    pub did_account: [u8; 32],
    /// The only key allowed to write, finish, or close the buffer.
    pub authority: [u8; 32],
    /// PDA bump seed.
    pub bump: u8,
    /// Key algorithm of the pending method.
    pub method_type: KeyType,
    /// Flags of the pending method, a bitwise OR of [`vm_flags`] values.
    pub flags: u16,
    /// Total key length, fixed when the buffer was opened.
    pub key_len: usize,
    /// Fragment of the pending method, without the leading `#`.
    pub fragment: String,
    /// The key bytes received so far, always a prefix of the key.
    pub key_data: Vec<u8>,
}

impl KeyBufferState {
    /// Decode key buffer account data by verifying the 8 byte
    /// discriminator, then reading the fixed header and the bytes written
    /// so far.
    pub fn from_account_data(data: &[u8]) -> Result<Self, Error> {
        if data.len() < KEY_BUFFER_HEADER_LEN {
            return Err(Error::InvalidAccountData(
                "shorter than the key buffer header",
            ));
        }
        if data[..KEY_BUFFER_DISCRIMINATOR.len()] != KEY_BUFFER_DISCRIMINATOR {
            return Err(Error::InvalidAccountData("discriminator mismatch"));
        }
        let mut cursor = Cursor {
            data: &data[KEY_BUFFER_DISCRIMINATOR.len()..],
            pos: 0,
        };
        let did_account = cursor.read_array32()?;
        let authority = cursor.read_array32()?;
        let bump = cursor.read_u8()?;
        let method_type = KeyType::from_tag(cursor.read_u8()?).ok_or(Error::InvalidAccountData(
            "unknown verification method type tag",
        ))?;
        let flags = cursor.read_u16()?;
        let key_len = cursor.read_u32()? as usize;
        let written = cursor.read_u32()? as usize;
        let fragment_len = cursor.read_u32()? as usize;
        if fragment_len > MAX_FRAGMENT_LEN {
            return Err(Error::InvalidAccountData(
                "fragment length exceeds the maximum",
            ));
        }
        let fragment = String::from_utf8(cursor.take(fragment_len)?.to_vec())
            .map_err(|_| Error::InvalidAccountData("fragment is not valid UTF-8"))?;
        if !crate::did::is_valid_fragment(&fragment) {
            return Err(Error::InvalidAccountData("fragment is not valid"));
        }
        if flags & !vm_flags::VALID_MASK != 0 {
            return Err(Error::InvalidAccountData(
                "unknown verification method flag bits",
            ));
        }
        let key = &data[KEY_BUFFER_HEADER_LEN..];
        if key.len() != key_len || written > key_len || key_len != method_type.expected_key_len() {
            return Err(Error::InvalidAccountData(
                "key buffer length does not match its header",
            ));
        }
        Ok(KeyBufferState {
            did_account,
            authority,
            bump,
            method_type,
            flags,
            key_len,
            fragment,
            key_data: key[..written].to_vec(),
        })
    }

    /// Number of key bytes received so far.
    pub fn written(&self) -> usize {
        self.key_data.len()
    }

    /// True once every byte of the key has been written.
    pub fn is_complete(&self) -> bool {
        self.key_data.len() == self.key_len
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

    /// A vector of at most `max` elements, the registry's limit for it. The
    /// count is checked before anything is allocated, so a hostile prefix
    /// cannot make the decoder reserve more than the limit.
    fn read_vec<T>(
        &mut self,
        max: usize,
        too_many: &'static str,
        mut read_element: impl FnMut(&mut Self) -> Result<T, Error>,
    ) -> Result<Vec<T>, Error> {
        let len = self.read_len(1)?;
        if len > max {
            return Err(Error::InvalidAccountData(too_many));
        }
        let mut out = Vec::with_capacity(len);
        for _ in 0..len {
            out.push(read_element(self)?);
        }
        Ok(out)
    }

    fn read_fragment(&mut self) -> Result<String, Error> {
        let fragment = self.read_string()?;
        if !crate::did::is_valid_fragment(&fragment) {
            return Err(Error::InvalidAccountData("fragment is not valid"));
        }
        Ok(fragment)
    }

    /// A string of printable ASCII without whitespace, of at most `max`
    /// bytes, the form of service values and external controllers.
    fn read_printable(&mut self, max: usize, what: &'static str) -> Result<String, Error> {
        let value = self.read_string()?;
        if value.is_empty() || value.len() > max || !value.bytes().all(|b| b.is_ascii_graphic()) {
            return Err(Error::InvalidAccountData(what));
        }
        Ok(value)
    }

    fn read_external_controller(&mut self) -> Result<String, Error> {
        let value = self.read_printable(
            MAX_CONTROLLER_LEN,
            "external controller is not a DID of another method",
        )?;
        if !value.starts_with("did:") || value.starts_with("did:bio:") {
            return Err(Error::InvalidAccountData(
                "external controller is not a DID of another method",
            ));
        }
        Ok(value)
    }

    fn read_verification_method(&mut self) -> Result<StoredVerificationMethod, Error> {
        let fragment = self.read_fragment()?;
        let method_type = KeyType::from_tag(self.read_u8()?).ok_or(Error::InvalidAccountData(
            "unknown verification method type tag",
        ))?;
        let flags = self.read_u16()?;
        if flags & !vm_flags::VALID_MASK != 0 {
            return Err(Error::InvalidAccountData(
                "unknown verification method flag bits",
            ));
        }
        let key_data = self.read_byte_vec()?;
        if key_data.len() != method_type.expected_key_len() {
            return Err(Error::InvalidAccountData(
                "key length does not match its type",
            ));
        }
        Ok(StoredVerificationMethod {
            fragment,
            method_type,
            flags,
            key_data,
        })
    }

    fn read_service(&mut self) -> Result<StoredService, Error> {
        Ok(StoredService {
            fragment: self.read_fragment()?,
            service_type: self.read_printable(MAX_SERVICE_TYPE_LEN, "service type is not valid")?,
            endpoint: self.read_printable(MAX_ENDPOINT_LEN, "service endpoint is not valid")?,
        })
    }
}
