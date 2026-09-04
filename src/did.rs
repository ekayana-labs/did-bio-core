//! The `did:bio` identifier: parsing, validation, and display (spec Section 4).

use core::fmt;
use core::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::error::Error;

/// The method name of this DID method (spec Section 3).
pub const METHOD_NAME: &str = "bio";

/// The `did:bio:` scheme and method prefix, always lowercase.
pub const DID_PREFIX: &str = "did:bio:";

/// Regular expression matching a full `did:bio` DID (spec Section 4.1, informative -
/// [`BioDid::parse`] is the normative implementation).
pub const DID_REGEX: &str = "^did:bio(:(devnet|testnet|localnet))?:[1-9A-HJ-NP-Za-km-z]{32,44}$";

const IDSTRING_MIN_LEN: usize = 32;
const IDSTRING_MAX_LEN: usize = 44;

/// Length in bytes of a subject key (an Ed25519 public key).
pub const SUBJECT_KEY_LEN: usize = 32;

fn is_base58_char(b: u8) -> bool {
    matches!(b,
        b'1'..=b'9'
        | b'A'..=b'H' | b'J'..=b'N' | b'P'..=b'Z'
        | b'a'..=b'k' | b'm'..=b'z')
}

/// The Solana cluster acting as the verifiable data registry for a DID
/// (spec Section 4.2). Selected by the optional `network` segment; a DID without a
/// segment uses mainnet-beta.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub enum Network {
    /// `did:bio:<idstring>` - mainnet-beta (no network segment).
    #[default]
    Mainnet,
    /// `did:bio:devnet:<idstring>` - the intended reference deployment cluster.
    Devnet,
    /// `did:bio:testnet:<idstring>`.
    Testnet,
    /// `did:bio:localnet:<idstring>` - a local validator.
    Localnet,
}

impl Network {
    /// The DID `network` segment for this cluster, or `None` for mainnet
    /// (which is expressed by omitting the segment).
    pub const fn segment(self) -> Option<&'static str> {
        match self {
            Network::Mainnet => None,
            Network::Devnet => Some("devnet"),
            Network::Testnet => Some("testnet"),
            Network::Localnet => Some("localnet"),
        }
    }

    /// Parse a `network` segment. `None` for anything that is not exactly
    /// `devnet`, `testnet`, or `localnet` (there is no `mainnet` segment).
    pub fn from_segment(segment: &str) -> Option<Network> {
        match segment {
            "devnet" => Some(Network::Devnet),
            "testnet" => Some(Network::Testnet),
            "localnet" => Some(Network::Localnet),
            _ => None,
        }
    }

    /// The conventional public RPC endpoint for this cluster (informative;
    /// resolvers may use any endpoint they trust - see spec Section 7).
    pub const fn default_rpc_url(self) -> &'static str {
        match self {
            Network::Mainnet => "https://api.mainnet-beta.solana.com",
            Network::Devnet => "https://api.devnet.solana.com",
            Network::Testnet => "https://api.testnet.solana.com",
            Network::Localnet => "http://127.0.0.1:8899",
        }
    }
}

/// A parsed, validated `did:bio` DID.
///
/// A `BioDid` is the pair of a [`Network`] and a 32 byte **subject key**
/// (an Ed25519 public key). Its string form is
/// `did:bio[:<network>]:<base58btc(subject)>`.
///
/// ```
/// use did_bio_core::{BioDid, Network};
///
/// let did: BioDid = "did:bio:devnet:2T6zLFvMx7NJac5qQtiKTaPhMwHLkwKETWjUK1yKv4tc"
///     .parse()
///     .unwrap();
/// assert_eq!(did.network, Network::Devnet);
/// assert_eq!(did.to_string(), "did:bio:devnet:2T6zLFvMx7NJac5qQtiKTaPhMwHLkwKETWjUK1yKv4tc");
/// ```
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct BioDid {
    /// Cluster selected by the `network` segment.
    pub network: Network,
    /// The 32 byte Ed25519 subject key encoded in the `idstring`.
    pub subject: [u8; SUBJECT_KEY_LEN],
}

impl BioDid {
    /// Build a DID from a network and subject key (spec Section 4.2 Generation).
    pub const fn new(network: Network, subject: [u8; SUBJECT_KEY_LEN]) -> Self {
        BioDid { network, subject }
    }

    /// Parse and validate a DID against the ABNF of spec Section 4.1 and the
    /// 32 byte decoding rule of Section 6.2 step 3.
    ///
    /// Rejects (with [`Error::InvalidDid`]): a wrong prefix or one not in lowercase,
    /// an unknown or empty network segment, an `idstring` outside 32-44
    /// characters or outside the base58btc alphabet, and an `idstring` that
    /// does not decode to exactly 32 bytes.
    pub fn parse(did: &str) -> Result<Self, Error> {
        let rest = did
            .strip_prefix(DID_PREFIX)
            .ok_or(Error::InvalidDid("missing lowercase `did:bio:` prefix"))?;

        let (network, idstring) = match rest.split_once(':') {
            Some((segment, idstring)) => {
                let network = Network::from_segment(segment)
                    .ok_or(Error::InvalidDid("unknown network segment"))?;
                (network, idstring)
            }
            None => (Network::Mainnet, rest),
        };

        if !(IDSTRING_MIN_LEN..=IDSTRING_MAX_LEN).contains(&idstring.len()) {
            return Err(Error::InvalidDid("idstring must be 32-44 characters"));
        }
        if !idstring.bytes().all(is_base58_char) {
            return Err(Error::InvalidDid(
                "idstring contains characters outside the base58btc alphabet",
            ));
        }

        let mut subject = [0u8; SUBJECT_KEY_LEN];
        let decoded_len = bs58::decode(idstring)
            .onto(&mut subject)
            .map_err(|_| Error::InvalidDid("idstring does not decode to a 32-byte key"))?;
        if decoded_len != SUBJECT_KEY_LEN {
            return Err(Error::InvalidDid(
                "idstring does not decode to a 32-byte key",
            ));
        }

        Ok(BioDid { network, subject })
    }

    /// The method specific identifier: base58btc of the subject key.
    pub fn method_specific_id(&self) -> String {
        bs58::encode(&self.subject).into_string()
    }

    /// The DID URL of a fragment within this DID document: `<did>#<fragment>`.
    pub fn url(&self, fragment: &str) -> String {
        format!("{self}#{fragment}")
    }

    /// The DID URL of the subject key's reserved verification method,
    /// `<did>#default` (spec Section 5.6).
    pub fn default_verification_method_id(&self) -> String {
        self.url(crate::account::DEFAULT_FRAGMENT)
    }
}

impl fmt::Display for BioDid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.network.segment() {
            Some(segment) => write!(f, "{DID_PREFIX}{segment}:{}", self.method_specific_id()),
            None => write!(f, "{DID_PREFIX}{}", self.method_specific_id()),
        }
    }
}

impl fmt::Debug for BioDid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "BioDid({self})")
    }
}

impl FromStr for BioDid {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        BioDid::parse(s)
    }
}

impl Serialize for BioDid {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for BioDid {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        BioDid::parse(&s).map_err(serde::de::Error::custom)
    }
}

/// A `did:bio` DID URL: a DID plus an optional `#fragment`.
///
/// `did:bio` defines no path or query components; fragments follow the
/// registry's fragment rule (`[A-Za-z0-9_-]{1,32}`, spec Section 6.3), which every
/// fragment in a materialized document satisfies.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DidUrl {
    /// The DID part, before any `#`.
    pub did: BioDid,
    /// The fragment after `#`, without the `#` itself.
    pub fragment: Option<String>,
}

/// True when `fragment` satisfies the registry fragment rule
/// `[A-Za-z0-9_-]{1,32}` (spec Section 6.3).
pub fn is_valid_fragment(fragment: &str) -> bool {
    !fragment.is_empty()
        && fragment.len() <= crate::account::MAX_FRAGMENT_LEN
        && fragment
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

impl DidUrl {
    /// Parse `<did>[#<fragment>]`.
    ///
    /// Rejects path (`/`) and query (`?`) components - `did:bio` does not
    /// define them - and fragments outside `[A-Za-z0-9_-]{1,32}`.
    pub fn parse(url: &str) -> Result<Self, Error> {
        let (did_part, fragment) = match url.split_once('#') {
            Some((did_part, fragment)) => (did_part, Some(fragment)),
            None => (url, None),
        };
        if did_part.contains('/') || did_part.contains('?') {
            return Err(Error::InvalidDidUrl(
                "did:bio defines no path or query components",
            ));
        }
        let did = BioDid::parse(did_part).map_err(|e| match e {
            Error::InvalidDid(reason) => Error::InvalidDidUrl(reason),
            other => other,
        })?;
        let fragment = match fragment {
            Some(f) => {
                if !is_valid_fragment(f) {
                    return Err(Error::InvalidDidUrl(
                        "fragment must match [A-Za-z0-9_-]{1,32}",
                    ));
                }
                Some(f.to_string())
            }
            None => None,
        };
        Ok(DidUrl { did, fragment })
    }
}

impl fmt::Display for DidUrl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.fragment {
            Some(fragment) => write!(f, "{}#{fragment}", self.did),
            None => write!(f, "{}", self.did),
        }
    }
}

impl FromStr for DidUrl {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        DidUrl::parse(s)
    }
}
