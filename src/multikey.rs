//! Multikey encoding and decoding (Controlled Identifiers v1.0 Section 2.2.2).
//!
//! A Multikey `publicKeyMultibase` value is the multibase `z` (base58btc)
//! encoding of a multicodec varint prefix followed by the raw public key
//! bytes (spec Section 5.2).

use crate::error::Error;

/// Multicodec key codecs used by `did:bio` verification methods.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KeyCodec {
    /// `ed25519-pub`, multicodec `0xed`; 32 byte key; `z6Mk...`.
    Ed25519Pub,
    /// `x25519-pub`, multicodec `0xec`; 32 byte key; `z6LS...`.
    X25519Pub,
    /// `secp256k1-pub`, multicodec `0xe7`; 33 byte compressed key; `zQ3s...`.
    Secp256k1Pub,
}

impl KeyCodec {
    /// The multicodec code point.
    pub const fn multicodec(self) -> u64 {
        match self {
            KeyCodec::Ed25519Pub => 0xed,
            KeyCodec::X25519Pub => 0xec,
            KeyCodec::Secp256k1Pub => 0xe7,
        }
    }

    /// Required raw key length in bytes.
    pub const fn key_len(self) -> usize {
        match self {
            KeyCodec::Ed25519Pub => 32,
            KeyCodec::X25519Pub => 32,
            KeyCodec::Secp256k1Pub => 33,
        }
    }

    /// The characteristic multibase prefix of encoded keys (informative,
    /// spec Section 5.2 table).
    pub const fn multibase_prefix(self) -> &'static str {
        match self {
            KeyCodec::Ed25519Pub => "z6Mk",
            KeyCodec::X25519Pub => "z6LS",
            KeyCodec::Secp256k1Pub => "zQ3s",
        }
    }

    fn from_multicodec(code: u64) -> Option<KeyCodec> {
        match code {
            0xed => Some(KeyCodec::Ed25519Pub),
            0xec => Some(KeyCodec::X25519Pub),
            0xe7 => Some(KeyCodec::Secp256k1Pub),
            _ => None,
        }
    }
}

/// Append `value` to `out` as an unsigned varint (multiformats LEB128).
fn write_uvarint(out: &mut Vec<u8>, mut value: u64) {
    loop {
        let byte = (value & 0x7f) as u8;
        value >>= 7;
        if value == 0 {
            out.push(byte);
            return;
        }
        out.push(byte | 0x80);
    }
}

/// Read an unsigned varint from the front of `bytes`, returning the value
/// and the number of bytes consumed.
fn read_uvarint(bytes: &[u8]) -> Result<(u64, usize), Error> {
    let mut value: u64 = 0;
    for (i, &byte) in bytes.iter().enumerate().take(9) {
        value |= u64::from(byte & 0x7f) << (7 * i);
        if byte & 0x80 == 0 {
            return Ok((value, i + 1));
        }
    }
    Err(Error::InvalidMultikey("malformed multicodec varint"))
}

/// Encode raw public key bytes as a Multikey `publicKeyMultibase` string.
///
/// Fails with [`Error::InvalidKeyLength`] when `key` does not have the
/// codec's required length.
///
/// ```
/// use did_bio_core::multikey;
/// use did_bio_core::multikey::KeyCodec;
///
/// let encoded = multikey::encode(KeyCodec::Ed25519Pub, &[0u8; 32]).unwrap();
/// assert!(encoded.starts_with("z6Mk"));
/// ```
pub fn encode(codec: KeyCodec, key: &[u8]) -> Result<String, Error> {
    if key.len() != codec.key_len() {
        return Err(Error::InvalidKeyLength {
            expected: codec.key_len(),
            actual: key.len(),
        });
    }
    let mut bytes = Vec::with_capacity(2 + key.len());
    write_uvarint(&mut bytes, codec.multicodec());
    bytes.extend_from_slice(key);
    Ok(format!("z{}", bs58::encode(bytes).into_string()))
}

/// Decode a Multikey `publicKeyMultibase` string to its codec and raw key
/// bytes.
///
/// Rejects non-`z` multibase headers, undecodable base58, unknown
/// multicodec prefixes, and key material of the wrong length.
pub fn decode(multikey: &str) -> Result<(KeyCodec, Vec<u8>), Error> {
    let encoded = multikey.strip_prefix('z').ok_or(Error::InvalidMultikey(
        "expected multibase `z` (base58btc) header",
    ))?;
    let bytes = bs58::decode(encoded)
        .into_vec()
        .map_err(|_| Error::InvalidMultikey("invalid base58btc payload"))?;
    let (code, consumed) = read_uvarint(&bytes)?;
    let codec = KeyCodec::from_multicodec(code)
        .ok_or(Error::InvalidMultikey("unknown multicodec key prefix"))?;
    let key = &bytes[consumed..];
    if key.len() != codec.key_len() {
        return Err(Error::InvalidKeyLength {
            expected: codec.key_len(),
            actual: key.len(),
        });
    }
    Ok((codec, key.to_vec()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn varint_two_byte_prefixes() {
        let mut out = Vec::new();
        write_uvarint(&mut out, 0xed);
        assert_eq!(out, [0xed, 0x01]);
        assert_eq!(read_uvarint(&[0xed, 0x01]).unwrap(), (0xed, 2));
        assert_eq!(read_uvarint(&[0x7f]).unwrap(), (0x7f, 1));
        assert!(read_uvarint(&[0x80]).is_err());
    }

    #[test]
    fn roundtrip_all_codecs() {
        for codec in [
            KeyCodec::Ed25519Pub,
            KeyCodec::X25519Pub,
            KeyCodec::Secp256k1Pub,
        ] {
            let key = vec![7u8; codec.key_len()];
            let encoded = encode(codec, &key).unwrap();
            assert!(encoded.starts_with(codec.multibase_prefix()), "{encoded}");
            let (decoded_codec, decoded_key) = decode(&encoded).unwrap();
            assert_eq!(decoded_codec, codec);
            assert_eq!(decoded_key, key);
        }
    }

    #[test]
    fn rejects_wrong_lengths_and_headers() {
        assert!(matches!(
            encode(KeyCodec::Ed25519Pub, &[0u8; 31]),
            Err(Error::InvalidKeyLength {
                expected: 32,
                actual: 31
            })
        ));
        assert!(decode("m6Mk").is_err());
        assert!(decode("z0OIl").is_err());
        // ed25519 prefix but 31 key bytes
        let mut bytes = vec![0xed, 0x01];
        bytes.extend_from_slice(&[0u8; 31]);
        let bad = format!("z{}", bs58::encode(bytes).into_string());
        assert!(matches!(decode(&bad), Err(Error::InvalidKeyLength { .. })));
    }
}
