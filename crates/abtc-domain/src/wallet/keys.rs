//! Bitcoin key management
//!
//! Private and public key types with WIF encoding/decoding,
//! key derivation, and random key generation using secp256k1.

use crate::hashing;
use secp256k1::{Secp256k1, SecretKey};

// Re-export PublicKey and KeyError from primitives (canonical definitions)
pub use crate::primitives::public_key::{KeyError, PublicKey};

/// A Bitcoin private key (secp256k1 scalar)
#[derive(Clone)]
pub struct PrivateKey {
    /// The raw secp256k1 secret key
    key: SecretKey,
    /// Whether to use compressed public keys (almost always true for modern Bitcoin)
    compressed: bool,
    /// Network prefix for WIF encoding (0x80 = mainnet, 0xEF = testnet)
    network_byte: u8,
}

impl PrivateKey {
    /// Create a new private key from raw 32 bytes.
    pub fn from_bytes(bytes: &[u8; 32], compressed: bool, mainnet: bool) -> Result<Self, KeyError> {
        let key = SecretKey::from_slice(bytes).map_err(|_| KeyError::InvalidPrivateKey)?;
        Ok(PrivateKey {
            key,
            compressed,
            network_byte: if mainnet { 0x80 } else { 0xEF },
        })
    }

    /// Generate a new random private key.
    pub fn generate(compressed: bool, mainnet: bool) -> Self {
        let secp = Secp256k1::new();
        let (key, _) = secp.generate_keypair(&mut rand::thread_rng());
        PrivateKey {
            key,
            compressed,
            network_byte: if mainnet { 0x80 } else { 0xEF },
        }
    }

    /// Derive the corresponding public key.
    pub fn public_key(&self) -> PublicKey {
        let secp = Secp256k1::new();
        let pk = secp256k1::PublicKey::from_secret_key(&secp, &self.key);
        PublicKey::from_inner(pk, self.compressed)
    }

    /// Get the raw 32-byte secret key.
    pub fn secret_bytes(&self) -> [u8; 32] {
        self.key.secret_bytes()
    }

    /// Get the inner secp256k1 SecretKey.
    pub fn inner(&self) -> &SecretKey {
        &self.key
    }

    /// Whether this key produces compressed public keys.
    pub fn compressed(&self) -> bool {
        self.compressed
    }

    /// Whether this key is for mainnet.
    pub fn is_mainnet(&self) -> bool {
        self.network_byte == 0x80
    }

    /// Encode as WIF (Wallet Import Format).
    ///
    /// WIF = Base58Check( network_byte | secret_bytes | [0x01 if compressed] )
    pub fn to_wif(&self) -> String {
        let mut payload = Vec::with_capacity(34);
        payload.push(self.network_byte);
        payload.extend_from_slice(&self.key.secret_bytes());
        if self.compressed {
            payload.push(0x01);
        }
        base58check_encode(&payload)
    }

    /// Decode from WIF (Wallet Import Format).
    pub fn from_wif(wif: &str) -> Result<Self, KeyError> {
        let payload = base58check_decode(wif)?;

        if payload.is_empty() {
            return Err(KeyError::InvalidWif("empty payload".into()));
        }

        let network_byte = payload[0];
        if network_byte != 0x80 && network_byte != 0xEF {
            return Err(KeyError::InvalidWif(format!(
                "unknown network byte: 0x{:02x}",
                network_byte
            )));
        }

        let (secret_bytes, compressed) = match payload.len() {
            // 1 (network) + 32 (key) = 33 → uncompressed
            33 => (&payload[1..33], false),
            // 1 (network) + 32 (key) + 1 (compression flag) = 34 → compressed
            34 => {
                if payload[33] != 0x01 {
                    return Err(KeyError::InvalidWif("bad compression flag".into()));
                }
                (&payload[1..33], true)
            }
            n => {
                return Err(KeyError::InvalidWif(format!(
                    "unexpected payload length: {}",
                    n
                )));
            }
        };

        let mut key_bytes = [0u8; 32];
        key_bytes.copy_from_slice(secret_bytes);

        PrivateKey::from_bytes(&key_bytes, compressed, network_byte == 0x80)
    }
}

impl std::fmt::Debug for PrivateKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "PrivateKey(compressed={}, mainnet={})",
            self.compressed,
            self.is_mainnet()
        )
    }
}

// ---- Base58Check encoding/decoding ----

/// Alphabet for Base58 encoding (Bitcoin variant)
const BASE58_ALPHABET: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/// Encode data with Base58Check (payload → Base58(payload | checksum))
pub fn base58check_encode(payload: &[u8]) -> String {
    let checksum = compute_base58_checksum(payload);

    let mut data = Vec::with_capacity(payload.len() + 4);
    data.extend_from_slice(payload);
    data.extend_from_slice(&checksum);

    base58_encode(&data)
}

/// Decode Base58Check encoded string → payload (verifying checksum)
pub fn base58check_decode(encoded: &str) -> Result<Vec<u8>, KeyError> {
    let data = base58_decode(encoded)?;

    if data.len() < 4 {
        return Err(KeyError::InvalidWif("too short for checksum".into()));
    }

    let (payload, expected_checksum) = data.split_at(data.len() - 4);
    let actual_checksum = compute_base58_checksum(payload);

    if expected_checksum != actual_checksum {
        return Err(KeyError::ChecksumMismatch);
    }

    Ok(payload.to_vec())
}

/// Compute the 4-byte Base58Check checksum (first 4 bytes of double-SHA256)
fn compute_base58_checksum(data: &[u8]) -> [u8; 4] {
    let hash = hashing::hash256(data);
    let mut checksum = [0u8; 4];
    checksum.copy_from_slice(&hash.as_bytes()[..4]);
    checksum
}

/// Raw Base58 encoding
fn base58_encode(data: &[u8]) -> String {
    // Count leading zeros
    let leading_zeros = data.iter().take_while(|&&b| b == 0).count();

    // Convert to big integer (simple implementation)
    let mut num = Vec::from(data);
    let mut result = Vec::new();

    while !num.is_empty() && !is_zero(&num) {
        let mut remainder = 0u32;
        let mut new_num = Vec::new();
        for &byte in &num {
            let current = (remainder << 8) | byte as u32;
            let quotient = current / 58;
            remainder = current % 58;
            if !new_num.is_empty() || quotient > 0 {
                new_num.push(quotient as u8);
            }
        }
        result.push(BASE58_ALPHABET[remainder as usize]);
        num = new_num;
    }

    // Add leading '1's for zero bytes
    result.extend(std::iter::repeat_n(b'1', leading_zeros));

    result.reverse();
    String::from_utf8(result).unwrap()
}

/// Raw Base58 decoding
fn base58_decode(encoded: &str) -> Result<Vec<u8>, KeyError> {
    let mut num: Vec<u8> = Vec::new();

    for ch in encoded.chars() {
        let digit = BASE58_ALPHABET
            .iter()
            .position(|&c| c == ch as u8)
            .ok_or_else(|| KeyError::InvalidWif(format!("invalid base58 char: {}", ch)))?
            as u8;

        // Multiply num by 58 and add digit
        let mut carry = digit as u32;
        for byte in num.iter_mut().rev() {
            carry += (*byte as u32) * 58;
            *byte = (carry & 0xff) as u8;
            carry >>= 8;
        }
        while carry > 0 {
            num.insert(0, (carry & 0xff) as u8);
            carry >>= 8;
        }
    }

    // Count leading '1's
    let leading_ones = encoded.chars().take_while(|&c| c == '1').count();

    let mut result = vec![0u8; leading_ones];
    result.extend_from_slice(&num);
    Ok(result)
}

/// Check if a big number (byte vector) is zero
fn is_zero(bytes: &[u8]) -> bool {
    bytes.iter().all(|&b| b == 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_generation() {
        let key = PrivateKey::generate(true, true);
        assert!(key.compressed());
        assert!(key.is_mainnet());

        let pubkey = key.public_key();
        assert!(pubkey.compressed());
        assert_eq!(pubkey.serialize().len(), 33);
    }

    #[test]
    fn test_uncompressed_key() {
        let key = PrivateKey::generate(false, true);
        assert!(!key.compressed());

        let pubkey = key.public_key();
        assert!(!pubkey.compressed());
        assert_eq!(pubkey.serialize().len(), 65);
    }

    #[test]
    fn test_wif_roundtrip_compressed() {
        let key = PrivateKey::generate(true, true);
        let wif = key.to_wif();

        // Compressed mainnet WIF starts with 'K' or 'L'
        assert!(wif.starts_with('K') || wif.starts_with('L'));

        let decoded = PrivateKey::from_wif(&wif).unwrap();
        assert_eq!(decoded.secret_bytes(), key.secret_bytes());
        assert!(decoded.compressed());
        assert!(decoded.is_mainnet());
    }

    #[test]
    fn test_wif_roundtrip_uncompressed() {
        let key = PrivateKey::generate(false, true);
        let wif = key.to_wif();

        // Uncompressed mainnet WIF starts with '5'
        assert!(wif.starts_with('5'));

        let decoded = PrivateKey::from_wif(&wif).unwrap();
        assert_eq!(decoded.secret_bytes(), key.secret_bytes());
        assert!(!decoded.compressed());
    }

    #[test]
    fn test_wif_testnet() {
        let key = PrivateKey::generate(true, false);
        let wif = key.to_wif();

        // Compressed testnet WIF starts with 'c'
        assert!(wif.starts_with('c'));

        let decoded = PrivateKey::from_wif(&wif).unwrap();
        assert!(!decoded.is_mainnet());
    }

    #[test]
    fn test_pubkey_hash() {
        let key = PrivateKey::generate(true, true);
        let pubkey = key.public_key();
        let hash = pubkey.pubkey_hash();
        assert_eq!(hash.len(), 20);

        // Same key should produce same hash
        let hash2 = pubkey.pubkey_hash();
        assert_eq!(hash, hash2);
    }

    #[test]
    fn test_from_bytes() {
        let key = PrivateKey::generate(true, true);
        let bytes = key.secret_bytes();

        let key2 = PrivateKey::from_bytes(&bytes, true, true).unwrap();
        assert_eq!(key.secret_bytes(), key2.secret_bytes());
    }

    #[test]
    fn test_base58check_roundtrip() {
        let data = vec![0x80, 0x01, 0x02, 0x03, 0x04];
        let encoded = base58check_encode(&data);
        let decoded = base58check_decode(&encoded).unwrap();
        assert_eq!(data, decoded);
    }

    #[test]
    fn test_base58check_bad_checksum() {
        let data = vec![0x80, 0x01, 0x02, 0x03, 0x04];
        let mut encoded = base58check_encode(&data);
        // Corrupt last character
        let len = encoded.len();
        encoded.replace_range(len - 1..len, "1");
        assert!(base58check_decode(&encoded).is_err());
    }

    #[test]
    fn test_pubkey_from_bytes() {
        let key = PrivateKey::generate(true, true);
        let pubkey = key.public_key();
        let bytes = pubkey.serialize();

        let pubkey2 = PublicKey::from_bytes(&bytes).unwrap();
        assert_eq!(pubkey, pubkey2);
    }
}
