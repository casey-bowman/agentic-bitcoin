//! Cryptographic hashing functions and core hash type
//!
//! Double-SHA256, SHA256, SHA-1, and RIPEMD-160 hashing used throughout Bitcoin.
//! Also defines `Hash256`, the fundamental 32-byte hash type, so that this
//! module has zero intra-crate dependencies (only external crate deps).

use sha1::Sha1;
use sha2::{Digest, Sha256};
use std::fmt;

// ---------------------------------------------------------------------------
// Hash256 — the core 32-byte hash type
// ---------------------------------------------------------------------------

/// A 256-bit hash as a byte array
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Hash256([u8; 32]);

impl Hash256 {
    /// Create a hash from a byte array
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Hash256(bytes)
    }

    /// Get the bytes
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Create from hex string (must be 64 hex chars)
    pub fn from_hex(hex: &str) -> Option<Self> {
        if hex.len() != 64 {
            return None;
        }
        let mut bytes = [0u8; 32];
        for i in 0..32 {
            let byte_hex = &hex[i * 2..i * 2 + 2];
            bytes[i] = u8::from_str_radix(byte_hex, 16).ok()?;
        }
        Some(Hash256(bytes))
    }

    /// Get hex string representation
    pub fn to_hex(&self) -> String {
        self.0.iter().map(|b| format!("{:02x}", b)).collect()
    }

    /// Display as hex (typically reversed for display)
    pub fn to_hex_reversed(&self) -> String {
        self.0.iter().rev().map(|b| format!("{:02x}", b)).collect()
    }

    /// Zero hash
    pub const fn zero() -> Self {
        Hash256([0u8; 32])
    }

    /// All ones hash
    pub const fn all_ones() -> Self {
        Hash256([0xffu8; 32])
    }
}

impl fmt::Display for Hash256 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_hex_reversed())
    }
}

impl std::str::FromStr for Hash256 {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Hash256::from_hex(s).ok_or_else(|| "Invalid hash256 hex string".to_string())
    }
}

// ---------------------------------------------------------------------------
// Hashing functions
// ---------------------------------------------------------------------------

/// Compute double-SHA256 hash (hash256)
///
/// This is the standard hashing function used throughout Bitcoin for
/// transaction IDs, block hashes, and merkle roots.
pub fn hash256(data: &[u8]) -> Hash256 {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let first_hash = hasher.finalize();

    let mut hasher = Sha256::new();
    hasher.update(first_hash);
    let second_hash = hasher.finalize();

    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&second_hash);
    Hash256::from_bytes(bytes)
}

/// Compute single SHA-256 hash
pub fn sha256(data: &[u8]) -> Hash256 {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let hash = hasher.finalize();

    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&hash);
    Hash256::from_bytes(bytes)
}

/// Compute RIPEMD-160(SHA-256) hash (hash160)
///
/// Used for address generation and script pubkey hashes.
pub fn hash160(data: &[u8]) -> [u8; 20] {
    use ripemd::Ripemd160;

    let mut sha256_hasher = Sha256::new();
    sha256_hasher.update(data);
    let sha256_hash = sha256_hasher.finalize();

    let mut ripemd_hasher = Ripemd160::new();
    ripemd_hasher.update(sha256_hash);
    let hash160_result = ripemd_hasher.finalize();

    let mut bytes = [0u8; 20];
    bytes.copy_from_slice(&hash160_result);
    bytes
}

/// Compute SHA-1 hash (OP_SHA1)
///
/// Returns a 20-byte SHA-1 digest. Used by the OP_SHA1 opcode in Bitcoin Script.
/// While SHA-1 is considered cryptographically weak for collision resistance,
/// it remains a valid opcode that must be supported for consensus compatibility.
pub fn sha1(data: &[u8]) -> [u8; 20] {
    let mut hasher = Sha1::new();
    hasher.update(data);
    let result = hasher.finalize();

    let mut bytes = [0u8; 20];
    bytes.copy_from_slice(&result);
    bytes
}

/// Hash a signature for signing
pub fn hash_sig(data: &[u8]) -> Hash256 {
    hash256(data)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_double_sha256() {
        let data = b"hello";
        let hash = hash256(data);
        assert_eq!(hash.as_bytes().len(), 32);
    }

    #[test]
    fn test_sha256() {
        let data = b"hello";
        let hash = sha256(data);
        assert_eq!(hash.as_bytes().len(), 32);
    }

    #[test]
    fn test_hash160() {
        let data = b"hello";
        let hash = hash160(data);
        assert_eq!(hash.len(), 20);
    }

    #[test]
    fn test_sha1() {
        let data = b"hello";
        let hash = sha1(data);
        assert_eq!(hash.len(), 20);

        // Known SHA-1 of "hello": aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d
        let expected = hex::decode("aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d").unwrap();
        assert_eq!(hash.to_vec(), expected);
    }

    #[test]
    fn test_consistent_hashing() {
        let data = b"test data";
        let hash1 = hash256(data);
        let hash2 = hash256(data);
        assert_eq!(hash1, hash2);
    }
}
