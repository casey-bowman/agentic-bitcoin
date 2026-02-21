//! Bitcoin hash types
//!
//! Implements Hash256 ([u8; 32]), Txid, Wtxid, and BlockHash types with
//! proper hashing using double-SHA256.

use std::fmt;

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

/// Bitcoin transaction ID (transaction hash)
///
/// Double-SHA256 of transaction serialization.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Txid(Hash256);

impl Txid {
    /// Create from hash
    pub const fn from_hash(hash: Hash256) -> Self {
        Txid(hash)
    }

    /// Get inner hash
    pub const fn inner(&self) -> Hash256 {
        self.0
    }

    /// Get bytes
    pub const fn as_bytes(&self) -> &[u8; 32] {
        self.0.as_bytes()
    }

    /// Create from hex string
    pub fn from_hex(hex: &str) -> Option<Self> {
        Hash256::from_hex(hex).map(Txid::from_hash)
    }

    /// Get hex string
    pub fn to_hex(&self) -> String {
        self.0.to_hex()
    }

    /// Display as reversed hex (typical Bitcoin convention)
    pub fn to_hex_reversed(&self) -> String {
        self.0.to_hex_reversed()
    }

    /// Zero txid
    pub const fn zero() -> Self {
        Txid(Hash256([0u8; 32]))
    }
}

impl fmt::Display for Txid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_hex_reversed())
    }
}

impl std::str::FromStr for Txid {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Txid::from_hex(s).ok_or_else(|| "Invalid txid hex string".to_string())
    }
}

/// Witness transaction ID (includes witness data)
///
/// Used for BIP141 witness transactions. For non-witness transactions,
/// wtxid equals txid.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Wtxid(Hash256);

impl Wtxid {
    /// Create from hash
    pub const fn from_hash(hash: Hash256) -> Self {
        Wtxid(hash)
    }

    /// Get inner hash
    pub const fn inner(&self) -> Hash256 {
        self.0
    }

    /// Get bytes
    pub const fn as_bytes(&self) -> &[u8; 32] {
        self.0.as_bytes()
    }

    /// Create from hex string
    pub fn from_hex(hex: &str) -> Option<Self> {
        Hash256::from_hex(hex).map(Wtxid::from_hash)
    }

    /// Get hex string
    pub fn to_hex(&self) -> String {
        self.0.to_hex()
    }

    /// Display as reversed hex
    pub fn to_hex_reversed(&self) -> String {
        self.0.to_hex_reversed()
    }

    /// Zero wtxid
    pub const fn zero() -> Self {
        Wtxid(Hash256([0u8; 32]))
    }
}

impl fmt::Display for Wtxid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_hex_reversed())
    }
}

impl std::str::FromStr for Wtxid {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Wtxid::from_hex(s).ok_or_else(|| "Invalid wtxid hex string".to_string())
    }
}

/// Block hash
///
/// Double-SHA256 of block header serialization.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct BlockHash(Hash256);

impl BlockHash {
    /// Create from hash
    pub const fn from_hash(hash: Hash256) -> Self {
        BlockHash(hash)
    }

    /// Get inner hash
    pub const fn inner(&self) -> Hash256 {
        self.0
    }

    /// Get bytes
    pub const fn as_bytes(&self) -> &[u8; 32] {
        self.0.as_bytes()
    }

    /// Create from hex string
    pub fn from_hex(hex: &str) -> Option<Self> {
        Hash256::from_hex(hex).map(BlockHash::from_hash)
    }

    /// Get hex string
    pub fn to_hex(&self) -> String {
        self.0.to_hex()
    }

    /// Display as reversed hex (typical Bitcoin convention)
    pub fn to_hex_reversed(&self) -> String {
        self.0.to_hex_reversed()
    }

    /// Genesis block hash (mainnet)
    pub const fn genesis_mainnet() -> Self {
        // 000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f
        BlockHash(Hash256([
            0x6f, 0xe2, 0x8c, 0x0a, 0xb6, 0xf1, 0xb3, 0x72, 0xc1, 0xa6, 0xa2, 0x46, 0xae, 0x63,
            0xf7, 0x4f, 0x93, 0x1e, 0x83, 0x65, 0xe1, 0x5a, 0x08, 0x9c, 0x68, 0xd6, 0x19, 0x00,
            0x00, 0x00, 0x00, 0x00,
        ]))
    }

    /// Zero block hash
    pub const fn zero() -> Self {
        BlockHash(Hash256([0u8; 32]))
    }
}

impl fmt::Display for BlockHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_hex_reversed())
    }
}

impl std::str::FromStr for BlockHash {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        BlockHash::from_hex(s).ok_or_else(|| "Invalid block hash hex string".to_string())
    }
}

/// Double-SHA256 hash computation
pub fn hash256(data: &[u8]) -> Hash256 {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(data);
    let first_hash = hasher.finalize();

    let mut hasher = Sha256::new();
    hasher.update(&first_hash);
    let second_hash = hasher.finalize();

    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&second_hash);
    Hash256(bytes)
}

/// Single SHA-256 hash computation
pub fn sha256(data: &[u8]) -> Hash256 {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(data);
    let hash = hasher.finalize();

    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&hash);
    Hash256(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash256_creation() {
        let bytes = [0x00u8; 32];
        let hash = Hash256::from_bytes(bytes);
        assert_eq!(hash.as_bytes(), &bytes);
    }

    #[test]
    fn test_hash256_hex() {
        let hex = "0000000000000000000000000000000000000000000000000000000000000001";
        let hash = Hash256::from_hex(hex).unwrap();
        assert_eq!(hash.to_hex(), hex);
    }

    #[test]
    fn test_hash256_display() {
        let hash = Hash256::from_hex("0000000000000000000000000000000000000000000000000000000000000001")
            .unwrap();
        assert_eq!(hash.to_hex_reversed(), "0100000000000000000000000000000000000000000000000000000000000000");
    }

    #[test]
    fn test_txid_creation() {
        let txid = Txid::zero();
        assert_eq!(txid.to_hex(), "0000000000000000000000000000000000000000000000000000000000000000");
    }
}
