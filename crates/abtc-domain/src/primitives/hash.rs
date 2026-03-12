//! Bitcoin hash types
//!
//! Re-exports `Hash256` from the `hashing` module and defines Txid, Wtxid,
//! and BlockHash newtypes.

use std::fmt;

// Re-export Hash256 from hashing (the canonical definition)
pub use crate::hashing::Hash256;

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
        Txid(Hash256::from_bytes([0u8; 32]))
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
        Wtxid(Hash256::from_bytes([0u8; 32]))
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
        BlockHash(Hash256::from_bytes([
            0x6f, 0xe2, 0x8c, 0x0a, 0xb6, 0xf1, 0xb3, 0x72, 0xc1, 0xa6, 0xa2, 0x46, 0xae, 0x63,
            0xf7, 0x4f, 0x93, 0x1e, 0x83, 0x65, 0xe1, 0x5a, 0x08, 0x9c, 0x68, 0xd6, 0x19, 0x00,
            0x00, 0x00, 0x00, 0x00,
        ]))
    }

    /// Zero block hash
    pub const fn zero() -> Self {
        BlockHash(Hash256::from_bytes([0u8; 32]))
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
        let hash =
            Hash256::from_hex("0000000000000000000000000000000000000000000000000000000000000001")
                .unwrap();
        assert_eq!(
            hash.to_hex_reversed(),
            "0100000000000000000000000000000000000000000000000000000000000000"
        );
    }

    #[test]
    fn test_txid_creation() {
        let txid = Txid::zero();
        assert_eq!(
            txid.to_hex(),
            "0000000000000000000000000000000000000000000000000000000000000000"
        );
    }
}
