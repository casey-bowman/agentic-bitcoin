//! Cryptographic hashing functions
//!
//! Double-SHA256, SHA256, SHA-1, and RIPEMD-160 hashing used throughout Bitcoin.

use crate::primitives::hash::Hash256;
use sha1::Sha1;
use sha2::{Digest, Sha256};

/// Compute double-SHA256 hash (hash256)
///
/// This is the standard hashing function used throughout Bitcoin for
/// transaction IDs, block hashes, and merkle roots.
pub fn hash256(data: &[u8]) -> Hash256 {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let first_hash = hasher.finalize();

    let mut hasher = Sha256::new();
    hasher.update(&first_hash);
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
    ripemd_hasher.update(&sha256_hash);
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
        
        // Verify it produces a 32-byte result
        assert_eq!(hash.as_bytes().len(), 32);
    }

    #[test]
    fn test_sha256() {
        let data = b"hello";
        let hash = sha256(data);
        
        // Verify it produces a 32-byte result
        assert_eq!(hash.as_bytes().len(), 32);
    }

    #[test]
    fn test_hash160() {
        let data = b"hello";
        let hash = hash160(data);
        
        // Verify it produces a 20-byte result
        assert_eq!(hash.len(), 20);
    }

    #[test]
    fn test_sha1() {
        let data = b"hello";
        let hash = sha1(data);

        // Verify it produces a 20-byte result
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
        
        // Same input should produce same hash
        assert_eq!(hash1, hash2);
    }
}
