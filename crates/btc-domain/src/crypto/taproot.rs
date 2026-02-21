//! BIP341/BIP342 Taproot verification
//!
//! Implements Taproot key-path and script-path spending as defined in:
//! - BIP341: Taproot: SegWit version 1 spending rules
//! - BIP342: Validation of Taproot scripts
//!
//! ## Taproot Structure
//!
//! A Taproot output is a witness v1 program containing a 32-byte x-only
//! public key (the "output key"). This key is computed as:
//!
//!   Q = P + t*G
//!
//! where P is the "internal key" and t = tagged_hash("TapTweak", P || merkle_root).
//!
//! ## Spending Paths
//!
//! **Key path**: witness = [signature]
//!   Verify the Schnorr signature against Q (the output key) directly.
//!
//! **Script path**: witness = [script_args..., script, control_block]
//!   1. Parse the control block (leaf version + internal key + merkle path)
//!   2. Compute the leaf hash from the script
//!   3. Verify the merkle proof against the internal key to get Q
//!   4. Execute the script with the remaining witness items

use sha2::{Digest, Sha256};

/// BIP341 leaf version for tapscript (BIP342)
pub const TAPSCRIPT_LEAF_VERSION: u8 = 0xC0;

/// Maximum depth of the taproot merkle tree
pub const TAPROOT_CONTROL_MAX_NODE_COUNT: usize = 128;

/// Size of a single merkle proof node (32 bytes)
pub const TAPROOT_CONTROL_NODE_SIZE: usize = 32;

/// Base size of control block: 1 (leaf version + parity) + 32 (internal key)
pub const TAPROOT_CONTROL_BASE_SIZE: usize = 33;

/// Maximum size of a control block
pub const TAPROOT_CONTROL_MAX_SIZE: usize =
    TAPROOT_CONTROL_BASE_SIZE + TAPROOT_CONTROL_NODE_COUNT * TAPROOT_CONTROL_NODE_SIZE;

// Correct: maximum is 128 nodes (not TAPROOT_CONTROL_MAX_NODE_COUNT which causes recursion)
const TAPROOT_CONTROL_NODE_COUNT: usize = 128;

/// A parsed Taproot control block (BIP341)
#[derive(Debug, Clone)]
pub struct ControlBlock {
    /// Leaf version (top 7 bits of first byte, with parity bit masked out)
    pub leaf_version: u8,
    /// Parity of the output key (lowest bit of first byte)
    pub output_key_parity: bool,
    /// The internal key (32-byte x-only pubkey)
    pub internal_key: [u8; 32],
    /// The merkle proof: sequence of 32-byte hashes
    pub merkle_path: Vec<[u8; 32]>,
}

impl ControlBlock {
    /// Parse a control block from raw bytes.
    ///
    /// Format: [leaf_version_and_parity (1 byte)] [internal_key (32 bytes)] [path (n * 32 bytes)]
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < TAPROOT_CONTROL_BASE_SIZE {
            return None;
        }

        let path_len = data.len() - TAPROOT_CONTROL_BASE_SIZE;
        if path_len % TAPROOT_CONTROL_NODE_SIZE != 0 {
            return None;
        }

        let node_count = path_len / TAPROOT_CONTROL_NODE_SIZE;
        if node_count > TAPROOT_CONTROL_MAX_NODE_COUNT {
            return None;
        }

        let first_byte = data[0];
        let leaf_version = first_byte & 0xFE; // Top 7 bits
        let output_key_parity = (first_byte & 0x01) != 0;

        let mut internal_key = [0u8; 32];
        internal_key.copy_from_slice(&data[1..33]);

        let mut merkle_path = Vec::with_capacity(node_count);
        for i in 0..node_count {
            let start = TAPROOT_CONTROL_BASE_SIZE + i * TAPROOT_CONTROL_NODE_SIZE;
            let mut node = [0u8; 32];
            node.copy_from_slice(&data[start..start + 32]);
            merkle_path.push(node);
        }

        Some(ControlBlock {
            leaf_version,
            output_key_parity,
            internal_key,
            merkle_path,
        })
    }
}

/// Compute a BIP340 tagged hash: SHA256(SHA256(tag) || SHA256(tag) || data)
///
/// Tagged hashes are used throughout Taproot to domain-separate different
/// hash computations, preventing cross-protocol attacks.
pub fn tagged_hash(tag: &str, data: &[u8]) -> [u8; 32] {
    // Compute the tag hash
    let mut tag_hasher = Sha256::new();
    tag_hasher.update(tag.as_bytes());
    let tag_hash = tag_hasher.finalize();

    // SHA256(tag_hash || tag_hash || data)
    let mut hasher = Sha256::new();
    hasher.update(&tag_hash);
    hasher.update(&tag_hash);
    hasher.update(data);
    let result = hasher.finalize();

    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&result);
    bytes
}

/// Compute the tapleaf hash for a script (BIP341).
///
/// tapleaf_hash = tagged_hash("TapLeaf", leaf_version || compact_size(script) || script)
pub fn tapleaf_hash(leaf_version: u8, script: &[u8]) -> [u8; 32] {
    let mut data = Vec::with_capacity(1 + 5 + script.len());
    data.push(leaf_version);
    // Compact size encoding of script length
    encode_compact_size(&mut data, script.len());
    data.extend_from_slice(script);
    tagged_hash("TapLeaf", &data)
}

/// Compute the tapbranch hash from two child hashes (BIP341).
///
/// tapbranch_hash = tagged_hash("TapBranch", sorted(left, right))
///
/// The two children are sorted lexicographically before hashing to ensure
/// the merkle tree construction is canonical.
pub fn tapbranch_hash(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let mut data = [0u8; 64];
    // Sort: the smaller hash goes first
    if a <= b {
        data[..32].copy_from_slice(a);
        data[32..].copy_from_slice(b);
    } else {
        data[..32].copy_from_slice(b);
        data[32..].copy_from_slice(a);
    }
    tagged_hash("TapBranch", &data)
}

/// Compute the taptweak hash (BIP341).
///
/// tweak = tagged_hash("TapTweak", internal_key || merkle_root)
///
/// For key-path spending (no scripts), merkle_root is empty.
pub fn taptweak_hash(internal_key: &[u8; 32], merkle_root: Option<&[u8; 32]>) -> [u8; 32] {
    let mut data = Vec::with_capacity(64);
    data.extend_from_slice(internal_key);
    if let Some(root) = merkle_root {
        data.extend_from_slice(root);
    }
    tagged_hash("TapTweak", &data)
}

/// Verify a Taproot script-path merkle proof (BIP341).
///
/// Given a leaf hash and the merkle path from the control block, compute
/// the merkle root and derive the expected output key. Then verify it
/// matches the actual witness program.
///
/// # Arguments
/// * `output_key_bytes` - 32-byte witness program (the output x-only pubkey)
/// * `control` - Parsed control block
/// * `script` - The script being executed
///
/// # Returns
/// `true` if the merkle proof is valid and the output key matches
pub fn verify_taproot_commitment(
    output_key_bytes: &[u8],
    control: &ControlBlock,
    script: &[u8],
) -> bool {
    if output_key_bytes.len() != 32 {
        return false;
    }

    // Step 1: Compute the leaf hash
    let mut k = tapleaf_hash(control.leaf_version, script);

    // Step 2: Walk the merkle path to compute the root
    for node in &control.merkle_path {
        k = tapbranch_hash(&k, node);
    }

    // Step 3: Compute the tweak from internal key + merkle root
    let tweak = taptweak_hash(&control.internal_key, Some(&k));

    // Step 4: Verify: Q = P + tweak*G
    // Use secp256k1 to check that the output key matches
    verify_tweaked_output(
        &control.internal_key,
        &tweak,
        output_key_bytes,
        control.output_key_parity,
    )
}

/// Verify that output_key = internal_key + tweak*G with the expected parity.
///
/// This is the core BIP341 commitment check.
fn verify_tweaked_output(
    internal_key: &[u8; 32],
    tweak: &[u8; 32],
    output_key: &[u8],
    expected_parity: bool,
) -> bool {
    use secp256k1::{Secp256k1, XOnlyPublicKey, Scalar};

    let secp = Secp256k1::verification_only();

    // Parse the internal key
    let pk = match XOnlyPublicKey::from_slice(internal_key) {
        Ok(pk) => pk,
        Err(_) => return false,
    };

    // Parse the tweak as a scalar
    let scalar = match Scalar::from_be_bytes(*tweak) {
        Ok(s) => s,
        Err(_) => return false,
    };

    // Compute tweaked key: Q = P + t*G
    // add_tweak returns (tweaked_key, parity)
    let (tweaked_key, parity) = match pk.add_tweak(&secp, &scalar) {
        Ok(result) => result,
        Err(_) => return false,
    };

    // Parse the expected output key
    let expected = match XOnlyPublicKey::from_slice(output_key) {
        Ok(pk) => pk,
        Err(_) => return false,
    };

    // Check both the key and parity match
    let parity_matches = match parity {
        secp256k1::Parity::Even => !expected_parity,
        secp256k1::Parity::Odd => expected_parity,
    };

    tweaked_key == expected && parity_matches
}

/// Compute the Taproot sighash for key-path spending (BIP341 §4.1).
///
/// This is a simplified version that handles SIGHASH_DEFAULT / SIGHASH_ALL.
/// The full sighash computation involves epoch, hash_type, and all transaction
/// data serialized in a specific order under the "TapSighash" tag.
///
/// # Arguments
/// * `epoch` - Always 0 for BIP341
/// * `hash_type` - The sighash type byte
/// * `tx_data` - Pre-serialized transaction data for the sighash
///
/// # Returns
/// 32-byte sighash digest
pub fn taproot_sighash(epoch: u8, hash_type: u8, tx_data: &[u8]) -> [u8; 32] {
    let mut data = Vec::with_capacity(1 + 1 + tx_data.len());
    data.push(epoch);
    data.push(hash_type);
    data.extend_from_slice(tx_data);
    tagged_hash("TapSighash", &data)
}

/// Encode a compact size integer (Bitcoin varint) into a buffer.
fn encode_compact_size(buf: &mut Vec<u8>, size: usize) {
    if size < 0xFD {
        buf.push(size as u8);
    } else if size <= 0xFFFF {
        buf.push(0xFD);
        buf.extend_from_slice(&(size as u16).to_le_bytes());
    } else if size <= 0xFFFF_FFFF {
        buf.push(0xFE);
        buf.extend_from_slice(&(size as u32).to_le_bytes());
    } else {
        buf.push(0xFF);
        buf.extend_from_slice(&(size as u64).to_le_bytes());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tagged_hash_deterministic() {
        let hash1 = tagged_hash("TapLeaf", b"test");
        let hash2 = tagged_hash("TapLeaf", b"test");
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_tagged_hash_domain_separation() {
        let hash1 = tagged_hash("TapLeaf", b"test");
        let hash2 = tagged_hash("TapBranch", b"test");
        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_tapbranch_hash_sorted() {
        let a = [0x01u8; 32];
        let b = [0x02u8; 32];

        // Order shouldn't matter — both orderings produce the same hash
        let hash_ab = tapbranch_hash(&a, &b);
        let hash_ba = tapbranch_hash(&b, &a);
        assert_eq!(hash_ab, hash_ba);
    }

    #[test]
    fn test_taptweak_no_merkle_root() {
        let key = [0x02u8; 32];
        let tweak1 = taptweak_hash(&key, None);
        let tweak2 = taptweak_hash(&key, Some(&[0u8; 32]));
        // With and without merkle root should differ
        assert_ne!(tweak1, tweak2);
    }

    #[test]
    fn test_control_block_parse_minimum() {
        // Minimum control block: 33 bytes (1 + 32)
        let mut data = vec![TAPSCRIPT_LEAF_VERSION]; // leaf version 0xC0, parity 0
        data.extend_from_slice(&[0x02; 32]); // internal key

        let cb = ControlBlock::parse(&data).unwrap();
        assert_eq!(cb.leaf_version, TAPSCRIPT_LEAF_VERSION);
        assert!(!cb.output_key_parity);
        assert_eq!(cb.internal_key, [0x02; 32]);
        assert!(cb.merkle_path.is_empty());
    }

    #[test]
    fn test_control_block_parse_with_path() {
        let mut data = vec![TAPSCRIPT_LEAF_VERSION | 0x01]; // parity = 1
        data.extend_from_slice(&[0x02; 32]); // internal key
        data.extend_from_slice(&[0xAA; 32]); // one merkle node

        let cb = ControlBlock::parse(&data).unwrap();
        assert!(cb.output_key_parity);
        assert_eq!(cb.merkle_path.len(), 1);
        assert_eq!(cb.merkle_path[0], [0xAA; 32]);
    }

    #[test]
    fn test_control_block_parse_too_short() {
        let data = vec![0xC0; 32]; // Only 32 bytes, need at least 33
        assert!(ControlBlock::parse(&data).is_none());
    }

    #[test]
    fn test_control_block_parse_bad_path_length() {
        let mut data = vec![TAPSCRIPT_LEAF_VERSION];
        data.extend_from_slice(&[0x02; 32]);
        data.extend_from_slice(&[0xAA; 15]); // Not a multiple of 32
        assert!(ControlBlock::parse(&data).is_none());
    }

    #[test]
    fn test_tapleaf_hash_basic() {
        let script = vec![0x51]; // OP_1
        let hash = tapleaf_hash(TAPSCRIPT_LEAF_VERSION, &script);
        assert_eq!(hash.len(), 32);
        // Should be deterministic
        assert_eq!(hash, tapleaf_hash(TAPSCRIPT_LEAF_VERSION, &script));
    }

    #[test]
    fn test_compact_size_encoding() {
        let mut buf = Vec::new();
        encode_compact_size(&mut buf, 0);
        assert_eq!(buf, vec![0x00]);

        buf.clear();
        encode_compact_size(&mut buf, 252);
        assert_eq!(buf, vec![0xFC]);

        buf.clear();
        encode_compact_size(&mut buf, 253);
        assert_eq!(buf, vec![0xFD, 0xFD, 0x00]);

        buf.clear();
        encode_compact_size(&mut buf, 0xFFFF);
        assert_eq!(buf, vec![0xFD, 0xFF, 0xFF]);
    }

    #[test]
    fn test_taproot_sighash_deterministic() {
        let tx_data = b"some transaction data";
        let hash1 = taproot_sighash(0, 0x00, tx_data);
        let hash2 = taproot_sighash(0, 0x00, tx_data);
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_taproot_sighash_different_types() {
        let tx_data = b"some transaction data";
        let hash_default = taproot_sighash(0, 0x00, tx_data);
        let hash_all = taproot_sighash(0, 0x01, tx_data);
        assert_ne!(hash_default, hash_all);
    }
}
