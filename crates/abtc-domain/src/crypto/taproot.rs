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
//! **Key path**: witness = \[signature\]
//!   Verify the Schnorr signature against Q (the output key) directly.
//!
//! **Script path**: witness = \[script_args..., script, control_block\]
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
    hasher.update(tag_hash);
    hasher.update(tag_hash);
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
    use secp256k1::{Scalar, Secp256k1, XOnlyPublicKey};

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

/// A leaf in a Taproot script tree.
#[derive(Debug, Clone)]
pub struct TapLeaf {
    /// Leaf version (0xC0 for tapscript / BIP342)
    pub leaf_version: u8,
    /// The script bytes
    pub script: Vec<u8>,
}

impl TapLeaf {
    /// Create a new tapscript leaf (leaf version 0xC0).
    pub fn new(script: Vec<u8>) -> Self {
        TapLeaf {
            leaf_version: TAPSCRIPT_LEAF_VERSION,
            script,
        }
    }

    /// Compute the leaf hash: tagged_hash("TapLeaf", version || compact_size(script) || script)
    pub fn hash(&self) -> [u8; 32] {
        tapleaf_hash(self.leaf_version, &self.script)
    }
}

/// Internal representation of a node in the tap tree.
#[derive(Debug, Clone)]
enum TapNode {
    Leaf(usize), // index into TapTree.leaves
    Branch(Box<TapNode>, Box<TapNode>),
}

impl TapNode {
    /// Compute the merkle hash for this node given the leaf hashes.
    fn hash(&self, leaf_hashes: &[[u8; 32]]) -> [u8; 32] {
        match self {
            TapNode::Leaf(idx) => leaf_hashes[*idx],
            TapNode::Branch(left, right) => {
                let lh = left.hash(leaf_hashes);
                let rh = right.hash(leaf_hashes);
                tapbranch_hash(&lh, &rh)
            }
        }
    }

    /// Collect the merkle proof (sibling hashes) for a target leaf index.
    fn merkle_proof(
        &self,
        target: usize,
        leaf_hashes: &[[u8; 32]],
        path: &mut Vec<[u8; 32]>,
    ) -> bool {
        match self {
            TapNode::Leaf(idx) => *idx == target,
            TapNode::Branch(left, right) => {
                if left.merkle_proof(target, leaf_hashes, path) {
                    path.push(right.hash(leaf_hashes));
                    true
                } else if right.merkle_proof(target, leaf_hashes, path) {
                    path.push(left.hash(leaf_hashes));
                    true
                } else {
                    false
                }
            }
        }
    }
}

/// A Taproot script tree builder.
///
/// Constructs a balanced binary Huffman-style tree from a set of script leaves,
/// computes the merkle root, and generates control blocks for spending any leaf.
///
/// # Example
///
/// ```ignore
/// let tree = TapTree::new(vec![
///     TapLeaf::new(vec![0x51]),  // OP_1
///     TapLeaf::new(vec![0x52]),  // OP_2
/// ]);
/// let root = tree.merkle_root();
/// let control = tree.control_block(0, &internal_key, parity);
/// ```
#[derive(Debug, Clone)]
pub struct TapTree {
    /// The script leaves in insertion order
    leaves: Vec<TapLeaf>,
    /// Pre-computed leaf hashes
    leaf_hashes: Vec<[u8; 32]>,
    /// The tree structure
    root_node: TapNode,
}

impl TapTree {
    /// Build a TapTree from a list of leaves.
    ///
    /// The tree is built as a balanced binary tree. For a single leaf, the
    /// leaf hash is the merkle root. For multiple leaves, they are paired
    /// bottom-up into a balanced structure.
    ///
    /// # Panics
    /// Panics if `leaves` is empty.
    pub fn new(leaves: Vec<TapLeaf>) -> Self {
        assert!(!leaves.is_empty(), "TapTree requires at least one leaf");

        let leaf_hashes: Vec<[u8; 32]> = leaves.iter().map(|l| l.hash()).collect();

        // Build a balanced tree from leaf indices
        let root_node = Self::build_tree(0, leaves.len());

        TapTree {
            leaves,
            leaf_hashes,
            root_node,
        }
    }

    /// Build a balanced binary tree over leaf indices [start..end).
    fn build_tree(start: usize, end: usize) -> TapNode {
        let count = end - start;
        if count == 1 {
            TapNode::Leaf(start)
        } else {
            // Split roughly in half (left-biased for odd counts)
            let mid = start + count / 2;
            TapNode::Branch(
                Box::new(Self::build_tree(start, mid)),
                Box::new(Self::build_tree(mid, end)),
            )
        }
    }

    /// Compute the merkle root of the script tree.
    pub fn merkle_root(&self) -> [u8; 32] {
        self.root_node.hash(&self.leaf_hashes)
    }

    /// Get the number of leaves in the tree.
    pub fn len(&self) -> usize {
        self.leaves.len()
    }

    /// Whether the tree is empty.
    pub fn is_empty(&self) -> bool {
        self.leaves.is_empty()
    }

    /// Get a reference to a leaf by index.
    pub fn leaf(&self, index: usize) -> Option<&TapLeaf> {
        self.leaves.get(index)
    }

    /// Get the leaf hash for a given leaf index.
    pub fn leaf_hash(&self, index: usize) -> Option<[u8; 32]> {
        self.leaf_hashes.get(index).copied()
    }

    /// Generate a control block for spending the leaf at `leaf_index`.
    ///
    /// # Arguments
    /// * `leaf_index` - Index of the leaf to spend
    /// * `internal_key` - The 32-byte x-only internal public key
    /// * `output_key_parity` - Parity bit of the output key (from tweaking)
    ///
    /// # Returns
    /// A `ControlBlock` containing the leaf version, internal key, parity,
    /// and the merkle proof (sibling hashes from leaf to root).
    pub fn control_block(
        &self,
        leaf_index: usize,
        internal_key: &[u8; 32],
        output_key_parity: bool,
    ) -> Option<ControlBlock> {
        if leaf_index >= self.leaves.len() {
            return None;
        }

        let mut merkle_path = Vec::new();
        self.root_node
            .merkle_proof(leaf_index, &self.leaf_hashes, &mut merkle_path);

        Some(ControlBlock {
            leaf_version: self.leaves[leaf_index].leaf_version,
            output_key_parity,
            internal_key: *internal_key,
            merkle_path,
        })
    }

    /// Serialize a control block to bytes for inclusion in the witness.
    pub fn serialize_control_block(control: &ControlBlock) -> Vec<u8> {
        let mut data =
            Vec::with_capacity(TAPROOT_CONTROL_BASE_SIZE + control.merkle_path.len() * 32);
        // First byte: leaf_version | parity_bit
        let first_byte = control.leaf_version
            | if control.output_key_parity {
                0x01
            } else {
                0x00
            };
        data.push(first_byte);
        data.extend_from_slice(&control.internal_key);
        for node in &control.merkle_path {
            data.extend_from_slice(node);
        }
        data
    }

    /// Compute the tweaked output key and parity from an internal key and this tree.
    ///
    /// Returns (output_key_x_only, parity_is_odd)
    pub fn compute_output_key(&self, internal_key: &[u8; 32]) -> Option<([u8; 32], bool)> {
        use secp256k1::{Scalar, Secp256k1, XOnlyPublicKey};

        let secp = Secp256k1::verification_only();

        let pk = XOnlyPublicKey::from_slice(internal_key).ok()?;
        let merkle_root = self.merkle_root();
        let tweak = taptweak_hash(internal_key, Some(&merkle_root));
        let scalar = Scalar::from_be_bytes(tweak).ok()?;
        let (tweaked_key, parity) = pk.add_tweak(&secp, &scalar).ok()?;

        let parity_is_odd = matches!(parity, secp256k1::Parity::Odd);
        Some((tweaked_key.serialize(), parity_is_odd))
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

    // ── Taproot script-path verification tests ─────────────────────

    #[test]
    fn test_verify_taproot_commitment_single_script() {
        // Construct a complete Taproot script-path commitment and verify it.
        // Steps: create internal key → create script → compute merkle root
        //        → derive output key → verify commitment
        use secp256k1::{Scalar, Secp256k1, SecretKey};

        let secp = Secp256k1::new();

        // Generate a real internal key
        let secret = SecretKey::from_slice(&[0x42; 32]).unwrap();
        let (internal_xonly, _parity) = secret.x_only_public_key(&secp);
        let internal_key_bytes: [u8; 32] = internal_xonly.serialize();

        // Create a simple tapscript: OP_1 (always true)
        let script = vec![0x51];

        // Compute leaf hash → this is also the merkle root for a single-script tree
        let leaf_hash = tapleaf_hash(TAPSCRIPT_LEAF_VERSION, &script);

        // Compute tweak and output key
        let tweak = taptweak_hash(&internal_key_bytes, Some(&leaf_hash));
        let scalar = Scalar::from_be_bytes(tweak).unwrap();
        let (tweaked_key, parity) = internal_xonly.add_tweak(&secp, &scalar).unwrap();
        let output_key_bytes = tweaked_key.serialize();

        let expected_parity = match parity {
            secp256k1::Parity::Even => false,
            secp256k1::Parity::Odd => true,
        };

        // Build control block
        let control = ControlBlock {
            leaf_version: TAPSCRIPT_LEAF_VERSION,
            output_key_parity: expected_parity,
            internal_key: internal_key_bytes,
            merkle_path: vec![], // Single script, no merkle path
        };

        // Verify the commitment
        assert!(
            verify_taproot_commitment(&output_key_bytes, &control, &script),
            "Single-script taproot commitment should be valid"
        );
    }

    #[test]
    fn test_verify_taproot_commitment_wrong_script_fails() {
        use secp256k1::{Scalar, Secp256k1, SecretKey};

        let secp = Secp256k1::new();
        let secret = SecretKey::from_slice(&[0x42; 32]).unwrap();
        let (internal_xonly, _) = secret.x_only_public_key(&secp);
        let internal_key_bytes = internal_xonly.serialize();

        // Commit to OP_1
        let script = vec![0x51];
        let leaf_hash = tapleaf_hash(TAPSCRIPT_LEAF_VERSION, &script);
        let tweak = taptweak_hash(&internal_key_bytes, Some(&leaf_hash));
        let scalar = Scalar::from_be_bytes(tweak).unwrap();
        let (tweaked_key, parity) = internal_xonly.add_tweak(&secp, &scalar).unwrap();
        let output_key_bytes = tweaked_key.serialize();

        let expected_parity = match parity {
            secp256k1::Parity::Even => false,
            secp256k1::Parity::Odd => true,
        };

        let control = ControlBlock {
            leaf_version: TAPSCRIPT_LEAF_VERSION,
            output_key_parity: expected_parity,
            internal_key: internal_key_bytes,
            merkle_path: vec![],
        };

        // Try to verify with a DIFFERENT script (OP_2 instead of OP_1)
        let wrong_script = vec![0x52];
        assert!(
            !verify_taproot_commitment(&output_key_bytes, &control, &wrong_script),
            "Wrong script should fail verification"
        );
    }

    #[test]
    fn test_verify_taproot_commitment_two_scripts() {
        // Build a Taproot tree with two scripts and verify each one
        use secp256k1::{Scalar, Secp256k1, SecretKey};

        let secp = Secp256k1::new();
        let secret = SecretKey::from_slice(&[0x42; 32]).unwrap();
        let (internal_xonly, _) = secret.x_only_public_key(&secp);
        let internal_key_bytes = internal_xonly.serialize();

        // Two scripts
        let script_a = vec![0x51]; // OP_1
        let script_b = vec![0x52]; // OP_2

        let leaf_a = tapleaf_hash(TAPSCRIPT_LEAF_VERSION, &script_a);
        let leaf_b = tapleaf_hash(TAPSCRIPT_LEAF_VERSION, &script_b);

        // Merkle root = tapbranch(leaf_a, leaf_b)
        let merkle_root = tapbranch_hash(&leaf_a, &leaf_b);

        // Derive output key from internal key + merkle root
        let tweak = taptweak_hash(&internal_key_bytes, Some(&merkle_root));
        let scalar = Scalar::from_be_bytes(tweak).unwrap();
        let (tweaked_key, parity) = internal_xonly.add_tweak(&secp, &scalar).unwrap();
        let output_key_bytes = tweaked_key.serialize();

        let expected_parity = match parity {
            secp256k1::Parity::Even => false,
            secp256k1::Parity::Odd => true,
        };

        // Verify script A: merkle path = [leaf_b]
        let control_a = ControlBlock {
            leaf_version: TAPSCRIPT_LEAF_VERSION,
            output_key_parity: expected_parity,
            internal_key: internal_key_bytes,
            merkle_path: vec![leaf_b],
        };
        assert!(
            verify_taproot_commitment(&output_key_bytes, &control_a, &script_a),
            "Script A should verify with leaf_b as sibling"
        );

        // Verify script B: merkle path = [leaf_a]
        let control_b = ControlBlock {
            leaf_version: TAPSCRIPT_LEAF_VERSION,
            output_key_parity: expected_parity,
            internal_key: internal_key_bytes,
            merkle_path: vec![leaf_a],
        };
        assert!(
            verify_taproot_commitment(&output_key_bytes, &control_b, &script_b),
            "Script B should verify with leaf_a as sibling"
        );
    }

    #[test]
    fn test_verify_taproot_commitment_wrong_parity_fails() {
        use secp256k1::{Scalar, Secp256k1, SecretKey};

        let secp = Secp256k1::new();
        let secret = SecretKey::from_slice(&[0x42; 32]).unwrap();
        let (internal_xonly, _) = secret.x_only_public_key(&secp);
        let internal_key_bytes = internal_xonly.serialize();

        let script = vec![0x51];
        let leaf_hash = tapleaf_hash(TAPSCRIPT_LEAF_VERSION, &script);
        let tweak = taptweak_hash(&internal_key_bytes, Some(&leaf_hash));
        let scalar = Scalar::from_be_bytes(tweak).unwrap();
        let (tweaked_key, parity) = internal_xonly.add_tweak(&secp, &scalar).unwrap();
        let output_key_bytes = tweaked_key.serialize();

        // Use the WRONG parity
        let wrong_parity = match parity {
            secp256k1::Parity::Even => true,
            secp256k1::Parity::Odd => false,
        };

        let control = ControlBlock {
            leaf_version: TAPSCRIPT_LEAF_VERSION,
            output_key_parity: wrong_parity,
            internal_key: internal_key_bytes,
            merkle_path: vec![],
        };

        assert!(
            !verify_taproot_commitment(&output_key_bytes, &control, &script),
            "Wrong parity should fail verification"
        );
    }

    #[test]
    fn test_verify_taproot_commitment_wrong_internal_key_fails() {
        use secp256k1::{Scalar, Secp256k1, SecretKey};

        let secp = Secp256k1::new();
        let secret = SecretKey::from_slice(&[0x42; 32]).unwrap();
        let (internal_xonly, _) = secret.x_only_public_key(&secp);
        let internal_key_bytes = internal_xonly.serialize();

        let script = vec![0x51];
        let leaf_hash = tapleaf_hash(TAPSCRIPT_LEAF_VERSION, &script);
        let tweak = taptweak_hash(&internal_key_bytes, Some(&leaf_hash));
        let scalar = Scalar::from_be_bytes(tweak).unwrap();
        let (tweaked_key, parity) = internal_xonly.add_tweak(&secp, &scalar).unwrap();
        let output_key_bytes = tweaked_key.serialize();

        let expected_parity = match parity {
            secp256k1::Parity::Even => false,
            secp256k1::Parity::Odd => true,
        };

        // Use a DIFFERENT internal key
        let wrong_secret = SecretKey::from_slice(&[0x43; 32]).unwrap();
        let (wrong_xonly, _) = wrong_secret.x_only_public_key(&secp);
        let wrong_key_bytes = wrong_xonly.serialize();

        let control = ControlBlock {
            leaf_version: TAPSCRIPT_LEAF_VERSION,
            output_key_parity: expected_parity,
            internal_key: wrong_key_bytes,
            merkle_path: vec![],
        };

        assert!(
            !verify_taproot_commitment(&output_key_bytes, &control, &script),
            "Wrong internal key should fail verification"
        );
    }

    #[test]
    fn test_verify_taproot_commitment_bad_output_key_length() {
        let control = ControlBlock {
            leaf_version: TAPSCRIPT_LEAF_VERSION,
            output_key_parity: false,
            internal_key: [0x02; 32],
            merkle_path: vec![],
        };

        // Output key too short (31 bytes instead of 32)
        assert!(!verify_taproot_commitment(&[0x02; 31], &control, &[0x51]));
        // Output key too long (33 bytes)
        assert!(!verify_taproot_commitment(&[0x02; 33], &control, &[0x51]));
        // Empty output key
        assert!(!verify_taproot_commitment(&[], &control, &[0x51]));
    }

    #[test]
    fn test_taptweak_key_path_vs_script_path_differ() {
        // Key-path spending uses taptweak with no merkle root
        // Script-path spending uses taptweak with a merkle root
        // These must produce different tweaks
        let internal_key = [0x02; 32];
        let script = vec![0x51];
        let leaf_hash = tapleaf_hash(TAPSCRIPT_LEAF_VERSION, &script);

        let key_path_tweak = taptweak_hash(&internal_key, None);
        let script_path_tweak = taptweak_hash(&internal_key, Some(&leaf_hash));

        assert_ne!(key_path_tweak, script_path_tweak);
    }

    #[test]
    fn test_tapleaf_hash_different_versions() {
        let script = vec![0x51]; // OP_1
        let hash_c0 = tapleaf_hash(0xC0, &script);
        let hash_c2 = tapleaf_hash(0xC2, &script); // hypothetical future leaf version

        assert_ne!(
            hash_c0, hash_c2,
            "Different leaf versions should produce different hashes"
        );
    }

    #[test]
    fn test_tapleaf_hash_different_scripts() {
        let hash_1 = tapleaf_hash(TAPSCRIPT_LEAF_VERSION, &[0x51]);
        let hash_2 = tapleaf_hash(TAPSCRIPT_LEAF_VERSION, &[0x52]);

        assert_ne!(
            hash_1, hash_2,
            "Different scripts should produce different leaf hashes"
        );
    }

    #[test]
    fn test_control_block_parse_multiple_path_nodes() {
        // 3 merkle path nodes (depth-3 tree)
        let mut data = vec![TAPSCRIPT_LEAF_VERSION];
        data.extend_from_slice(&[0x02; 32]); // internal key
        data.extend_from_slice(&[0xAA; 32]); // node 0
        data.extend_from_slice(&[0xBB; 32]); // node 1
        data.extend_from_slice(&[0xCC; 32]); // node 2

        let cb = ControlBlock::parse(&data).unwrap();
        assert_eq!(cb.merkle_path.len(), 3);
        assert_eq!(cb.merkle_path[0], [0xAA; 32]);
        assert_eq!(cb.merkle_path[1], [0xBB; 32]);
        assert_eq!(cb.merkle_path[2], [0xCC; 32]);
    }

    #[test]
    fn test_control_block_parse_max_depth_rejected() {
        // 129 nodes exceeds TAPROOT_CONTROL_MAX_NODE_COUNT (128)
        let mut data = vec![TAPSCRIPT_LEAF_VERSION];
        data.extend_from_slice(&[0x02; 32]); // internal key
        for _ in 0..129 {
            data.extend_from_slice(&[0xAA; 32]);
        }
        assert!(ControlBlock::parse(&data).is_none());
    }

    #[test]
    fn test_control_block_parity_bit_extraction() {
        // Parity 0 (even)
        let mut data_even = vec![TAPSCRIPT_LEAF_VERSION]; // 0xC0, bit 0 = 0
        data_even.extend_from_slice(&[0x02; 32]);
        let cb_even = ControlBlock::parse(&data_even).unwrap();
        assert!(!cb_even.output_key_parity);
        assert_eq!(cb_even.leaf_version, TAPSCRIPT_LEAF_VERSION);

        // Parity 1 (odd)
        let mut data_odd = vec![TAPSCRIPT_LEAF_VERSION | 0x01]; // 0xC1, bit 0 = 1
        data_odd.extend_from_slice(&[0x02; 32]);
        let cb_odd = ControlBlock::parse(&data_odd).unwrap();
        assert!(cb_odd.output_key_parity);
        assert_eq!(cb_odd.leaf_version, TAPSCRIPT_LEAF_VERSION);
    }

    #[test]
    fn test_compact_size_encoding_large_values() {
        // 4-byte encoding (0xFE prefix)
        let mut buf = Vec::new();
        encode_compact_size(&mut buf, 0x10000);
        assert_eq!(buf[0], 0xFE);
        assert_eq!(buf.len(), 5); // 1 prefix + 4 bytes

        // 8-byte encoding (0xFF prefix) — values > u32::MAX
        buf.clear();
        encode_compact_size(&mut buf, 0x1_0000_0000);
        assert_eq!(buf[0], 0xFF);
        assert_eq!(buf.len(), 9); // 1 prefix + 8 bytes
    }

    #[test]
    fn test_taproot_sighash_different_epochs() {
        // Different epochs should produce different hashes
        let tx_data = b"some transaction data";
        let hash_epoch0 = taproot_sighash(0, 0x00, tx_data);
        let hash_epoch1 = taproot_sighash(1, 0x00, tx_data);
        assert_ne!(hash_epoch0, hash_epoch1);
    }

    #[test]
    fn test_taproot_sighash_different_tx_data() {
        let hash1 = taproot_sighash(0, 0x00, b"tx data 1");
        let hash2 = taproot_sighash(0, 0x00, b"tx data 2");
        assert_ne!(hash1, hash2);
    }

    // ── TapTree builder tests ────────────────────────────────────────

    #[test]
    fn test_taptree_single_leaf() {
        let leaf = TapLeaf::new(vec![0x51]); // OP_1
        let tree = TapTree::new(vec![leaf]);

        assert_eq!(tree.len(), 1);
        // Merkle root of a single leaf IS the leaf hash
        let expected_root = tapleaf_hash(TAPSCRIPT_LEAF_VERSION, &[0x51]);
        assert_eq!(tree.merkle_root(), expected_root);
    }

    #[test]
    fn test_taptree_two_leaves() {
        let tree = TapTree::new(vec![
            TapLeaf::new(vec![0x51]), // OP_1
            TapLeaf::new(vec![0x52]), // OP_2
        ]);

        let leaf_a = tapleaf_hash(TAPSCRIPT_LEAF_VERSION, &[0x51]);
        let leaf_b = tapleaf_hash(TAPSCRIPT_LEAF_VERSION, &[0x52]);
        let expected = tapbranch_hash(&leaf_a, &leaf_b);
        assert_eq!(tree.merkle_root(), expected);
    }

    #[test]
    fn test_taptree_three_leaves_balanced() {
        let tree = TapTree::new(vec![
            TapLeaf::new(vec![0x51]),
            TapLeaf::new(vec![0x52]),
            TapLeaf::new(vec![0x53]),
        ]);

        // Left subtree: leaf[0] alone; Right subtree: branch(leaf[1], leaf[2])
        // Tree split: [0..1) and [1..3), so left = leaf0, right = branch(leaf1, leaf2)
        let h0 = tapleaf_hash(TAPSCRIPT_LEAF_VERSION, &[0x51]);
        let h1 = tapleaf_hash(TAPSCRIPT_LEAF_VERSION, &[0x52]);
        let h2 = tapleaf_hash(TAPSCRIPT_LEAF_VERSION, &[0x53]);
        let right = tapbranch_hash(&h1, &h2);
        let expected = tapbranch_hash(&h0, &right);
        assert_eq!(tree.merkle_root(), expected);
    }

    #[test]
    fn test_taptree_control_block_single_leaf() {
        let tree = TapTree::new(vec![TapLeaf::new(vec![0x51])]);
        let internal_key = [0x02u8; 32];

        let cb = tree.control_block(0, &internal_key, false).unwrap();
        assert_eq!(cb.leaf_version, TAPSCRIPT_LEAF_VERSION);
        assert!(!cb.output_key_parity);
        assert_eq!(cb.internal_key, internal_key);
        assert!(cb.merkle_path.is_empty()); // Single leaf, no siblings
    }

    #[test]
    fn test_taptree_control_block_two_leaves() {
        let tree = TapTree::new(vec![TapLeaf::new(vec![0x51]), TapLeaf::new(vec![0x52])]);
        let internal_key = [0x02u8; 32];

        // Control block for leaf 0: merkle path = [leaf_1_hash]
        let cb0 = tree.control_block(0, &internal_key, false).unwrap();
        assert_eq!(cb0.merkle_path.len(), 1);
        let leaf1_hash = tapleaf_hash(TAPSCRIPT_LEAF_VERSION, &[0x52]);
        assert_eq!(cb0.merkle_path[0], leaf1_hash);

        // Control block for leaf 1: merkle path = [leaf_0_hash]
        let cb1 = tree.control_block(1, &internal_key, false).unwrap();
        assert_eq!(cb1.merkle_path.len(), 1);
        let leaf0_hash = tapleaf_hash(TAPSCRIPT_LEAF_VERSION, &[0x51]);
        assert_eq!(cb1.merkle_path[0], leaf0_hash);
    }

    #[test]
    fn test_taptree_control_block_out_of_range() {
        let tree = TapTree::new(vec![TapLeaf::new(vec![0x51])]);
        assert!(tree.control_block(1, &[0x02; 32], false).is_none());
    }

    #[test]
    fn test_taptree_serialize_control_block_roundtrip() {
        let tree = TapTree::new(vec![TapLeaf::new(vec![0x51]), TapLeaf::new(vec![0x52])]);
        let internal_key = [0x02u8; 32];
        let cb = tree.control_block(0, &internal_key, true).unwrap();

        let serialized = TapTree::serialize_control_block(&cb);
        let parsed = ControlBlock::parse(&serialized).unwrap();

        assert_eq!(parsed.leaf_version, cb.leaf_version);
        assert_eq!(parsed.output_key_parity, cb.output_key_parity);
        assert_eq!(parsed.internal_key, cb.internal_key);
        assert_eq!(parsed.merkle_path, cb.merkle_path);
    }

    #[test]
    fn test_taptree_compute_output_key_and_verify() {
        use secp256k1::{Secp256k1, SecretKey};

        let secp = Secp256k1::new();
        let secret = SecretKey::from_slice(&[0x42; 32]).unwrap();
        let (internal_xonly, _) = secret.x_only_public_key(&secp);
        let internal_key = internal_xonly.serialize();

        let tree = TapTree::new(vec![TapLeaf::new(vec![0x51]), TapLeaf::new(vec![0x52])]);

        let (output_key, parity) = tree.compute_output_key(&internal_key).unwrap();

        // Verify leaf 0 via control block
        let cb0 = tree.control_block(0, &internal_key, parity).unwrap();
        assert!(verify_taproot_commitment(&output_key, &cb0, &[0x51]));

        // Verify leaf 1 via control block
        let cb1 = tree.control_block(1, &internal_key, parity).unwrap();
        assert!(verify_taproot_commitment(&output_key, &cb1, &[0x52]));
    }
}
