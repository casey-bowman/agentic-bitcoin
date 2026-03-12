//! BIP158 Block Filter Construction and Filter Header Chain
//!
//! Constructs compact block filters from block data and maintains the
//! filter header chain used for commitment and verification.
//!
//! ## Basic Filter (Type 0)
//!
//! For each block, the basic filter includes:
//! - All scriptPubKeys from the block's transaction outputs (excluding OP_RETURN)
//! - All scriptPubKeys of previous outputs spent by the block's inputs
//!   (excluding the coinbase input, which has no previous output)
//!
//! ## Filter Header Chain
//!
//! Each filter header commits to both the filter itself and the previous
//! filter header, forming a chain analogous to the block header chain:
//!
//! ```text
//! filter_hash   = hash(filter_data)
//! filter_header = hash(filter_hash || prev_filter_header)
//! ```
//!
//! ## References
//!
//! - BIP158: <https://github.com/bitcoin/bips/blob/master/bip-0158.mediawiki>
//! - BIP157: <https://github.com/bitcoin/bips/blob/master/bip-0157.mediawiki>

use super::gcs::{key_from_block_hash, GcsFilter};
use crate::hashing::hash256;
use crate::primitives::block::Block;
use crate::primitives::hash::{BlockHash, Hash256};
use crate::script::Script;

// ---------------------------------------------------------------------------
// Filter type constants
// ---------------------------------------------------------------------------

/// BIP158 basic filter type identifier.
pub const BASIC_FILTER_TYPE: u8 = 0;

// ---------------------------------------------------------------------------
// Block filter construction
// ---------------------------------------------------------------------------

/// A constructed block filter with its associated metadata.
#[derive(Debug, Clone)]
pub struct BlockFilter {
    /// The filter type (0 = basic)
    pub filter_type: u8,
    /// The block hash this filter covers
    pub block_hash: BlockHash,
    /// The encoded GCS filter
    pub filter: GcsFilter,
}

impl BlockFilter {
    /// Construct a BIP158 basic filter for a block.
    ///
    /// The filter includes:
    /// - All non-OP_RETURN scriptPubKeys from transaction outputs
    /// - All scriptPubKeys of previous outputs spent by non-coinbase inputs
    ///   (provided via `prev_output_scripts`)
    ///
    /// `prev_output_scripts` should contain the scriptPubKey for each
    /// non-coinbase input, in the order they appear across all transactions.
    pub fn build_basic(block: &Block, prev_output_scripts: &[Script]) -> Self {
        let block_hash = block.block_hash();
        let mut elements: Vec<Vec<u8>> = Vec::new();

        // Collect output scriptPubKeys (skip OP_RETURN)
        for tx in &block.transactions {
            for output in &tx.outputs {
                if !output.script_pubkey.is_empty() && !output.script_pubkey.is_op_return() {
                    elements.push(output.script_pubkey.as_bytes().to_vec());
                }
            }
        }

        // Collect input scriptPubKeys (the scripts being spent)
        for script in prev_output_scripts {
            if !script.is_empty() && !script.is_op_return() {
                elements.push(script.as_bytes().to_vec());
            }
        }

        // Build the GCS filter
        let elem_refs: Vec<&[u8]> = elements.iter().map(|e| e.as_slice()).collect();
        let filter = GcsFilter::build_basic(block_hash.as_bytes(), &elem_refs);

        BlockFilter {
            filter_type: BASIC_FILTER_TYPE,
            block_hash,
            filter,
        }
    }

    /// Construct a basic filter from raw elements (for testing or custom use).
    pub fn from_elements(block_hash: BlockHash, elements: &[&[u8]]) -> Self {
        let filter = GcsFilter::build_basic(block_hash.as_bytes(), elements);
        BlockFilter {
            filter_type: BASIC_FILTER_TYPE,
            block_hash,
            filter,
        }
    }

    /// Check if a scriptPubKey might be in this filter.
    pub fn match_script(&self, script: &Script) -> bool {
        let (k0, k1) = key_from_block_hash(self.block_hash.as_bytes());
        self.filter.match_any(k0, k1, script.as_bytes())
    }

    /// Check if any of the given scriptPubKeys might be in this filter.
    pub fn match_any_scripts(&self, scripts: &[&Script]) -> bool {
        let (k0, k1) = key_from_block_hash(self.block_hash.as_bytes());
        let data: Vec<&[u8]> = scripts.iter().map(|s| s.as_bytes()).collect();
        self.filter.match_any_of(k0, k1, &data)
    }

    /// Serialize the filter in BIP158 format (N || filter_data).
    pub fn serialize(&self) -> Vec<u8> {
        self.filter.serialize()
    }

    /// Compute the filter hash: hash256(filter_data_with_n).
    pub fn filter_hash(&self) -> Hash256 {
        let data = self.serialize();
        hash256(&data)
    }
}

// ---------------------------------------------------------------------------
// Filter header chain
// ---------------------------------------------------------------------------

/// Compute a filter header from a filter hash and the previous filter header.
///
/// ```text
/// filter_header = hash256(filter_hash || prev_filter_header)
/// ```
pub fn compute_filter_header(filter_hash: Hash256, prev_header: Hash256) -> Hash256 {
    let mut data = Vec::with_capacity(64);
    data.extend_from_slice(filter_hash.as_bytes());
    data.extend_from_slice(prev_header.as_bytes());
    hash256(&data)
}

/// A filter header entry in the chain.
#[derive(Debug, Clone)]
pub struct FilterHeader {
    /// The block hash this header corresponds to
    pub block_hash: BlockHash,
    /// The filter hash (hash of the serialized filter)
    pub filter_hash: Hash256,
    /// The chained filter header (hash of filter_hash || prev_header)
    pub header: Hash256,
}

/// Build a chain of filter headers from a sequence of block filters.
///
/// Takes an iterator of (block_hash, serialized_filter_data) pairs and the
/// genesis filter header (Hash256::zero() for the start of the chain).
pub fn build_filter_header_chain(
    filters: &[(BlockHash, Vec<u8>)],
    genesis_header: Hash256,
) -> Vec<FilterHeader> {
    let mut prev_header = genesis_header;
    let mut headers = Vec::with_capacity(filters.len());

    for (block_hash, filter_data) in filters {
        let filter_hash = hash256(filter_data);
        let header = compute_filter_header(filter_hash, prev_header);
        headers.push(FilterHeader {
            block_hash: *block_hash,
            filter_hash,
            header,
        });
        prev_header = header;
    }

    headers
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::primitives::amount::Amount;
    use crate::primitives::block::{Block, BlockHeader};
    use crate::primitives::hash::{BlockHash, Hash256};
    use crate::primitives::transaction::{OutPoint, Transaction, TxIn, TxOut};
    use crate::script::{Opcodes, Script, ScriptBuilder};

    fn dummy_tx(output_scripts: Vec<Script>) -> Transaction {
        let outputs: Vec<TxOut> = output_scripts
            .into_iter()
            .map(|s| TxOut {
                value: Amount::from_sat(50_000),
                script_pubkey: s,
            })
            .collect();
        Transaction {
            version: 2,
            inputs: vec![TxIn::new(OutPoint::coinbase(), Script::new(), 0xffffffff)],
            outputs,
            lock_time: 0,
        }
    }

    fn dummy_block(txs: Vec<Transaction>) -> Block {
        let header = BlockHeader::new(1, BlockHash::zero(), Hash256::zero(), 1000, 0x1d00ffff, 42);
        Block::new(header, txs)
    }

    // ── Block filter construction ───────────────────────────────────

    #[test]
    fn test_build_basic_filter_empty_block() {
        let block = dummy_block(vec![]);
        let bf = BlockFilter::build_basic(&block, &[]);
        assert_eq!(bf.filter_type, BASIC_FILTER_TYPE);
        assert_eq!(bf.filter.n, 0);
    }

    #[test]
    fn test_build_basic_filter_with_outputs() {
        let script1 = ScriptBuilder::new()
            .push_opcode(Opcodes::OP_DUP)
            .push_opcode(Opcodes::OP_HASH160)
            .push_slice(&[0xab; 20])
            .push_opcode(Opcodes::OP_EQUALVERIFY)
            .push_opcode(Opcodes::OP_CHECKSIG)
            .build();
        let script2 = ScriptBuilder::new()
            .push_opcode(Opcodes::OP_0)
            .push_slice(&[0xcd; 20])
            .build();

        let tx = dummy_tx(vec![script1.clone(), script2.clone()]);
        let block = dummy_block(vec![tx]);
        let bf = BlockFilter::build_basic(&block, &[]);

        assert_eq!(bf.filter.n, 2);
        assert!(bf.match_script(&script1));
        assert!(bf.match_script(&script2));
    }

    #[test]
    fn test_build_basic_filter_skips_op_return() {
        let normal_script = ScriptBuilder::new()
            .push_opcode(Opcodes::OP_0)
            .push_slice(&[0xab; 20])
            .build();
        let op_return_script = ScriptBuilder::new()
            .push_opcode(Opcodes::OP_RETURN)
            .push_slice(b"data payload")
            .build();

        let tx = dummy_tx(vec![normal_script.clone(), op_return_script.clone()]);
        let block = dummy_block(vec![tx]);
        let bf = BlockFilter::build_basic(&block, &[]);

        // Only the non-OP_RETURN script should be in the filter
        assert_eq!(bf.filter.n, 1);
        assert!(bf.match_script(&normal_script));
        assert!(!bf.match_script(&op_return_script));
    }

    #[test]
    fn test_build_basic_filter_with_prev_outputs() {
        let output_script = ScriptBuilder::new()
            .push_opcode(Opcodes::OP_0)
            .push_slice(&[0x11; 20])
            .build();
        let prev_script = ScriptBuilder::new()
            .push_opcode(Opcodes::OP_0)
            .push_slice(&[0x22; 20])
            .build();

        let tx = dummy_tx(vec![output_script.clone()]);
        let block = dummy_block(vec![tx]);
        let bf = BlockFilter::build_basic(&block, &[prev_script.clone()]);

        // Both output and prev-output scripts should be in the filter
        assert_eq!(bf.filter.n, 2);
        assert!(bf.match_script(&output_script));
        assert!(bf.match_script(&prev_script));
    }

    #[test]
    fn test_build_basic_filter_no_false_negatives() {
        // Build a block with many outputs and verify no false negatives
        let scripts: Vec<Script> = (0u8..50)
            .map(|i| {
                ScriptBuilder::new()
                    .push_opcode(Opcodes::OP_0)
                    .push_slice(&[i; 20])
                    .build()
            })
            .collect();

        let tx = dummy_tx(scripts.clone());
        let block = dummy_block(vec![tx]);
        let bf = BlockFilter::build_basic(&block, &[]);

        for script in &scripts {
            assert!(bf.match_script(script), "false negative for script");
        }
    }

    #[test]
    fn test_match_any_scripts() {
        let s1 = ScriptBuilder::new()
            .push_opcode(Opcodes::OP_0)
            .push_slice(&[0xaa; 20])
            .build();
        let s2 = ScriptBuilder::new()
            .push_opcode(Opcodes::OP_0)
            .push_slice(&[0xbb; 20])
            .build();
        let s3 = ScriptBuilder::new()
            .push_opcode(Opcodes::OP_0)
            .push_slice(&[0xcc; 20])
            .build();

        let tx = dummy_tx(vec![s1.clone(), s2.clone()]);
        let block = dummy_block(vec![tx]);
        let bf = BlockFilter::build_basic(&block, &[]);

        // s1 is in the filter
        assert!(bf.match_any_scripts(&[&s3, &s1]));
        // s3 is not
        assert!(!bf.match_any_scripts(&[&s3]));
    }

    // ── Filter hash ─────────────────────────────────────────────────

    #[test]
    fn test_filter_hash_deterministic() {
        let script = ScriptBuilder::new()
            .push_opcode(Opcodes::OP_0)
            .push_slice(&[0xab; 20])
            .build();
        let tx = dummy_tx(vec![script]);
        let block = dummy_block(vec![tx]);

        let bf1 = BlockFilter::build_basic(&block, &[]);
        let bf2 = BlockFilter::build_basic(&block, &[]);

        assert_eq!(bf1.filter_hash(), bf2.filter_hash());
    }

    #[test]
    fn test_filter_hash_changes_with_content() {
        let s1 = ScriptBuilder::new()
            .push_opcode(Opcodes::OP_0)
            .push_slice(&[0xaa; 20])
            .build();
        let s2 = ScriptBuilder::new()
            .push_opcode(Opcodes::OP_0)
            .push_slice(&[0xbb; 20])
            .build();

        let block1 = dummy_block(vec![dummy_tx(vec![s1])]);
        let block2 = dummy_block(vec![dummy_tx(vec![s2])]);

        let bf1 = BlockFilter::build_basic(&block1, &[]);
        let bf2 = BlockFilter::build_basic(&block2, &[]);

        assert_ne!(bf1.filter_hash(), bf2.filter_hash());
    }

    // ── Filter header chain ─────────────────────────────────────────

    #[test]
    fn test_compute_filter_header() {
        let filter_hash = Hash256::from_bytes([0x11; 32]);
        let prev_header = Hash256::zero();

        let header = compute_filter_header(filter_hash, prev_header);
        assert_ne!(header, Hash256::zero());

        // Deterministic
        let header2 = compute_filter_header(filter_hash, prev_header);
        assert_eq!(header, header2);
    }

    #[test]
    fn test_compute_filter_header_changes_with_prev() {
        let filter_hash = Hash256::from_bytes([0x22; 32]);
        let h1 = compute_filter_header(filter_hash, Hash256::zero());
        let h2 = compute_filter_header(filter_hash, Hash256::from_bytes([0x01; 32]));
        assert_ne!(h1, h2);
    }

    #[test]
    fn test_build_filter_header_chain() {
        let filters = vec![
            (
                BlockHash::from_hash(Hash256::from_bytes([0x01; 32])),
                vec![0, 1, 2, 3],
            ),
            (
                BlockHash::from_hash(Hash256::from_bytes([0x02; 32])),
                vec![4, 5, 6],
            ),
            (
                BlockHash::from_hash(Hash256::from_bytes([0x03; 32])),
                vec![7, 8],
            ),
        ];

        let chain = build_filter_header_chain(&filters, Hash256::zero());
        assert_eq!(chain.len(), 3);

        // Verify the chain links correctly
        let expected_fh0 = hash256(&filters[0].1);
        assert_eq!(chain[0].filter_hash, expected_fh0);
        assert_eq!(
            chain[0].header,
            compute_filter_header(expected_fh0, Hash256::zero())
        );

        let expected_fh1 = hash256(&filters[1].1);
        assert_eq!(chain[1].filter_hash, expected_fh1);
        assert_eq!(
            chain[1].header,
            compute_filter_header(expected_fh1, chain[0].header)
        );

        let expected_fh2 = hash256(&filters[2].1);
        assert_eq!(chain[2].filter_hash, expected_fh2);
        assert_eq!(
            chain[2].header,
            compute_filter_header(expected_fh2, chain[1].header)
        );
    }

    #[test]
    fn test_filter_header_chain_empty() {
        let chain = build_filter_header_chain(&[], Hash256::zero());
        assert!(chain.is_empty());
    }

    // ── Filter serialization roundtrip ──────────────────────────────

    #[test]
    fn test_block_filter_serialize_roundtrip() {
        let script = ScriptBuilder::new()
            .push_opcode(Opcodes::OP_0)
            .push_slice(&[0xab; 20])
            .build();
        let tx = dummy_tx(vec![script.clone()]);
        let block = dummy_block(vec![tx]);
        let bf = BlockFilter::build_basic(&block, &[]);

        let serialized = bf.serialize();
        let deserialized = GcsFilter::deserialize_basic(&serialized).unwrap();

        assert_eq!(deserialized.n, bf.filter.n);
        let (k0, k1) = key_from_block_hash(bf.block_hash.as_bytes());
        assert!(deserialized.match_any(k0, k1, script.as_bytes()));
    }

    // ── from_elements constructor ───────────────────────────────────

    #[test]
    fn test_from_elements() {
        let block_hash = BlockHash::from_hash(Hash256::from_bytes([0x55; 32]));
        let bf = BlockFilter::from_elements(block_hash, &[b"elem1", b"elem2", b"elem3"]);
        assert_eq!(bf.filter.n, 3);
        assert_eq!(bf.filter_type, BASIC_FILTER_TYPE);

        let (k0, k1) = key_from_block_hash(block_hash.as_bytes());
        assert!(bf.filter.match_any(k0, k1, b"elem1"));
        assert!(bf.filter.match_any(k0, k1, b"elem2"));
        assert!(bf.filter.match_any(k0, k1, b"elem3"));
        assert!(!bf.filter.match_any(k0, k1, b"elem4"));
    }
}
