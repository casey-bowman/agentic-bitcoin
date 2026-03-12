//! Bitcoin block types
//!
//! Complete representation of block headers and blocks with merkle root computation.

use crate::hashing::hash256;
use super::hash::{BlockHash, Hash256};
use super::transaction::Transaction;
use std::fmt;

/// Bitcoin block header
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockHeader {
    /// Block version/features
    pub version: i32,
    /// Hash of the previous block
    pub prev_block_hash: BlockHash,
    /// Merkle root of transactions
    pub merkle_root: Hash256,
    /// Unix timestamp
    pub time: u32,
    /// Difficulty target (bits)
    pub bits: u32,
    /// Nonce
    pub nonce: u32,
}

impl BlockHeader {
    /// Create a new block header
    pub fn new(
        version: i32,
        prev_block_hash: BlockHash,
        merkle_root: Hash256,
        time: u32,
        bits: u32,
        nonce: u32,
    ) -> Self {
        BlockHeader {
            version,
            prev_block_hash,
            merkle_root,
            time,
            bits,
            nonce,
        }
    }

    /// Compute the block hash
    pub fn block_hash(&self) -> BlockHash {
        let serialized = self.serialize();
        BlockHash::from_hash(hash256(&serialized))
    }

    /// Serialize the block header (80 bytes)
    fn serialize(&self) -> Vec<u8> {
        let mut data = Vec::with_capacity(80);

        data.extend_from_slice(&self.version.to_le_bytes());
        data.extend_from_slice(self.prev_block_hash.as_bytes());
        data.extend_from_slice(self.merkle_root.as_bytes());
        data.extend_from_slice(&self.time.to_le_bytes());
        data.extend_from_slice(&self.bits.to_le_bytes());
        data.extend_from_slice(&self.nonce.to_le_bytes());

        data
    }

    /// Get the target difficulty from bits
    pub fn target(&self) -> u128 {
        decode_compact(self.bits)
    }

    /// Difficulty adjustment period
    pub const DIFFICULTY_ADJUSTMENT_INTERVAL: u32 = 2016;
    pub const TARGET_TIMESPAN: u32 = 14 * 24 * 60 * 60; // 2 weeks in seconds
}

impl fmt::Display for BlockHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "BlockHeader {{ version: {}, prev: {}, merkle: {}, time: {}, bits: {}, nonce: {} }}",
            self.version,
            self.prev_block_hash,
            self.merkle_root.to_hex_reversed(),
            self.time,
            self.bits,
            self.nonce
        )
    }
}

/// A complete Bitcoin block
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Block {
    /// Block header
    pub header: BlockHeader,
    /// Transactions in the block
    pub transactions: Vec<Transaction>,
}

impl Block {
    /// Create a new block
    pub fn new(header: BlockHeader, transactions: Vec<Transaction>) -> Self {
        Block {
            header,
            transactions,
        }
    }

    /// Get the block hash
    pub fn block_hash(&self) -> BlockHash {
        self.header.block_hash()
    }

    /// Compute merkle root from transactions
    pub fn compute_merkle_root(&self) -> Hash256 {
        if self.transactions.is_empty() {
            return Hash256::zero();
        }

        let mut hashes: Vec<Hash256> = self
            .transactions
            .iter()
            .map(|tx| {
                let serialized = serialize_tx_for_merkle(tx);
                hash256(&serialized)
            })
            .collect();

        // Build merkle tree
        while hashes.len() > 1 {
            if hashes.len() % 2 != 0 {
                hashes.push(*hashes.last().unwrap());
            }

            let mut parent_hashes = Vec::new();
            for i in (0..hashes.len()).step_by(2) {
                let mut combined = Vec::new();
                combined.extend_from_slice(hashes[i].as_bytes());
                combined.extend_from_slice(hashes[i + 1].as_bytes());
                parent_hashes.push(hash256(&combined));
            }

            hashes = parent_hashes;
        }

        hashes[0]
    }

    /// Verify merkle root
    pub fn verify_merkle_root(&self) -> bool {
        self.compute_merkle_root() == self.header.merkle_root
    }

    /// Check if block header matches provided merkle root
    pub fn has_valid_merkle_root(&self) -> bool {
        self.verify_merkle_root()
    }

    /// Get block size in bytes
    pub fn size(&self) -> usize {
        80 + self
            .transactions
            .iter()
            .map(|tx| serialize_tx_for_merkle(tx).len())
            .sum::<usize>()
    }
}

impl fmt::Display for Block {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Block {{ hash: {}, txs: {}, time: {} }}",
            self.block_hash(),
            self.transactions.len(),
            self.header.time
        )
    }
}

/// Locator to identify blocks (used in P2P messages)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockLocator {
    /// Block hashes for locating blocks
    pub hashes: Vec<BlockHash>,
}

impl BlockLocator {
    /// Create a new block locator
    pub fn new(hashes: Vec<BlockHash>) -> Self {
        BlockLocator { hashes }
    }

    /// Create a locator with just the genesis block
    pub fn genesis() -> Self {
        BlockLocator {
            hashes: vec![BlockHash::genesis_mainnet()],
        }
    }
}

/// Serialize transaction for merkle root computation (non-witness)
fn serialize_tx_for_merkle(tx: &Transaction) -> Vec<u8> {
    let mut data = Vec::new();

    // Version
    data.extend_from_slice(&tx.version.to_le_bytes());

    // Input count
    data.extend_from_slice(&compact_size(tx.inputs.len() as u64));

    // Inputs (without witness)
    for input in &tx.inputs {
        // Previous output
        data.extend_from_slice(input.previous_output.txid.as_bytes());
        data.extend_from_slice(&input.previous_output.vout.to_le_bytes());

        // Script sig
        let script_bytes = input.script_sig.as_bytes();
        data.extend_from_slice(&compact_size(script_bytes.len() as u64));
        data.extend_from_slice(script_bytes);

        // Sequence
        data.extend_from_slice(&input.sequence.to_le_bytes());
    }

    // Output count
    data.extend_from_slice(&compact_size(tx.outputs.len() as u64));

    // Outputs
    for output in &tx.outputs {
        data.extend_from_slice(&output.value.as_sat().to_le_bytes());

        let script_bytes = output.script_pubkey.as_bytes();
        data.extend_from_slice(&compact_size(script_bytes.len() as u64));
        data.extend_from_slice(script_bytes);
    }

    // Locktime
    data.extend_from_slice(&tx.lock_time.to_le_bytes());

    data
}

/// Encode a value as a Bitcoin compact size
fn compact_size(value: u64) -> Vec<u8> {
    if value < 0xfd {
        vec![value as u8]
    } else if value <= 0xffff {
        let mut bytes = vec![0xfd];
        bytes.extend_from_slice(&(value as u16).to_le_bytes());
        bytes
    } else if value <= 0xffffffff {
        let mut bytes = vec![0xfe];
        bytes.extend_from_slice(&(value as u32).to_le_bytes());
        bytes
    } else {
        let mut bytes = vec![0xff];
        bytes.extend_from_slice(&value.to_le_bytes());
        bytes
    }
}

/// Decode compact target representation to 128-bit value
fn decode_compact(bits: u32) -> u128 {
    let exponent = bits >> 24;
    let mantissa = bits & 0xffffff;

    if exponent <= 3 {
        (mantissa >> (8 * (3 - exponent))) as u128
    } else {
        (mantissa as u128) << (8 * (exponent - 3))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_block_header_creation() {
        let header = BlockHeader::new(1, BlockHash::zero(), Hash256::zero(), 0, 0, 0);
        assert_eq!(header.version, 1);
    }

    #[test]
    fn test_block_locator_genesis() {
        let locator = BlockLocator::genesis();
        assert_eq!(locator.hashes.len(), 1);
        assert_eq!(locator.hashes[0], BlockHash::genesis_mainnet());
    }

    #[test]
    fn test_block_merkle_root_empty() {
        let header = BlockHeader::new(1, BlockHash::zero(), Hash256::zero(), 0, 0, 0);
        let block = Block::new(header, vec![]);
        assert_eq!(block.compute_merkle_root(), Hash256::zero());
    }
}
