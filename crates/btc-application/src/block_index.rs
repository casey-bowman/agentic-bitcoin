//! Block Index — Tracks all known block headers and best-chain selection
//!
//! The block index is a tree of all known block headers. It tracks which chain
//! has the most cumulative work (proof-of-work) and provides the "best chain"
//! used for validation and serving to peers.
//!
//! This corresponds to Bitcoin Core's `CBlockIndex` / `CChainState` / `mapBlockIndex`.
//!
//! ## Best-chain selection
//!
//! The "best chain" is the chain with the most cumulative proof-of-work.
//! Work is computed from the `bits` (nBits / compact target) field in the header.
//! When a new header arrives, we:
//! 1. Add it to the index (linking to its parent)
//! 2. Compute its cumulative work
//! 3. If it has more work than the current best chain, it becomes the new tip

use btc_domain::primitives::{BlockHash, BlockHeader};
use std::collections::HashMap;

/// Metadata tracked for each known block header.
#[derive(Debug, Clone)]
pub struct BlockIndexEntry {
    /// The block header
    pub header: BlockHeader,
    /// Height of this block
    pub height: u32,
    /// Cumulative proof-of-work up to and including this block
    /// Stored as a u128 to avoid overflow for high-difficulty chains
    pub chain_work: u128,
    /// Validation status
    pub status: BlockValidationStatus,
}

/// Validation status of a block in the index.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlockValidationStatus {
    /// Header received and valid
    HeaderValid,
    /// Full block data received and validated
    FullyValidated,
    /// Block failed validation
    Invalid,
    /// Block data not yet available (header-only)
    DataUnavailable,
}

/// The in-memory block index tree.
///
/// Maps block hashes to their index entries. The "best chain" is the chain
/// leading to the tip with the most cumulative proof-of-work.
pub struct BlockIndex {
    /// All known block headers
    entries: HashMap<BlockHash, BlockIndexEntry>,
    /// The current best (most-work) chain tip
    best_tip: BlockHash,
    /// Height-to-hash mapping for the active chain (for O(1) height lookups)
    active_chain: Vec<BlockHash>,
}

impl BlockIndex {
    /// Create a new empty block index.
    pub fn new() -> Self {
        BlockIndex {
            entries: HashMap::new(),
            best_tip: BlockHash::zero(),
            active_chain: Vec::new(),
        }
    }

    /// Initialize the block index with a genesis block header.
    pub fn init_genesis(&mut self, header: BlockHeader) {
        let hash = header.block_hash();
        let work = work_from_bits(header.bits);

        let entry = BlockIndexEntry {
            header,
            height: 0,
            chain_work: work,
            status: BlockValidationStatus::FullyValidated,
        };

        self.entries.insert(hash, entry);
        self.best_tip = hash;
        self.active_chain = vec![hash];
    }

    /// Add a new block header to the index. Returns the hash and whether
    /// a reorg occurred (the best chain tip changed to a different branch).
    ///
    /// If the parent is unknown, returns an error.
    pub fn add_header(
        &mut self,
        header: BlockHeader,
    ) -> Result<(BlockHash, bool), BlockIndexError> {
        let hash = header.block_hash();

        // Already known?
        if self.entries.contains_key(&hash) {
            return Ok((hash, false));
        }

        // Parent must be known
        let parent_hash = header.prev_block_hash;
        let (parent_height, parent_work) = {
            let parent = self
                .entries
                .get(&parent_hash)
                .ok_or(BlockIndexError::OrphanHeader)?;
            (parent.height, parent.chain_work)
        };

        let height = parent_height + 1;
        let work = parent_work + work_from_bits(header.bits);

        let entry = BlockIndexEntry {
            header,
            height,
            chain_work: work,
            status: BlockValidationStatus::HeaderValid,
        };

        self.entries.insert(hash, entry);

        // Check if this creates a new best chain
        let current_best_work = self
            .entries
            .get(&self.best_tip)
            .map(|e| e.chain_work)
            .unwrap_or(0);

        let reorged = if work > current_best_work {
            let old_tip = self.best_tip;
            self.best_tip = hash;
            self.rebuild_active_chain();
            old_tip != hash // Always true since work is strictly greater
        } else {
            false
        };

        Ok((hash, reorged))
    }

    /// Set the validation status of a block.
    pub fn set_status(&mut self, hash: &BlockHash, status: BlockValidationStatus) {
        if let Some(entry) = self.entries.get_mut(hash) {
            entry.status = status;
        }
    }

    /// Get a block index entry by hash.
    pub fn get(&self, hash: &BlockHash) -> Option<&BlockIndexEntry> {
        self.entries.get(hash)
    }

    /// Get the best chain tip hash.
    pub fn best_tip(&self) -> BlockHash {
        self.best_tip
    }

    /// Get the best chain tip entry.
    pub fn best_tip_entry(&self) -> Option<&BlockIndexEntry> {
        self.entries.get(&self.best_tip)
    }

    /// Get the block hash at a given height on the active chain.
    pub fn get_hash_at_height(&self, height: u32) -> Option<BlockHash> {
        self.active_chain.get(height as usize).copied()
    }

    /// Get the current best chain height.
    pub fn best_height(&self) -> u32 {
        self.active_chain
            .len()
            .saturating_sub(1) as u32
    }

    /// Get the total number of known headers.
    pub fn header_count(&self) -> usize {
        self.entries.len()
    }

    /// Check if we have a header for the given hash.
    pub fn contains(&self, hash: &BlockHash) -> bool {
        self.entries.contains_key(hash)
    }

    /// Walk ancestors from a given hash back to genesis.
    /// Returns hashes from the given block back to genesis (inclusive).
    pub fn get_ancestor_chain(&self, hash: &BlockHash) -> Vec<BlockHash> {
        let mut chain = Vec::new();
        let mut current = *hash;

        while current != BlockHash::zero() {
            chain.push(current);
            match self.entries.get(&current) {
                Some(entry) => current = entry.header.prev_block_hash,
                None => break,
            }
        }

        chain
    }

    /// Build a block locator (list of block hashes for the `getblocks` protocol message).
    /// Uses exponential backoff: recent blocks are listed individually, then
    /// the step size doubles.
    pub fn build_locator(&self) -> Vec<BlockHash> {
        let mut locator = Vec::new();
        let mut step = 1;
        let mut height = self.best_height() as i64;

        while height >= 0 {
            if let Some(hash) = self.get_hash_at_height(height as u32) {
                locator.push(hash);
            }

            if locator.len() >= 10 {
                step *= 2;
            }

            height -= step;
        }

        // Always include genesis
        if let Some(genesis) = self.active_chain.first() {
            if locator.last() != Some(genesis) {
                locator.push(*genesis);
            }
        }

        locator
    }

    /// Rebuild the active_chain vector by walking from best_tip back to genesis.
    fn rebuild_active_chain(&mut self) {
        let mut chain = Vec::new();
        let mut current = self.best_tip;

        while current != BlockHash::zero() {
            chain.push(current);
            match self.entries.get(&current) {
                Some(entry) => current = entry.header.prev_block_hash,
                None => break,
            }
        }

        chain.reverse();
        self.active_chain = chain;
    }
}

impl Default for BlockIndex {
    fn default() -> Self {
        Self::new()
    }
}

/// Errors from block index operations
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BlockIndexError {
    /// The parent block hash is not in the index
    OrphanHeader,
    /// The block is already known
    DuplicateBlock,
}

impl std::fmt::Display for BlockIndexError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BlockIndexError::OrphanHeader => write!(f, "orphan header (unknown parent)"),
            BlockIndexError::DuplicateBlock => write!(f, "duplicate block"),
        }
    }
}

impl std::error::Error for BlockIndexError {}

/// Compute the proof-of-work from a compact target (nBits).
///
/// Work is defined as 2^256 / (target + 1). We approximate this as
/// `u128::MAX / (target as u128)` which is good enough for chain comparison.
///
/// The compact target encoding is:
/// - First byte = exponent (number of bytes)
/// - Next 3 bytes = mantissa (coefficient)
/// - target = mantissa * 256^(exponent-3)
fn work_from_bits(bits: u32) -> u128 {
    let exponent = (bits >> 24) as u32;
    let mantissa = bits & 0x007fffff;

    if mantissa == 0 || exponent == 0 {
        return 0;
    }

    // Compute target = mantissa * 2^(8*(exponent-3))
    // But we need to be careful with overflow
    let shift = 8 * (exponent.saturating_sub(3)) as u32;

    if shift >= 128 {
        // Target is so large that work is effectively 1
        return 1;
    }

    let target = (mantissa as u128)
        .checked_shl(shift)
        .unwrap_or(u128::MAX);

    if target == 0 {
        return u128::MAX;
    }

    // work = 2^256 / (target+1)
    // Since we can't represent 2^256, we use ~0_u128 / target as approximation
    // This is fine for comparison purposes (which is all we use it for)
    u128::MAX / (target + 1)
}

#[cfg(test)]
mod tests {
    use super::*;
    use btc_domain::primitives::{BlockHash, Hash256};

    fn make_header(prev: BlockHash, nonce: u32) -> BlockHeader {
        BlockHeader {
            version: 1,
            prev_block_hash: prev,
            merkle_root: Hash256::from_bytes([nonce as u8; 32]),
            time: 1231006505 + nonce,
            bits: 0x1d00ffff, // mainnet genesis difficulty
            nonce,
        }
    }

    #[test]
    fn test_genesis_init() {
        let mut index = BlockIndex::new();
        let genesis_header = make_header(BlockHash::zero(), 0);
        index.init_genesis(genesis_header.clone());

        assert_eq!(index.best_height(), 0);
        assert_eq!(index.header_count(), 1);

        let tip = index.best_tip_entry().unwrap();
        assert_eq!(tip.height, 0);
    }

    #[test]
    fn test_add_headers_sequential() {
        let mut index = BlockIndex::new();
        let genesis = make_header(BlockHash::zero(), 0);
        let genesis_hash = genesis.block_hash();
        index.init_genesis(genesis);

        // Add block 1
        let header1 = make_header(genesis_hash, 1);
        let (hash1, reorged) = index.add_header(header1).unwrap();
        assert!(reorged); // New best chain
        assert_eq!(index.best_height(), 1);

        // Add block 2
        let header2 = make_header(hash1, 2);
        let (_, reorged) = index.add_header(header2).unwrap();
        assert!(reorged);
        assert_eq!(index.best_height(), 2);
    }

    #[test]
    fn test_orphan_header() {
        let mut index = BlockIndex::new();
        let genesis = make_header(BlockHash::zero(), 0);
        index.init_genesis(genesis);

        // Try to add a header with unknown parent
        let orphan = make_header(
            BlockHash::from_hash(Hash256::from_bytes([0xff; 32])),
            99,
        );
        let result = index.add_header(orphan);
        assert_eq!(result, Err(BlockIndexError::OrphanHeader));
    }

    #[test]
    fn test_duplicate_header() {
        let mut index = BlockIndex::new();
        let genesis = make_header(BlockHash::zero(), 0);
        let genesis_hash = genesis.block_hash();
        index.init_genesis(genesis);

        let header1 = make_header(genesis_hash, 1);
        let (hash1, _) = index.add_header(header1.clone()).unwrap();

        // Adding same header again should succeed silently (no reorg)
        let (hash1_again, reorged) = index.add_header(header1).unwrap();
        assert_eq!(hash1, hash1_again);
        assert!(!reorged);
    }

    #[test]
    fn test_fork_and_reorg() {
        let mut index = BlockIndex::new();
        let genesis = make_header(BlockHash::zero(), 0);
        let genesis_hash = genesis.block_hash();
        index.init_genesis(genesis);

        // Chain A: genesis → A1 → A2
        let a1 = make_header(genesis_hash, 10);
        let (a1_hash, _) = index.add_header(a1).unwrap();
        let a2 = make_header(a1_hash, 20);
        let (a2_hash, _) = index.add_header(a2).unwrap();
        assert_eq!(index.best_tip(), a2_hash);
        assert_eq!(index.best_height(), 2);

        // Chain B: genesis → B1 → B2 → B3 (longer, same difficulty = more work)
        let b1 = make_header(genesis_hash, 100);
        let (b1_hash, _) = index.add_header(b1).unwrap();
        let b2 = make_header(b1_hash, 200);
        let (b2_hash, _) = index.add_header(b2).unwrap();
        // At this point B2 is at height 2 same as A2, same work → no reorg (A2 is still tip)
        // B has same work as A (same bits), so B doesn't become best

        let b3 = make_header(b2_hash, 300);
        let (b3_hash, reorged) = index.add_header(b3).unwrap();
        assert!(reorged); // B3 at height 3 has more work
        assert_eq!(index.best_tip(), b3_hash);
        assert_eq!(index.best_height(), 3);
    }

    #[test]
    fn test_height_lookup() {
        let mut index = BlockIndex::new();
        let genesis = make_header(BlockHash::zero(), 0);
        let genesis_hash = genesis.block_hash();
        index.init_genesis(genesis);

        let h1 = make_header(genesis_hash, 1);
        let (h1_hash, _) = index.add_header(h1).unwrap();

        assert_eq!(index.get_hash_at_height(0), Some(genesis_hash));
        assert_eq!(index.get_hash_at_height(1), Some(h1_hash));
        assert_eq!(index.get_hash_at_height(2), None);
    }

    #[test]
    fn test_block_locator() {
        let mut index = BlockIndex::new();
        let genesis = make_header(BlockHash::zero(), 0);
        let genesis_hash = genesis.block_hash();
        index.init_genesis(genesis);

        // Build a chain of 20 blocks
        let mut prev = genesis_hash;
        for i in 1..=20 {
            let h = make_header(prev, i);
            let (hash, _) = index.add_header(h).unwrap();
            prev = hash;
        }

        let locator = index.build_locator();
        // Should start with the tip and end with genesis
        assert!(!locator.is_empty());
        assert_eq!(locator[0], prev); // tip
        assert_eq!(*locator.last().unwrap(), genesis_hash);
    }

    #[test]
    fn test_work_from_bits() {
        // Zero mantissa → zero work
        assert_eq!(work_from_bits(0), 0);

        // Mainnet genesis bits: 0x1d00ffff
        let work = work_from_bits(0x1d00ffff);
        assert!(work > 0);

        // Higher difficulty (lower target) → more work
        let work_easy = work_from_bits(0x1d00ffff);
        let work_hard = work_from_bits(0x1c00ffff); // smaller target
        assert!(work_hard > work_easy);
    }
}
