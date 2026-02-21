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

use btc_domain::chain_params::Checkpoint;
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
    /// Hardcoded checkpoints: height → expected hash (hex, reversed).
    /// Headers at checkpoint heights must match the expected hash.
    checkpoints: HashMap<u32, String>,
}

impl BlockIndex {
    /// Create a new empty block index.
    pub fn new() -> Self {
        BlockIndex {
            entries: HashMap::new(),
            best_tip: BlockHash::zero(),
            active_chain: Vec::new(),
            checkpoints: HashMap::new(),
        }
    }

    /// Load checkpoints into the block index.
    ///
    /// Call this after creation / before syncing so that `add_header`
    /// can reject headers that violate a checkpoint.
    pub fn load_checkpoints(&mut self, checkpoints: &[Checkpoint]) {
        for cp in checkpoints {
            self.checkpoints.insert(cp.height, cp.hash_hex.to_string());
        }
    }

    /// Get the highest loaded checkpoint height, or 0 if none.
    pub fn last_checkpoint_height(&self) -> u32 {
        self.checkpoints.keys().copied().max().unwrap_or(0)
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

        // ── Checkpoint verification ──────────────────────────────
        // If there is a checkpoint at this height, the hash must match.
        if let Some(expected_hex) = self.checkpoints.get(&height) {
            if hash.to_hex_reversed() != *expected_hex {
                return Err(BlockIndexError::CheckpointMismatch {
                    height,
                    expected: expected_hex.clone(),
                    got: hash.to_hex_reversed(),
                });
            }
        }

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

    /// Compute the Median Time Past (MTP) for a block on the active chain.
    ///
    /// BIP113: the "time" used for time-lock evaluation is the median of
    /// the timestamps of the previous 11 blocks (or all blocks if fewer
    /// than 11 exist). This prevents miners from manipulating the timestamp
    /// of a single block to bypass time locks.
    ///
    /// `height` is the height of the block whose MTP we want. The MTP is
    /// computed from blocks at heights `max(0, height-10)..=height`.
    ///
    /// Returns `None` if the height is not on the active chain.
    pub fn get_median_time_past(&self, height: u32) -> Option<u32> {
        const MEDIAN_TIME_SPAN: u32 = 11;

        let start = height.saturating_sub(MEDIAN_TIME_SPAN - 1);
        let mut timestamps = Vec::with_capacity(MEDIAN_TIME_SPAN as usize);

        for h in start..=height {
            let hash = self.get_hash_at_height(h)?;
            let entry = self.entries.get(&hash)?;
            timestamps.push(entry.header.time);
        }

        timestamps.sort_unstable();
        Some(timestamps[timestamps.len() / 2])
    }

    /// Compute the MTP for the current best chain tip.
    pub fn tip_median_time_past(&self) -> Option<u32> {
        if self.active_chain.is_empty() {
            return None;
        }
        self.get_median_time_past(self.best_height())
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
    /// A header at a checkpoint height does not match the expected hash
    CheckpointMismatch {
        height: u32,
        expected: String,
        got: String,
    },
}

impl std::fmt::Display for BlockIndexError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BlockIndexError::OrphanHeader => write!(f, "orphan header (unknown parent)"),
            BlockIndexError::DuplicateBlock => write!(f, "duplicate block"),
            BlockIndexError::CheckpointMismatch { height, expected, got } => {
                write!(
                    f,
                    "checkpoint mismatch at height {}: expected {}, got {}",
                    height, expected, got
                )
            }
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

    // target = mantissa * 2^(8*(exponent-3))
    // work = 2^256 / (target + 1)
    //
    // For targets that fit in u128 (shift < 128), compute directly.
    // For larger targets, we reformulate:
    //   work = 2^256 / (mantissa * 2^shift + 1)
    //        ≈ 2^(256-shift) / mantissa  (when mantissa << 2^shift)
    let shift = 8 * (exponent.saturating_sub(3));

    if shift >= 256 {
        // Target exceeds 2^256 — work is negligible but nonzero
        return 1;
    }

    if shift < 128 {
        // Target fits in u128 — direct computation
        let target = (mantissa as u128) << shift;
        if target == 0 {
            return u128::MAX;
        }
        u128::MAX / (target + 1)
    } else {
        // Target overflows u128. Compute work = 2^(256-shift) / mantissa.
        // Since shift >= 128 and shift < 256, (256-shift) is in 1..=128.
        let work_shift = 256 - shift;
        if work_shift >= 128 {
            // 2^128 / mantissa
            u128::MAX / (mantissa as u128)
        } else {
            (1u128 << work_shift) / (mantissa as u128)
        }
    }
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

    // ── Checkpoint tests ──────────────────────────────────────

    #[test]
    fn test_checkpoint_match_passes() {
        let mut index = BlockIndex::new();
        let genesis = make_header(BlockHash::zero(), 0);
        let genesis_hash = genesis.block_hash();
        index.init_genesis(genesis);

        // Build block at height 1 and record its hash
        let h1 = make_header(genesis_hash, 1);
        let h1_hash = h1.block_hash();

        // Load a checkpoint for height 1 that matches
        index.load_checkpoints(&[Checkpoint {
            height: 1,
            hash_hex: Box::leak(h1_hash.to_hex_reversed().into_boxed_str()),
        }]);

        // Should succeed — hash matches checkpoint
        let result = index.add_header(h1);
        assert!(result.is_ok());
        assert_eq!(index.best_height(), 1);
    }

    #[test]
    fn test_checkpoint_mismatch_rejected() {
        let mut index = BlockIndex::new();
        let genesis = make_header(BlockHash::zero(), 0);
        let genesis_hash = genesis.block_hash();
        index.init_genesis(genesis);

        // Load a checkpoint for height 1 with a bogus hash
        index.load_checkpoints(&[Checkpoint {
            height: 1,
            hash_hex: "0000000000000000000000000000000000000000000000000000000000abcdef",
        }]);

        // Adding a header at height 1 with a different hash should fail
        let h1 = make_header(genesis_hash, 1);
        let result = index.add_header(h1);
        assert!(matches!(
            result,
            Err(BlockIndexError::CheckpointMismatch { .. })
        ));
        assert_eq!(index.best_height(), 0); // Still at genesis
    }

    #[test]
    fn test_no_checkpoint_at_height_passes() {
        let mut index = BlockIndex::new();
        let genesis = make_header(BlockHash::zero(), 0);
        let genesis_hash = genesis.block_hash();
        index.init_genesis(genesis);

        // Checkpoint at height 5 — should not affect height 1
        index.load_checkpoints(&[Checkpoint {
            height: 5,
            hash_hex: "0000000000000000000000000000000000000000000000000000000000abcdef",
        }]);

        let h1 = make_header(genesis_hash, 1);
        let result = index.add_header(h1);
        assert!(result.is_ok());
    }

    #[test]
    fn test_last_checkpoint_height() {
        let mut index = BlockIndex::new();
        assert_eq!(index.last_checkpoint_height(), 0);

        index.load_checkpoints(&[
            Checkpoint { height: 100, hash_hex: "aaa" },
            Checkpoint { height: 500, hash_hex: "bbb" },
            Checkpoint { height: 250, hash_hex: "ccc" },
        ]);
        assert_eq!(index.last_checkpoint_height(), 500);
    }

    // ── Median Time Past tests ──────────────────────────────────

    fn make_header_with_time(prev: BlockHash, nonce: u32, time: u32) -> BlockHeader {
        BlockHeader {
            version: 1,
            prev_block_hash: prev,
            merkle_root: Hash256::from_bytes([nonce as u8; 32]),
            time,
            bits: 0x1d00ffff,
            nonce,
        }
    }

    #[test]
    fn test_mtp_genesis_only() {
        let mut index = BlockIndex::new();
        let genesis = make_header_with_time(BlockHash::zero(), 0, 1231006505);
        index.init_genesis(genesis);

        // MTP of genesis (only 1 block) = its own timestamp
        assert_eq!(index.get_median_time_past(0), Some(1231006505));
        assert_eq!(index.tip_median_time_past(), Some(1231006505));
    }

    #[test]
    fn test_mtp_three_blocks() {
        let mut index = BlockIndex::new();
        let genesis = make_header_with_time(BlockHash::zero(), 0, 100);
        let genesis_hash = genesis.block_hash();
        index.init_genesis(genesis);

        let h1 = make_header_with_time(genesis_hash, 1, 200);
        let (h1_hash, _) = index.add_header(h1).unwrap();

        let h2 = make_header_with_time(h1_hash, 2, 150); // Deliberately out of order
        let (_h2_hash, _) = index.add_header(h2).unwrap();

        // Heights 0,1,2 have timestamps [100, 200, 150]
        // Sorted: [100, 150, 200], median = 150
        assert_eq!(index.get_median_time_past(2), Some(150));
    }

    #[test]
    fn test_mtp_eleven_blocks() {
        let mut index = BlockIndex::new();
        let genesis = make_header_with_time(BlockHash::zero(), 0, 1000);
        let genesis_hash = genesis.block_hash();
        index.init_genesis(genesis);

        // Build a chain of 11 blocks (heights 0..=10) with timestamps
        // chosen so the median is well-defined.
        let timestamps = [1000, 1010, 1020, 1005, 1030, 1015, 1025, 1035, 1008, 1040, 1050];
        let mut prev = genesis_hash;
        for i in 1..=10u32 {
            let h = make_header_with_time(prev, i, timestamps[i as usize]);
            let (hash, _) = index.add_header(h).unwrap();
            prev = hash;
        }

        // MTP at height 10: median of timestamps[0..=10]
        // Sorted: [1000, 1005, 1008, 1010, 1015, 1020, 1025, 1030, 1035, 1040, 1050]
        // Median (index 5 of 11) = 1020
        assert_eq!(index.get_median_time_past(10), Some(1020));
    }

    #[test]
    fn test_mtp_more_than_eleven_blocks() {
        let mut index = BlockIndex::new();
        let genesis = make_header_with_time(BlockHash::zero(), 0, 500);
        let genesis_hash = genesis.block_hash();
        index.init_genesis(genesis);

        // Build 15 blocks, each 10 seconds apart
        let mut prev = genesis_hash;
        for i in 1..=15u32 {
            let h = make_header_with_time(prev, i, 500 + i * 10);
            let (hash, _) = index.add_header(h).unwrap();
            prev = hash;
        }

        // MTP at height 15 uses blocks 5..=15 (11 blocks)
        // Timestamps: [550, 560, 570, 580, 590, 600, 610, 620, 630, 640, 650]
        // Median = 600
        assert_eq!(index.get_median_time_past(15), Some(600));
    }

    #[test]
    fn test_mtp_invalid_height() {
        let mut index = BlockIndex::new();
        let genesis = make_header_with_time(BlockHash::zero(), 0, 1000);
        index.init_genesis(genesis);

        // Height 5 doesn't exist
        assert_eq!(index.get_median_time_past(5), None);
    }
}
