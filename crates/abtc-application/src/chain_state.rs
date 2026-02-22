//! Chain State Manager — Orchestrates block validation and chain selection
//!
//! This module ties together the pieces needed to maintain the active chain:
//!
//! - **BlockIndex** tracks all known headers and selects the most-work chain
//! - **UtxoView / MemoryUtxoSet** provides the UTXO set for contextual validation
//! - **connect_block / disconnect_block** perform the actual validation
//!
//! When a new block arrives, `ChainState::process_block()`:
//! 1. Adds its header to the block index
//! 2. If the block extends the current tip → connect it
//! 3. If it causes a reorg (new best chain) → disconnect old blocks, connect new ones
//! 4. If it's on a side chain with less work → store it but don't activate
//!
//! This corresponds roughly to Bitcoin Core's `CChainState::ConnectTip`,
//! `DisconnectTip`, and `ActivateBestChain`.

use crate::block_index::{BlockIndex, BlockIndexError, BlockValidationStatus};
use abtc_domain::consensus::connect::{
    connect_block, disconnect_block, BlockConnectResult, ConnectBlockError, MemoryUtxoSet, UtxoView,
};
use abtc_domain::consensus::ConsensusParams;
use abtc_domain::primitives::{Block, BlockHash, OutPoint};
use abtc_ports::{ChainStateStore, UtxoEntry};

use std::collections::HashMap;

// ── Chain state errors ──────────────────────────────────────────────

/// Errors that can occur during chain state operations.
#[derive(Debug)]
pub enum ChainStateError {
    /// The block's parent is unknown (orphan block).
    OrphanBlock,
    /// The block failed contextual validation.
    ValidationFailed(ConnectBlockError),
    /// The block index rejected the header.
    IndexError(BlockIndexError),
    /// A block needed for reorg is missing from our block store.
    MissingBlockData(BlockHash),
    /// Reorg failed — the chain state may be inconsistent.
    ReorgFailed {
        /// How far we got disconnecting before the error.
        disconnected: u32,
        /// The error that stopped the reorg.
        reason: Box<ConnectBlockError>,
    },
    /// Block index is missing an entry that should exist (corrupted state).
    CorruptedIndex(BlockHash),
    /// Could not find fork point during reorg (no shared ancestor).
    NoForkPoint,
}

impl std::fmt::Display for ChainStateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ChainStateError::OrphanBlock => write!(f, "orphan block (unknown parent)"),
            ChainStateError::ValidationFailed(e) => write!(f, "validation failed: {}", e),
            ChainStateError::IndexError(e) => write!(f, "block index error: {}", e),
            ChainStateError::MissingBlockData(h) => {
                write!(f, "missing block data for {}", h)
            }
            ChainStateError::ReorgFailed {
                disconnected,
                reason,
            } => write!(
                f,
                "reorg failed after disconnecting {} blocks: {}",
                disconnected, reason
            ),
            ChainStateError::CorruptedIndex(h) => {
                write!(f, "corrupted block index: missing entry for {}", h)
            }
            ChainStateError::NoForkPoint => write!(f, "no fork point found during reorg"),
        }
    }
}

impl std::error::Error for ChainStateError {}

impl From<BlockIndexError> for ChainStateError {
    fn from(e: BlockIndexError) -> Self {
        match e {
            BlockIndexError::OrphanHeader => ChainStateError::OrphanBlock,
            other => ChainStateError::IndexError(other),
        }
    }
}

impl From<ConnectBlockError> for ChainStateError {
    fn from(e: ConnectBlockError) -> Self {
        ChainStateError::ValidationFailed(e)
    }
}

// ── Process result ──────────────────────────────────────────────────

/// The outcome of processing a new block.
#[derive(Debug)]
pub enum ProcessBlockResult {
    /// The block extended the active chain (normal case).
    Connected {
        hash: BlockHash,
        height: u32,
    },
    /// The block triggered a reorganisation to a better chain.
    Reorged {
        hash: BlockHash,
        height: u32,
        /// Number of blocks disconnected from the old chain.
        disconnected: u32,
        /// Number of blocks connected on the new chain.
        connected: u32,
    },
    /// The block was accepted but is on a side chain (less work than active).
    SideChain {
        hash: BlockHash,
        height: u32,
    },
    /// The block was already known.
    AlreadyKnown {
        hash: BlockHash,
    },
}

// ── Chain state ─────────────────────────────────────────────────────

/// The chain state manager.
///
/// Owns the block index (header tree), UTXO set, and the undo data needed
/// to disconnect blocks during a reorg.
pub struct ChainState {
    /// The block index (header tree + best-chain selection).
    index: BlockIndex,
    /// The current UTXO set (reflects the tip of the active chain).
    utxo_set: MemoryUtxoSet,
    /// Consensus parameters (network, subsidy schedule, activation heights).
    params: ConsensusParams,
    /// Undo data: the `BlockConnectResult` for each connected block,
    /// keyed by block hash. Needed to disconnect blocks during a reorg.
    undo_data: HashMap<BlockHash, BlockConnectResult>,
    /// Block data store: full blocks keyed by hash.
    /// In production this would be backed by disk; here we keep blocks
    /// in memory so reorgs can re-read them.
    blocks: HashMap<BlockHash, Block>,
    /// The hash of the current active chain tip.
    tip: BlockHash,
    /// The height of the current active chain tip.
    tip_height: u32,
    /// Whether to verify scripts during block connection.
    verify_scripts: bool,
}

impl ChainState {
    /// Create a new chain state, initialised with a genesis block.
    ///
    /// The genesis block is connected immediately (its coinbase outputs
    /// are added to the UTXO set).
    pub fn new(genesis: Block, params: ConsensusParams) -> Result<Self, ChainStateError> {
        let genesis_hash = genesis.block_hash();
        let header = genesis.header.clone();

        // Initialise the block index with the genesis header.
        let mut index = BlockIndex::new_with_pow_limit(params.pow_limit_bits);
        index.init_genesis(header);

        // Connect the genesis block to build the initial UTXO set.
        let utxo_set = MemoryUtxoSet::new();
        let result = connect_block(&genesis, 0, &utxo_set, &params, false)?;

        let mut chain_state = ChainState {
            index,
            utxo_set,
            params,
            undo_data: HashMap::new(),
            blocks: HashMap::new(),
            tip: genesis_hash,
            tip_height: 0,
            verify_scripts: true,
        };

        // Apply genesis UTXO changes.
        chain_state.utxo_set.apply_connect(&result);
        chain_state.undo_data.insert(genesis_hash, result);
        chain_state.blocks.insert(genesis_hash, genesis);

        Ok(chain_state)
    }

    /// Enable or disable script verification (useful for fast-sync / IBD).
    pub fn set_verify_scripts(&mut self, verify: bool) {
        self.verify_scripts = verify;
    }

    /// Process a new block. This is the main entry point.
    ///
    /// Determines whether the block extends the tip, causes a reorg,
    /// or sits on a side chain, and acts accordingly.
    pub fn process_block(&mut self, block: Block) -> Result<ProcessBlockResult, ChainStateError> {
        let hash = block.block_hash();

        // Already known?
        if self.blocks.contains_key(&hash) {
            return Ok(ProcessBlockResult::AlreadyKnown { hash });
        }

        // Add header to the index (validates PoW, links to parent).
        let (_, reorg_signalled) = self.index.add_header(block.header.clone())?;

        // Store the full block data.
        self.blocks.insert(hash, block);

        let entry = self.index.get(&hash).unwrap();
        let height = entry.height;

        // Case 1: Block extends the current tip (most common).
        if self.index.get(&hash).unwrap().header.prev_block_hash == self.tip {
            return self.connect_tip(hash, height);
        }

        // Case 2: Block has more work → reorg.
        if reorg_signalled {
            return self.activate_best_chain(hash);
        }

        // Case 3: Side chain (less or equal work).
        Ok(ProcessBlockResult::SideChain { hash, height })
    }

    /// Connect a single block at the tip (the fast, common path).
    fn connect_tip(
        &mut self,
        hash: BlockHash,
        height: u32,
    ) -> Result<ProcessBlockResult, ChainStateError> {
        let block = self.blocks.get(&hash).unwrap();

        let result =
            connect_block(block, height, &self.utxo_set, &self.params, self.verify_scripts)?;

        self.utxo_set.apply_connect(&result);
        self.undo_data.insert(hash, result);
        self.tip = hash;
        self.tip_height = height;
        self.index
            .set_status(&hash, BlockValidationStatus::FullyValidated);

        Ok(ProcessBlockResult::Connected { hash, height })
    }

    /// Activate the best chain — disconnect the old tip and connect the new one.
    ///
    /// Finds the fork point, disconnects blocks from the old chain,
    /// then connects blocks on the new chain.
    fn activate_best_chain(
        &mut self,
        new_tip_hash: BlockHash,
    ) -> Result<ProcessBlockResult, ChainStateError> {
        // Walk both chains back to find the fork point.
        let old_chain = self.index.get_ancestor_chain(&self.tip);
        let new_chain = self.index.get_ancestor_chain(&new_tip_hash);

        // Build sets for O(1) lookup.
        let old_set: std::collections::HashSet<BlockHash> =
            old_chain.iter().copied().collect();

        // Find fork point: walk new chain from genesis-end and find first hash in old chain.
        // Note: get_ancestor_chain returns [tip, ..., genesis], so we reverse.
        let fork_hash = new_chain
            .iter()
            .rev()
            .find(|h| old_set.contains(h))
            .copied()
            .ok_or(ChainStateError::NoForkPoint)?;

        let fork_height = self.index.get(&fork_hash)
            .ok_or(ChainStateError::CorruptedIndex(fork_hash))?.height;

        // Blocks to disconnect: from current tip back to (but not including) fork point.
        let to_disconnect: Vec<BlockHash> = old_chain
            .iter()
            .take_while(|h| **h != fork_hash)
            .copied()
            .collect();

        // Blocks to connect: from fork point (exclusive) forward to new tip.
        // new_chain is [new_tip, ..., genesis], so we reverse and skip up to fork.
        let to_connect: Vec<BlockHash> = new_chain
            .iter()
            .rev()
            .skip_while(|h| **h != fork_hash)
            .skip(1) // skip the fork point itself
            .copied()
            .collect();

        let num_disconnect = to_disconnect.len() as u32;
        let num_connect = to_connect.len() as u32;

        // Phase 1: Disconnect old blocks (tip → fork).
        for (i, old_hash) in to_disconnect.iter().enumerate() {
            let undo = self
                .undo_data
                .remove(old_hash)
                .ok_or(ChainStateError::MissingBlockData(*old_hash))?;

            let disc = disconnect_block(&undo);
            self.utxo_set.apply_disconnect(&disc);
            self.index
                .set_status(old_hash, BlockValidationStatus::HeaderValid);

            self.tip = if i + 1 < to_disconnect.len() {
                // Next block to disconnect is the new temporary tip.
                // But we actually just set tip to fork after the loop.
                self.index.get(old_hash)
                    .ok_or(ChainStateError::CorruptedIndex(*old_hash))?.header.prev_block_hash
            } else {
                fork_hash
            };
        }

        self.tip = fork_hash;
        self.tip_height = fork_height;

        // Phase 2: Connect new blocks (fork → new tip).
        for new_hash in &to_connect {
            let height = self.index.get(new_hash)
                .ok_or(ChainStateError::CorruptedIndex(*new_hash))?.height;
            let block = self
                .blocks
                .get(new_hash)
                .ok_or(ChainStateError::MissingBlockData(*new_hash))?;

            let result = connect_block(
                block,
                height,
                &self.utxo_set,
                &self.params,
                self.verify_scripts,
            )
            .map_err(|e| ChainStateError::ReorgFailed {
                disconnected: num_disconnect,
                reason: Box::new(e),
            })?;

            self.utxo_set.apply_connect(&result);
            self.undo_data.insert(*new_hash, result);
            self.tip = *new_hash;
            self.tip_height = height;
            self.index
                .set_status(new_hash, BlockValidationStatus::FullyValidated);
        }

        let final_height = self.tip_height;

        Ok(ProcessBlockResult::Reorged {
            hash: new_tip_hash,
            height: final_height,
            disconnected: num_disconnect,
            connected: num_connect,
        })
    }

    // ── Accessors ───────────────────────────────────────────────────

    /// Current active chain tip hash.
    pub fn tip(&self) -> BlockHash {
        self.tip
    }

    /// Current active chain tip height.
    pub fn tip_height(&self) -> u32 {
        self.tip_height
    }

    /// Reference to the block index.
    pub fn index(&self) -> &BlockIndex {
        &self.index
    }

    /// Mutable reference to the block index.
    pub fn index_mut(&mut self) -> &mut BlockIndex {
        &mut self.index
    }

    /// Reference to the UTXO set.
    pub fn utxo_set(&self) -> &MemoryUtxoSet {
        &self.utxo_set
    }

    /// Get a stored block by hash.
    pub fn get_block(&self, hash: &BlockHash) -> Option<&Block> {
        self.blocks.get(hash)
    }

    /// Get the consensus parameters.
    pub fn params(&self) -> &ConsensusParams {
        &self.params
    }

    /// Number of blocks in the block store.
    pub fn block_count(&self) -> usize {
        self.blocks.len()
    }

    /// Number of UTXOs in the active set.
    pub fn utxo_count(&self) -> usize {
        self.utxo_set.len()
    }

    /// Check if a specific UTXO exists in the active set.
    pub fn has_utxo(&self, outpoint: &OutPoint) -> bool {
        self.utxo_set.get_utxo(outpoint).is_some()
    }

    /// Get the block hash at a given height on the active chain.
    pub fn get_block_hash_at_height(&self, height: u32) -> Option<BlockHash> {
        self.index.get_hash_at_height(height)
    }

    // ── Persistence ─────────────────────────────────────────────

    /// Flush the current UTXO set and chain tip to persistent storage.
    ///
    /// This writes a full snapshot of all UTXOs created/spent since the last
    /// flush, plus the chain tip. Call this after connecting a batch of blocks
    /// (e.g. at the end of IBD or periodically during normal operation).
    pub async fn flush_to_store(
        &self,
        store: &dyn ChainStateStore,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // Collect all UTXOs from the in-memory set
        let utxo_adds: Vec<(abtc_domain::primitives::Txid, u32, UtxoEntry)> = self
            .utxo_set
            .iter()
            .map(|(outpoint, entry)| {
                (
                    outpoint.txid,
                    outpoint.vout,
                    UtxoEntry {
                        output: entry.output.clone(),
                        height: entry.height,
                        is_coinbase: entry.is_coinbase,
                    },
                )
            })
            .collect();

        // Full flush: write all UTXOs (no removes — this is a snapshot)
        store.write_utxo_set(utxo_adds, Vec::new()).await?;
        store.write_chain_tip(self.tip, self.tip_height).await?;

        tracing::info!(
            "Flushed {} UTXOs to persistent store (tip={}, height={})",
            self.utxo_set.len(),
            self.tip,
            self.tip_height
        );

        Ok(())
    }

    /// Flush only the UTXO changes from a single block connect/disconnect.
    ///
    /// More efficient than a full flush — writes only the delta.
    pub async fn flush_block_delta(
        &self,
        result: &BlockConnectResult,
        store: &dyn ChainStateStore,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let adds: Vec<(abtc_domain::primitives::Txid, u32, UtxoEntry)> = result
            .created
            .iter()
            .map(|(outpoint, entry)| {
                (
                    outpoint.txid,
                    outpoint.vout,
                    UtxoEntry {
                        output: entry.output.clone(),
                        height: entry.height,
                        is_coinbase: entry.is_coinbase,
                    },
                )
            })
            .collect();

        let removes: Vec<(abtc_domain::primitives::Txid, u32)> = result
            .spent
            .keys()
            .map(|outpoint| (outpoint.txid, outpoint.vout))
            .collect();

        store.write_utxo_set(adds, removes).await?;
        store.write_chain_tip(self.tip, self.tip_height).await?;

        Ok(())
    }

    /// Load chain tip from a persistent store and verify consistency.
    ///
    /// Returns the stored (tip_hash, tip_height), or None if the store is empty.
    pub async fn load_tip_from_store(
        store: &dyn ChainStateStore,
    ) -> Result<Option<(BlockHash, u32)>, Box<dyn std::error::Error + Send + Sync>> {
        let (hash, height) = store.get_best_chain_tip().await?;
        if hash == BlockHash::zero() && height == 0 {
            return Ok(None);
        }
        Ok(Some((hash, height)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use abtc_domain::primitives::{
        Amount, Block, BlockHash, BlockHeader, Hash256, Transaction, TxOut,
    };
    use abtc_domain::Script;

    fn mainnet_params() -> ConsensusParams {
        ConsensusParams::mainnet()
    }

    fn make_genesis() -> Block {
        let coinbase = Transaction::coinbase(
            0,
            Script::from_bytes(vec![0x04, 0xFF, 0xFF, 0x00, 0x1D]),
            vec![TxOut::new(
                Amount::from_sat(5_000_000_000),
                Script::from_bytes(vec![0x76, 0xA9]),
            )],
        );
        // Build block with placeholder merkle root, then fix it
        let mut block = Block::new(
            BlockHeader {
                version: 1,
                prev_block_hash: BlockHash::zero(),
                merkle_root: Hash256::zero(),
                time: 1231006505,
                bits: 0x1d00ffff,
                nonce: 0,
            },
            vec![coinbase],
        );
        block.header.merkle_root = block.compute_merkle_root();
        block
    }

    #[test]
    fn test_chain_state_creation() {
        let genesis = make_genesis();
        let cs = ChainState::new(genesis.clone(), mainnet_params()).unwrap();

        assert_eq!(cs.tip_height(), 0);
        assert_eq!(cs.tip(), genesis.block_hash());
    }

    #[test]
    fn test_duplicate_block_is_already_known() {
        let genesis = make_genesis();
        let genesis2 = genesis.clone();
        let mut cs = ChainState::new(genesis, mainnet_params()).unwrap();

        match cs.process_block(genesis2).unwrap() {
            ProcessBlockResult::AlreadyKnown { .. } => {}
            other => panic!("Expected AlreadyKnown, got {:?}", other),
        }
    }

    #[test]
    fn test_orphan_block_rejected() {
        let genesis = make_genesis();
        let mut cs = ChainState::new(genesis, mainnet_params()).unwrap();

        // Create a block with unknown parent
        let orphan_header = BlockHeader {
            version: 1,
            prev_block_hash: BlockHash::from_hash(Hash256::from_bytes([0xFF; 32])),
            merkle_root: Hash256::from_bytes([0u8; 32]),
            time: 1231006505 + 600,
            bits: 0x1d00ffff,
            nonce: 42,
        };
        let orphan = Block::new(orphan_header, vec![]);

        match cs.process_block(orphan) {
            Err(ChainStateError::OrphanBlock) => {}
            other => panic!("Expected OrphanBlock error, got {:?}", other),
        }
    }

    #[test]
    fn test_set_verify_scripts() {
        let genesis = make_genesis();
        let mut cs = ChainState::new(genesis, mainnet_params()).unwrap();

        assert!(cs.verify_scripts);
        cs.set_verify_scripts(false);
        assert!(!cs.verify_scripts);
    }

    #[test]
    fn test_chain_state_error_display() {
        let err = ChainStateError::OrphanBlock;
        assert!(err.to_string().contains("orphan"));

        let err = ChainStateError::MissingBlockData(BlockHash::zero());
        assert!(err.to_string().contains("missing block data"));
    }

    #[test]
    fn test_chain_state_error_from_block_index_orphan() {
        let err = ChainStateError::from(BlockIndexError::OrphanHeader);
        match err {
            ChainStateError::OrphanBlock => {}
            _ => panic!("Expected OrphanBlock"),
        }
    }

    #[tokio::test]
    async fn test_load_tip_from_empty_store() {
        let store = abtc_adapters::storage::InMemoryChainStateStore::new();
        let result = ChainState::load_tip_from_store(&store).await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_load_tip_from_populated_store() {
        let store = abtc_adapters::storage::InMemoryChainStateStore::new();
        let tip = BlockHash::from_hash(Hash256::from_bytes([0x42; 32]));
        store.write_chain_tip(tip, 100).await.unwrap();

        let result = ChainState::load_tip_from_store(&store).await.unwrap();
        assert_eq!(result, Some((tip, 100)));
    }

    #[tokio::test]
    async fn test_flush_to_store() {
        let genesis = make_genesis();
        let cs = ChainState::new(genesis, mainnet_params()).unwrap();
        let store = abtc_adapters::storage::InMemoryChainStateStore::new();

        cs.flush_to_store(&store).await.unwrap();

        let (tip, height) = store.get_best_chain_tip().await.unwrap();
        assert_eq!(tip, cs.tip());
        assert_eq!(height, 0);
    }

    // ═══════════════════════════════════════════════════════════════════
    // Regression tests — Session 14, Part 4 (code review fixes)
    //
    // These tests were written specifically for this implementation to
    // guard against bugs found during a code review. They are NOT ports
    // of Bitcoin Core test vectors. Each test name begins with
    // `regression_` so it can be distinguished from the implementation
    // unit tests above, which exercise baseline functionality.
    // ═══════════════════════════════════════════════════════════════════

    #[test]
    fn regression_chain_state_error_variants_exist() {
        // Review finding #11: reorg path used .unwrap() which panics.
        // New error types CorruptedIndex and NoForkPoint must exist and
        // implement Display without panic.
        let hash = BlockHash::from_hash(Hash256::from_bytes([0xAB; 32]));
        let err1 = ChainStateError::CorruptedIndex(hash);
        let err2 = ChainStateError::NoForkPoint;
        let s1 = format!("{}", err1);
        let s2 = format!("{}", err2);
        assert!(s1.contains("corrupted"));
        assert!(s2.contains("fork"));
    }
}
