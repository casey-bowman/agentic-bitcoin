//! Storage Port Definitions
//!
//! This module defines the port traits for persisting blockchain data.
//! Implementations of these traits are provided by adapter crates (e.g., btc-adapter-leveldb, btc-adapter-sqlite).

use btc_domain::primitives::{Block, BlockHash, TxOut, Txid};
use std::error::Error;

/// Represents a UTXO (Unspent Transaction Output) stored in the UTXO set.
///
/// This struct contains all information needed to validate and spend an output.
#[derive(Clone, Debug)]
pub struct UtxoEntry {
    /// The transaction output
    pub output: TxOut,
    /// Height at which this output was created (block height)
    pub height: u32,
    /// Whether this output is from a coinbase transaction
    pub is_coinbase: bool,
}

/// Represents a block's entry in the block index.
///
/// The block index maintains metadata about all known blocks, including orphans and blocks
/// off the main chain.
#[derive(Clone, Debug)]
pub struct BlockIndexEntry {
    /// The hash of the block
    pub hash: BlockHash,
    /// Height of the block on the main chain (or -1 for orphans)
    pub height: i32,
    /// Hash of the previous block
    pub prev_hash: BlockHash,
    /// The block header
    pub header: btc_domain::primitives::BlockHeader,
    /// Validation status (valid, invalid, etc.)
    pub status: BlockStatus,
    /// File position where block data is stored
    pub data_pos: u64,
}

/// Validation status of a block.
#[derive(Clone, Debug, Copy, PartialEq, Eq)]
pub enum BlockStatus {
    /// Block has been validated and is accepted
    Valid,
    /// Block failed validation
    Invalid,
    /// Block has not been validated yet
    Unvalidated,
    /// Block conflicts with a previously validated block
    Conflicting,
}

/// Port trait for persistent block storage.
///
/// Implementations handle storing and retrieving blocks from persistent storage.
/// This is a secondary port that the domain layer depends on.
#[async_trait::async_trait]
pub trait BlockStore: Send + Sync {
    /// Stores a block in persistent storage.
    ///
    /// # Arguments
    ///
    /// * `block` - The block to store
    /// * `height` - The height of the block on the main chain
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` on success, or an error if storage fails.
    async fn store_block(
        &self,
        block: &Block,
        height: u32,
    ) -> Result<(), Box<dyn Error + Send + Sync>>;

    /// Retrieves a block by its hash.
    ///
    /// # Arguments
    ///
    /// * `hash` - The block hash to retrieve
    ///
    /// # Returns
    ///
    /// Returns `Some(block)` if the block exists, `None` if it doesn't.
    async fn get_block(&self, hash: &BlockHash) -> Result<Option<Block>, Box<dyn Error + Send + Sync>>;

    /// Retrieves a block header by its hash.
    ///
    /// # Arguments
    ///
    /// * `hash` - The block hash
    ///
    /// # Returns
    ///
    /// Returns `Some(header)` if the header exists, `None` otherwise.
    async fn get_block_header(
        &self,
        hash: &BlockHash,
    ) -> Result<Option<btc_domain::primitives::BlockHeader>, Box<dyn Error + Send + Sync>>;

    /// Checks if a block exists in storage.
    ///
    /// # Arguments
    ///
    /// * `hash` - The block hash to check
    ///
    /// # Returns
    ///
    /// Returns `true` if the block exists, `false` otherwise.
    async fn has_block(&self, hash: &BlockHash) -> Result<bool, Box<dyn Error + Send + Sync>>;

    /// Gets the hash of the best (most-work) block in the chain.
    ///
    /// # Returns
    ///
    /// Returns the hash of the tip of the best chain.
    async fn get_best_block_hash(&self) -> Result<BlockHash, Box<dyn Error + Send + Sync>>;

    /// Gets the height of a block.
    ///
    /// # Arguments
    ///
    /// * `hash` - The block hash
    ///
    /// # Returns
    ///
    /// Returns `Some(height)` if the block exists, `None` otherwise.
    async fn get_block_height(&self, hash: &BlockHash) -> Result<Option<u32>, Box<dyn Error + Send + Sync>>;
}

/// Port trait for persistent chain state storage.
///
/// This trait handles storage of UTXO set and chain tip information.
/// The UTXO set is critical for transaction validation.
#[async_trait::async_trait]
pub trait ChainStateStore: Send + Sync {
    /// Retrieves a UTXO from the UTXO set.
    ///
    /// # Arguments
    ///
    /// * `txid` - Transaction ID
    /// * `vout` - Output index
    ///
    /// # Returns
    ///
    /// Returns `Some(utxo)` if the UTXO exists, `None` if it's been spent or doesn't exist.
    async fn get_utxo(
        &self,
        txid: &Txid,
        vout: u32,
    ) -> Result<Option<UtxoEntry>, Box<dyn Error + Send + Sync>>;

    /// Checks if a UTXO exists in the UTXO set.
    ///
    /// # Arguments
    ///
    /// * `txid` - Transaction ID
    /// * `vout` - Output index
    ///
    /// # Returns
    ///
    /// Returns `true` if the UTXO exists and is unspent.
    async fn has_utxo(&self, txid: &Txid, vout: u32) -> Result<bool, Box<dyn Error + Send + Sync>>;

    /// Atomically writes a batch of UTXO updates to the UTXO set.
    ///
    /// This is typically called after validating a block, to remove spent outputs
    /// and add newly created outputs.
    ///
    /// # Arguments
    ///
    /// * `adds` - UTXOs to add to the UTXO set (new outputs)
    /// * `removes` - (txid, vout) pairs to remove from the UTXO set (spent outputs)
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` on success.
    async fn write_utxo_set(
        &self,
        adds: Vec<(Txid, u32, UtxoEntry)>,
        removes: Vec<(Txid, u32)>,
    ) -> Result<(), Box<dyn Error + Send + Sync>>;

    /// Gets the hash and height of the best chain tip.
    ///
    /// # Returns
    ///
    /// Returns `Ok((block_hash, height))` for the current tip, or an error if not set.
    async fn get_best_chain_tip(&self) -> Result<(BlockHash, u32), Box<dyn Error + Send + Sync>>;

    /// Writes the new best chain tip.
    ///
    /// # Arguments
    ///
    /// * `hash` - The hash of the new best block
    /// * `height` - The height of the new best block
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` on success.
    async fn write_chain_tip(&self, hash: BlockHash, height: u32)
        -> Result<(), Box<dyn Error + Send + Sync>>;
}
