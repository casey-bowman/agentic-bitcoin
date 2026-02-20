//! Mining Port Definitions
//!
//! This module defines the port traits for block template creation and block submission.
//! Implementations handle mining pool integration and template creation.

use btc_domain::primitives::Block;
use btc_domain::script::Script;
use btc_domain::primitives::Amount;
use btc_domain::consensus::{ConsensusParams, ValidationState};
use std::error::Error;

/// A block template ready for mining.
///
/// Contains the block structure and additional information useful for miners.
#[derive(Clone, Debug)]
pub struct BlockTemplate {
    /// The block that should be mined
    pub block: Block,
    /// Fee for each transaction (in satoshis)
    pub fees: Vec<Amount>,
    /// Signature operations count for each transaction
    pub sigops: Vec<u64>,
    /// Difficulty target for this template
    pub target: u32,
    /// Height of the block being mined
    pub height: u32,
}

/// Port trait for creating mining block templates.
///
/// Implementations are responsible for selecting transactions from the mempool,
/// creating a valid block header, and packaging everything into a template for miners.
#[async_trait::async_trait]
pub trait BlockTemplateProvider: Send + Sync {
    /// Creates a block template ready for mining.
    ///
    /// This method:
    /// 1. Selects transactions from the mempool to maximize fees
    /// 2. Creates a coinbase transaction
    /// 3. Constructs a block header with appropriate target
    /// 4. Returns all information needed for mining
    ///
    /// # Arguments
    ///
    /// * `coinbase_script` - The script to use in the coinbase output (usually miner address)
    /// * `params` - Consensus parameters (difficulty adjustment info, etc.)
    ///
    /// # Returns
    ///
    /// Returns a `BlockTemplate` ready for mining, or an error if template creation fails.
    async fn create_block_template(
        &self,
        coinbase_script: &Script,
        params: &ConsensusParams,
    ) -> Result<BlockTemplate, Box<dyn Error + Send + Sync>>;

    /// Gets the current block height.
    ///
    /// # Returns
    ///
    /// Returns the height of the next block to be mined.
    async fn get_block_height(&self) -> Result<u32, Box<dyn Error + Send + Sync>>;
}

/// Port trait for submitting blocks to the network.
///
/// Implementations validate blocks and add them to the chain if valid.
#[async_trait::async_trait]
pub trait BlockSubmitter: Send + Sync {
    /// Submits a mined block for validation and addition to the chain.
    ///
    /// This method:
    /// 1. Validates the block against consensus rules
    /// 2. Adds it to the chain if valid
    /// 3. Broadcasts it to the network
    ///
    /// # Arguments
    ///
    /// * `block` - The block to submit
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` if the block was accepted, or a `ValidationState` error if validation failed.
    async fn submit_block(&self, block: &Block) -> Result<(), ValidationState>;

    /// Gets the current best block hash.
    ///
    /// # Returns
    ///
    /// Returns the hash of the tip of the best chain.
    async fn get_best_block_hash(&self) -> Result<btc_domain::primitives::BlockHash, Box<dyn Error + Send + Sync>>;
}
