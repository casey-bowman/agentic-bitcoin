//! Command types for the application
//!
//! Commands represent actions that modify state (CQRS pattern).

use btc_domain::primitives::{Block, Transaction};

/// Command to submit a new transaction to the mempool
#[derive(Clone, Debug)]
pub struct SendTransaction {
    pub tx: Transaction,
}

impl SendTransaction {
    pub fn new(tx: Transaction) -> Self {
        SendTransaction { tx }
    }
}

/// Command to submit a mined block
#[derive(Clone, Debug)]
pub struct SubmitBlock {
    pub block: Block,
}

impl SubmitBlock {
    pub fn new(block: Block) -> Self {
        SubmitBlock { block }
    }
}

/// Command to mine a block
#[derive(Clone, Debug)]
pub struct MineBlock {
    pub coinbase_address: String,
}

impl MineBlock {
    pub fn new(coinbase_address: String) -> Self {
        MineBlock { coinbase_address }
    }
}

/// Command to update chain tip
#[derive(Clone, Debug)]
pub struct UpdateChainTip {
    pub block_hash: String,
    pub height: u32,
}

impl UpdateChainTip {
    pub fn new(block_hash: String, height: u32) -> Self {
        UpdateChainTip { block_hash, height }
    }
}
