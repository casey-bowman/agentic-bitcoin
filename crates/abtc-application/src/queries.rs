//! Query types for the application
//!
//! Queries represent actions that retrieve state without modifying it (CQRS pattern).

use abtc_domain::primitives::{BlockHash, Txid};

/// Query to get a specific block by hash
#[derive(Clone, Debug)]
pub struct GetBlock {
    pub hash: BlockHash,
}

impl GetBlock {
    pub fn new(hash: BlockHash) -> Self {
        GetBlock { hash }
    }
}

/// Query to get block height
#[derive(Clone, Debug)]
pub struct GetBlockHeight {
    pub hash: BlockHash,
}

impl GetBlockHeight {
    pub fn new(hash: BlockHash) -> Self {
        GetBlockHeight { hash }
    }
}

/// Query to get a specific transaction
#[derive(Clone, Debug)]
pub struct GetTransaction {
    pub txid: Txid,
}

impl GetTransaction {
    pub fn new(txid: Txid) -> Self {
        GetTransaction { txid }
    }
}

/// Query to get wallet balance
#[derive(Clone, Debug)]
pub struct GetBalance {
    pub address: Option<String>,
}

impl GetBalance {
    pub fn new(address: Option<String>) -> Self {
        GetBalance { address }
    }
}

/// Query to get chain info
#[derive(Clone, Debug)]
pub struct GetChainInfo;

/// Query to get mempool contents
#[derive(Clone, Debug)]
pub struct GetMempool {
    pub verbose: bool,
}

impl GetMempool {
    pub fn new(verbose: bool) -> Self {
        GetMempool { verbose }
    }
}

/// Query to estimate fee
#[derive(Clone, Debug)]
pub struct EstimateFee {
    pub target_blocks: u32,
}

impl EstimateFee {
    pub fn new(target_blocks: u32) -> Self {
        EstimateFee { target_blocks }
    }
}
