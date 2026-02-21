//! Mempool Port Definitions
//!
//! This module defines the port traits for transaction mempool management.
//! The mempool is the pool of unconfirmed transactions waiting to be mined into blocks.

use abtc_domain::primitives::{Transaction, Txid, Amount};
use std::error::Error;

/// An entry in the mempool.
///
/// Contains transaction information along with mempool-specific metadata.
#[derive(Clone, Debug)]
pub struct MempoolEntry {
    /// The transaction
    pub tx: Transaction,
    /// Total fee for the transaction (in satoshis)
    pub fee: Amount,
    /// Size of the transaction in bytes
    pub size: usize,
    /// Time the transaction was added to mempool (Unix timestamp)
    pub time: u64,
    /// Height at which the transaction was added
    pub height: u32,
    /// Number of transactions that depend on this one
    pub descendant_count: u32,
    /// Total size of all descendants (in bytes)
    pub descendant_size: u32,
    /// Number of transactions this one depends on
    pub ancestor_count: u32,
    /// Total size of all ancestors (in bytes)
    pub ancestor_size: u32,
}

/// Summary information about the mempool.
#[derive(Clone, Debug)]
pub struct MempoolInfo {
    /// Number of transactions in mempool
    pub size: u32,
    /// Total size of all mempool transactions (in bytes)
    pub bytes: u64,
    /// Estimated memory usage (in bytes)
    pub usage: u64,
    /// Maximum mempool size (in bytes)
    pub max_mempool: u64,
    /// Minimum relay fee (satoshis per byte)
    pub min_relay_fee: f64,
}

/// Port trait for managing the transaction mempool.
///
/// The mempool is the primary location where unconfirmed transactions wait before
/// being included in blocks. This trait defines operations for managing and querying
/// the mempool.
#[async_trait::async_trait]
pub trait MempoolPort: Send + Sync {
    /// Adds a transaction to the mempool.
    ///
    /// The transaction is validated before being added. It must:
    /// - Have valid signatures
    /// - Spend existing UTXOs
    /// - Meet relay policy rules
    ///
    /// # Arguments
    ///
    /// * `tx` - The transaction to add
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` if the transaction was added successfully.
    async fn add_transaction(&self, tx: &Transaction) -> Result<(), Box<dyn Error + Send + Sync>>;

    /// Removes a transaction from the mempool.
    ///
    /// Typically called when a transaction is confirmed in a block,
    /// or when evicted due to mempool size limits.
    ///
    /// # Arguments
    ///
    /// * `txid` - The transaction ID to remove
    /// * `recursive` - If true, also remove dependent transactions
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` if the transaction was removed (or didn't exist).
    async fn remove_transaction(
        &self,
        txid: &Txid,
        recursive: bool,
    ) -> Result<(), Box<dyn Error + Send + Sync>>;

    /// Retrieves a transaction from the mempool.
    ///
    /// # Arguments
    ///
    /// * `txid` - The transaction ID to retrieve
    ///
    /// # Returns
    ///
    /// Returns `Some(entry)` if the transaction is in the mempool, `None` otherwise.
    async fn get_transaction(
        &self,
        txid: &Txid,
    ) -> Result<Option<MempoolEntry>, Box<dyn Error + Send + Sync>>;

    /// Retrieves all transactions in the mempool.
    ///
    /// # Returns
    ///
    /// Returns a vector of all transactions currently in the mempool.
    async fn get_all_transactions(&self) -> Result<Vec<MempoolEntry>, Box<dyn Error + Send + Sync>>;

    /// Gets the number of transactions in the mempool.
    ///
    /// # Returns
    ///
    /// Returns the transaction count.
    async fn get_transaction_count(&self) -> Result<u32, Box<dyn Error + Send + Sync>>;

    /// Estimates the fee rate needed to confirm within target blocks.
    ///
    /// Uses mempool transaction patterns to estimate appropriate fee rates.
    ///
    /// # Arguments
    ///
    /// * `target_blocks` - Number of blocks to target for confirmation
    ///
    /// # Returns
    ///
    /// Returns the estimated fee rate in satoshis per byte.
    async fn estimate_fee(&self, target_blocks: u32) -> Result<f64, Box<dyn Error + Send + Sync>>;

    /// Gets summary information about the mempool.
    ///
    /// # Returns
    ///
    /// Returns a `MempoolInfo` struct with current mempool statistics.
    async fn get_mempool_info(&self) -> Result<MempoolInfo, Box<dyn Error + Send + Sync>>;

    /// Clears the entire mempool.
    ///
    /// This is typically only called during shutdown or in test scenarios.
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` on success.
    async fn clear(&self) -> Result<(), Box<dyn Error + Send + Sync>>;
}
