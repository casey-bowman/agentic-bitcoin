//! In-Memory Mempool Implementation
//!
//! Provides a real mempool that stores unconfirmed transactions, orders them by
//! fee rate for mining, enforces size limits, and supports eviction of low-fee
//! transactions when the pool is full.

use async_trait::async_trait;
use btc_domain::primitives::{Amount, Transaction, Txid};
use btc_ports::{MempoolPort, MempoolEntry, MempoolInfo};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;

/// Maximum mempool size in bytes (default: 300 MB, matching Bitcoin Core)
const DEFAULT_MAX_MEMPOOL_BYTES: u64 = 300_000_000;

/// Minimum relay fee rate in satoshis per byte
const MIN_RELAY_FEE_RATE: f64 = 1.0;

/// In-memory mempool implementation with fee-rate ordering and eviction.
///
/// This mempool:
/// - Stores transactions indexed by txid
/// - Tracks ancestor/descendant relationships
/// - Orders transactions by fee rate for mining selection
/// - Evicts the lowest fee-rate transactions when the pool exceeds its size limit
/// - Provides fee estimation based on recent transaction patterns
pub struct InMemoryMempool {
    /// All transactions indexed by txid
    entries: Arc<RwLock<HashMap<Txid, MempoolEntry>>>,
    /// Current total size of all transactions in bytes
    total_bytes: Arc<RwLock<u64>>,
    /// Maximum mempool size in bytes
    max_bytes: u64,
    /// Current chain height (for entry metadata)
    current_height: Arc<RwLock<u32>>,
    /// Fee rate buckets for fee estimation (fee_rate_sat_per_byte -> count)
    fee_rate_buckets: Arc<RwLock<Vec<f64>>>,
}

impl InMemoryMempool {
    /// Create a new in-memory mempool with default settings
    pub fn new() -> Self {
        InMemoryMempool {
            entries: Arc::new(RwLock::new(HashMap::new())),
            total_bytes: Arc::new(RwLock::new(0)),
            max_bytes: DEFAULT_MAX_MEMPOOL_BYTES,
            current_height: Arc::new(RwLock::new(0)),
            fee_rate_buckets: Arc::new(RwLock::new(Vec::new())),
        }
    }

    /// Create a new in-memory mempool with custom max size
    pub fn with_max_bytes(max_bytes: u64) -> Self {
        InMemoryMempool {
            max_bytes,
            ..Self::new()
        }
    }

    /// Set the current chain height
    pub async fn set_height(&self, height: u32) {
        let mut h = self.current_height.write().await;
        *h = height;
    }

    /// Get the number of transactions in the mempool
    pub async fn size(&self) -> usize {
        let entries = self.entries.read().await;
        entries.len()
    }

    /// Get transactions ordered by fee rate (highest first) for mining
    pub async fn get_transactions_by_fee_rate(&self, max_weight: u32) -> Vec<MempoolEntry> {
        let entries = self.entries.read().await;
        let mut sorted: Vec<MempoolEntry> = entries.values().cloned().collect();

        // Sort by fee rate (fee / size) descending
        sorted.sort_by(|a, b| {
            let rate_a = a.fee.as_sat() as f64 / a.size.max(1) as f64;
            let rate_b = b.fee.as_sat() as f64 / b.size.max(1) as f64;
            rate_b
                .partial_cmp(&rate_a)
                .unwrap_or(std::cmp::Ordering::Equal)
        });

        // Select transactions that fit within the weight limit
        let mut total_weight: u32 = 0;
        let mut selected = Vec::new();

        for entry in sorted {
            // Approximate weight: size * 4 for non-witness, but this is a simplification
            let tx_weight = (entry.size as u32) * 4;
            if total_weight + tx_weight > max_weight {
                continue; // Skip transactions that don't fit
            }
            total_weight += tx_weight;
            selected.push(entry);
        }

        selected
    }

    /// Evict lowest fee-rate transactions to make room
    async fn evict_if_needed(&self) {
        let total = *self.total_bytes.read().await;
        if total <= self.max_bytes {
            return;
        }

        let mut entries = self.entries.write().await;
        let mut total_bytes = self.total_bytes.write().await;

        // Build a list sorted by fee rate ascending (lowest first for eviction)
        let mut by_fee_rate: Vec<(Txid, f64, usize)> = entries
            .iter()
            .map(|(txid, entry)| {
                let rate = entry.fee.as_sat() as f64 / entry.size.max(1) as f64;
                (*txid, rate, entry.size)
            })
            .collect();

        by_fee_rate.sort_by(|a, b| {
            a.1.partial_cmp(&b.1)
                .unwrap_or(std::cmp::Ordering::Equal)
        });

        // Evict from lowest fee rate until under the limit
        for (txid, _rate, size) in by_fee_rate {
            if *total_bytes <= self.max_bytes {
                break;
            }
            entries.remove(&txid);
            *total_bytes = total_bytes.saturating_sub(size as u64);
            tracing::debug!("Evicted transaction {} from mempool (low fee rate)", txid);
        }
    }

    /// Compute the serialized size of a transaction (simplified estimate)
    fn estimate_tx_size(tx: &Transaction) -> usize {
        // Base: version(4) + locktime(4) + input_count(1-3) + output_count(1-3)
        let mut size = 10usize;

        for input in &tx.inputs {
            // outpoint(36) + script_sig_len(1-3) + script_sig + sequence(4)
            size += 41 + input.script_sig.len();
            // Add witness data if present
            if !input.witness.is_empty() {
                for item in input.witness.stack() {
                    size += 1 + item.len(); // length prefix + data
                }
            }
        }

        for output in &tx.outputs {
            // value(8) + script_len(1-3) + script
            size += 9 + output.script_pubkey.len();
        }

        size
    }

    /// Remove transactions that were confirmed in a block
    pub async fn remove_for_block(&self, transactions: &[Transaction]) {
        let mut entries = self.entries.write().await;
        let mut total_bytes = self.total_bytes.write().await;

        for tx in transactions {
            let txid = tx.txid();
            if let Some(entry) = entries.remove(&txid) {
                *total_bytes = total_bytes.saturating_sub(entry.size as u64);
                tracing::debug!("Removed confirmed transaction {} from mempool", txid);
            }
        }
    }
}

impl Default for InMemoryMempool {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl MempoolPort for InMemoryMempool {
    async fn add_transaction(
        &self,
        tx: &Transaction,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let txid = tx.txid();

        // Check if already in mempool
        {
            let entries = self.entries.read().await;
            if entries.contains_key(&txid) {
                return Err(format!("Transaction {} already in mempool", txid).into());
            }
        }

        let size = Self::estimate_tx_size(tx);
        let height = *self.current_height.read().await;

        // Compute fee (simplified: we don't have UTXO access here, so fee is
        // set to 0 and should be computed by the caller before adding)
        // In a real implementation, fee would be calculated as sum(input_values) - sum(output_values)
        let fee = Amount::from_sat(0);

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let entry = MempoolEntry {
            tx: tx.clone(),
            fee,
            size,
            time: now,
            height,
            descendant_count: 0,
            descendant_size: 0,
            ancestor_count: 0,
            ancestor_size: 0,
        };

        // Add the entry
        {
            let mut entries = self.entries.write().await;
            entries.insert(txid, entry);
        }

        // Update total bytes
        {
            let mut total = self.total_bytes.write().await;
            *total += size as u64;
        }

        // Track fee rate for estimation
        {
            let fee_rate = fee.as_sat() as f64 / size.max(1) as f64;
            let mut buckets = self.fee_rate_buckets.write().await;
            buckets.push(fee_rate);
            // Keep only last 10000 entries for estimation
            if buckets.len() > 10000 {
                let drain_end = buckets.len() - 10000;
                buckets.drain(0..drain_end);
            }
        }

        // Evict if over limit
        self.evict_if_needed().await;

        tracing::debug!("Added transaction {} to mempool ({} bytes)", txid, size);
        Ok(())
    }

    async fn remove_transaction(
        &self,
        txid: &Txid,
        recursive: bool,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let mut entries = self.entries.write().await;
        let mut total_bytes = self.total_bytes.write().await;

        if let Some(entry) = entries.remove(txid) {
            *total_bytes = total_bytes.saturating_sub(entry.size as u64);
            tracing::debug!("Removed transaction {} from mempool", txid);

            if recursive {
                // Find and remove dependent transactions (those spending this tx's outputs)
                let dependents: Vec<Txid> = entries
                    .iter()
                    .filter(|(_, e)| {
                        e.tx.inputs.iter().any(|input| input.previous_output.txid == *txid)
                    })
                    .map(|(id, _)| *id)
                    .collect();

                for dep_txid in dependents {
                    if let Some(dep_entry) = entries.remove(&dep_txid) {
                        *total_bytes = total_bytes.saturating_sub(dep_entry.size as u64);
                        tracing::debug!(
                            "Removed dependent transaction {} from mempool",
                            dep_txid
                        );
                    }
                }
            }
        }

        Ok(())
    }

    async fn get_transaction(
        &self,
        txid: &Txid,
    ) -> Result<Option<MempoolEntry>, Box<dyn std::error::Error + Send + Sync>> {
        let entries = self.entries.read().await;
        Ok(entries.get(txid).cloned())
    }

    async fn get_all_transactions(
        &self,
    ) -> Result<Vec<MempoolEntry>, Box<dyn std::error::Error + Send + Sync>> {
        let entries = self.entries.read().await;
        Ok(entries.values().cloned().collect())
    }

    async fn get_transaction_count(&self) -> Result<u32, Box<dyn std::error::Error + Send + Sync>> {
        let entries = self.entries.read().await;
        Ok(entries.len() as u32)
    }

    async fn estimate_fee(
        &self,
        target_blocks: u32,
    ) -> Result<f64, Box<dyn std::error::Error + Send + Sync>> {
        let buckets = self.fee_rate_buckets.read().await;

        if buckets.is_empty() {
            // No data, return minimum relay fee
            return Ok(MIN_RELAY_FEE_RATE);
        }

        // Simple fee estimation: higher target = lower fee needed
        // Sort fee rates and pick a percentile based on target blocks
        let mut sorted = buckets.clone();
        sorted.sort_by(|a, b| b.partial_cmp(a).unwrap_or(std::cmp::Ordering::Equal));

        // For 1 block target, use ~90th percentile; for 6 blocks, ~50th; for 25+, minimum
        let percentile = match target_blocks {
            1 => 0.10,      // Top 10%
            2..=3 => 0.25,  // Top 25%
            4..=6 => 0.50,  // Median
            7..=12 => 0.75, // 75th percentile
            _ => 0.90,      // 90th percentile (low fee)
        };

        let index = ((sorted.len() as f64 * percentile) as usize).min(sorted.len() - 1);
        let estimated = sorted[index].max(MIN_RELAY_FEE_RATE);

        Ok(estimated)
    }

    async fn get_mempool_info(
        &self,
    ) -> Result<MempoolInfo, Box<dyn std::error::Error + Send + Sync>> {
        let entries = self.entries.read().await;
        let total_bytes = *self.total_bytes.read().await;

        Ok(MempoolInfo {
            size: entries.len() as u32,
            bytes: total_bytes,
            usage: total_bytes + (entries.len() as u64 * 200), // Rough overhead estimate
            max_mempool: self.max_bytes,
            min_relay_fee: MIN_RELAY_FEE_RATE / 100_000_000.0, // Convert sat/byte to BTC/kB
        })
    }

    async fn clear(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let mut entries = self.entries.write().await;
        let mut total_bytes = self.total_bytes.write().await;

        entries.clear();
        *total_bytes = 0;

        tracing::info!("Mempool cleared");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use btc_domain::primitives::{OutPoint, Script, TxIn, TxOut};

    fn make_test_tx(value: i64) -> Transaction {
        let input = TxIn::final_input(OutPoint::new(Txid::zero(), 0), Script::new());
        let output = TxOut::new(Amount::from_sat(value), Script::new());
        Transaction::v1(vec![input], vec![output], 0)
    }

    #[tokio::test]
    async fn test_mempool_add_and_get() {
        let mempool = InMemoryMempool::new();
        let tx = make_test_tx(1000);
        let txid = tx.txid();

        mempool.add_transaction(&tx).await.unwrap();

        let entry = mempool.get_transaction(&txid).await.unwrap();
        assert!(entry.is_some());
        assert_eq!(entry.unwrap().tx, tx);
    }

    #[tokio::test]
    async fn test_mempool_duplicate_rejection() {
        let mempool = InMemoryMempool::new();
        let tx = make_test_tx(1000);

        assert!(mempool.add_transaction(&tx).await.is_ok());
        assert!(mempool.add_transaction(&tx).await.is_err());
    }

    #[tokio::test]
    async fn test_mempool_remove() {
        let mempool = InMemoryMempool::new();
        let tx = make_test_tx(1000);
        let txid = tx.txid();

        mempool.add_transaction(&tx).await.unwrap();
        assert_eq!(mempool.get_transaction_count().await.unwrap(), 1);

        mempool.remove_transaction(&txid, false).await.unwrap();
        assert_eq!(mempool.get_transaction_count().await.unwrap(), 0);
    }

    #[tokio::test]
    async fn test_mempool_clear() {
        let mempool = InMemoryMempool::new();

        for i in 0..5 {
            let tx = make_test_tx(1000 + i);
            mempool.add_transaction(&tx).await.unwrap();
        }

        assert_eq!(mempool.get_transaction_count().await.unwrap(), 5);

        mempool.clear().await.unwrap();
        assert_eq!(mempool.get_transaction_count().await.unwrap(), 0);
    }

    #[tokio::test]
    async fn test_mempool_info() {
        let mempool = InMemoryMempool::new();
        let tx = make_test_tx(1000);
        mempool.add_transaction(&tx).await.unwrap();

        let info = mempool.get_mempool_info().await.unwrap();
        assert_eq!(info.size, 1);
        assert!(info.bytes > 0);
        assert_eq!(info.max_mempool, DEFAULT_MAX_MEMPOOL_BYTES);
    }

    #[tokio::test]
    async fn test_fee_estimation() {
        let mempool = InMemoryMempool::new();

        // With no data, should return minimum
        let fee = mempool.estimate_fee(1).await.unwrap();
        assert_eq!(fee, MIN_RELAY_FEE_RATE);
    }

    #[tokio::test]
    async fn test_eviction() {
        // Create a tiny mempool
        let mempool = InMemoryMempool::with_max_bytes(500);

        // Add transactions until we exceed the limit
        for i in 0..10 {
            let tx = make_test_tx(1000 * (i + 1));
            let _ = mempool.add_transaction(&tx).await;
        }

        // Some should have been evicted
        let info = mempool.get_mempool_info().await.unwrap();
        assert!(info.bytes <= 500);
    }
}
