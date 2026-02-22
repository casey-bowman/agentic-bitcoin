//! In-Memory Mempool Implementation
//!
//! Provides a real mempool that stores unconfirmed transactions, orders them by
//! fee rate for mining, enforces size limits, and supports eviction of low-fee
//! transactions when the pool is full.
//!
//! Features:
//! - RBF (BIP125) replacement support
//! - Ancestor/descendant tracking with configurable limits
//! - CPFP-aware mining selection (ancestor fee rate ordering)
//! - Fee estimation from observed transaction patterns
//!
//! All mutable state lives behind a single `RwLock<MempoolInner>` to
//! eliminate the deadlock risk identified in the code review (finding #17).

use async_trait::async_trait;
use abtc_domain::policy::limits::{MempoolLimits, PackageInfo};
use abtc_domain::policy::rbf::{RbfPolicy, SignalsRbf};
use abtc_domain::primitives::{Amount, Transaction, Txid};
use abtc_ports::{MempoolEntry, MempoolInfo, MempoolPort};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;

/// Maximum mempool size in bytes (default: 300 MB, matching Bitcoin Core)
const DEFAULT_MAX_MEMPOOL_BYTES: u64 = 300_000_000;

/// Minimum relay fee rate in satoshis per byte
const MIN_RELAY_FEE_RATE: f64 = 1.0;

/// All mutable mempool state, held behind a single `RwLock` to prevent
/// deadlocks from multi-lock acquisition ordering.
struct MempoolInner {
    entries: HashMap<Txid, MempoolEntry>,
    packages: HashMap<Txid, PackageInfo>,
    children: HashMap<Txid, HashSet<Txid>>,
    parents: HashMap<Txid, HashSet<Txid>>,
    total_bytes: u64,
    current_height: u32,
    fee_rate_buckets: Vec<f64>,
}

impl MempoolInner {
    fn new() -> Self {
        MempoolInner {
            entries: HashMap::new(),
            packages: HashMap::new(),
            children: HashMap::new(),
            parents: HashMap::new(),
            total_bytes: 0,
            current_height: 0,
            fee_rate_buckets: Vec::new(),
        }
    }

    /// Collect all descendants of a txid into the given set (recursive).
    fn collect_descendants(&self, txid: Txid, result: &mut HashSet<Txid>) {
        if let Some(kids) = self.children.get(&txid) {
            for child in kids {
                if result.insert(*child) {
                    self.collect_descendants(*child, result);
                }
            }
        }
    }

    /// Collect all ancestors of a txid (recursive).
    fn collect_ancestors(&self, txid: &Txid, result: &mut HashSet<Txid>) {
        if let Some(pars) = self.parents.get(txid) {
            for parent in pars {
                if result.insert(*parent) {
                    self.collect_ancestors(parent, result);
                }
            }
        }
    }

    /// Remove a single transaction and clean up graph edges and package info.
    fn remove_entry(&mut self, txid: &Txid) {
        if let Some(entry) = self.entries.remove(txid) {
            self.total_bytes = self.total_bytes.saturating_sub(entry.size as u64);
            let fee = entry.fee;
            let vsize = entry.size as u32;

            // Update ancestors: decrement their descendant counts
            let mut ancestors = HashSet::new();
            self.collect_ancestors(txid, &mut ancestors);
            for anc_txid in &ancestors {
                if let Some(anc_pkg) = self.packages.get_mut(anc_txid) {
                    anc_pkg.descendant_count = anc_pkg.descendant_count.saturating_sub(1);
                    anc_pkg.descendant_size = anc_pkg.descendant_size.saturating_sub(vsize);
                    anc_pkg.descendant_fee = Amount::from_sat(
                        anc_pkg.descendant_fee.as_sat().saturating_sub(fee.as_sat()),
                    );
                }
            }

            // Clean up graph edges
            if let Some(my_parents) = self.parents.remove(txid) {
                for parent in &my_parents {
                    if let Some(parent_children) = self.children.get_mut(parent) {
                        parent_children.remove(txid);
                    }
                }
            }
            if let Some(my_children) = self.children.remove(txid) {
                for child in &my_children {
                    if let Some(child_parents) = self.parents.get_mut(child) {
                        child_parents.remove(txid);
                    }
                }
            }

            self.packages.remove(txid);
        }
    }

    /// Update ancestor/descendant package info after adding a transaction.
    fn update_package_info(&mut self, txid: Txid, fee: Amount, vsize: u32) {
        let mut ancestors = HashSet::new();
        self.collect_ancestors(&txid, &mut ancestors);

        let ancestor_count = (ancestors.len() + 1) as u32;
        let mut ancestor_size = vsize;
        let mut ancestor_fee = fee;

        for anc_txid in &ancestors {
            if let Some(pkg) = self.packages.get(anc_txid) {
                ancestor_size += pkg.vsize;
                ancestor_fee = Amount::from_sat(ancestor_fee.as_sat() + pkg.fee.as_sat());
            }
        }

        let pkg = PackageInfo {
            txid,
            vsize,
            fee,
            ancestor_count,
            ancestor_size,
            ancestor_fee,
            descendant_count: 1,
            descendant_size: vsize,
            descendant_fee: fee,
        };
        self.packages.insert(txid, pkg);

        // Update descendant info on all ancestors
        for anc_txid in &ancestors {
            if let Some(anc_pkg) = self.packages.get_mut(anc_txid) {
                anc_pkg.descendant_count += 1;
                anc_pkg.descendant_size += vsize;
                anc_pkg.descendant_fee =
                    Amount::from_sat(anc_pkg.descendant_fee.as_sat() + fee.as_sat());
            }
        }
    }

    /// Evict lowest descendant-fee-rate transactions to make room.
    fn evict_if_needed(&mut self, max_bytes: u64) {
        if self.total_bytes <= max_bytes {
            return;
        }

        let mut by_desc_rate: Vec<(Txid, f64, usize)> = self
            .entries
            .iter()
            .map(|(txid, entry)| {
                let rate = self
                    .packages
                    .get(txid)
                    .map(|p| p.descendant_fee_rate())
                    .unwrap_or(0.0);
                (*txid, rate, entry.size)
            })
            .collect();

        by_desc_rate.sort_by(|a, b| {
            a.1.partial_cmp(&b.1)
                .unwrap_or(std::cmp::Ordering::Equal)
        });

        for (txid, _rate, size) in by_desc_rate {
            if self.total_bytes <= max_bytes {
                break;
            }
            self.entries.remove(&txid);
            self.total_bytes = self.total_bytes.saturating_sub(size as u64);
            tracing::debug!("Evicted transaction {} from mempool (low descendant fee rate)", txid);
        }
    }

    /// Attempt RBF replacement: check if a new transaction can replace existing ones.
    /// Returns the set of txids that would be evicted if replacement succeeds.
    fn try_rbf_replacement(
        &self,
        tx: &Transaction,
        new_fee: Amount,
        new_size: usize,
    ) -> Result<Vec<Txid>, String> {
        let mut conflicting_txids: HashSet<Txid> = HashSet::new();

        for input in &tx.inputs {
            for (existing_txid, existing_entry) in self.entries.iter() {
                for existing_input in &existing_entry.tx.inputs {
                    if existing_input.previous_output == input.previous_output {
                        conflicting_txids.insert(*existing_txid);
                    }
                }
            }
        }

        if conflicting_txids.is_empty() {
            return Err("no conflicting transactions".into());
        }

        let mut to_evict: HashSet<Txid> = HashSet::new();
        for txid in &conflicting_txids {
            self.collect_descendants(*txid, &mut to_evict);
            to_evict.insert(*txid);
        }

        let originals: Vec<(Txid, Amount, usize, bool)> = conflicting_txids
            .iter()
            .filter_map(|txid| {
                self.entries.get(txid).map(|entry| {
                    (*txid, entry.fee, entry.size, entry.tx.signals_rbf())
                })
            })
            .collect();

        RbfPolicy::check_replacement(
            new_fee,
            new_size,
            &originals,
            to_evict.len(),
        )
        .map_err(|e| format!("RBF rejected: {}", e))?;

        Ok(to_evict.into_iter().collect())
    }
}

/// In-memory mempool implementation with fee-rate ordering and eviction.
///
/// All mutable state is held behind a single `RwLock<MempoolInner>` to
/// eliminate the deadlock risk from acquiring multiple independent locks
/// (code review finding #17).
pub struct InMemoryMempool {
    inner: Arc<RwLock<MempoolInner>>,
    max_bytes: u64,
    limits: MempoolLimits,
}

impl InMemoryMempool {
    /// Create a new in-memory mempool with default settings
    pub fn new() -> Self {
        InMemoryMempool {
            inner: Arc::new(RwLock::new(MempoolInner::new())),
            max_bytes: DEFAULT_MAX_MEMPOOL_BYTES,
            limits: MempoolLimits::default(),
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
        let mut inner = self.inner.write().await;
        inner.current_height = height;
    }

    /// Get the number of transactions in the mempool
    pub async fn size(&self) -> usize {
        let inner = self.inner.read().await;
        inner.entries.len()
    }

    /// Get transactions ordered by ancestor fee rate (CPFP-aware) for mining.
    pub async fn get_transactions_by_fee_rate(&self, max_weight: u32) -> Vec<MempoolEntry> {
        let inner = self.inner.read().await;

        let mut by_ancestor_rate: Vec<(Txid, f64)> = inner
            .entries
            .keys()
            .map(|txid| {
                let rate = inner
                    .packages
                    .get(txid)
                    .map(|p| p.ancestor_fee_rate())
                    .unwrap_or(0.0);
                (*txid, rate)
            })
            .collect();

        by_ancestor_rate.sort_by(|a, b| {
            b.1.partial_cmp(&a.1)
                .unwrap_or(std::cmp::Ordering::Equal)
        });

        let mut total_weight: u32 = 0;
        let mut selected = Vec::new();
        let mut included: HashSet<Txid> = HashSet::new();

        for (txid, _rate) in by_ancestor_rate {
            if let Some(entry) = inner.entries.get(&txid) {
                let tx_weight = (entry.size as u32) * 4;
                if total_weight + tx_weight > max_weight {
                    continue;
                }
                if included.contains(&txid) {
                    continue;
                }
                total_weight += tx_weight;
                included.insert(txid);
                selected.push(entry.clone());
            }
        }

        selected
    }

    /// Remove transactions that were confirmed in a block
    pub async fn remove_for_block(&self, transactions: &[Transaction]) {
        let mut inner = self.inner.write().await;
        for tx in transactions {
            let txid = tx.txid();
            inner.remove_entry(&txid);
            tracing::debug!("Removed confirmed transaction {} from mempool", txid);
        }
    }

    /// Compute the serialized size of a transaction (simplified estimate)
    fn estimate_tx_size(tx: &Transaction) -> usize {
        let mut size = 10usize;

        for input in &tx.inputs {
            size += 41 + input.script_sig.len();
            if !input.witness.is_empty() {
                for item in input.witness.stack() {
                    size += 1 + item.len();
                }
            }
        }

        for output in &tx.outputs {
            size += 9 + output.script_pubkey.len();
        }

        size
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
        let size = Self::estimate_tx_size(tx);
        let max_bytes = self.max_bytes;

        let mut inner = self.inner.write().await;

        // Check if already in mempool
        if inner.entries.contains_key(&txid) {
            return Err(format!("Transaction {} already in mempool", txid).into());
        }

        // Compute fee from in-mempool parent outputs where available.
        let fee = {
            let mut input_total: i64 = 0;
            let mut all_inputs_resolved = true;
            for input in &tx.inputs {
                let parent_txid = &input.previous_output.txid;
                let vout = input.previous_output.vout as usize;
                if let Some(parent) = inner.entries.get(parent_txid) {
                    if let Some(output) = parent.tx.outputs.get(vout) {
                        input_total += output.value.as_sat();
                    } else {
                        all_inputs_resolved = false;
                    }
                } else {
                    all_inputs_resolved = false;
                }
            }
            if all_inputs_resolved && !tx.inputs.is_empty() {
                let output_total: i64 = tx.outputs.iter().map(|o| o.value.as_sat()).sum();
                Amount::from_sat(std::cmp::max(0, input_total - output_total))
            } else {
                Amount::from_sat(0)
            }
        };

        // Check for conflicts (same inputs) and attempt RBF if applicable
        let evict_list = inner.try_rbf_replacement(tx, fee, size);
        if let Ok(to_evict) = evict_list {
            for evict_txid in to_evict {
                inner.remove_entry(&evict_txid);
                tracing::info!("RBF: evicted conflicting transaction {}", evict_txid);
            }
        }

        // Identify in-mempool parents
        let in_mempool_parents: HashSet<Txid> = tx
            .inputs
            .iter()
            .filter(|input| inner.entries.contains_key(&input.previous_output.txid))
            .map(|input| input.previous_output.txid)
            .collect();

        // Check ancestor limits
        {
            let mut all_ancestors = HashSet::new();
            for parent_txid in &in_mempool_parents {
                all_ancestors.insert(*parent_txid);
                inner.collect_ancestors(parent_txid, &mut all_ancestors);
            }

            let ancestor_count = (all_ancestors.len() + 1) as u32;
            let ancestor_size: u32 = all_ancestors
                .iter()
                .filter_map(|t| inner.packages.get(t))
                .map(|p| p.vsize)
                .sum::<u32>()
                + size as u32;

            self.limits
                .check_ancestor_limits(ancestor_count, ancestor_size)
                .map_err(|e| format!("Ancestor limit exceeded: {}", e))?;
        }

        // Check descendant limits (on all ancestors)
        {
            for parent_txid in &in_mempool_parents {
                if let Some(parent_pkg) = inner.packages.get(parent_txid) {
                    let new_desc_count = parent_pkg.descendant_count + 1;
                    let new_desc_size = parent_pkg.descendant_size + size as u32;

                    self.limits
                        .check_descendant_limits(new_desc_count, new_desc_size)
                        .map_err(|e| format!("Descendant limit exceeded: {}", e))?;
                }

                let mut ancestors_of_parent = HashSet::new();
                inner.collect_ancestors(parent_txid, &mut ancestors_of_parent);
                for anc in &ancestors_of_parent {
                    if let Some(anc_pkg) = inner.packages.get(anc) {
                        let new_desc_count = anc_pkg.descendant_count + 1;
                        let new_desc_size = anc_pkg.descendant_size + size as u32;

                        self.limits
                            .check_descendant_limits(new_desc_count, new_desc_size)
                            .map_err(|e| format!("Descendant limit exceeded on ancestor: {}", e))?;
                    }
                }
            }
        }

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let height = inner.current_height;

        let entry = MempoolEntry {
            tx: tx.clone(),
            fee,
            size,
            time: now,
            height,
            descendant_count: 0,
            descendant_size: 0,
            ancestor_count: in_mempool_parents.len() as u32,
            ancestor_size: size as u32,
        };

        inner.entries.insert(txid, entry);

        // Update graph
        inner.parents.insert(txid, in_mempool_parents.clone());
        for parent_txid in &in_mempool_parents {
            inner
                .children
                .entry(*parent_txid)
                .or_default()
                .insert(txid);
        }
        inner.children.entry(txid).or_default();

        // Update total bytes
        inner.total_bytes += size as u64;

        // Update package info
        inner.update_package_info(txid, fee, size as u32);

        // Track fee rate for estimation
        let fee_rate = fee.as_sat() as f64 / size.max(1) as f64;
        inner.fee_rate_buckets.push(fee_rate);
        if inner.fee_rate_buckets.len() > 10000 {
            let drain_end = inner.fee_rate_buckets.len() - 10000;
            inner.fee_rate_buckets.drain(0..drain_end);
        }

        // Evict if over limit
        inner.evict_if_needed(max_bytes);

        tracing::debug!("Added transaction {} to mempool ({} bytes)", txid, size);
        Ok(())
    }

    async fn remove_transaction(
        &self,
        txid: &Txid,
        recursive: bool,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let mut inner = self.inner.write().await;

        if recursive {
            let mut desc = HashSet::new();
            inner.collect_descendants(*txid, &mut desc);
            for desc_txid in desc {
                inner.remove_entry(&desc_txid);
                tracing::debug!("Removed dependent transaction {} from mempool", desc_txid);
            }
        }

        inner.remove_entry(txid);
        tracing::debug!("Removed transaction {} from mempool", txid);
        Ok(())
    }

    async fn get_transaction(
        &self,
        txid: &Txid,
    ) -> Result<Option<MempoolEntry>, Box<dyn std::error::Error + Send + Sync>> {
        let inner = self.inner.read().await;
        Ok(inner.entries.get(txid).cloned())
    }

    async fn get_all_transactions(
        &self,
    ) -> Result<Vec<MempoolEntry>, Box<dyn std::error::Error + Send + Sync>> {
        let inner = self.inner.read().await;
        Ok(inner.entries.values().cloned().collect())
    }

    async fn get_transaction_count(&self) -> Result<u32, Box<dyn std::error::Error + Send + Sync>> {
        let inner = self.inner.read().await;
        Ok(inner.entries.len() as u32)
    }

    async fn estimate_fee(
        &self,
        target_blocks: u32,
    ) -> Result<f64, Box<dyn std::error::Error + Send + Sync>> {
        let inner = self.inner.read().await;

        if inner.fee_rate_buckets.is_empty() {
            return Ok(MIN_RELAY_FEE_RATE);
        }

        let mut sorted = inner.fee_rate_buckets.clone();
        sorted.sort_by(|a, b| b.partial_cmp(a).unwrap_or(std::cmp::Ordering::Equal));

        let percentile = match target_blocks {
            1 => 0.10,
            2..=3 => 0.25,
            4..=6 => 0.50,
            7..=12 => 0.75,
            _ => 0.90,
        };

        let index = ((sorted.len() as f64 * percentile) as usize).min(sorted.len() - 1);
        let estimated = sorted[index].max(MIN_RELAY_FEE_RATE);

        Ok(estimated)
    }

    async fn get_mempool_info(
        &self,
    ) -> Result<MempoolInfo, Box<dyn std::error::Error + Send + Sync>> {
        let inner = self.inner.read().await;

        Ok(MempoolInfo {
            size: inner.entries.len() as u32,
            bytes: inner.total_bytes,
            usage: inner.total_bytes + (inner.entries.len() as u64 * 200),
            max_mempool: self.max_bytes,
            min_relay_fee: MIN_RELAY_FEE_RATE / 100_000_000.0,
        })
    }

    async fn clear(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let mut inner = self.inner.write().await;

        inner.entries.clear();
        inner.packages.clear();
        inner.children.clear();
        inner.parents.clear();
        inner.total_bytes = 0;

        tracing::info!("Mempool cleared");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use abtc_domain::primitives::{OutPoint, TxIn, TxOut};
    use abtc_domain::Script;

    fn make_test_tx(value: i64) -> Transaction {
        let input = TxIn::final_input(OutPoint::new(Txid::zero(), 0), Script::new());
        let output = TxOut::new(Amount::from_sat(value), Script::new());
        Transaction::v1(vec![input], vec![output], 0)
    }

    fn make_child_tx(parent_txid: Txid, value: i64) -> Transaction {
        let input = TxIn::final_input(OutPoint::new(parent_txid, 0), Script::new());
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

        let fee = mempool.estimate_fee(1).await.unwrap();
        assert_eq!(fee, MIN_RELAY_FEE_RATE);
    }

    #[tokio::test]
    async fn test_eviction() {
        let mempool = InMemoryMempool::with_max_bytes(500);

        for i in 0..10 {
            let tx = make_test_tx(1000 * (i + 1));
            let _ = mempool.add_transaction(&tx).await;
        }

        let info = mempool.get_mempool_info().await.unwrap();
        assert!(info.bytes <= 500);
    }

    #[tokio::test]
    async fn test_parent_child_tracking() {
        let mempool = InMemoryMempool::new();

        let parent = make_test_tx(50_000);
        let parent_txid = parent.txid();
        mempool.add_transaction(&parent).await.unwrap();

        let child = make_child_tx(parent_txid, 40_000);
        mempool.add_transaction(&child).await.unwrap();

        assert_eq!(mempool.get_transaction_count().await.unwrap(), 2);

        let inner = mempool.inner.read().await;
        let parent_pkg = inner.packages.get(&parent_txid).unwrap();
        assert_eq!(parent_pkg.descendant_count, 2);
    }

    #[tokio::test]
    async fn test_recursive_remove() {
        let mempool = InMemoryMempool::new();

        let parent = make_test_tx(50_000);
        let parent_txid = parent.txid();
        mempool.add_transaction(&parent).await.unwrap();

        let child = make_child_tx(parent_txid, 40_000);
        mempool.add_transaction(&child).await.unwrap();

        assert_eq!(mempool.get_transaction_count().await.unwrap(), 2);

        mempool.remove_transaction(&parent_txid, true).await.unwrap();
        assert_eq!(mempool.get_transaction_count().await.unwrap(), 0);
    }

    #[tokio::test]
    async fn test_cpfp_mining_order() {
        let mempool = InMemoryMempool::new();

        let parent = make_test_tx(50_000);
        let parent_txid = parent.txid();
        mempool.add_transaction(&parent).await.unwrap();

        let child = make_child_tx(parent_txid, 40_000);
        mempool.add_transaction(&child).await.unwrap();

        let selected = mempool.get_transactions_by_fee_rate(4_000_000).await;
        assert_eq!(selected.len(), 2);
    }

    #[tokio::test]
    async fn test_remove_for_block() {
        let mempool = InMemoryMempool::new();

        let tx1 = make_test_tx(1000);
        let tx2 = make_test_tx(2000);
        mempool.add_transaction(&tx1).await.unwrap();
        mempool.add_transaction(&tx2).await.unwrap();

        assert_eq!(mempool.get_transaction_count().await.unwrap(), 2);

        mempool.remove_for_block(&[tx1]).await;
        assert_eq!(mempool.get_transaction_count().await.unwrap(), 1);
    }

    #[tokio::test]
    async fn test_ancestor_chain_limit() {
        let mempool = InMemoryMempool::new();

        let mut prev_txid = Txid::zero();
        let mut txids = Vec::new();

        for i in 0..25 {
            let tx = if i == 0 {
                make_test_tx(100_000)
            } else {
                make_child_tx(prev_txid, 100_000 - (i * 1000))
            };
            prev_txid = tx.txid();
            txids.push(prev_txid);
            mempool.add_transaction(&tx).await.unwrap();
        }

        assert_eq!(mempool.get_transaction_count().await.unwrap(), 25);

        let tx26 = make_child_tx(prev_txid, 50_000);
        let result = mempool.add_transaction(&tx26).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Ancestor limit"));
    }

    #[tokio::test]
    async fn test_get_all_transactions() {
        let mempool = InMemoryMempool::new();

        let tx1 = make_test_tx(1000);
        let tx2 = make_test_tx(2000);
        mempool.add_transaction(&tx1).await.unwrap();
        mempool.add_transaction(&tx2).await.unwrap();

        let all = mempool.get_all_transactions().await.unwrap();
        assert_eq!(all.len(), 2);
    }

    #[tokio::test]
    async fn test_get_nonexistent_transaction() {
        let mempool = InMemoryMempool::new();
        let result = mempool.get_transaction(&Txid::zero()).await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_remove_nonexistent_transaction() {
        let mempool = InMemoryMempool::new();
        mempool
            .remove_transaction(&Txid::zero(), false)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn test_mempool_set_height() {
        let mempool = InMemoryMempool::new();
        mempool.set_height(500).await;

        let tx = make_test_tx(10_000);
        mempool.add_transaction(&tx).await.unwrap();

        let entry = mempool.get_transaction(&tx.txid()).await.unwrap().unwrap();
        assert_eq!(entry.height, 500);
    }

    #[tokio::test]
    async fn test_mining_selection_weight_limit() {
        let mempool = InMemoryMempool::new();

        for i in 0..10 {
            let tx = make_test_tx(1000 * (i + 1));
            mempool.add_transaction(&tx).await.unwrap();
        }

        let selected = mempool.get_transactions_by_fee_rate(200).await;
        assert!(selected.len() < 10);

        let all = mempool.get_transactions_by_fee_rate(4_000_000).await;
        assert_eq!(all.len(), 10);
    }

    #[tokio::test]
    async fn test_remove_for_block_nonexistent() {
        let mempool = InMemoryMempool::new();

        let fake_tx = make_test_tx(999);
        mempool.remove_for_block(&[fake_tx]).await;
        assert_eq!(mempool.get_transaction_count().await.unwrap(), 0);
    }

    #[tokio::test]
    async fn test_child_removal_updates_parent_descendants() {
        let mempool = InMemoryMempool::new();

        let parent = make_test_tx(50_000);
        let parent_txid = parent.txid();
        mempool.add_transaction(&parent).await.unwrap();

        let child = make_child_tx(parent_txid, 40_000);
        let child_txid = child.txid();
        mempool.add_transaction(&child).await.unwrap();

        {
            let inner = mempool.inner.read().await;
            assert_eq!(inner.packages.get(&parent_txid).unwrap().descendant_count, 2);
        }

        mempool
            .remove_transaction(&child_txid, false)
            .await
            .unwrap();

        {
            let inner = mempool.inner.read().await;
            assert_eq!(inner.packages.get(&parent_txid).unwrap().descendant_count, 1);
        }
    }

    #[tokio::test]
    async fn test_default_impl() {
        let mempool = InMemoryMempool::default();
        assert_eq!(mempool.size().await, 0);
    }

    #[tokio::test]
    async fn test_fee_estimation_with_data() {
        let mempool = InMemoryMempool::new();

        for i in 0..100 {
            let tx = make_test_tx(1000 + i);
            mempool.add_transaction(&tx).await.unwrap();
        }

        let fee_1 = mempool.estimate_fee(1).await.unwrap();
        let fee_12 = mempool.estimate_fee(12).await.unwrap();

        assert!(fee_1 >= MIN_RELAY_FEE_RATE);
        assert!(fee_12 >= MIN_RELAY_FEE_RATE);
    }
}
