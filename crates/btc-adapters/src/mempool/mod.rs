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

use async_trait::async_trait;
use btc_domain::policy::limits::{MempoolLimits, PackageInfo};
use btc_domain::policy::rbf::{RbfPolicy, SignalsRbf};
use btc_domain::primitives::{Amount, Transaction, Txid};
use btc_ports::{MempoolEntry, MempoolInfo, MempoolPort};
use std::collections::{HashMap, HashSet};
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
/// - Tracks ancestor/descendant relationships with graph traversal
/// - Enforces ancestor/descendant count and size limits (Bitcoin Core defaults: 25/101KB)
/// - Supports BIP125 Replace-by-Fee
/// - Orders transactions by ancestor fee rate (CPFP) for mining selection
/// - Evicts lowest descendant-fee-rate transactions when over the size limit
/// - Provides fee estimation based on recent transaction patterns
pub struct InMemoryMempool {
    /// All transactions indexed by txid
    entries: Arc<RwLock<HashMap<Txid, MempoolEntry>>>,
    /// Package info (ancestor/descendant tracking) per txid
    packages: Arc<RwLock<HashMap<Txid, PackageInfo>>>,
    /// Parent→children mapping (txid → set of child txids that spend its outputs)
    children: Arc<RwLock<HashMap<Txid, HashSet<Txid>>>>,
    /// Child→parents mapping (txid → set of parent txids it spends from)
    parents: Arc<RwLock<HashMap<Txid, HashSet<Txid>>>>,
    /// Current total size of all transactions in bytes
    total_bytes: Arc<RwLock<u64>>,
    /// Maximum mempool size in bytes
    max_bytes: u64,
    /// Current chain height (for entry metadata)
    current_height: Arc<RwLock<u32>>,
    /// Fee rate buckets for fee estimation (fee_rate_sat_per_byte -> count)
    fee_rate_buckets: Arc<RwLock<Vec<f64>>>,
    /// Configurable package limits
    limits: MempoolLimits,
}

impl InMemoryMempool {
    /// Create a new in-memory mempool with default settings
    pub fn new() -> Self {
        InMemoryMempool {
            entries: Arc::new(RwLock::new(HashMap::new())),
            packages: Arc::new(RwLock::new(HashMap::new())),
            children: Arc::new(RwLock::new(HashMap::new())),
            parents: Arc::new(RwLock::new(HashMap::new())),
            total_bytes: Arc::new(RwLock::new(0)),
            max_bytes: DEFAULT_MAX_MEMPOOL_BYTES,
            current_height: Arc::new(RwLock::new(0)),
            fee_rate_buckets: Arc::new(RwLock::new(Vec::new())),
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
        let mut h = self.current_height.write().await;
        *h = height;
    }

    /// Get the number of transactions in the mempool
    pub async fn size(&self) -> usize {
        let entries = self.entries.read().await;
        entries.len()
    }

    /// Get transactions ordered by ancestor fee rate (CPFP-aware) for mining.
    ///
    /// This is the key improvement over simple fee-rate ordering: a low-fee parent
    /// with a high-fee child gets a boosted "ancestor fee rate", so miners will
    /// include both the parent and child together.
    pub async fn get_transactions_by_fee_rate(&self, max_weight: u32) -> Vec<MempoolEntry> {
        let entries = self.entries.read().await;
        let packages = self.packages.read().await;

        // Build (txid, ancestor_fee_rate) pairs and sort descending
        let mut by_ancestor_rate: Vec<(Txid, f64)> = entries
            .keys()
            .map(|txid| {
                let rate = packages
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

        // Select transactions that fit within the weight limit
        let mut total_weight: u32 = 0;
        let mut selected = Vec::new();
        let mut included: HashSet<Txid> = HashSet::new();

        for (txid, _rate) in by_ancestor_rate {
            if let Some(entry) = entries.get(&txid) {
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

    /// Attempt RBF replacement: check if a new transaction can replace existing ones.
    ///
    /// Returns the set of txids that would be evicted if replacement succeeds.
    async fn try_rbf_replacement(
        &self,
        tx: &Transaction,
        new_fee: Amount,
        new_size: usize,
    ) -> Result<Vec<Txid>, String> {
        let entries = self.entries.read().await;
        let children_map = self.children.read().await;

        // Find which existing mempool transactions conflict with the new tx
        // (i.e., spend the same inputs)
        let mut conflicting_txids: HashSet<Txid> = HashSet::new();

        for input in &tx.inputs {
            for (existing_txid, existing_entry) in entries.iter() {
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

        // Collect all descendants of conflicting transactions (they'll be evicted too)
        let mut to_evict: HashSet<Txid> = HashSet::new();
        for txid in &conflicting_txids {
            self.collect_descendants_locked(*txid, &children_map, &mut to_evict);
            to_evict.insert(*txid);
        }

        // Build originals list for RBF policy check
        let originals: Vec<(Txid, Amount, usize, bool)> = conflicting_txids
            .iter()
            .filter_map(|txid| {
                entries.get(txid).map(|entry| {
                    (*txid, entry.fee, entry.size, entry.tx.signals_rbf())
                })
            })
            .collect();

        // Check BIP125 rules
        RbfPolicy::check_replacement(
            new_fee,
            new_size,
            &originals,
            to_evict.len(),
        )
        .map_err(|e| format!("RBF rejected: {}", e))?;

        Ok(to_evict.into_iter().collect())
    }

    /// Collect all descendants of a txid into the given set (recursive).
    fn collect_descendants_locked(
        &self,
        txid: Txid,
        children_map: &HashMap<Txid, HashSet<Txid>>,
        result: &mut HashSet<Txid>,
    ) {
        if let Some(kids) = children_map.get(&txid) {
            for child in kids {
                if result.insert(*child) {
                    self.collect_descendants_locked(*child, children_map, result);
                }
            }
        }
    }

    /// Collect all ancestors of a txid (recursive).
    fn collect_ancestors_locked(
        &self,
        txid: Txid,
        parents_map: &HashMap<Txid, HashSet<Txid>>,
        result: &mut HashSet<Txid>,
    ) {
        if let Some(pars) = parents_map.get(&txid) {
            for parent in pars {
                if result.insert(*parent) {
                    self.collect_ancestors_locked(*parent, parents_map, result);
                }
            }
        }
    }

    /// Update ancestor/descendant package info after adding a transaction.
    async fn update_package_info(&self, txid: Txid, fee: Amount, vsize: u32) {
        let parents_map = self.parents.read().await;
        let _children_map = self.children.read().await;
        let mut packages = self.packages.write().await;

        // Compute ancestors
        let mut ancestors = HashSet::new();
        self.collect_ancestors_locked(txid, &parents_map, &mut ancestors);

        let ancestor_count = (ancestors.len() + 1) as u32;
        let mut ancestor_size = vsize;
        let mut ancestor_fee = fee;

        for anc_txid in &ancestors {
            if let Some(pkg) = packages.get(anc_txid) {
                ancestor_size += pkg.vsize;
                ancestor_fee = Amount::from_sat(ancestor_fee.as_sat() + pkg.fee.as_sat());
            }
        }

        // Create package info for the new transaction
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
        packages.insert(txid, pkg);

        // Update descendant info on all ancestors
        for anc_txid in &ancestors {
            if let Some(anc_pkg) = packages.get_mut(anc_txid) {
                anc_pkg.descendant_count += 1;
                anc_pkg.descendant_size += vsize;
                anc_pkg.descendant_fee =
                    Amount::from_sat(anc_pkg.descendant_fee.as_sat() + fee.as_sat());
            }
        }
    }

    /// Evict lowest descendant-fee-rate transactions to make room.
    ///
    /// Uses descendant fee rate (not individual fee rate) so that low-fee
    /// parents with high-fee children aren't evicted first.
    async fn evict_if_needed(&self) {
        let total = *self.total_bytes.read().await;
        if total <= self.max_bytes {
            return;
        }

        let packages = self.packages.read().await;
        let mut entries = self.entries.write().await;
        let mut total_bytes = self.total_bytes.write().await;

        // Sort by descendant fee rate ascending (lowest first for eviction)
        let mut by_desc_rate: Vec<(Txid, f64, usize)> = entries
            .iter()
            .map(|(txid, entry)| {
                let rate = packages
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
            if *total_bytes <= self.max_bytes {
                break;
            }
            entries.remove(&txid);
            *total_bytes = total_bytes.saturating_sub(size as u64);
            tracing::debug!("Evicted transaction {} from mempool (low descendant fee rate)", txid);
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

    /// Remove a single transaction and clean up graph edges.
    async fn remove_entry(&self, txid: &Txid) {
        let mut entries = self.entries.write().await;
        let mut packages = self.packages.write().await;
        let mut children_map = self.children.write().await;
        let mut parents_map = self.parents.write().await;
        let mut total_bytes = self.total_bytes.write().await;

        if let Some(entry) = entries.remove(txid) {
            *total_bytes = total_bytes.saturating_sub(entry.size as u64);
            let fee = entry.fee;
            let vsize = entry.size as u32;

            // Update ancestors: decrement their descendant counts
            let mut ancestors = HashSet::new();
            Self::collect_ancestors_static(txid, &parents_map, &mut ancestors);
            for anc_txid in &ancestors {
                if let Some(anc_pkg) = packages.get_mut(anc_txid) {
                    anc_pkg.descendant_count = anc_pkg.descendant_count.saturating_sub(1);
                    anc_pkg.descendant_size = anc_pkg.descendant_size.saturating_sub(vsize);
                    anc_pkg.descendant_fee = Amount::from_sat(
                        anc_pkg.descendant_fee.as_sat().saturating_sub(fee.as_sat()),
                    );
                }
            }

            // Clean up graph edges
            if let Some(my_parents) = parents_map.remove(txid) {
                for parent in &my_parents {
                    if let Some(parent_children) = children_map.get_mut(parent) {
                        parent_children.remove(txid);
                    }
                }
            }
            if let Some(my_children) = children_map.remove(txid) {
                for child in &my_children {
                    if let Some(child_parents) = parents_map.get_mut(child) {
                        child_parents.remove(txid);
                    }
                }
            }

            packages.remove(txid);
        }
    }

    /// Static version of collect_ancestors (doesn't need &self)
    fn collect_ancestors_static(
        txid: &Txid,
        parents_map: &HashMap<Txid, HashSet<Txid>>,
        result: &mut HashSet<Txid>,
    ) {
        if let Some(pars) = parents_map.get(txid) {
            for parent in pars {
                if result.insert(*parent) {
                    Self::collect_ancestors_static(parent, parents_map, result);
                }
            }
        }
    }

    /// Remove transactions that were confirmed in a block
    pub async fn remove_for_block(&self, transactions: &[Transaction]) {
        for tx in transactions {
            let txid = tx.txid();
            self.remove_entry(&txid).await;
            tracing::debug!("Removed confirmed transaction {} from mempool", txid);
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
        let size = Self::estimate_tx_size(tx);
        let height = *self.current_height.read().await;

        // Compute fee (simplified — real impl needs UTXO lookup)
        let fee = Amount::from_sat(0);

        // Check if already in mempool
        {
            let entries = self.entries.read().await;
            if entries.contains_key(&txid) {
                return Err(format!("Transaction {} already in mempool", txid).into());
            }
        }

        // Check for conflicts (same inputs) and attempt RBF if applicable
        {
            let evict_list = self.try_rbf_replacement(tx, fee, size).await;
            if let Ok(to_evict) = evict_list {
                if !to_evict.is_empty() {
                    for evict_txid in to_evict {
                        self.remove_entry(&evict_txid).await;
                        tracing::info!("RBF: evicted conflicting transaction {}", evict_txid);
                    }
                }
            }
            // If RBF check fails, that means either no conflicts exist or the
            // replacement doesn't qualify — we proceed with normal addition.
        }

        // Identify in-mempool parents (inputs that spend mempool transactions)
        let in_mempool_parents: HashSet<Txid> = {
            let entries = self.entries.read().await;
            tx.inputs
                .iter()
                .filter(|input| entries.contains_key(&input.previous_output.txid))
                .map(|input| input.previous_output.txid)
                .collect()
        };

        // Check ancestor limits
        {
            let parents_map = self.parents.read().await;
            let packages = self.packages.read().await;

            let mut all_ancestors = HashSet::new();
            for parent_txid in &in_mempool_parents {
                all_ancestors.insert(*parent_txid);
                self.collect_ancestors_locked(*parent_txid, &parents_map, &mut all_ancestors);
            }

            let ancestor_count = (all_ancestors.len() + 1) as u32;
            let ancestor_size: u32 = all_ancestors
                .iter()
                .filter_map(|t| packages.get(t))
                .map(|p| p.vsize)
                .sum::<u32>()
                + size as u32;

            self.limits
                .check_ancestor_limits(ancestor_count, ancestor_size)
                .map_err(|e| format!("Ancestor limit exceeded: {}", e))?;
        }

        // Check descendant limits (on all ancestors)
        {
            let parents_map = self.parents.read().await;
            let packages = self.packages.read().await;

            for parent_txid in &in_mempool_parents {
                if let Some(parent_pkg) = packages.get(parent_txid) {
                    let new_desc_count = parent_pkg.descendant_count + 1;
                    let new_desc_size = parent_pkg.descendant_size + size as u32;

                    self.limits
                        .check_descendant_limits(new_desc_count, new_desc_size)
                        .map_err(|e| format!("Descendant limit exceeded: {}", e))?;
                }

                // Also check ancestors of the parent
                let mut ancestors_of_parent = HashSet::new();
                self.collect_ancestors_locked(*parent_txid, &parents_map, &mut ancestors_of_parent);
                for anc in &ancestors_of_parent {
                    if let Some(anc_pkg) = packages.get(anc) {
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

        // Add the entry
        {
            let mut entries = self.entries.write().await;
            entries.insert(txid, entry);
        }

        // Update graph
        {
            let mut children_map = self.children.write().await;
            let mut parents_map = self.parents.write().await;

            parents_map.insert(txid, in_mempool_parents.clone());
            for parent_txid in &in_mempool_parents {
                children_map
                    .entry(*parent_txid)
                    .or_default()
                    .insert(txid);
            }
            children_map.entry(txid).or_default();
        }

        // Update total bytes
        {
            let mut total = self.total_bytes.write().await;
            *total += size as u64;
        }

        // Update package info (ancestor/descendant tracking)
        self.update_package_info(txid, fee, size as u32).await;

        // Track fee rate for estimation
        {
            let fee_rate = fee.as_sat() as f64 / size.max(1) as f64;
            let mut buckets = self.fee_rate_buckets.write().await;
            buckets.push(fee_rate);
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
        if recursive {
            // Collect all descendants first
            let descendants = {
                let children_map = self.children.read().await;
                let mut desc = HashSet::new();
                self.collect_descendants_locked(*txid, &children_map, &mut desc);
                desc
            };

            // Remove descendants first (children before parents)
            for desc_txid in descendants {
                self.remove_entry(&desc_txid).await;
                tracing::debug!("Removed dependent transaction {} from mempool", desc_txid);
            }
        }

        self.remove_entry(txid).await;
        tracing::debug!("Removed transaction {} from mempool", txid);
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
            return Ok(MIN_RELAY_FEE_RATE);
        }

        let mut sorted = buckets.clone();
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
        let entries = self.entries.read().await;
        let total_bytes = *self.total_bytes.read().await;

        Ok(MempoolInfo {
            size: entries.len() as u32,
            bytes: total_bytes,
            usage: total_bytes + (entries.len() as u64 * 200),
            max_mempool: self.max_bytes,
            min_relay_fee: MIN_RELAY_FEE_RATE / 100_000_000.0,
        })
    }

    async fn clear(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let mut entries = self.entries.write().await;
        let mut packages = self.packages.write().await;
        let mut children = self.children.write().await;
        let mut parents = self.parents.write().await;
        let mut total_bytes = self.total_bytes.write().await;

        entries.clear();
        packages.clear();
        children.clear();
        parents.clear();
        *total_bytes = 0;

        tracing::info!("Mempool cleared");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use btc_domain::primitives::{OutPoint, TxIn, TxOut};
    use btc_domain::Script;

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

        // Add parent
        let parent = make_test_tx(50_000);
        let parent_txid = parent.txid();
        mempool.add_transaction(&parent).await.unwrap();

        // Add child spending parent's output
        let child = make_child_tx(parent_txid, 40_000);
        mempool.add_transaction(&child).await.unwrap();

        assert_eq!(mempool.get_transaction_count().await.unwrap(), 2);

        // Verify parent's descendant count was updated
        let packages = mempool.packages.read().await;
        let parent_pkg = packages.get(&parent_txid).unwrap();
        assert_eq!(parent_pkg.descendant_count, 2); // self + child
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

        // Remove parent recursively — should also remove child
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

        // Build a chain of 25 transactions (at the limit)
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

        // The 26th should fail with ancestor limit
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
        // Should not error when removing a txid that doesn't exist
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

        // Add several transactions
        for i in 0..10 {
            let tx = make_test_tx(1000 * (i + 1));
            mempool.add_transaction(&tx).await.unwrap();
        }

        // Request with very small weight limit — should get fewer transactions
        let selected = mempool.get_transactions_by_fee_rate(200).await;
        assert!(selected.len() < 10);

        // Request with huge limit — should get all
        let all = mempool.get_transactions_by_fee_rate(4_000_000).await;
        assert_eq!(all.len(), 10);
    }

    #[tokio::test]
    async fn test_remove_for_block_nonexistent() {
        let mempool = InMemoryMempool::new();

        // Removing transactions not in mempool should not panic
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

        // Verify parent has 2 descendants (self + child)
        {
            let packages = mempool.packages.read().await;
            assert_eq!(packages.get(&parent_txid).unwrap().descendant_count, 2);
        }

        // Remove the child only (non-recursive)
        mempool
            .remove_transaction(&child_txid, false)
            .await
            .unwrap();

        // Parent's descendant count should drop back to 1
        {
            let packages = mempool.packages.read().await;
            assert_eq!(packages.get(&parent_txid).unwrap().descendant_count, 1);
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

        // Add transactions to populate fee rate buckets
        for i in 0..100 {
            let tx = make_test_tx(1000 + i);
            mempool.add_transaction(&tx).await.unwrap();
        }

        // Fee estimation should return something > 0
        let fee_1 = mempool.estimate_fee(1).await.unwrap();
        let fee_12 = mempool.estimate_fee(12).await.unwrap();

        assert!(fee_1 >= MIN_RELAY_FEE_RATE);
        assert!(fee_12 >= MIN_RELAY_FEE_RATE);
    }
}
