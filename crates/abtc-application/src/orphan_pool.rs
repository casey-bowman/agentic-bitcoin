//! Orphan Transaction Pool
//!
//! Holds transactions whose parent inputs are not yet available (missing from
//! both the UTXO set and the mempool). When a parent transaction arrives and
//! is accepted, orphans that depend on it are re-evaluated.
//!
//! This corresponds to Bitcoin Core's `mapOrphanTransactions` /
//! `OrphanageAddTx` logic in `txorphanage.cpp`.
//!
//! ## Design
//!
//! - Orphans are keyed by txid for O(1) lookup and removal.
//! - A reverse index (`by_prev`) maps each missing parent outpoint to the set
//!   of orphan txids that need it. This allows efficient re-evaluation when a
//!   new transaction confirms.
//! - Each orphan has an expiry timestamp; `expire_old_orphans()` prunes stale
//!   entries that have lingered too long.
//! - A hard cap (`MAX_ORPHAN_TRANSACTIONS`) prevents memory exhaustion from
//!   flooding attacks. When full, a random existing orphan is evicted.

use abtc_domain::primitives::{OutPoint, Transaction, Txid};
use std::collections::{HashMap, HashSet};

// ── Configuration ───────────────────────────────────────────────────

/// Maximum number of orphan transactions we will hold.
const MAX_ORPHAN_TRANSACTIONS: usize = 100;

/// How long (in seconds) an orphan may linger before expiry.
const ORPHAN_TX_EXPIRE_TIME: u64 = 20 * 60; // 20 minutes

/// Maximum size (in bytes) of a single orphan transaction we accept.
const MAX_ORPHAN_TX_SIZE: usize = 100_000; // 100 KB

// ── Types ───────────────────────────────────────────────────────────

/// An orphan transaction and its metadata.
#[derive(Debug, Clone)]
pub struct OrphanEntry {
    /// The transaction itself.
    pub tx: Transaction,
    /// Unix timestamp when this orphan was added.
    pub time_added: u64,
    /// The peer that sent us this orphan (for eviction priority).
    pub from_peer: u64,
    /// Serialized size of the transaction.
    pub size: usize,
}

/// Result of attempting to add an orphan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AddOrphanResult {
    /// Successfully added as a new orphan.
    Added,
    /// Already in the orphan pool.
    AlreadyExists,
    /// Rejected: transaction too large.
    TooLarge,
    /// Rejected: pool is full and eviction occurred; orphan was added.
    AddedAfterEviction { evicted: Txid },
}

/// The orphan transaction pool.
pub struct OrphanPool {
    /// Orphan transactions keyed by txid.
    orphans: HashMap<Txid, OrphanEntry>,
    /// Reverse index: for each outpoint, which orphan txids need it.
    by_prev: HashMap<OutPoint, HashSet<Txid>>,
    /// Maximum number of orphans to hold.
    max_orphans: usize,
    /// Expiry time in seconds.
    expire_time: u64,
}

impl OrphanPool {
    /// Create a new orphan pool with default settings.
    pub fn new() -> Self {
        OrphanPool {
            orphans: HashMap::new(),
            by_prev: HashMap::new(),
            max_orphans: MAX_ORPHAN_TRANSACTIONS,
            expire_time: ORPHAN_TX_EXPIRE_TIME,
        }
    }

    /// Create with custom limits (useful for testing).
    pub fn with_config(max_orphans: usize, expire_time: u64) -> Self {
        OrphanPool {
            orphans: HashMap::new(),
            by_prev: HashMap::new(),
            max_orphans,
            expire_time,
        }
    }

    /// Add a transaction to the orphan pool.
    ///
    /// Returns the result of the add operation.
    pub fn add_orphan(&mut self, tx: Transaction, from_peer: u64, now: u64) -> AddOrphanResult {
        let txid = tx.txid();

        // Already known?
        if self.orphans.contains_key(&txid) {
            return AddOrphanResult::AlreadyExists;
        }

        // Size check
        let size = tx.serialize().len();
        if size > MAX_ORPHAN_TX_SIZE {
            return AddOrphanResult::TooLarge;
        }

        // Evict if at capacity
        let evicted = if self.orphans.len() >= self.max_orphans {
            let victim = self.evict_random();
            victim
        } else {
            None
        };

        // Build reverse index entries for all inputs
        for input in &tx.inputs {
            self.by_prev
                .entry(input.previous_output)
                .or_default()
                .insert(txid);
        }

        self.orphans.insert(
            txid,
            OrphanEntry {
                tx,
                time_added: now,
                from_peer,
                size,
            },
        );

        match evicted {
            Some(evicted_txid) => AddOrphanResult::AddedAfterEviction {
                evicted: evicted_txid,
            },
            None => AddOrphanResult::Added,
        }
    }

    /// Remove an orphan by txid. Returns the entry if it was present.
    pub fn remove_orphan(&mut self, txid: &Txid) -> Option<OrphanEntry> {
        if let Some(entry) = self.orphans.remove(txid) {
            // Clean up reverse index
            for input in &entry.tx.inputs {
                if let Some(set) = self.by_prev.get_mut(&input.previous_output) {
                    set.remove(txid);
                    if set.is_empty() {
                        self.by_prev.remove(&input.previous_output);
                    }
                }
            }
            Some(entry)
        } else {
            None
        }
    }

    /// Get all orphan txids that depend on a given outpoint.
    ///
    /// Call this when a new transaction is accepted to find orphans
    /// that can now be re-evaluated.
    pub fn get_orphans_by_prev(&self, outpoint: &OutPoint) -> Vec<Txid> {
        self.by_prev
            .get(outpoint)
            .map(|set| set.iter().copied().collect())
            .unwrap_or_default()
    }

    /// Get all orphan txids that depend on any output of a given transaction.
    ///
    /// This is the common pattern: when tx `parent_txid` is accepted, find
    /// all orphans that spent one of its outputs.
    pub fn get_children_of(&self, parent_txid: &Txid, output_count: u32) -> Vec<Txid> {
        let mut children = HashSet::new();
        for vout in 0..output_count {
            let outpoint = OutPoint::new(*parent_txid, vout);
            if let Some(set) = self.by_prev.get(&outpoint) {
                children.extend(set.iter().copied());
            }
        }
        children.into_iter().collect()
    }

    /// Remove all orphans that are older than the expiry time.
    ///
    /// Returns the number of orphans removed.
    pub fn expire_old_orphans(&mut self, now: u64) -> usize {
        let expired: Vec<Txid> = self
            .orphans
            .iter()
            .filter(|(_, entry)| now.saturating_sub(entry.time_added) > self.expire_time)
            .map(|(txid, _)| *txid)
            .collect();

        let count = expired.len();
        for txid in expired {
            self.remove_orphan(&txid);
        }
        count
    }

    /// Remove all orphans from a specific peer.
    ///
    /// Useful when a peer is banned or disconnected.
    pub fn remove_for_peer(&mut self, peer_id: u64) -> usize {
        let to_remove: Vec<Txid> = self
            .orphans
            .iter()
            .filter(|(_, entry)| entry.from_peer == peer_id)
            .map(|(txid, _)| *txid)
            .collect();

        let count = to_remove.len();
        for txid in to_remove {
            self.remove_orphan(&txid);
        }
        count
    }

    /// Get an orphan entry by txid.
    pub fn get(&self, txid: &Txid) -> Option<&OrphanEntry> {
        self.orphans.get(txid)
    }

    /// Check if we have an orphan with the given txid.
    pub fn contains(&self, txid: &Txid) -> bool {
        self.orphans.contains_key(txid)
    }

    /// Get the number of orphan transactions in the pool.
    pub fn len(&self) -> usize {
        self.orphans.len()
    }

    /// Check if the pool is empty.
    pub fn is_empty(&self) -> bool {
        self.orphans.is_empty()
    }

    /// Clear all orphans.
    pub fn clear(&mut self) {
        self.orphans.clear();
        self.by_prev.clear();
    }

    /// Evict a random orphan (deterministic: pick the first by iteration order).
    ///
    /// In a real implementation this would use a random selection to prevent
    /// targeted eviction attacks. For simplicity we pick the oldest by time_added.
    fn evict_random(&mut self) -> Option<Txid> {
        let oldest = self
            .orphans
            .iter()
            .min_by_key(|(_, entry)| entry.time_added)
            .map(|(txid, _)| *txid);

        if let Some(txid) = oldest {
            self.remove_orphan(&txid);
            Some(txid)
        } else {
            None
        }
    }
}

impl Default for OrphanPool {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use abtc_domain::primitives::{Amount, Hash256, OutPoint, TxIn, TxOut};
    use abtc_domain::script::Script;

    fn make_tx(prev_txid: Txid, prev_vout: u32, value: i64) -> Transaction {
        Transaction::v1(
            vec![TxIn::final_input(
                OutPoint::new(prev_txid, prev_vout),
                Script::new(),
            )],
            vec![TxOut::new(Amount::from_sat(value), Script::new())],
            0,
        )
    }

    fn make_txid(byte: u8) -> Txid {
        Txid::from_hash(Hash256::from_bytes([byte; 32]))
    }

    #[test]
    fn test_add_orphan() {
        let mut pool = OrphanPool::new();
        let parent_txid = make_txid(0x01);
        let tx = make_tx(parent_txid, 0, 5000);
        let txid = tx.txid();

        let result = pool.add_orphan(tx, 1, 1000);
        assert_eq!(result, AddOrphanResult::Added);
        assert_eq!(pool.len(), 1);
        assert!(pool.contains(&txid));
    }

    #[test]
    fn test_add_duplicate() {
        let mut pool = OrphanPool::new();
        let parent_txid = make_txid(0x01);
        let tx = make_tx(parent_txid, 0, 5000);

        pool.add_orphan(tx.clone(), 1, 1000);
        let result = pool.add_orphan(tx, 1, 1001);
        assert_eq!(result, AddOrphanResult::AlreadyExists);
        assert_eq!(pool.len(), 1);
    }

    #[test]
    fn test_remove_orphan() {
        let mut pool = OrphanPool::new();
        let parent_txid = make_txid(0x01);
        let tx = make_tx(parent_txid, 0, 5000);
        let txid = tx.txid();

        pool.add_orphan(tx, 1, 1000);
        let removed = pool.remove_orphan(&txid);
        assert!(removed.is_some());
        assert_eq!(pool.len(), 0);
        assert!(!pool.contains(&txid));
    }

    #[test]
    fn test_get_orphans_by_prev() {
        let mut pool = OrphanPool::new();
        let parent_txid = make_txid(0x01);

        // Two orphans that both spend different outputs of the same parent
        let tx1 = make_tx(parent_txid, 0, 3000);
        let tx2 = make_tx(parent_txid, 1, 2000);
        let txid1 = tx1.txid();
        let txid2 = tx2.txid();

        pool.add_orphan(tx1, 1, 1000);
        pool.add_orphan(tx2, 1, 1000);

        let children1 = pool.get_orphans_by_prev(&OutPoint::new(parent_txid, 0));
        assert_eq!(children1.len(), 1);
        assert_eq!(children1[0], txid1);

        let children2 = pool.get_orphans_by_prev(&OutPoint::new(parent_txid, 1));
        assert_eq!(children2.len(), 1);
        assert_eq!(children2[0], txid2);
    }

    #[test]
    fn test_get_children_of() {
        let mut pool = OrphanPool::new();
        let parent_txid = make_txid(0x01);

        let tx1 = make_tx(parent_txid, 0, 3000);
        let tx2 = make_tx(parent_txid, 1, 2000);

        pool.add_orphan(tx1, 1, 1000);
        pool.add_orphan(tx2, 1, 1000);

        let children = pool.get_children_of(&parent_txid, 2);
        assert_eq!(children.len(), 2);
    }

    #[test]
    fn test_expire_old_orphans() {
        let mut pool = OrphanPool::with_config(100, 600); // 10 min expiry
        let tx1 = make_tx(make_txid(0x01), 0, 3000);
        let tx2 = make_tx(make_txid(0x02), 0, 2000);

        pool.add_orphan(tx1, 1, 1000);
        pool.add_orphan(tx2, 1, 1500);

        // At t=1500 neither is expired (within 600s)
        let removed = pool.expire_old_orphans(1500);
        assert_eq!(removed, 0);
        assert_eq!(pool.len(), 2);

        // At t=1700 tx1 is expired (1700 - 1000 = 700 > 600) but tx2 is not (200 < 600)
        let removed = pool.expire_old_orphans(1700);
        assert_eq!(removed, 1);
        assert_eq!(pool.len(), 1);
    }

    #[test]
    fn test_eviction_when_full() {
        let mut pool = OrphanPool::with_config(3, 600);

        let tx1 = make_tx(make_txid(0x01), 0, 1000);
        let tx2 = make_tx(make_txid(0x02), 0, 2000);
        let tx3 = make_tx(make_txid(0x03), 0, 3000);
        let tx4 = make_tx(make_txid(0x04), 0, 4000);

        pool.add_orphan(tx1, 1, 100);
        pool.add_orphan(tx2, 1, 200);
        pool.add_orphan(tx3, 1, 300);
        assert_eq!(pool.len(), 3);

        // Adding a 4th should evict the oldest (tx1 at time 100)
        let result = pool.add_orphan(tx4, 1, 400);
        match result {
            AddOrphanResult::AddedAfterEviction { .. } => {}
            _ => panic!("Expected AddedAfterEviction"),
        }
        assert_eq!(pool.len(), 3); // Still at max
    }

    #[test]
    fn test_remove_for_peer() {
        let mut pool = OrphanPool::new();
        let tx1 = make_tx(make_txid(0x01), 0, 1000);
        let tx2 = make_tx(make_txid(0x02), 0, 2000);
        let tx3 = make_tx(make_txid(0x03), 0, 3000);

        pool.add_orphan(tx1, 1, 100); // peer 1
        pool.add_orphan(tx2, 2, 200); // peer 2
        pool.add_orphan(tx3, 1, 300); // peer 1

        let removed = pool.remove_for_peer(1);
        assert_eq!(removed, 2);
        assert_eq!(pool.len(), 1);
    }

    #[test]
    fn test_clear() {
        let mut pool = OrphanPool::new();
        pool.add_orphan(make_tx(make_txid(0x01), 0, 1000), 1, 100);
        pool.add_orphan(make_tx(make_txid(0x02), 0, 2000), 1, 200);
        assert_eq!(pool.len(), 2);

        pool.clear();
        assert_eq!(pool.len(), 0);
        assert!(pool.is_empty());
    }

    #[test]
    fn test_reverse_index_cleanup() {
        let mut pool = OrphanPool::new();
        let parent_txid = make_txid(0x01);
        let tx = make_tx(parent_txid, 0, 5000);
        let txid = tx.txid();

        pool.add_orphan(tx, 1, 1000);
        assert!(!pool
            .get_orphans_by_prev(&OutPoint::new(parent_txid, 0))
            .is_empty());

        let _ = pool.remove_orphan(&txid);
        assert!(pool
            .get_orphans_by_prev(&OutPoint::new(parent_txid, 0))
            .is_empty());
    }

    #[test]
    fn test_default_trait() {
        let pool = OrphanPool::default();
        assert_eq!(pool.len(), 0);
    }
}
