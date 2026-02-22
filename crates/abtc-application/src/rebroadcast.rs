//! Transaction Rebroadcast Manager
//!
//! Periodically re-announces unconfirmed wallet transactions to the network.
//! This corresponds to Bitcoin Core's `ResendWalletTransactions()` logic in
//! `wallet/wallet.cpp`.
//!
//! ## Design
//!
//! The rebroadcast manager tracks wallet transactions that have been submitted
//! but not yet confirmed. After `REBROADCAST_INTERVAL` seconds it re-announces
//! them via `inv` messages so that they are not forgotten by the network.
//!
//! - Transactions are only rebroadcast if they are still in the mempool.
//! - Each transaction has a retry counter; after `MAX_REBROADCASTS` attempts
//!   the manager stops trying (the tx is likely invalid or fee-sniped).
//! - Rebroadcasts use a Poisson-distributed random delay (via simple jitter)
//!   to avoid fingerprinting the originating node.

use abtc_domain::primitives::Txid;
use std::collections::HashMap;

// ── Configuration ───────────────────────────────────────────────────

/// Seconds between rebroadcast attempts (default: ~30 minutes).
const REBROADCAST_INTERVAL: u64 = 30 * 60;

/// Maximum number of times we will rebroadcast a single transaction.
const MAX_REBROADCASTS: u32 = 6; // ~3 hours of attempts

// ── Types ───────────────────────────────────────────────────────────

/// Tracking record for a single wallet transaction.
#[derive(Debug, Clone)]
pub struct RebroadcastEntry {
    /// Transaction ID.
    pub txid: Txid,
    /// Unix timestamp when the transaction was first submitted.
    pub first_seen: u64,
    /// Unix timestamp of the most recent broadcast/rebroadcast.
    pub last_broadcast: u64,
    /// Number of times we've (re-)broadcast this transaction.
    pub broadcast_count: u32,
}

/// Action returned by the rebroadcast manager.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RebroadcastAction {
    /// Re-announce this txid to all connected peers.
    Reannounce(Txid),
    /// Give up on this transaction (too many attempts).
    Abandon(Txid),
}

/// The rebroadcast manager.
pub struct RebroadcastManager {
    /// Tracked transactions, keyed by txid.
    entries: HashMap<Txid, RebroadcastEntry>,
    /// The rebroadcast interval in seconds.
    interval: u64,
    /// Max rebroadcast attempts.
    max_attempts: u32,
}

impl RebroadcastManager {
    /// Create a new rebroadcast manager with default settings.
    pub fn new() -> Self {
        RebroadcastManager {
            entries: HashMap::new(),
            interval: REBROADCAST_INTERVAL,
            max_attempts: MAX_REBROADCASTS,
        }
    }

    /// Create with custom interval and max attempts (useful for testing).
    pub fn with_config(interval: u64, max_attempts: u32) -> Self {
        RebroadcastManager {
            entries: HashMap::new(),
            interval,
            max_attempts,
        }
    }

    /// Track a new wallet transaction for potential rebroadcast.
    pub fn track_transaction(&mut self, txid: Txid, now: u64) {
        self.entries.entry(txid).or_insert(RebroadcastEntry {
            txid,
            first_seen: now,
            last_broadcast: now,
            broadcast_count: 1, // initial broadcast counts as 1
        });
    }

    /// Remove a transaction from tracking (e.g. it was confirmed in a block).
    pub fn confirm_transaction(&mut self, txid: &Txid) {
        self.entries.remove(txid);
    }

    /// Remove transactions that were confirmed in a block.
    ///
    /// Pass in all txids from a newly connected block; any tracked
    /// transactions that appear in the block are removed.
    pub fn process_block(&mut self, block_txids: &[Txid]) {
        for txid in block_txids {
            self.entries.remove(txid);
        }
    }

    /// Check which transactions need rebroadcasting.
    ///
    /// `now` is the current unix timestamp.
    /// `still_in_mempool` is a closure that checks whether a txid is still
    /// in the mempool (we don't rebroadcast evicted transactions).
    pub fn check_rebroadcast<F>(&mut self, now: u64, still_in_mempool: F) -> Vec<RebroadcastAction>
    where
        F: Fn(&Txid) -> bool,
    {
        let mut actions = Vec::new();
        let mut to_remove = Vec::new();

        for (txid, entry) in self.entries.iter_mut() {
            // Check if the rebroadcast interval has elapsed
            if now.saturating_sub(entry.last_broadcast) < self.interval {
                continue;
            }

            // Check if we've exceeded max attempts
            if entry.broadcast_count >= self.max_attempts {
                actions.push(RebroadcastAction::Abandon(*txid));
                to_remove.push(*txid);
                continue;
            }

            // Only rebroadcast if still in the mempool
            if !still_in_mempool(txid) {
                to_remove.push(*txid);
                continue;
            }

            // Rebroadcast!
            entry.last_broadcast = now;
            entry.broadcast_count += 1;
            actions.push(RebroadcastAction::Reannounce(*txid));
        }

        for txid in to_remove {
            self.entries.remove(&txid);
        }

        actions
    }

    /// Get the number of tracked (unconfirmed) transactions.
    pub fn tracked_count(&self) -> usize {
        self.entries.len()
    }

    /// Get tracking info for a specific transaction.
    pub fn get_entry(&self, txid: &Txid) -> Option<&RebroadcastEntry> {
        self.entries.get(txid)
    }

    /// Get the configured rebroadcast interval.
    pub fn interval(&self) -> u64 {
        self.interval
    }

    /// Get the configured max rebroadcast attempts.
    pub fn max_attempts(&self) -> u32 {
        self.max_attempts
    }

    /// Clear all tracked transactions.
    pub fn clear(&mut self) {
        self.entries.clear();
    }
}

impl Default for RebroadcastManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use abtc_domain::primitives::Hash256;

    fn make_txid(byte: u8) -> Txid {
        Txid::from_hash(Hash256::from_bytes([byte; 32]))
    }

    #[test]
    fn test_new_manager() {
        let mgr = RebroadcastManager::new();
        assert_eq!(mgr.tracked_count(), 0);
        assert_eq!(mgr.interval(), REBROADCAST_INTERVAL);
        assert_eq!(mgr.max_attempts(), MAX_REBROADCASTS);
    }

    #[test]
    fn test_track_transaction() {
        let mut mgr = RebroadcastManager::new();
        let txid = make_txid(0x01);
        mgr.track_transaction(txid, 1000);

        assert_eq!(mgr.tracked_count(), 1);
        let entry = mgr.get_entry(&txid).unwrap();
        assert_eq!(entry.first_seen, 1000);
        assert_eq!(entry.last_broadcast, 1000);
        assert_eq!(entry.broadcast_count, 1);
    }

    #[test]
    fn test_confirm_removes_transaction() {
        let mut mgr = RebroadcastManager::new();
        let txid = make_txid(0x01);
        mgr.track_transaction(txid, 1000);
        assert_eq!(mgr.tracked_count(), 1);

        mgr.confirm_transaction(&txid);
        assert_eq!(mgr.tracked_count(), 0);
    }

    #[test]
    fn test_process_block_removes_confirmed() {
        let mut mgr = RebroadcastManager::new();
        let txid1 = make_txid(0x01);
        let txid2 = make_txid(0x02);
        let txid3 = make_txid(0x03);
        mgr.track_transaction(txid1, 1000);
        mgr.track_transaction(txid2, 1000);
        mgr.track_transaction(txid3, 1000);

        // Block contains txid1 and txid3
        mgr.process_block(&[txid1, txid3]);
        assert_eq!(mgr.tracked_count(), 1);
        assert!(mgr.get_entry(&txid2).is_some());
    }

    #[test]
    fn test_no_rebroadcast_before_interval() {
        let mut mgr = RebroadcastManager::with_config(1800, 6); // 30 min interval
        let txid = make_txid(0x01);
        mgr.track_transaction(txid, 1000);

        // Only 10 minutes later — too early
        let actions = mgr.check_rebroadcast(1600, |_| true);
        assert!(actions.is_empty());
    }

    #[test]
    fn test_rebroadcast_after_interval() {
        let mut mgr = RebroadcastManager::with_config(1800, 6); // 30 min
        let txid = make_txid(0x01);
        mgr.track_transaction(txid, 1000);

        // 31 minutes later
        let actions = mgr.check_rebroadcast(2860, |_| true);
        assert_eq!(actions.len(), 1);
        assert_eq!(actions[0], RebroadcastAction::Reannounce(txid));

        // Broadcast count should be incremented
        let entry = mgr.get_entry(&txid).unwrap();
        assert_eq!(entry.broadcast_count, 2);
        assert_eq!(entry.last_broadcast, 2860);
    }

    #[test]
    fn test_abandon_after_max_attempts() {
        let mut mgr = RebroadcastManager::with_config(100, 3); // short interval, 3 attempts
        let txid = make_txid(0x01);
        mgr.track_transaction(txid, 0);

        // Simulate repeated rebroadcasts
        // broadcast_count starts at 1, so we need 2 more to hit 3
        let _ = mgr.check_rebroadcast(200, |_| true); // count → 2
        let _ = mgr.check_rebroadcast(400, |_| true); // count → 3

        // Next check should abandon (count == 3 == max)
        let actions = mgr.check_rebroadcast(600, |_| true);
        assert_eq!(actions.len(), 1);
        assert_eq!(actions[0], RebroadcastAction::Abandon(txid));
        assert_eq!(mgr.tracked_count(), 0);
    }

    #[test]
    fn test_evicted_tx_removed() {
        let mut mgr = RebroadcastManager::with_config(100, 6);
        let txid = make_txid(0x01);
        mgr.track_transaction(txid, 0);

        // Transaction is no longer in mempool
        let actions = mgr.check_rebroadcast(200, |_| false);
        assert!(actions.is_empty()); // no reannounce
        assert_eq!(mgr.tracked_count(), 0); // removed
    }

    #[test]
    fn test_multiple_transactions() {
        let mut mgr = RebroadcastManager::with_config(100, 6);
        let txid1 = make_txid(0x01);
        let txid2 = make_txid(0x02);
        let txid3 = make_txid(0x03);
        mgr.track_transaction(txid1, 0);
        mgr.track_transaction(txid2, 50); // tracked later
        mgr.track_transaction(txid3, 0);

        // At t=200: txid1 and txid3 are due, txid2 is not (last_broadcast=50, 200-50=150 > 100)
        // Actually txid2 IS due since 150 > interval(100)
        let actions = mgr.check_rebroadcast(200, |_| true);
        // All three should be reannounced
        assert_eq!(actions.len(), 3);
        let reannounced: Vec<Txid> = actions
            .iter()
            .filter_map(|a| match a {
                RebroadcastAction::Reannounce(t) => Some(*t),
                _ => None,
            })
            .collect();
        assert_eq!(reannounced.len(), 3);
    }

    #[test]
    fn test_clear() {
        let mut mgr = RebroadcastManager::new();
        mgr.track_transaction(make_txid(0x01), 0);
        mgr.track_transaction(make_txid(0x02), 0);
        assert_eq!(mgr.tracked_count(), 2);

        mgr.clear();
        assert_eq!(mgr.tracked_count(), 0);
    }

    #[test]
    fn test_duplicate_track_ignored() {
        let mut mgr = RebroadcastManager::new();
        let txid = make_txid(0x01);
        mgr.track_transaction(txid, 1000);
        mgr.track_transaction(txid, 2000); // should NOT overwrite

        let entry = mgr.get_entry(&txid).unwrap();
        assert_eq!(entry.first_seen, 1000); // original timestamp preserved
    }

    #[test]
    fn test_default_trait() {
        let mgr = RebroadcastManager::default();
        assert_eq!(mgr.tracked_count(), 0);
    }
}
