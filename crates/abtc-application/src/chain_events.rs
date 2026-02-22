//! Chain Tip Notification Event Bus
//!
//! A lightweight publish/subscribe system for chain state changes. Components
//! can subscribe to events without direct coupling, following the hexagonal
//! architecture principle.
//!
//! ## Events
//!
//! - `BlockConnected` — a new block has been connected to the active chain
//! - `BlockDisconnected` — a block has been disconnected during a reorg
//! - `TransactionAddedToMempool` — a transaction was accepted into the mempool
//! - `TransactionRemovedFromMempool` — a transaction was removed from the mempool
//!
//! ## Usage
//!
//! ```ignore
//! let bus = ChainEventBus::new();
//! let mut rx = bus.subscribe();
//!
//! // In another task:
//! bus.emit(ChainEvent::BlockConnected { hash, height });
//!
//! // Subscriber receives:
//! while let Ok(event) = rx.recv().await { ... }
//! ```
//!
//! ## Design
//!
//! Uses `tokio::sync::broadcast` under the hood, which supports multiple
//! subscribers and is lock-free for sends. Slow subscribers that fall behind
//! will receive a `RecvError::Lagged` and can catch up.

use abtc_domain::primitives::{BlockHash, Txid};
use tokio::sync::broadcast;

// ── Configuration ───────────────────────────────────────────────────

/// Default channel capacity for the event bus.
const DEFAULT_CHANNEL_CAPACITY: usize = 256;

// ── Event types ─────────────────────────────────────────────────────

/// A chain state change event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChainEvent {
    /// A new block was connected to the active chain tip.
    BlockConnected {
        /// The block hash.
        hash: BlockHash,
        /// The height of the connected block.
        height: u32,
        /// Number of transactions in the block.
        num_txs: usize,
    },

    /// A block was disconnected from the active chain tip (reorg).
    BlockDisconnected {
        /// The block hash that was disconnected.
        hash: BlockHash,
        /// The height that was disconnected.
        height: u32,
    },

    /// A transaction was accepted into the mempool.
    TransactionAddedToMempool {
        /// The transaction id.
        txid: Txid,
        /// Virtual size in vbytes.
        vsize: u64,
        /// Fee in satoshis.
        fee: i64,
    },

    /// A transaction was removed from the mempool.
    TransactionRemovedFromMempool {
        /// The transaction id.
        txid: Txid,
        /// Reason for removal.
        reason: MempoolRemovalReason,
    },
}

/// Why a transaction was removed from the mempool.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MempoolRemovalReason {
    /// Included in a block.
    Block,
    /// Replaced by a higher-fee transaction (RBF).
    Replaced,
    /// Expired.
    Expiry,
    /// Evicted due to mempool size limits.
    SizeLimit,
    /// Conflicted with an in-block transaction.
    Conflict,
    /// Manually removed.
    Manual,
}

// ── Event Bus ───────────────────────────────────────────────────────

/// A broadcast-based event bus for chain state changes.
///
/// Multiple subscribers can listen for events without blocking the
/// publisher. The bus is cheap to clone (it shares the underlying
/// channel via `Arc`).
#[derive(Clone)]
pub struct ChainEventBus {
    sender: broadcast::Sender<ChainEvent>,
}

impl ChainEventBus {
    /// Create a new event bus with the default capacity.
    pub fn new() -> Self {
        Self::with_capacity(DEFAULT_CHANNEL_CAPACITY)
    }

    /// Create a new event bus with a custom capacity.
    pub fn with_capacity(capacity: usize) -> Self {
        let (sender, _) = broadcast::channel(capacity);
        ChainEventBus { sender }
    }

    /// Subscribe to chain events.
    ///
    /// Returns a `broadcast::Receiver` that will receive all events
    /// emitted after this call. If the receiver falls behind, it will
    /// get a `RecvError::Lagged` with the number of missed events.
    pub fn subscribe(&self) -> broadcast::Receiver<ChainEvent> {
        self.sender.subscribe()
    }

    /// Emit a chain event to all subscribers.
    ///
    /// Returns the number of active subscribers that received the event.
    /// Returns 0 if there are no subscribers (this is not an error).
    pub fn emit(&self, event: ChainEvent) -> usize {
        // broadcast::send returns Err only if there are no receivers,
        // which is fine — events are fire-and-forget.
        self.sender.send(event).unwrap_or(0)
    }

    /// Get the current number of active subscribers.
    pub fn subscriber_count(&self) -> usize {
        self.sender.receiver_count()
    }

    /// Convenience: emit a BlockConnected event.
    pub fn notify_block_connected(&self, hash: BlockHash, height: u32, num_txs: usize) -> usize {
        self.emit(ChainEvent::BlockConnected {
            hash,
            height,
            num_txs,
        })
    }

    /// Convenience: emit a BlockDisconnected event.
    pub fn notify_block_disconnected(&self, hash: BlockHash, height: u32) -> usize {
        self.emit(ChainEvent::BlockDisconnected { hash, height })
    }

    /// Convenience: emit a TransactionAddedToMempool event.
    pub fn notify_tx_added(&self, txid: Txid, vsize: u64, fee: i64) -> usize {
        self.emit(ChainEvent::TransactionAddedToMempool { txid, vsize, fee })
    }

    /// Convenience: emit a TransactionRemovedFromMempool event.
    pub fn notify_tx_removed(&self, txid: Txid, reason: MempoolRemovalReason) -> usize {
        self.emit(ChainEvent::TransactionRemovedFromMempool { txid, reason })
    }
}

impl Default for ChainEventBus {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use abtc_domain::primitives::Hash256;

    fn test_hash(byte: u8) -> BlockHash {
        BlockHash::from_hash(Hash256::from_bytes([byte; 32]))
    }

    fn test_txid(byte: u8) -> Txid {
        Txid::from_hash(Hash256::from_bytes([byte; 32]))
    }

    #[tokio::test]
    async fn test_emit_and_receive() {
        let bus = ChainEventBus::new();
        let mut rx = bus.subscribe();

        let hash = test_hash(0x01);
        bus.notify_block_connected(hash, 100, 5);

        let event = rx.recv().await.unwrap();
        assert_eq!(
            event,
            ChainEvent::BlockConnected {
                hash,
                height: 100,
                num_txs: 5,
            }
        );
    }

    #[tokio::test]
    async fn test_multiple_subscribers() {
        let bus = ChainEventBus::new();
        let mut rx1 = bus.subscribe();
        let mut rx2 = bus.subscribe();

        assert_eq!(bus.subscriber_count(), 2);

        let hash = test_hash(0x02);
        let count = bus.notify_block_connected(hash, 200, 10);
        assert_eq!(count, 2);

        let e1 = rx1.recv().await.unwrap();
        let e2 = rx2.recv().await.unwrap();
        assert_eq!(e1, e2);
    }

    #[tokio::test]
    async fn test_no_subscribers() {
        let bus = ChainEventBus::new();
        // No subscribers — emit should return 0
        let count = bus.notify_block_connected(test_hash(0x03), 300, 1);
        assert_eq!(count, 0);
    }

    #[tokio::test]
    async fn test_block_disconnected() {
        let bus = ChainEventBus::new();
        let mut rx = bus.subscribe();

        let hash = test_hash(0x04);
        bus.notify_block_disconnected(hash, 50);

        let event = rx.recv().await.unwrap();
        assert_eq!(event, ChainEvent::BlockDisconnected { hash, height: 50 });
    }

    #[tokio::test]
    async fn test_tx_events() {
        let bus = ChainEventBus::new();
        let mut rx = bus.subscribe();

        let txid = test_txid(0x05);
        bus.notify_tx_added(txid, 250, 5000);

        let event = rx.recv().await.unwrap();
        assert_eq!(
            event,
            ChainEvent::TransactionAddedToMempool {
                txid,
                vsize: 250,
                fee: 5000,
            }
        );

        bus.notify_tx_removed(txid, MempoolRemovalReason::Block);

        let event = rx.recv().await.unwrap();
        assert_eq!(
            event,
            ChainEvent::TransactionRemovedFromMempool {
                txid,
                reason: MempoolRemovalReason::Block,
            }
        );
    }

    #[tokio::test]
    async fn test_multiple_events_in_order() {
        let bus = ChainEventBus::new();
        let mut rx = bus.subscribe();

        let h1 = test_hash(0x10);
        let h2 = test_hash(0x11);
        let h3 = test_hash(0x12);

        bus.notify_block_connected(h1, 1, 1);
        bus.notify_block_connected(h2, 2, 2);
        bus.notify_block_connected(h3, 3, 3);

        // Events should arrive in order
        let e1 = rx.recv().await.unwrap();
        let e2 = rx.recv().await.unwrap();
        let e3 = rx.recv().await.unwrap();

        match (&e1, &e2, &e3) {
            (
                ChainEvent::BlockConnected { height: 1, .. },
                ChainEvent::BlockConnected { height: 2, .. },
                ChainEvent::BlockConnected { height: 3, .. },
            ) => {} // correct
            _ => panic!("Events out of order: {:?}, {:?}, {:?}", e1, e2, e3),
        }
    }

    #[tokio::test]
    async fn test_subscriber_dropped() {
        let bus = ChainEventBus::new();
        let rx = bus.subscribe();
        assert_eq!(bus.subscriber_count(), 1);

        drop(rx);
        assert_eq!(bus.subscriber_count(), 0);
    }

    #[test]
    fn test_clone_bus() {
        let bus = ChainEventBus::new();
        let bus2 = bus.clone();

        let mut rx = bus.subscribe();
        // Emit from the clone
        bus2.notify_block_connected(test_hash(0x20), 42, 7);

        // Should be receivable from the original's subscriber
        let event = rx.try_recv().unwrap();
        assert_eq!(
            event,
            ChainEvent::BlockConnected {
                hash: test_hash(0x20),
                height: 42,
                num_txs: 7,
            }
        );
    }

    #[test]
    fn test_removal_reasons() {
        // Ensure all variants are distinct
        let reasons = [
            MempoolRemovalReason::Block,
            MempoolRemovalReason::Replaced,
            MempoolRemovalReason::Expiry,
            MempoolRemovalReason::SizeLimit,
            MempoolRemovalReason::Conflict,
            MempoolRemovalReason::Manual,
        ];
        for i in 0..reasons.len() {
            for j in (i + 1)..reasons.len() {
                assert_ne!(reasons[i], reasons[j]);
            }
        }
    }
}
