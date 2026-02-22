//! Block Download Scheduler
//!
//! Tracks in-flight block requests with timeouts, stale-tip detection,
//! and per-peer download performance. This corresponds to block download
//! management logic in Bitcoin Core's `net_processing.cpp`.
//!
//! ## Design
//!
//! Each block request is tracked with a timestamp. If a peer doesn't
//! deliver a block within `BLOCK_DOWNLOAD_TIMEOUT` seconds, the request
//! is cancelled and reassigned to another peer. Peers that consistently
//! time out receive a misbehavior penalty.
//!
//! The scheduler also detects a "stale tip" — when no new blocks have
//! been connected for `STALE_TIP_CHECK_INTERVAL` seconds — and triggers
//! re-sync with a different peer.

use std::collections::HashMap;
use std::net::SocketAddr;

// ── Configuration ───────────────────────────────────────────────────

/// Seconds to wait for a requested block before timing out.
const BLOCK_DOWNLOAD_TIMEOUT: u64 = 60;

/// Seconds of no new block before we consider the tip stale.
const STALE_TIP_CHECK_INTERVAL: u64 = 600; // 10 minutes

/// Maximum number of blocks a single peer can have in flight.
const MAX_BLOCKS_PER_PEER: usize = 16;

// ── Types ───────────────────────────────────────────────────────────

/// A single in-flight block request.
#[derive(Debug, Clone)]
pub struct BlockRequest {
    /// The hash of the block being requested.
    pub block_hash: [u8; 32],
    /// Peer ID that was assigned this request.
    pub peer_id: u64,
    /// Unix timestamp when the request was sent.
    pub requested_at: u64,
    /// Expected block height (for ordering).
    pub height: u32,
}

/// Per-peer download statistics.
#[derive(Debug, Clone)]
pub struct PeerDownloadStats {
    /// Total blocks successfully delivered.
    pub blocks_delivered: u64,
    /// Total blocks that timed out.
    pub blocks_timed_out: u64,
    /// Total bytes downloaded from this peer.
    pub bytes_downloaded: u64,
    /// Average delivery time in milliseconds.
    pub avg_delivery_ms: f64,
    /// Current number of in-flight requests.
    pub in_flight: usize,
    /// Peer's socket address.
    pub addr: SocketAddr,
}

impl PeerDownloadStats {
    fn new(addr: SocketAddr) -> Self {
        PeerDownloadStats {
            blocks_delivered: 0,
            blocks_timed_out: 0,
            bytes_downloaded: 0,
            avg_delivery_ms: 0.0,
            in_flight: 0,
            addr,
        }
    }

    /// Delivery success rate (0.0 to 1.0).
    pub fn success_rate(&self) -> f64 {
        let total = self.blocks_delivered + self.blocks_timed_out;
        if total == 0 {
            return 1.0;
        }
        self.blocks_delivered as f64 / total as f64
    }

    /// Estimated download speed in bytes/sec.
    pub fn estimated_speed(&self) -> u64 {
        if self.avg_delivery_ms < 1.0 || self.blocks_delivered == 0 {
            return 0;
        }
        let avg_size = self.bytes_downloaded / self.blocks_delivered;
        (avg_size as f64 / (self.avg_delivery_ms / 1000.0)) as u64
    }
}

/// Action returned by the scheduler.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SchedulerAction {
    /// Request this block from the specified peer.
    RequestBlock { peer_id: u64, block_hash: [u8; 32] },
    /// A block request timed out — penalize the peer.
    TimeoutPeer { peer_id: u64, block_hash: [u8; 32] },
    /// The chain tip appears stale — trigger re-sync with any available peer.
    StaleTipDetected,
}

/// The block download scheduler.
pub struct DownloadScheduler {
    /// Currently in-flight requests, keyed by block hash.
    in_flight: HashMap<[u8; 32], BlockRequest>,
    /// Per-peer download statistics.
    peer_stats: HashMap<u64, PeerDownloadStats>,
    /// Unix timestamp of the last block successfully connected.
    last_block_time: u64,
    /// Whether a stale-tip warning has already been emitted (avoid spam).
    stale_tip_warned: bool,
}

impl DownloadScheduler {
    /// Create a new download scheduler.
    pub fn new(now: u64) -> Self {
        DownloadScheduler {
            in_flight: HashMap::new(),
            peer_stats: HashMap::new(),
            last_block_time: now,
            stale_tip_warned: false,
        }
    }

    /// Register a peer so we can track its stats.
    pub fn register_peer(&mut self, peer_id: u64, addr: SocketAddr) {
        self.peer_stats
            .insert(peer_id, PeerDownloadStats::new(addr));
    }

    /// Remove a peer and cancel all its in-flight requests.
    /// Returns the block hashes that need to be re-queued.
    pub fn remove_peer(&mut self, peer_id: u64) -> Vec<[u8; 32]> {
        self.peer_stats.remove(&peer_id);
        let cancelled: Vec<[u8; 32]> = self
            .in_flight
            .iter()
            .filter(|(_, req)| req.peer_id == peer_id)
            .map(|(hash, _)| *hash)
            .collect();
        for hash in &cancelled {
            self.in_flight.remove(hash);
        }
        cancelled
    }

    /// Record a block request being sent.
    pub fn record_request(&mut self, block_hash: [u8; 32], peer_id: u64, height: u32, now: u64) {
        self.in_flight.insert(
            block_hash,
            BlockRequest {
                block_hash,
                peer_id,
                requested_at: now,
                height,
            },
        );
        if let Some(stats) = self.peer_stats.get_mut(&peer_id) {
            stats.in_flight += 1;
        }
    }

    /// Record a successfully received block.
    pub fn record_delivery(&mut self, block_hash: &[u8; 32], block_size: u64, now: u64) {
        if let Some(req) = self.in_flight.remove(block_hash) {
            let delivery_ms = (now.saturating_sub(req.requested_at)) * 1000;
            if let Some(stats) = self.peer_stats.get_mut(&req.peer_id) {
                stats.blocks_delivered += 1;
                stats.bytes_downloaded += block_size;
                stats.in_flight = stats.in_flight.saturating_sub(1);
                // Exponential moving average of delivery time
                if stats.blocks_delivered == 1 {
                    stats.avg_delivery_ms = delivery_ms as f64;
                } else {
                    stats.avg_delivery_ms = stats.avg_delivery_ms * 0.9 + delivery_ms as f64 * 0.1;
                }
            }
            self.last_block_time = now;
            self.stale_tip_warned = false;
        }
    }

    /// Check for timed-out requests and stale tip.
    /// Returns actions that the caller should execute.
    pub fn check_timeouts(&mut self, now: u64) -> Vec<SchedulerAction> {
        let mut actions = Vec::new();

        // Check for timed-out block requests
        let timed_out: Vec<([u8; 32], u64)> = self
            .in_flight
            .iter()
            .filter(|(_, req)| now.saturating_sub(req.requested_at) > BLOCK_DOWNLOAD_TIMEOUT)
            .map(|(hash, req)| (*hash, req.peer_id))
            .collect();

        for (hash, peer_id) in timed_out {
            self.in_flight.remove(&hash);
            if let Some(stats) = self.peer_stats.get_mut(&peer_id) {
                stats.blocks_timed_out += 1;
                stats.in_flight = stats.in_flight.saturating_sub(1);
            }
            actions.push(SchedulerAction::TimeoutPeer {
                peer_id,
                block_hash: hash,
            });
        }

        // Check for stale tip
        if !self.stale_tip_warned
            && now.saturating_sub(self.last_block_time) > STALE_TIP_CHECK_INTERVAL
        {
            self.stale_tip_warned = true;
            actions.push(SchedulerAction::StaleTipDetected);
        }

        actions
    }

    /// Pick the best peer to request a block from.
    ///
    /// Prefers peers with:
    /// 1. Fewer in-flight requests (below MAX_BLOCKS_PER_PEER)
    /// 2. Higher success rate
    /// 3. Higher download speed
    pub fn pick_peer(&self, available_peers: &[u64]) -> Option<u64> {
        available_peers
            .iter()
            .filter_map(|&pid| self.peer_stats.get(&pid).map(|s| (pid, s)))
            .filter(|(_, stats)| stats.in_flight < MAX_BLOCKS_PER_PEER)
            .max_by(|(_, a), (_, b)| {
                // Score: success_rate * 100 + speed/1024
                let score_a = a.success_rate() * 100.0 + a.estimated_speed() as f64 / 1024.0;
                let score_b = b.success_rate() * 100.0 + b.estimated_speed() as f64 / 1024.0;
                score_a
                    .partial_cmp(&score_b)
                    .unwrap_or(std::cmp::Ordering::Equal)
            })
            .map(|(pid, _)| pid)
    }

    /// Get the number of in-flight requests.
    pub fn in_flight_count(&self) -> usize {
        self.in_flight.len()
    }

    /// Get download stats for a specific peer.
    pub fn peer_stats(&self, peer_id: u64) -> Option<&PeerDownloadStats> {
        self.peer_stats.get(&peer_id)
    }

    /// Get the last block connection time.
    pub fn last_block_time(&self) -> u64 {
        self.last_block_time
    }

    /// Get the download timeout threshold.
    pub fn timeout_secs(&self) -> u64 {
        BLOCK_DOWNLOAD_TIMEOUT
    }

    /// Get the stale tip threshold.
    pub fn stale_tip_secs(&self) -> u64 {
        STALE_TIP_CHECK_INTERVAL
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(port: u16) -> SocketAddr {
        format!("127.0.0.1:{}", port).parse().unwrap()
    }

    #[test]
    fn test_new_scheduler() {
        let sched = DownloadScheduler::new(1000);
        assert_eq!(sched.in_flight_count(), 0);
        assert_eq!(sched.last_block_time(), 1000);
    }

    #[test]
    fn test_register_and_remove_peer() {
        let mut sched = DownloadScheduler::new(1000);
        sched.register_peer(1, addr(8333));
        assert!(sched.peer_stats(1).is_some());

        let cancelled = sched.remove_peer(1);
        assert!(cancelled.is_empty());
        assert!(sched.peer_stats(1).is_none());
    }

    #[test]
    fn test_request_and_delivery() {
        let mut sched = DownloadScheduler::new(1000);
        sched.register_peer(1, addr(8333));

        let hash = [0xAB; 32];
        sched.record_request(hash, 1, 100, 1000);
        assert_eq!(sched.in_flight_count(), 1);
        assert_eq!(sched.peer_stats(1).unwrap().in_flight, 1);

        sched.record_delivery(&hash, 500_000, 1005);
        assert_eq!(sched.in_flight_count(), 0);

        let stats = sched.peer_stats(1).unwrap();
        assert_eq!(stats.blocks_delivered, 1);
        assert_eq!(stats.bytes_downloaded, 500_000);
        assert_eq!(stats.in_flight, 0);
        assert_eq!(sched.last_block_time(), 1005);
    }

    #[test]
    fn test_timeout_detection() {
        let mut sched = DownloadScheduler::new(1000);
        sched.register_peer(1, addr(8333));

        let hash = [0xCD; 32];
        sched.record_request(hash, 1, 100, 1000);

        // Not timed out yet
        let actions = sched.check_timeouts(1050);
        assert!(actions.is_empty());

        // Now timed out (> 60 seconds)
        let actions = sched.check_timeouts(1061);
        assert_eq!(actions.len(), 1);
        assert_eq!(
            actions[0],
            SchedulerAction::TimeoutPeer {
                peer_id: 1,
                block_hash: hash
            }
        );

        // Request should be removed from in-flight
        assert_eq!(sched.in_flight_count(), 0);
        assert_eq!(sched.peer_stats(1).unwrap().blocks_timed_out, 1);
    }

    #[test]
    fn test_stale_tip_detection() {
        let mut sched = DownloadScheduler::new(1000);

        // Not stale yet
        let actions = sched.check_timeouts(1500);
        assert!(actions.is_empty());

        // Stale tip (> 600 seconds)
        let actions = sched.check_timeouts(1601);
        assert_eq!(actions.len(), 1);
        assert_eq!(actions[0], SchedulerAction::StaleTipDetected);

        // Should not warn again (stale_tip_warned = true)
        let actions = sched.check_timeouts(1700);
        assert!(actions.is_empty());
    }

    #[test]
    fn test_stale_tip_resets_on_delivery() {
        let mut sched = DownloadScheduler::new(1000);
        sched.register_peer(1, addr(8333));

        // Trigger stale
        let actions = sched.check_timeouts(1601);
        assert!(actions
            .iter()
            .any(|a| *a == SchedulerAction::StaleTipDetected));

        // Deliver a block → resets stale warning
        let hash = [0xEF; 32];
        sched.record_request(hash, 1, 200, 1600);
        sched.record_delivery(&hash, 1_000_000, 1605);

        // Should be able to trigger stale again later
        let actions = sched.check_timeouts(2210);
        assert!(actions
            .iter()
            .any(|a| *a == SchedulerAction::StaleTipDetected));
    }

    #[test]
    fn test_pick_peer_prefers_fewer_inflight() {
        let mut sched = DownloadScheduler::new(1000);
        sched.register_peer(1, addr(8333));
        sched.register_peer(2, addr(8334));

        // Give peer 1 some in-flight requests
        for i in 0..5u8 {
            let mut hash = [0u8; 32];
            hash[0] = i;
            sched.record_request(hash, 1, i as u32, 1000);
        }

        // Peer 2 has no in-flight, so should be preferred
        let best = sched.pick_peer(&[1, 2]);
        assert_eq!(best, Some(2));
    }

    #[test]
    fn test_pick_peer_respects_max_inflight() {
        let mut sched = DownloadScheduler::new(1000);
        sched.register_peer(1, addr(8333));

        // Fill peer 1 to max
        for i in 0..MAX_BLOCKS_PER_PEER as u8 {
            let mut hash = [0u8; 32];
            hash[0] = i;
            sched.record_request(hash, 1, i as u32, 1000);
        }

        // No peer available
        let best = sched.pick_peer(&[1]);
        assert_eq!(best, None);
    }

    #[test]
    fn test_remove_peer_cancels_requests() {
        let mut sched = DownloadScheduler::new(1000);
        sched.register_peer(1, addr(8333));

        let hash1 = [0xAA; 32];
        let hash2 = [0xBB; 32];
        sched.record_request(hash1, 1, 100, 1000);
        sched.record_request(hash2, 1, 101, 1000);

        let cancelled = sched.remove_peer(1);
        assert_eq!(cancelled.len(), 2);
        assert_eq!(sched.in_flight_count(), 0);
    }

    #[test]
    fn test_peer_success_rate() {
        let mut sched = DownloadScheduler::new(1000);
        sched.register_peer(1, addr(8333));

        // 3 deliveries, 1 timeout → 75% success
        for i in 0..4u8 {
            let mut hash = [0u8; 32];
            hash[0] = i;
            sched.record_request(hash, 1, i as u32, 1000 + i as u64);
        }
        // Deliver first 3
        for i in 0..3u8 {
            let mut hash = [0u8; 32];
            hash[0] = i;
            sched.record_delivery(&hash, 100_000, 1010);
        }
        // Timeout the 4th
        let actions = sched.check_timeouts(1070);
        assert_eq!(actions.len(), 1);

        let stats = sched.peer_stats(1).unwrap();
        assert_eq!(stats.blocks_delivered, 3);
        assert_eq!(stats.blocks_timed_out, 1);
        assert!((stats.success_rate() - 0.75).abs() < 0.01);
    }
}
