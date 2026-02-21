//! Peer Misbehavior & Ban Score Tracking
//!
//! Implements Bitcoin Core's peer scoring system (see `net_processing.cpp`
//! `Misbehaving()`). Every protocol violation adds to a peer's "ban score".
//! Once the score reaches or exceeds the ban threshold (default 100), the peer
//! is disconnected and its address is banned for a configurable duration.
//!
//! ## Violation Categories
//!
//! | Violation                          | Score |
//! |-----------------------------------|-------|
//! | Invalid block header              |  100  |
//! | Invalid block (consensus failure) |  100  |
//! | Invalid transaction               |   10  |
//! | Unexpected message during handshake|  10  |
//! | Too many addr messages            |   20  |
//! | Invalid network message           |   20  |
//! | DoS (too many messages, etc.)     |   50  |
//! | Unconnectable block               |   10  |

use std::collections::HashMap;
use std::net::SocketAddr;

// ── Configuration ───────────────────────────────────────────────────

/// Default ban score threshold — disconnect + ban when score >= this.
const DEFAULT_BAN_THRESHOLD: i32 = 100;

/// Default ban duration in seconds (24 hours).
const DEFAULT_BAN_DURATION: u64 = 24 * 60 * 60;

// ── Violation types ─────────────────────────────────────────────────

/// Categories of protocol violations with associated ban scores.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Misbehavior {
    /// Invalid block header (immediate ban).
    InvalidBlockHeader,
    /// Block fails consensus validation (immediate ban).
    InvalidBlock,
    /// Transaction fails validation.
    InvalidTransaction,
    /// Unexpected message during handshake.
    UnexpectedMessage,
    /// Flooding with addr messages.
    AddrFlood,
    /// Malformed or unrecognised network message.
    InvalidNetworkMessage,
    /// Generic DoS (rate-limit exceeded, etc.).
    DosAttack,
    /// Sent a block that doesn't connect to our chain.
    UnconnectableBlock,
    /// Peer sent a version message after handshake was already complete.
    DuplicateVersion,
    /// Custom score (for future extensions).
    Custom(i32),
}

impl Misbehavior {
    /// The ban score increment for this violation.
    pub fn score(&self) -> i32 {
        match self {
            Misbehavior::InvalidBlockHeader => 100,
            Misbehavior::InvalidBlock => 100,
            Misbehavior::InvalidTransaction => 10,
            Misbehavior::UnexpectedMessage => 10,
            Misbehavior::AddrFlood => 20,
            Misbehavior::InvalidNetworkMessage => 20,
            Misbehavior::DosAttack => 50,
            Misbehavior::UnconnectableBlock => 10,
            Misbehavior::DuplicateVersion => 10,
            Misbehavior::Custom(score) => *score,
        }
    }

    /// Human-readable reason string.
    pub fn reason(&self) -> &'static str {
        match self {
            Misbehavior::InvalidBlockHeader => "invalid block header",
            Misbehavior::InvalidBlock => "invalid block (consensus failure)",
            Misbehavior::InvalidTransaction => "invalid transaction",
            Misbehavior::UnexpectedMessage => "unexpected message during handshake",
            Misbehavior::AddrFlood => "addr message flood",
            Misbehavior::InvalidNetworkMessage => "invalid network message",
            Misbehavior::DosAttack => "DoS attack detected",
            Misbehavior::UnconnectableBlock => "unconnectable block",
            Misbehavior::DuplicateVersion => "duplicate version message",
            Misbehavior::Custom(_) => "custom violation",
        }
    }
}

impl std::fmt::Display for Misbehavior {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} (+{})", self.reason(), self.score())
    }
}

// ── Per-peer score tracking ─────────────────────────────────────────

/// Tracking state for a single peer.
#[derive(Debug, Clone)]
struct PeerScore {
    /// Accumulated ban score.
    score: i32,
    /// Network address (for banning).
    addr: SocketAddr,
    /// Log of violations with timestamps.
    violations: Vec<(Misbehavior, u64)>,
}

/// A banned address entry.
#[derive(Debug, Clone)]
pub struct BanEntry {
    /// The banned address.
    pub addr: SocketAddr,
    /// Timestamp when the ban was imposed (seconds since epoch).
    pub ban_time: u64,
    /// Duration of the ban in seconds.
    pub ban_duration: u64,
    /// The violation that triggered the ban.
    pub reason: String,
}

impl BanEntry {
    /// Whether this ban has expired at the given timestamp.
    pub fn is_expired(&self, now: u64) -> bool {
        now >= self.ban_time + self.ban_duration
    }
}

// ── The PeerScoring manager ─────────────────────────────────────────

/// Actions the caller should take after recording misbehavior.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScoreAction {
    /// No action needed — score is below threshold.
    None,
    /// Peer should be disconnected and banned.
    Ban {
        peer_id: u64,
        addr: SocketAddr,
        reason: String,
    },
}

/// Manages per-peer ban scores and a ban list.
///
/// Thread-safe usage: wrap in `Arc<RwLock<PeerScoring>>` if shared.
#[derive(Debug)]
pub struct PeerScoring {
    /// Per-peer scores, keyed by peer_id.
    peer_scores: HashMap<u64, PeerScore>,
    /// Banned addresses.
    ban_list: HashMap<SocketAddr, BanEntry>,
    /// Ban threshold (default: 100).
    ban_threshold: i32,
    /// Ban duration in seconds (default: 24h).
    ban_duration: u64,
}

impl PeerScoring {
    /// Create a new peer scoring manager with default settings.
    pub fn new() -> Self {
        PeerScoring {
            peer_scores: HashMap::new(),
            ban_list: HashMap::new(),
            ban_threshold: DEFAULT_BAN_THRESHOLD,
            ban_duration: DEFAULT_BAN_DURATION,
        }
    }

    /// Create with custom threshold and ban duration.
    pub fn with_config(ban_threshold: i32, ban_duration: u64) -> Self {
        PeerScoring {
            peer_scores: HashMap::new(),
            ban_list: HashMap::new(),
            ban_threshold,
            ban_duration,
        }
    }

    /// Register a new peer (call when peer connects).
    pub fn register_peer(&mut self, peer_id: u64, addr: SocketAddr) {
        self.peer_scores.insert(
            peer_id,
            PeerScore {
                score: 0,
                addr,
                violations: Vec::new(),
            },
        );
    }

    /// Remove a peer (call when peer disconnects).
    pub fn remove_peer(&mut self, peer_id: u64) {
        self.peer_scores.remove(&peer_id);
    }

    /// Record a misbehavior event for a peer.
    ///
    /// Returns an action the caller should take (either None or Ban).
    pub fn record_misbehavior(
        &mut self,
        peer_id: u64,
        violation: Misbehavior,
        now: u64,
    ) -> ScoreAction {
        let increment = violation.score();

        let peer = match self.peer_scores.get_mut(&peer_id) {
            Some(p) => p,
            None => return ScoreAction::None, // unknown peer — ignore
        };

        peer.score += increment;
        peer.violations.push((violation, now));

        tracing::debug!(
            "Peer {} misbehaving: {} (score now {})",
            peer_id,
            violation,
            peer.score
        );

        if peer.score >= self.ban_threshold {
            let addr = peer.addr;
            let reason = format!(
                "ban score {} >= {} (last: {})",
                peer.score, self.ban_threshold, violation.reason()
            );

            // Add to ban list.
            self.ban_list.insert(addr, BanEntry {
                addr,
                ban_time: now,
                ban_duration: self.ban_duration,
                reason: reason.clone(),
            });

            tracing::warn!(
                "Banning peer {} ({}): {}",
                peer_id,
                addr,
                reason
            );

            ScoreAction::Ban {
                peer_id,
                addr,
                reason,
            }
        } else {
            ScoreAction::None
        }
    }

    /// Check whether an address is currently banned.
    pub fn is_banned(&self, addr: &SocketAddr, now: u64) -> bool {
        match self.ban_list.get(addr) {
            Some(entry) => !entry.is_expired(now),
            None => false,
        }
    }

    /// Manually ban an address.
    pub fn ban_address(&mut self, addr: SocketAddr, reason: String, now: u64) {
        self.ban_list.insert(addr, BanEntry {
            addr,
            ban_time: now,
            ban_duration: self.ban_duration,
            reason,
        });
    }

    /// Manually unban an address.
    pub fn unban_address(&mut self, addr: &SocketAddr) -> bool {
        self.ban_list.remove(addr).is_some()
    }

    /// Remove expired bans.
    pub fn sweep_expired_bans(&mut self, now: u64) -> usize {
        let before = self.ban_list.len();
        self.ban_list.retain(|_, entry| !entry.is_expired(now));
        before - self.ban_list.len()
    }

    /// Get the current score for a peer.
    pub fn get_score(&self, peer_id: u64) -> i32 {
        self.peer_scores.get(&peer_id).map(|p| p.score).unwrap_or(0)
    }

    /// Get all currently banned addresses.
    pub fn list_bans(&self) -> Vec<&BanEntry> {
        self.ban_list.values().collect()
    }

    /// Number of tracked peers.
    pub fn peer_count(&self) -> usize {
        self.peer_scores.len()
    }

    /// Number of banned addresses.
    pub fn ban_count(&self) -> usize {
        self.ban_list.len()
    }
}

impl Default for PeerScoring {
    fn default() -> Self {
        Self::new()
    }
}

// ── Tests ───────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(port: u16) -> SocketAddr {
        format!("127.0.0.1:{}", port).parse().unwrap()
    }

    #[test]
    fn test_new_peer_score_zero() {
        let mut scoring = PeerScoring::new();
        scoring.register_peer(1, addr(8333));
        assert_eq!(scoring.get_score(1), 0);
    }

    #[test]
    fn test_record_misbehavior_below_threshold() {
        let mut scoring = PeerScoring::new();
        scoring.register_peer(1, addr(8333));

        let action = scoring.record_misbehavior(1, Misbehavior::InvalidTransaction, 1000);
        assert_eq!(action, ScoreAction::None);
        assert_eq!(scoring.get_score(1), 10);
    }

    #[test]
    fn test_record_misbehavior_triggers_ban() {
        let mut scoring = PeerScoring::new();
        scoring.register_peer(1, addr(8333));

        // InvalidBlock = 100, which meets the threshold immediately.
        let action = scoring.record_misbehavior(1, Misbehavior::InvalidBlock, 1000);
        match action {
            ScoreAction::Ban { peer_id, addr: a, .. } => {
                assert_eq!(peer_id, 1);
                assert_eq!(a, addr(8333));
            }
            ScoreAction::None => panic!("Expected ban"),
        }

        assert!(scoring.is_banned(&addr(8333), 1000));
    }

    #[test]
    fn test_cumulative_score_triggers_ban() {
        let mut scoring = PeerScoring::new();
        scoring.register_peer(1, addr(8333));

        // 10 invalid transactions × 10 = 100 → ban
        for i in 0..9 {
            let action = scoring.record_misbehavior(1, Misbehavior::InvalidTransaction, 1000 + i);
            assert_eq!(action, ScoreAction::None);
        }

        let action = scoring.record_misbehavior(1, Misbehavior::InvalidTransaction, 1009);
        assert!(matches!(action, ScoreAction::Ban { .. }));
        assert_eq!(scoring.get_score(1), 100);
    }

    #[test]
    fn test_ban_expires() {
        let mut scoring = PeerScoring::new();
        scoring.register_peer(1, addr(8333));

        scoring.record_misbehavior(1, Misbehavior::InvalidBlock, 1000);
        assert!(scoring.is_banned(&addr(8333), 1000));

        // Still banned 12 hours later.
        assert!(scoring.is_banned(&addr(8333), 1000 + 12 * 3600));

        // Expired after 24 hours.
        assert!(!scoring.is_banned(&addr(8333), 1000 + DEFAULT_BAN_DURATION));
    }

    #[test]
    fn test_sweep_expired_bans() {
        let mut scoring = PeerScoring::new();
        scoring.register_peer(1, addr(8333));
        scoring.register_peer(2, addr(8334));

        scoring.record_misbehavior(1, Misbehavior::InvalidBlock, 1000);
        scoring.record_misbehavior(2, Misbehavior::InvalidBlock, 2000);

        assert_eq!(scoring.ban_count(), 2);

        // Sweep at t=1000+24h — first ban expired, second still active.
        let swept = scoring.sweep_expired_bans(1000 + DEFAULT_BAN_DURATION);
        assert_eq!(swept, 1);
        assert_eq!(scoring.ban_count(), 1);
        assert!(!scoring.is_banned(&addr(8333), 1000 + DEFAULT_BAN_DURATION));
        assert!(scoring.is_banned(&addr(8334), 1000 + DEFAULT_BAN_DURATION));
    }

    #[test]
    fn test_manual_ban_unban() {
        let mut scoring = PeerScoring::new();

        scoring.ban_address(addr(9999), "manual ban".into(), 1000);
        assert!(scoring.is_banned(&addr(9999), 1000));

        let removed = scoring.unban_address(&addr(9999));
        assert!(removed);
        assert!(!scoring.is_banned(&addr(9999), 1000));
    }

    #[test]
    fn test_remove_peer() {
        let mut scoring = PeerScoring::new();
        scoring.register_peer(1, addr(8333));
        assert_eq!(scoring.peer_count(), 1);

        scoring.remove_peer(1);
        assert_eq!(scoring.peer_count(), 0);
        assert_eq!(scoring.get_score(1), 0); // unknown peer returns 0
    }

    #[test]
    fn test_unknown_peer_misbehavior_ignored() {
        let mut scoring = PeerScoring::new();
        let action = scoring.record_misbehavior(999, Misbehavior::InvalidBlock, 1000);
        assert_eq!(action, ScoreAction::None);
    }

    #[test]
    fn test_custom_threshold() {
        let mut scoring = PeerScoring::with_config(50, 3600);
        scoring.register_peer(1, addr(8333));

        // DosAttack = 50, meets the custom threshold of 50.
        let action = scoring.record_misbehavior(1, Misbehavior::DosAttack, 1000);
        assert!(matches!(action, ScoreAction::Ban { .. }));
    }

    #[test]
    fn test_misbehavior_scores() {
        assert_eq!(Misbehavior::InvalidBlockHeader.score(), 100);
        assert_eq!(Misbehavior::InvalidBlock.score(), 100);
        assert_eq!(Misbehavior::InvalidTransaction.score(), 10);
        assert_eq!(Misbehavior::UnexpectedMessage.score(), 10);
        assert_eq!(Misbehavior::AddrFlood.score(), 20);
        assert_eq!(Misbehavior::InvalidNetworkMessage.score(), 20);
        assert_eq!(Misbehavior::DosAttack.score(), 50);
        assert_eq!(Misbehavior::UnconnectableBlock.score(), 10);
        assert_eq!(Misbehavior::DuplicateVersion.score(), 10);
        assert_eq!(Misbehavior::Custom(42).score(), 42);
    }

    #[test]
    fn test_misbehavior_display() {
        let m = Misbehavior::InvalidTransaction;
        let s = format!("{}", m);
        assert!(s.contains("invalid transaction"));
        assert!(s.contains("+10"));
    }

    #[test]
    fn test_list_bans() {
        let mut scoring = PeerScoring::new();
        scoring.register_peer(1, addr(8333));
        scoring.register_peer(2, addr(8334));

        scoring.record_misbehavior(1, Misbehavior::InvalidBlock, 1000);
        scoring.record_misbehavior(2, Misbehavior::InvalidBlockHeader, 1000);

        let bans = scoring.list_bans();
        assert_eq!(bans.len(), 2);
    }
}
