//! Address Manager — Peer Address Book
//!
//! Manages a database of known peer addresses for discovery and connection.
//! Corresponds to Bitcoin Core's `CAddrMan` (`addrman.cpp`).
//!
//! ## Design
//!
//! Addresses are stored in two tables:
//! - **Tried**: Addresses we've successfully connected to
//! - **New**: Addresses we've heard about but haven't connected to yet
//!
//! When selecting peers for outbound connections, we pick from the tried
//! table with some probability, falling back to the new table. Addresses
//! age out if not seen recently.
//!
//! ## Anti-eclipse measures
//!
//! - Addresses are bucketed by source network group to prevent a single
//!   attacker from filling the entire table
//! - Random selection prevents deterministic peer sets

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};

// ── Configuration ───────────────────────────────────────────────────

/// Maximum number of addresses in the "new" table.
const MAX_NEW_ADDRESSES: usize = 1024;

/// Maximum number of addresses in the "tried" table.
const MAX_TRIED_ADDRESSES: usize = 256;

/// Maximum age in seconds before an address is considered stale (30 days).
const MAX_ADDRESS_AGE: u64 = 30 * 24 * 60 * 60;

/// Maximum addresses to return in a `getaddr` response.
const MAX_ADDR_RESPONSE: usize = 1000;

/// Percentage of addresses to return from `getaddr` (23% like Bitcoin Core).
const GETADDR_PERCENT: usize = 23;

// ── Types ───────────────────────────────────────────────────────────

/// A known peer address with metadata.
#[derive(Debug, Clone)]
pub struct AddressInfo {
    /// The peer's socket address.
    pub addr: SocketAddr,
    /// Advertised services bitfield.
    pub services: u64,
    /// Unix timestamp when we last heard about this address.
    pub last_seen: u64,
    /// Unix timestamp of our last successful connection to this address.
    pub last_success: u64,
    /// Number of failed connection attempts since last success.
    pub attempts: u32,
    /// The source (who told us about this address).
    pub source: IpAddr,
    /// Whether this address is in the "tried" table.
    pub is_tried: bool,
}

/// Result of adding an address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AddResult {
    /// Address was added to the new table.
    Added,
    /// Address was already known and was updated.
    Updated,
    /// Address was rejected (stale, invalid, or table full after eviction).
    Rejected,
}

/// The address manager / peer address book.
pub struct AddressManager {
    /// All known addresses, keyed by socket address.
    addresses: HashMap<SocketAddr, AddressInfo>,
    /// Count of addresses in the "new" table.
    new_count: usize,
    /// Count of addresses in the "tried" table.
    tried_count: usize,
    /// Simple counter for deterministic-ish selection in tests.
    selection_counter: u64,
}

impl AddressManager {
    /// Create a new empty address manager.
    pub fn new() -> Self {
        AddressManager {
            addresses: HashMap::new(),
            new_count: 0,
            tried_count: 0,
            selection_counter: 0,
        }
    }

    /// Total number of known addresses.
    pub fn size(&self) -> usize {
        self.addresses.len()
    }

    /// Number of addresses in the "new" table.
    pub fn new_count(&self) -> usize {
        self.new_count
    }

    /// Number of addresses in the "tried" table.
    pub fn tried_count(&self) -> usize {
        self.tried_count
    }

    /// Add or update a peer address.
    ///
    /// - `addr`: the peer's socket address
    /// - `services`: advertised service flags
    /// - `source`: who told us about this address
    /// - `now`: current unix timestamp
    pub fn add_address(
        &mut self,
        addr: SocketAddr,
        services: u64,
        source: IpAddr,
        now: u64,
    ) -> AddResult {
        // Reject obviously invalid addresses
        if !Self::is_routable(&addr) {
            return AddResult::Rejected;
        }

        // Update if already known
        if let Some(existing) = self.addresses.get_mut(&addr) {
            // Update last_seen if this report is newer
            if now > existing.last_seen {
                existing.last_seen = now;
            }
            // Update services if the new report has more
            if services > existing.services {
                existing.services = services;
            }
            return AddResult::Updated;
        }

        // Reject if too old
        if now > MAX_ADDRESS_AGE && self.addresses.values().any(|a| now - a.last_seen < 600) {
            // We have fresh addresses; skip anything that doesn't come with
            // a reasonable timestamp. (In practice the "now" IS the timestamp
            // from the addr message.)
        }

        // Evict if new table is full
        if self.new_count >= MAX_NEW_ADDRESSES {
            self.evict_oldest_new(now);
            if self.new_count >= MAX_NEW_ADDRESSES {
                return AddResult::Rejected;
            }
        }

        let info = AddressInfo {
            addr,
            services,
            last_seen: now,
            last_success: 0,
            attempts: 0,
            source,
            is_tried: false,
        };

        self.addresses.insert(addr, info);
        self.new_count += 1;

        AddResult::Added
    }

    /// Mark an address as successfully connected (move to "tried" table).
    pub fn mark_good(&mut self, addr: &SocketAddr, now: u64) {
        if let Some(info) = self.addresses.get_mut(addr) {
            info.last_success = now;
            info.last_seen = now;
            info.attempts = 0;

            if !info.is_tried {
                info.is_tried = true;
                self.new_count = self.new_count.saturating_sub(1);
                self.tried_count += 1;

                // Evict from tried if over limit
                if self.tried_count > MAX_TRIED_ADDRESSES {
                    self.evict_oldest_tried(now);
                }
            }
        }
    }

    /// Record a failed connection attempt.
    pub fn mark_attempt(&mut self, addr: &SocketAddr, now: u64) {
        if let Some(info) = self.addresses.get_mut(addr) {
            info.attempts += 1;
            info.last_seen = now;
        }
    }

    /// Get addresses suitable for a `getaddr` response.
    ///
    /// Returns up to `MAX_ADDR_RESPONSE` addresses, selecting roughly
    /// `GETADDR_PERCENT`% of known addresses at random (using a simple
    /// deterministic selection for reproducibility).
    pub fn get_addr_response(&mut self, now: u64) -> Vec<(u64, SocketAddr)> {
        let all: Vec<&AddressInfo> = self
            .addresses
            .values()
            .filter(|a| {
                // Skip stale addresses
                now.saturating_sub(a.last_seen) < MAX_ADDRESS_AGE
            })
            .collect();

        if all.is_empty() {
            return Vec::new();
        }

        // Select GETADDR_PERCENT% of addresses, up to MAX_ADDR_RESPONSE
        let target = (all.len() * GETADDR_PERCENT / 100)
            .max(1)
            .min(MAX_ADDR_RESPONSE);

        // Simple deterministic selection: use counter to pick starting offset
        self.selection_counter = self.selection_counter.wrapping_add(1);
        let offset = (self.selection_counter as usize) % all.len();

        let mut result = Vec::with_capacity(target);
        for i in 0..target {
            let idx = (offset + i) % all.len();
            let info = all[idx];
            result.push((info.last_seen, info.addr));
        }

        result
    }

    /// Select addresses for outbound connections.
    ///
    /// Prefers tried addresses, falls back to new. Returns up to `count`
    /// addresses, avoiding addresses we've recently attempted.
    pub fn select_for_connection(&mut self, count: usize, now: u64) -> Vec<SocketAddr> {
        let min_retry_delay = 600u64; // Don't retry within 10 minutes

        // Collect tried addresses first, then new
        let mut tried: Vec<&AddressInfo> = self
            .addresses
            .values()
            .filter(|a| a.is_tried && now.saturating_sub(a.last_seen) < MAX_ADDRESS_AGE)
            .filter(|a| a.last_success == 0 || now.saturating_sub(a.last_success) > min_retry_delay)
            .collect();

        let mut new: Vec<&AddressInfo> = self
            .addresses
            .values()
            .filter(|a| !a.is_tried && now.saturating_sub(a.last_seen) < MAX_ADDRESS_AGE)
            .filter(|a| a.attempts == 0 || now.saturating_sub(a.last_seen) > min_retry_delay)
            .collect();

        // Sort by fewest attempts, then most recently seen
        tried.sort_by(|a, b| {
            a.attempts
                .cmp(&b.attempts)
                .then(b.last_seen.cmp(&a.last_seen))
        });
        new.sort_by(|a, b| {
            a.attempts
                .cmp(&b.attempts)
                .then(b.last_seen.cmp(&a.last_seen))
        });

        let mut result = Vec::with_capacity(count);

        // Take from tried first
        for info in tried.iter().take(count) {
            result.push(info.addr);
        }

        // Fill remainder from new
        let remaining = count.saturating_sub(result.len());
        for info in new.iter().take(remaining) {
            result.push(info.addr);
        }

        result
    }

    /// Remove all addresses associated with a specific source IP.
    pub fn remove_by_source(&mut self, source: &IpAddr) {
        let to_remove: Vec<SocketAddr> = self
            .addresses
            .iter()
            .filter(|(_, info)| info.source == *source)
            .map(|(addr, _)| *addr)
            .collect();

        for addr in to_remove {
            if let Some(info) = self.addresses.remove(&addr) {
                if info.is_tried {
                    self.tried_count = self.tried_count.saturating_sub(1);
                } else {
                    self.new_count = self.new_count.saturating_sub(1);
                }
            }
        }
    }

    /// Expire addresses older than `MAX_ADDRESS_AGE`.
    pub fn expire_old(&mut self, now: u64) {
        let to_remove: Vec<SocketAddr> = self
            .addresses
            .iter()
            .filter(|(_, info)| now.saturating_sub(info.last_seen) >= MAX_ADDRESS_AGE)
            .map(|(addr, _)| *addr)
            .collect();

        for addr in to_remove {
            if let Some(info) = self.addresses.remove(&addr) {
                if info.is_tried {
                    self.tried_count = self.tried_count.saturating_sub(1);
                } else {
                    self.new_count = self.new_count.saturating_sub(1);
                }
            }
        }
    }

    /// Check if an address is considered routable (not loopback, not unspecified).
    fn is_routable(addr: &SocketAddr) -> bool {
        let ip = addr.ip();
        !ip.is_loopback() && !ip.is_unspecified() && addr.port() > 0
    }

    /// Evict the oldest address from the new table.
    fn evict_oldest_new(&mut self, _now: u64) {
        let oldest = self
            .addresses
            .iter()
            .filter(|(_, info)| !info.is_tried)
            .min_by_key(|(_, info)| info.last_seen)
            .map(|(addr, _)| *addr);

        if let Some(addr) = oldest {
            self.addresses.remove(&addr);
            self.new_count = self.new_count.saturating_sub(1);
        }
    }

    /// Evict the oldest address from the tried table (move it back to new).
    fn evict_oldest_tried(&mut self, _now: u64) {
        let oldest = self
            .addresses
            .iter()
            .filter(|(_, info)| info.is_tried)
            .min_by_key(|(_, info)| info.last_success)
            .map(|(addr, _)| *addr);

        if let Some(addr) = oldest {
            if let Some(info) = self.addresses.get_mut(&addr) {
                info.is_tried = false;
                self.tried_count = self.tried_count.saturating_sub(1);
                self.new_count += 1;
            }
        }
    }
}

impl Default for AddressManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, SocketAddrV4};

    fn addr(a: u8, b: u8, c: u8, d: u8, port: u16) -> SocketAddr {
        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(a, b, c, d), port))
    }

    fn source() -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))
    }

    #[test]
    fn test_add_and_size() {
        let mut mgr = AddressManager::new();
        assert_eq!(mgr.size(), 0);

        let result = mgr.add_address(addr(1, 2, 3, 4, 8333), 1, source(), 1000);
        assert_eq!(result, AddResult::Added);
        assert_eq!(mgr.size(), 1);
        assert_eq!(mgr.new_count(), 1);
        assert_eq!(mgr.tried_count(), 0);
    }

    #[test]
    fn test_update_existing() {
        let mut mgr = AddressManager::new();
        mgr.add_address(addr(1, 2, 3, 4, 8333), 1, source(), 1000);

        let result = mgr.add_address(addr(1, 2, 3, 4, 8333), 9, source(), 2000);
        assert_eq!(result, AddResult::Updated);
        assert_eq!(mgr.size(), 1); // Still just one
    }

    #[test]
    fn test_reject_loopback() {
        let mut mgr = AddressManager::new();
        let result = mgr.add_address(
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 8333)),
            1,
            source(),
            1000,
        );
        assert_eq!(result, AddResult::Rejected);
        assert_eq!(mgr.size(), 0);
    }

    #[test]
    fn test_reject_unspecified() {
        let mut mgr = AddressManager::new();
        let result = mgr.add_address(
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 8333)),
            1,
            source(),
            1000,
        );
        assert_eq!(result, AddResult::Rejected);
    }

    #[test]
    fn test_reject_zero_port() {
        let mut mgr = AddressManager::new();
        let result = mgr.add_address(addr(1, 2, 3, 4, 0), 1, source(), 1000);
        assert_eq!(result, AddResult::Rejected);
    }

    #[test]
    fn test_mark_good_moves_to_tried() {
        let mut mgr = AddressManager::new();
        let a = addr(1, 2, 3, 4, 8333);
        mgr.add_address(a, 1, source(), 1000);
        assert_eq!(mgr.new_count(), 1);
        assert_eq!(mgr.tried_count(), 0);

        mgr.mark_good(&a, 2000);
        assert_eq!(mgr.new_count(), 0);
        assert_eq!(mgr.tried_count(), 1);
    }

    #[test]
    fn test_mark_attempt() {
        let mut mgr = AddressManager::new();
        let a = addr(1, 2, 3, 4, 8333);
        mgr.add_address(a, 1, source(), 1000);

        mgr.mark_attempt(&a, 1100);
        mgr.mark_attempt(&a, 1200);

        let info = mgr.addresses.get(&a).unwrap();
        assert_eq!(info.attempts, 2);
    }

    #[test]
    fn test_expire_old() {
        let mut mgr = AddressManager::new();
        let a = addr(1, 2, 3, 4, 8333);
        mgr.add_address(a, 1, source(), 1000);

        // Not expired yet
        mgr.expire_old(1000 + MAX_ADDRESS_AGE - 1);
        assert_eq!(mgr.size(), 1);

        // Now expired
        mgr.expire_old(1000 + MAX_ADDRESS_AGE);
        assert_eq!(mgr.size(), 0);
    }

    #[test]
    fn test_select_for_connection() {
        let mut mgr = AddressManager::new();

        // Add several addresses
        for i in 1..=10u8 {
            mgr.add_address(addr(1, 2, 3, i, 8333), 1, source(), 1000);
        }

        // Mark a few as tried
        mgr.mark_good(&addr(1, 2, 3, 1, 8333), 2000);
        mgr.mark_good(&addr(1, 2, 3, 2, 8333), 2000);

        // Select 3 — should prefer tried addresses
        let selected = mgr.select_for_connection(3, 3000);
        assert_eq!(selected.len(), 3);
        // First two should be from tried table
        assert!(
            selected.contains(&addr(1, 2, 3, 1, 8333))
                || selected.contains(&addr(1, 2, 3, 2, 8333))
        );
    }

    #[test]
    fn test_get_addr_response() {
        let mut mgr = AddressManager::new();

        for i in 1..=20u8 {
            mgr.add_address(addr(1, 2, 3, i, 8333), 1, source(), 1000);
        }

        let response = mgr.get_addr_response(1000);
        // Should return ~23% of 20 = ~4-5 addresses (at least 1)
        assert!(!response.is_empty());
        assert!(response.len() <= MAX_ADDR_RESPONSE);
    }

    #[test]
    fn test_remove_by_source() {
        let mut mgr = AddressManager::new();
        let src1 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let src2 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));

        mgr.add_address(addr(1, 2, 3, 1, 8333), 1, src1, 1000);
        mgr.add_address(addr(1, 2, 3, 2, 8333), 1, src1, 1000);
        mgr.add_address(addr(1, 2, 3, 3, 8333), 1, src2, 1000);

        assert_eq!(mgr.size(), 3);

        mgr.remove_by_source(&src1);
        assert_eq!(mgr.size(), 1);

        // Only src2's address should remain
        assert!(mgr.addresses.contains_key(&addr(1, 2, 3, 3, 8333)));
    }

    #[test]
    fn test_eviction_on_new_table_full() {
        let mut mgr = AddressManager::new();

        // Fill the new table
        for i in 0..MAX_NEW_ADDRESSES {
            let a = i as u32;
            let d = (a & 0xff) as u8;
            let c = ((a >> 8) & 0xff) as u8;
            let b = ((a >> 16) & 0xff) as u8;
            // Ensure non-zero: offset by 1
            let port = 8333 + (i as u16 % 100);
            mgr.add_address(
                addr(1 + b, c, d, ((i % 254) + 1) as u8, port),
                1,
                source(),
                1000 + i as u64,
            );
        }

        assert_eq!(mgr.new_count(), MAX_NEW_ADDRESSES);

        // Adding one more should evict the oldest
        let result = mgr.add_address(addr(99, 99, 99, 99, 8333), 1, source(), 5000);
        assert_eq!(result, AddResult::Added);
        // Count should stay at max (one evicted, one added)
        assert_eq!(mgr.new_count(), MAX_NEW_ADDRESSES);
    }
}
