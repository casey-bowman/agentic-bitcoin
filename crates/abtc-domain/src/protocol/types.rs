//! P2P protocol types
//!
//! Service flags, inventory types, network addresses, and protocol constants
//! used across the Bitcoin P2P wire protocol.

use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};

// ---------------------------------------------------------------------------
// Protocol constants
// ---------------------------------------------------------------------------

/// Current protocol version we advertise (BIP339 wtxidrelay support)
pub const PROTOCOL_VERSION: u32 = 70016;

/// Minimum protocol version we accept from peers
pub const MIN_PEER_PROTO_VERSION: u32 = 31800;

/// Version at which headers-first sync was introduced
pub const HEADERS_VERSION: u32 = 31800;

/// Version at which compact blocks (BIP152) was introduced
pub const SHORT_IDS_BLOCKS_VERSION: u32 = 70014;

/// Version at which fee filter (BIP133) was introduced
pub const FEEFILTER_VERSION: u32 = 70013;

/// Version at which sendheaders (BIP130) was introduced
pub const SENDHEADERS_VERSION: u32 = 70012;

/// Version at which wtxidrelay (BIP339) was introduced
pub const WTXID_RELAY_VERSION: u32 = 70016;

/// Maximum size of a protocol message payload (4 MB for segwit blocks)
pub const MAX_PROTOCOL_MESSAGE_LENGTH: u32 = 4_000_000;

/// Maximum number of headers in a headers message
pub const MAX_HEADERS: usize = 2000;

/// Maximum number of inventory items in an inv/getdata message
pub const MAX_INV_SIZE: usize = 50_000;

/// Maximum number of entries in an addr message
pub const MAX_ADDR_TO_SEND: usize = 1000;

/// Maximum number of entries in a locator
pub const MAX_LOCATOR_SIZE: usize = 101;

/// User agent string
pub const USER_AGENT: &str = "/AgenticBitcoin:0.1.0/";

// ---------------------------------------------------------------------------
// Service flags (BIP111, BIP144, BIP159)
// ---------------------------------------------------------------------------

/// Bitmask of services offered by a node.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ServiceFlags(u64);

impl ServiceFlags {
    /// Nothing
    pub const NONE: ServiceFlags = ServiceFlags(0);
    /// NODE_NETWORK: can serve full blocks
    pub const NETWORK: ServiceFlags = ServiceFlags(1 << 0);
    /// NODE_GETUTXO: can answer UTXO queries (BIP64)
    pub const GETUTXO: ServiceFlags = ServiceFlags(1 << 1);
    /// NODE_BLOOM: supports bloom filtering (BIP111)
    pub const BLOOM: ServiceFlags = ServiceFlags(1 << 2);
    /// NODE_WITNESS: supports segregated witness (BIP144)
    pub const WITNESS: ServiceFlags = ServiceFlags(1 << 3);
    /// NODE_COMPACT_FILTERS: serves compact block filters (BIP157)
    pub const COMPACT_FILTERS: ServiceFlags = ServiceFlags(1 << 6);
    /// NODE_NETWORK_LIMITED: can serve last 288 blocks (BIP159)
    pub const NETWORK_LIMITED: ServiceFlags = ServiceFlags(1 << 10);

    /// Create from raw u64 value
    pub const fn from_u64(value: u64) -> Self {
        ServiceFlags(value)
    }

    /// Get raw u64 value
    pub const fn as_u64(self) -> u64 {
        self.0
    }

    /// Check if a specific flag is set
    pub const fn has(self, other: ServiceFlags) -> bool {
        (self.0 & other.0) == other.0
    }

    /// Combine two sets of flags
    pub const fn union(self, other: ServiceFlags) -> ServiceFlags {
        ServiceFlags(self.0 | other.0)
    }

    /// Check if the peer has desirable services for a full node
    pub fn is_desirable(self) -> bool {
        self.has(Self::NETWORK) || self.has(Self::NETWORK_LIMITED)
    }
}

impl fmt::Display for ServiceFlags {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut parts = Vec::new();
        if self.has(Self::NETWORK) {
            parts.push("NETWORK");
        }
        if self.has(Self::GETUTXO) {
            parts.push("GETUTXO");
        }
        if self.has(Self::BLOOM) {
            parts.push("BLOOM");
        }
        if self.has(Self::WITNESS) {
            parts.push("WITNESS");
        }
        if self.has(Self::COMPACT_FILTERS) {
            parts.push("COMPACT_FILTERS");
        }
        if self.has(Self::NETWORK_LIMITED) {
            parts.push("NETWORK_LIMITED");
        }
        if parts.is_empty() {
            write!(f, "NONE")
        } else {
            write!(f, "{}", parts.join("|"))
        }
    }
}

// ---------------------------------------------------------------------------
// Inventory types
// ---------------------------------------------------------------------------

/// Inventory object type identifiers
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u32)]
pub enum InvType {
    /// Error / any
    Error = 0,
    /// Transaction (txid hash)
    Tx = 1,
    /// Block (block hash)
    Block = 2,
    /// Filtered block (block hash, for bloom filters)
    FilteredBlock = 3,
    /// Compact block (block hash, BIP152)
    CompactBlock = 4,
    /// Witness transaction (BIP144 — wtxid hash)
    WitnessTx = 0x40000001,
    /// Witness block (BIP144)
    WitnessBlock = 0x40000002,
    /// Witness filtered block (BIP144)
    WitnessFilteredBlock = 0x40000003,
}

impl InvType {
    /// Create from raw u32 value
    pub fn from_u32(v: u32) -> Option<InvType> {
        match v {
            0 => Some(InvType::Error),
            1 => Some(InvType::Tx),
            2 => Some(InvType::Block),
            3 => Some(InvType::FilteredBlock),
            4 => Some(InvType::CompactBlock),
            0x40000001 => Some(InvType::WitnessTx),
            0x40000002 => Some(InvType::WitnessBlock),
            0x40000003 => Some(InvType::WitnessFilteredBlock),
            _ => None,
        }
    }

    /// Get raw u32 value
    pub fn as_u32(self) -> u32 {
        self as u32
    }
}

/// An inventory vector — identifies a data object by type and hash.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct InvVector {
    /// Object type
    pub inv_type: InvType,
    /// Object hash (32 bytes)
    pub hash: [u8; 32],
}

impl InvVector {
    /// Create a new inventory vector
    pub const fn new(inv_type: InvType, hash: [u8; 32]) -> Self {
        InvVector { inv_type, hash }
    }
}

impl fmt::Display for InvVector {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let hash_hex: String = self
            .hash
            .iter()
            .rev()
            .map(|b| format!("{:02x}", b))
            .collect();
        write!(f, "{:?}({})", self.inv_type, hash_hex)
    }
}

// ---------------------------------------------------------------------------
// Network address
// ---------------------------------------------------------------------------

/// A network address as encoded in the Bitcoin P2P protocol.
///
/// Version messages use a slightly different format (no timestamp), while
/// addr/getaddr messages include a 4-byte timestamp prefix.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NetAddress {
    /// Services offered
    pub services: ServiceFlags,
    /// IPv6 address (IPv4 is mapped as ::ffff:a.b.c.d)
    pub addr: [u8; 16],
    /// Port (big-endian on the wire)
    pub port: u16,
}

impl NetAddress {
    /// Create a NetAddress from a SocketAddr
    pub fn from_socket_addr(addr: SocketAddr, services: ServiceFlags) -> Self {
        let ip_bytes = match addr {
            SocketAddr::V4(v4) => {
                let mut buf = [0u8; 16];
                buf[10] = 0xff;
                buf[11] = 0xff;
                buf[12..16].copy_from_slice(&v4.ip().octets());
                buf
            }
            SocketAddr::V6(v6) => v6.ip().octets(),
        };
        NetAddress {
            services,
            addr: ip_bytes,
            port: addr.port(),
        }
    }

    /// Convert back to a SocketAddr
    pub fn to_socket_addr(&self) -> SocketAddr {
        // Check for IPv4-mapped IPv6 address (::ffff:a.b.c.d)
        if self.addr[..10] == [0u8; 10] && self.addr[10] == 0xff && self.addr[11] == 0xff {
            let ip = Ipv4Addr::new(self.addr[12], self.addr[13], self.addr[14], self.addr[15]);
            SocketAddr::V4(SocketAddrV4::new(ip, self.port))
        } else {
            let ip = Ipv6Addr::from(self.addr);
            SocketAddr::V6(SocketAddrV6::new(ip, self.port, 0, 0))
        }
    }
}

impl fmt::Display for NetAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} ({})", self.to_socket_addr(), self.services)
    }
}

// ---------------------------------------------------------------------------
// Reject reason codes (BIP61, deprecated but still useful as domain types)
// ---------------------------------------------------------------------------

/// Reject message reason codes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum RejectCode {
    Malformed = 0x01,
    Invalid = 0x10,
    Obsolete = 0x11,
    Duplicate = 0x12,
    NonStandard = 0x40,
    Dust = 0x41,
    InsufficientFee = 0x42,
    Checkpoint = 0x43,
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_service_flags_none() {
        let flags = ServiceFlags::NONE;
        assert_eq!(flags.as_u64(), 0);
        assert!(!flags.has(ServiceFlags::NETWORK));
        assert_eq!(format!("{}", flags), "NONE");
    }

    #[test]
    fn test_service_flags_network() {
        let flags = ServiceFlags::NETWORK;
        assert_eq!(flags.as_u64(), 1);
        assert!(flags.has(ServiceFlags::NETWORK));
        assert!(!flags.has(ServiceFlags::WITNESS));
        assert!(flags.is_desirable());
    }

    #[test]
    fn test_service_flags_union() {
        let flags = ServiceFlags::NETWORK.union(ServiceFlags::WITNESS);
        assert!(flags.has(ServiceFlags::NETWORK));
        assert!(flags.has(ServiceFlags::WITNESS));
        assert!(!flags.has(ServiceFlags::BLOOM));
        assert_eq!(flags.as_u64(), 0x09);
        assert_eq!(format!("{}", flags), "NETWORK|WITNESS");
    }

    #[test]
    fn test_service_flags_from_u64() {
        // 0x044d = NETWORK(1) | BLOOM(4) | WITNESS(8) | COMPACT_FILTERS(0x40) | NETWORK_LIMITED(0x400)
        let flags = ServiceFlags::from_u64(0x044d);
        assert!(flags.has(ServiceFlags::NETWORK));
        assert!(flags.has(ServiceFlags::BLOOM));
        assert!(flags.has(ServiceFlags::WITNESS));
        assert!(flags.has(ServiceFlags::COMPACT_FILTERS));
    }

    #[test]
    fn test_inv_type_roundtrip() {
        assert_eq!(InvType::from_u32(1), Some(InvType::Tx));
        assert_eq!(InvType::from_u32(2), Some(InvType::Block));
        assert_eq!(InvType::from_u32(0x40000001), Some(InvType::WitnessTx));
        assert_eq!(InvType::from_u32(0x40000002), Some(InvType::WitnessBlock));
        assert_eq!(InvType::from_u32(999), None);
    }

    #[test]
    fn test_inv_type_as_u32() {
        assert_eq!(InvType::Tx.as_u32(), 1);
        assert_eq!(InvType::Block.as_u32(), 2);
        assert_eq!(InvType::WitnessTx.as_u32(), 0x40000001);
    }

    #[test]
    fn test_inv_vector_display() {
        let iv = InvVector::new(InvType::Tx, [0xab; 32]);
        let s = format!("{}", iv);
        assert!(s.starts_with("Tx("));
        assert!(s.contains("abababab"));
    }

    #[test]
    fn test_net_address_from_ipv4() {
        let addr: SocketAddr = "1.2.3.4:8333".parse().unwrap();
        let na = NetAddress::from_socket_addr(addr, ServiceFlags::NETWORK);
        assert_eq!(na.port, 8333);
        // IPv4-mapped prefix
        assert_eq!(na.addr[10], 0xff);
        assert_eq!(na.addr[11], 0xff);
        assert_eq!(&na.addr[12..16], &[1, 2, 3, 4]);
        // Roundtrip
        let back = na.to_socket_addr();
        assert_eq!(back, addr);
    }

    #[test]
    fn test_net_address_from_ipv6() {
        let addr: SocketAddr = "[::1]:18333".parse().unwrap();
        let na = NetAddress::from_socket_addr(addr, ServiceFlags::NONE);
        assert_eq!(na.port, 18333);
        assert_eq!(na.addr[15], 1);
        let back = na.to_socket_addr();
        assert_eq!(back.port(), 18333);
    }

    #[test]
    fn test_net_address_display() {
        let addr: SocketAddr = "192.168.1.1:8333".parse().unwrap();
        let na = NetAddress::from_socket_addr(addr, ServiceFlags::NETWORK);
        let s = format!("{}", na);
        assert!(s.contains("192.168.1.1:8333"));
        assert!(s.contains("NETWORK"));
    }

    #[test]
    fn test_protocol_constants() {
        assert_eq!(PROTOCOL_VERSION, 70016);
        assert!(MIN_PEER_PROTO_VERSION < PROTOCOL_VERSION);
        assert_eq!(MAX_PROTOCOL_MESSAGE_LENGTH, 4_000_000);
        assert_eq!(MAX_HEADERS, 2000);
    }
}
