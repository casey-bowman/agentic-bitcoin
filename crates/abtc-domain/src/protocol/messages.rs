//! P2P protocol messages
//!
//! Complete Bitcoin P2P message types. Each variant maps 1:1 to a Bitcoin
//! protocol command string (e.g. "version", "verack", "inv", "tx", "block").
//!
//! This module defines the high-level message types only; encoding/decoding
//! lives in `codec.rs`.

use crate::primitives::{Block, BlockHash, BlockHeader, Transaction};
use super::types::{InvVector, NetAddress, ServiceFlags};

// ---------------------------------------------------------------------------
// NetworkMessage — the top-level enum
// ---------------------------------------------------------------------------

/// A fully-parsed Bitcoin P2P network message.
#[derive(Debug, Clone)]
pub enum NetworkMessage {
    // ── Handshake ────────────────────────────────────────────────────

    /// Initiates or responds to a peer connection.
    Version(VersionMessage),

    /// Acknowledges receipt of the peer's version message.
    Verack,

    // ── Feature negotiation (post-handshake) ────────────────────────

    /// BIP339: Negotiate wtxid-based transaction relay.
    WtxidRelay,

    /// BIP130: Request headers announcements instead of inv.
    SendHeaders,

    /// BIP152: Negotiate compact block relay.
    SendCmpct(SendCmpctMessage),

    /// BIP133: Set minimum fee rate for tx relay (in sat/kB).
    FeeFilter {
        feerate: u64,
    },

    /// BIP155: Negotiate addrv2 support.
    SendAddrV2,

    // ── Address relay ───────────────────────────────────────────────

    /// Peer address announcement (legacy, up to 1000 entries).
    Addr(Vec<TimestampedAddress>),

    /// BIP155: Extended address announcement with Tor/I2P support.
    AddrV2(Vec<AddrV2Entry>),

    /// Request address list from peer.
    GetAddr,

    // ── Inventory / data relay ──────────────────────────────────────

    /// Announce available objects (transactions, blocks).
    Inv(Vec<InvVector>),

    /// Request objects by inventory vector.
    GetData(Vec<InvVector>),

    /// Peer does not have the requested objects.
    NotFound(Vec<InvVector>),

    // ── Block relay ─────────────────────────────────────────────────

    /// Transmit a full block (BIP144 segwit encoding when appropriate).
    Block(Block),

    /// Request block headers using a block locator.
    GetHeaders(GetHeadersMessage),

    /// Transmit block headers (up to 2000).
    Headers(Vec<BlockHeader>),

    /// Request block hashes using a block locator (legacy).
    GetBlocks(GetBlocksMessage),

    // ── Transaction relay ───────────────────────────────────────────

    /// Transmit a transaction (BIP144 segwit encoding when appropriate).
    Tx(Transaction),

    /// Request the mempool contents (as a stream of inv messages).
    MemPool,

    // ── Compact blocks (BIP152) ─────────────────────────────────────

    /// Compact block message.
    CmpctBlock(CmpctBlockMessage),

    /// Request missing transactions from a compact block.
    GetBlockTxn(GetBlockTxnMessage),

    /// Respond with the missing transactions.
    BlockTxn(BlockTxnMessage),

    // ── Ping / pong ─────────────────────────────────────────────────

    /// Ping — requests pong with matching nonce.
    Ping {
        nonce: u64,
    },

    /// Pong — echoes ping nonce.
    Pong {
        nonce: u64,
    },

    // ── Misc ────────────────────────────────────────────────────────

    /// Alert messages (deprecated, but peers may still send them).
    Alert(Vec<u8>),

    /// Unknown / unsupported command — payload preserved for forwarding.
    Unknown {
        command: String,
        payload: Vec<u8>,
    },
}

impl NetworkMessage {
    /// Get the protocol command string for this message.
    pub fn command(&self) -> &str {
        match self {
            NetworkMessage::Version(_) => "version",
            NetworkMessage::Verack => "verack",
            NetworkMessage::WtxidRelay => "wtxidrelay",
            NetworkMessage::SendHeaders => "sendheaders",
            NetworkMessage::SendCmpct(_) => "sendcmpct",
            NetworkMessage::FeeFilter { .. } => "feefilter",
            NetworkMessage::SendAddrV2 => "sendaddrv2",
            NetworkMessage::Addr(_) => "addr",
            NetworkMessage::AddrV2(_) => "addrv2",
            NetworkMessage::GetAddr => "getaddr",
            NetworkMessage::Inv(_) => "inv",
            NetworkMessage::GetData(_) => "getdata",
            NetworkMessage::NotFound(_) => "notfound",
            NetworkMessage::Block(_) => "block",
            NetworkMessage::GetHeaders(_) => "getheaders",
            NetworkMessage::Headers(_) => "headers",
            NetworkMessage::GetBlocks(_) => "getblocks",
            NetworkMessage::Tx(_) => "tx",
            NetworkMessage::MemPool => "mempool",
            NetworkMessage::CmpctBlock(_) => "cmpctblock",
            NetworkMessage::GetBlockTxn(_) => "getblocktxn",
            NetworkMessage::BlockTxn(_) => "blocktxn",
            NetworkMessage::Ping { .. } => "ping",
            NetworkMessage::Pong { .. } => "pong",
            NetworkMessage::Alert(_) => "alert",
            NetworkMessage::Unknown { command, .. } => command,
        }
    }
}

// ---------------------------------------------------------------------------
// Sub-message structs
// ---------------------------------------------------------------------------

/// Version message payload.
#[derive(Debug, Clone)]
pub struct VersionMessage {
    /// Protocol version
    pub version: u32,
    /// Services offered by the sender
    pub services: ServiceFlags,
    /// Unix timestamp of the message
    pub timestamp: i64,
    /// Address of the receiver as seen by the sender
    pub addr_recv: NetAddress,
    /// Address of the sender
    pub addr_from: NetAddress,
    /// Random nonce for connection dedup
    pub nonce: u64,
    /// User agent string
    pub user_agent: String,
    /// Block height the sender is at
    pub start_height: i32,
    /// Whether the sender wants relay of transactions (BIP37)
    pub relay: bool,
}

/// A timestamped network address (for addr messages).
#[derive(Debug, Clone, Copy)]
pub struct TimestampedAddress {
    /// Unix timestamp when this address was last seen active
    pub timestamp: u32,
    /// Network address
    pub addr: NetAddress,
}

/// BIP155 extended address entry.
#[derive(Debug, Clone)]
pub struct AddrV2Entry {
    /// Unix timestamp
    pub timestamp: u32,
    /// Services offered
    pub services: ServiceFlags,
    /// Network ID (1=IPv4, 2=IPv6, 3=TorV2, 4=TorV3, 5=I2P, 6=CJDNS)
    pub network_id: u8,
    /// Raw address bytes (length depends on network_id)
    pub addr: Vec<u8>,
    /// Port
    pub port: u16,
}

/// GetHeaders message payload.
#[derive(Debug, Clone)]
pub struct GetHeadersMessage {
    /// Protocol version
    pub version: u32,
    /// Block locator hashes (newest first)
    pub locator_hashes: Vec<BlockHash>,
    /// Stop hash (zero = get as many as possible)
    pub hash_stop: BlockHash,
}

/// GetBlocks message payload.
#[derive(Debug, Clone)]
pub struct GetBlocksMessage {
    /// Protocol version
    pub version: u32,
    /// Block locator hashes (newest first)
    pub locator_hashes: Vec<BlockHash>,
    /// Stop hash (zero = get 500 blocks)
    pub hash_stop: BlockHash,
}

/// BIP152: sendcmpct message payload.
#[derive(Debug, Clone, Copy)]
pub struct SendCmpctMessage {
    /// Whether the sender wants compact blocks (true = high bandwidth mode)
    pub announce: bool,
    /// Compact block protocol version (1 = original, 2 = segwit)
    pub version: u64,
}

/// BIP152: cmpctblock message payload.
#[derive(Debug, Clone)]
pub struct CmpctBlockMessage {
    /// Block header
    pub header: BlockHeader,
    /// Nonce used to compute short IDs
    pub nonce: u64,
    /// Short transaction IDs (6 bytes each, stored as u64 with top 2 bytes zero)
    pub short_ids: Vec<u64>,
    /// Pre-filled transactions (coinbase + any others the sender thinks we need)
    pub prefilled_txs: Vec<PrefilledTx>,
}

/// A pre-filled transaction in a compact block.
#[derive(Debug, Clone)]
pub struct PrefilledTx {
    /// Differentially-encoded index in the block
    pub index: u16,
    /// The full transaction
    pub tx: Transaction,
}

/// BIP152: getblocktxn message payload.
#[derive(Debug, Clone)]
pub struct GetBlockTxnMessage {
    /// Block hash
    pub block_hash: BlockHash,
    /// Differentially-encoded indices of requested transactions
    pub indices: Vec<u16>,
}

/// BIP152: blocktxn message payload.
#[derive(Debug, Clone)]
pub struct BlockTxnMessage {
    /// Block hash
    pub block_hash: BlockHash,
    /// The requested transactions
    pub transactions: Vec<Transaction>,
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_command_strings() {
        assert_eq!(NetworkMessage::Verack.command(), "verack");
        assert_eq!(NetworkMessage::WtxidRelay.command(), "wtxidrelay");
        assert_eq!(NetworkMessage::SendHeaders.command(), "sendheaders");
        assert_eq!(NetworkMessage::GetAddr.command(), "getaddr");
        assert_eq!(NetworkMessage::MemPool.command(), "mempool");
        assert_eq!(NetworkMessage::Ping { nonce: 42 }.command(), "ping");
        assert_eq!(NetworkMessage::Pong { nonce: 42 }.command(), "pong");
        assert_eq!(
            NetworkMessage::FeeFilter { feerate: 1000 }.command(),
            "feefilter"
        );
    }

    #[test]
    fn test_version_message() {
        let vm = VersionMessage {
            version: 70016,
            services: ServiceFlags::NETWORK.union(ServiceFlags::WITNESS),
            timestamp: 1700000000,
            addr_recv: NetAddress {
                services: ServiceFlags::NONE,
                addr: [0; 16],
                port: 8333,
            },
            addr_from: NetAddress {
                services: ServiceFlags::NONE,
                addr: [0; 16],
                port: 8333,
            },
            nonce: 12345,
            user_agent: "/AgenticBitcoin:0.1.0/".to_string(),
            start_height: 800000,
            relay: true,
        };
        let msg = NetworkMessage::Version(vm);
        assert_eq!(msg.command(), "version");
    }

    #[test]
    fn test_sendcmpct_message() {
        let sc = SendCmpctMessage {
            announce: true,
            version: 2,
        };
        let msg = NetworkMessage::SendCmpct(sc);
        assert_eq!(msg.command(), "sendcmpct");
    }

    #[test]
    fn test_unknown_message() {
        let msg = NetworkMessage::Unknown {
            command: "mycustom".to_string(),
            payload: vec![1, 2, 3],
        };
        assert_eq!(msg.command(), "mycustom");
    }

    #[test]
    fn test_inv_message() {
        use crate::protocol::types::InvType;
        let inv = vec![InvVector::new(InvType::Tx, [0xaa; 32])];
        let msg = NetworkMessage::Inv(inv);
        assert_eq!(msg.command(), "inv");
    }
}
