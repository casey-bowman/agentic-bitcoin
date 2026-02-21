//! Network/P2P Port Definitions
//!
//! This module defines the port traits for peer-to-peer network communication.
//! Implementations handle the details of connecting to peers, sending messages, and receiving blocks/transactions.

use btc_domain::primitives::{Block, Transaction, BlockHeader};
use std::error::Error;
use std::net::SocketAddr;

/// Network message types exchanged between peers.
///
/// These are the main message types in the Bitcoin P2P protocol.
#[derive(Clone, Debug)]
pub enum NetworkMessage {
    /// Version message - initiates connection handshake
    Version {
        version: u32,
        services: u64,
        timestamp: i64,
        addr_recv: SocketAddr,
        addr_from: SocketAddr,
        nonce: u64,
        user_agent: String,
        start_height: u32,
        relay: bool,
    },
    /// Verack message - acknowledges version
    Verack,
    /// Inv message - announces available transactions/blocks
    Inv {
        items: Vec<InventoryItem>,
    },
    /// GetData message - requests transactions/blocks
    GetData {
        items: Vec<InventoryItem>,
    },
    /// GetBlocks message - requests block hashes
    GetBlocks {
        version: u32,
        block_locator: Vec<btc_domain::primitives::BlockHash>,
        hash_stop: btc_domain::primitives::BlockHash,
    },
    /// GetHeaders message - requests block headers
    GetHeaders {
        version: u32,
        block_locator: Vec<btc_domain::primitives::BlockHash>,
        hash_stop: btc_domain::primitives::BlockHash,
    },
    /// Tx message - transmits a transaction
    Tx {
        tx: Transaction,
    },
    /// Block message - transmits a block
    Block {
        block: Block,
    },
    /// Headers message - transmits block headers
    Headers {
        headers: Vec<BlockHeader>,
    },
    /// Ping message - requests pong
    Ping {
        nonce: u64,
    },
    /// Pong message - responds to ping
    Pong {
        nonce: u64,
    },
    /// Addr message - announces addresses of peers
    Addr {
        addresses: Vec<(u32, SocketAddr)>, // (timestamp, address)
    },
}

/// Inventory item identifying a transaction or block.
#[derive(Clone, Debug, Copy, PartialEq, Eq)]
pub enum InventoryItem {
    /// Transaction inventory item
    Tx(btc_domain::primitives::Txid),
    /// Block inventory item
    Block(btc_domain::primitives::BlockHash),
}

/// Information about a connected peer.
#[derive(Clone, Debug)]
pub struct PeerInfo {
    /// Unique identifier for this peer
    pub id: u64,
    /// Network address of the peer
    pub addr: SocketAddr,
    /// Services offered by the peer (bitmask)
    pub services: u64,
    /// Protocol version reported by peer
    pub version: u32,
    /// User agent string reported by peer
    pub subver: String,
    /// Starting block height reported by peer
    pub start_height: u32,
    /// Whether peer relays transactions
    pub relay_txs: bool,
}

/// Events that occur during peer lifecycle.
#[derive(Clone, Debug)]
pub enum PeerEvent {
    /// Peer has successfully connected
    Connected {
        peer_info: PeerInfo,
    },
    /// Peer has disconnected
    Disconnected {
        peer_id: u64,
    },
    /// Message received from peer
    MessageReceived {
        peer_id: u64,
        message: NetworkMessage,
    },
    /// Peer has misbehaved (invalid message, etc.)
    Misbehaving {
        peer_id: u64,
        reason: String,
        score: i32,
    },
}

/// Port trait for P2P network management.
///
/// Implementations handle all aspects of peer connection management,
/// message sending/receiving, and network communication.
#[async_trait::async_trait]
pub trait PeerManager: Send + Sync {
    /// Initiates a connection to a peer.
    ///
    /// # Arguments
    ///
    /// * `addr` - The address to connect to
    ///
    /// # Returns
    ///
    /// Returns the peer ID if successful.
    async fn connect_peer(&self, addr: SocketAddr) -> Result<u64, Box<dyn Error + Send + Sync>>;

    /// Disconnects from a peer.
    ///
    /// # Arguments
    ///
    /// * `peer_id` - The peer ID to disconnect
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` on success.
    async fn disconnect_peer(&self, peer_id: u64) -> Result<(), Box<dyn Error + Send + Sync>>;

    /// Bans a peer, preventing further connections.
    ///
    /// # Arguments
    ///
    /// * `addr` - The address to ban
    /// * `ban_time` - Duration of the ban in seconds
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` on success.
    async fn ban_peer(
        &self,
        addr: SocketAddr,
        ban_time: u64,
    ) -> Result<(), Box<dyn Error + Send + Sync>>;

    /// Gets information about all connected peers.
    ///
    /// # Returns
    ///
    /// Returns a vector of PeerInfo for all connected peers.
    async fn get_connected_peers(&self) -> Result<Vec<PeerInfo>, Box<dyn Error + Send + Sync>>;

    /// Broadcasts a transaction to all connected peers.
    ///
    /// # Arguments
    ///
    /// * `tx` - The transaction to broadcast
    ///
    /// # Returns
    ///
    /// Returns the number of peers the message was sent to.
    async fn broadcast_transaction(
        &self,
        tx: &Transaction,
    ) -> Result<usize, Box<dyn Error + Send + Sync>>;

    /// Broadcasts a block to all connected peers.
    ///
    /// # Arguments
    ///
    /// * `block` - The block to broadcast
    ///
    /// # Returns
    ///
    /// Returns the number of peers the message was sent to.
    async fn broadcast_block(&self, block: &Block) -> Result<usize, Box<dyn Error + Send + Sync>>;

    /// Sends a network message to a specific peer.
    ///
    /// # Arguments
    ///
    /// * `peer_id` - The peer to send to
    /// * `message` - The message to send
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` on success.
    async fn send_to_peer(
        &self,
        peer_id: u64,
        message: NetworkMessage,
    ) -> Result<(), Box<dyn Error + Send + Sync>>;
}

/// Port trait for receiving network events.
///
/// Implementations listen for peer events and forward them to the domain layer.
#[async_trait::async_trait]
pub trait NetworkListener: Send + Sync {
    /// Called when a peer event occurs.
    ///
    /// # Arguments
    ///
    /// * `event` - The peer event that occurred
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` if the event was handled successfully.
    async fn on_peer_event(&self, event: PeerEvent) -> Result<(), Box<dyn Error + Send + Sync>>;
}
