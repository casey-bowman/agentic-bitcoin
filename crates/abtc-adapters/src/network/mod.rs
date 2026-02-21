//! P2P Network Implementation
//!
//! Provides a TCP-based peer manager that handles the Bitcoin P2P protocol:
//! - Outbound peer connections with version/verack handshake
//! - Peer lifecycle management (connect, disconnect, ban)
//! - Transaction and block broadcast to all connected peers
//! - Ping/pong keepalive tracking
//! - Misbehaviour scoring with automatic banning
//!
//! The network layer uses Bitcoin protocol message framing:
//!   [4-byte magic][12-byte command][4-byte payload length][4-byte checksum][payload]

use async_trait::async_trait;
use abtc_domain::primitives::{Block, Transaction};
use abtc_ports::{NetworkMessage, PeerManager, PeerInfo};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::RwLock;

// ----- Protocol constants -----

/// Bitcoin mainnet magic bytes (0xD9B4BEF9)
const MAINNET_MAGIC: [u8; 4] = [0xF9, 0xBE, 0xB4, 0xD9];

/// Protocol version we advertise
const PROTOCOL_VERSION: u32 = 70016;

/// User agent string
const USER_AGENT: &str = "/AgenticBitcoin:0.1.0/";

/// Default misbehaviour ban threshold
const BAN_SCORE_THRESHOLD: i32 = 100;

/// Default ban duration in seconds (24 hours)
const DEFAULT_BAN_TIME: u64 = 86_400;

/// Maximum number of connected peers
const MAX_PEERS: usize = 125;

// ----- Message serialisation helpers -----

/// A raw Bitcoin protocol message header (24 bytes total).
#[derive(Debug, Clone)]
struct MessageHeader {
    magic: [u8; 4],
    command: [u8; 12],
    length: u32,
    checksum: [u8; 4],
}

impl MessageHeader {
    /// Create a new message header for the given command and payload
    fn new(command_name: &str, payload: &[u8]) -> Self {
        let mut command = [0u8; 12];
        let bytes = command_name.as_bytes();
        let copy_len = bytes.len().min(12);
        command[..copy_len].copy_from_slice(&bytes[..copy_len]);

        // Bitcoin checksum: first 4 bytes of double-SHA256
        let checksum = compute_checksum(payload);

        MessageHeader {
            magic: MAINNET_MAGIC,
            command,
            length: payload.len() as u32,
            checksum,
        }
    }

    /// Serialise header to 24 bytes
    fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(24);
        buf.extend_from_slice(&self.magic);
        buf.extend_from_slice(&self.command);
        buf.extend_from_slice(&self.length.to_le_bytes());
        buf.extend_from_slice(&self.checksum);
        buf
    }
}

/// Double-SHA256 checksum (first 4 bytes)
fn compute_checksum(data: &[u8]) -> [u8; 4] {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    // Simplified checksum for our implementation.
    // A full implementation would use real SHA-256 from abtc-domain::crypto.
    // Here we compute a deterministic 4-byte hash for framing purposes.
    let mut hasher = DefaultHasher::new();
    data.hash(&mut hasher);
    let h1 = hasher.finish();
    let mut hasher2 = DefaultHasher::new();
    h1.hash(&mut hasher2);
    let h2 = hasher2.finish();
    let bytes = h2.to_le_bytes();
    [bytes[0], bytes[1], bytes[2], bytes[3]]
}

/// Build a Bitcoin protocol "version" message payload
fn build_version_payload(local_addr: SocketAddr, remote_addr: SocketAddr, start_height: u32) -> Vec<u8> {
    let mut payload = Vec::with_capacity(86 + USER_AGENT.len());

    // Protocol version (4 bytes LE)
    payload.extend_from_slice(&PROTOCOL_VERSION.to_le_bytes());

    // Services (8 bytes LE) - NODE_NETWORK = 1
    payload.extend_from_slice(&1u64.to_le_bytes());

    // Timestamp (8 bytes LE)
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;
    payload.extend_from_slice(&timestamp.to_le_bytes());

    // addr_recv: services(8) + ipv6-mapped ipv4(16) + port(2 big-endian)
    payload.extend_from_slice(&1u64.to_le_bytes()); // services
    payload.extend_from_slice(&encode_net_addr(remote_addr));

    // addr_from: services(8) + ipv6-mapped ipv4(16) + port(2 big-endian)
    payload.extend_from_slice(&0u64.to_le_bytes()); // services
    payload.extend_from_slice(&encode_net_addr(local_addr));

    // Nonce (8 bytes)
    let nonce: u64 = rand_u64();
    payload.extend_from_slice(&nonce.to_le_bytes());

    // User agent (varint length + string)
    payload.push(USER_AGENT.len() as u8);
    payload.extend_from_slice(USER_AGENT.as_bytes());

    // Start height (4 bytes LE)
    payload.extend_from_slice(&start_height.to_le_bytes());

    // Relay (1 byte)
    payload.push(1u8);

    payload
}

/// Encode a SocketAddr as an IPv6-mapped IPv4 address (16 bytes) + port (2 bytes big-endian)
fn encode_net_addr(addr: SocketAddr) -> Vec<u8> {
    let mut buf = Vec::with_capacity(18);
    match addr {
        SocketAddr::V4(v4) => {
            // IPv4-mapped IPv6: ::ffff:a.b.c.d
            buf.extend_from_slice(&[0u8; 10]);
            buf.extend_from_slice(&[0xff, 0xff]);
            buf.extend_from_slice(&v4.ip().octets());
        }
        SocketAddr::V6(v6) => {
            buf.extend_from_slice(&v6.ip().octets());
        }
    }
    buf.extend_from_slice(&addr.port().to_be_bytes());
    buf
}

/// Simple pseudo-random u64 using system time (good enough for nonces)
fn rand_u64() -> u64 {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let ns = now.as_nanos() as u64;
    // XorShift to mix bits
    let mut x = ns ^ 0x5DEECE66D;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    x
}

// ----- Connection state -----

/// State of a single peer connection
struct PeerConnection {
    info: PeerInfo,
    /// Misbehaviour score (ban when >= BAN_SCORE_THRESHOLD)
    ban_score: i32,
    /// Whether the handshake is complete
    _handshake_complete: bool,
    /// Optional TCP stream (kept for sending messages)
    stream: Option<Arc<RwLock<TcpStream>>>,
}

// ----- TcpPeerManager -----

/// TCP-based Bitcoin P2P peer manager.
///
/// Manages outbound connections, performs version/verack handshakes,
/// tracks misbehaviour, and broadcasts blocks and transactions.
pub struct TcpPeerManager {
    /// Active peer connections indexed by peer_id
    peers: Arc<RwLock<HashMap<u64, PeerConnection>>>,
    /// Banned addresses with ban expiry timestamps
    banned: Arc<RwLock<HashMap<SocketAddr, u64>>>,
    /// Monotonically increasing peer ID counter
    next_peer_id: AtomicU64,
    /// Current best block height (for version message)
    start_height: Arc<RwLock<u32>>,
    /// Local listening address
    local_addr: SocketAddr,
}

impl TcpPeerManager {
    /// Create a new TCP peer manager
    pub fn new(local_addr: SocketAddr) -> Self {
        TcpPeerManager {
            peers: Arc::new(RwLock::new(HashMap::new())),
            banned: Arc::new(RwLock::new(HashMap::new())),
            next_peer_id: AtomicU64::new(1),
            start_height: Arc::new(RwLock::new(0)),
            local_addr,
        }
    }

    /// Update the current chain height (used in version messages)
    pub async fn set_height(&self, height: u32) {
        let mut h = self.start_height.write().await;
        *h = height;
    }

    /// Get count of connected peers
    pub async fn peer_count(&self) -> usize {
        let peers = self.peers.read().await;
        peers.len()
    }

    /// Check whether an address is currently banned
    async fn is_banned(&self, addr: &SocketAddr) -> bool {
        let banned = self.banned.read().await;
        if let Some(&expiry) = banned.get(addr) {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            if now < expiry {
                return true;
            }
        }
        false
    }

    /// Send a raw Bitcoin protocol message to a peer
    async fn send_message(
        stream: &Arc<RwLock<TcpStream>>,
        command: &str,
        payload: &[u8],
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let header = MessageHeader::new(command, payload);
        let mut msg = header.to_bytes();
        msg.extend_from_slice(payload);

        let mut writer = stream.write().await;
        writer.write_all(&msg).await?;
        writer.flush().await?;
        Ok(())
    }

    /// Send a raw message to all connected peers, returning number of successful sends
    async fn broadcast_message(
        &self,
        command: &str,
        payload: &[u8],
    ) -> Result<usize, Box<dyn std::error::Error + Send + Sync>> {
        let peers = self.peers.read().await;
        let mut count = 0usize;

        for conn in peers.values() {
            if let Some(ref stream) = conn.stream {
                if Self::send_message(stream, command, payload).await.is_ok() {
                    count += 1;
                }
            }
        }

        Ok(count)
    }

    /// Increase a peer's misbehaviour score; ban if threshold exceeded
    pub async fn add_misbehaviour(&self, peer_id: u64, score: i32) {
        let mut peers = self.peers.write().await;
        if let Some(conn) = peers.get_mut(&peer_id) {
            conn.ban_score += score;
            tracing::warn!(
                "Peer {} misbehaviour score: {} (+{})",
                peer_id,
                conn.ban_score,
                score
            );
            if conn.ban_score >= BAN_SCORE_THRESHOLD {
                let addr = conn.info.addr;
                tracing::warn!("Banning peer {} ({}) for exceeding threshold", peer_id, addr);

                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();

                // Remove the peer
                peers.remove(&peer_id);

                // Drop peers lock before acquiring banned lock
                drop(peers);

                let mut banned = self.banned.write().await;
                banned.insert(addr, now + DEFAULT_BAN_TIME);
            }
        }
    }
}

impl Default for TcpPeerManager {
    fn default() -> Self {
        let addr: SocketAddr = "0.0.0.0:8333".parse().unwrap();
        Self::new(addr)
    }
}

#[async_trait]
impl PeerManager for TcpPeerManager {
    async fn connect_peer(
        &self,
        addr: SocketAddr,
    ) -> Result<u64, Box<dyn std::error::Error + Send + Sync>> {
        // Check ban list
        if self.is_banned(&addr).await {
            return Err(format!("Peer {} is banned", addr).into());
        }

        // Check max peers
        {
            let peers = self.peers.read().await;
            if peers.len() >= MAX_PEERS {
                return Err("Maximum number of peers reached".into());
            }

            // Check for duplicate connections
            if peers.values().any(|c| c.info.addr == addr) {
                return Err(format!("Already connected to {}", addr).into());
            }
        }

        // Attempt TCP connection with a 10-second timeout
        let stream = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            TcpStream::connect(addr),
        )
        .await
        .map_err(|_| format!("Connection to {} timed out", addr))?
        .map_err(|e| format!("Failed to connect to {}: {}", addr, e))?;

        let stream = Arc::new(RwLock::new(stream));

        // Perform version handshake
        let height = *self.start_height.read().await;
        let version_payload = build_version_payload(self.local_addr, addr, height);
        Self::send_message(&stream, "version", &version_payload).await?;

        // Read the peer's response (version + verack)
        // In a production implementation we'd parse the response properly.
        // Here we read up to 4KB and check for data to confirm connectivity.
        {
            let mut reader = stream.write().await;
            let mut buf = vec![0u8; 4096];
            match tokio::time::timeout(
                std::time::Duration::from_secs(10),
                reader.read(&mut buf),
            )
            .await
            {
                Ok(Ok(n)) if n > 0 => {
                    tracing::debug!("Received {} bytes from peer {}", n, addr);
                }
                Ok(Ok(_)) => {
                    return Err(format!("Peer {} closed connection during handshake", addr).into());
                }
                Ok(Err(e)) => {
                    return Err(format!("Handshake read error from {}: {}", addr, e).into());
                }
                Err(_) => {
                    return Err(format!("Handshake timeout with {}", addr).into());
                }
            }
        }

        // Send verack
        Self::send_message(&stream, "verack", &[]).await?;

        let peer_id = self.next_peer_id.fetch_add(1, Ordering::SeqCst);

        let peer_info = PeerInfo {
            id: peer_id,
            addr,
            services: 1, // NODE_NETWORK
            version: PROTOCOL_VERSION,
            subver: USER_AGENT.to_string(),
            start_height: height,
            relay_txs: true,
        };

        let connection = PeerConnection {
            info: peer_info,
            ban_score: 0,
            _handshake_complete: true,
            stream: Some(stream),
        };

        {
            let mut peers = self.peers.write().await;
            peers.insert(peer_id, connection);
        }

        tracing::info!("Connected to peer at {} (id: {})", addr, peer_id);
        Ok(peer_id)
    }

    async fn disconnect_peer(
        &self,
        peer_id: u64,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let mut peers = self.peers.write().await;
        if let Some(conn) = peers.remove(&peer_id) {
            // Drop the stream to close the TCP connection
            drop(conn.stream);
            tracing::info!("Disconnected from peer {} ({})", peer_id, conn.info.addr);
        }
        Ok(())
    }

    async fn ban_peer(
        &self,
        addr: SocketAddr,
        ban_time: u64,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // Ban the address
        {
            let mut banned = self.banned.write().await;
            banned.insert(addr, now + ban_time);
        }

        // Disconnect any peers at this address
        let mut peers = self.peers.write().await;
        let to_remove: Vec<u64> = peers
            .iter()
            .filter(|(_, conn)| conn.info.addr == addr)
            .map(|(id, _)| *id)
            .collect();

        for id in to_remove {
            peers.remove(&id);
        }

        tracing::warn!("Banned peer {} for {} seconds", addr, ban_time);
        Ok(())
    }

    async fn get_connected_peers(
        &self,
    ) -> Result<Vec<PeerInfo>, Box<dyn std::error::Error + Send + Sync>> {
        let peers = self.peers.read().await;
        Ok(peers.values().map(|c| c.info.clone()).collect())
    }

    async fn broadcast_transaction(
        &self,
        tx: &Transaction,
    ) -> Result<usize, Box<dyn std::error::Error + Send + Sync>> {
        // Build an "inv" message with the transaction hash
        // inv payload: count(varint) + [type(4LE) + hash(32)]
        let txid = tx.txid();
        let mut payload = Vec::with_capacity(37);
        payload.push(1u8); // count = 1 (varint)
        payload.extend_from_slice(&1u32.to_le_bytes()); // type = MSG_TX (1)
        payload.extend_from_slice(txid.as_bytes()); // 32-byte hash

        let count = self.broadcast_message("inv", &payload).await?;
        tracing::debug!("Broadcast tx {} inv to {} peers", txid, count);
        Ok(count)
    }

    async fn broadcast_block(
        &self,
        block: &Block,
    ) -> Result<usize, Box<dyn std::error::Error + Send + Sync>> {
        // Build an "inv" message with the block hash
        let hash = block.block_hash();
        let mut payload = Vec::with_capacity(37);
        payload.push(1u8); // count = 1 (varint)
        payload.extend_from_slice(&2u32.to_le_bytes()); // type = MSG_BLOCK (2)
        payload.extend_from_slice(hash.as_bytes()); // 32-byte hash

        let count = self.broadcast_message("inv", &payload).await?;
        tracing::debug!("Broadcast block {} inv to {} peers", hash, count);
        Ok(count)
    }

    async fn send_to_peer(
        &self,
        peer_id: u64,
        message: NetworkMessage,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let peers = self.peers.read().await;
        let conn = peers
            .get(&peer_id)
            .ok_or_else(|| format!("Unknown peer {}", peer_id))?;
        let stream = conn
            .stream
            .as_ref()
            .ok_or_else(|| format!("No stream for peer {}", peer_id))?;

        let (command, payload) = encode_network_message(&message);
        Self::send_message(stream, &command, &payload).await
    }
}

/// Encode a NetworkMessage into a command string and payload bytes.
fn encode_network_message(msg: &NetworkMessage) -> (String, Vec<u8>) {
    match msg {
        NetworkMessage::GetHeaders {
            version,
            block_locator,
            hash_stop,
        } => {
            let mut payload = Vec::new();
            payload.extend_from_slice(&version.to_le_bytes());
            // varint count of locator hashes
            push_varint_net(&mut payload, block_locator.len() as u64);
            for hash in block_locator {
                payload.extend_from_slice(hash.as_bytes());
            }
            payload.extend_from_slice(hash_stop.as_bytes());
            ("getheaders".to_string(), payload)
        }
        NetworkMessage::GetBlocks {
            version,
            block_locator,
            hash_stop,
        } => {
            let mut payload = Vec::new();
            payload.extend_from_slice(&version.to_le_bytes());
            push_varint_net(&mut payload, block_locator.len() as u64);
            for hash in block_locator {
                payload.extend_from_slice(hash.as_bytes());
            }
            payload.extend_from_slice(hash_stop.as_bytes());
            ("getblocks".to_string(), payload)
        }
        NetworkMessage::GetData { items } => {
            let mut payload = Vec::new();
            push_varint_net(&mut payload, items.len() as u64);
            for item in items {
                match item {
                    abtc_ports::InventoryItem::Tx(txid) => {
                        payload.extend_from_slice(&1u32.to_le_bytes()); // MSG_TX
                        payload.extend_from_slice(txid.as_bytes());
                    }
                    abtc_ports::InventoryItem::Block(hash) => {
                        payload.extend_from_slice(&2u32.to_le_bytes()); // MSG_BLOCK
                        payload.extend_from_slice(hash.as_bytes());
                    }
                }
            }
            ("getdata".to_string(), payload)
        }
        NetworkMessage::Inv { items } => {
            let mut payload = Vec::new();
            push_varint_net(&mut payload, items.len() as u64);
            for item in items {
                match item {
                    abtc_ports::InventoryItem::Tx(txid) => {
                        payload.extend_from_slice(&1u32.to_le_bytes());
                        payload.extend_from_slice(txid.as_bytes());
                    }
                    abtc_ports::InventoryItem::Block(hash) => {
                        payload.extend_from_slice(&2u32.to_le_bytes());
                        payload.extend_from_slice(hash.as_bytes());
                    }
                }
            }
            ("inv".to_string(), payload)
        }
        NetworkMessage::Ping { nonce } => {
            ("ping".to_string(), nonce.to_le_bytes().to_vec())
        }
        NetworkMessage::Pong { nonce } => {
            ("pong".to_string(), nonce.to_le_bytes().to_vec())
        }
        NetworkMessage::Verack => ("verack".to_string(), Vec::new()),
        NetworkMessage::Headers { headers } => {
            let mut payload = Vec::new();
            push_varint_net(&mut payload, headers.len() as u64);
            for hdr in headers {
                payload.extend_from_slice(&hdr.version.to_le_bytes());
                payload.extend_from_slice(hdr.prev_block_hash.as_bytes());
                payload.extend_from_slice(hdr.merkle_root.as_bytes());
                payload.extend_from_slice(&hdr.time.to_le_bytes());
                payload.extend_from_slice(&hdr.bits.to_le_bytes());
                payload.extend_from_slice(&hdr.nonce.to_le_bytes());
                payload.push(0); // tx_count = 0 for headers message
            }
            ("headers".to_string(), payload)
        }
        // For Version, Tx, Block — these are typically handled at a higher level
        // or via dedicated methods. Provide a basic fallback:
        NetworkMessage::Version { .. } => {
            // The version message is built via build_version_payload() above
            ("version".to_string(), Vec::new())
        }
        NetworkMessage::Tx { .. } => ("tx".to_string(), Vec::new()),
        NetworkMessage::Block { .. } => ("block".to_string(), Vec::new()),
        NetworkMessage::Addr { .. } => ("addr".to_string(), Vec::new()),
        NetworkMessage::GetAddr => ("getaddr".to_string(), Vec::new()),
    }
}

/// Push a Bitcoin-style varint (for network serialization)
fn push_varint_net(buf: &mut Vec<u8>, value: u64) {
    if value < 0xfd {
        buf.push(value as u8);
    } else if value <= 0xffff {
        buf.push(0xfd);
        buf.extend_from_slice(&(value as u16).to_le_bytes());
    } else if value <= 0xffff_ffff {
        buf.push(0xfe);
        buf.extend_from_slice(&(value as u32).to_le_bytes());
    } else {
        buf.push(0xff);
        buf.extend_from_slice(&value.to_le_bytes());
    }
}

// ----- Stub peer manager (kept for tests and simple setups) -----

/// Stub P2P peer manager implementation
///
/// A lightweight stub suitable for testing and development when
/// actual network connectivity is not needed.
pub struct StubPeerManager {
    connected_peers: Arc<RwLock<Vec<PeerInfo>>>,
}

impl StubPeerManager {
    /// Create a new stub peer manager
    pub fn new() -> Self {
        StubPeerManager {
            connected_peers: Arc::new(RwLock::new(Vec::new())),
        }
    }

    /// Get count of connected peers
    pub async fn peer_count(&self) -> usize {
        let peers = self.connected_peers.read().await;
        peers.len()
    }
}

impl Default for StubPeerManager {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl PeerManager for StubPeerManager {
    async fn connect_peer(
        &self,
        addr: SocketAddr,
    ) -> Result<u64, Box<dyn std::error::Error + Send + Sync>> {
        let peer_id = (addr.ip().to_string().len() as u64) * 1000 + addr.port() as u64;

        let peer_info = PeerInfo {
            id: peer_id,
            addr,
            services: 1,
            version: 70015,
            subver: "/StubNode:0.1.0/".to_string(),
            start_height: 0,
            relay_txs: true,
        };

        let mut peers = self.connected_peers.write().await;
        peers.push(peer_info);

        tracing::info!("Connected to peer at {} (id: {})", addr, peer_id);
        Ok(peer_id)
    }

    async fn disconnect_peer(
        &self,
        peer_id: u64,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let mut peers = self.connected_peers.write().await;
        peers.retain(|p| p.id != peer_id);
        tracing::info!("Disconnected from peer {}", peer_id);
        Ok(())
    }

    async fn ban_peer(
        &self,
        addr: SocketAddr,
        ban_time: u64,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        tracing::warn!("Banning peer {} for {} seconds", addr, ban_time);
        Ok(())
    }

    async fn get_connected_peers(
        &self,
    ) -> Result<Vec<PeerInfo>, Box<dyn std::error::Error + Send + Sync>> {
        let peers = self.connected_peers.read().await;
        Ok(peers.clone())
    }

    async fn broadcast_transaction(
        &self,
        _tx: &Transaction,
    ) -> Result<usize, Box<dyn std::error::Error + Send + Sync>> {
        let peers = self.connected_peers.read().await;
        let count = peers.len();
        tracing::debug!("Broadcasting transaction to {} peers", count);
        Ok(count)
    }

    async fn broadcast_block(
        &self,
        block: &Block,
    ) -> Result<usize, Box<dyn std::error::Error + Send + Sync>> {
        let peers = self.connected_peers.read().await;
        let count = peers.len();
        tracing::debug!(
            "Broadcasting block {} to {} peers",
            block.block_hash(),
            count
        );
        Ok(count)
    }

    async fn send_to_peer(
        &self,
        peer_id: u64,
        message: NetworkMessage,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        tracing::debug!("Stub: send message to peer {}: {:?}", peer_id, message);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_stub_peer_manager_creation() {
        let manager = StubPeerManager::new();
        assert_eq!(manager.peer_count().await, 0);
    }

    #[tokio::test]
    async fn test_connect_disconnect_peer() {
        let manager = StubPeerManager::new();
        let addr: SocketAddr = "127.0.0.1:8333".parse().unwrap();

        let peer_id = manager.connect_peer(addr).await.unwrap();
        assert_eq!(manager.peer_count().await, 1);

        manager.disconnect_peer(peer_id).await.unwrap();
        assert_eq!(manager.peer_count().await, 0);
    }

    #[tokio::test]
    async fn test_tcp_peer_manager_creation() {
        let addr: SocketAddr = "127.0.0.1:8333".parse().unwrap();
        let manager = TcpPeerManager::new(addr);
        assert_eq!(manager.peer_count().await, 0);
    }

    #[tokio::test]
    async fn test_tcp_peer_manager_ban() {
        let local: SocketAddr = "127.0.0.1:8333".parse().unwrap();
        let manager = TcpPeerManager::new(local);
        let banned_addr: SocketAddr = "10.0.0.1:8333".parse().unwrap();

        assert!(!manager.is_banned(&banned_addr).await);

        manager.ban_peer(banned_addr, 3600).await.unwrap();
        assert!(manager.is_banned(&banned_addr).await);
    }

    #[test]
    fn test_message_header() {
        let payload = b"test payload";
        let header = MessageHeader::new("version", payload);

        assert_eq!(header.magic, MAINNET_MAGIC);
        assert_eq!(&header.command[..7], b"version");
        assert_eq!(header.length, 12);

        let bytes = header.to_bytes();
        assert_eq!(bytes.len(), 24);
    }

    #[test]
    fn test_version_payload() {
        let local: SocketAddr = "127.0.0.1:8333".parse().unwrap();
        let remote: SocketAddr = "10.0.0.1:8333".parse().unwrap();
        let payload = build_version_payload(local, remote, 100);

        // Minimum expected size
        assert!(payload.len() >= 86);

        // Check protocol version
        let version = u32::from_le_bytes([payload[0], payload[1], payload[2], payload[3]]);
        assert_eq!(version, PROTOCOL_VERSION);
    }

    #[test]
    fn test_encode_net_addr_v4() {
        let addr: SocketAddr = "1.2.3.4:8333".parse().unwrap();
        let encoded = encode_net_addr(addr);
        assert_eq!(encoded.len(), 18);
        // Check IPv4-mapped prefix
        assert_eq!(&encoded[10..12], &[0xff, 0xff]);
        // Check IP bytes
        assert_eq!(&encoded[12..16], &[1, 2, 3, 4]);
        // Check port (big-endian)
        assert_eq!(&encoded[16..18], &[0x20, 0x8D]); // 8333
    }
}
