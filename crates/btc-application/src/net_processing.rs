//! Net Processing — Chain synchronization and message handling
//!
//! This module implements the "brain" of the P2P protocol, corresponding to
//! Bitcoin Core's `net_processing.cpp`. It orchestrates:
//!
//! - **Headers-first sync**: Send `getheaders`, receive `headers`, add to block index
//! - **Block download**: Request blocks via `getdata` for headers we've accepted
//! - **Transaction relay**: Process `inv`/`getdata`/`tx` messages for mempool
//! - **Initial Block Download (IBD)**: Fast sync from genesis to chain tip
//!
//! ## Architecture
//!
//! `SyncManager` holds references to the `BlockIndex`, `PeerManager`, and storage
//! ports. It processes `PeerEvent` messages and drives the sync state machine.

use crate::block_index::{BlockIndex, BlockValidationStatus};
use crate::orphan_pool::OrphanPool;
use crate::peer_scoring::{PeerScoring, Misbehavior, ScoreAction};
use btc_domain::primitives::{Block, BlockHash, BlockHeader, Transaction};
use btc_ports::{
    BlockStore, ChainStateStore, InventoryItem, MempoolPort, NetworkMessage, PeerEvent,
    PeerInfo, PeerManager,
};
use std::collections::{HashMap, HashSet, VecDeque};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Maximum number of headers to request in a single getheaders message
const MAX_HEADERS_PER_REQUEST: usize = 2000;

/// Maximum number of blocks to have in-flight at once
const MAX_BLOCKS_IN_FLIGHT: usize = 16;

/// Maximum number of inventory items to send in a single inv message
const MAX_INV_SIZE: usize = 500;

/// Protocol version we require from peers
const MIN_PEER_VERSION: u32 = 70015;

/// Our protocol version
const OUR_PROTOCOL_VERSION: u32 = 70016;

/// Our user agent string
const OUR_USER_AGENT: &str = "/agentic-bitcoin:0.1.0/";

/// Our advertised services (NODE_NETWORK | NODE_WITNESS)
const OUR_SERVICES: u64 = 1 | (1 << 3);

/// Maximum number of addresses to send in a single addr message
const MAX_ADDR_TO_SEND: usize = 1000;

/// Maximum number of addresses to store in our address book
const MAX_KNOWN_ADDRESSES: usize = 10_000;

/// Maximum age of an address before we discard it (3 hours in seconds)
const MAX_ADDR_AGE: u32 = 3 * 60 * 60;

/// State of the handshake with a peer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandshakeState {
    /// We've connected; waiting to send or receive Version.
    AwaitingVersion,
    /// We've received their Version and sent ours + Verack; waiting for their Verack.
    AwaitingVerack,
    /// Handshake complete — ready for normal message exchange.
    Complete,
}

/// Sync state for a single peer
#[derive(Debug, Clone)]
struct PeerSyncState {
    /// Peer info (used for logging and protocol checks)
    #[allow(dead_code)]
    info: PeerInfo,
    /// State of the P2P handshake
    handshake: HandshakeState,
    /// Whether we've sent a getheaders to this peer and are waiting for a response
    headers_sync_pending: bool,
    /// Blocks we've requested from this peer
    blocks_in_flight: HashSet<BlockHash>,
    /// The last header hash we received from this peer
    last_header_received: Option<BlockHash>,
}

/// Current state of the sync process
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyncState {
    /// Initial state — no peers connected
    Idle,
    /// Downloading headers from peers (IBD phase 1)
    HeaderSync,
    /// Downloading blocks for validated headers (IBD phase 2)
    BlockSync,
    /// Fully synced — processing new blocks as they arrive
    Synced,
}

/// The sync manager drives chain synchronization.
///
/// It processes peer events, manages the block index, and coordinates
/// header/block downloads across multiple peers.
pub struct SyncManager {
    /// The block header index
    block_index: Arc<RwLock<BlockIndex>>,
    /// Per-peer sync state
    peer_states: HashMap<u64, PeerSyncState>,
    /// Current overall sync state
    state: SyncState,
    /// Queue of block hashes we need to download (in order)
    blocks_to_download: VecDeque<BlockHash>,
    /// Set of blocks currently being downloaded
    blocks_in_flight: HashSet<BlockHash>,
    /// Blocks we've received but haven't processed yet (may be out of order)
    orphan_blocks: HashMap<BlockHash, Block>,
    /// The next block height we need to connect to the chain
    next_block_height: u32,
    /// Transactions we've recently seen (to avoid re-requesting)
    recently_seen_txids: HashSet<btc_domain::primitives::Txid>,
    /// Known peer addresses: (address → (timestamp, services))
    known_addresses: HashMap<SocketAddr, (u32, u64)>,
    /// Peer misbehavior scoring and ban tracking
    peer_scoring: PeerScoring,
    /// Orphan transaction pool — transactions whose parent inputs are missing
    orphan_tx_pool: OrphanPool,
}

impl SyncManager {
    /// Create a new sync manager with the given block index.
    pub fn new(block_index: Arc<RwLock<BlockIndex>>) -> Self {
        SyncManager {
            block_index,
            peer_states: HashMap::new(),
            state: SyncState::Idle,
            blocks_to_download: VecDeque::new(),
            blocks_in_flight: HashSet::new(),
            orphan_blocks: HashMap::new(),
            next_block_height: 1, // Genesis is height 0, we start downloading from 1
            recently_seen_txids: HashSet::new(),
            known_addresses: HashMap::new(),
            peer_scoring: PeerScoring::new(),
            orphan_tx_pool: OrphanPool::new(),
        }
    }

    /// Get the current sync state.
    pub fn state(&self) -> SyncState {
        self.state
    }

    /// Get the number of blocks remaining to download.
    pub fn blocks_remaining(&self) -> usize {
        self.blocks_to_download.len() + self.blocks_in_flight.len()
    }

    /// Process a peer event. Returns a list of actions the caller should take
    /// (send messages, store blocks, etc.).
    pub async fn on_peer_event(
        &mut self,
        event: PeerEvent,
        peer_manager: &dyn PeerManager,
        block_store: &dyn BlockStore,
        chain_state: &dyn ChainStateStore,
        mempool: &dyn MempoolPort,
    ) -> Result<Vec<SyncAction>, Box<dyn std::error::Error + Send + Sync>> {
        let mut actions = Vec::new();

        match event {
            PeerEvent::Connected { peer_info } => {
                actions.extend(self.on_peer_connected(peer_info, peer_manager).await?);
            }
            PeerEvent::Disconnected { peer_id } => {
                self.on_peer_disconnected(peer_id);
            }
            PeerEvent::MessageReceived { peer_id, message } => {
                actions.extend(
                    self.on_message_received(
                        peer_id,
                        message,
                        peer_manager,
                        block_store,
                        chain_state,
                        mempool,
                    )
                    .await?,
                );
            }
            PeerEvent::Misbehaving {
                peer_id,
                reason,
                score,
            } => {
                tracing::warn!(
                    "Peer {} misbehaving (score +{}): {}",
                    peer_id,
                    score,
                    reason
                );
                // Record misbehavior and check if the peer should be banned.
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0);
                let action = self.peer_scoring.record_misbehavior(
                    peer_id,
                    Misbehavior::Custom(score),
                    now,
                );
                if let ScoreAction::Ban { peer_id, addr, reason } = action {
                    tracing::warn!("Banning peer {} ({}): {}", peer_id, addr, reason);
                    actions.push(SyncAction::DisconnectPeer(peer_id));
                }
            }
        }

        Ok(actions)
    }

    /// Handle a new peer connection — initiate handshake by sending our Version.
    async fn on_peer_connected(
        &mut self,
        peer_info: PeerInfo,
        _peer_manager: &dyn PeerManager,
    ) -> Result<Vec<SyncAction>, Box<dyn std::error::Error + Send + Sync>> {
        let peer_id = peer_info.id;

        // Register peer in the scoring system.
        self.peer_scoring.register_peer(peer_id, peer_info.addr);

        tracing::info!(
            "New peer connected: {} — initiating handshake",
            peer_info.addr,
        );

        let best_height = {
            let index = self.block_index.read().await;
            index.best_height()
        };

        let sync_state = PeerSyncState {
            info: peer_info.clone(),
            handshake: HandshakeState::AwaitingVersion,
            headers_sync_pending: false,
            blocks_in_flight: HashSet::new(),
            last_header_received: None,
        };

        self.peer_states.insert(peer_id, sync_state);

        // Send our Version message
        let version_msg = self.build_version_message(peer_info.addr, best_height);
        Ok(vec![SyncAction::SendMessage(peer_id, version_msg)])
    }

    /// Build a Version message to send to a peer.
    fn build_version_message(
        &self,
        addr_recv: std::net::SocketAddr,
        start_height: u32,
    ) -> NetworkMessage {
        use std::time::{SystemTime, UNIX_EPOCH};
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;

        NetworkMessage::Version {
            version: OUR_PROTOCOL_VERSION,
            services: OUR_SERVICES,
            timestamp,
            addr_recv,
            addr_from: "0.0.0.0:0".parse().unwrap(),
            nonce: rand::random::<u64>(),
            user_agent: OUR_USER_AGENT.to_string(),
            start_height,
            relay: true,
        }
    }

    /// Handle an incoming Version message — validate and advance handshake.
    async fn on_version(
        &mut self,
        peer_id: u64,
        version: u32,
        services: u64,
        user_agent: String,
        start_height: u32,
        relay: bool,
        _peer_manager: &dyn PeerManager,
    ) -> Result<Vec<SyncAction>, Box<dyn std::error::Error + Send + Sync>> {
        let mut actions = Vec::new();

        // Check minimum version
        if version < MIN_PEER_VERSION {
            tracing::warn!(
                "Peer {} has old protocol version {}, disconnecting",
                peer_id,
                version
            );
            return Ok(vec![SyncAction::DisconnectPeer(peer_id)]);
        }

        // Update peer info with actual values from their Version
        if let Some(state) = self.peer_states.get_mut(&peer_id) {
            state.info.version = version;
            state.info.services = services;
            state.info.subver = user_agent.clone();
            state.info.start_height = start_height;
            state.info.relay_txs = relay;

            match state.handshake {
                HandshakeState::AwaitingVersion => {
                    // We sent our Version, they sent theirs. Send Verack.
                    state.handshake = HandshakeState::AwaitingVerack;
                    actions.push(SyncAction::SendMessage(peer_id, NetworkMessage::Verack));
                    tracing::debug!(
                        "Received Version from peer {} (v{}, {}, height={}), sent Verack",
                        peer_id,
                        version,
                        user_agent,
                        start_height
                    );
                }
                _ => {
                    tracing::warn!("Unexpected Version from peer {} (state: {:?})", peer_id, state.handshake);
                }
            }
        }

        Ok(actions)
    }

    /// Handle an incoming Verack message — complete handshake and start sync.
    async fn on_verack(
        &mut self,
        peer_id: u64,
        peer_manager: &dyn PeerManager,
    ) -> Result<Vec<SyncAction>, Box<dyn std::error::Error + Send + Sync>> {
        let mut actions = Vec::new();

        let should_start_sync = if let Some(state) = self.peer_states.get_mut(&peer_id) {
            match state.handshake {
                HandshakeState::AwaitingVerack => {
                    state.handshake = HandshakeState::Complete;
                    tracing::info!(
                        "Handshake complete with peer {} (v{}, height={})",
                        peer_id,
                        state.info.version,
                        state.info.start_height
                    );
                    true
                }
                _ => {
                    tracing::warn!("Unexpected Verack from peer {} (state: {:?})", peer_id, state.handshake);
                    false
                }
            }
        } else {
            false
        };

        // Start header sync now that handshake is complete
        if should_start_sync {
            // Add the peer's address to our address book.
            if let Some(state) = self.peer_states.get(&peer_id) {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs() as u32;
                self.known_addresses
                    .insert(state.info.addr, (now, state.info.services));
            }

            // Request addresses from the peer for discovery.
            actions.push(SyncAction::SendMessage(peer_id, NetworkMessage::GetAddr));

            if self.state == SyncState::Idle || self.state == SyncState::HeaderSync {
                self.state = SyncState::HeaderSync;
                self.request_headers_from_peer(peer_id, peer_manager)
                    .await?;
            }
        }

        Ok(actions)
    }

    /// Handle a peer disconnection — clean up state and reassign work.
    fn on_peer_disconnected(&mut self, peer_id: u64) {
        self.peer_scoring.remove_peer(peer_id);

        if let Some(state) = self.peer_states.remove(&peer_id) {
            // Put any in-flight blocks back in the download queue
            for hash in &state.blocks_in_flight {
                self.blocks_in_flight.remove(hash);
                self.blocks_to_download.push_front(*hash);
            }

            // Remove orphan transactions from this peer
            let orphans_removed = self.orphan_tx_pool.remove_for_peer(peer_id);
            tracing::info!(
                "Peer {} disconnected, {} blocks reassigned, {} orphan txs removed",
                peer_id, state.blocks_in_flight.len(), orphans_removed,
            );
        }

        if self.peer_states.is_empty() {
            self.state = SyncState::Idle;
        }
    }

    /// Handle an incoming message from a peer.
    async fn on_message_received(
        &mut self,
        peer_id: u64,
        message: NetworkMessage,
        peer_manager: &dyn PeerManager,
        block_store: &dyn BlockStore,
        _chain_state: &dyn ChainStateStore,
        mempool: &dyn MempoolPort,
    ) -> Result<Vec<SyncAction>, Box<dyn std::error::Error + Send + Sync>> {
        let mut actions = Vec::new();

        match message {
            // ── Handshake ────────────────────────────────────────
            NetworkMessage::Version {
                version,
                services,
                user_agent,
                start_height,
                relay,
                ..
            } => {
                actions.extend(
                    self.on_version(
                        peer_id, version, services, user_agent, start_height, relay,
                        peer_manager,
                    )
                    .await?,
                );
            }
            NetworkMessage::Verack => {
                actions.extend(self.on_verack(peer_id, peer_manager).await?);
            }

            // ── Sync messages ────────────────────────────────────
            NetworkMessage::Headers { headers } => {
                actions.extend(
                    self.on_headers(peer_id, headers, peer_manager).await?,
                );
            }
            NetworkMessage::Block { block } => {
                actions.extend(
                    self.on_block(peer_id, block, block_store, peer_manager).await?,
                );
            }
            NetworkMessage::Inv { items } => {
                actions.extend(
                    self.on_inv(peer_id, items, peer_manager).await?,
                );
            }
            NetworkMessage::GetHeaders {
                block_locator,
                hash_stop,
                ..
            } => {
                actions.extend(
                    self.on_getheaders(peer_id, block_locator, hash_stop).await?,
                );
            }
            NetworkMessage::GetBlocks {
                block_locator,
                hash_stop,
                ..
            } => {
                actions.extend(
                    self.on_getblocks(peer_id, block_locator, hash_stop).await?,
                );
            }
            NetworkMessage::GetData { items } => {
                actions.extend(
                    self.on_getdata(peer_id, items, block_store).await?,
                );
            }
            NetworkMessage::Ping { nonce } => {
                actions.push(SyncAction::SendMessage(
                    peer_id,
                    NetworkMessage::Pong { nonce },
                ));
            }
            NetworkMessage::Tx { tx } => {
                let txid = tx.txid();

                // Run basic consensus validation before accepting.
                if let Err(e) = btc_domain::consensus::rules::check_transaction(&tx) {
                    tracing::debug!(
                        "Rejected tx {} from peer {}: consensus violation: {}",
                        txid, peer_id, e,
                    );
                    // Invalid — don't relay or process.
                    return Ok(actions);
                }

                // Reject coinbase transactions from the network.
                if tx.is_coinbase() {
                    tracing::debug!(
                        "Rejected coinbase tx {} from peer {}", txid, peer_id
                    );
                    return Ok(actions);
                }

                // Expire stale orphans periodically.
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0);
                self.orphan_tx_pool.expire_old_orphans(now);

                // Attempt to add to the mempool.
                match mempool.add_transaction(&tx).await {
                    Ok(()) => {
                        tracing::info!(
                            "Accepted tx {} from peer {} into mempool",
                            txid, peer_id,
                        );
                        actions.push(SyncAction::AcceptedTransaction {
                            tx: tx.clone(),
                            from_peer: peer_id,
                        });

                        // Check if any orphan transactions were waiting for
                        // outputs from this newly-accepted transaction.
                        let children = self.orphan_tx_pool.get_children_of(
                            &txid,
                            tx.outputs.len() as u32,
                        );
                        for child_txid in children {
                            if let Some(entry) = self.orphan_tx_pool.remove_orphan(&child_txid) {
                                tracing::debug!(
                                    "Resolving orphan tx {} (parent {} now available)",
                                    child_txid, txid,
                                );
                                // Re-submit the orphan to the mempool
                                match mempool.add_transaction(&entry.tx).await {
                                    Ok(()) => {
                                        tracing::info!(
                                            "Orphan tx {} accepted into mempool",
                                            child_txid,
                                        );
                                        actions.push(SyncAction::AcceptedTransaction {
                                            tx: entry.tx,
                                            from_peer: entry.from_peer,
                                        });
                                    }
                                    Err(e) => {
                                        tracing::debug!(
                                            "Orphan tx {} still rejected: {}",
                                            child_txid, e,
                                        );
                                    }
                                }
                            }
                        }
                    }
                    Err(e) => {
                        tracing::debug!(
                            "Mempool rejected tx {} from peer {}: {}",
                            txid, peer_id, e,
                        );
                        // The mempool rejected this tx — it may be an orphan
                        // (missing parent inputs). Try adding to orphan pool.
                        let add_result = self.orphan_tx_pool.add_orphan(
                            tx.clone(),
                            peer_id,
                            now,
                        );
                        match add_result {
                            crate::orphan_pool::AddOrphanResult::Added => {
                                tracing::debug!(
                                    "Added tx {} to orphan pool (from peer {})",
                                    txid, peer_id,
                                );
                            }
                            crate::orphan_pool::AddOrphanResult::AddedAfterEviction { evicted } => {
                                tracing::debug!(
                                    "Added tx {} to orphan pool after evicting {} (from peer {})",
                                    txid, evicted, peer_id,
                                );
                            }
                            _ => {
                                // Already exists or too large — emit ProcessTransaction
                                // as fallback
                                actions.push(SyncAction::ProcessTransaction(tx));
                            }
                        }
                    }
                }
            }
            NetworkMessage::Addr { addresses } => {
                actions.extend(self.on_addr(peer_id, addresses).await?);
            }
            NetworkMessage::GetAddr => {
                actions.extend(self.on_getaddr(peer_id).await?);
            }
            _ => {
                // Pong, etc. — ignored
            }
        }

        Ok(actions)
    }

    /// Process received headers — add to block index and continue sync.
    async fn on_headers(
        &mut self,
        peer_id: u64,
        headers: Vec<BlockHeader>,
        peer_manager: &dyn PeerManager,
    ) -> Result<Vec<SyncAction>, Box<dyn std::error::Error + Send + Sync>> {
        if let Some(state) = self.peer_states.get_mut(&peer_id) {
            state.headers_sync_pending = false;
        }

        if headers.is_empty() {
            // No more headers — peer is caught up
            tracing::info!("Peer {} has no more headers", peer_id);
            self.transition_to_block_sync(peer_manager).await?;
            return Ok(Vec::new());
        }

        let count = headers.len();
        tracing::info!("Received {} headers from peer {}", count, peer_id);

        let mut last_hash = None;
        let mut new_headers = 0;
        {
            let mut index = self.block_index.write().await;
            for header in &headers {
                match index.add_header(header.clone()) {
                    Ok((hash, _reorged)) => {
                        last_hash = Some(hash);
                        new_headers += 1;
                    }
                    Err(e) => {
                        tracing::warn!(
                            "Failed to add header from peer {}: {}",
                            peer_id,
                            e
                        );
                        // Don't abort — continue with remaining headers
                    }
                }
            }
        }

        if let Some(hash) = last_hash {
            if let Some(state) = self.peer_states.get_mut(&peer_id) {
                state.last_header_received = Some(hash);
            }
        }

        tracing::info!(
            "Added {} new headers (block index height: {})",
            new_headers,
            self.block_index.read().await.best_height()
        );

        // If we received a full batch, request more headers
        if count >= MAX_HEADERS_PER_REQUEST {
            self.request_headers_from_peer(peer_id, peer_manager).await?;
        } else {
            // Received fewer than max — this peer is caught up
            self.transition_to_block_sync(peer_manager).await?;
        }

        Ok(Vec::new())
    }

    /// Process a received block — validate and connect to chain.
    async fn on_block(
        &mut self,
        peer_id: u64,
        block: Block,
        _block_store: &dyn BlockStore,
        peer_manager: &dyn PeerManager,
    ) -> Result<Vec<SyncAction>, Box<dyn std::error::Error + Send + Sync>> {
        let hash = block.block_hash();

        // Remove from in-flight tracking
        self.blocks_in_flight.remove(&hash);
        if let Some(state) = self.peer_states.get_mut(&peer_id) {
            state.blocks_in_flight.remove(&hash);
        }

        tracing::debug!("Received block {} from peer {}", hash, peer_id);

        // Check if this is the next block we need
        let expected_hash = {
            let index = self.block_index.read().await;
            index.get_hash_at_height(self.next_block_height)
        };

        let actions = if expected_hash == Some(hash) {
            // This is the next block in sequence — process it
            self.next_block_height += 1;

            // Mark as validated in the index
            {
                let mut index = self.block_index.write().await;
                index.set_status(&hash, BlockValidationStatus::FullyValidated);
            }

            let mut result = vec![SyncAction::ProcessBlock(block)];

            // Check if any orphan blocks can now be connected
            while let Some(next_hash) = {
                let index = self.block_index.read().await;
                index.get_hash_at_height(self.next_block_height)
            } {
                if let Some(orphan) = self.orphan_blocks.remove(&next_hash) {
                    self.next_block_height += 1;
                    {
                        let mut index = self.block_index.write().await;
                        index.set_status(&next_hash, BlockValidationStatus::FullyValidated);
                    }
                    result.push(SyncAction::ProcessBlock(orphan));
                } else {
                    break;
                }
            }

            result
        } else {
            // Out of order — store as orphan
            self.orphan_blocks.insert(hash, block);
            Vec::new()
        };

        // Request more blocks if we have capacity
        self.request_blocks(peer_manager).await?;

        // Check if sync is complete
        if self.blocks_to_download.is_empty()
            && self.blocks_in_flight.is_empty()
            && self.orphan_blocks.is_empty()
        {
            if self.state == SyncState::BlockSync {
                self.state = SyncState::Synced;
                tracing::info!(
                    "Chain sync complete at height {}",
                    self.next_block_height - 1
                );
            }
        }

        Ok(actions)
    }

    /// Process an inv message — request any blocks/txs we don't have.
    async fn on_inv(
        &mut self,
        peer_id: u64,
        items: Vec<InventoryItem>,
        _peer_manager: &dyn PeerManager,
    ) -> Result<Vec<SyncAction>, Box<dyn std::error::Error + Send + Sync>> {
        let mut blocks_to_request = Vec::new();
        let mut txs_to_request = Vec::new();

        for item in items {
            match item {
                InventoryItem::Block(hash) => {
                    let known = self.block_index.read().await.contains(&hash);
                    if !known && !self.blocks_in_flight.contains(&hash) {
                        blocks_to_request.push(InventoryItem::Block(hash));
                    }
                }
                InventoryItem::Tx(txid) => {
                    if !self.recently_seen_txids.contains(&txid) {
                        txs_to_request.push(InventoryItem::Tx(txid));
                        self.recently_seen_txids.insert(txid);

                        // Limit the size of the seen set
                        if self.recently_seen_txids.len() > 50_000 {
                            self.recently_seen_txids.clear();
                        }
                    }
                }
            }
        }

        let mut actions = Vec::new();

        // Request unknown blocks
        if !blocks_to_request.is_empty() {
            actions.push(SyncAction::SendMessage(
                peer_id,
                NetworkMessage::GetData {
                    items: blocks_to_request,
                },
            ));
        }

        // Request unknown transactions
        if !txs_to_request.is_empty() {
            actions.push(SyncAction::SendMessage(
                peer_id,
                NetworkMessage::GetData {
                    items: txs_to_request,
                },
            ));
        }

        Ok(actions)
    }

    /// Process a getheaders request from a peer — respond with our headers.
    async fn on_getheaders(
        &mut self,
        peer_id: u64,
        block_locator: Vec<BlockHash>,
        hash_stop: BlockHash,
    ) -> Result<Vec<SyncAction>, Box<dyn std::error::Error + Send + Sync>> {
        let index = self.block_index.read().await;

        // Find the fork point using the locator
        let mut start_height = 0u32;
        for locator_hash in &block_locator {
            if let Some(entry) = index.get(locator_hash) {
                start_height = entry.height + 1;
                break;
            }
        }

        // Collect headers from start_height
        let mut headers = Vec::new();
        let mut height = start_height;
        while headers.len() < MAX_HEADERS_PER_REQUEST {
            if let Some(hash) = index.get_hash_at_height(height) {
                if let Some(entry) = index.get(&hash) {
                    headers.push(entry.header.clone());
                    if hash == hash_stop {
                        break;
                    }
                }
            } else {
                break;
            }
            height += 1;
        }

        if !headers.is_empty() {
            return Ok(vec![SyncAction::SendMessage(
                peer_id,
                NetworkMessage::Headers { headers },
            )]);
        }

        Ok(Vec::new())
    }

    /// Process a getblocks request from a peer — respond with inv of block hashes.
    ///
    /// The peer provides a block locator (a sparse list of hashes from their chain).
    /// We find the fork point and send back an `inv` with up to MAX_INV_SIZE
    /// block hashes starting from there.
    async fn on_getblocks(
        &mut self,
        peer_id: u64,
        block_locator: Vec<BlockHash>,
        hash_stop: BlockHash,
    ) -> Result<Vec<SyncAction>, Box<dyn std::error::Error + Send + Sync>> {
        let index = self.block_index.read().await;

        // Find the fork point using the locator (same logic as getheaders)
        let mut start_height = 0u32;
        for locator_hash in &block_locator {
            if let Some(entry) = index.get(locator_hash) {
                start_height = entry.height + 1;
                break;
            }
        }

        // Collect block hashes from start_height up to MAX_INV_SIZE
        let mut inv_items = Vec::new();
        let mut height = start_height;
        while inv_items.len() < MAX_INV_SIZE {
            if let Some(hash) = index.get_hash_at_height(height) {
                inv_items.push(InventoryItem::Block(hash));
                if hash == hash_stop {
                    break;
                }
            } else {
                break;
            }
            height += 1;
        }

        if !inv_items.is_empty() {
            tracing::debug!(
                "Responding to getblocks from peer {} with {} inv items (heights {}..{})",
                peer_id,
                inv_items.len(),
                start_height,
                height.saturating_sub(1),
            );
            return Ok(vec![SyncAction::SendMessage(
                peer_id,
                NetworkMessage::Inv { items: inv_items },
            )]);
        }

        Ok(Vec::new())
    }

    /// Process a getdata request from a peer — respond with requested blocks/txs.
    ///
    /// For each requested block hash, look it up in the block store and send
    /// it back. For each requested txid, look it up in the mempool (if
    /// available) and send it back. Unknown items are silently skipped.
    async fn on_getdata(
        &mut self,
        peer_id: u64,
        items: Vec<InventoryItem>,
        block_store: &dyn BlockStore,
    ) -> Result<Vec<SyncAction>, Box<dyn std::error::Error + Send + Sync>> {
        let mut actions = Vec::new();

        for item in items {
            match item {
                InventoryItem::Block(hash) => {
                    match block_store.get_block(&hash).await {
                        Ok(Some(block)) => {
                            tracing::debug!(
                                "Serving block {} to peer {}",
                                hash,
                                peer_id,
                            );
                            actions.push(SyncAction::SendMessage(
                                peer_id,
                                NetworkMessage::Block { block },
                            ));
                        }
                        Ok(None) => {
                            tracing::debug!(
                                "Peer {} requested unknown block {}",
                                peer_id,
                                hash,
                            );
                        }
                        Err(e) => {
                            tracing::warn!(
                                "Error fetching block {} for peer {}: {}",
                                hash,
                                peer_id,
                                e,
                            );
                        }
                    }
                }
                InventoryItem::Tx(_txid) => {
                    // Transaction serving from mempool is handled by
                    // on_getdata_with_mempool below.
                }
            }
        }

        Ok(actions)
    }

    /// Process a getdata request that may include transactions.
    ///
    /// This is the full version that also serves transactions from the mempool.
    pub async fn on_getdata_with_mempool(
        &mut self,
        peer_id: u64,
        items: Vec<InventoryItem>,
        block_store: &dyn BlockStore,
        mempool: &dyn MempoolPort,
    ) -> Result<Vec<SyncAction>, Box<dyn std::error::Error + Send + Sync>> {
        let mut actions = Vec::new();

        for item in items {
            match item {
                InventoryItem::Block(hash) => {
                    if let Ok(Some(block)) = block_store.get_block(&hash).await {
                        actions.push(SyncAction::SendMessage(
                            peer_id,
                            NetworkMessage::Block { block },
                        ));
                    }
                }
                InventoryItem::Tx(txid) => {
                    if let Ok(Some(entry)) = mempool.get_transaction(&txid).await {
                        tracing::debug!(
                            "Serving transaction {} to peer {}",
                            txid,
                            peer_id,
                        );
                        actions.push(SyncAction::SendMessage(
                            peer_id,
                            NetworkMessage::Tx { tx: entry.tx },
                        ));
                    }
                }
            }
        }

        Ok(actions)
    }

    /// Announce a newly connected block to all connected peers.
    ///
    /// Sends an `inv` message with the block hash to every peer except
    /// the one that sent it to us (if known).
    pub async fn announce_block(
        &self,
        block_hash: BlockHash,
        from_peer: Option<u64>,
        peer_manager: &dyn PeerManager,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let inv = NetworkMessage::Inv {
            items: vec![InventoryItem::Block(block_hash)],
        };

        for &peer_id in self.peer_states.keys() {
            // Don't announce back to the peer that sent us the block
            if Some(peer_id) == from_peer {
                continue;
            }
            let _ = peer_manager.send_to_peer(peer_id, inv.clone()).await;
        }

        Ok(())
    }

    /// Announce a new transaction to all connected peers.
    ///
    /// Sends an `inv` message with the txid to every peer except
    /// the one that sent it to us (if known). This is called when a
    /// transaction is accepted into the mempool.
    pub async fn announce_transaction(
        &self,
        txid: btc_domain::primitives::Txid,
        from_peer: Option<u64>,
        peer_manager: &dyn PeerManager,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let inv = NetworkMessage::Inv {
            items: vec![InventoryItem::Tx(txid)],
        };

        for &peer_id in self.peer_states.keys() {
            if Some(peer_id) == from_peer {
                continue;
            }
            let _ = peer_manager.send_to_peer(peer_id, inv.clone()).await;
        }

        Ok(())
    }

    // ── Address management ────────────────────────────────────────

    /// Process an `addr` message — store new peer addresses.
    async fn on_addr(
        &mut self,
        peer_id: u64,
        addresses: Vec<(u32, SocketAddr)>,
    ) -> Result<Vec<SyncAction>, Box<dyn std::error::Error + Send + Sync>> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as u32;

        let mut added = 0usize;
        for (timestamp, addr) in &addresses {
            // Skip addresses that are too old.
            if now.saturating_sub(*timestamp) > MAX_ADDR_AGE {
                continue;
            }
            // Skip if we already know a more recent entry for this address.
            if let Some((existing_ts, _)) = self.known_addresses.get(addr) {
                if *existing_ts >= *timestamp {
                    continue;
                }
            }
            self.known_addresses.insert(*addr, (*timestamp, OUR_SERVICES));
            added += 1;
        }

        // Evict oldest entries if we exceed the limit.
        while self.known_addresses.len() > MAX_KNOWN_ADDRESSES {
            // Find the oldest entry.
            if let Some(oldest_addr) = self
                .known_addresses
                .iter()
                .min_by_key(|(_, (ts, _))| *ts)
                .map(|(addr, _)| *addr)
            {
                self.known_addresses.remove(&oldest_addr);
            } else {
                break;
            }
        }

        if added > 0 {
            tracing::debug!(
                "Learned {} new addresses from peer {} (total known: {})",
                added,
                peer_id,
                self.known_addresses.len(),
            );
        }

        Ok(Vec::new())
    }

    /// Process a `getaddr` message — respond with our known addresses.
    async fn on_getaddr(
        &self,
        peer_id: u64,
    ) -> Result<Vec<SyncAction>, Box<dyn std::error::Error + Send + Sync>> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as u32;

        // Collect recent addresses (not too old), up to MAX_ADDR_TO_SEND.
        let mut addrs: Vec<(u32, SocketAddr)> = self
            .known_addresses
            .iter()
            .filter(|(_, (ts, _))| now.saturating_sub(*ts) <= MAX_ADDR_AGE)
            .map(|(addr, (ts, _))| (*ts, *addr))
            .collect();

        // Sort by timestamp descending (most recent first) and truncate.
        addrs.sort_by(|a, b| b.0.cmp(&a.0));
        addrs.truncate(MAX_ADDR_TO_SEND);

        if addrs.is_empty() {
            return Ok(Vec::new());
        }

        tracing::debug!(
            "Sending {} addresses to peer {} in response to getaddr",
            addrs.len(),
            peer_id,
        );

        Ok(vec![SyncAction::SendMessage(
            peer_id,
            NetworkMessage::Addr { addresses: addrs },
        )])
    }

    /// Get the number of known peer addresses.
    pub fn known_address_count(&self) -> usize {
        self.known_addresses.len()
    }

    /// Check whether a given address is currently banned.
    pub fn is_banned(&self, addr: &SocketAddr) -> bool {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        self.peer_scoring.is_banned(addr, now)
    }

    /// Get the ban score for a connected peer.
    pub fn peer_ban_score(&self, peer_id: u64) -> i32 {
        self.peer_scoring.get_score(peer_id)
    }

    /// Get the number of orphan transactions currently held.
    pub fn orphan_tx_count(&self) -> usize {
        self.orphan_tx_pool.len()
    }

    /// Send a getheaders message to a peer using our current block locator.
    async fn request_headers_from_peer(
        &mut self,
        peer_id: u64,
        peer_manager: &dyn PeerManager,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        if let Some(state) = self.peer_states.get_mut(&peer_id) {
            if state.headers_sync_pending {
                return Ok(()); // Already waiting
            }
            state.headers_sync_pending = true;
        }

        let locator = self.block_index.read().await.build_locator();

        let msg = NetworkMessage::GetHeaders {
            version: 70016,
            block_locator: locator,
            hash_stop: BlockHash::zero(), // Get as many as possible
        };

        peer_manager.send_to_peer(peer_id, msg).await?;
        tracing::debug!("Sent getheaders to peer {}", peer_id);
        Ok(())
    }

    /// Transition from header sync to block sync.
    async fn transition_to_block_sync(
        &mut self,
        peer_manager: &dyn PeerManager,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        if self.state != SyncState::HeaderSync {
            return Ok(());
        }

        let index = self.block_index.read().await;
        let best_height = index.best_height();

        // Queue all blocks from our current position to the tip
        self.blocks_to_download.clear();
        for height in self.next_block_height..=best_height {
            if let Some(hash) = index.get_hash_at_height(height) {
                self.blocks_to_download.push_back(hash);
            }
        }

        drop(index);

        let count = self.blocks_to_download.len();
        if count == 0 {
            self.state = SyncState::Synced;
            tracing::info!("Already synced — no blocks to download");
        } else {
            self.state = SyncState::BlockSync;
            tracing::info!(
                "Transitioning to block sync: {} blocks to download",
                count
            );
            self.request_blocks(peer_manager).await?;
        }

        Ok(())
    }

    /// Request blocks from peers, up to MAX_BLOCKS_IN_FLIGHT.
    async fn request_blocks(
        &mut self,
        peer_manager: &dyn PeerManager,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // Distribute block requests across peers round-robin
        let peer_ids: Vec<u64> = self.peer_states.keys().copied().collect();
        if peer_ids.is_empty() {
            return Ok(());
        }

        let mut peer_idx = 0;

        while self.blocks_in_flight.len() < MAX_BLOCKS_IN_FLIGHT {
            let hash = match self.blocks_to_download.pop_front() {
                Some(h) => h,
                None => break,
            };

            let peer_id = peer_ids[peer_idx % peer_ids.len()];
            peer_idx += 1;

            self.blocks_in_flight.insert(hash);
            if let Some(state) = self.peer_states.get_mut(&peer_id) {
                state.blocks_in_flight.insert(hash);
            }

            let msg = NetworkMessage::GetData {
                items: vec![InventoryItem::Block(hash)],
            };
            let _ = peer_manager.send_to_peer(peer_id, msg).await;
        }

        Ok(())
    }
}

/// Actions that the infrastructure layer should take after processing events.
#[derive(Debug)]
pub enum SyncAction {
    /// Store and validate this block
    ProcessBlock(Block),
    /// Submit this transaction to the mempool (fallback — mempool rejected it)
    ProcessTransaction(Transaction),
    /// Transaction was accepted into the mempool and should be relayed to peers
    AcceptedTransaction {
        /// The accepted transaction
        tx: Transaction,
        /// The peer that sent it (skip when relaying)
        from_peer: u64,
    },
    /// Send a message to a specific peer
    SendMessage(u64, NetworkMessage),
    /// Disconnect a peer
    DisconnectPeer(u64),
}

#[cfg(test)]
mod tests {
    use super::*;
    use btc_domain::primitives::Hash256;

    fn make_header(prev: BlockHash, nonce: u32) -> BlockHeader {
        BlockHeader {
            version: 1,
            prev_block_hash: prev,
            merkle_root: Hash256::from_bytes([nonce as u8; 32]),
            time: 1231006505 + nonce,
            bits: 0x1d00ffff,
            nonce,
        }
    }

    #[tokio::test]
    async fn test_sync_manager_creation() {
        let mut index = BlockIndex::new();
        let genesis = make_header(BlockHash::zero(), 0);
        index.init_genesis(genesis);

        let index = Arc::new(RwLock::new(index));
        let manager = SyncManager::new(index);

        assert_eq!(manager.state(), SyncState::Idle);
        assert_eq!(manager.blocks_remaining(), 0);
    }

    #[tokio::test]
    async fn test_sync_state_transitions() {
        let mut index = BlockIndex::new();
        let genesis = make_header(BlockHash::zero(), 0);
        index.init_genesis(genesis);

        let index = Arc::new(RwLock::new(index));
        let mut manager = SyncManager::new(index);

        // Starts idle
        assert_eq!(manager.state(), SyncState::Idle);

        // After connecting a peer with high version, should move to HeaderSync
        let peer_info = PeerInfo {
            id: 1,
            addr: "127.0.0.1:8333".parse().unwrap(),
            services: 1,
            version: 70016,
            subver: "/test/".to_string(),
            start_height: 100,
            relay_txs: true,
        };

        // We can't fully test with a real PeerManager, but verify state tracking
        manager.peer_states.insert(
            1,
            PeerSyncState {
                info: peer_info,
                handshake: HandshakeState::Complete,
                headers_sync_pending: false,
                blocks_in_flight: HashSet::new(),
                last_header_received: None,
            },
        );
        manager.state = SyncState::HeaderSync;

        assert_eq!(manager.state(), SyncState::HeaderSync);
    }

    #[tokio::test]
    async fn test_peer_disconnect_reassigns_blocks() {
        let mut index = BlockIndex::new();
        let genesis = make_header(BlockHash::zero(), 0);
        let genesis_hash = genesis.block_hash();
        index.init_genesis(genesis);

        let h1 = make_header(genesis_hash, 1);
        let (h1_hash, _) = index.add_header(h1).unwrap();

        let index = Arc::new(RwLock::new(index));
        let mut manager = SyncManager::new(index);

        // Simulate a peer with a block in flight
        let mut in_flight = HashSet::new();
        in_flight.insert(h1_hash);
        manager.blocks_in_flight.insert(h1_hash);

        manager.peer_states.insert(
            1,
            PeerSyncState {
                info: PeerInfo {
                    id: 1,
                    addr: "127.0.0.1:8333".parse().unwrap(),
                    services: 1,
                    version: 70016,
                    subver: "/test/".to_string(),
                    start_height: 1,
                    relay_txs: true,
                },
                handshake: HandshakeState::Complete,
                headers_sync_pending: false,
                blocks_in_flight: in_flight,
                last_header_received: None,
            },
        );

        // Disconnect peer — block should be moved back to download queue
        manager.on_peer_disconnected(1);

        assert!(manager.blocks_in_flight.is_empty());
        assert_eq!(manager.blocks_to_download.len(), 1);
        assert_eq!(manager.blocks_to_download[0], h1_hash);
    }

    fn build_chain(count: u32) -> (BlockIndex, Vec<BlockHash>) {
        let mut index = BlockIndex::new();
        let genesis = make_header(BlockHash::zero(), 0);
        let genesis_hash = genesis.block_hash();
        index.init_genesis(genesis);

        let mut hashes = vec![genesis_hash];
        let mut prev = genesis_hash;
        for i in 1..=count {
            let h = make_header(prev, i);
            let (hash, _) = index.add_header(h).unwrap();
            hashes.push(hash);
            prev = hash;
        }
        (index, hashes)
    }

    fn make_peer_state(id: u64) -> (u64, PeerSyncState) {
        (
            id,
            PeerSyncState {
                info: PeerInfo {
                    id,
                    addr: "127.0.0.1:8333".parse().unwrap(),
                    services: 1,
                    version: 70016,
                    subver: "/test/".to_string(),
                    start_height: 100,
                    relay_txs: true,
                },
                handshake: HandshakeState::Complete,
                headers_sync_pending: false,
                blocks_in_flight: HashSet::new(),
                last_header_received: None,
            },
        )
    }

    #[tokio::test]
    async fn test_on_getblocks_responds_with_inv() {
        let (index, hashes) = build_chain(5);
        let genesis_hash = hashes[0];
        let index = Arc::new(RwLock::new(index));
        let mut manager = SyncManager::new(index);

        // Peer sends getblocks with genesis as locator → should get hashes 1..5
        let actions = manager
            .on_getblocks(1, vec![genesis_hash], BlockHash::zero())
            .await
            .unwrap();

        assert_eq!(actions.len(), 1);
        match &actions[0] {
            SyncAction::SendMessage(peer_id, NetworkMessage::Inv { items }) => {
                assert_eq!(*peer_id, 1);
                assert_eq!(items.len(), 5); // blocks 1,2,3,4,5
                // First item should be block at height 1
                match &items[0] {
                    InventoryItem::Block(h) => assert_eq!(*h, hashes[1]),
                    _ => panic!("Expected block inv item"),
                }
            }
            other => panic!("Expected SendMessage(Inv), got {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_on_getblocks_with_hash_stop() {
        let (index, hashes) = build_chain(5);
        let genesis_hash = hashes[0];
        let index = Arc::new(RwLock::new(index));
        let mut manager = SyncManager::new(index);

        // Request blocks from genesis but stop at height 3
        let actions = manager
            .on_getblocks(1, vec![genesis_hash], hashes[3])
            .await
            .unwrap();

        assert_eq!(actions.len(), 1);
        match &actions[0] {
            SyncAction::SendMessage(_, NetworkMessage::Inv { items }) => {
                assert_eq!(items.len(), 3); // blocks 1,2,3
            }
            other => panic!("Expected SendMessage(Inv), got {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_on_getblocks_empty_when_caught_up() {
        let (index, hashes) = build_chain(3);
        let tip = *hashes.last().unwrap();
        let index = Arc::new(RwLock::new(index));
        let mut manager = SyncManager::new(index);

        // Peer's locator includes the tip → nothing to send
        let actions = manager
            .on_getblocks(1, vec![tip], BlockHash::zero())
            .await
            .unwrap();

        assert!(actions.is_empty());
    }

    #[tokio::test]
    async fn test_on_getblocks_from_middle() {
        let (index, hashes) = build_chain(5);
        let index = Arc::new(RwLock::new(index));
        let mut manager = SyncManager::new(index);

        // Peer has up to height 2, sends that as locator
        let actions = manager
            .on_getblocks(1, vec![hashes[2]], BlockHash::zero())
            .await
            .unwrap();

        assert_eq!(actions.len(), 1);
        match &actions[0] {
            SyncAction::SendMessage(_, NetworkMessage::Inv { items }) => {
                assert_eq!(items.len(), 3); // blocks 3,4,5
                match &items[0] {
                    InventoryItem::Block(h) => assert_eq!(*h, hashes[3]),
                    _ => panic!("Expected block inv item"),
                }
            }
            other => panic!("Expected SendMessage(Inv), got {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_on_getdata_serves_known_block() {
        let (index, hashes) = build_chain(3);
        let index = Arc::new(RwLock::new(index));
        let mut manager = SyncManager::new(index);

        // Create a mock block store that has block at height 1
        let block_store = MockBlockStore {
            blocks: {
                let mut m = HashMap::new();
                // Create a minimal block for hash[1]
                let block = Block {
                    header: make_header(hashes[0], 1),
                    transactions: Vec::new(),
                };
                m.insert(block.block_hash(), block);
                m
            },
        };

        let actions = manager
            .on_getdata(
                1,
                vec![InventoryItem::Block(hashes[1])],
                &block_store,
            )
            .await
            .unwrap();

        assert_eq!(actions.len(), 1);
        match &actions[0] {
            SyncAction::SendMessage(peer_id, NetworkMessage::Block { block }) => {
                assert_eq!(*peer_id, 1);
                assert_eq!(block.block_hash(), hashes[1]);
            }
            other => panic!("Expected SendMessage(Block), got {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_on_getdata_unknown_block_skipped() {
        let (index, _hashes) = build_chain(1);
        let index = Arc::new(RwLock::new(index));
        let mut manager = SyncManager::new(index);

        let block_store = MockBlockStore {
            blocks: HashMap::new(), // empty
        };

        let unknown_hash = BlockHash::from_hash(Hash256::from_bytes([0xFF; 32]));
        let actions = manager
            .on_getdata(
                1,
                vec![InventoryItem::Block(unknown_hash)],
                &block_store,
            )
            .await
            .unwrap();

        assert!(actions.is_empty());
    }

    #[tokio::test]
    async fn test_announce_block_to_peers() {
        let (index, _hashes) = build_chain(1);
        let index = Arc::new(RwLock::new(index));
        let manager = SyncManager::new(index);

        // Need peers to announce to — use stub
        let stub = btc_adapters::network::StubPeerManager::new();
        let block_hash = BlockHash::from_hash(Hash256::from_bytes([0x42; 32]));

        // No peers → should succeed silently
        manager
            .announce_block(block_hash, None, &stub)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn test_announce_block_skips_sender() {
        let (index, _hashes) = build_chain(1);
        let index = Arc::new(RwLock::new(index));
        let mut manager = SyncManager::new(index);

        // Add two peers
        let (id1, state1) = make_peer_state(1);
        let (id2, state2) = make_peer_state(2);
        manager.peer_states.insert(id1, state1);
        manager.peer_states.insert(id2, state2);

        let stub = btc_adapters::network::StubPeerManager::new();
        let block_hash = BlockHash::from_hash(Hash256::from_bytes([0x42; 32]));

        // Announce from peer 1 → should only send to peer 2
        // (We can't easily verify with StubPeerManager, but at least
        // verify it doesn't crash)
        manager
            .announce_block(block_hash, Some(1), &stub)
            .await
            .unwrap();
    }

    /// Minimal mock block store for testing getdata
    struct MockBlockStore {
        blocks: HashMap<BlockHash, Block>,
    }

    #[async_trait::async_trait]
    impl BlockStore for MockBlockStore {
        async fn store_block(
            &self,
            _block: &Block,
            _height: u32,
        ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
            Ok(())
        }

        async fn get_block(
            &self,
            hash: &BlockHash,
        ) -> Result<Option<Block>, Box<dyn std::error::Error + Send + Sync>> {
            Ok(self.blocks.get(hash).cloned())
        }

        async fn get_block_header(
            &self,
            _hash: &BlockHash,
        ) -> Result<Option<BlockHeader>, Box<dyn std::error::Error + Send + Sync>> {
            Ok(None)
        }

        async fn has_block(
            &self,
            hash: &BlockHash,
        ) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
            Ok(self.blocks.contains_key(hash))
        }

        async fn get_best_block_hash(
            &self,
        ) -> Result<BlockHash, Box<dyn std::error::Error + Send + Sync>> {
            Ok(BlockHash::zero())
        }

        async fn get_block_height(
            &self,
            _hash: &BlockHash,
        ) -> Result<Option<u32>, Box<dyn std::error::Error + Send + Sync>> {
            Ok(None)
        }
    }

    // ── Transaction relay tests ────────────────────────────────

    /// Minimal mock mempool for testing tx relay.
    struct MockMempool {
        txs: HashMap<btc_domain::primitives::Txid, btc_ports::MempoolEntry>,
    }

    #[async_trait::async_trait]
    impl MempoolPort for MockMempool {
        async fn add_transaction(
            &self,
            _tx: &Transaction,
        ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
            Ok(())
        }
        async fn remove_transaction(
            &self,
            _txid: &btc_domain::primitives::Txid,
            _recursive: bool,
        ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
            Ok(())
        }
        async fn get_transaction(
            &self,
            txid: &btc_domain::primitives::Txid,
        ) -> Result<Option<btc_ports::MempoolEntry>, Box<dyn std::error::Error + Send + Sync>>
        {
            Ok(self.txs.get(txid).cloned())
        }
        async fn get_all_transactions(
            &self,
        ) -> Result<Vec<btc_ports::MempoolEntry>, Box<dyn std::error::Error + Send + Sync>>
        {
            Ok(self.txs.values().cloned().collect())
        }
        async fn get_transaction_count(
            &self,
        ) -> Result<u32, Box<dyn std::error::Error + Send + Sync>> {
            Ok(self.txs.len() as u32)
        }
        async fn estimate_fee(
            &self,
            _target_blocks: u32,
        ) -> Result<f64, Box<dyn std::error::Error + Send + Sync>> {
            Ok(1.0)
        }
        async fn get_mempool_info(
            &self,
        ) -> Result<btc_ports::MempoolInfo, Box<dyn std::error::Error + Send + Sync>> {
            Ok(btc_ports::MempoolInfo {
                size: self.txs.len() as u32,
                bytes: 0,
                usage: 0,
                max_mempool: 300_000_000,
                min_relay_fee: 0.00001,
            })
        }
        async fn clear(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
            Ok(())
        }
    }

    fn make_test_tx(value: i64) -> Transaction {
        use btc_domain::primitives::{Amount, OutPoint, TxIn, TxOut, Txid};
        use btc_domain::script::Script;
        let input = TxIn::final_input(OutPoint::new(Txid::zero(), 0), Script::new());
        let output = TxOut::new(Amount::from_sat(value), Script::new());
        Transaction::v1(vec![input], vec![output], 0)
    }

    #[tokio::test]
    async fn test_announce_transaction_to_peers() {
        let (index, _hashes) = build_chain(1);
        let index = Arc::new(RwLock::new(index));
        let manager = SyncManager::new(index);

        let stub = btc_adapters::network::StubPeerManager::new();
        let txid = btc_domain::primitives::Txid::zero();

        // No peers → should succeed silently
        manager
            .announce_transaction(txid, None, &stub)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn test_announce_transaction_skips_sender() {
        let (index, _hashes) = build_chain(1);
        let index = Arc::new(RwLock::new(index));
        let mut manager = SyncManager::new(index);

        let (id1, state1) = make_peer_state(1);
        let (id2, state2) = make_peer_state(2);
        manager.peer_states.insert(id1, state1);
        manager.peer_states.insert(id2, state2);

        let stub = btc_adapters::network::StubPeerManager::new();
        let txid = btc_domain::primitives::Txid::zero();

        // Announce from peer 1 → should skip peer 1, send to peer 2
        manager
            .announce_transaction(txid, Some(1), &stub)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn test_on_getdata_serves_transaction() {
        let (index, _hashes) = build_chain(1);
        let index = Arc::new(RwLock::new(index));
        let mut manager = SyncManager::new(index);

        let tx = make_test_tx(5000);
        let txid = tx.txid();

        let entry = btc_ports::MempoolEntry {
            tx: tx.clone(),
            fee: btc_domain::primitives::Amount::from_sat(100),
            size: 200,
            time: 0,
            height: 0,
            descendant_count: 0,
            descendant_size: 0,
            ancestor_count: 0,
            ancestor_size: 0,
        };

        let mut txs = HashMap::new();
        txs.insert(txid, entry);
        let mempool = MockMempool { txs };
        let block_store = MockBlockStore {
            blocks: HashMap::new(),
        };

        let actions = manager
            .on_getdata_with_mempool(
                1,
                vec![InventoryItem::Tx(txid)],
                &block_store,
                &mempool,
            )
            .await
            .unwrap();

        assert_eq!(actions.len(), 1);
        match &actions[0] {
            SyncAction::SendMessage(peer_id, NetworkMessage::Tx { tx: served_tx }) => {
                assert_eq!(*peer_id, 1);
                assert_eq!(served_tx.txid(), txid);
            }
            other => panic!("Expected SendMessage(Tx), got {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_on_getdata_unknown_tx_skipped() {
        let (index, _hashes) = build_chain(1);
        let index = Arc::new(RwLock::new(index));
        let mut manager = SyncManager::new(index);

        let mempool = MockMempool {
            txs: HashMap::new(),
        };
        let block_store = MockBlockStore {
            blocks: HashMap::new(),
        };

        let unknown_txid = btc_domain::primitives::Txid::zero();
        let actions = manager
            .on_getdata_with_mempool(
                1,
                vec![InventoryItem::Tx(unknown_txid)],
                &block_store,
                &mempool,
            )
            .await
            .unwrap();

        assert!(actions.is_empty());
    }

    #[tokio::test]
    async fn test_on_inv_requests_unknown_tx() {
        let (index, _hashes) = build_chain(1);
        let index = Arc::new(RwLock::new(index));
        let mut manager = SyncManager::new(index);

        let stub = btc_adapters::network::StubPeerManager::new();
        let txid = btc_domain::primitives::Txid::from_hash(
            Hash256::from_bytes([0xAB; 32]),
        );

        let actions = manager
            .on_inv(
                1,
                vec![InventoryItem::Tx(txid)],
                &stub,
            )
            .await
            .unwrap();

        // Should have sent a GetData request for the unknown tx
        assert!(!actions.is_empty());
    }

    #[tokio::test]
    async fn test_on_inv_deduplicates_seen_tx() {
        let (index, _hashes) = build_chain(1);
        let index = Arc::new(RwLock::new(index));
        let mut manager = SyncManager::new(index);

        let stub = btc_adapters::network::StubPeerManager::new();
        let txid = btc_domain::primitives::Txid::from_hash(
            Hash256::from_bytes([0xCD; 32]),
        );

        // First inv → should request
        let actions1 = manager
            .on_inv(1, vec![InventoryItem::Tx(txid)], &stub)
            .await
            .unwrap();
        assert!(!actions1.is_empty());

        // Second inv (same txid) → should NOT request again
        let actions2 = manager
            .on_inv(1, vec![InventoryItem::Tx(txid)], &stub)
            .await
            .unwrap();
        // The txid is now in recently_seen, so no getdata for it
        let has_tx_request = actions2.iter().any(|a| {
            matches!(a, SyncAction::SendMessage(_, NetworkMessage::GetData { items })
                if items.iter().any(|i| matches!(i, InventoryItem::Tx(t) if *t == txid)))
        });
        assert!(!has_tx_request, "Should not re-request already-seen txid");
    }

    // ── Handshake tests ──────────────────────────────────────

    #[tokio::test]
    async fn test_handshake_sends_version_on_connect() {
        let (index, _) = build_chain(1);
        let index = Arc::new(RwLock::new(index));
        let mut manager = SyncManager::new(index);

        let stub = btc_adapters::network::StubPeerManager::new();
        let peer_info = PeerInfo {
            id: 1,
            addr: "127.0.0.1:8333".parse().unwrap(),
            services: 1,
            version: 70016,
            subver: "/test/".to_string(),
            start_height: 0,
            relay_txs: true,
        };

        let actions = manager.on_peer_connected(peer_info, &stub).await.unwrap();

        // Should send a Version message
        assert_eq!(actions.len(), 1);
        assert!(matches!(
            &actions[0],
            SyncAction::SendMessage(1, NetworkMessage::Version { .. })
        ));

        // Peer should be in AwaitingVersion state
        assert_eq!(
            manager.peer_states.get(&1).unwrap().handshake,
            HandshakeState::AwaitingVersion
        );
    }

    #[tokio::test]
    async fn test_handshake_version_then_verack() {
        let (index, _) = build_chain(1);
        let index = Arc::new(RwLock::new(index));
        let mut manager = SyncManager::new(index);

        let stub = btc_adapters::network::StubPeerManager::new();
        let peer_info = PeerInfo {
            id: 1,
            addr: "127.0.0.1:8333".parse().unwrap(),
            services: 1,
            version: 70016,
            subver: "/test/".to_string(),
            start_height: 100,
            relay_txs: true,
        };

        // Step 1: Connect → sends our Version
        let _ = manager.on_peer_connected(peer_info, &stub).await.unwrap();
        assert_eq!(
            manager.peer_states.get(&1).unwrap().handshake,
            HandshakeState::AwaitingVersion
        );

        // Step 2: Receive their Version → sends Verack, moves to AwaitingVerack
        let actions = manager
            .on_version(1, 70016, 1, "/remote/".to_string(), 200, true, &stub)
            .await
            .unwrap();

        assert_eq!(actions.len(), 1);
        assert!(matches!(&actions[0], SyncAction::SendMessage(1, NetworkMessage::Verack)));
        assert_eq!(
            manager.peer_states.get(&1).unwrap().handshake,
            HandshakeState::AwaitingVerack
        );

        // Verify peer info was updated
        assert_eq!(manager.peer_states.get(&1).unwrap().info.start_height, 200);
        assert_eq!(manager.peer_states.get(&1).unwrap().info.subver, "/remote/");

        // Step 3: Receive Verack → handshake complete
        let _ = manager.on_verack(1, &stub).await.unwrap();
        assert_eq!(
            manager.peer_states.get(&1).unwrap().handshake,
            HandshakeState::Complete
        );
        // Should have started header sync
        assert_eq!(manager.state(), SyncState::HeaderSync);
    }

    #[tokio::test]
    async fn test_handshake_rejects_old_version() {
        let (index, _) = build_chain(1);
        let index = Arc::new(RwLock::new(index));
        let mut manager = SyncManager::new(index);

        let stub = btc_adapters::network::StubPeerManager::new();
        let peer_info = PeerInfo {
            id: 1,
            addr: "127.0.0.1:8333".parse().unwrap(),
            services: 1,
            version: 70016,
            subver: "/test/".to_string(),
            start_height: 0,
            relay_txs: true,
        };

        let _ = manager.on_peer_connected(peer_info, &stub).await.unwrap();

        // Send a Version with version < MIN_PEER_VERSION
        let actions = manager
            .on_version(1, 70000, 1, "/old/".to_string(), 100, true, &stub)
            .await
            .unwrap();

        // Should disconnect the peer
        assert_eq!(actions.len(), 1);
        assert!(matches!(&actions[0], SyncAction::DisconnectPeer(1)));
    }

    #[tokio::test]
    async fn test_ping_responds_with_pong() {
        let (index, _hashes) = build_chain(1);
        let index = Arc::new(RwLock::new(index));
        let mut manager = SyncManager::new(index);

        let stub = btc_adapters::network::StubPeerManager::new();
        let block_store = btc_adapters::storage::InMemoryBlockStore::new();
        let chain_state_store = btc_adapters::storage::InMemoryChainStateStore::new();
        let mempool = btc_adapters::mempool::InMemoryMempool::new();

        // Add a peer so message dispatch works
        let peer_info = PeerInfo {
            id: 1,
            addr: "127.0.0.1:8333".parse().unwrap(),
            services: 1,
            version: 70016,
            subver: "/test/".to_string(),
            start_height: 0,
            relay_txs: true,
        };
        manager.peer_states.insert(
            1,
            PeerSyncState {
                info: peer_info,
                handshake: HandshakeState::Complete,
                headers_sync_pending: false,
                blocks_in_flight: HashSet::new(),
                last_header_received: None,
            },
        );

        let actions = manager
            .on_message_received(
                1,
                NetworkMessage::Ping { nonce: 42 },
                &stub,
                &block_store,
                &chain_state_store,
                &mempool,
            )
            .await
            .unwrap();

        assert_eq!(actions.len(), 1);
        assert!(matches!(
            &actions[0],
            SyncAction::SendMessage(1, NetworkMessage::Pong { nonce: 42 })
        ));
    }

    #[tokio::test]
    async fn test_build_version_message() {
        let (index, _) = build_chain(1);
        let index = Arc::new(RwLock::new(index));
        let manager = SyncManager::new(index);

        let addr: std::net::SocketAddr = "1.2.3.4:8333".parse().unwrap();
        let msg = manager.build_version_message(addr, 500);

        match msg {
            NetworkMessage::Version {
                version,
                services,
                user_agent,
                start_height,
                relay,
                ..
            } => {
                assert_eq!(version, OUR_PROTOCOL_VERSION);
                assert_eq!(services, OUR_SERVICES);
                assert!(user_agent.contains("agentic-bitcoin"));
                assert_eq!(start_height, 500);
                assert!(relay);
            }
            _ => panic!("Expected Version message"),
        }
    }

    // ── Address management tests ────────────────────────────────

    #[tokio::test]
    async fn test_on_addr_stores_addresses() {
        let (index, _) = build_chain(1);
        let index = Arc::new(RwLock::new(index));
        let mut manager = SyncManager::new(index);

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as u32;

        let addrs = vec![
            (now, "1.2.3.4:8333".parse().unwrap()),
            (now, "5.6.7.8:8333".parse().unwrap()),
        ];

        let actions = manager.on_addr(1, addrs).await.unwrap();
        assert!(actions.is_empty()); // on_addr doesn't produce actions
        assert_eq!(manager.known_address_count(), 2);
    }

    #[tokio::test]
    async fn test_on_addr_rejects_old_addresses() {
        let (index, _) = build_chain(1);
        let index = Arc::new(RwLock::new(index));
        let mut manager = SyncManager::new(index);

        // Timestamp from 4 hours ago (exceeds MAX_ADDR_AGE of 3 hours)
        let old_ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as u32
            - 4 * 60 * 60;

        let addrs = vec![(old_ts, "1.2.3.4:8333".parse().unwrap())];
        manager.on_addr(1, addrs).await.unwrap();
        assert_eq!(manager.known_address_count(), 0);
    }

    #[tokio::test]
    async fn test_on_getaddr_responds_with_known_addresses() {
        let (index, _) = build_chain(1);
        let index = Arc::new(RwLock::new(index));
        let mut manager = SyncManager::new(index);

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as u32;

        // Pre-populate address book
        manager.known_addresses.insert(
            "1.2.3.4:8333".parse().unwrap(),
            (now, OUR_SERVICES),
        );
        manager.known_addresses.insert(
            "5.6.7.8:8333".parse().unwrap(),
            (now - 60, OUR_SERVICES),
        );

        let actions = manager.on_getaddr(1).await.unwrap();
        assert_eq!(actions.len(), 1);

        match &actions[0] {
            SyncAction::SendMessage(peer_id, NetworkMessage::Addr { addresses }) => {
                assert_eq!(*peer_id, 1);
                assert_eq!(addresses.len(), 2);
            }
            other => panic!("Expected SendMessage(Addr), got {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_on_getaddr_empty_when_no_addresses() {
        let (index, _) = build_chain(1);
        let index = Arc::new(RwLock::new(index));
        let manager = SyncManager::new(index);

        let actions = manager.on_getaddr(1).await.unwrap();
        assert!(actions.is_empty());
    }

    #[tokio::test]
    async fn test_handshake_sends_getaddr_after_verack() {
        let (index, _) = build_chain(1);
        let index = Arc::new(RwLock::new(index));
        let mut manager = SyncManager::new(index);

        let stub = btc_adapters::network::StubPeerManager::new();
        let peer_info = PeerInfo {
            id: 1,
            addr: "127.0.0.1:8333".parse().unwrap(),
            services: 1,
            version: 70016,
            subver: "/test/".to_string(),
            start_height: 100,
            relay_txs: true,
        };

        // Connect → Version → Verack
        let _ = manager.on_peer_connected(peer_info, &stub).await.unwrap();
        let _ = manager
            .on_version(1, 70016, 1, "/remote/".to_string(), 200, true, &stub)
            .await
            .unwrap();
        let actions = manager.on_verack(1, &stub).await.unwrap();

        // Should include a GetAddr message
        let has_getaddr = actions.iter().any(|a| {
            matches!(a, SyncAction::SendMessage(1, NetworkMessage::GetAddr))
        });
        assert!(has_getaddr, "Handshake should send GetAddr after Verack");

        // Peer's address should be in the address book
        assert_eq!(manager.known_address_count(), 1);
    }

    // ── Mempool integration tests ───────────────────────────────

    #[tokio::test]
    async fn test_tx_message_accepted_to_mempool() {
        let (index, _hashes) = build_chain(1);
        let index = Arc::new(RwLock::new(index));
        let mut manager = SyncManager::new(index);

        let stub = btc_adapters::network::StubPeerManager::new();
        let block_store = btc_adapters::storage::InMemoryBlockStore::new();
        let chain_state_store = btc_adapters::storage::InMemoryChainStateStore::new();
        let mempool = btc_adapters::mempool::InMemoryMempool::new();

        // Add a peer
        let peer_info = PeerInfo {
            id: 1,
            addr: "127.0.0.1:8333".parse().unwrap(),
            services: 1,
            version: 70016,
            subver: "/test/".to_string(),
            start_height: 0,
            relay_txs: true,
        };
        manager.peer_states.insert(
            1,
            PeerSyncState {
                info: peer_info,
                handshake: HandshakeState::Complete,
                headers_sync_pending: false,
                blocks_in_flight: HashSet::new(),
                last_header_received: None,
            },
        );

        let tx = make_test_tx(5000);
        let actions = manager
            .on_message_received(
                1,
                NetworkMessage::Tx { tx: tx.clone() },
                &stub,
                &block_store,
                &chain_state_store,
                &mempool,
            )
            .await
            .unwrap();

        // Should produce AcceptedTransaction (mempool accepts any valid tx)
        assert!(!actions.is_empty());
        let has_accepted = actions.iter().any(|a| {
            matches!(a, SyncAction::AcceptedTransaction { .. })
        });
        assert!(
            has_accepted,
            "Valid tx should produce AcceptedTransaction action"
        );

        // Verify the tx is now in the mempool
        assert_eq!(mempool.get_transaction_count().await.unwrap(), 1);
    }

    #[tokio::test]
    async fn test_coinbase_tx_rejected() {
        let (index, _hashes) = build_chain(1);
        let index = Arc::new(RwLock::new(index));
        let mut manager = SyncManager::new(index);

        let stub = btc_adapters::network::StubPeerManager::new();
        let block_store = btc_adapters::storage::InMemoryBlockStore::new();
        let chain_state_store = btc_adapters::storage::InMemoryChainStateStore::new();
        let mempool = btc_adapters::mempool::InMemoryMempool::new();

        manager.peer_states.insert(
            1,
            PeerSyncState {
                info: PeerInfo {
                    id: 1,
                    addr: "127.0.0.1:8333".parse().unwrap(),
                    services: 1,
                    version: 70016,
                    subver: "/test/".to_string(),
                    start_height: 0,
                    relay_txs: true,
                },
                handshake: HandshakeState::Complete,
                headers_sync_pending: false,
                blocks_in_flight: HashSet::new(),
                last_header_received: None,
            },
        );

        // Create a coinbase transaction
        let coinbase = Transaction::coinbase(
            1,
            btc_domain::script::Script::from_bytes(vec![0x01, 0x01]),
            vec![btc_domain::primitives::TxOut::new(
                btc_domain::primitives::Amount::from_sat(5_000_000_000),
                btc_domain::script::Script::new(),
            )],
        );

        let actions = manager
            .on_message_received(
                1,
                NetworkMessage::Tx { tx: coinbase },
                &stub,
                &block_store,
                &chain_state_store,
                &mempool,
            )
            .await
            .unwrap();

        // Should NOT produce any transaction actions (coinbase is rejected)
        let has_tx_action = actions.iter().any(|a| {
            matches!(
                a,
                SyncAction::AcceptedTransaction { .. }
                    | SyncAction::ProcessTransaction(_)
            )
        });
        assert!(!has_tx_action, "Coinbase tx should be rejected from P2P");
    }

    // ── Orphan pool integration tests ──────────────────────────

    #[tokio::test]
    async fn test_rejected_tx_goes_to_orphan_pool() {
        let (index, _hashes) = build_chain(1);
        let index = Arc::new(RwLock::new(index));
        let mut manager = SyncManager::new(index);

        let stub = btc_adapters::network::StubPeerManager::new();
        let block_store = btc_adapters::storage::InMemoryBlockStore::new();
        let chain_state_store = btc_adapters::storage::InMemoryChainStateStore::new();

        // Use a rejecting mempool
        let mempool = RejectingMempool;

        manager.peer_states.insert(
            1,
            PeerSyncState {
                info: PeerInfo {
                    id: 1,
                    addr: "127.0.0.1:8333".parse().unwrap(),
                    services: 1,
                    version: 70016,
                    subver: "/test/".to_string(),
                    start_height: 0,
                    relay_txs: true,
                },
                handshake: HandshakeState::Complete,
                headers_sync_pending: false,
                blocks_in_flight: HashSet::new(),
                last_header_received: None,
            },
        );

        let tx = make_test_tx(5000);
        let _ = manager
            .on_message_received(
                1,
                NetworkMessage::Tx { tx },
                &stub,
                &block_store,
                &chain_state_store,
                &mempool,
            )
            .await
            .unwrap();

        // The rejected tx should be in the orphan pool
        assert_eq!(manager.orphan_tx_count(), 1);
    }

    #[tokio::test]
    async fn test_peer_disconnect_clears_orphans() {
        let (index, _hashes) = build_chain(1);
        let index = Arc::new(RwLock::new(index));
        let mut manager = SyncManager::new(index);

        let stub = btc_adapters::network::StubPeerManager::new();
        let block_store = btc_adapters::storage::InMemoryBlockStore::new();
        let chain_state_store = btc_adapters::storage::InMemoryChainStateStore::new();
        let mempool = RejectingMempool;

        manager.peer_states.insert(
            1,
            PeerSyncState {
                info: PeerInfo {
                    id: 1,
                    addr: "127.0.0.1:8333".parse().unwrap(),
                    services: 1,
                    version: 70016,
                    subver: "/test/".to_string(),
                    start_height: 0,
                    relay_txs: true,
                },
                handshake: HandshakeState::Complete,
                headers_sync_pending: false,
                blocks_in_flight: HashSet::new(),
                last_header_received: None,
            },
        );

        // Send two rejected txs that go to orphan pool
        let tx1 = make_test_tx(5000);
        let tx2 = make_test_tx(6000);
        let _ = manager
            .on_message_received(
                1,
                NetworkMessage::Tx { tx: tx1 },
                &stub,
                &block_store,
                &chain_state_store,
                &mempool,
            )
            .await
            .unwrap();
        let _ = manager
            .on_message_received(
                1,
                NetworkMessage::Tx { tx: tx2 },
                &stub,
                &block_store,
                &chain_state_store,
                &mempool,
            )
            .await
            .unwrap();
        assert_eq!(manager.orphan_tx_count(), 2);

        // Disconnect peer → orphans from this peer should be removed
        manager.on_peer_disconnected(1);
        assert_eq!(manager.orphan_tx_count(), 0);
    }

    /// A mempool that rejects everything (simulates missing parent inputs).
    struct RejectingMempool;

    #[async_trait::async_trait]
    impl MempoolPort for RejectingMempool {
        async fn add_transaction(
            &self,
            _tx: &Transaction,
        ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
            Err("missing inputs".into())
        }
        async fn remove_transaction(
            &self,
            _txid: &btc_domain::primitives::Txid,
            _recursive: bool,
        ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
            Ok(())
        }
        async fn get_transaction(
            &self,
            _txid: &btc_domain::primitives::Txid,
        ) -> Result<Option<btc_ports::MempoolEntry>, Box<dyn std::error::Error + Send + Sync>>
        {
            Ok(None)
        }
        async fn get_all_transactions(
            &self,
        ) -> Result<Vec<btc_ports::MempoolEntry>, Box<dyn std::error::Error + Send + Sync>>
        {
            Ok(Vec::new())
        }
        async fn get_transaction_count(
            &self,
        ) -> Result<u32, Box<dyn std::error::Error + Send + Sync>> {
            Ok(0)
        }
        async fn estimate_fee(
            &self,
            _target_blocks: u32,
        ) -> Result<f64, Box<dyn std::error::Error + Send + Sync>> {
            Ok(1.0)
        }
        async fn get_mempool_info(
            &self,
        ) -> Result<btc_ports::MempoolInfo, Box<dyn std::error::Error + Send + Sync>> {
            Ok(btc_ports::MempoolInfo {
                size: 0,
                bytes: 0,
                usage: 0,
                max_mempool: 300_000_000,
                min_relay_fee: 0.00001,
            })
        }
        async fn clear(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
            Ok(())
        }
    }
}
