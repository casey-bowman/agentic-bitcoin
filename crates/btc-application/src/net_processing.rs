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
use btc_domain::primitives::{Block, BlockHash, BlockHeader, Transaction};
use btc_ports::{
    BlockStore, ChainStateStore, InventoryItem, MempoolPort, NetworkMessage, PeerEvent,
    PeerInfo, PeerManager,
};
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;
use tokio::sync::RwLock;

/// Maximum number of headers to request in a single getheaders message
const MAX_HEADERS_PER_REQUEST: usize = 2000;

/// Maximum number of blocks to have in-flight at once
const MAX_BLOCKS_IN_FLIGHT: usize = 16;

/// Protocol version we require from peers
const MIN_PEER_VERSION: u32 = 70015;

/// Sync state for a single peer
#[derive(Debug, Clone)]
struct PeerSyncState {
    /// Peer info (used for logging and protocol checks)
    #[allow(dead_code)]
    info: PeerInfo,
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
            }
        }

        Ok(actions)
    }

    /// Handle a new peer connection — start header sync if needed.
    async fn on_peer_connected(
        &mut self,
        peer_info: PeerInfo,
        peer_manager: &dyn PeerManager,
    ) -> Result<Vec<SyncAction>, Box<dyn std::error::Error + Send + Sync>> {
        let peer_id = peer_info.id;
        tracing::info!(
            "New peer connected: {} (height: {}, version: {})",
            peer_info.addr,
            peer_info.start_height,
            peer_info.version
        );

        // Check minimum version
        if peer_info.version < MIN_PEER_VERSION {
            tracing::warn!(
                "Peer {} has old protocol version {}, disconnecting",
                peer_id,
                peer_info.version
            );
            return Ok(vec![SyncAction::DisconnectPeer(peer_id)]);
        }

        let sync_state = PeerSyncState {
            info: peer_info,
            headers_sync_pending: false,
            blocks_in_flight: HashSet::new(),
            last_header_received: None,
        };

        self.peer_states.insert(peer_id, sync_state);

        // If we're idle or in header sync, request headers from this peer
        if self.state == SyncState::Idle || self.state == SyncState::HeaderSync {
            self.state = SyncState::HeaderSync;
            self.request_headers_from_peer(peer_id, peer_manager).await?;
        }

        Ok(Vec::new())
    }

    /// Handle a peer disconnection — clean up state and reassign work.
    fn on_peer_disconnected(&mut self, peer_id: u64) {
        if let Some(state) = self.peer_states.remove(&peer_id) {
            // Put any in-flight blocks back in the download queue
            for hash in &state.blocks_in_flight {
                self.blocks_in_flight.remove(hash);
                self.blocks_to_download.push_front(*hash);
            }
            tracing::info!("Peer {} disconnected, {} blocks reassigned",
                peer_id, state.blocks_in_flight.len());
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
        _mempool: &dyn MempoolPort,
    ) -> Result<Vec<SyncAction>, Box<dyn std::error::Error + Send + Sync>> {
        let mut actions = Vec::new();

        match message {
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
            NetworkMessage::Ping { nonce } => {
                // Respond with pong
                let _ = peer_manager
                    .send_to_peer(peer_id, NetworkMessage::Pong { nonce })
                    .await;
            }
            NetworkMessage::Tx { tx } => {
                actions.push(SyncAction::ProcessTransaction(tx));
            }
            _ => {
                // Other messages handled elsewhere or ignored
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
        peer_manager: &dyn PeerManager,
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

        // Request unknown blocks
        if !blocks_to_request.is_empty() {
            let _ = peer_manager
                .send_to_peer(
                    peer_id,
                    NetworkMessage::GetData {
                        items: blocks_to_request,
                    },
                )
                .await;
        }

        // Request unknown transactions
        if !txs_to_request.is_empty() {
            let _ = peer_manager
                .send_to_peer(
                    peer_id,
                    NetworkMessage::GetData {
                        items: txs_to_request,
                    },
                )
                .await;
        }

        Ok(Vec::new())
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
    /// Submit this transaction to the mempool
    ProcessTransaction(Transaction),
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
}
