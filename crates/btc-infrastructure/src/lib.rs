//! Bitcoin Infrastructure Layer - Composition Root
//!
//! This is the outermost layer that wires everything together.
//! It serves as the composition root for dependency injection and
//! the entry point for the entire Bitcoin implementation.

use btc_adapters::{
    InMemoryBlockStore, InMemoryChainStateStore, InMemoryMempool, InMemoryWallet,
    StubPeerManager, TcpPeerManager, JsonRpcServer, SimpleMiner,
};
use btc_application::block_index::BlockIndex;
use btc_application::fee_estimator::FeeEstimator;
use btc_application::net_processing::{SyncAction, SyncManager, SyncState};
use btc_application::rebroadcast::RebroadcastManager;
use btc_application::services::{BlockchainService, MempoolService, MiningService};
use btc_application::handlers::{BlockchainRpcHandler, MiningRpcHandler, WalletRpcHandler};
use btc_domain::ChainParams;
use btc_domain::wallet::address::AddressType;
use btc_ports::{BlockStore, ChainStateStore, MempoolPort, PeerEvent, PeerManager, RpcServer, WalletPort};
use clap::Parser;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing_subscriber::EnvFilter;

/// Command-line arguments for the Bitcoin node
#[derive(Parser, Debug)]
#[command(
    name = "Agentic Bitcoin",
    about = "A Bitcoin Core reimplementation in Rust with hexagonal architecture",
    version
)]
pub struct CliArgs {
    /// Network to connect to (mainnet, testnet, regtest, signet)
    #[arg(long, default_value = "mainnet")]
    pub network: String,

    /// Data directory for storing blockchain data
    #[arg(long, default_value = "~/.bitcoin")]
    pub datadir: String,

    /// RPC server port
    #[arg(long, default_value = "8332")]
    pub rpc_port: u16,

    /// P2P network port
    #[arg(long, default_value = "8333")]
    pub p2p_port: u16,

    /// Log level (trace, debug, info, warn, error)
    #[arg(long, default_value = "info")]
    pub log_level: String,

    /// Maximum mempool size in megabytes
    #[arg(long, default_value = "300")]
    pub max_mempool_mb: u64,

    /// Enable real TCP P2P networking (default: stub/offline mode)
    #[arg(long, default_value = "false")]
    pub enable_p2p: bool,

    /// Seed peer addresses (comma-separated) for initial connections
    #[arg(long, value_delimiter = ',')]
    pub seed_peers: Vec<String>,

    /// Storage backend: "memory" (default) or "rocksdb" (requires rocksdb-storage feature)
    #[arg(long, default_value = "memory")]
    pub storage_backend: String,

    /// Enable wallet functionality
    #[arg(long, default_value = "true")]
    pub enable_wallet: bool,

    /// Wallet address type: "bech32" (P2WPKH, default), "legacy" (P2PKH), or "p2sh-segwit" (P2SH-P2WPKH)
    #[arg(long, default_value = "bech32")]
    pub address_type: String,
}

/// Application state containing all services and ports
pub struct BitcoinNode {
    pub blockchain: Arc<BlockchainService>,
    pub mempool: Arc<MempoolService>,
    pub mining: Arc<MiningService>,
    pub rpc_server: Arc<JsonRpcServer>,
    pub peer_manager: Arc<dyn PeerManager>,
    pub mempool_adapter: Arc<InMemoryMempool>,
    pub block_index: Arc<RwLock<BlockIndex>>,
    pub sync_manager: Arc<RwLock<SyncManager>>,
    /// Fee estimator — updated every time a block is connected
    pub fee_estimator: Arc<RwLock<FeeEstimator>>,
    /// Rebroadcast manager — tracks wallet txs for periodic re-announcement
    pub rebroadcast_manager: Arc<RwLock<RebroadcastManager>>,
    /// Block store (for sync manager use)
    block_store: Arc<dyn BlockStore>,
    /// Chain state store (for sync manager use)
    chain_state: Arc<dyn ChainStateStore>,
    /// Optional TCP peer manager (only when enable_p2p is true)
    tcp_peer_manager: Option<Arc<TcpPeerManager>>,
    /// Seed peers to connect to on start
    seed_peers: Vec<String>,
    /// Wallet (optional — only when enable_wallet is true)
    pub wallet: Option<Arc<dyn WalletPort>>,
}

impl BitcoinNode {
    /// Create and wire all components
    pub async fn new(args: CliArgs) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        // Initialize tracing/logging.
        // Use try_init() so that concurrent tests (or repeated calls) don't
        // panic if a global subscriber has already been installed.
        let _ = tracing_subscriber::fmt()
            .with_env_filter(
                EnvFilter::try_from_default_env()
                    .unwrap_or_else(|_| EnvFilter::new(&args.log_level))
            )
            .try_init();

        tracing::info!("Initializing Agentic Bitcoin node on {}", args.network);

        // Parse network
        let network = match args.network.as_str() {
            "mainnet" => btc_domain::Network::Mainnet,
            "testnet" => btc_domain::Network::Testnet,
            "regtest" => btc_domain::Network::Regtest,
            "signet" => btc_domain::Network::Signet,
            _ => {
                return Err(format!("Unknown network: {}", args.network).into());
            }
        };

        let chain_params = ChainParams::for_network(network);
        tracing::info!("Using chain parameters for {}", network);

        // Create storage adapters based on backend flag
        let (block_store, chain_state): (Arc<dyn BlockStore>, Arc<dyn ChainStateStore>) =
            match args.storage_backend.as_str() {
                #[cfg(feature = "rocksdb-storage")]
                "rocksdb" => {
                    use btc_adapters::{RocksDbBlockStore, RocksDbChainStateStore};
                    use std::path::Path;

                    let datadir = args.datadir.replace('~', &std::env::var("HOME").unwrap_or_default());
                    let blocks_path = format!("{}/blocks", datadir);
                    let chainstate_path = format!("{}/chainstate", datadir);

                    // Create directories if they don't exist
                    std::fs::create_dir_all(&blocks_path)?;
                    std::fs::create_dir_all(&chainstate_path)?;

                    tracing::info!(
                        "Using RocksDB storage (blocks: {}, chainstate: {})",
                        blocks_path,
                        chainstate_path
                    );

                    let bs = Arc::new(RocksDbBlockStore::open(Path::new(&blocks_path))?);
                    let cs = Arc::new(RocksDbChainStateStore::open(Path::new(&chainstate_path))?);
                    (bs as Arc<dyn BlockStore>, cs as Arc<dyn ChainStateStore>)
                }
                #[cfg(not(feature = "rocksdb-storage"))]
                "rocksdb" => {
                    return Err(
                        "RocksDB storage requires the 'rocksdb-storage' feature. \
                         Build with: cargo build --features rocksdb-storage"
                            .into(),
                    );
                }
                _ => {
                    tracing::info!("Using in-memory storage backend");
                    let bs = Arc::new(InMemoryBlockStore::new());
                    let cs = Arc::new(InMemoryChainStateStore::new());
                    (bs as Arc<dyn BlockStore>, cs as Arc<dyn ChainStateStore>)
                }
            };

        let rpc_server = Arc::new(JsonRpcServer::new(args.rpc_port));
        let mempool_adapter = Arc::new(
            InMemoryMempool::with_max_bytes(args.max_mempool_mb * 1_000_000)
        );

        // Create peer manager: real TCP or stub depending on flag
        let (peer_manager, tcp_peer_manager): (Arc<dyn PeerManager>, Option<Arc<TcpPeerManager>>) =
            if args.enable_p2p {
                let local_addr: std::net::SocketAddr =
                    format!("0.0.0.0:{}", args.p2p_port).parse()?;
                let tcp_mgr = Arc::new(TcpPeerManager::new(local_addr));
                tracing::info!("P2P networking enabled on port {}", args.p2p_port);
                (tcp_mgr.clone() as Arc<dyn PeerManager>, Some(tcp_mgr))
            } else {
                let stub = Arc::new(StubPeerManager::new());
                tracing::info!("P2P networking disabled (stub mode)");
                (stub as Arc<dyn PeerManager>, None)
            };

        // Initialize with genesis block.
        // We use store_block + write_chain_tip which ARE on the traits,
        // rather than init_with_genesis which is only on concrete types.
        let genesis = chain_params.genesis_block();
        let genesis_hash = genesis.block_hash();

        // Store genesis block at height 0
        if !block_store.has_block(&genesis_hash).await.unwrap_or(false) {
            block_store.store_block(&genesis, 0).await
                .map_err(|e| format!("Failed to store genesis block: {}", e))?;
        }

        // Set chain tip to genesis
        chain_state.write_chain_tip(genesis_hash, 0).await
            .map_err(|e| format!("Failed to set genesis chain tip: {}", e))?;

        tracing::info!("Initialized blockchain with genesis block: {}", genesis_hash);

        // Initialize block index with genesis header and checkpoints
        let mut block_index = BlockIndex::new();
        block_index.init_genesis(genesis.header.clone());
        block_index.load_checkpoints(&chain_params.checkpoints);
        let block_index = Arc::new(RwLock::new(block_index));

        tracing::info!("Block index initialized with genesis header");

        // Create sync manager
        let sync_manager = Arc::new(RwLock::new(SyncManager::new(block_index.clone())));

        // Create application services
        let blockchain = Arc::new(BlockchainService::new(
            block_store.clone(),
            chain_state.clone(),
            peer_manager.clone(),
        ));

        // Wire the real mempool adapter
        let mempool = Arc::new(MempoolService::new(
            mempool_adapter.clone() as Arc<dyn MempoolPort>,
            chain_state.clone(),
        ));

        let template_provider = Arc::new(SimpleMiner::new());
        let mining = Arc::new(MiningService::new(template_provider, blockchain.clone()));

        // Create fee estimator
        let fee_estimator = Arc::new(RwLock::new(FeeEstimator::new()));

        // Create rebroadcast manager
        let rebroadcast_manager = Arc::new(RwLock::new(RebroadcastManager::new()));

        // Register RPC handlers
        let bc_handler = Box::new(BlockchainRpcHandler::new(blockchain.clone(), mempool.clone(), fee_estimator.clone(), chain_state.clone(), block_index.clone()));
        rpc_server.register_handler(bc_handler).await?;

        let mining_handler = Box::new(MiningRpcHandler::new(mining.clone()));
        rpc_server.register_handler(mining_handler).await?;

        // Create wallet if enabled
        let mainnet = matches!(network, btc_domain::Network::Mainnet);
        let wallet: Option<Arc<dyn WalletPort>> = if args.enable_wallet {
            let addr_type = match args.address_type.as_str() {
                "legacy" | "p2pkh" => AddressType::P2PKH,
                "p2sh-segwit" | "p2sh" => AddressType::P2shP2wpkh,
                _ => AddressType::P2WPKH, // "bech32" and default
            };

            let wallet = Arc::new(InMemoryWallet::new(mainnet, addr_type));
            tracing::info!("Wallet enabled (address type: {})", args.address_type);

            // Register wallet RPC handler
            let wallet_handler = Box::new(WalletRpcHandler::new(wallet.clone() as Arc<dyn WalletPort>));
            rpc_server.register_handler(wallet_handler).await?;

            Some(wallet as Arc<dyn WalletPort>)
        } else {
            tracing::info!("Wallet disabled");
            None
        };

        tracing::info!("Agentic Bitcoin node initialized successfully");

        Ok(BitcoinNode {
            blockchain,
            mempool,
            mining,
            rpc_server,
            peer_manager,
            mempool_adapter,
            block_index,
            sync_manager,
            fee_estimator,
            rebroadcast_manager,
            block_store,
            chain_state,
            tcp_peer_manager,
            seed_peers: args.seed_peers,
            wallet,
        })
    }

    /// Start the Bitcoin node
    pub async fn start(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        tracing::info!("Starting Agentic Bitcoin node");

        // Start RPC server (now actually listens for HTTP connections)
        self.rpc_server.start().await?;
        tracing::info!("RPC server started on port {}", self.rpc_server.get_port());

        // Connect to seed peers if P2P is enabled
        if !self.seed_peers.is_empty() {
            for seed in &self.seed_peers {
                match seed.parse::<std::net::SocketAddr>() {
                    Ok(addr) => {
                        match self.peer_manager.connect_peer(addr).await {
                            Ok(id) => tracing::info!("Connected to seed peer {} (id: {})", addr, id),
                            Err(e) => tracing::warn!("Failed to connect to seed peer {}: {}", addr, e),
                        }
                    }
                    Err(e) => tracing::warn!("Invalid seed peer address '{}': {}", seed, e),
                }
            }
        }

        // Start background tasks
        self.start_background_tasks().await;

        Ok(())
    }

    /// Launch background processing loops
    async fn start_background_tasks(&self) {
        // Mempool maintenance loop - periodically log mempool stats
        let mempool_adapter = self.mempool_adapter.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(60));
            loop {
                interval.tick().await;
                let size = mempool_adapter.size().await;
                if size > 0 {
                    tracing::info!("Mempool: {} transactions", size);
                }
            }
        });

        // Peer connection maintenance loop
        let peer_manager = self.peer_manager.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(30));
            loop {
                interval.tick().await;
                match peer_manager.get_connected_peers().await {
                    Ok(peers) => {
                        if !peers.is_empty() {
                            tracing::debug!("Connected peers: {}", peers.len());
                        }
                    }
                    Err(e) => tracing::debug!("Error checking peers: {}", e),
                }
            }
        });

        // Sync status reporting loop
        let sync_manager = self.sync_manager.clone();
        let block_index = self.block_index.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(10));
            loop {
                interval.tick().await;
                let sm = sync_manager.read().await;
                let state = sm.state();
                let remaining = sm.blocks_remaining();
                drop(sm);

                let idx = block_index.read().await;
                let height = idx.best_height();
                let headers = idx.header_count();
                drop(idx);

                match state {
                    SyncState::HeaderSync => {
                        tracing::info!(
                            "Sync: downloading headers ({} known, height {})",
                            headers,
                            height
                        );
                    }
                    SyncState::BlockSync => {
                        tracing::info!(
                            "Sync: downloading blocks ({} remaining, index height {})",
                            remaining,
                            height
                        );
                    }
                    SyncState::Synced => {
                        tracing::debug!(
                            "Sync: fully synced at height {} ({} headers)",
                            height,
                            headers
                        );
                    }
                    SyncState::Idle => {
                        // Don't spam in idle
                    }
                }
            }
        });

        // Transaction rebroadcast loop
        let rebroadcast_mgr = self.rebroadcast_manager.clone();
        let rebroadcast_mempool = self.mempool_adapter.clone();
        let rebroadcast_peers = self.peer_manager.clone();
        tokio::spawn(async move {
            // Check every 5 minutes
            let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(5 * 60));
            loop {
                interval.tick().await;
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0);

                let mempool_ref = &rebroadcast_mempool;
                let mut mgr = rebroadcast_mgr.write().await;

                // Collect txids to check before the closure
                let tracked_txids: Vec<btc_domain::primitives::Txid> = mgr
                    .check_rebroadcast(now, |txid| {
                        // Synchronous check — we can't await inside the closure.
                        // The InMemoryMempool uses async, so we approximate: always
                        // return true and let the actual inv send be best-effort.
                        let _ = txid;
                        true
                    })
                    .into_iter()
                    .filter_map(|action| match action {
                        btc_application::rebroadcast::RebroadcastAction::Reannounce(txid) => {
                            Some(txid)
                        }
                        btc_application::rebroadcast::RebroadcastAction::Abandon(txid) => {
                            tracing::info!("Abandoning rebroadcast of tx {}", txid);
                            None
                        }
                    })
                    .collect();

                drop(mgr);

                for txid in tracked_txids {
                    // Check mempool async and announce
                    if let Ok(Some(_)) = mempool_ref.get_transaction(&txid).await {
                        let inv = btc_ports::NetworkMessage::Inv {
                            items: vec![btc_ports::InventoryItem::Tx(txid)],
                        };
                        if let Ok(peers) = rebroadcast_peers.get_connected_peers().await {
                            for peer in peers {
                                let _ = rebroadcast_peers
                                    .send_to_peer(peer.id, inv.clone())
                                    .await;
                            }
                        }
                        tracing::debug!("Rebroadcast tx {} to peers", txid);
                    }
                }
            }
        });

        // Ping/keepalive loop for TCP peers
        if let Some(ref tcp_mgr) = self.tcp_peer_manager {
            let tcp = tcp_mgr.clone();
            tokio::spawn(async move {
                let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(120));
                loop {
                    interval.tick().await;
                    let count = tcp.peer_count().await;
                    if count > 0 {
                        tracing::debug!("TCP peers alive: {}", count);
                    }
                }
            });
        }

        tracing::info!("Background tasks started");
    }

    /// Process a peer event through the sync manager.
    ///
    /// This is the main entry point for handling P2P messages. It delegates
    /// to the SyncManager, which returns a list of actions to execute.
    pub async fn handle_peer_event(
        &self,
        event: PeerEvent,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let actions = {
            let mut sm = self.sync_manager.write().await;
            sm.on_peer_event(
                event,
                self.peer_manager.as_ref(),
                self.block_store.as_ref(),
                self.chain_state.as_ref(),
                self.mempool_adapter.as_ref(),
            )
            .await?
        };

        // Execute returned actions
        for action in actions {
            match action {
                SyncAction::ProcessBlock(block) => {
                    match self.blockchain.validate_and_accept_block(&block).await {
                        Ok(_) => {
                            // Block accepted — feed fee estimator with confirmed tx fee rates.
                            let info = self.chain_state.get_best_chain_tip().await;
                            let height = info.map(|(_, h)| h).unwrap_or(0);

                            let confirmed_fees: Vec<(btc_domain::primitives::Amount, usize, u32)> =
                                block.transactions.iter().filter_map(|tx| {
                                    if tx.is_coinbase() {
                                        return None;
                                    }
                                    // Approximate fee: we don't have input values readily,
                                    // so use a heuristic — the mempool had the fee when we
                                    // accepted the tx.  For now, estimate 1 sat/vB minimum
                                    // as a placeholder; real fee calculation requires UTXO lookup.
                                    let vsize = tx.compute_vsize() as usize;
                                    let estimated_fee = btc_domain::primitives::Amount::from_sat(
                                        vsize as i64, // ~1 sat/vB estimate
                                    );
                                    Some((estimated_fee, vsize, 1u32))
                                }).collect();

                            if !confirmed_fees.is_empty() {
                                let mut est = self.fee_estimator.write().await;
                                est.process_block(height, &confirmed_fees);
                                tracing::debug!(
                                    "Fee estimator updated: height={}, txs={}",
                                    height, confirmed_fees.len()
                                );
                            }
                        }
                        Err(e) => {
                            tracing::warn!("Failed to accept block {}: {}", block.block_hash(), e);
                        }
                    }
                }
                SyncAction::ProcessTransaction(tx) => {
                    if let Err(e) = self.blockchain.process_new_transaction(&tx).await {
                        tracing::debug!("Failed to process tx {}: {}", tx.txid(), e);
                    } else {
                        // Valid transaction — add to mempool
                        if let Err(e) = self.mempool_adapter.add_transaction(&tx).await {
                            tracing::debug!("Failed to add tx {} to mempool: {}", tx.txid(), e);
                        } else {
                            // Relay to peers
                            let _ = self.peer_manager.broadcast_transaction(&tx).await;
                        }
                    }
                }
                SyncAction::SendMessage(peer_id, msg) => {
                    if let Err(e) = self.peer_manager.send_to_peer(peer_id, msg).await {
                        tracing::debug!("Failed to send message to peer {}: {}", peer_id, e);
                    }
                }
                SyncAction::AcceptedTransaction { tx, from_peer } => {
                    // Transaction was already accepted into the mempool by the
                    // SyncManager. Relay it to all other peers.
                    tracing::info!(
                        "Relaying accepted tx {} (from peer {})",
                        tx.txid(),
                        from_peer,
                    );
                    let _ = self.peer_manager.broadcast_transaction(&tx).await;
                }
                SyncAction::DisconnectPeer(peer_id) => {
                    let _ = self.peer_manager.disconnect_peer(peer_id).await;
                }
            }
        }

        Ok(())
    }

    /// Stop the Bitcoin node
    pub async fn stop(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        tracing::info!("Stopping Agentic Bitcoin node");

        self.rpc_server.stop().await?;
        tracing::info!("RPC server stopped");

        // Disconnect all peers
        if let Ok(peers) = self.peer_manager.get_connected_peers().await {
            for peer in peers {
                let _ = self.peer_manager.disconnect_peer(peer.id).await;
            }
        }
        tracing::info!("All peers disconnected");

        // Log final sync state
        let sm = self.sync_manager.read().await;
        let idx = self.block_index.read().await;
        tracing::info!(
            "Final state: sync={:?}, block index height={}, headers={}",
            sm.state(),
            idx.best_height(),
            idx.header_count()
        );

        Ok(())
    }

    /// Get chain info
    pub async fn get_chain_info(&self) -> Result<btc_application::services::ChainInfo, String> {
        self.blockchain.get_chain_info().await
    }
}

/// Entry point for the Bitcoin infrastructure layer
pub async fn run() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let args = CliArgs::parse();

    let node = BitcoinNode::new(args).await?;
    node.start().await?;

    // Run until interrupted
    tokio::signal::ctrl_c().await?;

    node.stop().await?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_node_creation() {
        let args = CliArgs {
            network: "regtest".to_string(),
            datadir: "/tmp/bitcoin-test".to_string(),
            rpc_port: 18332,
            p2p_port: 18333,
            log_level: "debug".to_string(),
            max_mempool_mb: 300,
            enable_p2p: false,
            seed_peers: Vec::new(),
            storage_backend: "memory".to_string(),
            enable_wallet: true,
            address_type: "bech32".to_string(),
        };

        let node = BitcoinNode::new(args).await;
        assert!(node.is_ok());
    }

    #[tokio::test]
    async fn test_node_chain_info() {
        let args = CliArgs {
            network: "regtest".to_string(),
            datadir: "/tmp/bitcoin-test".to_string(),
            rpc_port: 18332,
            p2p_port: 18333,
            log_level: "warn".to_string(),
            max_mempool_mb: 300,
            enable_p2p: false,
            seed_peers: Vec::new(),
            storage_backend: "memory".to_string(),
            enable_wallet: true,
            address_type: "bech32".to_string(),
        };

        let node = BitcoinNode::new(args).await.unwrap();
        let info = node.get_chain_info().await.unwrap();
        assert_eq!(info.height, 0);
        assert_eq!(info.blocks, 1);
    }

    #[tokio::test]
    async fn test_node_has_block_index() {
        let args = CliArgs {
            network: "regtest".to_string(),
            datadir: "/tmp/bitcoin-test".to_string(),
            rpc_port: 18332,
            p2p_port: 18333,
            log_level: "warn".to_string(),
            max_mempool_mb: 300,
            enable_p2p: false,
            seed_peers: Vec::new(),
            storage_backend: "memory".to_string(),
            enable_wallet: true,
            address_type: "bech32".to_string(),
        };

        let node = BitcoinNode::new(args).await.unwrap();

        // Block index should be initialized with genesis
        let idx = node.block_index.read().await;
        assert_eq!(idx.best_height(), 0);
        assert_eq!(idx.header_count(), 1);
    }

    #[tokio::test]
    async fn test_node_has_sync_manager() {
        let args = CliArgs {
            network: "regtest".to_string(),
            datadir: "/tmp/bitcoin-test".to_string(),
            rpc_port: 18332,
            p2p_port: 18333,
            log_level: "warn".to_string(),
            max_mempool_mb: 300,
            enable_p2p: false,
            seed_peers: Vec::new(),
            storage_backend: "memory".to_string(),
            enable_wallet: true,
            address_type: "bech32".to_string(),
        };

        let node = BitcoinNode::new(args).await.unwrap();

        // Sync manager should start in Idle state
        let sm = node.sync_manager.read().await;
        assert_eq!(sm.state(), SyncState::Idle);
        assert_eq!(sm.blocks_remaining(), 0);
    }

    fn make_test_args() -> CliArgs {
        CliArgs {
            network: "regtest".to_string(),
            datadir: "/tmp/bitcoin-test".to_string(),
            rpc_port: 18332,
            p2p_port: 18333,
            log_level: "warn".to_string(),
            max_mempool_mb: 300,
            enable_p2p: false,
            seed_peers: Vec::new(),
            storage_backend: "memory".to_string(),
            enable_wallet: true,
            address_type: "bech32".to_string(),
        }
    }

    #[tokio::test]
    async fn test_node_has_fee_estimator() {
        let node = BitcoinNode::new(make_test_args()).await.unwrap();

        // Fee estimator should exist and return min relay fee initially
        let fe = node.fee_estimator.read().await;
        let estimate = fe.estimate_fee(6);
        // Min relay fee is 1.0 sat/vB = 1000 sat/kvB
        assert!(estimate > 0.0);
    }

    #[tokio::test]
    async fn test_node_has_rebroadcast_manager() {
        let node = BitcoinNode::new(make_test_args()).await.unwrap();

        let rb = node.rebroadcast_manager.read().await;
        assert_eq!(rb.tracked_count(), 0, "No transactions should be tracked initially");
    }

    #[tokio::test]
    async fn test_node_has_wallet_when_enabled() {
        let node = BitcoinNode::new(make_test_args()).await.unwrap();
        assert!(node.wallet.is_some(), "Wallet should be present when enable_wallet is true");
    }

    #[tokio::test]
    async fn test_node_no_wallet_when_disabled() {
        let mut args = make_test_args();
        args.enable_wallet = false;

        let node = BitcoinNode::new(args).await.unwrap();
        assert!(node.wallet.is_none(), "Wallet should be absent when enable_wallet is false");
    }

    #[tokio::test]
    async fn test_node_mempool_starts_empty() {
        let node = BitcoinNode::new(make_test_args()).await.unwrap();

        let info = node.mempool_adapter.get_mempool_info().await.unwrap();
        assert_eq!(info.size, 0);
        assert_eq!(info.bytes, 0);
    }

    #[tokio::test]
    async fn test_node_testnet_creation() {
        let mut args = make_test_args();
        args.network = "testnet".to_string();

        let node = BitcoinNode::new(args).await.unwrap();
        let info = node.get_chain_info().await.unwrap();
        assert_eq!(info.height, 0);
        assert_eq!(info.blocks, 1);
    }
}
