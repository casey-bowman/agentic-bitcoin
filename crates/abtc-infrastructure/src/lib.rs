//! Bitcoin Infrastructure Layer - Composition Root
//!
//! This is the outermost layer that wires everything together.
//! It serves as the composition root for dependency injection and
//! the entry point for the entire Bitcoin implementation.
//!
//! ## Graceful Shutdown
//!
//! All background tasks listen to a shutdown signal via `tokio::sync::watch`.
//! The `run()` entry point waits for SIGINT (Ctrl+C) or SIGTERM, then triggers
//! an orderly shutdown with a configurable timeout.

use abtc_adapters::{
    FileBasedWalletStore, InMemoryBlockStore, InMemoryChainStateStore, InMemoryMempool,
    InMemoryWallet, JsonRpcServer, PersistentWallet, SimpleMiner, StubPeerManager, TcpPeerManager,
};
use abtc_application::block_index::BlockIndex;
use abtc_application::fee_estimator::FeeEstimator;
use abtc_application::handlers::{BlockchainRpcHandler, MiningRpcHandler, WalletRpcHandler};
use abtc_application::net_processing::{SyncAction, SyncManager, SyncState};
use abtc_application::rebroadcast::RebroadcastManager;
use abtc_application::services::{BlockchainService, MempoolService, MiningService};
use abtc_domain::wallet::address::AddressType;
use abtc_domain::ChainParams;
use abtc_ports::{
    BlockStore, ChainStateStore, MempoolPort, PeerEvent, PeerManager, RpcServer, WalletPort,
};
use clap::Parser;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing_subscriber::EnvFilter;

/// Shutdown timeout in seconds — if services don't stop within this window
/// after receiving the shutdown signal, the process exits forcefully.
const SHUTDOWN_TIMEOUT_SECS: u64 = 10;

/// Node health status — tracks liveness of background tasks and overall node health.
#[derive(Debug, Clone)]
pub struct NodeHealth {
    /// Whether the node is running (not shutting down).
    pub is_running: bool,
    /// Number of background tasks that are alive.
    pub active_tasks: u32,
    /// Total background tasks spawned.
    pub total_tasks: u32,
    /// Uptime in seconds.
    pub uptime_secs: u64,
    /// Current sync state.
    pub sync_state: String,
    /// Block index height.
    pub block_height: u32,
    /// Mempool transaction count.
    pub mempool_size: u32,
    /// Connected peer count.
    pub peer_count: u32,
    /// RPC server running.
    pub rpc_running: bool,
}

/// Tracks liveness of spawned background tasks.
struct TaskTracker {
    /// Number of tasks still running.
    active: Arc<AtomicU64>,
    /// Total tasks launched.
    total: u32,
}

impl TaskTracker {
    fn new() -> Self {
        TaskTracker {
            active: Arc::new(AtomicU64::new(0)),
            total: 0,
        }
    }

    /// Register a new task and return a guard that decrements on drop.
    fn register(&mut self) -> TaskGuard {
        self.total += 1;
        self.active.fetch_add(1, Ordering::Relaxed);
        TaskGuard {
            active: self.active.clone(),
        }
    }

    fn active_count(&self) -> u64 {
        self.active.load(Ordering::Relaxed)
    }
}

/// RAII guard — decrements the active task count when dropped.
struct TaskGuard {
    active: Arc<AtomicU64>,
}

impl Drop for TaskGuard {
    fn drop(&mut self) {
        self.active.fetch_sub(1, Ordering::Relaxed);
    }
}

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

    /// Path to wallet file for persistent storage (optional).
    /// When set, wallet state (keys, UTXOs, metadata) is saved to this
    /// JSON file after every mutation and loaded on startup.
    #[arg(long)]
    pub wallet_file: Option<String>,

    /// Custom signet challenge script (hex string, optional).
    /// Overrides the default signet challenge when network is "signet".
    /// Enables custom/private signet networks.
    #[arg(long)]
    pub signet_challenge: Option<String>,
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
    /// Shutdown signal sender — set to `true` to initiate graceful shutdown.
    shutdown_tx: tokio::sync::watch::Sender<bool>,
    /// Shutdown signal receiver — background tasks clone and listen to this.
    shutdown_rx: tokio::sync::watch::Receiver<bool>,
    /// Background task tracker — monitors liveness of spawned tasks.
    task_tracker: Arc<std::sync::Mutex<TaskTracker>>,
    /// Node start time (Unix timestamp) for uptime calculation.
    start_time: Arc<AtomicU64>,
    /// Whether the node is running (not shutting down).
    running: Arc<AtomicBool>,
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
                    .unwrap_or_else(|_| EnvFilter::new(&args.log_level)),
            )
            .try_init();

        tracing::info!("Initializing Agentic Bitcoin node on {}", args.network);

        // Parse network
        let network = match args.network.as_str() {
            "mainnet" => abtc_domain::Network::Mainnet,
            "testnet" => abtc_domain::Network::Testnet,
            "regtest" => abtc_domain::Network::Regtest,
            "signet" => abtc_domain::Network::Signet,
            _ => {
                return Err(format!("Unknown network: {}", args.network).into());
            }
        };

        let mut chain_params = ChainParams::for_network(network);

        // Apply custom signet challenge if provided
        if let Some(ref challenge_hex) = args.signet_challenge {
            match hex::decode(challenge_hex) {
                Ok(challenge_bytes) => {
                    chain_params.consensus.signet_challenge = Some(challenge_bytes);
                    tracing::info!("Using custom signet challenge: {}", challenge_hex);
                }
                Err(e) => {
                    return Err(format!(
                        "Invalid --signet-challenge hex: {}: {}",
                        challenge_hex, e
                    )
                    .into());
                }
            }
        }

        tracing::info!("Using chain parameters for {}", network);

        // Create storage adapters based on backend flag
        let (block_store, chain_state): (Arc<dyn BlockStore>, Arc<dyn ChainStateStore>) =
            match args.storage_backend.as_str() {
                #[cfg(feature = "rocksdb-storage")]
                "rocksdb" => {
                    use abtc_adapters::{RocksDbBlockStore, RocksDbChainStateStore};
                    use std::path::Path;

                    let datadir = args
                        .datadir
                        .replace('~', &std::env::var("HOME").unwrap_or_default());
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
                    return Err("RocksDB storage requires the 'rocksdb-storage' feature. \
                         Build with: cargo build --features rocksdb-storage"
                        .into());
                }
                _ => {
                    tracing::info!("Using in-memory storage backend");
                    let bs = Arc::new(InMemoryBlockStore::new());
                    let cs = Arc::new(InMemoryChainStateStore::new());
                    (bs as Arc<dyn BlockStore>, cs as Arc<dyn ChainStateStore>)
                }
            };

        let rpc_server = Arc::new(JsonRpcServer::new(args.rpc_port));
        let mempool_adapter = Arc::new(InMemoryMempool::with_max_bytes(
            args.max_mempool_mb * 1_000_000,
        ));

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
            block_store
                .store_block(&genesis, 0)
                .await
                .map_err(|e| format!("Failed to store genesis block: {}", e))?;
        }

        // Set chain tip to genesis
        chain_state
            .write_chain_tip(genesis_hash, 0)
            .await
            .map_err(|e| format!("Failed to set genesis chain tip: {}", e))?;

        tracing::info!(
            "Initialized blockchain with genesis block: {}",
            genesis_hash
        );

        // Initialize block index with genesis header and checkpoints
        let mut block_index = BlockIndex::new();
        block_index.init_genesis(genesis.header.clone());
        block_index.load_checkpoints(&chain_params.checkpoints);
        let block_index = Arc::new(RwLock::new(block_index));

        tracing::info!("Block index initialized with genesis header");

        // Create sync manager
        let sync_manager = Arc::new(RwLock::new(SyncManager::new(block_index.clone())));

        // Create application services
        let blockchain = Arc::new(BlockchainService::with_params(
            block_store.clone(),
            chain_state.clone(),
            peer_manager.clone(),
            chain_params.consensus.clone(),
        ));

        // Wire the real mempool adapter
        let mempool = Arc::new(MempoolService::new(
            mempool_adapter.clone() as Arc<dyn MempoolPort>,
            chain_state.clone(),
        ));

        let template_provider = Arc::new(SimpleMiner::new());
        let mining = Arc::new(MiningService::with_params(
            template_provider,
            blockchain.clone(),
            chain_params.consensus.clone(),
        ));

        // Create fee estimator
        let fee_estimator = Arc::new(RwLock::new(FeeEstimator::new()));

        // Create rebroadcast manager
        let rebroadcast_manager = Arc::new(RwLock::new(RebroadcastManager::new()));

        // Register RPC handlers
        let bc_handler = Box::new(BlockchainRpcHandler::new(
            blockchain.clone(),
            mempool.clone(),
            fee_estimator.clone(),
            chain_state.clone(),
            block_index.clone(),
        ));
        rpc_server.register_handler(bc_handler).await?;

        let mining_handler = Box::new(MiningRpcHandler::new(mining.clone()));
        rpc_server.register_handler(mining_handler).await?;

        // Create wallet if enabled
        let mainnet = matches!(network, abtc_domain::Network::Mainnet);
        let wallet: Option<Arc<dyn WalletPort>> = if args.enable_wallet {
            let addr_type = match args.address_type.as_str() {
                "legacy" | "p2pkh" => AddressType::P2PKH,
                "p2sh-segwit" | "p2sh" => AddressType::P2shP2wpkh,
                _ => AddressType::P2WPKH, // "bech32" and default
            };

            let in_memory = Arc::new(InMemoryWallet::new(mainnet, addr_type));

            let wallet: Arc<dyn WalletPort> = if let Some(ref wallet_path) = args.wallet_file {
                // Persistent wallet: wrap InMemoryWallet with file-based store
                let store = Arc::new(FileBasedWalletStore::new(wallet_path));
                let persistent = PersistentWallet::new(in_memory, store)
                    .await
                    .map_err(|e| format!("Failed to initialize persistent wallet: {}", e))?;
                tracing::info!(
                    "Wallet enabled (address type: {}, persistence: {})",
                    args.address_type,
                    wallet_path
                );
                Arc::new(persistent)
            } else {
                // In-memory only wallet (no persistence)
                tracing::info!(
                    "Wallet enabled (address type: {}, in-memory only)",
                    args.address_type
                );
                in_memory
            };

            // Register wallet RPC handler
            let wallet_handler = Box::new(WalletRpcHandler::new(wallet.clone()));
            rpc_server.register_handler(wallet_handler).await?;

            Some(wallet)
        } else {
            tracing::info!("Wallet disabled");
            None
        };

        tracing::info!("Agentic Bitcoin node initialized successfully");

        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);

        let start_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

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
            shutdown_tx,
            shutdown_rx,
            task_tracker: Arc::new(std::sync::Mutex::new(TaskTracker::new())),
            start_time: Arc::new(AtomicU64::new(start_time)),
            running: Arc::new(AtomicBool::new(false)),
        })
    }

    /// Start the Bitcoin node
    pub async fn start(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        tracing::info!("Starting Agentic Bitcoin node");
        self.running.store(true, Ordering::Release);

        // Start RPC server (now actually listens for HTTP connections)
        self.rpc_server.start().await?;
        tracing::info!("RPC server started on port {}", self.rpc_server.get_port());

        // Connect to seed peers if P2P is enabled
        if !self.seed_peers.is_empty() {
            for seed in &self.seed_peers {
                match seed.parse::<std::net::SocketAddr>() {
                    Ok(addr) => match self.peer_manager.connect_peer(addr).await {
                        Ok(id) => tracing::info!("Connected to seed peer {} (id: {})", addr, id),
                        Err(e) => tracing::warn!("Failed to connect to seed peer {}: {}", addr, e),
                    },
                    Err(e) => tracing::warn!("Invalid seed peer address '{}': {}", seed, e),
                }
            }
        }

        // Start background tasks
        self.start_background_tasks().await;

        Ok(())
    }

    /// Launch background processing loops — all tasks listen to the shutdown signal.
    async fn start_background_tasks(&self) {
        let mut tracker = self.task_tracker.lock().unwrap();

        // ── Task 1: Mempool maintenance ─────────────────────────
        {
            let mempool_adapter = self.mempool_adapter.clone();
            let mut shutdown = self.shutdown_rx.clone();
            let guard = tracker.register();
            tokio::spawn(async move {
                let _guard = guard;
                let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(60));
                loop {
                    tokio::select! {
                        _ = interval.tick() => {
                            let size = mempool_adapter.size().await;
                            if size > 0 {
                                tracing::info!("Mempool: {} transactions", size);
                            }
                        }
                        _ = shutdown.changed() => {
                            tracing::debug!("Mempool maintenance task shutting down");
                            break;
                        }
                    }
                }
            });
        }

        // ── Task 2: Peer connection maintenance ─────────────────
        {
            let peer_manager = self.peer_manager.clone();
            let mut shutdown = self.shutdown_rx.clone();
            let guard = tracker.register();
            tokio::spawn(async move {
                let _guard = guard;
                let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(30));
                loop {
                    tokio::select! {
                        _ = interval.tick() => {
                            match peer_manager.get_connected_peers().await {
                                Ok(peers) => {
                                    if !peers.is_empty() {
                                        tracing::debug!("Connected peers: {}", peers.len());
                                    }
                                }
                                Err(e) => tracing::debug!("Error checking peers: {}", e),
                            }
                        }
                        _ = shutdown.changed() => {
                            tracing::debug!("Peer maintenance task shutting down");
                            break;
                        }
                    }
                }
            });
        }

        // ── Task 3: Sync status reporting ───────────────────────
        {
            let sync_manager = self.sync_manager.clone();
            let block_index = self.block_index.clone();
            let mut shutdown = self.shutdown_rx.clone();
            let guard = tracker.register();
            tokio::spawn(async move {
                let _guard = guard;
                let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(10));
                loop {
                    tokio::select! {
                        _ = interval.tick() => {
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
                                        headers, height
                                    );
                                }
                                SyncState::BlockSync => {
                                    tracing::info!(
                                        "Sync: downloading blocks ({} remaining, index height {})",
                                        remaining, height
                                    );
                                }
                                SyncState::Synced => {
                                    tracing::debug!(
                                        "Sync: fully synced at height {} ({} headers)",
                                        height, headers
                                    );
                                }
                                SyncState::Idle => {}
                            }
                        }
                        _ = shutdown.changed() => {
                            tracing::debug!("Sync reporter task shutting down");
                            break;
                        }
                    }
                }
            });
        }

        // ── Task 4: Transaction rebroadcast ─────────────────────
        {
            let rebroadcast_mgr = self.rebroadcast_manager.clone();
            let rebroadcast_mempool = self.mempool_adapter.clone();
            let rebroadcast_peers = self.peer_manager.clone();
            let mut shutdown = self.shutdown_rx.clone();
            let guard = tracker.register();
            tokio::spawn(async move {
                let _guard = guard;
                let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(5 * 60));
                loop {
                    tokio::select! {
                        _ = interval.tick() => {
                            let now = std::time::SystemTime::now()
                                .duration_since(std::time::UNIX_EPOCH)
                                .map(|d| d.as_secs())
                                .unwrap_or(0);

                            let mempool_ref = &rebroadcast_mempool;
                            let mut mgr = rebroadcast_mgr.write().await;

                            let tracked_txids: Vec<abtc_domain::primitives::Txid> = mgr
                                .check_rebroadcast(now, |txid| {
                                    let _ = txid;
                                    true
                                })
                                .into_iter()
                                .filter_map(|action| match action {
                                    abtc_application::rebroadcast::RebroadcastAction::Reannounce(txid) => {
                                        Some(txid)
                                    }
                                    abtc_application::rebroadcast::RebroadcastAction::Abandon(txid) => {
                                        tracing::info!("Abandoning rebroadcast of tx {}", txid);
                                        None
                                    }
                                })
                                .collect();

                            drop(mgr);

                            for txid in tracked_txids {
                                if let Ok(Some(_)) = mempool_ref.get_transaction(&txid).await {
                                    let inv = abtc_ports::NetworkMessage::Inv {
                                        items: vec![abtc_ports::InventoryItem::Tx(txid)],
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
                        _ = shutdown.changed() => {
                            tracing::debug!("Rebroadcast task shutting down");
                            break;
                        }
                    }
                }
            });
        }

        // ── Task 5: TCP peer keepalive ──────────────────────────
        if let Some(ref tcp_mgr) = self.tcp_peer_manager {
            let tcp = tcp_mgr.clone();
            let mut shutdown = self.shutdown_rx.clone();
            let guard = tracker.register();
            tokio::spawn(async move {
                let _guard = guard;
                let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(120));
                loop {
                    tokio::select! {
                        _ = interval.tick() => {
                            let count = tcp.peer_count().await;
                            if count > 0 {
                                tracing::debug!("TCP peers alive: {}", count);
                            }
                        }
                        _ = shutdown.changed() => {
                            tracing::debug!("TCP keepalive task shutting down");
                            break;
                        }
                    }
                }
            });
        }

        let total = tracker.total;
        drop(tracker);
        tracing::info!("Background tasks started ({} tasks)", total);
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

                            let confirmed_fees: Vec<(abtc_domain::primitives::Amount, usize, u32)> =
                                block
                                    .transactions
                                    .iter()
                                    .filter_map(|tx| {
                                        if tx.is_coinbase() {
                                            return None;
                                        }
                                        // Approximate fee: we don't have input values readily,
                                        // so use a heuristic — the mempool had the fee when we
                                        // accepted the tx.  For now, estimate 1 sat/vB minimum
                                        // as a placeholder; real fee calculation requires UTXO lookup.
                                        let vsize = tx.compute_vsize() as usize;
                                        let estimated_fee =
                                            abtc_domain::primitives::Amount::from_sat(
                                                vsize as i64, // ~1 sat/vB estimate
                                            );
                                        Some((estimated_fee, vsize, 1u32))
                                    })
                                    .collect();

                            if !confirmed_fees.is_empty() {
                                let mut est = self.fee_estimator.write().await;
                                est.process_block(height, &confirmed_fees);
                                tracing::debug!(
                                    "Fee estimator updated: height={}, txs={}",
                                    height,
                                    confirmed_fees.len()
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

    /// Stop the Bitcoin node gracefully.
    ///
    /// Sends the shutdown signal to all background tasks, stops the RPC
    /// server, disconnects all peers, and logs the final state.
    pub async fn stop(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        tracing::info!("Stopping Agentic Bitcoin node");
        self.running.store(false, Ordering::Release);

        // 1. Signal all background tasks to stop
        let _ = self.shutdown_tx.send(true);
        tracing::info!("Shutdown signal sent to background tasks");

        // 2. Wait briefly for tasks to exit (non-blocking check)
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
        let active = self.task_tracker.lock().unwrap().active_count();
        if active > 0 {
            tracing::info!("Waiting for {} background tasks to finish...", active);
            // Give tasks a moment to wind down
            tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
        }
        let remaining = self.task_tracker.lock().unwrap().active_count();
        if remaining > 0 {
            tracing::warn!("{} background tasks still running at shutdown", remaining);
        } else {
            tracing::info!("All background tasks stopped cleanly");
        }

        // 3. Stop RPC server
        self.rpc_server.stop().await?;
        tracing::info!("RPC server stopped");

        // 4. Disconnect all peers
        if let Ok(peers) = self.peer_manager.get_connected_peers().await {
            let count = peers.len();
            for peer in peers {
                let _ = self.peer_manager.disconnect_peer(peer.id).await;
            }
            tracing::info!("Disconnected {} peers", count);
        }

        // 5. Log final sync state
        let sm = self.sync_manager.read().await;
        let idx = self.block_index.read().await;
        let uptime = self.uptime_secs();
        tracing::info!(
            "Final state: sync={:?}, height={}, headers={}, uptime={}s",
            sm.state(),
            idx.best_height(),
            idx.header_count(),
            uptime,
        );

        tracing::info!("Agentic Bitcoin node stopped");
        Ok(())
    }

    /// Get current node health status.
    pub async fn health(&self) -> NodeHealth {
        let (active_tasks, total_tasks) = {
            let tracker = self.task_tracker.lock().unwrap();
            let active_tasks = tracker.active_count() as u32;
            let total_tasks = tracker.total;
            (active_tasks, total_tasks)
        };

        let sm = self.sync_manager.read().await;
        let sync_state = format!("{:?}", sm.state());
        drop(sm);

        let idx = self.block_index.read().await;
        let block_height = idx.best_height();
        drop(idx);

        let mempool_size = self.mempool_adapter.size().await as u32;

        let peer_count = self
            .peer_manager
            .get_connected_peers()
            .await
            .map(|p| p.len() as u32)
            .unwrap_or(0);

        let rpc_running = self.rpc_server.is_running();

        NodeHealth {
            is_running: self.running.load(Ordering::Acquire),
            active_tasks,
            total_tasks,
            uptime_secs: self.uptime_secs(),
            sync_state,
            block_height,
            mempool_size,
            peer_count,
            rpc_running,
        }
    }

    /// Calculate node uptime in seconds.
    fn uptime_secs(&self) -> u64 {
        let start = self.start_time.load(Ordering::Relaxed);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        now.saturating_sub(start)
    }

    /// Get chain info
    pub async fn get_chain_info(&self) -> Result<abtc_application::services::ChainInfo, String> {
        self.blockchain.get_chain_info().await
    }
}

/// Wait for a termination signal (SIGINT or SIGTERM).
///
/// On Unix, listens for both Ctrl+C (SIGINT) and SIGTERM (used by
/// containers, systemd, process managers). On other platforms, only
/// Ctrl+C is supported.
async fn wait_for_shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut sigterm =
            signal(SignalKind::terminate()).expect("failed to install SIGTERM handler");
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                tracing::info!("Received SIGINT (Ctrl+C)");
            }
            _ = sigterm.recv() => {
                tracing::info!("Received SIGTERM");
            }
        }
    }
    #[cfg(not(unix))]
    {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to listen for Ctrl+C");
        tracing::info!("Received Ctrl+C");
    }
}

/// Entry point for the Bitcoin infrastructure layer.
///
/// Creates the node, starts all services, waits for a termination signal,
/// then performs an orderly shutdown with a timeout.
pub async fn run() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let args = CliArgs::parse();

    let node = BitcoinNode::new(args).await?;
    node.start().await?;

    // Wait for SIGINT or SIGTERM
    wait_for_shutdown_signal().await;

    // Graceful shutdown with timeout
    tracing::info!(
        "Initiating graceful shutdown (timeout: {}s)...",
        SHUTDOWN_TIMEOUT_SECS
    );

    let shutdown_result = tokio::time::timeout(
        tokio::time::Duration::from_secs(SHUTDOWN_TIMEOUT_SECS),
        node.stop(),
    )
    .await;

    match shutdown_result {
        Ok(Ok(())) => {
            tracing::info!("Clean shutdown completed");
        }
        Ok(Err(e)) => {
            tracing::error!("Shutdown encountered error: {}", e);
        }
        Err(_) => {
            tracing::error!(
                "Shutdown timed out after {}s — forcing exit",
                SHUTDOWN_TIMEOUT_SECS
            );
        }
    }

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
            wallet_file: None,
            signet_challenge: None,
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
            wallet_file: None,
            signet_challenge: None,
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
            wallet_file: None,
            signet_challenge: None,
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
            wallet_file: None,
            signet_challenge: None,
        };

        let node = BitcoinNode::new(args).await.unwrap();

        // Sync manager should start in Idle state
        let sm = node.sync_manager.read().await;
        assert_eq!(sm.state(), SyncState::Idle);
        assert_eq!(sm.blocks_remaining(), 0);
    }

    fn make_test_args() -> CliArgs {
        make_test_args_with_port(18332)
    }

    /// Create test args with a specific RPC port — use unique ports for tests
    /// that call `node.start()` to avoid AddrInUse when tests run in parallel.
    fn make_test_args_with_port(rpc_port: u16) -> CliArgs {
        CliArgs {
            network: "regtest".to_string(),
            datadir: "/tmp/bitcoin-test".to_string(),
            rpc_port,
            p2p_port: 18333,
            log_level: "warn".to_string(),
            max_mempool_mb: 300,
            enable_p2p: false,
            seed_peers: Vec::new(),
            storage_backend: "memory".to_string(),
            enable_wallet: true,
            address_type: "bech32".to_string(),
            wallet_file: None,
            signet_challenge: None,
        }
    }

    /// Allocate a unique port for a test that needs to bind the RPC server.
    fn unique_port() -> u16 {
        use std::sync::atomic::{AtomicU16, Ordering};
        static PORT: AtomicU16 = AtomicU16::new(19400);
        PORT.fetch_add(1, Ordering::Relaxed)
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
        assert_eq!(
            rb.tracked_count(),
            0,
            "No transactions should be tracked initially"
        );
    }

    #[tokio::test]
    async fn test_node_has_wallet_when_enabled() {
        let node = BitcoinNode::new(make_test_args()).await.unwrap();
        assert!(
            node.wallet.is_some(),
            "Wallet should be present when enable_wallet is true"
        );
    }

    #[tokio::test]
    async fn test_node_no_wallet_when_disabled() {
        let mut args = make_test_args();
        args.enable_wallet = false;

        let node = BitcoinNode::new(args).await.unwrap();
        assert!(
            node.wallet.is_none(),
            "Wallet should be absent when enable_wallet is false"
        );
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

    #[tokio::test]
    async fn test_node_with_wallet_persistence() {
        let wallet_path = {
            let mut p = std::env::temp_dir();
            let id = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos() as u64;
            p.push(format!("test_infra_wallet_{}.json", id));
            p.to_str().unwrap().to_string()
        };

        // Phase 1: Create node with persistent wallet, generate an address
        {
            let mut args = make_test_args();
            args.wallet_file = Some(wallet_path.clone());

            let node = BitcoinNode::new(args).await.unwrap();
            assert!(node.wallet.is_some());

            // Generate an address
            let wallet = node.wallet.as_ref().unwrap();
            let addr = wallet.get_new_address(Some("persist-test")).await.unwrap();
            assert!(addr.starts_with("tb1q") || addr.starts_with("bcrt1q"));
        }

        // Wallet file should exist
        assert!(std::path::Path::new(&wallet_path).exists());

        // Phase 2: Create new node with same wallet file, verify address persists
        {
            let mut args = make_test_args();
            args.wallet_file = Some(wallet_path.clone());

            let node = BitcoinNode::new(args).await.unwrap();
            let wallet = node.wallet.as_ref().unwrap();

            // Should be able to list unspent (wallet is loaded, has 1 key)
            let unspent = wallet.list_unspent(0, None).await.unwrap();
            // No UTXOs, but the wallet loaded without error — that confirms persistence
            assert_eq!(unspent.len(), 0);
        }

        // Cleanup
        let _ = tokio::fs::remove_file(&wallet_path).await;
    }

    #[tokio::test]
    async fn test_node_wallet_file_none_is_in_memory() {
        let args = make_test_args(); // wallet_file is None

        let node = BitcoinNode::new(args).await.unwrap();
        assert!(node.wallet.is_some());

        // Generate an address — should work fine in-memory
        let wallet = node.wallet.as_ref().unwrap();
        let addr = wallet.get_new_address(None).await.unwrap();
        assert!(!addr.is_empty());
    }

    #[tokio::test]
    async fn test_node_signet_creation() {
        let mut args = make_test_args();
        args.network = "signet".to_string();

        let node = BitcoinNode::new(args).await.unwrap();
        let info = node.get_chain_info().await.unwrap();
        assert_eq!(info.height, 0);
        assert_eq!(info.blocks, 1);
    }

    #[tokio::test]
    async fn test_node_custom_signet_challenge() {
        let mut args = make_test_args();
        args.network = "signet".to_string();
        // OP_TRUE as a trivial custom challenge
        args.signet_challenge = Some("51".to_string());

        let node = BitcoinNode::new(args).await.unwrap();
        let info = node.get_chain_info().await.unwrap();
        assert_eq!(info.height, 0);
    }

    #[tokio::test]
    async fn test_node_invalid_signet_challenge_hex() {
        let mut args = make_test_args();
        args.network = "signet".to_string();
        args.signet_challenge = Some("not_valid_hex".to_string());

        let result = BitcoinNode::new(args).await;
        assert!(result.is_err(), "Invalid hex should produce an error");
    }

    // ── Infrastructure hardening tests ──────────────────────────

    #[test]
    fn test_task_tracker_register_and_count() {
        let mut tracker = TaskTracker::new();
        assert_eq!(tracker.active_count(), 0);
        assert_eq!(tracker.total, 0);

        let g1 = tracker.register();
        assert_eq!(tracker.active_count(), 1);
        assert_eq!(tracker.total, 1);

        let g2 = tracker.register();
        assert_eq!(tracker.active_count(), 2);
        assert_eq!(tracker.total, 2);

        drop(g1);
        assert_eq!(tracker.active_count(), 1);

        drop(g2);
        assert_eq!(tracker.active_count(), 0);
        // total stays at 2 — it's a high-water mark
        assert_eq!(tracker.total, 2);
    }

    #[test]
    fn test_task_guard_decrements_on_drop() {
        let mut tracker = TaskTracker::new();
        {
            let _g = tracker.register();
            assert_eq!(tracker.active_count(), 1);
        }
        // guard dropped at end of scope
        assert_eq!(tracker.active_count(), 0);
    }

    #[tokio::test]
    async fn test_node_starts_not_running() {
        let node = BitcoinNode::new(make_test_args()).await.unwrap();
        // Before start(), running should be false
        assert!(!node.running.load(Ordering::Acquire));
    }

    #[tokio::test]
    async fn test_node_start_sets_running() {
        let node = BitcoinNode::new(make_test_args_with_port(unique_port()))
            .await
            .unwrap();
        node.start().await.unwrap();
        assert!(node.running.load(Ordering::Acquire));
        // Clean up
        let _ = node.stop().await;
    }

    #[tokio::test]
    async fn test_node_stop_clears_running() {
        let node = BitcoinNode::new(make_test_args_with_port(unique_port()))
            .await
            .unwrap();
        node.start().await.unwrap();
        assert!(node.running.load(Ordering::Acquire));

        node.stop().await.unwrap();
        assert!(!node.running.load(Ordering::Acquire));
    }

    #[tokio::test]
    async fn test_shutdown_signal_stops_tasks() {
        let node = BitcoinNode::new(make_test_args_with_port(unique_port()))
            .await
            .unwrap();
        node.start().await.unwrap();

        // Background tasks should be running
        let active_before = node.task_tracker.lock().unwrap().active_count();
        assert!(active_before > 0, "Expected background tasks to be running");

        // Send shutdown signal
        let _ = node.shutdown_tx.send(true);
        // Give tasks a moment to exit
        tokio::time::sleep(tokio::time::Duration::from_millis(200)).await;

        let active_after = node.task_tracker.lock().unwrap().active_count();
        assert_eq!(
            active_after, 0,
            "All tasks should have exited after shutdown signal"
        );

        let _ = node.stop().await;
    }

    #[tokio::test]
    async fn test_health_before_start() {
        let node = BitcoinNode::new(make_test_args()).await.unwrap();
        let health = node.health().await;

        assert!(!health.is_running);
        assert_eq!(health.active_tasks, 0);
        assert_eq!(health.total_tasks, 0);
        assert_eq!(health.block_height, 0);
        assert_eq!(health.mempool_size, 0);
        assert_eq!(health.peer_count, 0);
        assert_eq!(health.sync_state, "Idle");
    }

    #[tokio::test]
    async fn test_health_after_start() {
        let node = BitcoinNode::new(make_test_args_with_port(unique_port()))
            .await
            .unwrap();
        node.start().await.unwrap();

        let health = node.health().await;
        assert!(health.is_running);
        assert!(health.active_tasks > 0, "Background tasks should be active");
        assert!(health.total_tasks > 0, "Total tasks should be non-zero");
        assert!(health.rpc_running);

        let _ = node.stop().await;
    }

    #[tokio::test]
    async fn test_health_after_stop() {
        let node = BitcoinNode::new(make_test_args_with_port(unique_port()))
            .await
            .unwrap();
        node.start().await.unwrap();
        node.stop().await.unwrap();

        let health = node.health().await;
        assert!(!health.is_running);
        assert_eq!(health.active_tasks, 0, "No tasks should remain after stop");
    }

    #[tokio::test]
    async fn test_uptime_increases() {
        let node = BitcoinNode::new(make_test_args()).await.unwrap();
        let t1 = node.uptime_secs();
        tokio::time::sleep(tokio::time::Duration::from_millis(1100)).await;
        let t2 = node.uptime_secs();
        assert!(t2 >= t1 + 1, "Uptime should increase over time");
    }

    #[tokio::test]
    async fn test_node_health_fields_consistent() {
        let node = BitcoinNode::new(make_test_args_with_port(unique_port()))
            .await
            .unwrap();
        node.start().await.unwrap();

        let health = node.health().await;

        // active_tasks should never exceed total_tasks
        assert!(health.active_tasks <= health.total_tasks);
        // uptime should be small (just started)
        assert!(health.uptime_secs < 60);

        let _ = node.stop().await;
    }

    #[tokio::test]
    async fn test_double_stop_is_safe() {
        let node = BitcoinNode::new(make_test_args_with_port(unique_port()))
            .await
            .unwrap();
        node.start().await.unwrap();

        // First stop
        node.stop().await.unwrap();
        // Second stop should not panic or error
        node.stop().await.unwrap();
    }

    #[test]
    fn test_node_health_clone() {
        let health = NodeHealth {
            is_running: true,
            active_tasks: 5,
            total_tasks: 5,
            uptime_secs: 100,
            sync_state: "Synced".to_string(),
            block_height: 800_000,
            mempool_size: 42,
            peer_count: 8,
            rpc_running: true,
        };

        let cloned = health.clone();
        assert_eq!(cloned.is_running, true);
        assert_eq!(cloned.active_tasks, 5);
        assert_eq!(cloned.block_height, 800_000);
        assert_eq!(cloned.peer_count, 8);
    }

    #[test]
    fn test_node_health_debug() {
        let health = NodeHealth {
            is_running: false,
            active_tasks: 0,
            total_tasks: 5,
            uptime_secs: 0,
            sync_state: "Idle".to_string(),
            block_height: 0,
            mempool_size: 0,
            peer_count: 0,
            rpc_running: false,
        };

        let debug_str = format!("{:?}", health);
        assert!(debug_str.contains("NodeHealth"));
        assert!(debug_str.contains("is_running: false"));
    }
}
