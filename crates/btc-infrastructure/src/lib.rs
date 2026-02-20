//! Bitcoin Infrastructure Layer - Composition Root
//!
//! This is the outermost layer that wires everything together.
//! It serves as the composition root for dependency injection and
//! the entry point for the entire Bitcoin implementation.

use btc_adapters::{
    InMemoryBlockStore, InMemoryChainStateStore, InMemoryMempool,
    StubPeerManager, TcpPeerManager, JsonRpcServer, SimpleMiner,
};
use btc_application::services::{BlockchainService, MempoolService, MiningService};
use btc_application::handlers::{BlockchainRpcHandler, MiningRpcHandler};
use btc_domain::ChainParams;
use btc_ports::{PeerManager, RpcServer};
use clap::Parser;
use std::sync::Arc;
use tracing_subscriber::EnvFilter;

/// Command-line arguments for the Bitcoin node
#[derive(Parser, Debug)]
#[command(
    name = "Bitcoin Rust",
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
}

/// Application state containing all services and ports
pub struct BitcoinNode {
    pub blockchain: Arc<BlockchainService>,
    pub mempool: Arc<MempoolService>,
    pub mining: Arc<MiningService>,
    pub rpc_server: Arc<JsonRpcServer>,
    pub peer_manager: Arc<dyn PeerManager>,
    pub mempool_adapter: Arc<InMemoryMempool>,
    /// Optional TCP peer manager (only when enable_p2p is true)
    tcp_peer_manager: Option<Arc<TcpPeerManager>>,
    /// Seed peers to connect to on start
    seed_peers: Vec<String>,
}

impl BitcoinNode {
    /// Create and wire all components
    pub async fn new(args: CliArgs) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        // Initialize tracing/logging
        tracing_subscriber::fmt()
            .with_env_filter(
                EnvFilter::try_from_default_env()
                    .unwrap_or_else(|_| EnvFilter::new(&args.log_level))
            )
            .init();

        tracing::info!("Initializing Bitcoin node on {}", args.network);

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

        // Create adapter instances
        let block_store = Arc::new(InMemoryBlockStore::new());
        let chain_state = Arc::new(InMemoryChainStateStore::new());
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

        // Initialize with genesis block
        let genesis = chain_params.genesis_block();
        block_store.init_with_genesis(genesis.clone()).await;
        let genesis_hash = genesis.block_hash();
        chain_state.init_with_genesis(genesis_hash).await;

        tracing::info!("Initialized blockchain with genesis block: {}", genesis_hash);

        // Create application services
        let blockchain = Arc::new(BlockchainService::new(
            block_store.clone(),
            chain_state.clone(),
            peer_manager.clone(),
        ));

        // Wire the real mempool adapter
        let mempool = Arc::new(MempoolService::new(
            mempool_adapter.clone() as Arc<dyn btc_ports::MempoolPort>,
            chain_state.clone(),
        ));

        let template_provider = Arc::new(SimpleMiner::new());
        let mining = Arc::new(MiningService::new(template_provider, blockchain.clone()));

        // Register RPC handlers
        let bc_handler = Box::new(BlockchainRpcHandler::new(blockchain.clone(), mempool.clone()));
        rpc_server.register_handler(bc_handler).await?;

        let mining_handler = Box::new(MiningRpcHandler::new(mining.clone()));
        rpc_server.register_handler(mining_handler).await?;

        tracing::info!("Bitcoin node initialized successfully");

        Ok(BitcoinNode {
            blockchain,
            mempool,
            mining,
            rpc_server,
            peer_manager,
            mempool_adapter,
            tcp_peer_manager,
            seed_peers: args.seed_peers,
        })
    }

    /// Start the Bitcoin node
    pub async fn start(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        tracing::info!("Starting Bitcoin node");

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

    /// Stop the Bitcoin node
    pub async fn stop(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        tracing::info!("Stopping Bitcoin node");

        self.rpc_server.stop().await?;
        tracing::info!("RPC server stopped");

        // Disconnect all peers
        if let Ok(peers) = self.peer_manager.get_connected_peers().await {
            for peer in peers {
                let _ = self.peer_manager.disconnect_peer(peer.id).await;
            }
        }
        tracing::info!("All peers disconnected");

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
        };

        let node = BitcoinNode::new(args).await.unwrap();
        let info = node.get_chain_info().await.unwrap();
        assert_eq!(info.height, 0);
        assert_eq!(info.blocks, 1);
    }
}
