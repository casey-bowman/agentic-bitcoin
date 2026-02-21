//! Bitcoin Adapter Layer - Concrete Implementations
//!
//! This crate provides concrete implementations of the ports defined in abtc-ports.
//! Implementations include:
//! - In-memory storage adapters
//! - Stub P2P network adapter
//! - Basic RPC server
//! - Simple mining provider
//! - Basic wallet adapter

pub mod storage;
pub mod network;
pub mod rpc;
pub mod mining;
pub mod wallet;
pub mod mempool;

// Re-exports for convenience
pub use storage::{InMemoryBlockStore, InMemoryChainStateStore};
#[cfg(feature = "rocksdb-storage")]
pub use storage::{RocksDbBlockStore, RocksDbChainStateStore};
pub use network::{StubPeerManager, TcpPeerManager};
pub use rpc::JsonRpcServer;
pub use mining::SimpleMiner;
pub use wallet::InMemoryWallet;
pub use mempool::InMemoryMempool;
