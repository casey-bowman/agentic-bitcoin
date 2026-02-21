//! Bitcoin Core Hexagonal Architecture - Ports Layer
//!
//! This crate defines the PORTS (traits/interfaces) that sit between the domain and adapters.
//! These are the secondary ports that define how the domain layer communicates with external systems.
//!
//! The btc-ports crate has NO concrete implementations - only trait definitions.
//! Implementations are provided by adapter crates that depend on this crate.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────┐
//! │          External Systems               │
//! │    (Databases, Network, RPC, etc.)      │
//! └─────────────────────────────────────────┘
//!              ▲                    ▲
//!              │                    │
//!         Adapter Implementation    │
//!              │                    │
//! ┌────────────┴────────────────────┴───────┐
//! │        btc-ports (This Crate)            │
//! │   ┌──────────────────────────────────┐   │
//! │   │  Trait Definitions (Ports)       │   │
//! │   │  - Storage                       │   │
//! │   │  - Network/P2P                   │   │
//! │   │  - Mining                        │   │
//! │   │  - Mempool                       │   │
//! │   │  - Wallet                        │   │
//! │   │  - RPC                           │   │
//! │   └──────────────────────────────────┘   │
//! └──────────────────────────────────────────┘
//!              ▲
//!              │
//! ┌────────────┴──────────────────────┐
//! │      btc-domain (Depends On)       │
//! │   ┌──────────────────────────────┐ │
//! │   │   Domain Logic & Entities    │ │
//! │   │   (Consensus, Validation)    │ │
//! │   └──────────────────────────────┘ │
//! └────────────────────────────────────┘
//! ```

pub mod storage;
pub mod network;
pub mod mining;
pub mod mempool;
pub mod wallet;
pub mod rpc;

// Re-export commonly used items
pub use storage::{BlockStore, ChainStateStore, UtxoEntry, BlockIndexEntry};
pub use network::{PeerManager, NetworkMessage, InventoryItem, PeerInfo, PeerEvent, NetworkListener};
pub use mining::{BlockTemplateProvider, BlockTemplate, BlockSubmitter};
pub use mempool::{MempoolPort, MempoolEntry, MempoolInfo};
pub use wallet::{WalletPort, Balance};
pub use rpc::{RpcServer, RpcHandler, RpcRequest, RpcResponse, RpcError};
