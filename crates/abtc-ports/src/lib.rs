//! Bitcoin Core Hexagonal Architecture - Ports Layer
//!
//! This crate defines the PORTS (traits/interfaces) that sit between the domain and adapters.
//! These are the secondary ports that define how the domain layer communicates with external systems.
//!
//! The abtc-ports crate has NO concrete implementations - only trait definitions.
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
//! │        abtc-ports (This Crate)            │
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
//! │      abtc-domain (Depends On)       │
//! │   ┌──────────────────────────────┐ │
//! │   │   Domain Logic & Entities    │ │
//! │   │   (Consensus, Validation)    │ │
//! │   └──────────────────────────────┘ │
//! └────────────────────────────────────┘
//! ```

pub mod mempool;
pub mod mining;
pub mod network;
pub mod rpc;
pub mod storage;
pub mod wallet;

// Re-export commonly used items
pub use mempool::{MempoolEntry, MempoolInfo, MempoolPort};
pub use mining::{BlockSubmitter, BlockTemplate, BlockTemplateProvider};
pub use network::{
    InventoryItem, NetworkListener, NetworkMessage, PeerEvent, PeerInfo, PeerManager,
};
pub use rpc::{RpcError, RpcHandler, RpcRequest, RpcResponse, RpcServer};
pub use storage::{BlockIndexEntry, BlockStore, ChainStateStore, UtxoEntry, UtxoSetInfo};
pub use wallet::{
    Balance, WalletKeyEntry, WalletPort, WalletSnapshot, WalletStore, WalletUtxoEntry,
};
