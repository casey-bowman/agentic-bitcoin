//! Bitcoin Application Layer
//!
//! Implements use cases and orchestrates interactions between the domain layer
//! and the ports/adapters. Provides high-level services for blockchain operations.

pub mod address_manager;
pub mod block_index;
pub mod block_template;
pub mod chain_events;
pub mod chain_state;
pub mod compact_blocks;
pub mod download_scheduler;
pub mod fee_estimator;
pub mod mempool_acceptance;
pub mod miner;
pub mod net_processing;
pub mod orphan_pool;
pub mod peer_scoring;
pub mod rebroadcast;
pub mod services;
pub mod commands;
pub mod queries;
pub mod handlers;

// Re-exports for convenience
pub use block_index::{BlockIndex, BlockIndexEntry, BlockIndexError, BlockValidationStatus};
pub use block_template::BlockAssembler;
pub use chain_state::{ChainState, ChainStateError, ProcessBlockResult};
pub use fee_estimator::FeeEstimator;
pub use mempool_acceptance::{MempoolAcceptor, AcceptError, AcceptResult};
pub use miner::{mine_block, generate_blocks, MiningError};
pub use net_processing::{SyncManager, SyncState, SyncAction, HandshakeState};
pub use services::{BlockchainService, MempoolService, MiningService};
pub use commands::*;
pub use queries::*;
