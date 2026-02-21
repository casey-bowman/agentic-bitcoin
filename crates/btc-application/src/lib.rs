//! Bitcoin Application Layer
//!
//! Implements use cases and orchestrates interactions between the domain layer
//! and the ports/adapters. Provides high-level services for blockchain operations.

pub mod block_index;
pub mod net_processing;
pub mod services;
pub mod commands;
pub mod queries;
pub mod handlers;

// Re-exports for convenience
pub use block_index::{BlockIndex, BlockIndexEntry, BlockIndexError, BlockValidationStatus};
pub use net_processing::{SyncManager, SyncState, SyncAction};
pub use services::{BlockchainService, MempoolService, MiningService};
pub use commands::*;
pub use queries::*;
