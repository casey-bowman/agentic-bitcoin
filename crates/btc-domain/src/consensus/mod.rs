//! Bitcoin consensus rules and validation
//!
//! Corresponds to Bitcoin Core's consensus/ directory containing consensus parameters,
//! rules, and validation logic.

pub mod connect;
pub mod params;
pub mod rules;
pub mod validation;

pub use params::{ConsensusParams, Network};
pub use connect::{
    connect_block, disconnect_block, BlockConnectResult, BlockDisconnectResult,
    ConnectBlockError, MemoryUtxoSet, UtxoEntry, UtxoView,
};
pub use rules::{
    check_block, check_block_header, check_transaction, decode_compact, encode_compact,
    hash_to_u128, get_next_work_required, calculate_next_work,
    DIFFICULTY_ADJUSTMENT_INTERVAL, MAX_BLOCK_SERIALIZED_SIZE, MAX_BLOCK_SIGOPS_COST,
    MAX_BLOCK_WEIGHT, WITNESS_SCALE_FACTOR, COINBASE_MATURITY,
};
pub use validation::{ValidationResult, ValidationState};
