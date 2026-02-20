//! Bitcoin consensus rules and validation
//!
//! Corresponds to Bitcoin Core's consensus/ directory containing consensus parameters,
//! rules, and validation logic.

pub mod params;
pub mod rules;
pub mod validation;

pub use params::{ConsensusParams, Network};
pub use rules::{
    check_block, check_block_header, check_transaction, MAX_BLOCK_SERIALIZED_SIZE,
    MAX_BLOCK_SIGOPS_COST, MAX_BLOCK_WEIGHT, WITNESS_SCALE_FACTOR,
};
pub use validation::{ValidationResult, ValidationState};
