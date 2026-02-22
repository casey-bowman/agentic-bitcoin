//! Bitcoin consensus rules and validation
//!
//! Corresponds to Bitcoin Core's consensus/ directory containing consensus parameters,
//! rules, and validation logic.

pub mod connect;
pub mod params;
pub mod rules;
pub mod signet;
pub mod validation;

pub use connect::{
    connect_block, disconnect_block, BlockConnectResult, BlockDisconnectResult, ConnectBlockError,
    MemoryUtxoSet, UtxoEntry, UtxoView,
};
pub use params::{ConsensusParams, Network};
pub use rules::{
    calculate_next_work, check_block, check_block_header, check_transaction, decode_compact,
    decode_compact_u256, encode_compact, get_next_work_required, hash_meets_target, hash_to_u128,
    COINBASE_MATURITY, DIFFICULTY_ADJUSTMENT_INTERVAL, MAX_BLOCK_SERIALIZED_SIZE,
    MAX_BLOCK_SIGOPS_COST, MAX_BLOCK_WEIGHT, WITNESS_SCALE_FACTOR,
};
pub use signet::{
    build_signet_commitment, compute_block_data_hash, extract_signet_solution, make_signet_to_sign,
    make_signet_to_spend, parse_witness_solution, serialize_witness_stack, sign_block_p2wpkh,
    validate_signet_block, SignetError, SIGNET_HEADER,
};
pub use validation::{ValidationResult, ValidationState};
