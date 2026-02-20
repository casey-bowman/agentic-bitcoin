//! Bitcoin Domain Layer - Pure domain logic with zero infrastructure dependencies
//!
//! This is the INNERMOST layer of the hexagonal architecture, mapping to Bitcoin Core's
//! primitives/, consensus/, script/, and crypto/ directories.

pub mod chain_params;
pub mod consensus;
pub mod crypto;
pub mod primitives;
pub mod script;

// Re-export common types for convenience
pub use chain_params::ChainParams;
pub use consensus::Network;
pub use consensus::{ConsensusParams, ValidationResult, ValidationState};
pub use primitives::{
    Amount, Block, BlockHash, BlockHeader, BlockLocator, Hash256, OutPoint, Sequence,
    Transaction, TxIn, TxOut, Txid, Witness, Wtxid,
};
pub use script::{Opcodes, Script, ScriptBuilder};
pub use script::{
    ScriptError, ScriptFlags, ScriptInterpreter, SignatureChecker,
    NoSigChecker, verify_script, is_push_only,
};
pub use crypto::signing::{TransactionSignatureChecker, verify_ecdsa};
