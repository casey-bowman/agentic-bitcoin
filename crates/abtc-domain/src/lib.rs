//! Bitcoin Domain Layer - Pure domain logic with zero infrastructure dependencies
//!
//! This is the INNERMOST layer of the hexagonal architecture, mapping to Bitcoin Core's
//! primitives/, consensus/, script/, and crypto/ directories.

pub mod chain_params;
pub mod consensus;
pub mod covenants;
pub mod crypto;
pub mod filters;
pub mod hashing;
pub mod policy;
pub mod primitives;
pub mod protocol;
pub mod script;
pub mod utxo;
pub mod wallet;

// Re-export common types for convenience
pub use chain_params::ChainParams;
pub use consensus::Network;
pub use consensus::{ConsensusParams, ValidationResult, ValidationState};
pub use crypto::signing::{verify_ecdsa, TransactionSignatureChecker};
pub use primitives::{
    Amount, Block, BlockHash, BlockHeader, BlockLocator, Hash256, OutPoint, Sequence, Transaction,
    TxIn, TxOut, Txid, Witness, Wtxid,
};
pub use script::{
    is_push_only, verify_script, verify_script_with_witness, NoSigChecker, ScriptError,
    ScriptFlags, ScriptInterpreter, SignatureChecker,
};
pub use script::{Opcodes, Script, ScriptBuilder};

// Re-export secp256k1 for downstream crates that need key types
pub use secp256k1;
