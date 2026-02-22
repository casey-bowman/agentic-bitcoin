//! Covenant opcodes — BIP119 CTV + BIP345 OP_VAULT
//!
//! Covenants restrict how a UTXO can be spent by constraining the structure
//! of the spending transaction itself, rather than just requiring a signature.
//!
//! ## BIP119 — OP_CHECKTEMPLATEVERIFY (CTV)
//!
//! CTV commits to a template of the spending transaction: its version,
//! locktime, outputs, sequences, and input count. A UTXO locked with CTV
//! can only be spent by a transaction that exactly matches the committed
//! template, enabling non-interactive payment pools, vaults, congestion
//! control, and other advanced constructions.
//!
//! ## BIP345 — OP_VAULT / OP_VAULT_RECOVER
//!
//! OP_VAULT enables native vault custody: coins are locked behind a
//! two-phase spending policy. To spend, the owner first triggers
//! an unvaulting transaction (with a timelock), then after the delay
//! completes the withdrawal. At any point during the delay, the coins
//! can be swept to a pre-committed recovery path using OP_VAULT_RECOVER.
//!
//! - **OP_VAULT**: Verifies that a trigger output is created with the
//!   correct script structure (timelock + spend path), preserving the
//!   vault amount.
//!
//! - **OP_VAULT_RECOVER**: Allows immediate clawback to a recovery
//!   address, bypassing any timelocks.

pub mod ctv;
pub mod vault;

pub use ctv::compute_ctv_hash;
pub use vault::{VaultParams, VaultTriggerInfo};
