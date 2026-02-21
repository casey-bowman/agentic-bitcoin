//! Bitcoin Wallet Domain Logic
//!
//! Pure domain-level wallet operations: key management, address derivation,
//! coin selection, and transaction building/signing. No I/O or async —
//! these are pure functions and data structures.
//!
//! ## Modules
//!
//! - `keys` — Private/public key types, WIF encoding, key generation
//! - `address` — Address derivation and encoding (P2PKH, P2WPKH, P2SH-P2WPKH)
//! - `coin_selection` — UTXO selection algorithms
//! - `tx_builder` — Transaction construction and signing

pub mod keys;
pub mod address;
pub mod coin_selection;
pub mod tx_builder;

pub use keys::{PrivateKey, PublicKey, KeyError};
pub use address::{Address, AddressType, AddressError};
pub use coin_selection::{CoinSelector, SelectionStrategy, CoinSelectionResult};
pub use tx_builder::{TransactionBuilder, BuilderError};
