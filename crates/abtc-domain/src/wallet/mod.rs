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
//! - `psbt` — Partially Signed Bitcoin Transactions (BIP174)

pub mod keys;
pub mod address;
pub mod coin_selection;
pub mod descriptors;
pub mod hd;
pub mod psbt;
pub mod tx_builder;

pub use keys::{PrivateKey, PublicKey, KeyError};
pub use address::{Address, AddressType, AddressError};
pub use coin_selection::{CoinSelector, SelectionStrategy, CoinSelectionResult};
pub use descriptors::{
    Descriptor, DescriptorKey, parse_descriptor, add_checksum,
    ParseError as DescriptorParseError, DescriptorError,
};
pub use hd::{ExtendedPrivateKey, ExtendedPublicKey, HdError, parse_derivation_path, HARDENED_OFFSET};
pub use psbt::{Psbt, PsbtInput, PsbtOutput, PsbtError, Bip32Derivation};
pub use tx_builder::{TransactionBuilder, BuilderError, TapScriptPath};
