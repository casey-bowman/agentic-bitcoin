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

pub mod address;
pub mod coin_selection;
pub mod descriptors;
pub mod hd;
pub mod keys;
pub mod psbt;
pub mod tx_builder;

pub use address::{Address, AddressError, AddressType};
pub use coin_selection::{CoinSelectionResult, CoinSelector, SelectionStrategy};
pub use descriptors::{
    add_checksum, parse_descriptor, Descriptor, DescriptorError, DescriptorKey,
    ParseError as DescriptorParseError,
};
pub use hd::{
    parse_derivation_path, ExtendedPrivateKey, ExtendedPublicKey, HdError, HARDENED_OFFSET,
};
pub use keys::{KeyError, PrivateKey, PublicKey};
pub use psbt::{Bip32Derivation, Psbt, PsbtError, PsbtInput, PsbtOutput};
pub use tx_builder::{BuilderError, TapScriptPath, TransactionBuilder};
