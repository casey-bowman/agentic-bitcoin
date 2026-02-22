//! Wallet Persistence Port Definitions
//!
//! This module defines the port traits and data types for wallet persistence.
//! Implementations handle serialization and storage of wallet state (keys, UTXOs,
//! metadata) to and from persistent storage.

use std::error::Error;

/// A serializable entry representing a wallet key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WalletKeyEntry {
    /// The address string (e.g., "bc1q..." or "1...")
    pub address: String,
    /// The private key in WIF format
    pub wif: String,
    /// Optional label for this key
    pub label: Option<String>,
}

/// A serializable entry representing an unspent transaction output.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WalletUtxoEntry {
    /// Transaction ID as hex string (display order, reversed)
    pub txid_hex: String,
    /// Output index
    pub vout: u32,
    /// Amount in satoshis
    pub amount_sat: i64,
    /// Script pubkey as hex string
    pub script_pubkey_hex: String,
    /// Number of confirmations
    pub confirmations: u32,
    /// Whether this is a coinbase output
    pub is_coinbase: bool,
}

/// A complete snapshot of wallet state for persistence.
///
/// This is a plain data container that can be serialized/deserialized
/// without any domain logic dependencies. All fields use simple types
/// (strings, integers, booleans) to avoid coupling to domain structs.
#[derive(Clone, Debug)]
pub struct WalletSnapshot {
    /// Schema version for forward compatibility
    pub version: u32,
    /// Whether this wallet uses mainnet addresses
    pub mainnet: bool,
    /// Preferred address type as string ("p2pkh", "p2wpkh", "p2sh-p2wpkh", "p2tr")
    pub address_type: String,
    /// Key generation counter
    pub key_counter: u64,
    /// All wallet keys
    pub keys: Vec<WalletKeyEntry>,
    /// All tracked unspent outputs
    pub utxos: Vec<WalletUtxoEntry>,
}

/// Port trait for wallet persistence.
///
/// Implementations handle the actual storage mechanism (file, database, etc.)
/// while this trait defines the interface for saving and loading wallet state.
#[async_trait::async_trait]
pub trait WalletStore: Send + Sync {
    /// Save a wallet state snapshot to persistent storage.
    ///
    /// Implementations should ensure atomicity — either the entire snapshot
    /// is saved or the previous state is preserved.
    async fn save(&self, snapshot: &WalletSnapshot) -> Result<(), Box<dyn Error + Send + Sync>>;

    /// Load a wallet state snapshot from persistent storage.
    ///
    /// Returns `Ok(None)` if no saved state exists (e.g., first run).
    /// Returns `Err` if the stored data exists but is corrupted or unreadable.
    async fn load(&self) -> Result<Option<WalletSnapshot>, Box<dyn Error + Send + Sync>>;

    /// Delete the persisted wallet state.
    ///
    /// After this call, `load()` should return `Ok(None)`.
    async fn delete(&self) -> Result<(), Box<dyn Error + Send + Sync>>;
}
