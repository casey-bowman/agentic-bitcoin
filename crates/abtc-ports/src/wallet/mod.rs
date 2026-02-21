//! Wallet Port Definitions
//!
//! This module defines the port traits for wallet functionality.
//! Implementations handle key management, transaction creation, and signing.

use abtc_domain::primitives::{Transaction, Amount, OutPoint, TxOut};
use std::error::Error;

/// Represents a wallet's balance broken down by confirmation status.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Balance {
    /// Confirmed balance (from transactions with sufficient confirmations)
    pub confirmed: Amount,
    /// Unconfirmed balance (from transactions with 0 confirmations)
    pub unconfirmed: Amount,
    /// Immature balance (from coinbase transactions that haven't matured)
    pub immature: Amount,
}

impl Balance {
    /// Gets the total balance across all categories.
    pub fn total(&self) -> Amount {
        Amount::from_sat(
            self.confirmed.as_sat() + self.unconfirmed.as_sat() + self.immature.as_sat()
        )
    }
}

/// Represents an unspent transaction output controlled by the wallet.
#[derive(Clone, Debug)]
pub struct UnspentOutput {
    /// The outpoint (txid + output index)
    pub outpoint: OutPoint,
    /// The output data (script + amount)
    pub output: TxOut,
    /// Number of confirmations
    pub confirmations: u32,
    /// Whether this is a coinbase output
    pub is_coinbase: bool,
}

/// Port trait for wallet operations.
///
/// Implementations manage keys, addresses, and transactions on behalf of the user.
#[async_trait::async_trait]
pub trait WalletPort: Send + Sync {
    /// Gets the wallet's current balance.
    ///
    /// # Returns
    ///
    /// Returns the balance broken down by confirmation status.
    async fn get_balance(&self) -> Result<Balance, Box<dyn Error + Send + Sync>>;

    /// Lists all unspent outputs (UTXOs) controlled by the wallet.
    ///
    /// # Arguments
    ///
    /// * `min_confirmations` - Only include outputs with at least this many confirmations
    /// * `max_amount` - Optional maximum amount to include per output
    ///
    /// # Returns
    ///
    /// Returns a vector of unspent outputs.
    async fn list_unspent(
        &self,
        min_confirmations: u32,
        max_amount: Option<Amount>,
    ) -> Result<Vec<UnspentOutput>, Box<dyn Error + Send + Sync>>;

    /// Creates a transaction sending to specified addresses.
    ///
    /// The wallet automatically:
    /// - Selects UTXOs to spend
    /// - Creates change outputs as needed
    /// - Estimates fees
    ///
    /// # Arguments
    ///
    /// * `to` - Vector of (address, amount) pairs to send to
    /// * `fee_rate` - Fee rate in satoshis per byte (0 = estimate)
    ///
    /// # Returns
    ///
    /// Returns an unsigned transaction.
    async fn create_transaction(
        &self,
        to: Vec<(String, Amount)>,
        fee_rate: Option<f64>,
    ) -> Result<Transaction, Box<dyn Error + Send + Sync>>;

    /// Signs a transaction with wallet keys.
    ///
    /// # Arguments
    ///
    /// * `tx` - The transaction to sign
    ///
    /// # Returns
    ///
    /// Returns the signed transaction.
    async fn sign_transaction(
        &self,
        tx: &Transaction,
    ) -> Result<Transaction, Box<dyn Error + Send + Sync>>;

    /// Broadcasts a signed transaction to the network.
    ///
    /// # Arguments
    ///
    /// * `tx` - The signed transaction to broadcast
    ///
    /// # Returns
    ///
    /// Returns the transaction ID if successful.
    async fn send_transaction(&self, tx: &Transaction) -> Result<String, Box<dyn Error + Send + Sync>>;

    /// Generates a new address for receiving funds.
    ///
    /// # Arguments
    ///
    /// * `label` - Optional label for this address
    ///
    /// # Returns
    ///
    /// Returns the new address as a string.
    async fn get_new_address(&self, label: Option<&str>) -> Result<String, Box<dyn Error + Send + Sync>>;

    /// Imports a private key into the wallet.
    ///
    /// # Arguments
    ///
    /// * `privkey` - The private key to import (WIF format)
    /// * `label` - Optional label for this key
    /// * `rescan` - Whether to rescan the blockchain for related transactions
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` if the key was imported successfully.
    async fn import_key(
        &self,
        privkey: &str,
        label: Option<&str>,
        rescan: bool,
    ) -> Result<(), Box<dyn Error + Send + Sync>>;

    /// Gets transaction history for the wallet.
    ///
    /// # Arguments
    ///
    /// * `count` - Maximum number of transactions to return
    /// * `skip` - Number of transactions to skip (for pagination)
    ///
    /// # Returns
    ///
    /// Returns a vector of transaction information.
    async fn get_transaction_history(
        &self,
        count: u32,
        skip: u32,
    ) -> Result<Vec<Transaction>, Box<dyn Error + Send + Sync>>;
}
