//! In-Memory Wallet Implementation
//!
//! Provides a basic wallet that tracks keys and UTXOs in memory.
//! Suitable for testing and development. Production wallets should use
//! secure key storage (hardware wallets, encrypted DBs, etc.).

use async_trait::async_trait;
use btc_domain::primitives::{Amount, Transaction};
use btc_ports::{WalletPort, Balance};
use btc_ports::wallet::UnspentOutput;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

/// In-memory wallet implementation
///
/// Tracks private keys and unspent outputs. NOT suitable for production use.
pub struct InMemoryWallet {
    // Simplified: just tracks addresses and balances
    addresses: Arc<RwLock<HashMap<String, Amount>>>,
    utxos: Arc<RwLock<Vec<UnspentOutput>>>,
}

impl InMemoryWallet {
    /// Create a new in-memory wallet
    pub fn new() -> Self {
        InMemoryWallet {
            addresses: Arc::new(RwLock::new(HashMap::new())),
            utxos: Arc::new(RwLock::new(Vec::new())),
        }
    }

    /// Add a UTXO to the wallet
    pub async fn add_utxo(&self, utxo: UnspentOutput) {
        let mut utxos = self.utxos.write().await;
        utxos.push(utxo);
    }

    /// Add an address with initial balance
    pub async fn add_address(&self, address: String, amount: Amount) {
        let mut addrs = self.addresses.write().await;
        addrs.insert(address, amount);
    }
}

impl Default for InMemoryWallet {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl WalletPort for InMemoryWallet {
    async fn get_balance(&self) -> Result<Balance, Box<dyn std::error::Error + Send + Sync>> {
        let utxos = self.utxos.read().await;

        let confirmed: i64 = utxos
            .iter()
            .filter(|u| u.confirmations >= 1)
            .map(|u| u.output.value.as_sat())
            .sum();

        let unconfirmed: i64 = utxos
            .iter()
            .filter(|u| u.confirmations == 0)
            .map(|u| u.output.value.as_sat())
            .sum();

        Ok(Balance {
            confirmed: Amount::from_sat(confirmed),
            unconfirmed: Amount::from_sat(unconfirmed),
            immature: Amount::from_sat(0),
        })
    }

    async fn list_unspent(
        &self,
        min_confirmations: u32,
        _max_amount: Option<Amount>,
    ) -> Result<Vec<UnspentOutput>, Box<dyn std::error::Error + Send + Sync>> {
        let utxos = self.utxos.read().await;
        let filtered: Vec<UnspentOutput> = utxos
            .iter()
            .filter(|u| u.confirmations >= min_confirmations)
            .cloned()
            .collect();
        Ok(filtered)
    }

    async fn create_transaction(
        &self,
        _to: Vec<(String, Amount)>,
        _fee_rate: Option<f64>,
    ) -> Result<Transaction, Box<dyn std::error::Error + Send + Sync>> {
        // TODO: Implement transaction creation
        Err("Transaction creation not yet implemented".into())
    }

    async fn sign_transaction(
        &self,
        tx: &Transaction,
    ) -> Result<Transaction, Box<dyn std::error::Error + Send + Sync>> {
        // TODO: Implement transaction signing
        Ok(tx.clone())
    }

    async fn send_transaction(&self, tx: &Transaction) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
        // TODO: Implement transaction broadcasting
        let txid = tx.txid();
        tracing::debug!("Would send transaction: {}", txid);
        Ok(txid.to_hex_reversed())
    }

    async fn get_new_address(&self, label: Option<&str>) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
        let address = format!("bitcoin_{:?}", label.unwrap_or("default"));
        tracing::debug!("Generated new address: {}", address);
        Ok(address)
    }

    async fn import_key(
        &self,
        _privkey: &str,
        _label: Option<&str>,
        _rescan: bool,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // TODO: Implement key import
        tracing::debug!("Would import private key");
        Ok(())
    }

    async fn get_transaction_history(
        &self,
        _count: u32,
        _skip: u32,
    ) -> Result<Vec<Transaction>, Box<dyn std::error::Error + Send + Sync>> {
        // Return empty for now
        Ok(Vec::new())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_wallet_creation() {
        let wallet = InMemoryWallet::new();
        let balance = wallet.get_balance().await.unwrap();
        assert_eq!(balance.confirmed.as_sat(), 0);
        assert_eq!(balance.unconfirmed.as_sat(), 0);
    }

    #[tokio::test]
    async fn test_add_address() {
        let wallet = InMemoryWallet::new();
        wallet.add_address("addr1".to_string(), Amount::from_sat(1000)).await;

        let addrs = wallet.addresses.read().await;
        assert_eq!(addrs.len(), 1);
        assert_eq!(addrs.get("addr1").unwrap().as_sat(), 1000);
    }

    #[tokio::test]
    async fn test_get_new_address() {
        let wallet = InMemoryWallet::new();
        let addr = wallet.get_new_address(Some("test")).await.unwrap();
        assert!(!addr.is_empty());
    }
}
