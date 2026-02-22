//! Persistent Wallet Wrapper
//!
//! Wraps an InMemoryWallet with a WalletStore to provide automatic
//! persistence after mutation operations. The wrapper delegates all
//! WalletPort methods to the inner wallet and saves state to disk
//! after operations that modify wallet state (key generation, key
//! import, transaction sending).

use async_trait::async_trait;
use abtc_domain::primitives::{Amount, OutPoint, Transaction};
use abtc_ports::wallet::store::WalletStore;
use abtc_ports::wallet::UnspentOutput;
use abtc_ports::{Balance, WalletPort};
use std::sync::Arc;

use super::InMemoryWallet;

/// A wallet that automatically persists state to a WalletStore after mutations.
///
/// Wraps an `InMemoryWallet` and a `WalletStore` implementation. All read
/// operations delegate directly to the inner wallet. Write operations (key
/// generation, key import, transaction broadcast) trigger an automatic save
/// after the operation completes.
///
/// # Construction
///
/// Use `PersistentWallet::new()` to create a persistent wallet. If the store
/// contains previously saved state, it will be loaded into the inner wallet.
pub struct PersistentWallet {
    inner: Arc<InMemoryWallet>,
    store: Arc<dyn WalletStore>,
}

impl PersistentWallet {
    /// Create a persistent wallet, loading any existing state from the store.
    ///
    /// If the store contains a saved snapshot, it is restored into the inner
    /// wallet. If the store is empty (first run), the wallet starts fresh.
    pub async fn new(
        inner: Arc<InMemoryWallet>,
        store: Arc<dyn WalletStore>,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        // Load existing state if available
        if let Some(snapshot) = store.load().await? {
            inner.restore_from_snapshot(&snapshot).await?;
            tracing::info!("Persistent wallet: loaded existing state");
        } else {
            tracing::info!("Persistent wallet: no existing state, starting fresh");
        }

        Ok(PersistentWallet { inner, store })
    }

    /// Save the current wallet state to the store.
    pub async fn save(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let snapshot = self.inner.snapshot().await;
        self.store.save(&snapshot).await
    }

    /// Add a UTXO and persist.
    pub async fn add_utxo(&self, utxo: UnspentOutput) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.inner.add_utxo(utxo).await;
        self.save().await
    }

    /// Remove spent UTXOs and persist.
    pub async fn remove_utxos(&self, spent: &[OutPoint]) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.inner.remove_utxos(spent).await;
        self.save().await
    }

    /// Get the number of keys in the wallet.
    pub async fn key_count(&self) -> usize {
        self.inner.key_count().await
    }

    /// Get a reference to the inner InMemoryWallet.
    pub fn inner(&self) -> &InMemoryWallet {
        &self.inner
    }
}

#[async_trait]
impl WalletPort for PersistentWallet {
    async fn get_balance(&self) -> Result<Balance, Box<dyn std::error::Error + Send + Sync>> {
        self.inner.get_balance().await
    }

    async fn list_unspent(
        &self,
        min_confirmations: u32,
        max_amount: Option<Amount>,
    ) -> Result<Vec<UnspentOutput>, Box<dyn std::error::Error + Send + Sync>> {
        self.inner.list_unspent(min_confirmations, max_amount).await
    }

    async fn create_transaction(
        &self,
        to: Vec<(String, Amount)>,
        fee_rate: Option<f64>,
    ) -> Result<Transaction, Box<dyn std::error::Error + Send + Sync>> {
        self.inner.create_transaction(to, fee_rate).await
    }

    async fn sign_transaction(
        &self,
        tx: &Transaction,
    ) -> Result<Transaction, Box<dyn std::error::Error + Send + Sync>> {
        self.inner.sign_transaction(tx).await
    }

    async fn send_transaction(
        &self,
        tx: &Transaction,
    ) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
        let result = self.inner.send_transaction(tx).await?;
        // Persist after spending UTXOs
        self.save().await?;
        Ok(result)
    }

    async fn get_new_address(
        &self,
        label: Option<&str>,
    ) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
        let addr = self.inner.get_new_address(label).await?;
        // Persist after generating new key
        self.save().await?;
        Ok(addr)
    }

    async fn import_key(
        &self,
        privkey_wif: &str,
        label: Option<&str>,
        rescan: bool,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.inner.import_key(privkey_wif, label, rescan).await?;
        // Persist after importing key
        self.save().await?;
        Ok(())
    }

    async fn get_transaction_history(
        &self,
        count: u32,
        skip: u32,
    ) -> Result<Vec<Transaction>, Box<dyn std::error::Error + Send + Sync>> {
        self.inner.get_transaction_history(count, skip).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use abtc_domain::primitives::{Amount, TxOut};
    use abtc_domain::wallet::address::AddressType;
    use abtc_ports::wallet::store::WalletSnapshot;
    use std::sync::Mutex;

    /// A mock WalletStore that tracks save/load calls in memory.
    struct MockWalletStore {
        data: Mutex<Option<WalletSnapshot>>,
        save_count: Mutex<u32>,
    }

    impl MockWalletStore {
        fn new() -> Self {
            MockWalletStore {
                data: Mutex::new(None),
                save_count: Mutex::new(0),
            }
        }

        fn save_count(&self) -> u32 {
            *self.save_count.lock().unwrap()
        }
    }

    #[async_trait]
    impl WalletStore for MockWalletStore {
        async fn save(&self, snapshot: &WalletSnapshot) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
            *self.data.lock().unwrap() = Some(snapshot.clone());
            *self.save_count.lock().unwrap() += 1;
            Ok(())
        }

        async fn load(&self) -> Result<Option<WalletSnapshot>, Box<dyn std::error::Error + Send + Sync>> {
            Ok(self.data.lock().unwrap().clone())
        }

        async fn delete(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
            *self.data.lock().unwrap() = None;
            Ok(())
        }
    }

    #[tokio::test]
    async fn test_persistent_wallet_starts_fresh() {
        let inner = Arc::new(InMemoryWallet::default_testnet());
        let store = Arc::new(MockWalletStore::new());

        let wallet = PersistentWallet::new(inner, store.clone())
            .await
            .unwrap();

        let balance = wallet.get_balance().await.unwrap();
        assert_eq!(balance.confirmed.as_sat(), 0);
        assert_eq!(store.save_count(), 0);
    }

    #[tokio::test]
    async fn test_get_new_address_triggers_save() {
        let inner = Arc::new(InMemoryWallet::default_testnet());
        let store = Arc::new(MockWalletStore::new());

        let wallet = PersistentWallet::new(inner, store.clone())
            .await
            .unwrap();

        let addr = wallet.get_new_address(Some("test")).await.unwrap();
        assert!(addr.starts_with("tb1q"));
        assert_eq!(store.save_count(), 1);

        // Verify the saved snapshot has the key
        let snapshot = store.data.lock().unwrap().clone().unwrap();
        assert_eq!(snapshot.keys.len(), 1);
        assert_eq!(snapshot.keys[0].label, Some("test".to_string()));
    }

    #[tokio::test]
    async fn test_import_key_triggers_save() {
        let inner = Arc::new(InMemoryWallet::default_testnet());
        let store = Arc::new(MockWalletStore::new());

        let wallet = PersistentWallet::new(inner, store.clone())
            .await
            .unwrap();

        // Generate a key to get a valid WIF
        let key = abtc_domain::wallet::keys::PrivateKey::generate(true, false);
        let wif = key.to_wif();

        wallet.import_key(&wif, Some("imported"), false).await.unwrap();
        assert_eq!(store.save_count(), 1);
        assert_eq!(wallet.key_count().await, 1);
    }

    #[tokio::test]
    async fn test_add_utxo_triggers_save() {
        let inner = Arc::new(InMemoryWallet::default_testnet());
        let store = Arc::new(MockWalletStore::new());

        let wallet = PersistentWallet::new(inner, store.clone())
            .await
            .unwrap();

        let utxo = UnspentOutput {
            outpoint: OutPoint::new(abtc_domain::Txid::zero(), 0),
            output: TxOut::new(Amount::from_sat(50_000), abtc_domain::Script::new()),
            confirmations: 3,
            is_coinbase: false,
        };

        wallet.add_utxo(utxo).await.unwrap();
        assert_eq!(store.save_count(), 1);

        let balance = wallet.get_balance().await.unwrap();
        assert_eq!(balance.confirmed.as_sat(), 50_000);
    }

    #[tokio::test]
    async fn test_load_restores_state() {
        let store = Arc::new(MockWalletStore::new());

        // Phase 1: Create wallet, add key, save
        {
            let inner = Arc::new(InMemoryWallet::new(false, AddressType::P2WPKH));
            let wallet = PersistentWallet::new(inner, store.clone())
                .await
                .unwrap();

            wallet.get_new_address(Some("restored")).await.unwrap();
            assert_eq!(store.save_count(), 1);
        }

        // Phase 2: Create new inner wallet, load from store
        {
            let inner2 = Arc::new(InMemoryWallet::new(false, AddressType::P2WPKH));
            let wallet2 = PersistentWallet::new(inner2, store.clone())
                .await
                .unwrap();

            // Key should be restored
            assert_eq!(wallet2.key_count().await, 1);
        }
    }

    #[tokio::test]
    async fn test_multiple_saves_increment() {
        let inner = Arc::new(InMemoryWallet::default_testnet());
        let store = Arc::new(MockWalletStore::new());

        let wallet = PersistentWallet::new(inner, store.clone())
            .await
            .unwrap();

        wallet.get_new_address(None).await.unwrap();
        wallet.get_new_address(None).await.unwrap();
        wallet.get_new_address(None).await.unwrap();

        assert_eq!(store.save_count(), 3);
        assert_eq!(wallet.key_count().await, 3);
    }
}
