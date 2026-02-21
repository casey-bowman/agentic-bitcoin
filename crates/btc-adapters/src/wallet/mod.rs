//! In-Memory Wallet Implementation
//!
//! Provides a real wallet that manages private keys, tracks UTXOs,
//! creates and signs transactions. Suitable for testing and development.
//! Production wallets should use secure key storage (hardware wallets,
//! encrypted DBs, etc.).

use async_trait::async_trait;
use btc_domain::primitives::{Amount, OutPoint, Transaction, TxOut};
use btc_domain::wallet::address::{Address, AddressType};
use btc_domain::wallet::coin_selection::{Coin, CoinSelector, SelectionStrategy};
use btc_domain::wallet::keys::PrivateKey;
use btc_domain::wallet::tx_builder::{
    InputInfo, TransactionBuilder,
    P2PKH_INPUT_VSIZE, P2WPKH_INPUT_VSIZE, P2WPKH_OUTPUT_VSIZE,
    TX_OVERHEAD_VSIZE,
};
use btc_ports::wallet::UnspentOutput;
use btc_ports::{Balance, WalletPort};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Default fee rate in satoshis per virtual byte
const DEFAULT_FEE_RATE: f64 = 10.0;

/// A tracked key with its address
#[derive(Clone)]
struct WalletKey {
    /// The private key
    private_key: PrivateKey,
    /// The derived address
    address: Address,
    /// Optional label
    #[allow(dead_code)]
    label: Option<String>,
}

/// In-memory wallet implementation
///
/// Tracks private keys and unspent outputs. Keys are stored in memory
/// (NOT suitable for production use — keys should be encrypted/in HSM).
pub struct InMemoryWallet {
    /// Keys indexed by address string
    keys: Arc<RwLock<HashMap<String, WalletKey>>>,
    /// Unspent outputs tracked by the wallet
    utxos: Arc<RwLock<Vec<UnspentOutput>>>,
    /// Whether to use mainnet addresses
    mainnet: bool,
    /// Preferred address type for new addresses
    address_type: AddressType,
    /// Key index counter (for deterministic-like key gen)
    key_counter: Arc<RwLock<u64>>,
}

impl InMemoryWallet {
    /// Create a new in-memory wallet.
    pub fn new(mainnet: bool, address_type: AddressType) -> Self {
        InMemoryWallet {
            keys: Arc::new(RwLock::new(HashMap::new())),
            utxos: Arc::new(RwLock::new(Vec::new())),
            mainnet,
            address_type,
            key_counter: Arc::new(RwLock::new(0)),
        }
    }

    /// Create a default mainnet P2WPKH wallet.
    pub fn default_mainnet() -> Self {
        Self::new(true, AddressType::P2WPKH)
    }

    /// Create a default testnet P2WPKH wallet.
    pub fn default_testnet() -> Self {
        Self::new(false, AddressType::P2WPKH)
    }

    /// Add a UTXO to the wallet.
    pub async fn add_utxo(&self, utxo: UnspentOutput) {
        let mut utxos = self.utxos.write().await;
        utxos.push(utxo);
    }

    /// Remove spent UTXOs (by outpoints).
    pub async fn remove_utxos(&self, spent_outpoints: &[OutPoint]) {
        let mut utxos = self.utxos.write().await;
        utxos.retain(|u| !spent_outpoints.contains(&u.outpoint));
    }

    /// Get the number of keys in the wallet.
    pub async fn key_count(&self) -> usize {
        let keys = self.keys.read().await;
        keys.len()
    }

    /// Find the private key for a given script pubkey.
    async fn find_key_for_script(&self, script_pubkey: &btc_domain::Script) -> Option<WalletKey> {
        let keys = self.keys.read().await;
        keys.values()
            .find(|wk| wk.address.script_pubkey.as_bytes() == script_pubkey.as_bytes())
            .cloned()
    }

    /// Estimate the input virtual size based on the UTXO's script type.
    fn estimate_input_vsize(script_pubkey: &btc_domain::Script) -> u32 {
        if script_pubkey.is_p2wpkh() {
            P2WPKH_INPUT_VSIZE
        } else if script_pubkey.is_p2pkh() {
            P2PKH_INPUT_VSIZE
        } else {
            // Default to P2WPKH size
            P2WPKH_INPUT_VSIZE
        }
    }
}

impl Default for InMemoryWallet {
    fn default() -> Self {
        Self::default_mainnet()
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

        let immature: i64 = utxos
            .iter()
            .filter(|u| u.is_coinbase && u.confirmations < 100)
            .map(|u| u.output.value.as_sat())
            .sum();

        Ok(Balance {
            confirmed: Amount::from_sat(confirmed),
            unconfirmed: Amount::from_sat(unconfirmed),
            immature: Amount::from_sat(immature),
        })
    }

    async fn list_unspent(
        &self,
        min_confirmations: u32,
        max_amount: Option<Amount>,
    ) -> Result<Vec<UnspentOutput>, Box<dyn std::error::Error + Send + Sync>> {
        let utxos = self.utxos.read().await;
        let filtered: Vec<UnspentOutput> = utxos
            .iter()
            .filter(|u| u.confirmations >= min_confirmations)
            .filter(|u| match max_amount {
                Some(max) => u.output.value.as_sat() <= max.as_sat(),
                None => true,
            })
            .cloned()
            .collect();
        Ok(filtered)
    }

    async fn create_transaction(
        &self,
        to: Vec<(String, Amount)>,
        fee_rate: Option<f64>,
    ) -> Result<Transaction, Box<dyn std::error::Error + Send + Sync>> {
        let fee_rate = fee_rate.unwrap_or(DEFAULT_FEE_RATE);

        // Decode destination addresses and build outputs
        let mut outputs = Vec::new();
        let mut total_send: i64 = 0;

        for (addr_str, amount) in &to {
            let addr = Address::decode(addr_str)
                .map_err(|e| format!("invalid address '{}': {}", addr_str, e))?;
            outputs.push(TxOut::new(*amount, addr.script_pubkey));
            total_send += amount.as_sat();
        }

        let target = Amount::from_sat(total_send);

        // Get wallet UTXOs and build coin candidates
        let utxos = self.utxos.read().await;
        let coins: Vec<Coin> = utxos
            .iter()
            .enumerate()
            .filter(|(_, u)| u.confirmations >= 1) // Only confirmed UTXOs
            .map(|(i, u)| Coin {
                index: i,
                amount: u.output.value,
                input_size: Self::estimate_input_vsize(&u.output.script_pubkey),
            })
            .collect();

        // Calculate total output size
        let output_vsize: u32 = outputs.len() as u32 * P2WPKH_OUTPUT_VSIZE
            + P2WPKH_OUTPUT_VSIZE; // +1 for change output

        // Select coins
        let selection = CoinSelector::select(
            &coins,
            target,
            fee_rate,
            output_vsize,
            TX_OVERHEAD_VSIZE,
            SelectionStrategy::LargestFirst,
        )
        .map_err(|e| format!("coin selection failed: {}", e))?;

        // Add change output if significant (> dust threshold of 546 sat)
        if selection.change.as_sat() > 546 {
            // Use our first key's address as change address
            let keys = self.keys.read().await;
            if let Some(change_key) = keys.values().next() {
                outputs.push(TxOut::new(
                    selection.change,
                    change_key.address.script_pubkey.clone(),
                ));
            }
        }

        // Build the transaction
        let mut builder = TransactionBuilder::new().version(2);

        for &coin_idx in &selection.selected_indices {
            let utxo = &utxos[coin_idx];
            let wallet_key = self.find_key_for_script(&utxo.output.script_pubkey).await;

            builder = builder.add_input(InputInfo {
                outpoint: utxo.outpoint,
                script_pubkey: utxo.output.script_pubkey.clone(),
                amount: utxo.output.value,
                signing_key: wallet_key.map(|wk| wk.private_key),
                sequence: 0xFFFFFFFE, // RBF-compatible
                tap_script_path: None,
            });
        }

        for output in outputs {
            builder = builder.add_output(output);
        }

        // Build unsigned (signing is separate step via sign_transaction)
        let tx = builder
            .build_unsigned()
            .map_err(|e| format!("build failed: {}", e))?;

        Ok(tx)
    }

    async fn sign_transaction(
        &self,
        tx: &Transaction,
    ) -> Result<Transaction, Box<dyn std::error::Error + Send + Sync>> {
        // Reconstruct builder with signing keys
        let utxos = self.utxos.read().await;
        let mut builder = TransactionBuilder::new().version(tx.version);

        for input in &tx.inputs {
            // Find the UTXO for this input
            let utxo = utxos
                .iter()
                .find(|u| u.outpoint == input.previous_output)
                .ok_or_else(|| {
                    format!("unknown UTXO for input {}", input.previous_output)
                })?;

            let wallet_key = self.find_key_for_script(&utxo.output.script_pubkey).await;

            builder = builder.add_input(InputInfo {
                outpoint: input.previous_output,
                script_pubkey: utxo.output.script_pubkey.clone(),
                amount: utxo.output.value,
                signing_key: wallet_key.map(|wk| wk.private_key),
                sequence: input.sequence,
                tap_script_path: None,
            });
        }

        for output in &tx.outputs {
            builder = builder.add_output(output.clone());
        }

        builder = builder.lock_time(tx.lock_time);

        let signed = builder
            .sign()
            .map_err(|e| format!("signing failed: {}", e))?;

        Ok(signed)
    }

    async fn send_transaction(
        &self,
        tx: &Transaction,
    ) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
        let txid = tx.txid();
        tracing::info!("Wallet: broadcasting transaction {}", txid);

        // Mark spent UTXOs
        let spent: Vec<OutPoint> = tx
            .inputs
            .iter()
            .map(|input| input.previous_output)
            .collect();
        self.remove_utxos(&spent).await;

        Ok(txid.to_hex_reversed())
    }

    async fn get_new_address(
        &self,
        label: Option<&str>,
    ) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
        // Generate a new key
        let key = PrivateKey::generate(true, self.mainnet);
        let pubkey = key.public_key();

        // Derive address based on preferred type
        let address = match self.address_type {
            AddressType::P2PKH => Address::p2pkh(&pubkey, self.mainnet),
            AddressType::P2WPKH => Address::p2wpkh(&pubkey, self.mainnet)
                .map_err(|e| format!("address derivation failed: {}", e))?,
            AddressType::P2shP2wpkh => Address::p2sh_p2wpkh(&pubkey, self.mainnet)
                .map_err(|e| format!("address derivation failed: {}", e))?,
            AddressType::P2TR => {
                // Derive x-only internal key from the compressed pubkey
                let serialized = pubkey.serialize();
                let mut x_only = [0u8; 32];
                x_only.copy_from_slice(&serialized[1..33]);
                Address::p2tr_from_internal_key(&x_only, self.mainnet)
                    .map_err(|e| format!("address derivation failed: {}", e))?
            }
        };

        let addr_string = address.encoded.clone();

        // Store the key
        let wallet_key = WalletKey {
            private_key: key,
            address,
            label: label.map(|s| s.to_string()),
        };

        let mut keys = self.keys.write().await;
        keys.insert(addr_string.clone(), wallet_key);

        // Increment counter
        let mut counter = self.key_counter.write().await;
        *counter += 1;

        tracing::debug!("Generated new {} address: {}",
            match self.address_type {
                AddressType::P2PKH => "P2PKH",
                AddressType::P2WPKH => "P2WPKH",
                AddressType::P2shP2wpkh => "P2SH-P2WPKH",
                AddressType::P2TR => "P2TR",
            },
            addr_string
        );

        Ok(addr_string)
    }

    async fn import_key(
        &self,
        privkey_wif: &str,
        label: Option<&str>,
        _rescan: bool,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let key = PrivateKey::from_wif(privkey_wif)
            .map_err(|e| format!("invalid WIF key: {}", e))?;

        let pubkey = key.public_key();

        // Derive address based on preferred type
        let address = match self.address_type {
            AddressType::P2PKH => Address::p2pkh(&pubkey, self.mainnet),
            AddressType::P2WPKH => Address::p2wpkh(&pubkey, self.mainnet)
                .map_err(|e| format!("address derivation failed: {}", e))?,
            AddressType::P2shP2wpkh => Address::p2sh_p2wpkh(&pubkey, self.mainnet)
                .map_err(|e| format!("address derivation failed: {}", e))?,
            AddressType::P2TR => {
                let serialized = pubkey.serialize();
                let mut x_only = [0u8; 32];
                x_only.copy_from_slice(&serialized[1..33]);
                Address::p2tr_from_internal_key(&x_only, self.mainnet)
                    .map_err(|e| format!("address derivation failed: {}", e))?
            }
        };

        let addr_string = address.encoded.clone();

        let wallet_key = WalletKey {
            private_key: key,
            address,
            label: label.map(|s| s.to_string()),
        };

        let mut keys = self.keys.write().await;
        keys.insert(addr_string.clone(), wallet_key);

        tracing::info!("Imported key for address: {}", addr_string);
        Ok(())
    }

    async fn get_transaction_history(
        &self,
        _count: u32,
        _skip: u32,
    ) -> Result<Vec<Transaction>, Box<dyn std::error::Error + Send + Sync>> {
        // TODO: Implement transaction history tracking
        Ok(Vec::new())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_wallet_creation() {
        let wallet = InMemoryWallet::default_mainnet();
        let balance = wallet.get_balance().await.unwrap();
        assert_eq!(balance.confirmed.as_sat(), 0);
        assert_eq!(balance.unconfirmed.as_sat(), 0);
    }

    #[tokio::test]
    async fn test_generate_p2pkh_address() {
        let wallet = InMemoryWallet::new(true, AddressType::P2PKH);
        let addr = wallet.get_new_address(Some("test")).await.unwrap();
        assert!(addr.starts_with('1'));
        assert_eq!(wallet.key_count().await, 1);
    }

    #[tokio::test]
    async fn test_generate_p2wpkh_address() {
        let wallet = InMemoryWallet::default_mainnet();
        let addr = wallet.get_new_address(None).await.unwrap();
        assert!(addr.starts_with("bc1q"));
        assert_eq!(wallet.key_count().await, 1);
    }

    #[tokio::test]
    async fn test_generate_p2sh_p2wpkh_address() {
        let wallet = InMemoryWallet::new(true, AddressType::P2shP2wpkh);
        let addr = wallet.get_new_address(None).await.unwrap();
        assert!(addr.starts_with('3'));
    }

    #[tokio::test]
    async fn test_generate_testnet_address() {
        let wallet = InMemoryWallet::default_testnet();
        let addr = wallet.get_new_address(None).await.unwrap();
        assert!(addr.starts_with("tb1q"));
    }

    #[tokio::test]
    async fn test_import_and_export_key() {
        let wallet = InMemoryWallet::default_mainnet();

        // Generate a key, export WIF
        let key = PrivateKey::generate(true, true);
        let wif = key.to_wif();

        // Import it
        wallet.import_key(&wif, Some("imported"), false).await.unwrap();
        assert_eq!(wallet.key_count().await, 1);
    }

    #[tokio::test]
    async fn test_add_and_list_utxos() {
        let wallet = InMemoryWallet::default_mainnet();

        let utxo = UnspentOutput {
            outpoint: OutPoint::new(btc_domain::Txid::zero(), 0),
            output: TxOut::new(
                Amount::from_sat(100_000),
                btc_domain::Script::new(),
            ),
            confirmations: 6,
            is_coinbase: false,
        };

        wallet.add_utxo(utxo).await;

        let unspent = wallet.list_unspent(1, None).await.unwrap();
        assert_eq!(unspent.len(), 1);
        assert_eq!(unspent[0].output.value.as_sat(), 100_000);

        let balance = wallet.get_balance().await.unwrap();
        assert_eq!(balance.confirmed.as_sat(), 100_000);
    }

    #[tokio::test]
    async fn test_multiple_addresses() {
        let wallet = InMemoryWallet::default_mainnet();

        let addr1 = wallet.get_new_address(Some("first")).await.unwrap();
        let addr2 = wallet.get_new_address(Some("second")).await.unwrap();

        assert_ne!(addr1, addr2);
        assert_eq!(wallet.key_count().await, 2);
    }

    #[tokio::test]
    async fn test_balance_confirmed_vs_unconfirmed() {
        let wallet = InMemoryWallet::default_mainnet();

        // Add a confirmed UTXO
        wallet
            .add_utxo(UnspentOutput {
                outpoint: OutPoint::new(btc_domain::Txid::zero(), 0),
                output: TxOut::new(Amount::from_sat(50_000), btc_domain::Script::new()),
                confirmations: 3,
                is_coinbase: false,
            })
            .await;

        // Add an unconfirmed UTXO
        wallet
            .add_utxo(UnspentOutput {
                outpoint: OutPoint::new(btc_domain::Txid::zero(), 1),
                output: TxOut::new(Amount::from_sat(25_000), btc_domain::Script::new()),
                confirmations: 0,
                is_coinbase: false,
            })
            .await;

        let balance = wallet.get_balance().await.unwrap();
        assert_eq!(balance.confirmed.as_sat(), 50_000);
        assert_eq!(balance.unconfirmed.as_sat(), 25_000);
    }

    #[tokio::test]
    async fn test_balance_immature_coinbase() {
        let wallet = InMemoryWallet::default_mainnet();

        // Coinbase with < 100 confirmations → immature
        wallet
            .add_utxo(UnspentOutput {
                outpoint: OutPoint::new(btc_domain::Txid::zero(), 0),
                output: TxOut::new(
                    Amount::from_sat(5_000_000_000),
                    btc_domain::Script::new(),
                ),
                confirmations: 50,
                is_coinbase: true,
            })
            .await;

        // Coinbase with >= 100 confirmations → not immature
        wallet
            .add_utxo(UnspentOutput {
                outpoint: OutPoint::new(btc_domain::Txid::zero(), 1),
                output: TxOut::new(
                    Amount::from_sat(5_000_000_000),
                    btc_domain::Script::new(),
                ),
                confirmations: 100,
                is_coinbase: true,
            })
            .await;

        let balance = wallet.get_balance().await.unwrap();
        assert_eq!(balance.immature.as_sat(), 5_000_000_000); // only the 50-conf one
    }

    #[tokio::test]
    async fn test_list_unspent_min_confirmations() {
        let wallet = InMemoryWallet::default_mainnet();

        wallet
            .add_utxo(UnspentOutput {
                outpoint: OutPoint::new(btc_domain::Txid::zero(), 0),
                output: TxOut::new(Amount::from_sat(10_000), btc_domain::Script::new()),
                confirmations: 0,
                is_coinbase: false,
            })
            .await;
        wallet
            .add_utxo(UnspentOutput {
                outpoint: OutPoint::new(btc_domain::Txid::zero(), 1),
                output: TxOut::new(Amount::from_sat(20_000), btc_domain::Script::new()),
                confirmations: 3,
                is_coinbase: false,
            })
            .await;
        wallet
            .add_utxo(UnspentOutput {
                outpoint: OutPoint::new(btc_domain::Txid::zero(), 2),
                output: TxOut::new(Amount::from_sat(30_000), btc_domain::Script::new()),
                confirmations: 10,
                is_coinbase: false,
            })
            .await;

        // min_confirmations = 0 → all 3
        let all = wallet.list_unspent(0, None).await.unwrap();
        assert_eq!(all.len(), 3);

        // min_confirmations = 1 → 2 (skip unconfirmed)
        let confirmed = wallet.list_unspent(1, None).await.unwrap();
        assert_eq!(confirmed.len(), 2);

        // min_confirmations = 6 → 1
        let deep = wallet.list_unspent(6, None).await.unwrap();
        assert_eq!(deep.len(), 1);
        assert_eq!(deep[0].output.value.as_sat(), 30_000);
    }

    #[tokio::test]
    async fn test_list_unspent_max_amount() {
        let wallet = InMemoryWallet::default_mainnet();

        wallet
            .add_utxo(UnspentOutput {
                outpoint: OutPoint::new(btc_domain::Txid::zero(), 0),
                output: TxOut::new(Amount::from_sat(1_000), btc_domain::Script::new()),
                confirmations: 1,
                is_coinbase: false,
            })
            .await;
        wallet
            .add_utxo(UnspentOutput {
                outpoint: OutPoint::new(btc_domain::Txid::zero(), 1),
                output: TxOut::new(Amount::from_sat(100_000), btc_domain::Script::new()),
                confirmations: 1,
                is_coinbase: false,
            })
            .await;

        let filtered = wallet
            .list_unspent(0, Some(Amount::from_sat(50_000)))
            .await
            .unwrap();
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].output.value.as_sat(), 1_000);
    }

    #[tokio::test]
    async fn test_remove_utxos() {
        let wallet = InMemoryWallet::default_mainnet();

        let op1 = OutPoint::new(
            btc_domain::Txid::from_hash(btc_domain::primitives::Hash256::from_bytes([0x01; 32])),
            0,
        );
        let op2 = OutPoint::new(
            btc_domain::Txid::from_hash(btc_domain::primitives::Hash256::from_bytes([0x02; 32])),
            0,
        );

        wallet
            .add_utxo(UnspentOutput {
                outpoint: op1,
                output: TxOut::new(Amount::from_sat(10_000), btc_domain::Script::new()),
                confirmations: 1,
                is_coinbase: false,
            })
            .await;
        wallet
            .add_utxo(UnspentOutput {
                outpoint: op2,
                output: TxOut::new(Amount::from_sat(20_000), btc_domain::Script::new()),
                confirmations: 1,
                is_coinbase: false,
            })
            .await;

        assert_eq!(wallet.list_unspent(0, None).await.unwrap().len(), 2);

        wallet.remove_utxos(&[op1]).await;

        let remaining = wallet.list_unspent(0, None).await.unwrap();
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0].outpoint, op2);
    }

    #[tokio::test]
    async fn test_send_transaction_removes_spent_utxos() {
        let wallet = InMemoryWallet::default_mainnet();

        let op = OutPoint::new(
            btc_domain::Txid::from_hash(btc_domain::primitives::Hash256::from_bytes([0x01; 32])),
            0,
        );

        wallet
            .add_utxo(UnspentOutput {
                outpoint: op,
                output: TxOut::new(Amount::from_sat(100_000), btc_domain::Script::new()),
                confirmations: 6,
                is_coinbase: false,
            })
            .await;

        // Create a tx that spends the UTXO
        use btc_domain::primitives::TxIn;
        let tx = Transaction::v1(
            vec![TxIn::final_input(op, btc_domain::Script::new())],
            vec![TxOut::new(Amount::from_sat(90_000), btc_domain::Script::new())],
            0,
        );

        let txid_hex = wallet.send_transaction(&tx).await.unwrap();
        assert!(!txid_hex.is_empty());

        // UTXO should be removed
        let remaining = wallet.list_unspent(0, None).await.unwrap();
        assert_eq!(remaining.len(), 0);
    }

    #[tokio::test]
    async fn test_import_invalid_wif_fails() {
        let wallet = InMemoryWallet::default_mainnet();
        let result = wallet.import_key("not-a-valid-wif", None, false).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_default_wallet() {
        let wallet = InMemoryWallet::default();
        let addr = wallet.get_new_address(None).await.unwrap();
        // Default is mainnet P2WPKH
        assert!(addr.starts_with("bc1q"));
    }

    #[tokio::test]
    async fn test_empty_balance() {
        let wallet = InMemoryWallet::default_mainnet();
        let balance = wallet.get_balance().await.unwrap();
        assert_eq!(balance.confirmed.as_sat(), 0);
        assert_eq!(balance.unconfirmed.as_sat(), 0);
        assert_eq!(balance.immature.as_sat(), 0);
    }
}
