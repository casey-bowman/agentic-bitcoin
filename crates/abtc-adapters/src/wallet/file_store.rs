//! File-Based Wallet Store Implementation
//!
//! Provides JSON file persistence for wallet state. Uses atomic writes
//! (temp file + rename) to prevent corruption. File permissions are set
//! to 0o600 (owner read/write only) to protect private keys.

use abtc_ports::wallet::store::{WalletKeyEntry, WalletSnapshot, WalletStore, WalletUtxoEntry};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// JSON-serializable representation of a wallet snapshot.
///
/// This mirrors `WalletSnapshot` but with serde derives for JSON encoding.
/// We keep serde out of the port types themselves.
#[derive(Serialize, Deserialize)]
struct WalletFileData {
    version: u32,
    mainnet: bool,
    address_type: String,
    key_counter: u64,
    keys: Vec<KeyFileEntry>,
    utxos: Vec<UtxoFileEntry>,
}

#[derive(Serialize, Deserialize)]
struct KeyFileEntry {
    address: String,
    wif: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    label: Option<String>,
}

#[derive(Serialize, Deserialize)]
struct UtxoFileEntry {
    txid: String,
    vout: u32,
    amount_sat: i64,
    script_pubkey_hex: String,
    confirmations: u32,
    is_coinbase: bool,
}

/// File-based wallet store using JSON format.
///
/// Saves wallet state to a JSON file with atomic writes and restricted
/// file permissions. Suitable for development and testing; production
/// wallets should use encrypted storage.
pub struct FileBasedWalletStore {
    path: PathBuf,
}

impl FileBasedWalletStore {
    /// Create a new file-based wallet store at the given path.
    pub fn new<P: AsRef<Path>>(path: P) -> Self {
        FileBasedWalletStore {
            path: path.as_ref().to_path_buf(),
        }
    }

    /// Get the file path.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Convert a port-layer snapshot to a file-layer data struct.
    fn to_file_data(snapshot: &WalletSnapshot) -> WalletFileData {
        WalletFileData {
            version: snapshot.version,
            mainnet: snapshot.mainnet,
            address_type: snapshot.address_type.clone(),
            key_counter: snapshot.key_counter,
            keys: snapshot
                .keys
                .iter()
                .map(|k| KeyFileEntry {
                    address: k.address.clone(),
                    wif: k.wif.clone(),
                    label: k.label.clone(),
                })
                .collect(),
            utxos: snapshot
                .utxos
                .iter()
                .map(|u| UtxoFileEntry {
                    txid: u.txid_hex.clone(),
                    vout: u.vout,
                    amount_sat: u.amount_sat,
                    script_pubkey_hex: u.script_pubkey_hex.clone(),
                    confirmations: u.confirmations,
                    is_coinbase: u.is_coinbase,
                })
                .collect(),
        }
    }

    /// Convert a file-layer data struct back to a port-layer snapshot.
    fn from_file_data(data: WalletFileData) -> WalletSnapshot {
        WalletSnapshot {
            version: data.version,
            mainnet: data.mainnet,
            address_type: data.address_type,
            key_counter: data.key_counter,
            keys: data
                .keys
                .into_iter()
                .map(|k| WalletKeyEntry {
                    address: k.address,
                    wif: k.wif,
                    label: k.label,
                })
                .collect(),
            utxos: data
                .utxos
                .into_iter()
                .map(|u| WalletUtxoEntry {
                    txid_hex: u.txid,
                    vout: u.vout,
                    amount_sat: u.amount_sat,
                    script_pubkey_hex: u.script_pubkey_hex,
                    confirmations: u.confirmations,
                    is_coinbase: u.is_coinbase,
                })
                .collect(),
        }
    }
}

#[async_trait]
impl WalletStore for FileBasedWalletStore {
    async fn save(
        &self,
        snapshot: &WalletSnapshot,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let data = Self::to_file_data(snapshot);
        let json = serde_json::to_string_pretty(&data)
            .map_err(|e| format!("JSON serialization failed: {}", e))?;

        // Ensure parent directory exists
        if let Some(parent) = self.path.parent() {
            if !parent.exists() {
                tokio::fs::create_dir_all(parent).await.map_err(|e| {
                    format!("failed to create directory {}: {}", parent.display(), e)
                })?;
            }
        }

        // Atomic write: write to temp file, then rename
        let temp_path = self.path.with_extension("tmp");
        tokio::fs::write(&temp_path, json.as_bytes())
            .await
            .map_err(|e| format!("failed to write temp file {}: {}", temp_path.display(), e))?;

        // Set restrictive permissions (Unix only) — 0o600 = owner read/write
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::Permissions::from_mode(0o600);
            tokio::fs::set_permissions(&temp_path, perms)
                .await
                .map_err(|e| format!("failed to set permissions: {}", e))?;
        }

        // Atomic rename
        tokio::fs::rename(&temp_path, &self.path)
            .await
            .map_err(|e| {
                format!(
                    "failed to rename {} → {}: {}",
                    temp_path.display(),
                    self.path.display(),
                    e
                )
            })?;

        tracing::debug!("Wallet state saved to {}", self.path.display());
        Ok(())
    }

    async fn load(
        &self,
    ) -> Result<Option<WalletSnapshot>, Box<dyn std::error::Error + Send + Sync>> {
        // Missing file is not an error — it means first run
        if !self.path.exists() {
            return Ok(None);
        }

        let contents = tokio::fs::read_to_string(&self.path)
            .await
            .map_err(|e| format!("failed to read wallet file {}: {}", self.path.display(), e))?;

        let data: WalletFileData = serde_json::from_str(&contents)
            .map_err(|e| format!("failed to parse wallet file {}: {}", self.path.display(), e))?;

        // Version check for forward compatibility
        if data.version != 1 {
            return Err(format!(
                "unsupported wallet file version {} (expected 1)",
                data.version
            )
            .into());
        }

        tracing::debug!("Wallet state loaded from {}", self.path.display());
        Ok(Some(Self::from_file_data(data)))
    }

    async fn delete(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        if self.path.exists() {
            tokio::fs::remove_file(&self.path).await.map_err(|e| {
                format!(
                    "failed to delete wallet file {}: {}",
                    self.path.display(),
                    e
                )
            })?;
            tracing::debug!("Wallet file deleted: {}", self.path.display());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    use std::sync::atomic::{AtomicU64, Ordering};

    /// Atomic counter to guarantee unique temp paths even when tests run
    /// concurrently and share the same nanosecond timestamp.
    static TEST_COUNTER: AtomicU64 = AtomicU64::new(0);

    fn temp_wallet_path() -> PathBuf {
        let mut path = std::env::temp_dir();
        let ts: u64 = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64;
        let seq = TEST_COUNTER.fetch_add(1, Ordering::SeqCst);
        path.push(format!("test_wallet_{}_{}.json", ts, seq));
        path
    }

    fn sample_snapshot() -> WalletSnapshot {
        WalletSnapshot {
            version: 1,
            mainnet: true,
            address_type: "p2wpkh".to_string(),
            key_counter: 3,
            keys: vec![
                WalletKeyEntry {
                    address: "bc1qtest1".to_string(),
                    wif: "L1aW4aubDFB7yfras2S1mN3bqg9nwySY8nkoLmJebSLD5BWv3ENZ".to_string(),
                    label: Some("first".to_string()),
                },
                WalletKeyEntry {
                    address: "bc1qtest2".to_string(),
                    wif: "KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn".to_string(),
                    label: None,
                },
            ],
            utxos: vec![WalletUtxoEntry {
                txid_hex: "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"
                    .to_string(),
                vout: 0,
                amount_sat: 100_000,
                script_pubkey_hex: "0014abcdef1234567890abcdef1234567890abcdef12".to_string(),
                confirmations: 6,
                is_coinbase: false,
            }],
        }
    }

    #[tokio::test]
    async fn test_save_and_load_roundtrip() {
        let path = temp_wallet_path();
        let store = FileBasedWalletStore::new(&path);
        let snapshot = sample_snapshot();

        // Save
        store.save(&snapshot).await.unwrap();
        assert!(path.exists());

        // Load
        let loaded = store.load().await.unwrap().expect("should load snapshot");
        assert_eq!(loaded.version, 1);
        assert_eq!(loaded.mainnet, true);
        assert_eq!(loaded.address_type, "p2wpkh");
        assert_eq!(loaded.key_counter, 3);
        assert_eq!(loaded.keys.len(), 2);
        assert_eq!(loaded.keys[0].address, snapshot.keys[0].address);
        assert_eq!(loaded.keys[0].wif, snapshot.keys[0].wif);
        assert_eq!(loaded.keys[0].label, Some("first".to_string()));
        assert_eq!(loaded.keys[1].label, None);
        assert_eq!(loaded.utxos.len(), 1);
        assert_eq!(loaded.utxos[0].amount_sat, 100_000);
        assert_eq!(loaded.utxos[0].confirmations, 6);

        // Cleanup
        let _ = tokio::fs::remove_file(&path).await;
    }

    #[tokio::test]
    async fn test_load_missing_file_returns_none() {
        let path = temp_wallet_path();
        let store = FileBasedWalletStore::new(&path);

        let result = store.load().await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_load_corrupt_json_returns_error() {
        let path = temp_wallet_path();
        tokio::fs::write(&path, b"not valid json{{{").await.unwrap();

        let store = FileBasedWalletStore::new(&path);
        let result = store.load().await;
        assert!(result.is_err());

        let _ = tokio::fs::remove_file(&path).await;
    }

    #[tokio::test]
    async fn test_load_wrong_version_returns_error() {
        let path = temp_wallet_path();
        let bad_data = serde_json::json!({
            "version": 99,
            "mainnet": true,
            "address_type": "p2wpkh",
            "key_counter": 0,
            "keys": [],
            "utxos": []
        });
        tokio::fs::write(&path, serde_json::to_string(&bad_data).unwrap().as_bytes())
            .await
            .unwrap();

        let store = FileBasedWalletStore::new(&path);
        let result = store.load().await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("version"));

        let _ = tokio::fs::remove_file(&path).await;
    }

    #[tokio::test]
    async fn test_delete_existing_file() {
        let path = temp_wallet_path();
        let store = FileBasedWalletStore::new(&path);
        let snapshot = sample_snapshot();

        store.save(&snapshot).await.unwrap();
        assert!(path.exists());

        store.delete().await.unwrap();
        assert!(!path.exists());

        // Load after delete should return None
        let result = store.load().await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_delete_nonexistent_file_ok() {
        let path = temp_wallet_path();
        let store = FileBasedWalletStore::new(&path);

        // Should not error
        store.delete().await.unwrap();
    }

    #[tokio::test]
    async fn test_save_creates_parent_directories() {
        let mut path = std::env::temp_dir();
        let id: u64 = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64;
        path.push(format!("nested_{}", id));
        path.push("subdir");
        path.push("wallet.json");

        let store = FileBasedWalletStore::new(&path);
        let snapshot = sample_snapshot();

        store.save(&snapshot).await.unwrap();
        assert!(path.exists());

        // Cleanup
        let grandparent = path.parent().unwrap().parent().unwrap();
        let _ = tokio::fs::remove_dir_all(grandparent).await;
    }

    #[tokio::test]
    async fn test_save_overwrites_existing() {
        let path = temp_wallet_path();
        let store = FileBasedWalletStore::new(&path);

        let mut snapshot1 = sample_snapshot();
        snapshot1.key_counter = 1;
        store.save(&snapshot1).await.unwrap();

        let mut snapshot2 = sample_snapshot();
        snapshot2.key_counter = 42;
        store.save(&snapshot2).await.unwrap();

        let loaded = store.load().await.unwrap().unwrap();
        assert_eq!(loaded.key_counter, 42);

        let _ = tokio::fs::remove_file(&path).await;
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn test_file_permissions_0o600() {
        use std::os::unix::fs::PermissionsExt;

        let path = temp_wallet_path();
        let store = FileBasedWalletStore::new(&path);
        store.save(&sample_snapshot()).await.unwrap();

        let metadata = tokio::fs::metadata(&path).await.unwrap();
        let mode = metadata.permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "wallet file should have 0o600 permissions");

        let _ = tokio::fs::remove_file(&path).await;
    }

    #[tokio::test]
    async fn test_empty_wallet_roundtrip() {
        let path = temp_wallet_path();
        let store = FileBasedWalletStore::new(&path);

        let snapshot = WalletSnapshot {
            version: 1,
            mainnet: false,
            address_type: "p2tr".to_string(),
            key_counter: 0,
            keys: vec![],
            utxos: vec![],
        };

        store.save(&snapshot).await.unwrap();
        let loaded = store.load().await.unwrap().unwrap();

        assert_eq!(loaded.mainnet, false);
        assert_eq!(loaded.address_type, "p2tr");
        assert_eq!(loaded.key_counter, 0);
        assert!(loaded.keys.is_empty());
        assert!(loaded.utxos.is_empty());

        let _ = tokio::fs::remove_file(&path).await;
    }
}
