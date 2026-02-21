//! Storage implementations
//!
//! Provides both in-memory (HashMap-based) and persistent (RocksDB-based)
//! implementations of BlockStore and ChainStateStore traits.
//!
//! - `InMemoryBlockStore` / `InMemoryChainStateStore` — suitable for testing
//! - `RocksDbBlockStore` / `RocksDbChainStateStore` — persistent, crash-safe
//!   (requires the `rocksdb-storage` feature)

#[cfg(feature = "rocksdb-storage")]
pub mod rocksdb_store;

#[cfg(feature = "rocksdb-storage")]
pub use rocksdb_store::{RocksDbBlockStore, RocksDbChainStateStore};

use async_trait::async_trait;
use btc_domain::primitives::{Block, BlockHash, Txid};
use btc_ports::{BlockStore, ChainStateStore, UtxoEntry};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

/// In-memory implementation of BlockStore using HashMap and RwLock
pub struct InMemoryBlockStore {
    blocks: Arc<RwLock<HashMap<BlockHash, Block>>>,
    best_block_hash: Arc<RwLock<BlockHash>>,
    block_heights: Arc<RwLock<HashMap<BlockHash, u32>>>,
}

impl InMemoryBlockStore {
    /// Create a new in-memory block store
    pub fn new() -> Self {
        InMemoryBlockStore {
            blocks: Arc::new(RwLock::new(HashMap::new())),
            best_block_hash: Arc::new(RwLock::new(BlockHash::zero())),
            block_heights: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Initialize with genesis block
    pub async fn init_with_genesis(&self, genesis: Block) {
        let genesis_hash = genesis.block_hash();
        let mut blocks = self.blocks.write().await;
        blocks.insert(genesis_hash, genesis);

        let mut best = self.best_block_hash.write().await;
        *best = genesis_hash;

        let mut heights = self.block_heights.write().await;
        heights.insert(genesis_hash, 0);

        tracing::debug!("Initialized block store with genesis block: {}", genesis_hash);
    }
}

impl Default for InMemoryBlockStore {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl BlockStore for InMemoryBlockStore {
    async fn store_block(
        &self,
        block: &Block,
        height: u32,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let block_hash = block.block_hash();
        let mut blocks = self.blocks.write().await;
        blocks.insert(block_hash, block.clone());

        let mut heights = self.block_heights.write().await;
        heights.insert(block_hash, height);

        tracing::debug!("Stored block {} at height {}", block_hash, height);
        Ok(())
    }

    async fn get_block(&self, hash: &BlockHash) -> Result<Option<Block>, Box<dyn std::error::Error + Send + Sync>> {
        let blocks = self.blocks.read().await;
        Ok(blocks.get(hash).cloned())
    }

    async fn get_block_header(
        &self,
        hash: &BlockHash,
    ) -> Result<Option<btc_domain::primitives::BlockHeader>, Box<dyn std::error::Error + Send + Sync>> {
        let blocks = self.blocks.read().await;
        Ok(blocks.get(hash).map(|b| b.header.clone()))
    }

    async fn has_block(&self, hash: &BlockHash) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
        let blocks = self.blocks.read().await;
        Ok(blocks.contains_key(hash))
    }

    async fn get_best_block_hash(&self) -> Result<BlockHash, Box<dyn std::error::Error + Send + Sync>> {
        let best = self.best_block_hash.read().await;
        Ok(*best)
    }

    async fn get_block_height(&self, hash: &BlockHash) -> Result<Option<u32>, Box<dyn std::error::Error + Send + Sync>> {
        let heights = self.block_heights.read().await;
        Ok(heights.get(hash).copied())
    }
}

/// In-memory implementation of ChainStateStore using HashMap and RwLock
pub struct InMemoryChainStateStore {
    utxos: Arc<RwLock<HashMap<(Txid, u32), UtxoEntry>>>,
    chain_tip: Arc<RwLock<(BlockHash, u32)>>,
}

impl InMemoryChainStateStore {
    /// Create a new in-memory chain state store
    pub fn new() -> Self {
        InMemoryChainStateStore {
            utxos: Arc::new(RwLock::new(HashMap::new())),
            chain_tip: Arc::new(RwLock::new((BlockHash::zero(), 0))),
        }
    }

    /// Initialize with genesis block tip
    pub async fn init_with_genesis(&self, genesis_hash: BlockHash) {
        let mut tip = self.chain_tip.write().await;
        *tip = (genesis_hash, 0);
        tracing::debug!("Initialized chain state store with genesis tip: {}", genesis_hash);
    }
}

impl Default for InMemoryChainStateStore {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl ChainStateStore for InMemoryChainStateStore {
    async fn get_utxo(
        &self,
        txid: &Txid,
        vout: u32,
    ) -> Result<Option<UtxoEntry>, Box<dyn std::error::Error + Send + Sync>> {
        let utxos = self.utxos.read().await;
        Ok(utxos.get(&(*txid, vout)).cloned())
    }

    async fn has_utxo(&self, txid: &Txid, vout: u32) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
        let utxos = self.utxos.read().await;
        Ok(utxos.contains_key(&(*txid, vout)))
    }

    async fn write_utxo_set(
        &self,
        adds: Vec<(Txid, u32, UtxoEntry)>,
        removes: Vec<(Txid, u32)>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let mut utxos = self.utxos.write().await;

        for (txid, vout, entry) in adds {
            utxos.insert((txid, vout), entry);
        }

        for (txid, vout) in removes {
            utxos.remove(&(txid, vout));
        }

        tracing::debug!("Updated UTXO set");
        Ok(())
    }

    async fn get_best_chain_tip(&self) -> Result<(BlockHash, u32), Box<dyn std::error::Error + Send + Sync>> {
        let tip = self.chain_tip.read().await;
        Ok(*tip)
    }

    async fn write_chain_tip(&self, hash: BlockHash, height: u32) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let mut tip = self.chain_tip.write().await;
        *tip = (hash, height);
        tracing::debug!("Updated chain tip to {} (height {})", hash, height);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_block_store_creation() {
        let store = InMemoryBlockStore::new();
        let best = store.get_best_block_hash().await.unwrap();
        assert_eq!(best, BlockHash::zero());
    }

    #[tokio::test]
    async fn test_chain_state_store_creation() {
        let store = InMemoryChainStateStore::new();
        let (tip, height) = store.get_best_chain_tip().await.unwrap();
        assert_eq!(tip, BlockHash::zero());
        assert_eq!(height, 0);
    }
}
