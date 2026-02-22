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

use abtc_domain::primitives::{Block, BlockHash, Txid};
use abtc_ports::{BlockStore, ChainStateStore, UtxoEntry, UtxoSetInfo};
use async_trait::async_trait;
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

        tracing::debug!(
            "Initialized block store with genesis block: {}",
            genesis_hash
        );
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

        // Update best block hash if this block extends the chain
        let current_best_height = {
            let best = self.best_block_hash.read().await;
            heights.get(&*best).copied().unwrap_or(0)
        };
        if height > current_best_height {
            let mut best = self.best_block_hash.write().await;
            *best = block_hash;
        }

        tracing::debug!("Stored block {} at height {}", block_hash, height);
        Ok(())
    }

    async fn get_block(
        &self,
        hash: &BlockHash,
    ) -> Result<Option<Block>, Box<dyn std::error::Error + Send + Sync>> {
        let blocks = self.blocks.read().await;
        Ok(blocks.get(hash).cloned())
    }

    async fn get_block_header(
        &self,
        hash: &BlockHash,
    ) -> Result<
        Option<abtc_domain::primitives::BlockHeader>,
        Box<dyn std::error::Error + Send + Sync>,
    > {
        let blocks = self.blocks.read().await;
        Ok(blocks.get(hash).map(|b| b.header.clone()))
    }

    async fn has_block(
        &self,
        hash: &BlockHash,
    ) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
        let blocks = self.blocks.read().await;
        Ok(blocks.contains_key(hash))
    }

    async fn get_best_block_hash(
        &self,
    ) -> Result<BlockHash, Box<dyn std::error::Error + Send + Sync>> {
        let best = self.best_block_hash.read().await;
        Ok(*best)
    }

    async fn get_block_height(
        &self,
        hash: &BlockHash,
    ) -> Result<Option<u32>, Box<dyn std::error::Error + Send + Sync>> {
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
        tracing::debug!(
            "Initialized chain state store with genesis tip: {}",
            genesis_hash
        );
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

    async fn has_utxo(
        &self,
        txid: &Txid,
        vout: u32,
    ) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
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

    async fn get_best_chain_tip(
        &self,
    ) -> Result<(BlockHash, u32), Box<dyn std::error::Error + Send + Sync>> {
        let tip = self.chain_tip.read().await;
        Ok(*tip)
    }

    async fn write_chain_tip(
        &self,
        hash: BlockHash,
        height: u32,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let mut tip = self.chain_tip.write().await;
        *tip = (hash, height);
        tracing::debug!("Updated chain tip to {} (height {})", hash, height);
        Ok(())
    }

    async fn get_utxo_set_info(
        &self,
    ) -> Result<UtxoSetInfo, Box<dyn std::error::Error + Send + Sync>> {
        let utxos = self.utxos.read().await;
        let tip = self.chain_tip.read().await;

        let txout_count = utxos.len() as u64;
        let total_sats: i64 = utxos.values().map(|e| e.output.value.as_sat()).sum();

        Ok(UtxoSetInfo {
            txout_count,
            total_amount: abtc_domain::primitives::Amount::from_sat(total_sats),
            best_block: tip.0,
            height: tip.1,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use abtc_domain::primitives::{Amount, Block, BlockHash, BlockHeader, Hash256, TxOut, Txid};
    use abtc_domain::Script;

    fn make_header(prev: BlockHash, nonce: u32) -> BlockHeader {
        BlockHeader {
            version: 1,
            prev_block_hash: prev,
            merkle_root: Hash256::from_bytes([nonce as u8; 32]),
            time: 1231006505 + nonce,
            bits: 0x1d00ffff,
            nonce,
        }
    }

    fn make_block(prev: BlockHash, nonce: u32) -> Block {
        Block::new(make_header(prev, nonce), vec![])
    }

    fn make_utxo_entry(value: i64, height: u32, is_coinbase: bool) -> UtxoEntry {
        UtxoEntry {
            output: TxOut::new(Amount::from_sat(value), Script::new()),
            height,
            is_coinbase,
        }
    }

    // ── InMemoryBlockStore tests ────────────────────────────

    #[tokio::test]
    async fn test_block_store_creation() {
        let store = InMemoryBlockStore::new();
        let best = store.get_best_block_hash().await.unwrap();
        assert_eq!(best, BlockHash::zero());
    }

    #[tokio::test]
    async fn test_store_and_retrieve_block() {
        let store = InMemoryBlockStore::new();
        let block = make_block(BlockHash::zero(), 1);
        let hash = block.block_hash();

        store.store_block(&block, 0).await.unwrap();

        let retrieved = store.get_block(&hash).await.unwrap();
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().block_hash(), hash);
    }

    #[tokio::test]
    async fn test_get_nonexistent_block() {
        let store = InMemoryBlockStore::new();
        let fake = BlockHash::from_hash(Hash256::from_bytes([0xFF; 32]));
        assert!(store.get_block(&fake).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn test_has_block() {
        let store = InMemoryBlockStore::new();
        let block = make_block(BlockHash::zero(), 1);
        let hash = block.block_hash();

        assert!(!store.has_block(&hash).await.unwrap());
        store.store_block(&block, 0).await.unwrap();
        assert!(store.has_block(&hash).await.unwrap());
    }

    #[tokio::test]
    async fn test_get_block_header() {
        let store = InMemoryBlockStore::new();
        let block = make_block(BlockHash::zero(), 42);
        let hash = block.block_hash();

        store.store_block(&block, 5).await.unwrap();

        let header = store.get_block_header(&hash).await.unwrap();
        assert!(header.is_some());
        assert_eq!(header.unwrap().nonce, 42);
    }

    #[tokio::test]
    async fn test_get_block_height() {
        let store = InMemoryBlockStore::new();
        let block = make_block(BlockHash::zero(), 1);
        let hash = block.block_hash();

        store.store_block(&block, 100).await.unwrap();
        assert_eq!(store.get_block_height(&hash).await.unwrap(), Some(100));
    }

    #[tokio::test]
    async fn test_store_multiple_blocks_chain() {
        let store = InMemoryBlockStore::new();

        let b1 = make_block(BlockHash::zero(), 1);
        let h1 = b1.block_hash();
        store.store_block(&b1, 0).await.unwrap();

        let b2 = make_block(h1, 2);
        let h2 = b2.block_hash();
        store.store_block(&b2, 1).await.unwrap();

        let b3 = make_block(h2, 3);
        let h3 = b3.block_hash();
        store.store_block(&b3, 2).await.unwrap();

        assert!(store.has_block(&h1).await.unwrap());
        assert!(store.has_block(&h2).await.unwrap());
        assert!(store.has_block(&h3).await.unwrap());
        assert_eq!(store.get_block_height(&h3).await.unwrap(), Some(2));
    }

    #[tokio::test]
    async fn test_init_with_genesis() {
        let store = InMemoryBlockStore::new();
        let genesis = make_block(BlockHash::zero(), 0);
        let genesis_hash = genesis.block_hash();

        store.init_with_genesis(genesis).await;

        assert!(store.has_block(&genesis_hash).await.unwrap());
        assert_eq!(store.get_best_block_hash().await.unwrap(), genesis_hash);
        assert_eq!(
            store.get_block_height(&genesis_hash).await.unwrap(),
            Some(0)
        );
    }

    // ── InMemoryChainStateStore tests ───────────────────────

    #[tokio::test]
    async fn test_chain_state_store_creation() {
        let store = InMemoryChainStateStore::new();
        let (tip, height) = store.get_best_chain_tip().await.unwrap();
        assert_eq!(tip, BlockHash::zero());
        assert_eq!(height, 0);
    }

    #[tokio::test]
    async fn test_write_and_read_utxo() {
        let store = InMemoryChainStateStore::new();
        let txid = Txid::from_hash(Hash256::from_bytes([0x01; 32]));

        store
            .write_utxo_set(vec![(txid, 0, make_utxo_entry(50_000, 10, false))], vec![])
            .await
            .unwrap();

        let utxo = store.get_utxo(&txid, 0).await.unwrap();
        assert!(utxo.is_some());
        assert_eq!(utxo.unwrap().output.value.as_sat(), 50_000);
    }

    #[tokio::test]
    async fn test_has_utxo() {
        let store = InMemoryChainStateStore::new();
        let txid = Txid::from_hash(Hash256::from_bytes([0x02; 32]));

        assert!(!store.has_utxo(&txid, 0).await.unwrap());

        store
            .write_utxo_set(vec![(txid, 0, make_utxo_entry(100, 1, false))], vec![])
            .await
            .unwrap();

        assert!(store.has_utxo(&txid, 0).await.unwrap());
        assert!(!store.has_utxo(&txid, 1).await.unwrap());
    }

    #[tokio::test]
    async fn test_atomic_add_and_remove() {
        let store = InMemoryChainStateStore::new();
        let txid1 = Txid::from_hash(Hash256::from_bytes([0x01; 32]));
        let txid2 = Txid::from_hash(Hash256::from_bytes([0x02; 32]));

        // Add two UTXOs
        store
            .write_utxo_set(
                vec![
                    (txid1, 0, make_utxo_entry(100, 1, false)),
                    (txid2, 0, make_utxo_entry(200, 1, false)),
                ],
                vec![],
            )
            .await
            .unwrap();

        // Add one, remove one
        let txid3 = Txid::from_hash(Hash256::from_bytes([0x03; 32]));
        store
            .write_utxo_set(
                vec![(txid3, 0, make_utxo_entry(300, 2, false))],
                vec![(txid1, 0)],
            )
            .await
            .unwrap();

        assert!(!store.has_utxo(&txid1, 0).await.unwrap());
        assert!(store.has_utxo(&txid2, 0).await.unwrap());
        assert!(store.has_utxo(&txid3, 0).await.unwrap());
    }

    #[tokio::test]
    async fn test_write_and_read_chain_tip() {
        let store = InMemoryChainStateStore::new();
        let tip_hash = BlockHash::from_hash(Hash256::from_bytes([0x42; 32]));

        store.write_chain_tip(tip_hash, 500).await.unwrap();

        let (hash, height) = store.get_best_chain_tip().await.unwrap();
        assert_eq!(hash, tip_hash);
        assert_eq!(height, 500);
    }

    #[tokio::test]
    async fn test_utxo_set_info() {
        let store = InMemoryChainStateStore::new();
        let txid1 = Txid::from_hash(Hash256::from_bytes([0x01; 32]));
        let txid2 = Txid::from_hash(Hash256::from_bytes([0x02; 32]));
        let tip = BlockHash::from_hash(Hash256::from_bytes([0xFF; 32]));

        store
            .write_utxo_set(
                vec![
                    (txid1, 0, make_utxo_entry(100_000, 1, false)),
                    (txid2, 0, make_utxo_entry(200_000, 2, false)),
                ],
                vec![],
            )
            .await
            .unwrap();
        store.write_chain_tip(tip, 10).await.unwrap();

        let info = store.get_utxo_set_info().await.unwrap();
        assert_eq!(info.txout_count, 2);
        assert_eq!(info.total_amount.as_sat(), 300_000);
        assert_eq!(info.best_block, tip);
        assert_eq!(info.height, 10);
    }

    #[tokio::test]
    async fn test_multiple_vouts_same_txid() {
        let store = InMemoryChainStateStore::new();
        let txid = Txid::from_hash(Hash256::from_bytes([0x10; 32]));

        store
            .write_utxo_set(
                vec![
                    (txid, 0, make_utxo_entry(1_000, 5, false)),
                    (txid, 1, make_utxo_entry(2_000, 5, false)),
                    (txid, 2, make_utxo_entry(3_000, 5, false)),
                ],
                vec![],
            )
            .await
            .unwrap();

        assert_eq!(
            store
                .get_utxo(&txid, 0)
                .await
                .unwrap()
                .unwrap()
                .output
                .value
                .as_sat(),
            1_000
        );
        assert_eq!(
            store
                .get_utxo(&txid, 2)
                .await
                .unwrap()
                .unwrap()
                .output
                .value
                .as_sat(),
            3_000
        );

        // Remove middle vout only
        store.write_utxo_set(vec![], vec![(txid, 1)]).await.unwrap();
        assert!(store.has_utxo(&txid, 0).await.unwrap());
        assert!(!store.has_utxo(&txid, 1).await.unwrap());
        assert!(store.has_utxo(&txid, 2).await.unwrap());
    }

    #[tokio::test]
    async fn test_coinbase_utxo_entry() {
        let store = InMemoryChainStateStore::new();
        let txid = Txid::from_hash(Hash256::from_bytes([0xCB; 32]));

        store
            .write_utxo_set(
                vec![(txid, 0, make_utxo_entry(5_000_000_000, 0, true))],
                vec![],
            )
            .await
            .unwrap();

        let entry = store.get_utxo(&txid, 0).await.unwrap().unwrap();
        assert!(entry.is_coinbase);
        assert_eq!(entry.height, 0);
        assert_eq!(entry.output.value.as_sat(), 5_000_000_000);
    }

    #[tokio::test]
    async fn test_init_chain_state_genesis() {
        let store = InMemoryChainStateStore::new();
        let genesis_hash = BlockHash::from_hash(Hash256::from_bytes([0xAA; 32]));

        store.init_with_genesis(genesis_hash).await;

        let (tip, height) = store.get_best_chain_tip().await.unwrap();
        assert_eq!(tip, genesis_hash);
        assert_eq!(height, 0);
    }

    // ═══════════════════════════════════════════════════════════════════
    // Regression tests — Session 14, Part 4 (code review fixes)
    //
    // These tests were written specifically for this implementation to
    // guard against bugs found during a code review. They are NOT ports
    // of Bitcoin Core test vectors. Each test name begins with
    // `regression_` so it can be distinguished from the implementation
    // unit tests above, which exercise baseline functionality.
    // ═══════════════════════════════════════════════════════════════════

    #[tokio::test]
    async fn regression_store_block_updates_best_block_hash() {
        // Review finding #8: store_block never updated best_block_hash, so
        // get_best_block_hash always returned BlockHash::zero().
        let store = InMemoryBlockStore::new();

        let b1 = make_block(BlockHash::zero(), 1);
        let h1 = b1.block_hash();
        store.store_block(&b1, 1).await.unwrap();

        let best = store.get_best_block_hash().await.unwrap();
        assert_eq!(best, h1, "best block hash should update after store_block");

        // Storing a higher block should update again.
        let b2 = make_block(h1, 2);
        let h2 = b2.block_hash();
        store.store_block(&b2, 2).await.unwrap();

        let best = store.get_best_block_hash().await.unwrap();
        assert_eq!(best, h2, "best block hash should follow the highest block");
    }

    #[tokio::test]
    async fn regression_store_block_does_not_regress_best_hash() {
        // Safety net: storing a block at a lower height must NOT demote
        // the best block hash.
        let store = InMemoryBlockStore::new();

        let b1 = make_block(BlockHash::zero(), 1);
        let h1 = b1.block_hash();
        store.store_block(&b1, 10).await.unwrap();

        let b2 = make_block(BlockHash::zero(), 99);
        store.store_block(&b2, 5).await.unwrap(); // lower height

        let best = store.get_best_block_hash().await.unwrap();
        assert_eq!(
            best, h1,
            "best block hash should not regress to a lower height"
        );
    }
}
