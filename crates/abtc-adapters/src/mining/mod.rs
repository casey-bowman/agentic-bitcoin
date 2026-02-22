//! Mining Provider Implementation
//!
//! Provides a block template provider that:
//! - Selects transactions from the mempool by fee rate
//! - Computes the correct block subsidy following the halving schedule
//! - Builds a complete block template ready for mining

use async_trait::async_trait;
use abtc_domain::primitives::{Block, BlockHeader, BlockHash, Hash256, Transaction, TxOut, Amount};
use abtc_domain::script::Script;
use abtc_ports::{BlockTemplateProvider, BlockTemplate, MempoolPort};
use abtc_domain::consensus::ConsensusParams;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Reserved weight for the coinbase transaction
const COINBASE_RESERVED_WEIGHT: u32 = 4_000;

/// Maximum block weight (4 million weight units)
const MAX_BLOCK_WEIGHT: u32 = 4_000_000;

/// Mining block template provider with mempool-aware transaction selection
/// and correct halving-based subsidy calculation.
pub struct SimpleMiner {
    current_height: Arc<RwLock<u32>>,
    best_block_hash: Arc<RwLock<BlockHash>>,
    mempool: Option<Arc<dyn MempoolPort>>,
}

impl SimpleMiner {
    /// Create a new miner without mempool access (empty blocks only)
    pub fn new() -> Self {
        SimpleMiner {
            current_height: Arc::new(RwLock::new(0)),
            best_block_hash: Arc::new(RwLock::new(BlockHash::zero())),
            mempool: None,
        }
    }

    /// Create a new miner with mempool access for transaction selection
    pub fn with_mempool(mempool: Arc<dyn MempoolPort>) -> Self {
        SimpleMiner {
            current_height: Arc::new(RwLock::new(0)),
            best_block_hash: Arc::new(RwLock::new(BlockHash::zero())),
            mempool: Some(mempool),
        }
    }

    /// Set the current block height
    pub async fn set_height(&self, height: u32) {
        let mut h = self.current_height.write().await;
        *h = height;
    }

    /// Set the best block hash
    pub async fn set_best_block_hash(&self, hash: BlockHash) {
        let mut b = self.best_block_hash.write().await;
        *b = hash;
    }

    /// Calculate block subsidy for a given height following the halving schedule.
    ///
    /// Bitcoin starts at 50 BTC per block and halves every 210,000 blocks.
    /// After 64 halvings, the subsidy drops to 0.
    fn get_block_subsidy(height: u32, params: &ConsensusParams) -> Amount {
        let halving_interval = params.subsidy_halving_interval;
        if halving_interval == 0 {
            return Amount::from_sat(5_000_000_000);
        }

        let halvings = height / halving_interval;
        if halvings >= 64 {
            return Amount::from_sat(0);
        }

        // Initial subsidy: 50 BTC = 5,000,000,000 satoshis
        let initial_subsidy: i64 = 50 * 100_000_000;
        let subsidy = initial_subsidy >> halvings;
        Amount::from_sat(subsidy)
    }

    /// Select transactions from the mempool ordered by fee rate,
    /// fitting within the block weight limit.
    async fn select_mempool_transactions(&self) -> (Vec<Transaction>, Vec<Amount>) {
        let mempool = match &self.mempool {
            Some(m) => m,
            None => return (Vec::new(), Vec::new()),
        };

        let entries = match mempool.get_all_transactions().await {
            Ok(e) => e,
            Err(_) => return (Vec::new(), Vec::new()),
        };

        if entries.is_empty() {
            return (Vec::new(), Vec::new());
        }

        // Sort by fee rate descending (greedy selection)
        let mut sorted = entries;
        sorted.sort_by(|a, b| {
            let rate_a = a.fee.as_sat() as f64 / a.size.max(1) as f64;
            let rate_b = b.fee.as_sat() as f64 / b.size.max(1) as f64;
            rate_b
                .partial_cmp(&rate_a)
                .unwrap_or(std::cmp::Ordering::Equal)
        });

        let mut selected_txs = Vec::new();
        let mut selected_fees = Vec::new();
        let mut total_weight: u32 = COINBASE_RESERVED_WEIGHT;

        for entry in sorted {
            let tx_weight = (entry.size as u32) * 4;
            if total_weight + tx_weight > MAX_BLOCK_WEIGHT {
                continue;
            }
            total_weight += tx_weight;
            selected_fees.push(entry.fee);
            selected_txs.push(entry.tx);
        }

        (selected_txs, selected_fees)
    }
}

impl Default for SimpleMiner {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl BlockTemplateProvider for SimpleMiner {
    async fn create_block_template(
        &self,
        coinbase_script: &Script,
        params: &ConsensusParams,
    ) -> Result<BlockTemplate, Box<dyn std::error::Error + Send + Sync>> {
        let height = *self.current_height.read().await;
        let prev_hash = *self.best_block_hash.read().await;

        // Select transactions from mempool
        let (mempool_txs, mempool_fees) = self.select_mempool_transactions().await;

        // Block subsidy with proper halving
        let subsidy = Self::get_block_subsidy(height, params);
        let total_fees: i64 = mempool_fees.iter().map(|f| f.as_sat()).sum();
        let coinbase_reward = Amount::from_sat(subsidy.as_sat() + total_fees);

        // Create coinbase transaction
        let coinbase_tx = Transaction::coinbase(
            height,
            coinbase_script.clone(),
            vec![TxOut::new(coinbase_reward, coinbase_script.clone())],
        );

        // Assemble transactions: coinbase first, then mempool
        let mut transactions = vec![coinbase_tx];
        transactions.extend(mempool_txs);

        // Compute merkle root
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as u32;

        let difficulty_bits = params.pow_limit_bits;

        let temp_block = Block::new(
            BlockHeader::new(0x20000000, prev_hash, Hash256::zero(), now, difficulty_bits, 0),
            transactions.clone(),
        );
        let merkle_root = temp_block.compute_merkle_root();

        // Build final block with correct merkle root
        let header = BlockHeader::new(0x20000000, prev_hash, merkle_root, now, difficulty_bits, 0);
        let block = Block::new(header, transactions);

        let mut fees = vec![Amount::from_sat(0)]; // Coinbase
        fees.extend(mempool_fees);

        let sigops = vec![0u64; fees.len()];

        let template = BlockTemplate {
            block,
            fees,
            sigops,
            target: difficulty_bits,
            height,
        };

        tracing::debug!(
            "Created block template for height {} ({} txs, subsidy {} sat, fees {} sat)",
            height,
            template.block.transactions.len(),
            subsidy.as_sat(),
            total_fees
        );

        Ok(template)
    }

    async fn get_block_height(&self) -> Result<u32, Box<dyn std::error::Error + Send + Sync>> {
        let h = self.current_height.read().await;
        Ok(*h)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_simple_miner_creation() {
        let miner = SimpleMiner::new();
        assert_eq!(miner.get_block_height().await.unwrap(), 0);
    }

    #[tokio::test]
    async fn test_create_block_template() {
        let miner = SimpleMiner::new();
        miner.set_height(1).await;
        miner.set_best_block_hash(BlockHash::genesis_mainnet()).await;

        let params = ConsensusParams::mainnet();
        let template = miner
            .create_block_template(&Script::new(), &params)
            .await
            .unwrap();

        assert_eq!(template.height, 1);
        assert!(!template.block.transactions.is_empty());
        // Should have 50 BTC reward at height 1
        let coinbase_value = template.block.transactions[0].total_output_value();
        assert_eq!(coinbase_value.as_sat(), 5_000_000_000);
    }

    #[test]
    fn test_block_subsidy_initial() {
        let params = ConsensusParams::mainnet();
        assert_eq!(SimpleMiner::get_block_subsidy(0, &params).as_sat(), 5_000_000_000);
    }

    #[test]
    fn test_block_subsidy_first_halving() {
        let params = ConsensusParams::mainnet();
        assert_eq!(SimpleMiner::get_block_subsidy(210_000, &params).as_sat(), 2_500_000_000);
    }

    #[test]
    fn test_block_subsidy_second_halving() {
        let params = ConsensusParams::mainnet();
        assert_eq!(SimpleMiner::get_block_subsidy(420_000, &params).as_sat(), 1_250_000_000);
    }

    #[test]
    fn test_block_subsidy_exhausted() {
        let params = ConsensusParams::mainnet();
        assert_eq!(SimpleMiner::get_block_subsidy(210_000 * 64, &params).as_sat(), 0);
    }
}
