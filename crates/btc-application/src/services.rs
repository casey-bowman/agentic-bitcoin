//! Application services that orchestrate domain logic through ports
//!
//! Services implement use cases by coordinating the domain layer with adapters.

use btc_domain::consensus::rules;
use btc_domain::consensus::ConsensusParams;
use btc_domain::primitives::{Block, BlockHash, Transaction};
use btc_ports::{BlockStore, ChainStateStore, MempoolPort, BlockTemplateProvider, PeerManager, UtxoEntry};
use std::sync::Arc;

/// Blockchain validation and acceptance service
///
/// Orchestrates block validation, chain updates, UTXO set management, and consensus enforcement.
pub struct BlockchainService {
    block_store: Arc<dyn BlockStore>,
    chain_state: Arc<dyn ChainStateStore>,
    peer_manager: Arc<dyn PeerManager>,
}

impl BlockchainService {
    /// Create a new blockchain service
    pub fn new(
        block_store: Arc<dyn BlockStore>,
        chain_state: Arc<dyn ChainStateStore>,
        peer_manager: Arc<dyn PeerManager>,
    ) -> Self {
        BlockchainService {
            block_store,
            chain_state,
            peer_manager,
        }
    }

    /// Validate and accept a block into the blockchain
    ///
    /// This performs:
    /// 1. Duplicate block check
    /// 2. Merkle root verification
    /// 3. Consensus rule validation (block structure, transaction validity)
    /// 4. UTXO set update (remove spent, add new outputs)
    /// 5. Chain tip update
    /// 6. Broadcast to peers
    pub async fn validate_and_accept_block(&self, block: &Block) -> Result<(), String> {
        let block_hash = block.block_hash();
        tracing::info!("Validating block: {}", block_hash);

        // Check if block already exists
        if self.block_store.has_block(&block_hash).await.map_err(|e| e.to_string())? {
            return Err("Block already exists".to_string());
        }

        // Verify merkle root
        if !block.has_valid_merkle_root() {
            return Err("Invalid merkle root".to_string());
        }

        // Validate block against consensus rules
        let params = ConsensusParams::mainnet(); // TODO: Store network params in service
        rules::check_block(block, &params).map_err(|e| format!("Block validation failed: {}", e))?;

        // Get current chain tip height
        let (_, current_height) = self.chain_state
            .get_best_chain_tip()
            .await
            .map_err(|e| e.to_string())?;
        let new_height = current_height + 1;

        // Update UTXO set: process each transaction
        let mut utxo_adds = Vec::new();
        let mut utxo_removes = Vec::new();

        for (tx_idx, tx) in block.transactions.iter().enumerate() {
            let txid = tx.txid();

            // For non-coinbase transactions, mark inputs as spent
            if !tx.is_coinbase() {
                for input in &tx.inputs {
                    utxo_removes.push((input.previous_output.txid, input.previous_output.vout));
                }
            }

            // Add new outputs to UTXO set
            for (vout, output) in tx.outputs.iter().enumerate() {
                let entry = UtxoEntry {
                    output: output.clone(),
                    height: new_height,
                    is_coinbase: tx_idx == 0,
                };
                utxo_adds.push((txid, vout as u32, entry));
            }
        }

        // Write UTXO set changes
        self.chain_state
            .write_utxo_set(utxo_adds, utxo_removes)
            .await
            .map_err(|e| e.to_string())?;

        // Store the block
        self.block_store
            .store_block(block, new_height)
            .await
            .map_err(|e| e.to_string())?;

        // Update chain tip
        self.chain_state
            .write_chain_tip(block_hash, new_height)
            .await
            .map_err(|e| e.to_string())?;

        // Broadcast to peers
        let peer_count = self.peer_manager
            .broadcast_block(block)
            .await
            .map_err(|e| e.to_string())?;

        tracing::info!(
            "Accepted block {} at height {} (broadcast to {} peers)",
            block_hash,
            new_height,
            peer_count
        );

        Ok(())
    }

    /// Process a new transaction (validate and prepare for mempool)
    ///
    /// Performs:
    /// 1. Basic consensus validation (structure, sizes, amounts)
    /// 2. Double-spend check against UTXO set
    /// 3. Input value verification (all inputs exist in UTXO set)
    pub async fn process_new_transaction(&self, tx: &Transaction) -> Result<(), String> {
        let txid = tx.txid();
        tracing::debug!("Processing transaction: {}", txid);

        // Validate transaction against consensus rules
        rules::check_transaction(tx).map_err(|e| format!("Transaction validation failed: {}", e))?;

        // Coinbase transactions can't be submitted to mempool
        if tx.is_coinbase() {
            return Err("Cannot submit coinbase transaction to mempool".to_string());
        }

        // Check that all inputs reference existing UTXOs (no double-spends)
        for input in &tx.inputs {
            let has_utxo = self.chain_state
                .has_utxo(&input.previous_output.txid, input.previous_output.vout)
                .await
                .map_err(|e| e.to_string())?;

            if !has_utxo {
                return Err(format!(
                    "Input {}:{} references non-existent or already-spent UTXO",
                    input.previous_output.txid, input.previous_output.vout
                ));
            }
        }

        // Verify total input value >= total output value
        let mut total_input_value: i64 = 0;
        for input in &tx.inputs {
            let utxo = self.chain_state
                .get_utxo(&input.previous_output.txid, input.previous_output.vout)
                .await
                .map_err(|e| e.to_string())?
                .ok_or_else(|| "UTXO disappeared during validation".to_string())?;

            total_input_value += utxo.output.value.as_sat();
        }

        let total_output_value = tx.total_output_value().as_sat();
        if total_input_value < total_output_value {
            return Err(format!(
                "Transaction outputs ({}) exceed inputs ({})",
                total_output_value, total_input_value
            ));
        }

        let fee = total_input_value - total_output_value;
        tracing::debug!(
            "Transaction {} validated (fee: {} satoshis)",
            txid,
            fee
        );

        Ok(())
    }

    /// Get current chain information
    pub async fn get_chain_info(&self) -> Result<ChainInfo, String> {
        let (best_block_hash, height) = self.chain_state
            .get_best_chain_tip()
            .await
            .map_err(|e| e.to_string())?;

        Ok(ChainInfo {
            best_block_hash,
            height,
            blocks: height + 1,
        })
    }

    /// Get a block by hash
    pub async fn get_block(&self, hash: &BlockHash) -> Result<Option<Block>, String> {
        self.block_store
            .get_block(hash)
            .await
            .map_err(|e| e.to_string())
    }
}

/// Mempool transaction management service
pub struct MempoolService {
    mempool: Arc<dyn MempoolPort>,
    #[allow(dead_code)]
    chain_state: Arc<dyn ChainStateStore>,
}

impl MempoolService {
    /// Create a new mempool service
    pub fn new(mempool: Arc<dyn MempoolPort>, chain_state: Arc<dyn ChainStateStore>) -> Self {
        MempoolService { mempool, chain_state }
    }

    /// Submit a transaction to the mempool
    pub async fn submit_transaction(&self, tx: &Transaction) -> Result<String, String> {
        tracing::info!("Submitting transaction: {}", tx.txid());

        self.mempool
            .add_transaction(tx)
            .await
            .map_err(|e| e.to_string())?;

        Ok(tx.txid().to_hex_reversed())
    }

    /// Get all transactions in the mempool
    pub async fn get_mempool_contents(&self) -> Result<Vec<String>, String> {
        let txs = self.mempool
            .get_all_transactions()
            .await
            .map_err(|e| e.to_string())?;

        Ok(txs.iter().map(|entry| entry.tx.txid().to_hex_reversed()).collect())
    }

    /// Estimate fee for a transaction
    pub async fn estimate_fee(&self, target_blocks: u32) -> Result<f64, String> {
        self.mempool
            .estimate_fee(target_blocks)
            .await
            .map_err(|e| e.to_string())
    }

    /// Get mempool statistics
    pub async fn get_mempool_info(&self) -> Result<btc_ports::MempoolInfo, String> {
        self.mempool
            .get_mempool_info()
            .await
            .map_err(|e| e.to_string())
    }
}

/// Block mining service
pub struct MiningService {
    template_provider: Arc<dyn BlockTemplateProvider>,
    blockchain: Arc<BlockchainService>,
}

impl MiningService {
    /// Create a new mining service
    pub fn new(
        template_provider: Arc<dyn BlockTemplateProvider>,
        blockchain: Arc<BlockchainService>,
    ) -> Self {
        MiningService {
            template_provider,
            blockchain,
        }
    }

    /// Generate a block template for miners
    pub async fn generate_block_template(
        &self,
        coinbase_script: &btc_domain::script::Script,
    ) -> Result<btc_ports::BlockTemplate, String> {
        let params = btc_domain::ChainParams::mainnet().consensus;
        self.template_provider
            .create_block_template(coinbase_script, &params)
            .await
            .map_err(|e| e.to_string())
    }

    /// Submit a mined block
    pub async fn submit_mined_block(&self, block: &Block) -> Result<(), String> {
        self.blockchain.validate_and_accept_block(block).await
    }
}

/// Information about the current chain state
#[derive(Clone, Debug)]
pub struct ChainInfo {
    pub best_block_hash: BlockHash,
    pub height: u32,
    pub blocks: u32,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_chain_info_creation() {
        let info = ChainInfo {
            best_block_hash: BlockHash::zero(),
            height: 0,
            blocks: 1,
        };
        assert_eq!(info.height, 0);
    }
}
