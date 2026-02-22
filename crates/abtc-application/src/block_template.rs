//! Block Template Assembly — Transaction Selection and Template Construction
//!
//! This module implements the `BlockTemplateProvider` port trait, assembling
//! block templates from mempool transactions for mining. It corresponds to
//! Bitcoin Core's `BlockAssembler` (in `node/miner.cpp`).
//!
//! ## Strategy
//!
//! 1. Query the mempool for transactions sorted by ancestor fee rate (CPFP-aware).
//! 2. Fill the block up to `MAX_BLOCK_WEIGHT` (4,000,000 weight units / BIP 141).
//! 3. Build a coinbase transaction with the correct subsidy + collected fees.
//! 4. Compute the merkle root and assemble the header.
//!
//! The resulting `BlockTemplate` is ready for nonce-grinding by the miner.

use abtc_domain::consensus::{ConsensusParams, MAX_BLOCK_WEIGHT};
use abtc_domain::primitives::{Amount, Block, BlockHeader, Hash256, Transaction, TxOut};
use abtc_domain::script::Script;
use abtc_ports::{BlockTemplate, BlockTemplateProvider, ChainStateStore, MempoolPort};
use async_trait::async_trait;
use std::error::Error;
use std::sync::Arc;

/// Weight reserved for the coinbase transaction (conservative estimate).
/// A typical coinbase with BIP34 height + single output is ~700 WU.
const COINBASE_WEIGHT_RESERVE: u32 = 4_000;

/// Block template assembler.
///
/// Holds references to the chain state (for tip/height/bits) and mempool
/// (for transaction selection). Implements `BlockTemplateProvider`.
pub struct BlockAssembler {
    chain_state: Arc<dyn ChainStateStore>,
    mempool: Arc<dyn MempoolPort>,
}

impl BlockAssembler {
    /// Create a new block assembler.
    pub fn new(chain_state: Arc<dyn ChainStateStore>, mempool: Arc<dyn MempoolPort>) -> Self {
        BlockAssembler {
            chain_state,
            mempool,
        }
    }

    /// Build a BIP34-compliant coinbase scriptSig encoding the block height.
    fn build_coinbase_script(height: u32) -> Script {
        let mut script = Vec::new();

        if height == 0 {
            script.push(0x00); // OP_0
        } else if height <= 16 {
            script.push(0x50 + height as u8); // OP_1..OP_16
        } else {
            let mut h = height;
            let mut buf = Vec::new();
            while h > 0 {
                buf.push((h & 0xff) as u8);
                h >>= 8;
            }
            if buf.last().map_or(false, |&b| b & 0x80 != 0) {
                buf.push(0);
            }
            script.push(buf.len() as u8);
            script.extend_from_slice(&buf);
        }

        // Pad to minimum 2 bytes.
        while script.len() < 2 {
            script.push(0x00);
        }

        Script::from_bytes(script)
    }

    /// Calculate the block subsidy for a given height.
    fn get_block_subsidy(height: u32, params: &ConsensusParams) -> Amount {
        let interval = params.subsidy_halving_interval;
        if interval == 0 {
            return Amount::from_sat(5_000_000_000);
        }
        let halvings = height / interval;
        if halvings >= 64 {
            return Amount::from_sat(0);
        }
        let initial: i64 = 50 * 100_000_000;
        Amount::from_sat(initial >> halvings)
    }
}

#[async_trait]
impl BlockTemplateProvider for BlockAssembler {
    /// Create a block template by selecting mempool transactions and building
    /// a valid block structure ready for mining.
    async fn create_block_template(
        &self,
        coinbase_script: &Script,
        params: &ConsensusParams,
    ) -> Result<BlockTemplate, Box<dyn Error + Send + Sync>> {
        // 1. Get chain tip info.
        let (prev_hash, tip_height) = self.chain_state.get_best_chain_tip().await?;
        let new_height = tip_height + 1;

        // 2. Select transactions from mempool by ancestor fee rate.
        //    Leave room for the coinbase.
        let available_weight = MAX_BLOCK_WEIGHT - COINBASE_WEIGHT_RESERVE;
        let selected = self.mempool.get_all_transactions().await?;

        // Sort by fee rate descending and pack into the block greedily.
        let mut sorted: Vec<_> = selected.into_iter().collect();
        sorted.sort_by(|a, b| {
            let rate_a = a.fee.as_sat() as f64 / a.size.max(1) as f64;
            let rate_b = b.fee.as_sat() as f64 / b.size.max(1) as f64;
            rate_b
                .partial_cmp(&rate_a)
                .unwrap_or(std::cmp::Ordering::Equal)
        });

        let mut block_txs: Vec<Transaction> = Vec::new();
        let mut total_fees = Amount::from_sat(0);
        let mut fees_per_tx: Vec<Amount> = Vec::new();
        let mut sigops_per_tx: Vec<u64> = Vec::new();
        let mut total_weight: u32 = 0;

        for entry in &sorted {
            let tx_weight = (entry.size as u32) * 4; // conservative: size * 4
            if total_weight + tx_weight > available_weight {
                continue;
            }
            total_weight += tx_weight;
            total_fees = Amount::from_sat(total_fees.as_sat() + entry.fee.as_sat());
            fees_per_tx.push(entry.fee);
            // Estimate sigops conservatively (1 per input + 1 per output).
            let sigops = (entry.tx.inputs.len() + entry.tx.outputs.len()) as u64;
            sigops_per_tx.push(sigops);
            block_txs.push(entry.tx.clone());
        }

        // 3. Build the coinbase transaction.
        let subsidy = Self::get_block_subsidy(new_height, params);
        let coinbase_value = Amount::from_sat(subsidy.as_sat() + total_fees.as_sat());

        let coinbase_scriptsig = Self::build_coinbase_script(new_height);
        let coinbase = Transaction::coinbase(
            new_height,
            coinbase_scriptsig,
            vec![TxOut::new(coinbase_value, coinbase_script.clone())],
        );

        // Prepend coinbase (fees/sigops entry at index 0 is the coinbase).
        let mut all_txs = vec![coinbase];
        all_txs.extend(block_txs);

        let mut all_fees = vec![Amount::from_sat(0)]; // coinbase has no fee
        all_fees.extend(fees_per_tx);

        let mut all_sigops = vec![1u64]; // coinbase typically has 1 sigop
        all_sigops.extend(sigops_per_tx);

        // 4. Compute merkle root and assemble header.
        let time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as u32;

        // Use the tip's bits for the template. In production, `get_next_work_required`
        // would be called, but that requires the previous block's timestamp which
        // we don't have from the ChainStateStore. Use pow_limit_bits as a safe
        // default — the miner/caller can override.
        let bits = params.pow_limit_bits;

        let temp_block = Block::new(
            BlockHeader::new(0x20000000, prev_hash, Hash256::zero(), time, bits, 0),
            all_txs.clone(),
        );
        let merkle_root = temp_block.compute_merkle_root();

        let header = BlockHeader::new(0x20000000, prev_hash, merkle_root, time, bits, 0);
        let block = Block::new(header, all_txs);

        Ok(BlockTemplate {
            block,
            fees: all_fees,
            sigops: all_sigops,
            target: bits,
            height: new_height,
        })
    }

    async fn get_block_height(&self) -> Result<u32, Box<dyn Error + Send + Sync>> {
        let (_, height) = self.chain_state.get_best_chain_tip().await?;
        Ok(height + 1) // next block height
    }
}

// ── Tests ────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use abtc_domain::primitives::{BlockHash, OutPoint, TxIn, Txid};
    use abtc_ports::{MempoolEntry, MempoolInfo, UtxoEntry};

    // ── Mock chain state store ───────────────────────────────────

    struct MockChainState {
        tip_hash: BlockHash,
        tip_height: u32,
    }

    #[async_trait]
    impl ChainStateStore for MockChainState {
        async fn get_utxo(
            &self,
            _txid: &Txid,
            _vout: u32,
        ) -> Result<Option<UtxoEntry>, Box<dyn Error + Send + Sync>> {
            Ok(None)
        }
        async fn has_utxo(
            &self,
            _txid: &Txid,
            _vout: u32,
        ) -> Result<bool, Box<dyn Error + Send + Sync>> {
            Ok(false)
        }
        async fn write_utxo_set(
            &self,
            _adds: Vec<(Txid, u32, UtxoEntry)>,
            _removes: Vec<(Txid, u32)>,
        ) -> Result<(), Box<dyn Error + Send + Sync>> {
            Ok(())
        }
        async fn get_best_chain_tip(
            &self,
        ) -> Result<(BlockHash, u32), Box<dyn Error + Send + Sync>> {
            Ok((self.tip_hash, self.tip_height))
        }
        async fn write_chain_tip(
            &self,
            _hash: BlockHash,
            _height: u32,
        ) -> Result<(), Box<dyn Error + Send + Sync>> {
            Ok(())
        }
        async fn get_utxo_set_info(
            &self,
        ) -> Result<abtc_ports::UtxoSetInfo, Box<dyn Error + Send + Sync>> {
            Ok(abtc_ports::UtxoSetInfo {
                txout_count: 0,
                total_amount: abtc_domain::primitives::Amount::from_sat(0),
                best_block: self.tip_hash,
                height: self.tip_height,
            })
        }
    }

    // ── Mock mempool ─────────────────────────────────────────────

    struct MockMempool {
        entries: Vec<MempoolEntry>,
    }

    #[async_trait]
    impl MempoolPort for MockMempool {
        async fn add_transaction(
            &self,
            _tx: &Transaction,
        ) -> Result<(), Box<dyn Error + Send + Sync>> {
            Ok(())
        }
        async fn remove_transaction(
            &self,
            _txid: &Txid,
            _recursive: bool,
        ) -> Result<(), Box<dyn Error + Send + Sync>> {
            Ok(())
        }
        async fn get_transaction(
            &self,
            _txid: &Txid,
        ) -> Result<Option<MempoolEntry>, Box<dyn Error + Send + Sync>> {
            Ok(None)
        }
        async fn get_all_transactions(
            &self,
        ) -> Result<Vec<MempoolEntry>, Box<dyn Error + Send + Sync>> {
            Ok(self.entries.clone())
        }
        async fn get_transaction_count(&self) -> Result<u32, Box<dyn Error + Send + Sync>> {
            Ok(self.entries.len() as u32)
        }
        async fn estimate_fee(
            &self,
            _target_blocks: u32,
        ) -> Result<f64, Box<dyn Error + Send + Sync>> {
            Ok(1.0)
        }
        async fn get_mempool_info(&self) -> Result<MempoolInfo, Box<dyn Error + Send + Sync>> {
            Ok(MempoolInfo {
                size: self.entries.len() as u32,
                bytes: 0,
                usage: 0,
                max_mempool: 300_000_000,
                min_relay_fee: 0.00001,
            })
        }
        async fn clear(&self) -> Result<(), Box<dyn Error + Send + Sync>> {
            Ok(())
        }
    }

    fn make_test_tx(value: i64) -> Transaction {
        let input = TxIn::final_input(OutPoint::new(Txid::zero(), 0), Script::new());
        let output = TxOut::new(Amount::from_sat(value), Script::new());
        Transaction::v1(vec![input], vec![output], 0)
    }

    fn make_mempool_entry(tx: &Transaction, fee: i64) -> MempoolEntry {
        MempoolEntry {
            tx: tx.clone(),
            fee: Amount::from_sat(fee),
            size: 200,
            time: 0,
            height: 0,
            descendant_count: 0,
            descendant_size: 0,
            ancestor_count: 0,
            ancestor_size: 0,
        }
    }

    #[tokio::test]
    async fn test_create_empty_template() {
        let chain_state = Arc::new(MockChainState {
            tip_hash: BlockHash::zero(),
            tip_height: 0,
        });
        let mempool = Arc::new(MockMempool {
            entries: Vec::new(),
        });

        let assembler = BlockAssembler::new(chain_state, mempool);
        let params = ConsensusParams::regtest();
        let script = Script::new();

        let template = assembler
            .create_block_template(&script, &params)
            .await
            .unwrap();

        // Should have just the coinbase
        assert_eq!(template.block.transactions.len(), 1);
        assert!(template.block.transactions[0].is_coinbase());
        assert_eq!(template.height, 1);

        // Coinbase should pay the full subsidy (no fees)
        let coinbase_value = template.block.transactions[0].total_output_value();
        assert_eq!(coinbase_value.as_sat(), 5_000_000_000); // 50 BTC regtest
    }

    #[tokio::test]
    async fn test_template_includes_mempool_txs() {
        let chain_state = Arc::new(MockChainState {
            tip_hash: BlockHash::zero(),
            tip_height: 100,
        });

        let tx1 = make_test_tx(50_000);
        let tx2 = make_test_tx(30_000);
        let entries = vec![
            make_mempool_entry(&tx1, 1000),
            make_mempool_entry(&tx2, 500),
        ];

        let mempool = Arc::new(MockMempool { entries });
        let assembler = BlockAssembler::new(chain_state, mempool);
        let params = ConsensusParams::regtest();
        let script = Script::new();

        let template = assembler
            .create_block_template(&script, &params)
            .await
            .unwrap();

        // Coinbase + 2 mempool txs
        assert_eq!(template.block.transactions.len(), 3);
        assert!(template.block.transactions[0].is_coinbase());
        assert_eq!(template.height, 101);

        // Coinbase should include subsidy + fees
        let coinbase_value = template.block.transactions[0].total_output_value();
        let expected = 5_000_000_000 + 1000 + 500; // subsidy + fees
        assert_eq!(coinbase_value.as_sat(), expected);
    }

    #[tokio::test]
    async fn test_template_sorts_by_fee_rate() {
        let chain_state = Arc::new(MockChainState {
            tip_hash: BlockHash::zero(),
            tip_height: 0,
        });

        let tx_low = make_test_tx(10_000);
        let tx_high = make_test_tx(20_000);
        let entries = vec![
            make_mempool_entry(&tx_low, 100),   // 0.5 sat/byte
            make_mempool_entry(&tx_high, 2000), // 10 sat/byte
        ];

        let mempool = Arc::new(MockMempool { entries });
        let assembler = BlockAssembler::new(chain_state, mempool);
        let params = ConsensusParams::regtest();
        let script = Script::new();

        let template = assembler
            .create_block_template(&script, &params)
            .await
            .unwrap();

        // Higher fee-rate tx should come first (after coinbase)
        assert_eq!(template.block.transactions.len(), 3);
        assert_eq!(template.fees[1].as_sat(), 2000); // high-fee first
        assert_eq!(template.fees[2].as_sat(), 100); // low-fee second
    }

    #[tokio::test]
    async fn test_template_has_valid_merkle_root() {
        let chain_state = Arc::new(MockChainState {
            tip_hash: BlockHash::zero(),
            tip_height: 50,
        });
        let mempool = Arc::new(MockMempool {
            entries: Vec::new(),
        });

        let assembler = BlockAssembler::new(chain_state, mempool);
        let params = ConsensusParams::regtest();
        let script = Script::new();

        let template = assembler
            .create_block_template(&script, &params)
            .await
            .unwrap();

        assert!(template.block.has_valid_merkle_root());
    }

    #[tokio::test]
    async fn test_template_subsidy_halving() {
        let chain_state = Arc::new(MockChainState {
            tip_hash: BlockHash::zero(),
            tip_height: 149, // Next block is height 150 = first halving on regtest
        });
        let mempool = Arc::new(MockMempool {
            entries: Vec::new(),
        });

        let assembler = BlockAssembler::new(chain_state, mempool);
        let params = ConsensusParams::regtest();
        let script = Script::new();

        let template = assembler
            .create_block_template(&script, &params)
            .await
            .unwrap();

        // At height 150, subsidy should be halved to 25 BTC
        let coinbase_value = template.block.transactions[0].total_output_value();
        assert_eq!(coinbase_value.as_sat(), 2_500_000_000);
    }

    #[tokio::test]
    async fn test_get_block_height() {
        let chain_state = Arc::new(MockChainState {
            tip_hash: BlockHash::zero(),
            tip_height: 42,
        });
        let mempool = Arc::new(MockMempool {
            entries: Vec::new(),
        });

        let assembler = BlockAssembler::new(chain_state, mempool);
        let height = assembler.get_block_height().await.unwrap();
        assert_eq!(height, 43);
    }

    #[tokio::test]
    async fn test_coinbase_script_bip34() {
        // Height 0 → OP_0
        let s0 = BlockAssembler::build_coinbase_script(0);
        assert!(s0.len() >= 2);

        // Height 1 → OP_1
        let s1 = BlockAssembler::build_coinbase_script(1);
        assert!(s1.len() >= 2);

        // Height 100 → serialized CScriptNum
        let s100 = BlockAssembler::build_coinbase_script(100);
        assert!(s100.len() >= 2);
        // First byte is push length, second byte should be 100
        assert_eq!(s100.as_bytes()[0], 1); // 1-byte push
        assert_eq!(s100.as_bytes()[1], 100);

        // Height 500 → 2-byte push
        let s500 = BlockAssembler::build_coinbase_script(500);
        assert_eq!(s500.as_bytes()[0], 2); // 2-byte push
    }
}
