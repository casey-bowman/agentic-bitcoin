//! Accept-to-Mempool — Transaction validation and acceptance pipeline
//!
//! Implements the full validation pipeline for accepting transactions into the
//! mempool, corresponding to Bitcoin Core's `AcceptToMemoryPool()`. This bridges:
//!
//! - **Consensus validation**: Basic transaction structure checks
//! - **UTXO verification**: All inputs reference unspent outputs
//! - **Fee calculation**: Compute fee from input values minus output values
//! - **Policy checks**: Dust, min relay fee, tx weight, standard checks
//! - **Script verification**: Full signature validation (ECDSA/SegWit)
//! - **Mempool admission**: Add to mempool with computed fee
//!
//! This is the gateway for all new transactions entering the mempool, whether
//! received from peers via `tx` messages or submitted locally via RPC.

use abtc_domain::consensus::rules;
use abtc_domain::crypto::signing::TransactionSignatureChecker;
use abtc_domain::policy::limits::MempoolLimits;
use abtc_domain::primitives::{Amount, Sequence, Transaction};
use abtc_domain::script::{verify_script_with_witness, ScriptFlags};
use abtc_ports::{ChainStateStore, MempoolPort, UtxoEntry};
use std::sync::Arc;

/// BIP113: lock_time values below this threshold are interpreted as block
/// heights; at or above it they are interpreted as Unix timestamps.
const LOCKTIME_THRESHOLD: u32 = 500_000_000;

/// Errors that can occur during mempool acceptance.
#[derive(Debug)]
pub enum AcceptError {
    /// Transaction fails consensus validation.
    ConsensusViolation(String),
    /// A referenced UTXO does not exist (double-spend or missing input).
    MissingInput(String),
    /// Fee is below the minimum relay threshold.
    InsufficientFee { fee: i64, required: i64 },
    /// Transaction fails policy checks (dust, oversized, etc.).
    PolicyViolation(String),
    /// Script verification failed.
    ScriptFailure(String),
    /// Mempool rejected the transaction (duplicate, limits, etc.).
    MempoolRejection(String),
}

impl std::fmt::Display for AcceptError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AcceptError::ConsensusViolation(e) => write!(f, "consensus: {}", e),
            AcceptError::MissingInput(e) => write!(f, "missing input: {}", e),
            AcceptError::InsufficientFee { fee, required } => {
                write!(f, "insufficient fee: {} < {}", fee, required)
            }
            AcceptError::PolicyViolation(e) => write!(f, "policy: {}", e),
            AcceptError::ScriptFailure(e) => write!(f, "script: {}", e),
            AcceptError::MempoolRejection(e) => write!(f, "mempool: {}", e),
        }
    }
}

impl std::error::Error for AcceptError {}

/// Result of a successful mempool acceptance.
#[derive(Debug, Clone)]
pub struct AcceptResult {
    /// The transaction ID.
    pub txid: abtc_domain::primitives::Txid,
    /// Computed fee in satoshis.
    pub fee: Amount,
    /// Virtual size (weight / 4).
    pub vsize: u32,
    /// Fee rate in sat/vB.
    pub fee_rate: f64,
}

/// Accept-to-mempool validator.
///
/// Orchestrates the full pipeline of checks before admitting a transaction
/// to the mempool.
pub struct MempoolAcceptor {
    chain_state: Arc<dyn ChainStateStore>,
    mempool: Arc<dyn MempoolPort>,
    /// Configurable policy limits for ancestor/descendant checks.
    _limits: MempoolLimits,
    /// Whether to verify scripts (can be disabled for testing).
    verify_scripts: bool,
}

impl MempoolAcceptor {
    /// Create a new mempool acceptor.
    pub fn new(chain_state: Arc<dyn ChainStateStore>, mempool: Arc<dyn MempoolPort>) -> Self {
        MempoolAcceptor {
            chain_state,
            mempool,
            _limits: MempoolLimits::default(),
            verify_scripts: true,
        }
    }

    /// Create a new mempool acceptor with custom limits.
    pub fn with_limits(
        chain_state: Arc<dyn ChainStateStore>,
        mempool: Arc<dyn MempoolPort>,
        limits: MempoolLimits,
    ) -> Self {
        MempoolAcceptor {
            chain_state,
            mempool,
            _limits: limits,
            verify_scripts: true,
        }
    }

    /// Enable or disable script verification (useful for testing).
    pub fn set_verify_scripts(&mut self, verify: bool) {
        self.verify_scripts = verify;
    }

    /// Validate and accept a transaction into the mempool.
    ///
    /// This is the main entry point — the equivalent of Bitcoin Core's
    /// `AcceptToMemoryPool()`.
    pub async fn accept_transaction(&self, tx: &Transaction) -> Result<AcceptResult, AcceptError> {
        let txid = tx.txid();

        // 1. Consensus validation (structure, sizes, amounts)
        rules::check_transaction(tx)
            .map_err(|e| AcceptError::ConsensusViolation(format!("{}", e)))?;

        // 2. Reject coinbase transactions
        if tx.is_coinbase() {
            return Err(AcceptError::ConsensusViolation(
                "coinbase transactions cannot enter the mempool".into(),
            ));
        }

        // 3. Verify all inputs exist in the UTXO set and compute fee
        let mut total_input_value: i64 = 0;
        let mut input_utxos = Vec::with_capacity(tx.inputs.len());

        for input in &tx.inputs {
            let utxo = self
                .chain_state
                .get_utxo(&input.previous_output.txid, input.previous_output.vout)
                .await
                .map_err(|e| AcceptError::MissingInput(e.to_string()))?
                .ok_or_else(|| {
                    AcceptError::MissingInput(format!(
                        "{}:{}",
                        input.previous_output.txid, input.previous_output.vout
                    ))
                })?;

            total_input_value += utxo.output.value.as_sat();
            input_utxos.push(utxo);
        }

        let total_output_value = tx.total_output_value().as_sat();
        if total_input_value < total_output_value {
            return Err(AcceptError::ConsensusViolation(format!(
                "outputs ({}) exceed inputs ({})",
                total_output_value, total_input_value
            )));
        }

        let fee = total_input_value - total_output_value;

        // 3b. BIP65 — absolute locktime validation
        //     If lock_time > 0, at least one input must be non-final.
        //     If lock_time is a block height (< 500M), it must not exceed
        //     the current chain tip height + 1 (the next block).
        if tx.lock_time > 0 {
            let all_final = tx.inputs.iter().all(|inp| inp.sequence == Sequence::FINAL);
            if all_final {
                return Err(AcceptError::ConsensusViolation(
                    "non-zero lock_time but all inputs are final".into(),
                ));
            }

            let (_tip_hash, tip_height) = self
                .chain_state
                .get_best_chain_tip()
                .await
                .map_err(|e| AcceptError::ConsensusViolation(e.to_string()))?;

            if tx.lock_time < LOCKTIME_THRESHOLD {
                // Block-height lock: tx is valid for inclusion in the *next* block.
                let next_height = tip_height + 1;
                if tx.lock_time > next_height {
                    return Err(AcceptError::PolicyViolation(format!(
                        "locktime {} exceeds next block height {}",
                        tx.lock_time, next_height
                    )));
                }
            }
            // Timestamp-based locktimes (>= 500M) would need MTP comparison.
            // TODO: add MTP access to ChainStateStore and check here.
        }

        // 3c. BIP68 — relative locktime (sequence) validation
        //     For tx version >= 2, each input whose sequence does not have
        //     the LOCKTIME_DISABLE_FLAG set encodes a relative lock. If the
        //     type flag is clear, the masked value is a block count; the
        //     input's UTXO must be buried by at least that many blocks.
        if tx.version >= 2 {
            let (_tip_hash, tip_height) = self
                .chain_state
                .get_best_chain_tip()
                .await
                .map_err(|e| AcceptError::ConsensusViolation(e.to_string()))?;

            Self::check_sequence_locks(tx, &input_utxos, tip_height)?;
        }

        // 4. Estimate tx weight/vsize and check policy
        let vsize = Self::estimate_vsize(tx);
        let fee_rate = fee as f64 / vsize.max(1) as f64;

        // Check standard tx policy (dust, min fee, oversized)
        let output_values: Vec<i64> = tx.outputs.iter().map(|o| o.value.as_sat()).collect();
        let tx_weight = vsize * 4; // simplified
        MempoolLimits::check_standard_tx(tx_weight, Amount::from_sat(fee), vsize, &output_values)
            .map_err(|e| AcceptError::PolicyViolation(format!("{}", e)))?;

        // 5. Script verification (full ECDSA/SegWit signature checks)
        if self.verify_scripts {
            let script_flags = ScriptFlags::standard();

            for (input_idx, input) in tx.inputs.iter().enumerate() {
                let utxo = &input_utxos[input_idx];
                let script_pubkey = &utxo.output.script_pubkey;
                let spent_amount = utxo.output.value;

                let checker =
                    if script_pubkey.is_witness_program() || is_p2sh_witness(tx, input_idx) {
                        TransactionSignatureChecker::new_witness_v0(tx, input_idx, spent_amount)
                    } else {
                        TransactionSignatureChecker::new(tx, input_idx, spent_amount)
                    };

                verify_script_with_witness(
                    &input.script_sig,
                    script_pubkey,
                    &input.witness,
                    script_flags,
                    &checker,
                )
                .map_err(|e| {
                    AcceptError::ScriptFailure(format!(
                        "input {} of tx {}: {:?}",
                        input_idx, txid, e
                    ))
                })?;
            }
        }

        // 6. Add to mempool
        self.mempool
            .add_transaction(tx)
            .await
            .map_err(|e| AcceptError::MempoolRejection(e.to_string()))?;

        tracing::info!(
            "Accepted tx {} to mempool (fee={}, vsize={}, rate={:.1} sat/vB)",
            txid,
            fee,
            vsize,
            fee_rate
        );

        Ok(AcceptResult {
            txid,
            fee: Amount::from_sat(fee),
            vsize,
            fee_rate,
        })
    }

    /// Check BIP68 relative locktime constraints for all inputs.
    ///
    /// For each input whose sequence does not have `LOCKTIME_DISABLE_FLAG` set:
    /// - If `LOCKTIME_TYPE_FLAG` is clear, the masked value is a block count.
    ///   The UTXO must be at least that many blocks deep (tip_height - utxo_height >= required).
    /// - If `LOCKTIME_TYPE_FLAG` is set, the masked value is in 512-second units.
    ///   Full validation requires MTP; for now we only enforce block-based locks.
    fn check_sequence_locks(
        tx: &Transaction,
        input_utxos: &[UtxoEntry],
        tip_height: u32,
    ) -> Result<(), AcceptError> {
        for (idx, input) in tx.inputs.iter().enumerate() {
            let seq = input.sequence;

            // Skip if disable flag is set or sequence is final
            if seq & Sequence::LOCKTIME_DISABLE_FLAG != 0 || seq == Sequence::FINAL {
                continue;
            }

            let utxo_height = input_utxos[idx].height;

            if seq & Sequence::LOCKTIME_TYPE_FLAG == 0 {
                // Block-based relative lock
                let required_blocks = seq & Sequence::LOCKTIME_MASK;
                let depth = tip_height.saturating_sub(utxo_height);
                if depth < required_blocks {
                    return Err(AcceptError::PolicyViolation(format!(
                        "input {} requires {} blocks of depth but UTXO only has {} (BIP68)",
                        idx, required_blocks, depth
                    )));
                }
            }
            // Time-based relative locks (LOCKTIME_TYPE_FLAG set) require MTP.
            // TODO: enforce when MTP is available through ChainStateStore.
        }
        Ok(())
    }

    /// Estimate virtual size (vsize) of a transaction.
    ///
    /// vsize = weight / 4, where weight = base_size * 3 + total_size.
    fn estimate_vsize(tx: &Transaction) -> u32 {
        let mut base_size = 10u32; // version(4) + input_count(~1) + output_count(~1) + locktime(4)
        let mut witness_size = 0u32;

        for input in &tx.inputs {
            base_size += 41 + input.script_sig.len() as u32; // outpoint(36) + seq(4) + script_len(~1)
            if !input.witness.is_empty() {
                witness_size += 2; // witness item count varint
                for item in input.witness.stack() {
                    witness_size += 1 + item.len() as u32; // item length varint + data
                }
            }
        }

        for output in &tx.outputs {
            base_size += 9 + output.script_pubkey.len() as u32; // value(8) + script_len(~1)
        }

        if witness_size > 0 {
            witness_size += 2; // marker + flag bytes
        }

        let weight = base_size * 4 + witness_size;
        (weight + 3) / 4 // ceil division
    }
}

/// Detect if a transaction input is a P2SH-wrapped witness program.
fn is_p2sh_witness(tx: &Transaction, input_idx: usize) -> bool {
    let script_sig = &tx.inputs[input_idx].script_sig;
    let bytes = script_sig.as_bytes();

    if bytes.is_empty() {
        return false;
    }

    // P2SH-P2WPKH scriptSig: 0x16 0x0014{20} (23 bytes total)
    // P2SH-P2WSH scriptSig:  0x22 0x0020{32} (35 bytes total)
    let inner = if bytes.len() == 23 && bytes[0] == 0x16 {
        &bytes[1..]
    } else if bytes.len() == 35 && bytes[0] == 0x22 {
        &bytes[1..]
    } else {
        return false;
    };

    if inner.len() >= 2 {
        let version_byte = inner[0];
        let push_len = inner[1] as usize;
        let is_valid_version =
            version_byte == 0x00 || (version_byte >= 0x51 && version_byte <= 0x60);
        let is_valid_program = (push_len == 20 || push_len == 32) && inner.len() == 2 + push_len;
        return is_valid_version && is_valid_program;
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use abtc_domain::primitives::{OutPoint, TxIn, TxOut, Txid};
    use abtc_domain::Script;
    use abtc_ports::{MempoolEntry, MempoolInfo, UtxoEntry};
    use async_trait::async_trait;
    use std::collections::HashMap;
    use tokio::sync::RwLock;

    // ── Mock ChainStateStore ─────────────────────────────────

    struct MockChainState {
        utxos: RwLock<HashMap<(Txid, u32), UtxoEntry>>,
    }

    impl MockChainState {
        fn new() -> Self {
            MockChainState {
                utxos: RwLock::new(HashMap::new()),
            }
        }

        async fn add_utxo(&self, txid: Txid, vout: u32, entry: UtxoEntry) {
            self.utxos.write().await.insert((txid, vout), entry);
        }
    }

    #[async_trait]
    impl ChainStateStore for MockChainState {
        async fn get_utxo(
            &self,
            txid: &Txid,
            vout: u32,
        ) -> Result<Option<UtxoEntry>, Box<dyn std::error::Error + Send + Sync>> {
            Ok(self.utxos.read().await.get(&(*txid, vout)).cloned())
        }

        async fn has_utxo(
            &self,
            txid: &Txid,
            vout: u32,
        ) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
            Ok(self.utxos.read().await.contains_key(&(*txid, vout)))
        }

        async fn write_utxo_set(
            &self,
            _adds: Vec<(Txid, u32, UtxoEntry)>,
            _removes: Vec<(Txid, u32)>,
        ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
            Ok(())
        }

        async fn get_best_chain_tip(
            &self,
        ) -> Result<
            (abtc_domain::primitives::BlockHash, u32),
            Box<dyn std::error::Error + Send + Sync>,
        > {
            Ok((abtc_domain::primitives::BlockHash::zero(), 0))
        }

        async fn write_chain_tip(
            &self,
            _hash: abtc_domain::primitives::BlockHash,
            _height: u32,
        ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
            Ok(())
        }
        async fn get_utxo_set_info(
            &self,
        ) -> Result<abtc_ports::UtxoSetInfo, Box<dyn std::error::Error + Send + Sync>> {
            Ok(abtc_ports::UtxoSetInfo {
                txout_count: 0,
                total_amount: abtc_domain::primitives::Amount::from_sat(0),
                best_block: abtc_domain::primitives::BlockHash::zero(),
                height: 0,
            })
        }
    }

    // ── Mock MempoolPort ─────────────────────────────────────

    struct MockMempool {
        txs: RwLock<HashMap<Txid, Transaction>>,
    }

    impl MockMempool {
        fn new() -> Self {
            MockMempool {
                txs: RwLock::new(HashMap::new()),
            }
        }
    }

    #[async_trait]
    impl MempoolPort for MockMempool {
        async fn add_transaction(
            &self,
            tx: &Transaction,
        ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
            let txid = tx.txid();
            let mut txs = self.txs.write().await;
            if txs.contains_key(&txid) {
                return Err("already in mempool".into());
            }
            txs.insert(txid, tx.clone());
            Ok(())
        }

        async fn remove_transaction(
            &self,
            txid: &Txid,
            _recursive: bool,
        ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
            self.txs.write().await.remove(txid);
            Ok(())
        }

        async fn get_transaction(
            &self,
            txid: &Txid,
        ) -> Result<Option<MempoolEntry>, Box<dyn std::error::Error + Send + Sync>> {
            let txs = self.txs.read().await;
            Ok(txs.get(txid).map(|tx| MempoolEntry {
                tx: tx.clone(),
                fee: Amount::from_sat(0),
                size: 100,
                time: 0,
                height: 0,
                descendant_count: 0,
                descendant_size: 0,
                ancestor_count: 0,
                ancestor_size: 0,
            }))
        }

        async fn get_all_transactions(
            &self,
        ) -> Result<Vec<MempoolEntry>, Box<dyn std::error::Error + Send + Sync>> {
            Ok(vec![])
        }

        async fn get_transaction_count(
            &self,
        ) -> Result<u32, Box<dyn std::error::Error + Send + Sync>> {
            Ok(self.txs.read().await.len() as u32)
        }

        async fn estimate_fee(
            &self,
            _target_blocks: u32,
        ) -> Result<f64, Box<dyn std::error::Error + Send + Sync>> {
            Ok(1.0)
        }

        async fn get_mempool_info(
            &self,
        ) -> Result<MempoolInfo, Box<dyn std::error::Error + Send + Sync>> {
            Ok(MempoolInfo {
                size: 0,
                bytes: 0,
                usage: 0,
                max_mempool: 300_000_000,
                min_relay_fee: 0.00001,
            })
        }

        async fn clear(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
            self.txs.write().await.clear();
            Ok(())
        }
    }

    // ── Helper ───────────────────────────────────────────────

    fn make_funding_utxo(value: i64) -> UtxoEntry {
        UtxoEntry {
            output: TxOut::new(Amount::from_sat(value), Script::new()),
            height: 1,
            is_coinbase: false,
        }
    }

    // ── Tests ────────────────────────────────────────────────

    #[tokio::test]
    async fn test_accept_valid_transaction() {
        let chain_state = Arc::new(MockChainState::new());
        let mempool = Arc::new(MockMempool::new());

        // Create a funding UTXO
        let funding_txid =
            Txid::from_hash(abtc_domain::primitives::Hash256::from_bytes([0x01; 32]));
        chain_state
            .add_utxo(funding_txid, 0, make_funding_utxo(100_000))
            .await;

        let mut acceptor = MempoolAcceptor::new(chain_state, mempool.clone());
        acceptor.set_verify_scripts(false); // Skip script checks for unit test

        let tx = Transaction::v1(
            vec![TxIn::final_input(
                OutPoint::new(funding_txid, 0),
                Script::new(),
            )],
            vec![TxOut::new(Amount::from_sat(90_000), Script::new())],
            0,
        );

        let result = acceptor.accept_transaction(&tx).await;
        assert!(result.is_ok());

        let accept = result.unwrap();
        assert_eq!(accept.fee.as_sat(), 10_000);
        assert!(accept.fee_rate > 0.0);

        // Verify it's now in the mempool
        let count = mempool.get_transaction_count().await.unwrap();
        assert_eq!(count, 1);
    }

    #[tokio::test]
    async fn test_reject_missing_input() {
        let chain_state = Arc::new(MockChainState::new());
        let mempool = Arc::new(MockMempool::new());

        let mut acceptor = MempoolAcceptor::new(chain_state, mempool);
        acceptor.set_verify_scripts(false);

        let tx = Transaction::v1(
            vec![TxIn::final_input(
                OutPoint::new(Txid::zero(), 0),
                Script::new(),
            )],
            vec![TxOut::new(Amount::from_sat(1000), Script::new())],
            0,
        );

        let result = acceptor.accept_transaction(&tx).await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), AcceptError::MissingInput(_)));
    }

    #[tokio::test]
    async fn test_reject_coinbase() {
        let chain_state = Arc::new(MockChainState::new());
        let mempool = Arc::new(MockMempool::new());

        let acceptor = MempoolAcceptor::new(chain_state, mempool);

        let tx = Transaction::coinbase(
            0,
            Script::from_bytes(vec![0x01, 0x00]),
            vec![TxOut::new(Amount::from_sat(5_000_000_000), Script::new())],
        );

        let result = acceptor.accept_transaction(&tx).await;
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            AcceptError::ConsensusViolation(_)
        ));
    }

    #[tokio::test]
    async fn test_reject_outputs_exceed_inputs() {
        let chain_state = Arc::new(MockChainState::new());
        let mempool = Arc::new(MockMempool::new());

        let funding_txid =
            Txid::from_hash(abtc_domain::primitives::Hash256::from_bytes([0x02; 32]));
        chain_state
            .add_utxo(funding_txid, 0, make_funding_utxo(1_000))
            .await;

        let mut acceptor = MempoolAcceptor::new(chain_state, mempool);
        acceptor.set_verify_scripts(false);

        let tx = Transaction::v1(
            vec![TxIn::final_input(
                OutPoint::new(funding_txid, 0),
                Script::new(),
            )],
            vec![TxOut::new(Amount::from_sat(2_000), Script::new())],
            0,
        );

        let result = acceptor.accept_transaction(&tx).await;
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            AcceptError::ConsensusViolation(_)
        ));
    }

    #[tokio::test]
    async fn test_reject_dust_output() {
        let chain_state = Arc::new(MockChainState::new());
        let mempool = Arc::new(MockMempool::new());

        let funding_txid =
            Txid::from_hash(abtc_domain::primitives::Hash256::from_bytes([0x03; 32]));
        chain_state
            .add_utxo(funding_txid, 0, make_funding_utxo(100_000))
            .await;

        let mut acceptor = MempoolAcceptor::new(chain_state, mempool);
        acceptor.set_verify_scripts(false);

        // Output of 100 satoshis is below the dust threshold (546 sat)
        let tx = Transaction::v1(
            vec![TxIn::final_input(
                OutPoint::new(funding_txid, 0),
                Script::new(),
            )],
            vec![TxOut::new(Amount::from_sat(100), Script::new())],
            0,
        );

        let result = acceptor.accept_transaction(&tx).await;
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            AcceptError::PolicyViolation(_)
        ));
    }

    #[tokio::test]
    async fn test_fee_calculation() {
        let chain_state = Arc::new(MockChainState::new());
        let mempool = Arc::new(MockMempool::new());

        let funding_txid =
            Txid::from_hash(abtc_domain::primitives::Hash256::from_bytes([0x04; 32]));
        chain_state
            .add_utxo(funding_txid, 0, make_funding_utxo(500_000))
            .await;

        let mut acceptor = MempoolAcceptor::new(chain_state, mempool);
        acceptor.set_verify_scripts(false);

        let tx = Transaction::v1(
            vec![TxIn::final_input(
                OutPoint::new(funding_txid, 0),
                Script::new(),
            )],
            vec![TxOut::new(Amount::from_sat(450_000), Script::new())],
            0,
        );

        let result = acceptor.accept_transaction(&tx).await.unwrap();
        assert_eq!(result.fee.as_sat(), 50_000);
        assert!(result.vsize > 0);
    }

    #[tokio::test]
    async fn test_vsize_estimation() {
        // Simple legacy transaction
        let tx = Transaction::v1(
            vec![TxIn::final_input(
                OutPoint::new(Txid::zero(), 0),
                Script::new(),
            )],
            vec![TxOut::new(Amount::from_sat(1000), Script::new())],
            0,
        );
        let vsize = MempoolAcceptor::estimate_vsize(&tx);
        assert!(vsize > 0);
        // A simple 1-in 1-out legacy tx should be ~60-70 vbytes
        assert!(vsize >= 50 && vsize <= 100, "vsize was {}", vsize);
    }

    #[tokio::test]
    async fn test_duplicate_rejection() {
        let chain_state = Arc::new(MockChainState::new());
        let mempool = Arc::new(MockMempool::new());

        let funding_txid =
            Txid::from_hash(abtc_domain::primitives::Hash256::from_bytes([0x05; 32]));
        chain_state
            .add_utxo(funding_txid, 0, make_funding_utxo(100_000))
            .await;

        let mut acceptor = MempoolAcceptor::new(chain_state, mempool);
        acceptor.set_verify_scripts(false);

        let tx = Transaction::v1(
            vec![TxIn::final_input(
                OutPoint::new(funding_txid, 0),
                Script::new(),
            )],
            vec![TxOut::new(Amount::from_sat(90_000), Script::new())],
            0,
        );

        // First should succeed
        assert!(acceptor.accept_transaction(&tx).await.is_ok());

        // Second should fail (duplicate)
        let result = acceptor.accept_transaction(&tx).await;
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            AcceptError::MempoolRejection(_)
        ));
    }

    // ═══════════════════════════════════════════════════════════════════
    // Regression tests — Session 15 (review finding #22: locktime/sequence)
    //
    // These tests verify BIP65 absolute locktime and BIP68 relative
    // locktime enforcement during mempool acceptance.
    // ═══════════════════════════════════════════════════════════════════

    #[tokio::test]
    async fn regression_locktime_future_block_rejected() {
        let chain_state = Arc::new(MockChainState::new());
        let mempool = Arc::new(MockMempool::new());

        let funding_txid =
            Txid::from_hash(abtc_domain::primitives::Hash256::from_bytes([0x10; 32]));
        chain_state
            .add_utxo(funding_txid, 0, make_funding_utxo(100_000))
            .await;

        let mut acceptor = MempoolAcceptor::new(chain_state, mempool);
        acceptor.set_verify_scripts(false);

        // lock_time = 1000 but chain tip is at height 0 → next block is 1
        let tx = Transaction::new(
            1,
            vec![TxIn::new(
                OutPoint::new(funding_txid, 0),
                Script::new(),
                Sequence::MAX_NONFINAL, // non-final to activate locktime
            )],
            vec![TxOut::new(Amount::from_sat(90_000), Script::new())],
            1000, // lock_time = block 1000
        );

        let result = acceptor.accept_transaction(&tx).await;
        assert!(result.is_err());
        let err = format!("{}", result.unwrap_err());
        assert!(err.contains("locktime"), "error was: {}", err);
    }

    #[tokio::test]
    async fn regression_locktime_all_final_rejected() {
        let chain_state = Arc::new(MockChainState::new());
        let mempool = Arc::new(MockMempool::new());

        let funding_txid =
            Txid::from_hash(abtc_domain::primitives::Hash256::from_bytes([0x11; 32]));
        chain_state
            .add_utxo(funding_txid, 0, make_funding_utxo(100_000))
            .await;

        let mut acceptor = MempoolAcceptor::new(chain_state, mempool);
        acceptor.set_verify_scripts(false);

        // lock_time > 0 but all inputs are final → invalid
        let tx = Transaction::new(
            1,
            vec![TxIn::final_input(
                OutPoint::new(funding_txid, 0),
                Script::new(),
            )],
            vec![TxOut::new(Amount::from_sat(90_000), Script::new())],
            100, // non-zero locktime
        );

        let result = acceptor.accept_transaction(&tx).await;
        assert!(result.is_err());
        let err = format!("{}", result.unwrap_err());
        assert!(err.contains("all inputs are final"), "error was: {}", err);
    }

    #[tokio::test]
    async fn regression_locktime_zero_accepted() {
        let chain_state = Arc::new(MockChainState::new());
        let mempool = Arc::new(MockMempool::new());

        let funding_txid =
            Txid::from_hash(abtc_domain::primitives::Hash256::from_bytes([0x12; 32]));
        chain_state
            .add_utxo(funding_txid, 0, make_funding_utxo(100_000))
            .await;

        let mut acceptor = MempoolAcceptor::new(chain_state, mempool);
        acceptor.set_verify_scripts(false);

        // lock_time = 0 → no locktime check
        let tx = Transaction::v1(
            vec![TxIn::final_input(
                OutPoint::new(funding_txid, 0),
                Script::new(),
            )],
            vec![TxOut::new(Amount::from_sat(90_000), Script::new())],
            0,
        );

        assert!(acceptor.accept_transaction(&tx).await.is_ok());
    }

    #[tokio::test]
    async fn regression_bip68_relative_lock_rejected() {
        let chain_state = Arc::new(MockChainState::new());
        let mempool = Arc::new(MockMempool::new());

        let funding_txid =
            Txid::from_hash(abtc_domain::primitives::Hash256::from_bytes([0x13; 32]));
        // UTXO confirmed at height 0; chain tip is also 0 → depth = 0
        chain_state
            .add_utxo(funding_txid, 0, make_funding_utxo(100_000))
            .await;

        let mut acceptor = MempoolAcceptor::new(chain_state, mempool);
        acceptor.set_verify_scripts(false);

        // Version 2 tx with sequence encoding "10 blocks relative lock"
        // (no disable flag, no type flag, masked value = 10)
        let relative_lock_sequence = 10u32; // 10 blocks
        let tx = Transaction::new(
            2,
            vec![TxIn::new(
                OutPoint::new(funding_txid, 0),
                Script::new(),
                relative_lock_sequence,
            )],
            vec![TxOut::new(Amount::from_sat(90_000), Script::new())],
            0,
        );

        let result = acceptor.accept_transaction(&tx).await;
        assert!(result.is_err());
        let err = format!("{}", result.unwrap_err());
        assert!(err.contains("BIP68"), "error was: {}", err);
    }

    #[tokio::test]
    async fn regression_bip68_disabled_flag_accepted() {
        let chain_state = Arc::new(MockChainState::new());
        let mempool = Arc::new(MockMempool::new());

        let funding_txid =
            Txid::from_hash(abtc_domain::primitives::Hash256::from_bytes([0x14; 32]));
        chain_state
            .add_utxo(funding_txid, 0, make_funding_utxo(100_000))
            .await;

        let mut acceptor = MempoolAcceptor::new(chain_state, mempool);
        acceptor.set_verify_scripts(false);

        // Sequence with disable flag set → BIP68 doesn't apply
        let seq_disabled = Sequence::LOCKTIME_DISABLE_FLAG | 10;
        let tx = Transaction::new(
            2,
            vec![TxIn::new(
                OutPoint::new(funding_txid, 0),
                Script::new(),
                seq_disabled,
            )],
            vec![TxOut::new(Amount::from_sat(90_000), Script::new())],
            0,
        );

        assert!(acceptor.accept_transaction(&tx).await.is_ok());
    }

    #[tokio::test]
    async fn regression_bip68_v1_tx_skips_sequence_check() {
        let chain_state = Arc::new(MockChainState::new());
        let mempool = Arc::new(MockMempool::new());

        let funding_txid =
            Txid::from_hash(abtc_domain::primitives::Hash256::from_bytes([0x15; 32]));
        chain_state
            .add_utxo(funding_txid, 0, make_funding_utxo(100_000))
            .await;

        let mut acceptor = MempoolAcceptor::new(chain_state, mempool);
        acceptor.set_verify_scripts(false);

        // Version 1 tx — BIP68 relative locks don't apply regardless of sequence
        let tx = Transaction::new(
            1,
            vec![TxIn::new(
                OutPoint::new(funding_txid, 0),
                Script::new(),
                10, // Would be a 10-block relative lock in v2
            )],
            vec![TxOut::new(Amount::from_sat(90_000), Script::new())],
            0,
        );

        assert!(acceptor.accept_transaction(&tx).await.is_ok());
    }
}
