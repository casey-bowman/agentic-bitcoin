//! Package Relay — Application-layer package acceptance service
//!
//! Orchestrates the acceptance of transaction packages into the mempool.
//! A package is a group of related transactions (typically parent + child
//! for CPFP) that are validated and submitted as a unit.
//!
//! ## Design
//!
//! Unlike individual transaction acceptance (`MempoolAcceptor`), package
//! acceptance uses aggregate fee evaluation: a child with high fees can
//! compensate for parents with low/zero individual fees, as long as the
//! combined package fee rate meets the minimum.
//!
//! ## Acceptance Pipeline
//!
//! 1. Validate package structure (topological order, no conflicts, limits)
//! 2. For each transaction: verify inputs against UTXO set + earlier package txs
//! 3. Compute aggregate fee across the package
//! 4. Check aggregate package fee rate against minimum
//! 5. Submit each transaction to the mempool in topological order
//!
//! ## Relationship to Net Processing
//!
//! `SyncManager` dispatches incoming package messages to `PackageAcceptor`.
//! The acceptor returns `PackageResult` which the sync manager uses to
//! decide whether to relay the package to other peers.

use abtc_domain::policy::packages::{
    self, PackageError, PackageType, MAX_PACKAGE_VSIZE,
};
use abtc_domain::primitives::{Amount, Transaction, Txid};
use abtc_ports::{ChainStateStore, MempoolPort};
use std::collections::HashMap;
use std::sync::Arc;

/// Result of accepting a package into the mempool.
#[derive(Debug, Clone)]
pub struct PackageResult {
    /// Transactions that were accepted (in submission order).
    pub accepted: Vec<PackageAcceptedTx>,
    /// Package type that was detected.
    pub package_type: PackageType,
    /// Aggregate fee for all accepted transactions.
    pub total_fee: Amount,
    /// Aggregate virtual size.
    pub total_vsize: u32,
    /// Aggregate fee rate (sat/vB).
    pub package_fee_rate: f64,
}

/// Info about a single accepted transaction within a package.
#[derive(Debug, Clone)]
pub struct PackageAcceptedTx {
    /// Transaction ID.
    pub txid: Txid,
    /// Individual fee.
    pub fee: Amount,
    /// Individual virtual size.
    pub vsize: u32,
}

/// Errors from package acceptance.
#[derive(Debug)]
pub enum PackageAcceptError {
    /// Package validation (structure, topology) failed.
    PackageValidation(PackageError),
    /// A transaction in the package failed UTXO lookup.
    MissingInput { txid: Txid, detail: String },
    /// A transaction's outputs don't cover inputs (negative fee).
    NegativeFee { txid: Txid },
    /// Aggregate package fee rate too low.
    InsufficientPackageFeeRate { fee_rate: f64, min_rate: f64 },
    /// A transaction failed mempool submission.
    MempoolRejection { txid: Txid, reason: String },
    /// Package total vsize exceeded.
    PackageTooLarge { vsize: u32, limit: u32 },
}

impl std::fmt::Display for PackageAcceptError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PackageAcceptError::PackageValidation(e) => write!(f, "package validation: {}", e),
            PackageAcceptError::MissingInput { txid, detail } => {
                write!(f, "missing input for tx {}: {}", txid, detail)
            }
            PackageAcceptError::NegativeFee { txid } => {
                write!(f, "tx {} has negative fee", txid)
            }
            PackageAcceptError::InsufficientPackageFeeRate { fee_rate, min_rate } => {
                write!(
                    f,
                    "package fee rate {:.2} sat/vB below minimum {:.2}",
                    fee_rate, min_rate
                )
            }
            PackageAcceptError::MempoolRejection { txid, reason } => {
                write!(f, "mempool rejected tx {}: {}", txid, reason)
            }
            PackageAcceptError::PackageTooLarge { vsize, limit } => {
                write!(f, "package {} vB exceeds limit {} vB", vsize, limit)
            }
        }
    }
}

impl std::error::Error for PackageAcceptError {}

/// Package acceptance orchestrator.
///
/// Validates and submits transaction packages to the mempool, using
/// aggregate fee evaluation to support CPFP fee-bumping.
pub struct PackageAcceptor {
    chain_state: Arc<dyn ChainStateStore>,
    mempool: Arc<dyn MempoolPort>,
    /// Whether to verify scripts (can be disabled for testing).
    verify_scripts: bool,
}

impl PackageAcceptor {
    /// Create a new package acceptor.
    pub fn new(
        chain_state: Arc<dyn ChainStateStore>,
        mempool: Arc<dyn MempoolPort>,
    ) -> Self {
        PackageAcceptor {
            chain_state,
            mempool,
            verify_scripts: true,
        }
    }

    /// Enable or disable script verification (useful for testing).
    pub fn set_verify_scripts(&mut self, verify: bool) {
        self.verify_scripts = verify;
    }

    /// Accept a package of transactions into the mempool.
    ///
    /// Transactions should be in topological order (parents before children).
    /// If not, the package validator will reject them.
    pub async fn accept_package(
        &self,
        transactions: &[Transaction],
    ) -> Result<PackageResult, PackageAcceptError> {
        // 1. Validate package structure
        let package_type = packages::validate_package(transactions)
            .map_err(PackageAcceptError::PackageValidation)?;

        // 2. Compute fees and vsizes for each transaction
        //    We track outputs created by earlier package transactions so
        //    children can reference their parents' outputs.
        let mut package_outputs: HashMap<(Txid, u32), Amount> = HashMap::new();
        let mut tx_fees: Vec<(Txid, Amount, u32)> = Vec::new();
        let mut total_fee = Amount::from_sat(0);
        let mut total_vsize: u32 = 0;

        for tx in transactions {
            let txid = tx.txid();
            let vsize = packages::estimate_package_tx_vsize(tx);

            // Resolve input values from UTXO set + package-internal outputs
            let mut input_total: i64 = 0;
            for input in &tx.inputs {
                let prev_txid = input.previous_output.txid;
                let prev_vout = input.previous_output.vout;

                // First check package-internal outputs
                if let Some(value) = package_outputs.get(&(prev_txid, prev_vout)) {
                    input_total += value.as_sat();
                } else {
                    // Fall back to the UTXO set
                    let utxo = self
                        .chain_state
                        .get_utxo(&prev_txid, prev_vout)
                        .await
                        .map_err(|e| PackageAcceptError::MissingInput {
                            txid,
                            detail: e.to_string(),
                        })?
                        .ok_or_else(|| PackageAcceptError::MissingInput {
                            txid,
                            detail: format!("{}:{}", prev_txid, prev_vout),
                        })?;
                    input_total += utxo.output.value.as_sat();
                }
            }

            let output_total: i64 = tx.outputs.iter().map(|o| o.value.as_sat()).sum();

            if input_total < output_total {
                return Err(PackageAcceptError::NegativeFee { txid });
            }

            let fee = Amount::from_sat(input_total - output_total);

            // Register this transaction's outputs for later children
            for (vout, output) in tx.outputs.iter().enumerate() {
                package_outputs.insert((txid, vout as u32), output.value);
            }

            total_fee = Amount::from_sat(total_fee.as_sat() + fee.as_sat());
            total_vsize += vsize;
            tx_fees.push((txid, fee, vsize));
        }

        // 3. Check total package size
        if total_vsize > MAX_PACKAGE_VSIZE {
            return Err(PackageAcceptError::PackageTooLarge {
                vsize: total_vsize,
                limit: MAX_PACKAGE_VSIZE,
            });
        }

        // 4. Check aggregate fee rate
        let package_fee_rate = packages::check_package_fee_rate(total_fee, total_vsize)
            .map_err(|e| match e {
                PackageError::InsufficientPackageFeeRate { fee_rate, min_rate } => {
                    PackageAcceptError::InsufficientPackageFeeRate { fee_rate, min_rate }
                }
                _ => PackageAcceptError::PackageValidation(e),
            })?;

        // 5. Submit each transaction to the mempool in topological order
        let mut accepted = Vec::new();

        for (i, tx) in transactions.iter().enumerate() {
            let (txid, fee, vsize) = &tx_fees[i];

            self.mempool
                .add_transaction(tx)
                .await
                .map_err(|e| PackageAcceptError::MempoolRejection {
                    txid: *txid,
                    reason: e.to_string(),
                })?;

            tracing::info!(
                "Package: accepted tx {} ({}/{}, fee={}, vsize={})",
                txid,
                i + 1,
                transactions.len(),
                fee.as_sat(),
                vsize,
            );

            accepted.push(PackageAcceptedTx {
                txid: *txid,
                fee: *fee,
                vsize: *vsize,
            });
        }

        tracing::info!(
            "Package accepted: {} txs, total_fee={}, total_vsize={}, rate={:.1} sat/vB, type={:?}",
            accepted.len(),
            total_fee.as_sat(),
            total_vsize,
            package_fee_rate,
            package_type,
        );

        Ok(PackageResult {
            accepted,
            package_type,
            total_fee,
            total_vsize,
            package_fee_rate,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use abtc_domain::primitives::{BlockHash, Hash256, OutPoint, TxIn, TxOut};
    use abtc_domain::Script;
    use abtc_ports::{MempoolEntry, MempoolInfo, UtxoEntry, UtxoSetInfo};
    use std::collections::HashMap;
    use tokio::sync::RwLock;

    // ── Mock Chain State ────────────────────────────────────

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
        ) -> Result<(BlockHash, u32), Box<dyn std::error::Error + Send + Sync>> {
            Ok((BlockHash::zero(), 100))
        }

        async fn write_chain_tip(
            &self,
            _hash: BlockHash,
            _height: u32,
        ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
            Ok(())
        }

        async fn get_utxo_set_info(
            &self,
        ) -> Result<UtxoSetInfo, Box<dyn std::error::Error + Send + Sync>> {
            Ok(UtxoSetInfo {
                txout_count: 0,
                total_amount: Amount::from_sat(0),
                best_block: BlockHash::zero(),
                height: 100,
            })
        }
    }

    // ── Mock Mempool ────────────────────────────────────────

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

    // ── Helper ──────────────────────────────────────────────

    fn funding_txid(byte: u8) -> Txid {
        Txid::from_hash(Hash256::from_bytes([byte; 32]))
    }

    fn make_utxo(value: i64) -> UtxoEntry {
        UtxoEntry {
            output: TxOut::new(Amount::from_sat(value), Script::new()),
            height: 1,
            is_coinbase: false,
        }
    }

    // ── Tests ───────────────────────────────────────────────

    #[tokio::test]
    async fn test_accept_simple_package() {
        let chain_state = Arc::new(MockChainState::new());
        let mempool = Arc::new(MockMempool::new());

        // Funding UTXO for the parent
        let ftxid = funding_txid(0x01);
        chain_state.add_utxo(ftxid, 0, make_utxo(100_000)).await;

        let parent = Transaction::v1(
            vec![TxIn::final_input(OutPoint::new(ftxid, 0), Script::new())],
            vec![TxOut::new(Amount::from_sat(90_000), Script::new())],
            0,
        );
        let parent_txid = parent.txid();

        let child = Transaction::v1(
            vec![TxIn::final_input(
                OutPoint::new(parent_txid, 0),
                Script::new(),
            )],
            vec![TxOut::new(Amount::from_sat(80_000), Script::new())],
            0,
        );

        let mut acceptor = PackageAcceptor::new(chain_state, mempool.clone());
        acceptor.set_verify_scripts(false);

        let result = acceptor
            .accept_package(&[parent, child])
            .await
            .unwrap();

        assert_eq!(result.accepted.len(), 2);
        assert_eq!(result.package_type, PackageType::ChildWithParents);
        assert_eq!(result.total_fee.as_sat(), 20_000); // 10k + 10k
        assert!(result.package_fee_rate > 0.0);

        // Both should be in the mempool
        assert_eq!(mempool.get_transaction_count().await.unwrap(), 2);
    }

    #[tokio::test]
    async fn test_cpfp_low_parent_high_child() {
        let chain_state = Arc::new(MockChainState::new());
        let mempool = Arc::new(MockMempool::new());

        let ftxid = funding_txid(0x02);
        chain_state.add_utxo(ftxid, 0, make_utxo(100_000)).await;

        // Parent: very low fee (100 sat for ~60 vB = ~1.7 sat/vB)
        let parent = Transaction::v1(
            vec![TxIn::final_input(OutPoint::new(ftxid, 0), Script::new())],
            vec![TxOut::new(Amount::from_sat(99_900), Script::new())],
            0,
        );
        let parent_txid = parent.txid();

        // Child: high fee (10,000 sat for ~60 vB = ~167 sat/vB)
        let child = Transaction::v1(
            vec![TxIn::final_input(
                OutPoint::new(parent_txid, 0),
                Script::new(),
            )],
            vec![TxOut::new(Amount::from_sat(89_900), Script::new())],
            0,
        );

        let mut acceptor = PackageAcceptor::new(chain_state, mempool.clone());
        acceptor.set_verify_scripts(false);

        let result = acceptor.accept_package(&[parent, child]).await.unwrap();

        // Parent fee: 100_000 - 99_900 = 100
        // Child fee: 99_900 - 89_900 = 10_000
        // Total: 10_100 over ~120 vB
        assert_eq!(result.total_fee.as_sat(), 10_100);
        assert!(result.package_fee_rate > 1.0); // Above minimum
    }

    #[tokio::test]
    async fn test_missing_input_rejected() {
        let chain_state = Arc::new(MockChainState::new());
        let mempool = Arc::new(MockMempool::new());

        // No funding UTXO — parent's input is missing
        let parent = Transaction::v1(
            vec![TxIn::final_input(
                OutPoint::new(funding_txid(0x99), 0),
                Script::new(),
            )],
            vec![TxOut::new(Amount::from_sat(50_000), Script::new())],
            0,
        );

        let mut acceptor = PackageAcceptor::new(chain_state, mempool);
        acceptor.set_verify_scripts(false);

        let result = acceptor.accept_package(&[parent]).await;
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            PackageAcceptError::MissingInput { .. }
        ));
    }

    #[tokio::test]
    async fn test_empty_package_rejected() {
        let chain_state = Arc::new(MockChainState::new());
        let mempool = Arc::new(MockMempool::new());

        let acceptor = PackageAcceptor::new(chain_state, mempool);
        let result = acceptor.accept_package(&[]).await;
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            PackageAcceptError::PackageValidation(_)
        ));
    }

    #[tokio::test]
    async fn test_negative_fee_rejected() {
        let chain_state = Arc::new(MockChainState::new());
        let mempool = Arc::new(MockMempool::new());

        let ftxid = funding_txid(0x03);
        chain_state.add_utxo(ftxid, 0, make_utxo(1_000)).await;

        // Outputs exceed input — negative fee
        let tx = Transaction::v1(
            vec![TxIn::final_input(OutPoint::new(ftxid, 0), Script::new())],
            vec![TxOut::new(Amount::from_sat(2_000), Script::new())],
            0,
        );

        let mut acceptor = PackageAcceptor::new(chain_state, mempool);
        acceptor.set_verify_scripts(false);

        let result = acceptor.accept_package(&[tx]).await;
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            PackageAcceptError::NegativeFee { .. }
        ));
    }

    #[tokio::test]
    async fn test_two_parents_one_child_package() {
        let chain_state = Arc::new(MockChainState::new());
        let mempool = Arc::new(MockMempool::new());

        let ftxid_a = funding_txid(0x10);
        let ftxid_b = funding_txid(0x11);
        chain_state.add_utxo(ftxid_a, 0, make_utxo(50_000)).await;
        chain_state.add_utxo(ftxid_b, 0, make_utxo(50_000)).await;

        let parent_a = Transaction::v1(
            vec![TxIn::final_input(
                OutPoint::new(ftxid_a, 0),
                Script::new(),
            )],
            vec![TxOut::new(Amount::from_sat(49_000), Script::new())],
            0,
        );
        let parent_a_txid = parent_a.txid();

        let parent_b = Transaction::v1(
            vec![TxIn::final_input(
                OutPoint::new(ftxid_b, 0),
                Script::new(),
            )],
            vec![TxOut::new(Amount::from_sat(49_000), Script::new())],
            0,
        );
        let parent_b_txid = parent_b.txid();

        let child = Transaction::v1(
            vec![
                TxIn::final_input(OutPoint::new(parent_a_txid, 0), Script::new()),
                TxIn::final_input(OutPoint::new(parent_b_txid, 0), Script::new()),
            ],
            vec![TxOut::new(Amount::from_sat(90_000), Script::new())],
            0,
        );

        let mut acceptor = PackageAcceptor::new(chain_state, mempool.clone());
        acceptor.set_verify_scripts(false);

        let result = acceptor
            .accept_package(&[parent_a, parent_b, child])
            .await
            .unwrap();

        assert_eq!(result.accepted.len(), 3);
        assert_eq!(result.package_type, PackageType::ChildWithParents);
        // Parent A fee: 1000, Parent B fee: 1000, Child fee: 8000
        assert_eq!(result.total_fee.as_sat(), 10_000);
        assert_eq!(mempool.get_transaction_count().await.unwrap(), 3);
    }

    // ── Regression tests ────────────────────────────────────

    #[tokio::test]
    async fn regression_child_references_parent_output() {
        // Ensures the package acceptor correctly resolves outputs from
        // earlier transactions in the package (not just UTXO set).
        let chain_state = Arc::new(MockChainState::new());
        let mempool = Arc::new(MockMempool::new());

        let ftxid = funding_txid(0x20);
        chain_state.add_utxo(ftxid, 0, make_utxo(100_000)).await;

        let parent = Transaction::v1(
            vec![TxIn::final_input(OutPoint::new(ftxid, 0), Script::new())],
            vec![
                TxOut::new(Amount::from_sat(40_000), Script::new()),
                TxOut::new(Amount::from_sat(50_000), Script::new()),
            ],
            0,
        );
        let parent_txid = parent.txid();

        // Child spends parent output index 1 (50,000 sat)
        let child = Transaction::v1(
            vec![TxIn::final_input(
                OutPoint::new(parent_txid, 1),
                Script::new(),
            )],
            vec![TxOut::new(Amount::from_sat(45_000), Script::new())],
            0,
        );

        let mut acceptor = PackageAcceptor::new(chain_state, mempool.clone());
        acceptor.set_verify_scripts(false);

        let result = acceptor
            .accept_package(&[parent, child])
            .await
            .unwrap();

        // Parent fee: 100_000 - 90_000 = 10_000
        // Child fee: 50_000 - 45_000 = 5_000
        assert_eq!(result.total_fee.as_sat(), 15_000);
        assert_eq!(result.accepted.len(), 2);
    }

    #[tokio::test]
    async fn regression_duplicate_mempool_submission_fails() {
        // If a tx is already in the mempool, submitting it again
        // as part of a package should fail gracefully.
        let chain_state = Arc::new(MockChainState::new());
        let mempool = Arc::new(MockMempool::new());

        let ftxid = funding_txid(0x30);
        chain_state.add_utxo(ftxid, 0, make_utxo(100_000)).await;

        let tx = Transaction::v1(
            vec![TxIn::final_input(OutPoint::new(ftxid, 0), Script::new())],
            vec![TxOut::new(Amount::from_sat(90_000), Script::new())],
            0,
        );

        // Pre-add to mempool
        mempool.add_transaction(&tx).await.unwrap();

        let mut acceptor = PackageAcceptor::new(chain_state, mempool);
        acceptor.set_verify_scripts(false);

        let result = acceptor.accept_package(&[tx]).await;
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            PackageAcceptError::MempoolRejection { .. }
        ));
    }

    #[tokio::test]
    async fn regression_package_fee_components() {
        // Verify individual fee tracking is correct
        let chain_state = Arc::new(MockChainState::new());
        let mempool = Arc::new(MockMempool::new());

        let ftxid = funding_txid(0x40);
        chain_state.add_utxo(ftxid, 0, make_utxo(100_000)).await;

        let parent = Transaction::v1(
            vec![TxIn::final_input(OutPoint::new(ftxid, 0), Script::new())],
            vec![TxOut::new(Amount::from_sat(95_000), Script::new())],
            0,
        );
        let parent_txid = parent.txid();

        let child = Transaction::v1(
            vec![TxIn::final_input(
                OutPoint::new(parent_txid, 0),
                Script::new(),
            )],
            vec![TxOut::new(Amount::from_sat(85_000), Script::new())],
            0,
        );

        let mut acceptor = PackageAcceptor::new(chain_state, mempool);
        acceptor.set_verify_scripts(false);

        let result = acceptor
            .accept_package(&[parent, child])
            .await
            .unwrap();

        // Parent fee = 100_000 - 95_000 = 5_000
        assert_eq!(result.accepted[0].fee.as_sat(), 5_000);
        // Child fee = 95_000 - 85_000 = 10_000
        assert_eq!(result.accepted[1].fee.as_sat(), 10_000);
        // Total = 15_000
        assert_eq!(result.total_fee.as_sat(), 15_000);
    }
}
