//! Block connection — contextual validation against the UTXO set
//!
//! This module implements the "connect block" logic that Bitcoin Core performs
//! when a new block extends the active chain. Unlike the non-contextual checks
//! in `rules.rs`, these checks require knowledge of the current chain state:
//!
//! - Every input references an existing, unspent output (UTXO)
//! - No double-spends within the block
//! - Coinbase outputs are mature (100+ confirmations before spending)
//! - Total input value >= total output value (no inflation)
//! - Coinbase reward <= block subsidy + total fees
//! - All scripts/signatures verify correctly
//!
//! The design uses a `UtxoView` trait so that the domain logic remains
//! independent of storage (hexagonal architecture).

use crate::consensus::params::ConsensusParams;
use crate::consensus::rules::COINBASE_MATURITY;
use crate::consensus::validation::ValidationError;
use crate::crypto::signing::TransactionSignatureChecker;
use crate::primitives::{Amount, Block, OutPoint, TxOut};
use crate::script::{verify_script_with_witness, ScriptFlags};

use std::collections::HashMap;

// ── UTXO view trait ──────────────────────────────────────────────────

/// A read-only view of the unspent transaction output set.
///
/// This trait abstracts the UTXO database so that block validation logic
/// can be tested with simple in-memory maps while production uses RocksDB.
pub trait UtxoView {
    /// Look up a UTXO by outpoint. Returns `None` if already spent or unknown.
    fn get_utxo(&self, outpoint: &OutPoint) -> Option<UtxoEntry>;
}

/// An entry in the UTXO set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UtxoEntry {
    /// The unspent transaction output.
    pub output: TxOut,
    /// The block height at which this output was created.
    pub height: u32,
    /// Whether this output was created by a coinbase transaction.
    pub is_coinbase: bool,
}

// ── Block connection result ──────────────────────────────────────────

/// The state changes produced by connecting a block.
///
/// The caller (application layer) applies these changes to the UTXO database.
#[derive(Debug)]
pub struct BlockConnectResult {
    /// UTXOs consumed (spent) by this block.  Key = outpoint consumed.
    pub spent: HashMap<OutPoint, UtxoEntry>,
    /// UTXOs created by this block.  Key = outpoint created.
    pub created: HashMap<OutPoint, UtxoEntry>,
    /// Total fees collected by all non-coinbase transactions.
    pub total_fees: Amount,
}

// ── Contextual validation errors ─────────────────────────────────────

/// Errors specific to contextual block validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConnectBlockError {
    /// A transaction input references an output that doesn't exist in the UTXO set.
    MissingUtxo(OutPoint),
    /// A coinbase output is being spent before it has matured.
    PrematureCoinbaseSpend {
        outpoint: OutPoint,
        created_height: u32,
        spend_height: u32,
    },
    /// A transaction spends more than its inputs provide.
    InputValueBelowOutput {
        tx_index: usize,
        input_total: i64,
        output_total: i64,
    },
    /// The coinbase reward exceeds the allowed subsidy + fees.
    CoinbaseOverpay {
        allowed: i64,
        actual: i64,
    },
    /// A transaction's script verification failed.
    ScriptVerificationFailed {
        tx_index: usize,
        input_index: usize,
        reason: String,
    },
    /// A non-contextual consensus rule was violated.
    ConsensusError(ValidationError),
    /// An output is being double-spent within the same block.
    DoubleSpendInBlock(OutPoint),
}

impl std::fmt::Display for ConnectBlockError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConnectBlockError::MissingUtxo(op) => {
                write!(f, "missing UTXO: {}:{}", op.txid, op.vout)
            }
            ConnectBlockError::PrematureCoinbaseSpend {
                outpoint,
                created_height,
                spend_height,
            } => write!(
                f,
                "premature coinbase spend of {}:{} (created at {}, spent at {}, need {} confirmations)",
                outpoint.txid, outpoint.vout, created_height, spend_height, COINBASE_MATURITY
            ),
            ConnectBlockError::InputValueBelowOutput {
                tx_index,
                input_total,
                output_total,
            } => write!(
                f,
                "tx {} input total ({}) < output total ({})",
                tx_index, input_total, output_total
            ),
            ConnectBlockError::CoinbaseOverpay { allowed, actual } => {
                write!(f, "coinbase overpay: allowed {}, actual {}", allowed, actual)
            }
            ConnectBlockError::ScriptVerificationFailed {
                tx_index,
                input_index,
                reason,
            } => write!(
                f,
                "script verification failed for tx {} input {}: {}",
                tx_index, input_index, reason
            ),
            ConnectBlockError::ConsensusError(e) => write!(f, "consensus error: {}", e),
            ConnectBlockError::DoubleSpendInBlock(op) => {
                write!(f, "double-spend within block: {}:{}", op.txid, op.vout)
            }
        }
    }
}

impl std::error::Error for ConnectBlockError {}

impl From<ValidationError> for ConnectBlockError {
    fn from(e: ValidationError) -> Self {
        ConnectBlockError::ConsensusError(e)
    }
}

// ── Core logic ───────────────────────────────────────────────────────

/// Connect a block to the active chain, performing full contextual validation.
///
/// This is the core of Bitcoin's block validation:
/// 1. Run non-contextual checks (`check_block`)
/// 2. For each non-coinbase transaction:
///    a. Look up every input in the UTXO set (or block-internal outputs)
///    b. Check coinbase maturity
///    c. Verify input_value >= output_value
///    d. Verify all scripts/signatures
/// 3. Check that coinbase reward <= subsidy + total_fees
/// 4. Return the UTXO changes (spent/created sets)
///
/// The caller applies the returned changes to the UTXO database.
pub fn connect_block(
    block: &Block,
    height: u32,
    utxo_view: &dyn UtxoView,
    params: &ConsensusParams,
    verify_scripts: bool,
) -> Result<BlockConnectResult, ConnectBlockError> {
    use crate::consensus::rules::{check_block, check_block_header};

    // Step 0: Non-contextual validation
    check_block_header(&block.header, params)?;
    check_block(block, params)?;

    // Track UTXOs created within this block (for transactions spending
    // outputs created earlier in the same block).
    let mut block_utxos: HashMap<OutPoint, UtxoEntry> = HashMap::new();

    // Track all consumed outpoints (detect double-spends within the block).
    let mut spent: HashMap<OutPoint, UtxoEntry> = HashMap::new();

    // Track all created outpoints.
    let mut created: HashMap<OutPoint, UtxoEntry> = HashMap::new();

    let mut total_fees = 0i64;

    // Script verification flags — in production these depend on BIP activation
    // heights, but we use a reasonable default set.
    let script_flags = ScriptFlags::standard();

    // Process each transaction
    for (tx_idx, tx) in block.transactions.iter().enumerate() {
        let txid = tx.txid();
        let is_coinbase = tx.is_coinbase();

        if !is_coinbase {
            // --- Validate inputs ---
            let mut input_total = 0i64;

            for (in_idx, input) in tx.inputs.iter().enumerate() {
                let outpoint = &input.previous_output;

                // Check for double-spend within this block
                if spent.contains_key(outpoint) {
                    return Err(ConnectBlockError::DoubleSpendInBlock(*outpoint));
                }

                // Look up UTXO: first check outputs created earlier in this block,
                // then fall back to the persistent UTXO set.
                let utxo = block_utxos
                    .get(outpoint)
                    .cloned()
                    .or_else(|| utxo_view.get_utxo(outpoint))
                    .ok_or_else(|| ConnectBlockError::MissingUtxo(*outpoint))?;

                // Check coinbase maturity
                if utxo.is_coinbase {
                    let confirmations = height.saturating_sub(utxo.height);
                    if confirmations < COINBASE_MATURITY {
                        return Err(ConnectBlockError::PrematureCoinbaseSpend {
                            outpoint: *outpoint,
                            created_height: utxo.height,
                            spend_height: height,
                        });
                    }
                }

                input_total += utxo.output.value.as_sat();

                // Verify script
                if verify_scripts {
                    let checker = if input.witness.is_empty() {
                        TransactionSignatureChecker::new(tx, in_idx, utxo.output.value)
                    } else {
                        TransactionSignatureChecker::new_witness_v0(tx, in_idx, utxo.output.value)
                    };

                    let result = verify_script_with_witness(
                        &input.script_sig,
                        &utxo.output.script_pubkey,
                        &input.witness,
                        script_flags,
                        &checker,
                    );

                    if let Err(e) = result {
                        return Err(ConnectBlockError::ScriptVerificationFailed {
                            tx_index: tx_idx,
                            input_index: in_idx,
                            reason: format!("{:?}", e),
                        });
                    }
                }

                // Record as spent
                spent.insert(*outpoint, utxo);

                // Remove from block_utxos if it was created earlier in this block
                block_utxos.remove(outpoint);
            }

            // Check input value >= output value
            let output_total = tx.total_output_value().as_sat();
            if input_total < output_total {
                return Err(ConnectBlockError::InputValueBelowOutput {
                    tx_index: tx_idx,
                    input_total,
                    output_total,
                });
            }

            let fee = input_total - output_total;
            total_fees += fee;
        }

        // Register outputs as new UTXOs
        for (vout, output) in tx.outputs.iter().enumerate() {
            let outpoint = OutPoint::new(txid, vout as u32);
            let entry = UtxoEntry {
                output: output.clone(),
                height,
                is_coinbase,
            };
            block_utxos.insert(outpoint, entry.clone());
            created.insert(outpoint, entry);
        }
    }

    // Check coinbase reward
    let subsidy = params.get_block_subsidy(height) as i64;
    let allowed_reward = subsidy + total_fees;
    let coinbase_output = block.transactions[0].total_output_value().as_sat();

    if coinbase_output > allowed_reward {
        return Err(ConnectBlockError::CoinbaseOverpay {
            allowed: allowed_reward,
            actual: coinbase_output,
        });
    }

    Ok(BlockConnectResult {
        spent,
        created,
        total_fees: Amount::from_sat(total_fees),
    })
}

/// Compute the UTXO changes needed to disconnect (revert) a block.
///
/// This is the inverse of `connect_block`: outputs created by the block
/// are removed, and outputs consumed by the block are restored.
///
/// The caller must have stored the `BlockConnectResult` from when the
/// block was originally connected.
pub fn disconnect_block(connect_result: &BlockConnectResult) -> BlockDisconnectResult {
    BlockDisconnectResult {
        restore: connect_result.spent.clone(),
        remove: connect_result.created.keys().cloned().collect(),
    }
}

/// The state changes needed to disconnect (revert) a block.
#[derive(Debug)]
pub struct BlockDisconnectResult {
    /// UTXOs to restore (were spent when the block was connected).
    pub restore: HashMap<OutPoint, UtxoEntry>,
    /// Outpoints to remove (were created when the block was connected).
    pub remove: Vec<OutPoint>,
}

// ── Simple in-memory UTXO view for testing ──────────────────────────

/// A simple in-memory UTXO set that implements `UtxoView`.
///
/// Useful for testing and for tracking changes during block connection.
#[derive(Debug, Clone, Default)]
pub struct MemoryUtxoSet {
    utxos: HashMap<OutPoint, UtxoEntry>,
}

impl MemoryUtxoSet {
    pub fn new() -> Self {
        MemoryUtxoSet {
            utxos: HashMap::new(),
        }
    }

    /// Add a UTXO to the set.
    pub fn add(&mut self, outpoint: OutPoint, entry: UtxoEntry) {
        self.utxos.insert(outpoint, entry);
    }

    /// Remove a UTXO from the set.
    pub fn remove(&mut self, outpoint: &OutPoint) -> Option<UtxoEntry> {
        self.utxos.remove(outpoint)
    }

    /// Apply the results of connecting a block.
    pub fn apply_connect(&mut self, result: &BlockConnectResult) {
        for outpoint in result.spent.keys() {
            self.utxos.remove(outpoint);
        }
        for (outpoint, entry) in &result.created {
            self.utxos.insert(*outpoint, entry.clone());
        }
    }

    /// Apply the results of disconnecting a block.
    pub fn apply_disconnect(&mut self, result: &BlockDisconnectResult) {
        for outpoint in &result.remove {
            self.utxos.remove(outpoint);
        }
        for (outpoint, entry) in &result.restore {
            self.utxos.insert(*outpoint, entry.clone());
        }
    }

    /// Number of UTXOs in the set.
    pub fn len(&self) -> usize {
        self.utxos.len()
    }

    /// Whether the set is empty.
    pub fn is_empty(&self) -> bool {
        self.utxos.is_empty()
    }

    /// Iterate over all UTXOs in the set.
    pub fn iter(&self) -> impl Iterator<Item = (&OutPoint, &UtxoEntry)> {
        self.utxos.iter()
    }
}

impl UtxoView for MemoryUtxoSet {
    fn get_utxo(&self, outpoint: &OutPoint) -> Option<UtxoEntry> {
        self.utxos.get(outpoint).cloned()
    }
}
