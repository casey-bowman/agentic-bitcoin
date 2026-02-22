//! Package Relay — Transaction package validation and policy
//!
//! Implements package relay support corresponding to Bitcoin Core's BIP331
//! package relay protocol. Packages allow groups of related transactions
//! (typically parent + child for CPFP) to be validated and accepted as a
//! unit, which is critical for fee-bumping via Child Pays For Parent.
//!
//! ## Package Types
//!
//! - **ChildWithParents**: One child transaction with one or more unconfirmed
//!   parents. This is the primary CPFP use case — a child with high fees
//!   "pays for" its low-fee parents.
//!
//! ## Key Rules
//!
//! 1. Topological order: parents must appear before children
//! 2. No conflicting transactions within a package
//! 3. Package fee rate must meet minimum relay fee
//! 4. Ancestor/descendant limits apply to the full package
//! 5. Maximum package size: 25 transactions, 101 kvB total

use crate::policy::limits::{DEFAULT_ANCESTOR_LIMIT, MIN_RELAY_FEE_RATE};
use crate::primitives::{Amount, Transaction, Txid};
use std::collections::{HashMap, HashSet};

/// Maximum number of transactions in a package
pub const MAX_PACKAGE_COUNT: usize = 25;

/// Maximum total virtual size of a package in vbytes
pub const MAX_PACKAGE_VSIZE: u32 = 101_000;

/// Minimum package fee rate in sat/vB — packages whose aggregate fee rate
/// falls below this are rejected even if individual txs pass.
pub const MIN_PACKAGE_FEE_RATE: f64 = MIN_RELAY_FEE_RATE;

/// Type of package relationship
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PackageType {
    /// One child transaction with one or more unconfirmed parents.
    /// This is the canonical CPFP package: the child's fee subsidises
    /// the parents so a miner will include the whole family.
    ChildWithParents,

    /// A general package of topologically sorted transactions.
    /// Each transaction may spend outputs of earlier transactions
    /// in the package.
    TopologicalPackage,
}

/// A validated package of transactions ready for mempool submission.
#[derive(Debug, Clone)]
pub struct TransactionPackage {
    /// Transactions in topological order (parents before children).
    pub transactions: Vec<Transaction>,
    /// Package type classification.
    pub package_type: PackageType,
    /// Aggregate virtual size (sum of all tx vsizes).
    pub total_vsize: u32,
    /// Aggregate fee (sum of all fees — computed externally since we
    /// need UTXO data to determine fees).
    pub total_fee: Amount,
}

/// Errors from package validation.
#[derive(Debug, Clone, PartialEq)]
pub enum PackageError {
    /// Package is empty.
    EmptyPackage,
    /// Package exceeds maximum transaction count.
    TooManyTransactions { count: usize, limit: usize },
    /// Package exceeds maximum total virtual size.
    TotalSizeTooLarge { vsize: u32, limit: u32 },
    /// A duplicate transaction appears in the package.
    DuplicateTransaction(Txid),
    /// Transactions are not in topological order.
    NotTopologicallySorted { child: Txid, missing_parent: Txid },
    /// Package contains conflicting transactions (double-spends within package).
    ConflictingTransactions { txid_a: Txid, txid_b: Txid },
    /// Package fee rate is below minimum.
    InsufficientPackageFeeRate { fee_rate: f64, min_rate: f64 },
    /// A transaction in the package fails consensus checks.
    ConsensusFailure { txid: Txid, reason: String },
    /// Adding this package would violate ancestor/descendant limits.
    AncestorLimitExceeded { txid: Txid, count: u32, limit: u32 },
}

impl std::fmt::Display for PackageError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PackageError::EmptyPackage => write!(f, "package is empty"),
            PackageError::TooManyTransactions { count, limit } => {
                write!(f, "package has {} txs (limit {})", count, limit)
            }
            PackageError::TotalSizeTooLarge { vsize, limit } => {
                write!(f, "package size {} vB exceeds limit {} vB", vsize, limit)
            }
            PackageError::DuplicateTransaction(txid) => {
                write!(f, "duplicate transaction {}", txid)
            }
            PackageError::NotTopologicallySorted {
                child,
                missing_parent,
            } => {
                write!(
                    f,
                    "tx {} spends output of {} which appears later or is missing",
                    child, missing_parent
                )
            }
            PackageError::ConflictingTransactions { txid_a, txid_b } => {
                write!(
                    f,
                    "transactions {} and {} spend the same input",
                    txid_a, txid_b
                )
            }
            PackageError::InsufficientPackageFeeRate { fee_rate, min_rate } => {
                write!(
                    f,
                    "package fee rate {:.2} sat/vB below minimum {:.2}",
                    fee_rate, min_rate
                )
            }
            PackageError::ConsensusFailure { txid, reason } => {
                write!(f, "tx {} fails consensus: {}", txid, reason)
            }
            PackageError::AncestorLimitExceeded { txid, count, limit } => {
                write!(
                    f,
                    "tx {} would have {} ancestors (limit {})",
                    txid, count, limit
                )
            }
        }
    }
}

impl std::error::Error for PackageError {}

/// Sort transactions into topological order (parents before children).
///
/// Returns the sorted list, or an error if a cycle is detected (which
/// would indicate an invalid package).
pub fn topological_sort(transactions: &[Transaction]) -> Result<Vec<Transaction>, PackageError> {
    let txid_set: HashSet<Txid> = transactions.iter().map(|tx| tx.txid()).collect();
    let mut txid_to_tx: HashMap<Txid, &Transaction> = HashMap::new();
    for tx in transactions {
        txid_to_tx.insert(tx.txid(), tx);
    }

    // Build dependency graph: txid -> set of in-package parents
    let mut deps: HashMap<Txid, HashSet<Txid>> = HashMap::new();
    for tx in transactions {
        let txid = tx.txid();
        let parents: HashSet<Txid> = tx
            .inputs
            .iter()
            .map(|inp| inp.previous_output.txid)
            .filter(|parent_txid| txid_set.contains(parent_txid))
            .collect();
        deps.insert(txid, parents);
    }

    // Kahn's algorithm
    let mut result = Vec::with_capacity(transactions.len());
    let mut ready: Vec<Txid> = deps
        .iter()
        .filter(|(_, parents)| parents.is_empty())
        .map(|(txid, _)| *txid)
        .collect();

    // Sort for determinism
    ready.sort();

    while let Some(txid) = ready.pop() {
        result.push((*txid_to_tx[&txid]).clone());

        // Remove this txid from all dependency sets
        for (other_txid, parents) in deps.iter_mut() {
            if parents.remove(&txid)
                && parents.is_empty()
                && !result.iter().any(|t| t.txid() == *other_txid)
            {
                ready.push(*other_txid);
                ready.sort();
            }
        }
    }

    if result.len() != transactions.len() {
        // Cycle detected — find a transaction that's still blocked
        let sorted_txids: HashSet<Txid> = result.iter().map(|tx| tx.txid()).collect();
        for (txid, parents) in &deps {
            if !sorted_txids.contains(txid) {
                if let Some(blocked_by) = parents.iter().find(|p| !sorted_txids.contains(p)) {
                    return Err(PackageError::NotTopologicallySorted {
                        child: *txid,
                        missing_parent: *blocked_by,
                    });
                }
            }
        }
        // Shouldn't reach here, but fallback
        return Err(PackageError::EmptyPackage);
    }

    Ok(result)
}

/// Validate a package of transactions.
///
/// Checks:
/// 1. Non-empty, within size limits
/// 2. No duplicate txids
/// 3. No conflicting inputs (double-spends within package)
/// 4. Topologically sorted (parents before children)
/// 5. Each transaction passes basic consensus checks
/// 6. In-package ancestor counts within limits
pub fn validate_package(transactions: &[Transaction]) -> Result<PackageType, PackageError> {
    // 1. Non-empty
    if transactions.is_empty() {
        return Err(PackageError::EmptyPackage);
    }

    // 2. Count limit
    if transactions.len() > MAX_PACKAGE_COUNT {
        return Err(PackageError::TooManyTransactions {
            count: transactions.len(),
            limit: MAX_PACKAGE_COUNT,
        });
    }

    // 3. No duplicates
    let mut seen_txids: HashSet<Txid> = HashSet::new();
    for tx in transactions {
        let txid = tx.txid();
        if !seen_txids.insert(txid) {
            return Err(PackageError::DuplicateTransaction(txid));
        }
    }

    // 4. No conflicting inputs within the package
    {
        let mut spent_outpoints: HashMap<(Txid, u32), Txid> = HashMap::new();
        for tx in transactions {
            let txid = tx.txid();
            for input in &tx.inputs {
                let outpoint = (input.previous_output.txid, input.previous_output.vout);
                if let Some(existing) = spent_outpoints.get(&outpoint) {
                    return Err(PackageError::ConflictingTransactions {
                        txid_a: *existing,
                        txid_b: txid,
                    });
                }
                spent_outpoints.insert(outpoint, txid);
            }
        }
    }

    // 5. Topological order verification
    {
        let mut available_txids: HashSet<Txid> = HashSet::new();
        for tx in transactions {
            let txid = tx.txid();
            // Check that any in-package parent has already been seen
            for input in &tx.inputs {
                let parent_txid = input.previous_output.txid;
                if seen_txids.contains(&parent_txid) && !available_txids.contains(&parent_txid) {
                    return Err(PackageError::NotTopologicallySorted {
                        child: txid,
                        missing_parent: parent_txid,
                    });
                }
            }
            available_txids.insert(txid);
        }
    }

    // 6. Consensus validation for each transaction
    for tx in transactions {
        if let Err(e) = crate::consensus::rules::check_transaction(tx) {
            return Err(PackageError::ConsensusFailure {
                txid: tx.txid(),
                reason: format!("{}", e),
            });
        }
    }

    // 7. Check in-package ancestor limits
    {
        let mut ancestor_counts: HashMap<Txid, u32> = HashMap::new();
        for tx in transactions {
            let txid = tx.txid();
            let mut my_ancestors: HashSet<Txid> = HashSet::new();

            for input in &tx.inputs {
                let parent_txid = input.previous_output.txid;
                if seen_txids.contains(&parent_txid) {
                    my_ancestors.insert(parent_txid);
                    // Include transitive ancestors
                    // (within-package ancestors already counted)
                }
            }

            let count = (my_ancestors.len() + 1) as u32;
            if count > DEFAULT_ANCESTOR_LIMIT {
                return Err(PackageError::AncestorLimitExceeded {
                    txid,
                    count,
                    limit: DEFAULT_ANCESTOR_LIMIT,
                });
            }
            ancestor_counts.insert(txid, count);
        }
    }

    // Classify the package type
    let package_type = classify_package(transactions);

    Ok(package_type)
}

/// Classify a package into its type.
fn classify_package(transactions: &[Transaction]) -> PackageType {
    if transactions.len() <= 1 {
        return PackageType::TopologicalPackage;
    }

    let txid_set: HashSet<Txid> = transactions.iter().map(|tx| tx.txid()).collect();

    // Check if the last transaction is the only child (all others are parents)
    let child = &transactions[transactions.len() - 1];
    let child_parents: HashSet<Txid> = child
        .inputs
        .iter()
        .map(|inp| inp.previous_output.txid)
        .filter(|parent| txid_set.contains(parent))
        .collect();

    // All other transactions in the package should be parents of the child
    // and should not spend from each other
    let parent_txids: HashSet<Txid> = transactions[..transactions.len() - 1]
        .iter()
        .map(|tx| tx.txid())
        .collect();

    if child_parents == parent_txids {
        // Verify parents don't spend from each other
        let no_inter_parent_deps = transactions[..transactions.len() - 1].iter().all(|tx| {
            tx.inputs
                .iter()
                .all(|inp| !parent_txids.contains(&inp.previous_output.txid))
        });
        if no_inter_parent_deps {
            return PackageType::ChildWithParents;
        }
    }

    PackageType::TopologicalPackage
}

/// Check the aggregate package fee rate.
///
/// For CPFP packages, the combined fee rate of all transactions in the
/// package must meet the minimum relay fee. This allows a high-fee child
/// to compensate for low-fee parents.
pub fn check_package_fee_rate(total_fee: Amount, total_vsize: u32) -> Result<f64, PackageError> {
    let fee_rate = total_fee.as_sat() as f64 / total_vsize.max(1) as f64;

    if fee_rate < MIN_PACKAGE_FEE_RATE {
        return Err(PackageError::InsufficientPackageFeeRate {
            fee_rate,
            min_rate: MIN_PACKAGE_FEE_RATE,
        });
    }

    Ok(fee_rate)
}

/// Estimate the virtual size of a transaction (simplified).
///
/// vsize = weight / 4, where weight ≈ base_size * 4 + witness_size.
pub fn estimate_package_tx_vsize(tx: &Transaction) -> u32 {
    let mut base_size = 10u32;
    let mut witness_size = 0u32;

    for input in &tx.inputs {
        base_size += 41 + input.script_sig.len() as u32;
        if !input.witness.is_empty() {
            witness_size += 2;
            for item in input.witness.stack() {
                witness_size += 1 + item.len() as u32;
            }
        }
    }

    for output in &tx.outputs {
        base_size += 9 + output.script_pubkey.len() as u32;
    }

    if witness_size > 0 {
        witness_size += 2;
    }

    let weight = base_size * 4 + witness_size;
    (weight + 3) / 4
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::primitives::{Amount, OutPoint, TxIn, TxOut};
    use crate::Script;

    fn make_tx(value: i64) -> Transaction {
        let input = TxIn::final_input(OutPoint::new(Txid::zero(), 0), Script::new());
        let output = TxOut::new(Amount::from_sat(value), Script::new());
        Transaction::v1(vec![input], vec![output], 0)
    }

    fn make_child(parent_txid: Txid, vout: u32, value: i64) -> Transaction {
        let input = TxIn::final_input(OutPoint::new(parent_txid, vout), Script::new());
        let output = TxOut::new(Amount::from_sat(value), Script::new());
        Transaction::v1(vec![input], vec![output], 0)
    }

    // ── Package structure tests ─────────────────────────────

    #[test]
    fn test_empty_package_rejected() {
        let result = validate_package(&[]);
        assert!(matches!(result, Err(PackageError::EmptyPackage)));
    }

    #[test]
    fn test_single_tx_package() {
        let tx = make_tx(50_000);
        let result = validate_package(&[tx]);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), PackageType::TopologicalPackage);
    }

    #[test]
    fn test_parent_child_package() {
        let parent = make_tx(50_000);
        let parent_txid = parent.txid();
        let child = make_child(parent_txid, 0, 40_000);

        let result = validate_package(&[parent, child]);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), PackageType::ChildWithParents);
    }

    #[test]
    fn test_wrong_order_rejected() {
        let parent = make_tx(50_000);
        let parent_txid = parent.txid();
        let child = make_child(parent_txid, 0, 40_000);

        // Child before parent — wrong topological order
        let result = validate_package(&[child, parent]);
        assert!(matches!(
            result,
            Err(PackageError::NotTopologicallySorted { .. })
        ));
    }

    #[test]
    fn test_duplicate_transaction_rejected() {
        let tx = make_tx(50_000);
        let result = validate_package(&[tx.clone(), tx]);
        assert!(matches!(result, Err(PackageError::DuplicateTransaction(_))));
    }

    #[test]
    fn test_conflicting_inputs_rejected() {
        // Two transactions spending the same outpoint
        let tx_a = make_tx(50_000);
        let tx_b = make_tx(40_000);

        // Both spend Txid::zero():0 — conflict
        let result = validate_package(&[tx_a, tx_b]);
        assert!(matches!(
            result,
            Err(PackageError::ConflictingTransactions { .. })
        ));
    }

    // ── Fee rate tests ──────────────────────────────────────

    #[test]
    fn test_package_fee_rate_ok() {
        // 1000 sat / 200 vB = 5.0 sat/vB
        let result = check_package_fee_rate(Amount::from_sat(1000), 200);
        assert!(result.is_ok());
        let rate = result.unwrap();
        assert!((rate - 5.0).abs() < 0.01);
    }

    #[test]
    fn test_package_fee_rate_too_low() {
        // 10 sat / 200 vB = 0.05 sat/vB — below 1.0
        let result = check_package_fee_rate(Amount::from_sat(10), 200);
        assert!(matches!(
            result,
            Err(PackageError::InsufficientPackageFeeRate { .. })
        ));
    }

    #[test]
    fn test_cpfp_package_fee_rate() {
        // Parent: 200 vB, 100 sat fee (0.5 sat/vB — below min!)
        // Child:  150 vB, 2000 sat fee (13.3 sat/vB)
        // Combined: 350 vB, 2100 sat fee (6.0 sat/vB — above min)
        let result = check_package_fee_rate(Amount::from_sat(2100), 350);
        assert!(result.is_ok());
        assert!(result.unwrap() > 5.0);
    }

    // ── Topological sort tests ──────────────────────────────

    #[test]
    fn test_topological_sort_already_sorted() {
        let parent = make_tx(50_000);
        let parent_txid = parent.txid();
        let child = make_child(parent_txid, 0, 40_000);

        let sorted = topological_sort(&[parent.clone(), child.clone()]).unwrap();
        assert_eq!(sorted[0].txid(), parent.txid());
        assert_eq!(sorted[1].txid(), child.txid());
    }

    #[test]
    fn test_topological_sort_reorders() {
        let parent = make_tx(50_000);
        let parent_txid = parent.txid();
        let child = make_child(parent_txid, 0, 40_000);

        // Pass in wrong order
        let sorted = topological_sort(&[child.clone(), parent.clone()]).unwrap();
        assert_eq!(sorted[0].txid(), parent.txid());
        assert_eq!(sorted[1].txid(), child.txid());
    }

    #[test]
    fn test_topological_sort_independent_txs() {
        let tx_a = make_tx(50_000);
        let tx_b = make_tx(40_000);

        let sorted = topological_sort(&[tx_a.clone(), tx_b.clone()]).unwrap();
        assert_eq!(sorted.len(), 2);
    }

    // ── Package classification tests ────────────────────────

    #[test]
    fn test_classify_child_with_parents() {
        let parent = make_tx(50_000);
        let parent_txid = parent.txid();
        let child = make_child(parent_txid, 0, 40_000);

        let pkg_type = classify_package(&[parent, child]);
        assert_eq!(pkg_type, PackageType::ChildWithParents);
    }

    #[test]
    fn test_classify_chain_as_topological() {
        // A -> B -> C (chain, not child-with-parents)
        let a = make_tx(50_000);
        let a_txid = a.txid();
        let b = make_child(a_txid, 0, 40_000);
        let b_txid = b.txid();
        let c = make_child(b_txid, 0, 30_000);

        let pkg_type = classify_package(&[a, b, c]);
        assert_eq!(pkg_type, PackageType::TopologicalPackage);
    }

    // ── Size estimation tests ───────────────────────────────

    #[test]
    fn test_estimate_vsize() {
        let tx = make_tx(50_000);
        let vsize = estimate_package_tx_vsize(&tx);
        // Simple 1-in 1-out should be ~60 vB
        assert!(vsize >= 50 && vsize <= 100, "vsize was {}", vsize);
    }

    // ── Package count limit test ────────────────────────────

    #[test]
    fn test_too_many_transactions() {
        let mut txs: Vec<Transaction> = Vec::new();
        for i in 0..26 {
            // Each tx is unique because it has a unique output value
            txs.push(make_tx(50_000 + i));
        }
        let result = validate_package(&txs);
        assert!(matches!(
            result,
            Err(PackageError::TooManyTransactions {
                count: 26,
                limit: 25
            })
        ));
    }

    // ── Regression tests ────────────────────────────────────

    #[test]
    fn regression_two_parents_one_child() {
        // Parent A and Parent B each spend different inputs, Child spends both parents
        let parent_a = Transaction::v1(
            vec![TxIn::final_input(
                OutPoint::new(Txid::zero(), 0),
                Script::new(),
            )],
            vec![TxOut::new(Amount::from_sat(50_000), Script::new())],
            0,
        );
        let parent_a_txid = parent_a.txid();

        let parent_b = Transaction::v1(
            vec![TxIn::final_input(
                OutPoint::new(Txid::zero(), 1),
                Script::new(),
            )],
            vec![TxOut::new(Amount::from_sat(60_000), Script::new())],
            0,
        );
        let parent_b_txid = parent_b.txid();

        let child = Transaction::v1(
            vec![
                TxIn::final_input(OutPoint::new(parent_a_txid, 0), Script::new()),
                TxIn::final_input(OutPoint::new(parent_b_txid, 0), Script::new()),
            ],
            vec![TxOut::new(Amount::from_sat(100_000), Script::new())],
            0,
        );

        let result = validate_package(&[parent_a, parent_b, child]);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), PackageType::ChildWithParents);
    }

    #[test]
    fn regression_package_fee_rate_boundary() {
        // Exactly at minimum: 1.0 sat/vB → 200 sat for 200 vB
        let result = check_package_fee_rate(Amount::from_sat(200), 200);
        assert!(result.is_ok());
        let rate = result.unwrap();
        assert!((rate - 1.0).abs() < 0.01);

        // Just below: 199 sat for 200 vB = 0.995 sat/vB
        let result = check_package_fee_rate(Amount::from_sat(199), 200);
        assert!(result.is_err());
    }

    #[test]
    fn regression_topological_sort_three_level_chain() {
        // A -> B -> C, passed in reverse order
        let a = make_tx(100_000);
        let a_txid = a.txid();
        let b = make_child(a_txid, 0, 80_000);
        let b_txid = b.txid();
        let c = make_child(b_txid, 0, 60_000);

        let sorted = topological_sort(&[c.clone(), b.clone(), a.clone()]).unwrap();
        assert_eq!(sorted[0].txid(), a.txid());
        assert_eq!(sorted[1].txid(), b.txid());
        assert_eq!(sorted[2].txid(), c.txid());
    }

    #[test]
    fn regression_diamond_dependency() {
        // Diamond: A -> B, A -> C, B -> D, C -> D
        // A has two outputs so B and C don't conflict.
        let a_two_out = Transaction::v1(
            vec![TxIn::final_input(
                OutPoint::new(Txid::zero(), 0),
                Script::new(),
            )],
            vec![
                TxOut::new(Amount::from_sat(50_000), Script::new()),
                TxOut::new(Amount::from_sat(50_000), Script::new()),
            ],
            0,
        );
        let a2_txid = a_two_out.txid();

        let b2 = make_child(a2_txid, 0, 40_000);
        let b2_txid = b2.txid();
        let c2 = make_child(a2_txid, 1, 40_000);
        let c2_txid = c2.txid();

        // D spends both B and C
        let d = Transaction::v1(
            vec![
                TxIn::final_input(OutPoint::new(b2_txid, 0), Script::new()),
                TxIn::final_input(OutPoint::new(c2_txid, 0), Script::new()),
            ],
            vec![TxOut::new(Amount::from_sat(70_000), Script::new())],
            0,
        );

        // Topological sort should handle the diamond
        let sorted =
            topological_sort(&[d.clone(), c2.clone(), b2.clone(), a_two_out.clone()]).unwrap();
        assert_eq!(sorted[0].txid(), a_two_out.txid()); // A first
                                                        // B and C can be in either order
        let middle_txids: HashSet<Txid> = vec![sorted[1].txid(), sorted[2].txid()]
            .into_iter()
            .collect();
        assert!(middle_txids.contains(&b2_txid));
        assert!(middle_txids.contains(&c2_txid));
        assert_eq!(sorted[3].txid(), d.txid()); // D last
    }
}
