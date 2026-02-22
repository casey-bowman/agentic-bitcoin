//! Replace-by-Fee (BIP125) policy
//!
//! BIP125 allows an unconfirmed transaction to be replaced by a new transaction
//! that spends one or more of the same inputs, provided the replacement pays
//! a higher fee rate and absolute fee.
//!
//! See: <https://github.com/bitcoin/bips/blob/master/bip-0125.mediawiki>

use crate::primitives::{Amount, Sequence, Transaction, Txid};

/// Whether a transaction signals RBF opt-in.
///
/// BIP125 rule #1: The original transaction signals replaceability by having
/// at least one input with nSequence < 0xFFFFFFFE.
pub trait SignalsRbf {
    /// Returns true if this transaction signals opt-in RBF.
    fn signals_rbf(&self) -> bool;
}

impl SignalsRbf for Transaction {
    fn signals_rbf(&self) -> bool {
        self.inputs
            .iter()
            .any(|input| input.sequence < Sequence::MAX_NONFINAL)
    }
}

/// Errors from RBF policy checks
#[derive(Debug, Clone, PartialEq)]
pub enum RbfError {
    /// The original transaction does not signal RBF
    NotSignaling(Txid),
    /// The replacement pays an insufficient absolute fee
    /// (must be higher than the sum of fees of all replaced transactions)
    InsufficientFee { required: Amount, provided: Amount },
    /// The replacement fee rate is too low
    /// (must be higher than the original's fee rate)
    InsufficientFeeRate {
        original_rate: f64,
        replacement_rate: f64,
    },
    /// The replacement must pay for its own additional bandwidth
    /// (incremental relay fee: at least min_relay_fee * replacement_size)
    InsufficientRelay { required: Amount, provided: Amount },
    /// Too many original transactions would be evicted
    /// (BIP125 rule #5: max 100 replaced transactions)
    TooManyReplacements { count: usize, max: usize },
    /// Replacement creates new unconfirmed inputs
    /// (BIP125 rule #2: replacement must not introduce new unconfirmed parents)
    NewUnconfirmedInputs,
}

impl std::fmt::Display for RbfError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RbfError::NotSignaling(txid) => {
                write!(f, "transaction {} does not signal RBF", txid)
            }
            RbfError::InsufficientFee { required, provided } => {
                write!(
                    f,
                    "insufficient replacement fee: need {} sat, got {} sat",
                    required.as_sat(),
                    provided.as_sat()
                )
            }
            RbfError::InsufficientFeeRate {
                original_rate,
                replacement_rate,
            } => {
                write!(
                    f,
                    "insufficient fee rate: original {:.2} sat/vB, replacement {:.2} sat/vB",
                    original_rate, replacement_rate
                )
            }
            RbfError::InsufficientRelay { required, provided } => {
                write!(
                    f,
                    "insufficient relay fee: need {} sat, got {} sat",
                    required.as_sat(),
                    provided.as_sat()
                )
            }
            RbfError::TooManyReplacements { count, max } => {
                write!(
                    f,
                    "too many potential replacements: {} (max {})",
                    count, max
                )
            }
            RbfError::NewUnconfirmedInputs => {
                write!(f, "replacement introduces new unconfirmed inputs")
            }
        }
    }
}

impl std::error::Error for RbfError {}

/// Maximum number of transactions that can be replaced at once (BIP125 rule #5)
pub const MAX_REPLACEMENT_COUNT: usize = 100;

/// Minimum incremental relay fee rate (sat/vB)
pub const MIN_INCREMENTAL_RELAY_FEE: f64 = 1.0;

/// RBF policy checker
pub struct RbfPolicy;

impl RbfPolicy {
    /// Check whether a replacement transaction satisfies BIP125 rules.
    ///
    /// # Arguments
    /// * `replacement` - The new transaction attempting to replace
    /// * `replacement_fee` - Fee of the replacement transaction
    /// * `replacement_size` - Virtual size of the replacement transaction
    /// * `originals` - The original transactions being replaced, with their fees and sizes
    /// * `original_descendant_count` - Total number of transactions being evicted (originals + their descendants)
    ///
    /// # Returns
    /// Ok(()) if the replacement is valid, or an RbfError explaining why not.
    pub fn check_replacement(
        replacement_fee: Amount,
        replacement_size: usize,
        originals: &[(Txid, Amount, usize, bool)], // (txid, fee, size, signals_rbf)
        original_descendant_count: usize,
    ) -> Result<(), RbfError> {
        // Rule #1: All original transactions must signal RBF
        for (txid, _, _, signals) in originals {
            if !signals {
                return Err(RbfError::NotSignaling(*txid));
            }
        }

        // Rule #5: Can't evict more than MAX_REPLACEMENT_COUNT transactions
        if original_descendant_count > MAX_REPLACEMENT_COUNT {
            return Err(RbfError::TooManyReplacements {
                count: original_descendant_count,
                max: MAX_REPLACEMENT_COUNT,
            });
        }

        // Rule #3: Replacement must pay higher absolute fee than sum of all replaced fees
        let total_original_fee: i64 = originals.iter().map(|(_, fee, _, _)| fee.as_sat()).sum();
        if replacement_fee.as_sat() <= total_original_fee {
            return Err(RbfError::InsufficientFee {
                required: Amount::from_sat(total_original_fee + 1),
                provided: replacement_fee,
            });
        }

        // Rule #4: Replacement must pay for its own relay bandwidth
        // The additional fee must be at least min_relay_fee * replacement_vsize
        let incremental_fee = (replacement_size as f64 * MIN_INCREMENTAL_RELAY_FEE).ceil() as i64;
        let fee_increase = replacement_fee.as_sat() - total_original_fee;
        if fee_increase < incremental_fee {
            return Err(RbfError::InsufficientRelay {
                required: Amount::from_sat(incremental_fee),
                provided: Amount::from_sat(fee_increase),
            });
        }

        // Rule #6: Replacement fee rate must be higher than every original's fee rate
        for (_, orig_fee, orig_size, _) in originals {
            let orig_rate = orig_fee.as_sat() as f64 / (*orig_size).max(1) as f64;
            let repl_rate = replacement_fee.as_sat() as f64 / replacement_size.max(1) as f64;
            if repl_rate <= orig_rate {
                return Err(RbfError::InsufficientFeeRate {
                    original_rate: orig_rate,
                    replacement_rate: repl_rate,
                });
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::primitives::{OutPoint, TxIn, TxOut};
    use crate::script::Script;

    fn make_rbf_tx() -> Transaction {
        let input = TxIn::new(
            OutPoint::new(Txid::zero(), 0),
            Script::new(),
            Sequence::MAX_NONFINAL - 1, // Signals RBF
        );
        let output = TxOut::new(Amount::from_sat(50_000), Script::new());
        Transaction::new(2, vec![input], vec![output], 0)
    }

    fn make_final_tx() -> Transaction {
        let input = TxIn::final_input(OutPoint::new(Txid::zero(), 0), Script::new());
        let output = TxOut::new(Amount::from_sat(50_000), Script::new());
        Transaction::new(2, vec![input], vec![output], 0)
    }

    #[test]
    fn test_signals_rbf() {
        let rbf_tx = make_rbf_tx();
        assert!(rbf_tx.signals_rbf());

        let final_tx = make_final_tx();
        assert!(!final_tx.signals_rbf());
    }

    #[test]
    fn test_replacement_valid() {
        let originals = vec![(
            Txid::zero(),
            Amount::from_sat(1000), // original fee
            200,                    // original size
            true,                   // signals RBF
        )];

        let result = RbfPolicy::check_replacement(
            Amount::from_sat(2000), // higher fee
            200,                    // same size
            &originals,
            1, // 1 transaction evicted
        );

        assert!(result.is_ok());
    }

    #[test]
    fn test_replacement_insufficient_fee() {
        let originals = vec![(Txid::zero(), Amount::from_sat(1000), 200, true)];

        let result = RbfPolicy::check_replacement(
            Amount::from_sat(500), // lower fee — should fail
            200,
            &originals,
            1,
        );

        assert!(matches!(result, Err(RbfError::InsufficientFee { .. })));
    }

    #[test]
    fn test_replacement_not_signaling() {
        let originals = vec![(
            Txid::zero(),
            Amount::from_sat(1000),
            200,
            false, // NOT signaling
        )];

        let result = RbfPolicy::check_replacement(Amount::from_sat(2000), 200, &originals, 1);

        assert!(matches!(result, Err(RbfError::NotSignaling(_))));
    }

    #[test]
    fn test_too_many_replacements() {
        let originals = vec![(Txid::zero(), Amount::from_sat(1000), 200, true)];

        let result = RbfPolicy::check_replacement(
            Amount::from_sat(2000),
            200,
            &originals,
            101, // over limit
        );

        assert!(matches!(result, Err(RbfError::TooManyReplacements { .. })));
    }

    #[test]
    fn test_replacement_multiple_originals() {
        // Replacing 3 transactions, total original fees = 3000
        let originals = vec![
            (Txid::zero(), Amount::from_sat(1000), 200, true),
            (Txid::zero(), Amount::from_sat(1000), 150, true),
            (Txid::zero(), Amount::from_sat(1000), 180, true),
        ];

        // Replacement fee must exceed 3000
        let result = RbfPolicy::check_replacement(Amount::from_sat(5000), 250, &originals, 3);

        assert!(result.is_ok());
    }

    #[test]
    fn test_replacement_fee_rate_check() {
        let originals = vec![(
            Txid::zero(),
            Amount::from_sat(1000), // 1000/200 = 5 sat/vB
            200,
            true,
        )];

        // Higher abs fee but lower fee rate (2000/500 = 4 sat/vB < 5)
        let result = RbfPolicy::check_replacement(Amount::from_sat(2000), 500, &originals, 1);

        assert!(matches!(result, Err(RbfError::InsufficientFeeRate { .. })));
    }
}
