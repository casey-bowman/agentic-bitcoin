//! Mempool package limits and CPFP (Child Pays for Parent) support
//!
//! Bitcoin Core enforces ancestor and descendant limits to prevent
//! transaction graph DoS attacks. These limits correspond to
//! Bitcoin Core's `DEFAULT_ANCESTOR_LIMIT`, `DEFAULT_DESCENDANT_LIMIT`, etc.
//!
//! CPFP allows a child transaction with a high fee to "pay for" a low-fee
//! parent, making both economically rational to mine together.

use crate::primitives::{Amount, Txid};

/// Default maximum number of ancestors (including self) — Bitcoin Core default: 25
pub const DEFAULT_ANCESTOR_LIMIT: u32 = 25;

/// Default maximum number of descendants (including self) — Bitcoin Core default: 25
pub const DEFAULT_DESCENDANT_LIMIT: u32 = 25;

/// Default maximum ancestor package size in virtual bytes — Bitcoin Core default: 101,000
pub const DEFAULT_ANCESTOR_SIZE_LIMIT: u32 = 101_000;

/// Default maximum descendant package size in virtual bytes — Bitcoin Core default: 101,000
pub const DEFAULT_DESCENDANT_SIZE_LIMIT: u32 = 101_000;

/// Dust threshold in satoshis — outputs below this are non-standard
pub const DUST_THRESHOLD: i64 = 546;

/// Minimum relay fee rate in sat/vB
pub const MIN_RELAY_FEE_RATE: f64 = 1.0;

/// Maximum standard transaction weight (400,000 weight units = 100,000 vbytes)
pub const MAX_STANDARD_TX_WEIGHT: u32 = 400_000;

/// Maximum number of sigops in a standard transaction
pub const MAX_STANDARD_TX_SIGOPS: u32 = 16_000;

/// Configurable mempool package limits
#[derive(Debug, Clone)]
pub struct MempoolLimits {
    /// Maximum ancestor count (including the transaction itself)
    pub max_ancestor_count: u32,
    /// Maximum descendant count (including the transaction itself)
    pub max_descendant_count: u32,
    /// Maximum total ancestor package size in vbytes
    pub max_ancestor_size: u32,
    /// Maximum total descendant package size in vbytes
    pub max_descendant_size: u32,
}

impl Default for MempoolLimits {
    fn default() -> Self {
        MempoolLimits {
            max_ancestor_count: DEFAULT_ANCESTOR_LIMIT,
            max_descendant_count: DEFAULT_DESCENDANT_LIMIT,
            max_ancestor_size: DEFAULT_ANCESTOR_SIZE_LIMIT,
            max_descendant_size: DEFAULT_DESCENDANT_SIZE_LIMIT,
        }
    }
}

/// Errors from package limit checks
#[derive(Debug, Clone, PartialEq)]
pub enum LimitError {
    /// Too many ancestors
    TooManyAncestors { count: u32, limit: u32 },
    /// Too many descendants
    TooManyDescendants { count: u32, limit: u32 },
    /// Ancestor package too large
    AncestorSizeTooLarge { size: u32, limit: u32 },
    /// Descendant package too large
    DescendantSizeTooLarge { size: u32, limit: u32 },
    /// Transaction output is dust
    DustOutput { index: usize, value: i64 },
    /// Transaction exceeds maximum weight
    OversizedTransaction { weight: u32, max: u32 },
    /// Fee rate below minimum relay fee
    BelowMinRelayFee { fee_rate: f64, min_rate: f64 },
}

impl std::fmt::Display for LimitError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LimitError::TooManyAncestors { count, limit } => {
                write!(f, "too many ancestors: {} (limit {})", count, limit)
            }
            LimitError::TooManyDescendants { count, limit } => {
                write!(f, "too many descendants: {} (limit {})", count, limit)
            }
            LimitError::AncestorSizeTooLarge { size, limit } => {
                write!(
                    f,
                    "ancestor package too large: {} vB (limit {} vB)",
                    size, limit
                )
            }
            LimitError::DescendantSizeTooLarge { size, limit } => {
                write!(
                    f,
                    "descendant package too large: {} vB (limit {} vB)",
                    size, limit
                )
            }
            LimitError::DustOutput { index, value } => {
                write!(
                    f,
                    "output {} is dust ({} sat < {} sat)",
                    index, value, DUST_THRESHOLD
                )
            }
            LimitError::OversizedTransaction { weight, max } => {
                write!(f, "transaction too large: {} weight (max {})", weight, max)
            }
            LimitError::BelowMinRelayFee { fee_rate, min_rate } => {
                write!(
                    f,
                    "fee rate too low: {:.2} sat/vB (min {:.2})",
                    fee_rate, min_rate
                )
            }
        }
    }
}

impl std::error::Error for LimitError {}

/// Information about a transaction's package (ancestors + descendants)
#[derive(Debug, Clone)]
pub struct PackageInfo {
    /// Transaction ID
    pub txid: Txid,
    /// Transaction virtual size
    pub vsize: u32,
    /// Transaction fee
    pub fee: Amount,
    /// Number of ancestors (including self)
    pub ancestor_count: u32,
    /// Total ancestor package size in vbytes (including self)
    pub ancestor_size: u32,
    /// Total ancestor package fee (including self)
    pub ancestor_fee: Amount,
    /// Number of descendants (including self)
    pub descendant_count: u32,
    /// Total descendant package size in vbytes (including self)
    pub descendant_size: u32,
    /// Total descendant package fee (including self)
    pub descendant_fee: Amount,
}

impl PackageInfo {
    /// Create package info for a transaction with no ancestors or descendants
    pub fn new(txid: Txid, vsize: u32, fee: Amount) -> Self {
        PackageInfo {
            txid,
            vsize,
            fee,
            ancestor_count: 1,
            ancestor_size: vsize,
            ancestor_fee: fee,
            descendant_count: 1,
            descendant_size: vsize,
            descendant_fee: fee,
        }
    }

    /// Individual fee rate (sat/vB)
    pub fn fee_rate(&self) -> f64 {
        self.fee.as_sat() as f64 / self.vsize.max(1) as f64
    }

    /// Ancestor fee rate (sat/vB) — used for CPFP mining priority
    ///
    /// This is the key metric for CPFP: if a child has a high fee,
    /// the ancestor_fee_rate of the child will be high, pulling
    /// the parent into the block even if the parent's individual
    /// fee rate is low.
    pub fn ancestor_fee_rate(&self) -> f64 {
        self.ancestor_fee.as_sat() as f64 / self.ancestor_size.max(1) as f64
    }

    /// Descendant fee rate (sat/vB) — used for eviction
    ///
    /// When evicting transactions, we consider the descendant fee rate.
    /// A low-fee transaction with high-fee descendants should be kept.
    pub fn descendant_fee_rate(&self) -> f64 {
        self.descendant_fee.as_sat() as f64 / self.descendant_size.max(1) as f64
    }
}

impl MempoolLimits {
    /// Check whether adding a transaction would violate ancestor limits.
    ///
    /// # Arguments
    /// * `ancestor_count` - Current ancestor count (including the new tx)
    /// * `ancestor_size` - Current ancestor package size (including the new tx)
    pub fn check_ancestor_limits(
        &self,
        ancestor_count: u32,
        ancestor_size: u32,
    ) -> Result<(), LimitError> {
        if ancestor_count > self.max_ancestor_count {
            return Err(LimitError::TooManyAncestors {
                count: ancestor_count,
                limit: self.max_ancestor_count,
            });
        }

        if ancestor_size > self.max_ancestor_size {
            return Err(LimitError::AncestorSizeTooLarge {
                size: ancestor_size,
                limit: self.max_ancestor_size,
            });
        }

        Ok(())
    }

    /// Check whether adding a transaction would violate descendant limits
    /// on any of its ancestors.
    ///
    /// # Arguments
    /// * `descendant_count` - Worst-case descendant count across all ancestors
    /// * `descendant_size` - Worst-case descendant package size across all ancestors
    pub fn check_descendant_limits(
        &self,
        descendant_count: u32,
        descendant_size: u32,
    ) -> Result<(), LimitError> {
        if descendant_count > self.max_descendant_count {
            return Err(LimitError::TooManyDescendants {
                count: descendant_count,
                limit: self.max_descendant_count,
            });
        }

        if descendant_size > self.max_descendant_size {
            return Err(LimitError::DescendantSizeTooLarge {
                size: descendant_size,
                limit: self.max_descendant_size,
            });
        }

        Ok(())
    }

    /// Check standard transaction policy rules (not consensus).
    ///
    /// # Arguments
    /// * `tx_weight` - Transaction weight in weight units
    /// * `fee` - Transaction fee
    /// * `vsize` - Transaction virtual size
    /// * `output_values` - Values of each output (for dust check)
    pub fn check_standard_tx(
        tx_weight: u32,
        fee: Amount,
        vsize: u32,
        output_values: &[i64],
    ) -> Result<(), LimitError> {
        // Check transaction weight
        if tx_weight > MAX_STANDARD_TX_WEIGHT {
            return Err(LimitError::OversizedTransaction {
                weight: tx_weight,
                max: MAX_STANDARD_TX_WEIGHT,
            });
        }

        // Check minimum relay fee
        let fee_rate = fee.as_sat() as f64 / vsize.max(1) as f64;
        if fee_rate < MIN_RELAY_FEE_RATE {
            return Err(LimitError::BelowMinRelayFee {
                fee_rate,
                min_rate: MIN_RELAY_FEE_RATE,
            });
        }

        // Check dust outputs
        for (i, &value) in output_values.iter().enumerate() {
            if value > 0 && value < DUST_THRESHOLD {
                return Err(LimitError::DustOutput { index: i, value });
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_limits() {
        let limits = MempoolLimits::default();
        assert_eq!(limits.max_ancestor_count, 25);
        assert_eq!(limits.max_descendant_count, 25);
        assert_eq!(limits.max_ancestor_size, 101_000);
        assert_eq!(limits.max_descendant_size, 101_000);
    }

    #[test]
    fn test_ancestor_count_ok() {
        let limits = MempoolLimits::default();
        assert!(limits.check_ancestor_limits(10, 5000).is_ok());
    }

    #[test]
    fn test_ancestor_count_exceeded() {
        let limits = MempoolLimits::default();
        let result = limits.check_ancestor_limits(26, 5000);
        assert!(matches!(
            result,
            Err(LimitError::TooManyAncestors {
                count: 26,
                limit: 25
            })
        ));
    }

    #[test]
    fn test_ancestor_size_exceeded() {
        let limits = MempoolLimits::default();
        let result = limits.check_ancestor_limits(5, 102_000);
        assert!(matches!(
            result,
            Err(LimitError::AncestorSizeTooLarge { .. })
        ));
    }

    #[test]
    fn test_descendant_count_exceeded() {
        let limits = MempoolLimits::default();
        let result = limits.check_descendant_limits(26, 5000);
        assert!(matches!(result, Err(LimitError::TooManyDescendants { .. })));
    }

    #[test]
    fn test_descendant_size_exceeded() {
        let limits = MempoolLimits::default();
        let result = limits.check_descendant_limits(5, 102_000);
        assert!(matches!(
            result,
            Err(LimitError::DescendantSizeTooLarge { .. })
        ));
    }

    #[test]
    fn test_package_info_fee_rates() {
        let pkg = PackageInfo {
            txid: Txid::zero(),
            vsize: 200,
            fee: Amount::from_sat(2000),
            ancestor_count: 3,
            ancestor_size: 600,
            ancestor_fee: Amount::from_sat(3000),
            descendant_count: 2,
            descendant_size: 400,
            descendant_fee: Amount::from_sat(5000),
        };

        assert!((pkg.fee_rate() - 10.0).abs() < 0.01);
        assert!((pkg.ancestor_fee_rate() - 5.0).abs() < 0.01);
        assert!((pkg.descendant_fee_rate() - 12.5).abs() < 0.01);
    }

    #[test]
    fn test_cpfp_scenario() {
        // Parent: low fee rate (1 sat/vB)
        let parent = PackageInfo::new(Txid::zero(), 200, Amount::from_sat(200));
        assert!((parent.fee_rate() - 1.0).abs() < 0.01);

        // Child: high fee rate, ancestor fee rate pulls parent along
        let child = PackageInfo {
            txid: Txid::zero(),
            vsize: 150,
            fee: Amount::from_sat(3000),
            ancestor_count: 2,
            ancestor_size: 350,                   // 200 + 150
            ancestor_fee: Amount::from_sat(3200), // 200 + 3000
            descendant_count: 1,
            descendant_size: 150,
            descendant_fee: Amount::from_sat(3000),
        };

        // Child's individual fee rate
        assert!((child.fee_rate() - 20.0).abs() < 0.01);
        // Ancestor fee rate (CPFP metric) = 3200/350 ≈ 9.14 sat/vB
        assert!(child.ancestor_fee_rate() > 9.0);
        // This is much higher than the parent's individual 1 sat/vB,
        // so the miner would include both parent and child together.
    }

    #[test]
    fn test_standard_tx_ok() {
        let result =
            MempoolLimits::check_standard_tx(1000, Amount::from_sat(500), 250, &[50_000, 100_000]);
        assert!(result.is_ok());
    }

    #[test]
    fn test_oversized_transaction() {
        let result = MempoolLimits::check_standard_tx(
            500_000, // exceeds 400,000
            Amount::from_sat(5000),
            125_000,
            &[50_000],
        );
        assert!(matches!(
            result,
            Err(LimitError::OversizedTransaction { .. })
        ));
    }

    #[test]
    fn test_dust_output() {
        let result = MempoolLimits::check_standard_tx(
            1000,
            Amount::from_sat(500),
            250,
            &[50_000, 100], // 100 sat is dust
        );
        assert!(matches!(
            result,
            Err(LimitError::DustOutput {
                index: 1,
                value: 100
            })
        ));
    }

    #[test]
    fn test_below_min_relay_fee() {
        let result = MempoolLimits::check_standard_tx(
            1000,
            Amount::from_sat(10), // 10/250 = 0.04 sat/vB, below 1.0
            250,
            &[50_000],
        );
        assert!(matches!(result, Err(LimitError::BelowMinRelayFee { .. })));
    }
}
