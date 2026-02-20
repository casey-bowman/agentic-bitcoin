//! Bitcoin amount and money types
//!
//! Represents satoshi values and money range validation according to Bitcoin consensus rules.

use std::fmt;

/// One Bitcoin in satoshis
pub const COIN: i64 = 100_000_000;

/// Maximum Bitcoin supply (21 million BTC)
pub const MAX_MONEY: i64 = 21_000_000 * COIN;

/// Bitcoin amount in satoshis
///
/// Represents an amount of Bitcoin as a signed 64-bit integer counting satoshis.
/// Negative values are sometimes used in transaction outputs during validation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Amount(i64);

impl Amount {
    /// Create an amount from satoshis
    pub const fn from_sat(satoshis: i64) -> Self {
        Amount(satoshis)
    }

    /// Get satoshi value
    pub const fn as_sat(&self) -> i64 {
        self.0
    }

    /// Create amount from BTC value
    pub fn from_btc(btc: f64) -> Option<Self> {
        let sat = (btc * COIN as f64) as i64;
        if (sat as f64 - btc * COIN as f64).abs() < 1.0 {
            Some(Amount(sat))
        } else {
            None
        }
    }

    /// Get amount as BTC value
    pub fn as_btc(&self) -> f64 {
        self.0 as f64 / COIN as f64
    }

    /// Check if amount is in valid money range
    pub fn is_money_range(&self) -> bool {
        is_money_range(self.0)
    }
}

impl fmt::Display for Amount {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} sat", self.0)
    }
}

impl std::ops::Add for Amount {
    type Output = Amount;

    fn add(self, other: Amount) -> Amount {
        Amount(self.0 + other.0)
    }
}

impl std::ops::Sub for Amount {
    type Output = Amount;

    fn sub(self, other: Amount) -> Amount {
        Amount(self.0 - other.0)
    }
}

impl std::ops::Mul<i64> for Amount {
    type Output = Amount;

    fn mul(self, other: i64) -> Amount {
        Amount(self.0 * other)
    }
}

/// Validate that amount is within valid money range
///
/// Checks that the value is non-negative and does not exceed MAX_MONEY.
pub fn is_money_range(value: i64) -> bool {
    value >= 0 && value <= MAX_MONEY
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_amount_creation() {
        let amt = Amount::from_sat(1_000_000);
        assert_eq!(amt.as_sat(), 1_000_000);
    }

    #[test]
    fn test_amount_btc_conversion() {
        let amt = Amount::from_sat(COIN);
        assert!((amt.as_btc() - 1.0).abs() < 0.0001);
    }

    #[test]
    fn test_money_range() {
        assert!(is_money_range(0));
        assert!(is_money_range(COIN));
        assert!(is_money_range(MAX_MONEY));
        assert!(!is_money_range(-1));
        assert!(!is_money_range(MAX_MONEY + 1));
    }

    #[test]
    fn test_amount_arithmetic() {
        let a = Amount::from_sat(100);
        let b = Amount::from_sat(50);
        assert_eq!((a + b).as_sat(), 150);
        assert_eq!((a - b).as_sat(), 50);
        assert_eq!((a * 2).as_sat(), 200);
    }
}
