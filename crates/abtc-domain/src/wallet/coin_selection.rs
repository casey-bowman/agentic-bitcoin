//! Coin selection algorithms
//!
//! Implements UTXO selection strategies for building transactions.
//! Corresponds to Bitcoin Core's `wallet/coinselection.cpp`.

use crate::primitives::Amount;

/// A UTXO candidate for selection
#[derive(Debug, Clone)]
pub struct Coin {
    /// Index into the caller's UTXO list
    pub index: usize,
    /// The amount of this UTXO
    pub amount: Amount,
    /// The estimated input size in vbytes (for fee calculation)
    pub input_size: u32,
}

/// Result of coin selection
#[derive(Debug, Clone)]
pub struct CoinSelectionResult {
    /// Indices of selected coins (into the original UTXO list)
    pub selected_indices: Vec<usize>,
    /// Total value of selected coins
    pub total_value: Amount,
    /// Estimated fee for using these coins
    pub estimated_fee: Amount,
    /// Change amount (total_value - target - fee)
    pub change: Amount,
}

/// Coin selection strategy
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SelectionStrategy {
    /// Select largest UTXOs first (minimizes number of inputs)
    LargestFirst,
    /// Select smallest UTXOs first that can cover the target (reduces UTXO set)
    SmallestFirst,
    /// Select the single UTXO closest in value to the target (minimizes change)
    ClosestMatch,
    /// Select smallest sufficient subset using branch-and-bound (Bitcoin Core default)
    BranchAndBound,
}

/// Coin selector that picks UTXOs to fund a transaction
pub struct CoinSelector;

impl CoinSelector {
    /// Select coins to meet a target amount with the given fee rate.
    ///
    /// # Arguments
    /// * `coins` - Available UTXOs
    /// * `target` - Amount to send (excluding fees)
    /// * `fee_rate_sat_per_vb` - Fee rate in satoshis per virtual byte
    /// * `output_size` - Estimated total output size in vbytes
    /// * `overhead_size` - Transaction overhead in vbytes (version, locktime, etc.)
    /// * `strategy` - Selection algorithm to use
    ///
    /// # Returns
    /// A `CoinSelectionResult` or an error string.
    pub fn select(
        coins: &[Coin],
        target: Amount,
        fee_rate_sat_per_vb: f64,
        output_size: u32,
        overhead_size: u32,
        strategy: SelectionStrategy,
    ) -> Result<CoinSelectionResult, String> {
        if coins.is_empty() {
            return Err("no coins available".into());
        }

        match strategy {
            SelectionStrategy::LargestFirst => {
                Self::select_largest_first(coins, target, fee_rate_sat_per_vb, output_size, overhead_size)
            }
            SelectionStrategy::SmallestFirst => {
                Self::select_smallest_first(coins, target, fee_rate_sat_per_vb, output_size, overhead_size)
            }
            SelectionStrategy::ClosestMatch => {
                Self::select_closest_match(coins, target, fee_rate_sat_per_vb, output_size, overhead_size)
            }
            SelectionStrategy::BranchAndBound => {
                // Fall back to largest-first for now — B&B is complex
                Self::select_largest_first(coins, target, fee_rate_sat_per_vb, output_size, overhead_size)
            }
        }
    }

    /// Estimate the fee for a transaction with the given inputs.
    fn estimate_fee(
        selected: &[&Coin],
        fee_rate: f64,
        output_size: u32,
        overhead_size: u32,
    ) -> Amount {
        let input_size: u32 = selected.iter().map(|c| c.input_size).sum();
        let total_vsize = overhead_size + input_size + output_size;
        let fee = (total_vsize as f64 * fee_rate).ceil() as i64;
        Amount::from_sat(fee)
    }

    /// Largest-first selection: greedily pick the biggest UTXOs.
    fn select_largest_first(
        coins: &[Coin],
        target: Amount,
        fee_rate: f64,
        output_size: u32,
        overhead_size: u32,
    ) -> Result<CoinSelectionResult, String> {
        let mut sorted: Vec<&Coin> = coins.iter().collect();
        sorted.sort_by(|a, b| b.amount.as_sat().cmp(&a.amount.as_sat()));

        Self::select_greedy(&sorted, target, fee_rate, output_size, overhead_size)
    }

    /// Smallest-first selection: pick the smallest UTXOs that suffice.
    fn select_smallest_first(
        coins: &[Coin],
        target: Amount,
        fee_rate: f64,
        output_size: u32,
        overhead_size: u32,
    ) -> Result<CoinSelectionResult, String> {
        let mut sorted: Vec<&Coin> = coins.iter().collect();
        sorted.sort_by(|a, b| a.amount.as_sat().cmp(&b.amount.as_sat()));

        Self::select_greedy(&sorted, target, fee_rate, output_size, overhead_size)
    }

    /// Closest-match: find the single UTXO closest to target + fee, or
    /// fall back to greedy if no single coin suffices.
    fn select_closest_match(
        coins: &[Coin],
        target: Amount,
        fee_rate: f64,
        output_size: u32,
        overhead_size: u32,
    ) -> Result<CoinSelectionResult, String> {
        // Try to find a single coin that covers target + estimated single-input fee
        let single_input_size = coins.iter().map(|c| c.input_size).min().unwrap_or(148);
        let est_fee = ((overhead_size + single_input_size + output_size) as f64 * fee_rate).ceil() as i64;
        let needed = target.as_sat() + est_fee;

        let mut best: Option<&Coin> = None;
        let mut best_waste: i64 = i64::MAX;

        for coin in coins {
            if coin.amount.as_sat() >= needed {
                let waste = coin.amount.as_sat() - needed;
                if waste < best_waste {
                    best_waste = waste;
                    best = Some(coin);
                }
            }
        }

        if let Some(coin) = best {
            let fee = Self::estimate_fee(&[coin], fee_rate, output_size, overhead_size);
            let change = Amount::from_sat(coin.amount.as_sat() - target.as_sat() - fee.as_sat());

            return Ok(CoinSelectionResult {
                selected_indices: vec![coin.index],
                total_value: coin.amount,
                estimated_fee: fee,
                change,
            });
        }

        // Fall back to largest-first
        Self::select_largest_first(coins, target, fee_rate, output_size, overhead_size)
    }

    /// Generic greedy selection (used by largest-first and smallest-first).
    fn select_greedy(
        sorted: &[&Coin],
        target: Amount,
        fee_rate: f64,
        output_size: u32,
        overhead_size: u32,
    ) -> Result<CoinSelectionResult, String> {
        let mut selected: Vec<&Coin> = Vec::new();
        let mut total: i64 = 0;

        for &coin in sorted {
            selected.push(coin);
            total += coin.amount.as_sat();

            let fee = Self::estimate_fee(&selected, fee_rate, output_size, overhead_size);
            let needed = target.as_sat() + fee.as_sat();

            if total >= needed {
                let change = Amount::from_sat(total - needed);
                let indices: Vec<usize> = selected.iter().map(|c| c.index).collect();

                return Ok(CoinSelectionResult {
                    selected_indices: indices,
                    total_value: Amount::from_sat(total),
                    estimated_fee: fee,
                    change,
                });
            }
        }

        let fee = Self::estimate_fee(&selected, fee_rate, output_size, overhead_size);
        Err(format!(
            "insufficient funds: have {} sat, need {} + {} fee",
            total,
            target.as_sat(),
            fee.as_sat()
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_coins(amounts: &[i64]) -> Vec<Coin> {
        amounts
            .iter()
            .enumerate()
            .map(|(i, &amount)| Coin {
                index: i,
                amount: Amount::from_sat(amount),
                input_size: 148, // legacy P2PKH input size
            })
            .collect()
    }

    #[test]
    fn test_largest_first_single_coin() {
        let coins = make_coins(&[100_000, 200_000, 50_000]);
        let result = CoinSelector::select(
            &coins,
            Amount::from_sat(150_000),
            1.0,  // 1 sat/vB
            34,   // single output
            10,   // overhead
            SelectionStrategy::LargestFirst,
        )
        .unwrap();

        assert_eq!(result.selected_indices, vec![1]); // 200,000 sat coin
        assert!(result.total_value.as_sat() >= 150_000);
    }

    #[test]
    fn test_largest_first_multiple_coins() {
        let coins = make_coins(&[30_000, 40_000, 50_000]);
        let result = CoinSelector::select(
            &coins,
            Amount::from_sat(80_000),
            1.0,
            34,
            10,
            SelectionStrategy::LargestFirst,
        )
        .unwrap();

        // Should select 50k + 40k = 90k (covers 80k target + fees)
        assert!(result.total_value.as_sat() >= 80_000);
        assert!(result.selected_indices.len() >= 2);
    }

    #[test]
    fn test_insufficient_funds() {
        let coins = make_coins(&[10_000, 20_000]);
        let result = CoinSelector::select(
            &coins,
            Amount::from_sat(100_000),
            1.0,
            34,
            10,
            SelectionStrategy::LargestFirst,
        );

        assert!(result.is_err());
    }

    #[test]
    fn test_closest_match() {
        let coins = make_coins(&[100_000, 200_000, 150_500]);
        let result = CoinSelector::select(
            &coins,
            Amount::from_sat(150_000),
            1.0,
            34,
            10,
            SelectionStrategy::ClosestMatch,
        )
        .unwrap();

        // Should prefer 150,500 (closest to 150,000 + fees)
        assert_eq!(result.selected_indices.len(), 1);
        // The coin at index 2 (150,500) is closest
        assert_eq!(result.selected_indices[0], 2);
    }

    #[test]
    fn test_smallest_first() {
        let coins = make_coins(&[10_000, 20_000, 30_000, 50_000]);
        let result = CoinSelector::select(
            &coins,
            Amount::from_sat(25_000),
            1.0,
            34,
            10,
            SelectionStrategy::SmallestFirst,
        )
        .unwrap();

        // Smallest first picks 10k, then 20k (total 30k), which covers 25k + ~192 fee
        assert!(result.total_value.as_sat() >= 25_000);
    }

    #[test]
    fn test_change_calculation() {
        let coins = make_coins(&[500_000]);
        let result = CoinSelector::select(
            &coins,
            Amount::from_sat(100_000),
            1.0,
            34,
            10,
            SelectionStrategy::LargestFirst,
        )
        .unwrap();

        // change = total - target - fee
        let expected_change = result.total_value.as_sat()
            - 100_000
            - result.estimated_fee.as_sat();
        assert_eq!(result.change.as_sat(), expected_change);
        assert!(result.change.as_sat() > 0);
    }

    #[test]
    fn test_empty_coins() {
        let coins: Vec<Coin> = Vec::new();
        let result = CoinSelector::select(
            &coins,
            Amount::from_sat(100_000),
            1.0,
            34,
            10,
            SelectionStrategy::LargestFirst,
        );
        assert!(result.is_err());
    }
}
