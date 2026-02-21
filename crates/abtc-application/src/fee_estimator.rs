//! Fee Estimation Tracker
//!
//! Tracks confirmed transaction fee rates across blocks to provide
//! `estimatesmartfee`-style predictions. This corresponds to Bitcoin Core's
//! `CBlockPolicyEstimator` in `src/policy/fees.cpp`.
//!
//! ## Design
//!
//! Every time a block is connected we record the fee rates of each confirmed
//! transaction. Fee rates are bucketed into exponential ranges and, for each
//! bucket, we track how many transactions confirmed within 1, 2, 3, … N
//! blocks of entering the mempool. When asked to estimate a fee for a target
//! confirmation window we find the lowest fee-rate bucket where at least 85%
//! of historical transactions confirmed within that window.

use abtc_domain::primitives::{Amount, Transaction};
use std::collections::VecDeque;

// ── Configuration ───────────────────────────────────────────────────

/// Maximum number of confirmation target blocks we track.
const MAX_TARGET_BLOCKS: usize = 25;

/// Number of fee-rate buckets (exponentially spaced).
const NUM_BUCKETS: usize = 40;

/// Success threshold: the fraction of transactions in a bucket that must
/// have confirmed within the target window before we consider that bucket.
const SUCCESS_THRESHOLD: f64 = 0.85;

/// Decay factor applied to old observations so that recent data weighs more.
const DECAY: f64 = 0.998;

/// Minimum fee rate (sat/vB) we will ever return.
const MIN_FEE_RATE: f64 = 1.0;

/// Maximum number of block records we keep (sliding window).
const MAX_BLOCK_HISTORY: usize = 1008; // ~1 week of blocks

// ── Types ───────────────────────────────────────────────────────────

/// Per-bucket tracking: weighted counts of observations, partitioned by
/// how many blocks until confirmation.
#[derive(Debug, Clone)]
struct Bucket {
    /// Lower bound of the fee-rate range (sat/vB).
    lower: f64,
    /// Upper bound of the fee-rate range (sat/vB).
    upper: f64,
    /// Weighted total of transactions that fell into this bucket.
    total_confirmed: f64,
    /// Weighted total of transactions that confirmed within `i+1` blocks,
    /// cumulative from index 0 upward.  `within_target[i]` = how many
    /// confirmed within `i+1` blocks.
    within_target: Vec<f64>,
}

/// Summary of a single block's confirmed fees (kept for rolling window stats).
#[derive(Debug, Clone)]
#[allow(dead_code)]
struct BlockFeeRecord {
    height: u32,
    /// Median fee rate of transactions in this block (sat/vB).
    median_fee_rate: f64,
    /// Number of non-coinbase transactions.
    tx_count: u32,
}

/// The fee estimator.
///
/// Call [`process_block`] every time a new block is connected, and
/// [`estimate_fee`] to get a fee-rate prediction for a given target.
#[derive(Debug, Clone)]
pub struct FeeEstimator {
    /// Exponentially-spaced fee-rate buckets.
    buckets: Vec<Bucket>,
    /// Rolling window of per-block fee summaries.
    block_history: VecDeque<BlockFeeRecord>,
    /// Height of the highest block we have processed.
    best_height: u32,
    /// Total number of transactions processed.
    total_txs_tracked: u64,
}

impl FeeEstimator {
    /// Create a new, empty fee estimator.
    pub fn new() -> Self {
        let buckets = Self::init_buckets();
        FeeEstimator {
            buckets,
            block_history: VecDeque::with_capacity(MAX_BLOCK_HISTORY),
            best_height: 0,
            total_txs_tracked: 0,
        }
    }

    /// Initialise exponentially-spaced fee-rate buckets.
    ///
    /// The buckets cover roughly 1 sat/vB … 10 000 sat/vB.
    fn init_buckets() -> Vec<Bucket> {
        let min_rate: f64 = 1.0;
        let max_rate: f64 = 10_000.0;
        let ratio = (max_rate / min_rate).powf(1.0 / NUM_BUCKETS as f64);

        let mut buckets = Vec::with_capacity(NUM_BUCKETS);
        let mut lower = min_rate;
        for _ in 0..NUM_BUCKETS {
            let upper = lower * ratio;
            buckets.push(Bucket {
                lower,
                upper,
                total_confirmed: 0.0,
                within_target: vec![0.0; MAX_TARGET_BLOCKS],
            });
            lower = upper;
        }
        buckets
    }

    /// Find which bucket a fee rate falls into.
    fn bucket_index(&self, fee_rate: f64) -> usize {
        for (i, bucket) in self.buckets.iter().enumerate() {
            if fee_rate < bucket.upper {
                return i;
            }
        }
        NUM_BUCKETS - 1
    }

    /// Process a newly connected block.
    ///
    /// For each non-coinbase transaction in the block, we record its fee rate
    /// and how many blocks it waited (approximated as 1 since we don't have
    /// per-transaction mempool entry times in this simplified model).
    ///
    /// `confirmed_fees` should contain `(fee_amount, tx_vsize, blocks_waited)`
    /// for each non-coinbase transaction. If `blocks_waited` is not known,
    /// pass 1 (the optimistic assumption).
    pub fn process_block(
        &mut self,
        height: u32,
        confirmed_fees: &[(Amount, usize, u32)],
    ) {
        if height <= self.best_height && self.best_height > 0 {
            return; // already processed or reorg (ignore for now)
        }

        // Decay old observations so recent data weighs more.
        for bucket in &mut self.buckets {
            bucket.total_confirmed *= DECAY;
            for wt in bucket.within_target.iter_mut() {
                *wt *= DECAY;
            }
        }

        let mut fee_rates: Vec<f64> = Vec::with_capacity(confirmed_fees.len());

        for &(fee, vsize, blocks_waited) in confirmed_fees {
            let fee_rate = fee.as_sat() as f64 / vsize.max(1) as f64;
            fee_rates.push(fee_rate);

            let idx = self.bucket_index(fee_rate);
            let bucket = &mut self.buckets[idx];
            bucket.total_confirmed += 1.0;

            // Mark it as confirmed within each target >= blocks_waited.
            let blocks_waited = (blocks_waited as usize).max(1);
            for target in (blocks_waited - 1)..MAX_TARGET_BLOCKS {
                bucket.within_target[target] += 1.0;
            }

            self.total_txs_tracked += 1;
        }

        // Compute median fee rate for this block.
        fee_rates.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        let median = if fee_rates.is_empty() {
            0.0
        } else {
            fee_rates[fee_rates.len() / 2]
        };

        let record = BlockFeeRecord {
            height,
            median_fee_rate: median,
            tx_count: confirmed_fees.len() as u32,
        };

        self.block_history.push_back(record);
        if self.block_history.len() > MAX_BLOCK_HISTORY {
            self.block_history.pop_front();
        }

        self.best_height = height;
    }

    /// Convenience: process a block given the raw transactions and a fee
    /// calculator closure.  `fee_for_tx` should return `Some((fee, vsize))`
    /// for non-coinbase transactions and `None` for coinbase.
    pub fn process_block_txs<F>(
        &mut self,
        height: u32,
        txs: &[Transaction],
        fee_for_tx: F,
    ) where
        F: Fn(&Transaction) -> Option<(Amount, usize)>,
    {
        let confirmed: Vec<(Amount, usize, u32)> = txs
            .iter()
            .filter_map(|tx| {
                fee_for_tx(tx).map(|(fee, vsize)| (fee, vsize, 1u32))
            })
            .collect();
        self.process_block(height, &confirmed);
    }

    /// Estimate the fee rate (sat/vB) needed to confirm within `target_blocks`.
    ///
    /// Returns the minimum bucket lower-bound where at least [`SUCCESS_THRESHOLD`]
    /// of tracked transactions confirmed within `target_blocks`.
    /// Falls back to the median of recent blocks if insufficient data.
    pub fn estimate_fee(&self, target_blocks: u32) -> f64 {
        let target = (target_blocks as usize).clamp(1, MAX_TARGET_BLOCKS);

        // Try bucket-based estimation.
        let mut best_rate: Option<f64> = None;

        for bucket in self.buckets.iter().rev() {
            if bucket.total_confirmed < 2.0 {
                continue; // not enough data in this bucket
            }
            let success_rate = bucket.within_target[target - 1] / bucket.total_confirmed;
            if success_rate >= SUCCESS_THRESHOLD {
                best_rate = Some(bucket.lower);
            } else {
                // Once we drop below threshold, stop — the previous bucket was the answer.
                break;
            }
        }

        if let Some(rate) = best_rate {
            return rate.max(MIN_FEE_RATE);
        }

        // Fallback: use rolling median of recent blocks.
        self.fallback_median().max(MIN_FEE_RATE)
    }

    /// Simple fallback: median of recent block medians.
    fn fallback_median(&self) -> f64 {
        if self.block_history.is_empty() {
            return MIN_FEE_RATE;
        }

        let mut medians: Vec<f64> = self
            .block_history
            .iter()
            .filter(|r| r.tx_count > 0)
            .map(|r| r.median_fee_rate)
            .collect();

        if medians.is_empty() {
            return MIN_FEE_RATE;
        }

        medians.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        medians[medians.len() / 2]
    }

    // ── Accessors ───────────────────────────────────────────────────

    /// The height of the latest block we have processed.
    pub fn best_height(&self) -> u32 {
        self.best_height
    }

    /// Total number of transactions observed.
    pub fn total_txs_tracked(&self) -> u64 {
        self.total_txs_tracked
    }

    /// Number of blocks in the rolling history window.
    pub fn block_history_len(&self) -> usize {
        self.block_history.len()
    }

    /// Get the median fee rate for the most recent block, or None if empty.
    pub fn latest_block_median(&self) -> Option<f64> {
        self.block_history.back().map(|r| r.median_fee_rate)
    }

    /// Get fee rate percentiles across the rolling window (useful for RPC).
    ///
    /// Returns (10th, 25th, 50th, 75th, 90th) percentile median fee rates.
    pub fn fee_rate_percentiles(&self) -> (f64, f64, f64, f64, f64) {
        let mut medians: Vec<f64> = self
            .block_history
            .iter()
            .filter(|r| r.tx_count > 0)
            .map(|r| r.median_fee_rate)
            .collect();

        if medians.is_empty() {
            return (MIN_FEE_RATE, MIN_FEE_RATE, MIN_FEE_RATE, MIN_FEE_RATE, MIN_FEE_RATE);
        }

        medians.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));

        let p = |pct: f64| -> f64 {
            let idx = ((medians.len() as f64 * pct) as usize).min(medians.len() - 1);
            medians[idx]
        };

        (p(0.10), p(0.25), p(0.50), p(0.75), p(0.90))
    }
}

impl Default for FeeEstimator {
    fn default() -> Self {
        Self::new()
    }
}

// ── Tests ───────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_estimator_returns_min_fee() {
        let est = FeeEstimator::new();
        let fee = est.estimate_fee(6);
        assert_eq!(fee, MIN_FEE_RATE);
    }

    #[test]
    fn test_process_single_block() {
        let mut est = FeeEstimator::new();

        // Simulate a block with 5 transactions at 10 sat/vB.
        let fees: Vec<(Amount, usize, u32)> = (0..5)
            .map(|_| (Amount::from_sat(2500), 250, 1))
            .collect();

        est.process_block(1, &fees);

        assert_eq!(est.best_height(), 1);
        assert_eq!(est.total_txs_tracked(), 5);
        assert_eq!(est.block_history_len(), 1);
    }

    #[test]
    fn test_estimate_after_many_blocks() {
        let mut est = FeeEstimator::new();

        // Feed 100 blocks each with 50 transactions at ~10 sat/vB.
        for h in 1..=100 {
            let fees: Vec<(Amount, usize, u32)> = (0..50)
                .map(|i| {
                    // Mix of fee rates: 5-15 sat/vB
                    let rate = 5.0 + (i as f64 % 11.0);
                    let vsize = 250usize;
                    let fee = (rate * vsize as f64) as i64;
                    (Amount::from_sat(fee), vsize, 1)
                })
                .collect();
            est.process_block(h, &fees);
        }

        // Estimate for 1-block confirmation should return a fee rate.
        let fee1 = est.estimate_fee(1);
        assert!(fee1 >= MIN_FEE_RATE, "fee1={}", fee1);

        // Longer targets should be equal or lower.
        let fee6 = est.estimate_fee(6);
        assert!(fee6 <= fee1, "fee6={} should be <= fee1={}", fee6, fee1);
    }

    #[test]
    fn test_duplicate_height_ignored() {
        let mut est = FeeEstimator::new();

        let fees = vec![(Amount::from_sat(2500), 250, 1)];
        est.process_block(1, &fees);
        est.process_block(1, &fees); // duplicate

        assert_eq!(est.total_txs_tracked(), 1);
        assert_eq!(est.block_history_len(), 1);
    }

    #[test]
    fn test_block_history_window() {
        let mut est = FeeEstimator::new();

        // Feed more blocks than MAX_BLOCK_HISTORY.
        for h in 1..=(MAX_BLOCK_HISTORY as u32 + 100) {
            let fees = vec![(Amount::from_sat(2500), 250, 1)];
            est.process_block(h, &fees);
        }

        assert_eq!(est.block_history_len(), MAX_BLOCK_HISTORY);
    }

    #[test]
    fn test_fee_rate_percentiles_empty() {
        let est = FeeEstimator::new();
        let (p10, _p25, p50, _p75, p90) = est.fee_rate_percentiles();
        assert_eq!(p10, MIN_FEE_RATE);
        assert_eq!(p50, MIN_FEE_RATE);
        assert_eq!(p90, MIN_FEE_RATE);
    }

    #[test]
    fn test_fee_rate_percentiles_populated() {
        let mut est = FeeEstimator::new();

        // Feed blocks with varying median fee rates.
        for h in 1..=100 {
            let rate = h as f64; // 1, 2, 3, … 100 sat/vB
            let vsize = 250;
            let fee = (rate * vsize as f64) as i64;
            est.process_block(h, &[(Amount::from_sat(fee), vsize, 1)]);
        }

        let (p10, p25, p50, p75, p90) = est.fee_rate_percentiles();
        // Rough checks: percentiles should increase.
        assert!(p10 <= p25, "p10={} p25={}", p10, p25);
        assert!(p25 <= p50, "p25={} p50={}", p25, p50);
        assert!(p50 <= p75, "p50={} p75={}", p50, p75);
        assert!(p75 <= p90, "p75={} p90={}", p75, p90);
    }

    #[test]
    fn test_latest_block_median() {
        let mut est = FeeEstimator::new();
        assert!(est.latest_block_median().is_none());

        est.process_block(1, &[(Amount::from_sat(5000), 250, 1)]);
        let median = est.latest_block_median().unwrap();
        assert!((median - 20.0).abs() < 0.01, "median={}", median);
    }

    #[test]
    fn test_process_block_txs_helper() {
        let mut est = FeeEstimator::new();

        // Create a simple transaction list.
        use abtc_domain::primitives::{OutPoint, TxIn, TxOut, Txid};
        use abtc_domain::script::Script;

        let tx = abtc_domain::primitives::Transaction::v1(
            vec![TxIn::final_input(OutPoint::new(Txid::zero(), 0), Script::new())],
            vec![TxOut::new(Amount::from_sat(49_000), Script::new())],
            0,
        );

        // Coinbase should be filtered out.
        let coinbase = abtc_domain::primitives::Transaction::v1(
            vec![TxIn::final_input(OutPoint::coinbase(), Script::new())],
            vec![TxOut::new(Amount::from_sat(50_000), Script::new())],
            0,
        );

        est.process_block_txs(1, &[coinbase, tx], |tx| {
            if tx.is_coinbase() {
                None
            } else {
                Some((Amount::from_sat(1000), 250))
            }
        });

        assert_eq!(est.total_txs_tracked(), 1); // only the non-coinbase
    }
}
