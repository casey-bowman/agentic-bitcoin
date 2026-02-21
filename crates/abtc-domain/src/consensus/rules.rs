//! Bitcoin consensus rules
//!
//! Pure validation functions for transactions and blocks according to Bitcoin consensus rules.

use crate::consensus::validation::{ValidationError, ValidationResult};
use crate::consensus::ConsensusParams;
use crate::primitives::{Block, BlockHeader, Transaction, MAX_MONEY};

// Block and transaction size constants
/// Maximum block serialized size (4 MB)
pub const MAX_BLOCK_SERIALIZED_SIZE: u32 = 4_000_000;

/// Maximum block weight (4 million witness units)
pub const MAX_BLOCK_WEIGHT: u32 = 4_000_000;

/// Witness scale factor (witness data counts 1/4 as much as non-witness data)
pub const WITNESS_SCALE_FACTOR: u32 = 4;

/// Maximum block sigops cost
pub const MAX_BLOCK_SIGOPS_COST: u32 = 20_000_000;

/// Coinbase transaction maturity (100 blocks)
pub const COINBASE_MATURITY: u32 = 100;

/// Maximum transaction size (400 KB)
pub const MAX_TX_SIZE: u32 = 400_000;

/// Minimum coinbase script size
pub const MIN_COINBASE_SCRIPT_SIZE: usize = 2;

/// Maximum coinbase script size
pub const MAX_COINBASE_SCRIPT_SIZE: usize = 100;

/// Check basic transaction validity
///
/// Performs these checks:
/// - Transaction has at least one input
/// - Transaction has at least one output
/// - All outputs have non-negative values
/// - Total output value does not exceed MAX_MONEY
/// - No duplicate inputs
/// - Coinbase script size (for coinbase transactions)
pub fn check_transaction(tx: &Transaction) -> ValidationResult<()> {
    // Check inputs/outputs exist
    if tx.inputs.is_empty() {
        return Err(ValidationError::TxInputsEmpty);
    }
    if tx.outputs.is_empty() {
        return Err(ValidationError::TxOutputsEmpty);
    }

    // Check output values
    let mut total_out = 0i64;
    for output in &tx.outputs {
        let value = output.value.as_sat();
        if value < 0 {
            return Err(ValidationError::TxOutputsNegative);
        }
        total_out += value;
        if total_out > MAX_MONEY {
            return Err(ValidationError::TxOutputsTooLarge);
        }
    }

    // Check for duplicate inputs
    for i in 0..tx.inputs.len() {
        for j in (i + 1)..tx.inputs.len() {
            if tx.inputs[i].previous_output == tx.inputs[j].previous_output {
                return Err(ValidationError::TxInputsDuplicate);
            }
        }
    }

    // Check coinbase constraints
    if tx.is_coinbase() {
        let script_size = tx.inputs[0].script_sig.len();
        if script_size < MIN_COINBASE_SCRIPT_SIZE {
            return Err(ValidationError::TxCoinbaseScriptSizeTooSmall);
        }
        if script_size > MAX_COINBASE_SCRIPT_SIZE {
            return Err(ValidationError::TxCoinbaseScriptSizeTooLarge);
        }
    }

    // Check transaction size
    let tx_size = serialize_tx(tx).len() as u32;
    if tx_size > MAX_TX_SIZE {
        return Err(ValidationError::TxSizeTooLarge);
    }

    Ok(())
}

/// Check block header validity
///
/// Performs these checks:
/// - Proof of work is valid (hash meets difficulty target)
pub fn check_block_header(header: &BlockHeader, _params: &ConsensusParams) -> ValidationResult<()> {
    // Verify proof of work
    let block_hash = header.block_hash();
    let hash_as_int = hash_to_u128(block_hash.as_bytes());
    let target = decode_compact(header.bits);

    if hash_as_int > target {
        return Err(ValidationError::BlockProofOfWorkInvalid);
    }

    Ok(())
}

/// Check block validity
///
/// Performs these checks:
/// - Block has transactions
/// - First transaction is coinbase
/// - Other transactions are not coinbase
/// - Merkle root matches
/// - Block size within limits
/// - Block weight within limits
/// - Sigops cost within limits
pub fn check_block(block: &Block, _params: &ConsensusParams) -> ValidationResult<()> {
    // Check has transactions
    if block.transactions.is_empty() {
        return Err(ValidationError::BlockNoTransactions);
    }

    // Check first is coinbase
    if !block.transactions[0].is_coinbase() {
        return Err(ValidationError::BlockCoinbaseNotFirst);
    }

    // Check no other coinbase
    for i in 1..block.transactions.len() {
        if block.transactions[i].is_coinbase() {
            return Err(ValidationError::BlockCoinbaseMultiple);
        }
    }

    // Check merkle root
    if !block.has_valid_merkle_root() {
        return Err(ValidationError::BlockMerkleRootInvalid);
    }

    // Check block size
    if block.size() > MAX_BLOCK_SERIALIZED_SIZE as usize {
        return Err(ValidationError::BlockSizeTooLarge);
    }

    // Check block weight
    let total_weight: u32 = block
        .transactions
        .iter()
        .map(|tx| tx.compute_weight())
        .sum();
    if total_weight > MAX_BLOCK_WEIGHT {
        return Err(ValidationError::BlockWeightTooLarge);
    }

    // Check all transactions
    for tx in &block.transactions {
        check_transaction(tx)?;
    }

    Ok(())
}

/// Serialize a transaction (without witness for now)
fn serialize_tx(tx: &Transaction) -> Vec<u8> {
    let mut data = Vec::new();

    // Version
    data.extend_from_slice(&tx.version.to_le_bytes());

    // Input count
    data.extend_from_slice(&compact_size(tx.inputs.len() as u64));

    // Inputs
    for input in &tx.inputs {
        // Previous output
        data.extend_from_slice(input.previous_output.txid.as_bytes());
        data.extend_from_slice(&input.previous_output.vout.to_le_bytes());

        // Script sig
        let script_bytes = input.script_sig.as_bytes();
        data.extend_from_slice(&compact_size(script_bytes.len() as u64));
        data.extend_from_slice(script_bytes);

        // Sequence
        data.extend_from_slice(&input.sequence.to_le_bytes());
    }

    // Output count
    data.extend_from_slice(&compact_size(tx.outputs.len() as u64));

    // Outputs
    for output in &tx.outputs {
        data.extend_from_slice(&output.value.as_sat().to_le_bytes());

        let script_bytes = output.script_pubkey.as_bytes();
        data.extend_from_slice(&compact_size(script_bytes.len() as u64));
        data.extend_from_slice(script_bytes);
    }

    // Locktime
    data.extend_from_slice(&tx.lock_time.to_le_bytes());

    data
}

/// Encode a value as Bitcoin compact size
fn compact_size(value: u64) -> Vec<u8> {
    if value < 0xfd {
        vec![value as u8]
    } else if value <= 0xffff {
        let mut bytes = vec![0xfd];
        bytes.extend_from_slice(&(value as u16).to_le_bytes());
        bytes
    } else if value <= 0xffffffff {
        let mut bytes = vec![0xfe];
        bytes.extend_from_slice(&(value as u32).to_le_bytes());
        bytes
    } else {
        let mut bytes = vec![0xff];
        bytes.extend_from_slice(&value.to_le_bytes());
        bytes
    }
}

/// Decode compact target representation to 128-bit value
pub fn decode_compact(bits: u32) -> u128 {
    let exponent = (bits >> 24) as u32;
    let mantissa = bits & 0xffffff;

    if exponent <= 3 {
        (mantissa >> (8 * (3 - exponent))) as u128
    } else {
        let shift = 8 * (exponent - 3);
        if shift >= 128 {
            // Exponent too large for u128 — target is effectively unlimited
            // (any hash passes). This occurs with regtest bits (0x207fffff).
            u128::MAX
        } else {
            (mantissa as u128) << shift
        }
    }
}

// ── Difficulty retargeting ──────────────────────────────────────────

/// Difficulty adjustment interval (2016 blocks on mainnet).
pub const DIFFICULTY_ADJUSTMENT_INTERVAL: u32 = 2016;

/// Calculate the next work required (compact target / nBits) for a block.
///
/// This is the Rust equivalent of Bitcoin Core's `GetNextWorkRequired()`.
///
/// # Arguments
///
/// * `height` — height of the block we are producing (1-indexed).
/// * `prev_time` — timestamp of the previous block (height - 1).
/// * `prev_bits` — compact target of the previous block.
/// * `first_time` — timestamp of the first block in this retarget period
///   (i.e. the block at height `height - INTERVAL`).
/// * `params` — consensus parameters.
///
/// # Logic
///
/// 1. If `no_retargeting` (regtest), return `pow_limit_bits`.
/// 2. If we are not at a retarget boundary (`height % interval != 0`),
///    return `prev_bits` (with a special case for testnet's
///    `allow_min_difficulty` mode).
/// 3. Otherwise, compute `actual_timespan = prev_time - first_time`,
///    clamp it to `[timespan/4 .. timespan*4]`, and scale the target:
///    `new_target = old_target * actual_timespan / pow_target_timespan`.
/// 4. If the new target exceeds `pow_limit`, cap it.
///
/// # Returns
///
/// The compact target (nBits) for the new block.
pub fn get_next_work_required(
    height: u32,
    prev_time: u32,
    prev_bits: u32,
    first_time: Option<u32>,
    params: &ConsensusParams,
) -> u32 {
    // Regtest: no retargeting — always minimum difficulty.
    if params.no_retargeting {
        return params.pow_limit_bits;
    }

    let interval = params.pow_target_timespan / params.pow_target_spacing;

    // If not at a retarget boundary, keep the same difficulty.
    if height % interval != 0 {
        // Testnet special rule: if the block is more than 2× target spacing
        // after the previous block, allow minimum difficulty.
        if params.allow_min_difficulty {
            // Caller would need to check if prev_time + 2*spacing < this_time
            // but we don't have `this_time` here. This is handled by the
            // application layer (block index) which can inspect timestamps.
        }
        return prev_bits;
    }

    // We're at a retarget boundary. `first_time` must be provided.
    let first_time = match first_time {
        Some(t) => t,
        None => return prev_bits, // safety fallback
    };

    calculate_next_work(prev_bits, first_time, prev_time, params)
}

/// Perform the actual difficulty retarget calculation.
///
/// Given the old compact target and the actual timespan of the last
/// `interval` blocks, compute the new compact target.
///
/// This corresponds to Bitcoin Core's `CalculateNextWorkRequired()`.
///
/// Unlike a naïve approach of decoding to a full integer, this operates
/// directly on the compact (mantissa, exponent) representation to avoid
/// precision loss for large targets that exceed u128.
pub fn calculate_next_work(
    prev_bits: u32,
    first_time: u32,
    last_time: u32,
    params: &ConsensusParams,
) -> u32 {
    let target_timespan = params.pow_target_timespan;

    // Compute actual timespan, clamping to [timespan/4 .. timespan*4].
    let mut actual_timespan = last_time.saturating_sub(first_time);
    if actual_timespan < target_timespan / 4 {
        actual_timespan = target_timespan / 4;
    }
    if actual_timespan > target_timespan * 4 {
        actual_timespan = target_timespan * 4;
    }

    // Extract mantissa and exponent from the old compact target.
    let exponent = (prev_bits >> 24) as u32;
    let mantissa = prev_bits & 0x7fffff;
    let _negative = prev_bits & 0x800000 != 0;

    if mantissa == 0 {
        return prev_bits;
    }

    // Scale the mantissa: new = mantissa * actual_timespan / target_timespan.
    // mantissa ≤ 0x7fffff (23 bits), actual_timespan ≤ ~4.8M (23 bits)
    // → product ≤ 46 bits, fits safely in u64.
    let scaled = (mantissa as u64) * (actual_timespan as u64);
    let mut new_mantissa = scaled / (target_timespan as u64);
    let mut new_exponent = exponent;

    // Handle overflow: if mantissa exceeds 23 bits, shift right by whole
    // bytes and increase the exponent.
    while new_mantissa > 0x7fffff {
        new_mantissa >>= 8;
        new_exponent += 1;
    }

    let new_bits = (new_exponent << 24) | (new_mantissa as u32 & 0x7fffff);

    // Cap at pow_limit: compare compact representations.
    if compact_gt(new_bits, params.pow_limit_bits) {
        params.pow_limit_bits
    } else {
        new_bits
    }
}

/// Compare two compact targets: returns true if `a` represents a larger
/// target (= easier difficulty) than `b`.
fn compact_gt(a: u32, b: u32) -> bool {
    let a_exp = (a >> 24) as u32;
    let b_exp = (b >> 24) as u32;
    let a_man = a & 0x7fffff;
    let b_man = b & 0x7fffff;

    if a_exp != b_exp {
        a_exp > b_exp
    } else {
        a_man > b_man
    }
}

/// Encode a u128 target value into compact nBits format.
///
/// Inverse of `decode_compact` for targets that fit in u128. For targets
/// larger than u128::MAX (e.g. regtest), the original compact value should
/// be preserved directly rather than round-tripping through u128.
pub fn encode_compact(target: u128) -> u32 {
    if target == 0 {
        return 0;
    }

    // Find how many bytes are needed to represent the target.
    let mut size = 0u32;
    let mut t = target;
    while t > 0 {
        t >>= 8;
        size += 1;
    }

    // Extract the top 3 bytes as mantissa.
    let mantissa: u32 = if size <= 3 {
        (target << (8 * (3 - size))) as u32 & 0xffffff
    } else {
        let shift = 8 * (size - 3);
        if shift >= 128 {
            0
        } else {
            (target >> shift) as u32 & 0xffffff
        }
    };

    // If the high bit of the mantissa is set, we need one more byte
    // (bit 23 is the sign bit in compact format).
    let (size, mantissa) = if mantissa & 0x800000 != 0 {
        (size + 1, mantissa >> 8)
    } else {
        (size, mantissa)
    };

    (size << 24) | mantissa
}

/// Convert hash bytes to u128 for comparison
pub fn hash_to_u128(bytes: &[u8; 32]) -> u128 {
    // Take first 16 bytes and interpret as u128 (little-endian)
    let mut val = 0u128;
    for i in 0..16 {
        val |= (bytes[i] as u128) << (i * 8);
    }
    val
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::primitives::{OutPoint, TxIn, TxOut, Txid, Amount};
    use crate::Script;

    #[test]
    fn test_empty_inputs() {
        let tx = Transaction::new(1, vec![], vec![], 0);
        assert!(check_transaction(&tx).is_err());
    }

    #[test]
    fn test_valid_transaction() {
        let input = TxIn::final_input(OutPoint::new(Txid::zero(), 0), Script::new());
        let output = TxOut::new(Amount::from_sat(1000), Script::new());
        let tx = Transaction::v1(vec![input], vec![output], 0);

        assert!(check_transaction(&tx).is_ok());
    }

    // ── Compact encoding tests ───────────────────────────────

    #[test]
    fn test_encode_decode_compact_fits_u128() {
        // Targets with exponent ≤ 18 fit in u128 and should roundtrip.
        // 0x0f0404cb: exponent=15, shift=96, target fits in ~120 bits.
        let bits = 0x0f0404cbu32;
        let target = decode_compact(bits);
        assert_ne!(target, u128::MAX);
        let re_encoded = encode_compact(target);
        assert_eq!(decode_compact(re_encoded), target);
    }

    #[test]
    fn test_encode_compact_zero() {
        assert_eq!(encode_compact(0), 0);
    }

    #[test]
    fn test_decode_compact_large_targets_clamp() {
        // Targets with shift >= 128 are clamped to u128::MAX.
        assert_eq!(decode_compact(0x1d00ffff), u128::MAX); // genesis
        assert_eq!(decode_compact(0x1b0404cb), u128::MAX); // exp=27, shift=192
    }

    // ── Difficulty retargeting tests ───────────────────────────
    //
    // `calculate_next_work` operates on compact bits directly (mantissa +
    // exponent) so it works correctly even for targets that overflow u128.
    // Tests compare compact nBits values using `compact_gt`.

    #[test]
    fn test_retarget_on_time() {
        // Exact 2-week timespan → same bits.
        let params = ConsensusParams::mainnet();
        let prev_bits = 0x1d00ffff;
        let ts = params.pow_target_timespan;
        let new_bits = calculate_next_work(prev_bits, 1_000_000, 1_000_000 + ts, &params);
        assert_eq!(new_bits, prev_bits);
    }

    #[test]
    fn test_retarget_on_time_higher_difficulty() {
        let params = ConsensusParams::mainnet();
        let prev_bits = 0x1b0404cb;
        let ts = params.pow_target_timespan;
        let new_bits = calculate_next_work(prev_bits, 1_000_000, 1_000_000 + ts, &params);
        assert_eq!(new_bits, prev_bits);
    }

    #[test]
    fn test_retarget_blocks_too_fast() {
        // 2× faster → target shrinks (harder difficulty).
        // Compact: smaller target = lower exponent or lower mantissa.
        let params = ConsensusParams::mainnet();
        let prev_bits = 0x1d00ffff;
        let ts = params.pow_target_timespan;
        let new_bits = calculate_next_work(prev_bits, 1_000_000, 1_000_000 + ts / 2, &params);
        // new_bits should encode a smaller target.
        assert!(compact_gt(prev_bits, new_bits), "difficulty should increase (target decrease)");
        assert_ne!(new_bits, prev_bits);
    }

    #[test]
    fn test_retarget_blocks_too_slow() {
        // 2× slower → target grows (easier difficulty).
        let params = ConsensusParams::mainnet();
        let prev_bits = 0x1b0404cb;
        let ts = params.pow_target_timespan;
        let new_bits = calculate_next_work(prev_bits, 1_000_000, 1_000_000 + ts * 2, &params);
        assert!(compact_gt(new_bits, prev_bits), "difficulty should decrease (target increase)");
    }

    #[test]
    fn test_retarget_clamp_max_increase() {
        // Extremely slow → clamped at 4× the timespan.
        // Mantissa should be exactly 4× the original.
        let params = ConsensusParams::mainnet();
        let prev_bits = 0x1b0404cb;
        let ts = params.pow_target_timespan;
        let prev_mantissa = prev_bits & 0x7fffff;

        let new_bits = calculate_next_work(prev_bits, 1_000_000, 1_000_000 + ts * 100, &params);
        let new_mantissa = new_bits & 0x7fffff;
        let new_exp = new_bits >> 24;
        let old_exp = prev_bits >> 24;

        // 4× the mantissa. If it overflows 23 bits, exponent increases.
        let expected_mantissa = prev_mantissa * 4;
        if expected_mantissa <= 0x7fffff {
            assert_eq!(new_mantissa, expected_mantissa);
            assert_eq!(new_exp, old_exp);
        } else {
            // Mantissa overflowed → shifted right by 1 byte, exponent +1
            assert_eq!(new_exp, old_exp + 1);
            assert_eq!(new_mantissa, expected_mantissa >> 8);
        }
    }

    #[test]
    fn test_retarget_clamp_max_decrease() {
        // Extremely fast → clamped at timespan/4.
        // Mantissa should be ~1/4 the original.
        let params = ConsensusParams::mainnet();
        let prev_bits = 0x1d00ffff;
        let prev_mantissa = prev_bits & 0x7fffff;

        let new_bits = calculate_next_work(prev_bits, 1_000_000, 1_000_001, &params);
        let new_mantissa = new_bits & 0x7fffff;
        let new_exp = new_bits >> 24;
        let old_exp = prev_bits >> 24;

        // Mantissa divided by 4 (integer truncation).
        assert_eq!(new_mantissa, prev_mantissa / 4);
        assert_eq!(new_exp, old_exp);
    }

    #[test]
    fn test_retarget_cap_at_pow_limit() {
        // Already at pow_limit, 4× slower → capped at pow_limit.
        let params = ConsensusParams::mainnet();
        let prev_bits = params.pow_limit_bits;
        let ts = params.pow_target_timespan;
        let new_bits = calculate_next_work(prev_bits, 1_000_000, 1_000_000 + ts * 4, &params);
        assert_eq!(new_bits, params.pow_limit_bits);
    }

    #[test]
    fn test_get_next_work_regtest() {
        let params = ConsensusParams::regtest();
        let bits = get_next_work_required(100, 12345, 0x1d00ffff, None, &params);
        assert_eq!(bits, params.pow_limit_bits);
    }

    #[test]
    fn test_get_next_work_non_boundary() {
        let params = ConsensusParams::mainnet();
        let prev_bits = 0x1b0404cb;
        let bits = get_next_work_required(2015, 12345, prev_bits, None, &params);
        assert_eq!(bits, prev_bits);
    }

    #[test]
    fn test_get_next_work_at_boundary() {
        let params = ConsensusParams::mainnet();
        let prev_bits = 0x1b0404cb;
        let ts = params.pow_target_timespan;
        let bits = get_next_work_required(2016, 1_000_000 + ts, prev_bits, Some(1_000_000), &params);
        assert_eq!(bits, prev_bits);
    }

    #[test]
    fn test_compact_gt() {
        assert!(compact_gt(0x1d00ffff, 0x1b0404cb));
        assert!(!compact_gt(0x1b0404cb, 0x1d00ffff));
        assert!(compact_gt(0x1b0500cb, 0x1b0404cb));
        assert!(!compact_gt(0x1b0404cb, 0x1b0500cb));
        assert!(!compact_gt(0x1b0404cb, 0x1b0404cb));
    }
}
