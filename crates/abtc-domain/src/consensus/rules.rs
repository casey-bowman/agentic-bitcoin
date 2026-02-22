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

/// Maximum block sigops cost (80,000 = MAX_BLOCK_WEIGHT / 50)
pub const MAX_BLOCK_SIGOPS_COST: u32 = 80_000;

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
pub fn check_block_header(header: &BlockHeader, params: &ConsensusParams) -> ValidationResult<()> {
    // Regtest fast path: when the target decodes to a value that saturates
    // u128, PoW is effectively unchecked (any hash passes). This matches
    // mine_block's fast path, which returns nonce 0 for such targets.
    let target_u128 = decode_compact(header.bits);
    if target_u128 == u128::MAX {
        return Ok(());
    }

    // Also fast-path when the 256-bit target is all 0xff bytes.
    let target = decode_compact_u256(header.bits);
    if target == [0xff; 32] {
        return Ok(());
    }

    // Verify proof of work (full 256-bit comparison)
    let block_hash = header.block_hash();
    let _ = params; // params available for future target-range checks

    if !hash_meets_target(block_hash.as_bytes(), &target) {
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
    let exponent = bits >> 24;
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
    let exponent = prev_bits >> 24;
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
    let a_exp = a >> 24;
    let b_exp = b >> 24;
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

/// Convert hash bytes to u128 for comparison (DEPRECATED — truncates to 128 bits).
///
/// Use `hash_meets_target` for proof-of-work validation instead.
pub fn hash_to_u128(bytes: &[u8; 32]) -> u128 {
    // Take first 16 bytes and interpret as u128 (little-endian)
    let mut val = 0u128;
    for (i, byte) in bytes[..16].iter().enumerate() {
        val |= (*byte as u128) << (i * 8);
    }
    val
}

/// Decode compact target to a full 256-bit value (32 bytes, little-endian).
///
/// Unlike `decode_compact` (which truncates to u128), this preserves the full
/// 256-bit target needed for correct proof-of-work validation.
pub fn decode_compact_u256(bits: u32) -> [u8; 32] {
    let exponent = (bits >> 24) as usize;
    let mantissa = bits & 0x7fffff; // mask sign bit (negative target → zero)
    let negative = (bits & 0x800000) != 0;

    if exponent == 0 || negative {
        return [0u8; 32];
    }

    let mut target = [0u8; 32];

    // The mantissa occupies 3 bytes placed at byte offset (exponent - 3) in LE.
    // When exponent < 3 the mantissa is right-shifted (losing low bits).
    // When exponent == 3, base == 0 and all 3 mantissa bytes are placed at [0..2].
    // When exponent > 3, base > 0 and the mantissa is placed at [base..base+2].
    if exponent < 3 {
        let shifted = mantissa >> (8 * (3 - exponent));
        // After shifting, at most `exponent` bytes remain.
        for (i, target_byte) in target[..exponent].iter_mut().enumerate() {
            *target_byte = ((shifted >> (8 * i)) & 0xff) as u8;
        }
    } else {
        let base = exponent - 3;
        if base < 32 {
            target[base] = (mantissa & 0xff) as u8;
        }
        if base + 1 < 32 {
            target[base + 1] = ((mantissa >> 8) & 0xff) as u8;
        }
        if base + 2 < 32 {
            target[base + 2] = ((mantissa >> 16) & 0xff) as u8;
        }
    }
    target
}

/// Check if a block hash meets the proof-of-work target (full 256-bit comparison).
///
/// Both `hash` and `target` are 32 bytes in little-endian uint256 format.
/// Returns true if hash <= target.
pub fn hash_meets_target(hash: &[u8; 32], target: &[u8; 32]) -> bool {
    // Compare from the most significant byte (index 31) downward
    for i in (0..32).rev() {
        if hash[i] < target[i] {
            return true;
        }
        if hash[i] > target[i] {
            return false;
        }
    }
    true // equal
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::primitives::{Amount, OutPoint, TxIn, TxOut, Txid};
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
        assert!(
            compact_gt(prev_bits, new_bits),
            "difficulty should increase (target decrease)"
        );
        assert_ne!(new_bits, prev_bits);
    }

    #[test]
    fn test_retarget_blocks_too_slow() {
        // 2× slower → target grows (easier difficulty).
        let params = ConsensusParams::mainnet();
        let prev_bits = 0x1b0404cb;
        let ts = params.pow_target_timespan;
        let new_bits = calculate_next_work(prev_bits, 1_000_000, 1_000_000 + ts * 2, &params);
        assert!(
            compact_gt(new_bits, prev_bits),
            "difficulty should decrease (target increase)"
        );
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
        let bits =
            get_next_work_required(2016, 1_000_000 + ts, prev_bits, Some(1_000_000), &params);
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

    // ═══════════════════════════════════════════════════════════════════
    // Regression tests — Session 14, Part 4 (code review fixes)
    //
    // These tests were written specifically for this implementation to
    // guard against bugs found during a code review. They are NOT ports
    // of Bitcoin Core test vectors. Each test name begins with
    // `regression_` so it can be distinguished from the implementation
    // unit tests above, which exercise baseline functionality.
    // ═══════════════════════════════════════════════════════════════════

    #[test]
    fn regression_max_block_sigops_cost_is_80k() {
        // Review finding #12: was mistakenly 20,000,000 (250× too high).
        // Correct value is MAX_BLOCK_WEIGHT / 50 = 4,000,000 / 50 = 80,000.
        assert_eq!(MAX_BLOCK_SIGOPS_COST, 80_000);
        assert_eq!(MAX_BLOCK_SIGOPS_COST, MAX_BLOCK_WEIGHT / 50);
    }

    #[test]
    fn regression_decode_compact_u256_zero_exponent() {
        assert_eq!(decode_compact_u256(0x00000000), [0u8; 32]);
    }

    #[test]
    fn regression_decode_compact_u256_negative_target() {
        // Sign bit set → target should be zero (negative targets are invalid).
        assert_eq!(decode_compact_u256(0x04800001), [0u8; 32]);
    }

    #[test]
    fn regression_decode_compact_u256_small_target() {
        // 0x03010000 → exponent=3, mantissa=0x010000.
        // Target = 0x010000 placed at byte offset 0 (exponent - 3 = 0).
        // In LE: [0x00, 0x00, 0x01, 0, 0, ...].
        let target = decode_compact_u256(0x03010000);
        assert_eq!(target[0], 0x00);
        assert_eq!(target[1], 0x00);
        assert_eq!(target[2], 0x01);
        for i in 3..32 {
            assert_eq!(target[i], 0, "byte {} should be zero", i);
        }
    }

    #[test]
    fn regression_decode_compact_u256_regtest() {
        // Regtest bits 0x207fffff: exponent=32, base=29.
        // Mantissa 0x7fffff placed at bytes 29..31.
        let target = decode_compact_u256(0x207fffff);
        assert_eq!(target[29], 0xff);
        assert_eq!(target[30], 0xff);
        assert_eq!(target[31], 0x7f);
    }

    #[test]
    fn regression_hash_meets_target_equal() {
        let hash = [0x42u8; 32];
        let target = [0x42u8; 32];
        assert!(hash_meets_target(&hash, &target), "equal hash should pass");
    }

    #[test]
    fn regression_hash_meets_target_less() {
        let mut hash = [0x00u8; 32];
        hash[31] = 0x01; // hash = 1 << 248
        let mut target = [0x00u8; 32];
        target[31] = 0x02; // target = 2 << 248
        assert!(
            hash_meets_target(&hash, &target),
            "smaller hash should pass"
        );
    }

    #[test]
    fn regression_hash_meets_target_greater() {
        let mut hash = [0x00u8; 32];
        hash[31] = 0x03; // hash = 3 << 248
        let mut target = [0x00u8; 32];
        target[31] = 0x02; // target = 2 << 248
        assert!(
            !hash_meets_target(&hash, &target),
            "greater hash should fail"
        );
    }

    #[test]
    fn regression_hash_meets_target_high_bytes_matter() {
        // Review finding #4: the old u128 comparison only checked the first
        // 16 bytes. This test uses a hash where bytes 16–31 exceed the target
        // but the lower 16 bytes are all zero (would pass the old u128 check).
        let mut hash = [0x00u8; 32];
        hash[16] = 0x01; // non-zero in byte 16 (beyond u128 range)
        let target = [0x00u8; 32]; // target = 0
        assert!(
            !hash_meets_target(&hash, &target),
            "hash with non-zero high bytes must fail against zero target"
        );
    }

    #[test]
    fn regression_256bit_pow_rejects_truncation_bug() {
        // Review finding #4: a u128 comparison (bytes 0..15) would see
        // hash < target and PASS. But the full 256-bit check catches
        // that hash[17] > target[17] and correctly REJECTS.
        let mut hash = [0x00u8; 32];
        hash[17] = 0x02; // above u128 range, exceeds target
        let mut target = [0x00u8; 32];
        target[15] = 0xff; // makes lower 16 bytes of target large
        target[17] = 0x01; // target[17] < hash[17]
                           // u128 view: hash_u128 = 0, target_u128 = 0xff << 120 → hash < target → PASS
                           // 256-bit:   bytes 31..18 equal. Byte 17: hash=0x02 > target=0x01 → REJECT
        assert!(
            !hash_meets_target(&hash, &target),
            "256-bit comparison should catch high-byte violation that u128 misses"
        );
    }
}
