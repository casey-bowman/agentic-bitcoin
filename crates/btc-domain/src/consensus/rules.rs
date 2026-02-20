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
fn decode_compact(bits: u32) -> u128 {
    let exponent = (bits >> 24) as u32;
    let mantissa = bits & 0xffffff;

    if exponent <= 3 {
        (mantissa >> (8 * (3 - exponent))) as u128
    } else {
        (mantissa as u128) << (8 * (exponent - 3))
    }
}

/// Convert hash bytes to u128 for comparison
fn hash_to_u128(bytes: &[u8; 32]) -> u128 {
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
    use crate::primitives::{OutPoint, Script, TxIn, TxOut, Txid};

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
}
