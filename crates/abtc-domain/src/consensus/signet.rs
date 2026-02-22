//! BIP325 Signet Block Validation
//!
//! Signet replaces proof-of-work as the sole block validation mechanism with
//! an additional signature-based check. Each signet block must contain a valid
//! signature in its coinbase transaction that satisfies a predetermined
//! "challenge script."
//!
//! ## Protocol
//!
//! 1. The coinbase transaction contains an OP_RETURN output with a 4-byte
//!    magic header (`0xeца7b2ef`) followed by the "signet solution."
//! 2. A "block data hash" is computed by stripping the signet commitment
//!    from the coinbase, recomputing the merkle root, and hashing the
//!    modified 80-byte header.
//! 3. Two virtual transactions are constructed:
//!    - **to_spend**: a single output whose scriptPubKey is the challenge.
//!    - **to_sign**: spends to_spend with the signet solution as witness.
//! 4. The script interpreter verifies that the solution satisfies the challenge.
//!
//! PoW is still checked (signet uses low difficulty), but the signet signature
//! provides the real block authorization.

use crate::crypto::hashing::hash256;
use crate::crypto::signing::TransactionSignatureChecker;
use crate::primitives::{Amount, Block, Hash256, OutPoint, Transaction, TxIn, TxOut, Txid};
use crate::script::interpreter::verify_script_with_witness;
use crate::script::witness::Witness;
use crate::script::{Opcodes, Script, ScriptBuilder, ScriptFlags};

use std::fmt;

// ── Constants ────────────────────────────────────────────────────────

/// 4-byte magic prefix identifying the signet commitment in a coinbase
/// OP_RETURN output.
pub const SIGNET_HEADER: [u8; 4] = [0xec, 0xa7, 0xb2, 0xef];

// ── Error type ───────────────────────────────────────────────────────

/// Errors that can occur during signet block validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignetError {
    /// The coinbase transaction has no OP_RETURN output with the signet header.
    MissingSignetSolution,
    /// The signet solution bytes could not be parsed as a witness stack.
    InvalidSolutionEncoding(String),
    /// The challenge script verification failed.
    ChallengeScriptFailed(String),
    /// No challenge script is configured (signet_challenge is None).
    NoChallengeScript,
    /// Block has no transactions (cannot extract coinbase).
    EmptyBlock,
}

impl fmt::Display for SignetError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SignetError::MissingSignetSolution => {
                write!(
                    f,
                    "no signet commitment found in coinbase OP_RETURN outputs"
                )
            }
            SignetError::InvalidSolutionEncoding(reason) => {
                write!(f, "invalid signet solution encoding: {}", reason)
            }
            SignetError::ChallengeScriptFailed(reason) => {
                write!(f, "signet challenge script failed: {}", reason)
            }
            SignetError::NoChallengeScript => {
                write!(f, "no signet challenge script configured")
            }
            SignetError::EmptyBlock => {
                write!(f, "block has no transactions")
            }
        }
    }
}

impl std::error::Error for SignetError {}

// ── Core BIP325 functions ────────────────────────────────────────────

/// Extract the signet solution from a block's coinbase transaction.
///
/// Scans the coinbase outputs for an OP_RETURN whose data begins with the
/// 4-byte `SIGNET_HEADER`. Returns the raw solution bytes (everything after
/// the header).
///
/// The signet commitment format in the OP_RETURN script is:
///   `OP_RETURN OP_PUSH <signet_header (4 bytes) + solution_data>`
pub fn extract_signet_solution(block: &Block) -> Result<Vec<u8>, SignetError> {
    if block.transactions.is_empty() {
        return Err(SignetError::EmptyBlock);
    }

    let coinbase = &block.transactions[0];

    for output in &coinbase.outputs {
        let script_bytes = output.script_pubkey.as_bytes();

        // Must start with OP_RETURN (0x6a)
        if script_bytes.is_empty() || script_bytes[0] != Opcodes::OP_RETURN as u8 {
            continue;
        }

        // Parse the data push after OP_RETURN
        if let Some(data) = extract_push_data(&script_bytes[1..]) {
            // Check for signet header
            if data.len() >= SIGNET_HEADER.len() && data[..4] == SIGNET_HEADER {
                return Ok(data[4..].to_vec());
            }
        }
    }

    Err(SignetError::MissingSignetSolution)
}

/// Compute the "block data hash" per BIP325.
///
/// This hash commits to the block contents without the signet solution:
/// 1. Clone the block and strip the signet commitment from the coinbase
///    (replace the commitment output's scriptPubKey with bare `OP_RETURN`).
/// 2. Recompute the merkle root with the modified coinbase.
/// 3. Construct a modified header with the new merkle root.
/// 4. Double-SHA256 the 80-byte modified header.
pub fn compute_block_data_hash(block: &Block) -> Hash256 {
    // Clone the block so we can modify the coinbase
    let mut modified = block.clone();

    if !modified.transactions.is_empty() {
        let coinbase = &mut modified.transactions[0];

        // Find and strip the signet commitment output
        for output in &mut coinbase.outputs {
            let script_bytes = output.script_pubkey.as_bytes();

            if script_bytes.is_empty() || script_bytes[0] != Opcodes::OP_RETURN as u8 {
                continue;
            }

            if let Some(data) = extract_push_data(&script_bytes[1..]) {
                if data.len() >= 4 && data[..4] == SIGNET_HEADER {
                    // Replace with bare OP_RETURN (no data)
                    output.script_pubkey =
                        ScriptBuilder::new().push_opcode(Opcodes::OP_RETURN).build();
                    break;
                }
            }
        }
    }

    // Recompute merkle root with modified coinbase
    let new_merkle_root = modified.compute_merkle_root();

    // Serialize the modified header (80 bytes) and hash
    let mut header_bytes = Vec::with_capacity(80);
    header_bytes.extend_from_slice(&modified.header.version.to_le_bytes());
    header_bytes.extend_from_slice(modified.header.prev_block_hash.as_bytes());
    header_bytes.extend_from_slice(new_merkle_root.as_bytes());
    header_bytes.extend_from_slice(&modified.header.time.to_le_bytes());
    header_bytes.extend_from_slice(&modified.header.bits.to_le_bytes());
    header_bytes.extend_from_slice(&modified.header.nonce.to_le_bytes());

    hash256(&header_bytes)
}

/// Construct the virtual `to_spend` transaction per BIP325.
///
/// - Version: 0
/// - Single input: outpoint = (block_data_hash, 0xFFFFFFFF), empty scriptSig,
///   sequence 0
/// - Single output: value = 0, scriptPubKey = challenge
/// - Locktime: 0
pub fn make_signet_to_spend(challenge: &Script, block_data_hash: &Hash256) -> Transaction {
    let outpoint = OutPoint::new(Txid::from_hash(*block_data_hash), 0xFFFFFFFF);

    let input = TxIn::new(outpoint, Script::new(), 0);

    let output = TxOut::new(Amount::from_sat(0), challenge.clone());

    Transaction::new(0, vec![input], vec![output], 0)
}

/// Construct the virtual `to_sign` transaction per BIP325.
///
/// - Version: 0
/// - Single input: spends to_spend output 0, empty scriptSig, sequence 0
/// - Single output: value = 0, scriptPubKey = OP_RETURN
/// - Locktime: 0
///
/// The witness (signet solution) is set on the input.
pub fn make_signet_to_sign(to_spend_txid: Txid, solution: Witness) -> Transaction {
    let outpoint = OutPoint::new(to_spend_txid, 0);

    let input = TxIn::new(outpoint, Script::new(), 0).with_witness(solution);

    let op_return_script = ScriptBuilder::new().push_opcode(Opcodes::OP_RETURN).build();

    let output = TxOut::new(Amount::from_sat(0), op_return_script);

    Transaction::new(0, vec![input], vec![output], 0)
}

/// Parse a raw byte sequence into a witness stack.
///
/// BIP325 encodes the signet solution as a serialized witness stack:
/// `compact_size(item_count) [compact_size(item_len) item_data]...`
pub fn parse_witness_solution(data: &[u8]) -> Result<Witness, SignetError> {
    let mut cursor = 0;

    let (count, consumed) =
        read_compact_size(data, cursor).map_err(SignetError::InvalidSolutionEncoding)?;
    cursor += consumed;

    let mut witness = Witness::new();

    for _ in 0..count {
        let (item_len, consumed) =
            read_compact_size(data, cursor).map_err(SignetError::InvalidSolutionEncoding)?;
        cursor += consumed;

        if cursor + item_len as usize > data.len() {
            return Err(SignetError::InvalidSolutionEncoding(
                "witness item extends beyond data".to_string(),
            ));
        }

        witness.push(data[cursor..cursor + item_len as usize].to_vec());
        cursor += item_len as usize;
    }

    Ok(witness)
}

/// Validate a signet block against the given challenge script.
///
/// This is the main entry point for BIP325 validation. It:
/// 1. Extracts the signet solution from the coinbase OP_RETURN
/// 2. Computes the block data hash (modified header without signet data)
/// 3. Constructs virtual to_spend and to_sign transactions
/// 4. Verifies the challenge script is satisfied by the solution
pub fn validate_signet_block(block: &Block, challenge: &Script) -> Result<(), SignetError> {
    // Step 1: Extract solution
    let solution_data = extract_signet_solution(block)?;

    // Step 2: Parse solution into witness stack
    let witness = parse_witness_solution(&solution_data)?;

    // Step 3: Compute block data hash
    let block_data_hash = compute_block_data_hash(block);

    // Step 4: Construct virtual transactions
    let to_spend = make_signet_to_spend(challenge, &block_data_hash);
    let to_spend_txid = to_spend.txid();

    let to_sign = make_signet_to_sign(to_spend_txid, witness.clone());

    // Step 5: Verify the challenge script
    // Use standard flags including witness and P2SH support
    let flags = ScriptFlags::new(
        ScriptFlags::VERIFY_P2SH
            | ScriptFlags::VERIFY_WITNESS
            | ScriptFlags::VERIFY_DERSIG
            | ScriptFlags::VERIFY_LOW_S
            | ScriptFlags::VERIFY_NULLDUMMY,
    );

    // The checker needs the to_sign transaction and the spent amount (0)
    let checker = if witness.is_empty() {
        TransactionSignatureChecker::new(&to_sign, 0, Amount::from_sat(0))
    } else {
        TransactionSignatureChecker::new_witness_v0(&to_sign, 0, Amount::from_sat(0))
    };

    verify_script_with_witness(
        &to_sign.inputs[0].script_sig, // empty
        challenge,                     // the challenge script
        &to_sign.inputs[0].witness,    // the signet solution
        flags,
        &checker,
    )
    .map_err(|e| SignetError::ChallengeScriptFailed(format!("{:?}", e)))
}

// ── Signet commitment builder (for mining) ──────────────────────────

/// Build the signet commitment output to embed in a coinbase transaction.
///
/// Creates an OP_RETURN output containing the signet header followed by the
/// serialized witness solution.
///
/// Format: `OP_RETURN OP_PUSH <signet_header (4 bytes) + witness_stack_serialized>`
pub fn build_signet_commitment(solution: &Witness) -> TxOut {
    let mut commitment_data = SIGNET_HEADER.to_vec();
    commitment_data.extend_from_slice(&serialize_witness_stack(solution));

    let script = ScriptBuilder::new()
        .push_opcode(Opcodes::OP_RETURN)
        .push_slice(&commitment_data)
        .build();

    TxOut::new(Amount::from_sat(0), script)
}

/// Serialize a witness stack into the BIP325 solution format.
///
/// Format: `compact_size(item_count) [compact_size(item_len) item_data]...`
pub fn serialize_witness_stack(witness: &Witness) -> Vec<u8> {
    let mut data = Vec::new();
    data.extend_from_slice(&encode_compact_size(witness.len() as u64));

    for item in witness.iter() {
        data.extend_from_slice(&encode_compact_size(item.len() as u64));
        data.extend_from_slice(item);
    }

    data
}

// ── Helpers ──────────────────────────────────────────────────────────

/// Extract push data from script bytes (after OP_RETURN).
///
/// Handles direct push (1–75 bytes), OP_PUSHDATA1, and OP_PUSHDATA2.
fn extract_push_data(bytes: &[u8]) -> Option<&[u8]> {
    if bytes.is_empty() {
        return None;
    }

    let first = bytes[0];

    match first {
        // Direct push: 1–75 bytes
        1..=75 => {
            let len = first as usize;
            if bytes.len() > len {
                Some(&bytes[1..1 + len])
            } else {
                None
            }
        }
        // OP_PUSHDATA1
        0x4c => {
            if bytes.len() < 2 {
                return None;
            }
            let len = bytes[1] as usize;
            if bytes.len() >= 2 + len {
                Some(&bytes[2..2 + len])
            } else {
                None
            }
        }
        // OP_PUSHDATA2
        0x4d => {
            if bytes.len() < 3 {
                return None;
            }
            let len = u16::from_le_bytes([bytes[1], bytes[2]]) as usize;
            if bytes.len() >= 3 + len {
                Some(&bytes[3..3 + len])
            } else {
                None
            }
        }
        _ => None,
    }
}

/// Read a Bitcoin compact size integer from a byte slice at the given offset.
///
/// Returns (value, bytes_consumed).
fn read_compact_size(data: &[u8], offset: usize) -> Result<(u64, usize), String> {
    if offset >= data.len() {
        return Err("unexpected end of data reading compact size".to_string());
    }

    let first = data[offset];
    match first {
        0x00..=0xfc => Ok((first as u64, 1)),
        0xfd => {
            if offset + 3 > data.len() {
                return Err("unexpected end of data for 2-byte compact size".to_string());
            }
            let val = u16::from_le_bytes([data[offset + 1], data[offset + 2]]);
            Ok((val as u64, 3))
        }
        0xfe => {
            if offset + 5 > data.len() {
                return Err("unexpected end of data for 4-byte compact size".to_string());
            }
            let val = u32::from_le_bytes([
                data[offset + 1],
                data[offset + 2],
                data[offset + 3],
                data[offset + 4],
            ]);
            Ok((val as u64, 5))
        }
        0xff => {
            if offset + 9 > data.len() {
                return Err("unexpected end of data for 8-byte compact size".to_string());
            }
            let val = u64::from_le_bytes([
                data[offset + 1],
                data[offset + 2],
                data[offset + 3],
                data[offset + 4],
                data[offset + 5],
                data[offset + 6],
                data[offset + 7],
                data[offset + 8],
            ]);
            Ok((val, 9))
        }
    }
}

/// Encode a value as a Bitcoin compact size.
fn encode_compact_size(value: u64) -> Vec<u8> {
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

// ── Signet block signing (P2WPKH challenge) ─────────────────────────

/// Sign a signet block for a P2WPKH challenge script.
///
/// Takes a block (with or without a placeholder signet commitment) and
/// produces a properly signed block by:
///
/// 1. Computing the block data hash (BIP325)
/// 2. Constructing virtual to_spend / to_sign transactions
/// 3. Computing the BIP143 sighash for P2WPKH
/// 4. Signing with ECDSA using the provided secret key
/// 5. Embedding the signed signet commitment in the coinbase
/// 6. Recomputing the merkle root
///
/// The `secret_key_bytes` must be 32 raw bytes of a valid secp256k1 secret
/// key whose corresponding compressed public key hashes to the P2WPKH
/// witness program in the challenge script.
///
/// # Returns
///
/// A new block with the signed signet commitment and updated merkle root,
/// or `SignetError` if signing fails.
pub fn sign_block_p2wpkh(
    block: &Block,
    challenge: &Script,
    secret_key_bytes: &[u8; 32],
) -> Result<Block, SignetError> {
    use crate::crypto::hashing::hash160;
    use crate::crypto::signing::{sighash_type, TransactionSignatureChecker};

    // Parse the secret key
    let secp = secp256k1::Secp256k1::new();
    let secret_key = secp256k1::SecretKey::from_slice(secret_key_bytes)
        .map_err(|e| SignetError::ChallengeScriptFailed(format!("invalid secret key: {}", e)))?;

    // Derive public key and P2PKH script code for BIP143 sighash
    let pubkey = secp256k1::PublicKey::from_secret_key(&secp, &secret_key);
    let compressed = pubkey.serialize();
    let pkh = hash160(&compressed);

    let mut p2pkh_script_bytes = vec![Opcodes::OP_DUP as u8, Opcodes::OP_HASH160 as u8, 20];
    p2pkh_script_bytes.extend_from_slice(&pkh);
    p2pkh_script_bytes.push(Opcodes::OP_EQUALVERIFY as u8);
    p2pkh_script_bytes.push(Opcodes::OP_CHECKSIG as u8);
    let script_code = Script::from_bytes(p2pkh_script_bytes);

    // Step 0: Ensure the block has a placeholder signet commitment.
    // The block data hash must be computed with a commitment output present
    // (stripped to bare OP_RETURN), so signer and verifier agree on the hash.
    let mut working_block = block.clone();
    if working_block.transactions.is_empty() {
        return Err(SignetError::EmptyBlock);
    }
    let has_commitment = working_block.transactions[0].outputs.iter().any(|o| {
        let sb = o.script_pubkey.as_bytes();
        if sb.is_empty() || sb[0] != Opcodes::OP_RETURN as u8 {
            return false;
        }
        extract_push_data(&sb[1..]).is_some_and(|d| d.len() >= 4 && d[..4] == SIGNET_HEADER)
    });
    if !has_commitment {
        let placeholder = build_signet_commitment(&Witness::new());
        working_block.transactions[0].outputs.push(placeholder);
        // Recompute merkle root with the placeholder
        let mr = working_block.compute_merkle_root();
        working_block.header.merkle_root = mr;
    }

    // Step 1: Compute block data hash (strips commitment to bare OP_RETURN)
    let block_data_hash = compute_block_data_hash(&working_block);

    // Step 2: Construct virtual transactions
    let to_spend = make_signet_to_spend(challenge, &block_data_hash);
    let to_spend_txid = to_spend.txid();

    // Temporary to_sign with empty witness (for sighash computation)
    let temp_to_sign = make_signet_to_sign(to_spend_txid, Witness::new());

    // Step 3: Compute BIP143 sighash
    let checker =
        TransactionSignatureChecker::new_witness_v0(&temp_to_sign, 0, Amount::from_sat(0));
    let sighash = checker.compute_sighash_witness_v0(&script_code, sighash_type::SIGHASH_ALL);

    // Step 4: Sign with ECDSA
    let message = secp256k1::Message::from_digest_slice(&sighash)
        .map_err(|e| SignetError::ChallengeScriptFailed(format!("invalid sighash: {}", e)))?;
    let ecdsa_sig = secp.sign_ecdsa(&message, &secret_key);
    let mut sig_bytes = ecdsa_sig.serialize_der().to_vec();
    sig_bytes.push(sighash_type::SIGHASH_ALL);

    // Step 5: Build witness solution [signature, pubkey]
    let mut solution = Witness::new();
    solution.push(sig_bytes);
    solution.push(compressed.to_vec());

    // Step 6: Build the real signet commitment output
    let commitment = build_signet_commitment(&solution);

    // Step 7: Replace the placeholder commitment with the signed one
    let coinbase = &mut working_block.transactions[0];
    for output in &mut coinbase.outputs {
        if output.script_pubkey.is_op_return() {
            let script_bytes = output.script_pubkey.as_bytes();
            if let Some(data) = extract_push_data(&script_bytes[1..]) {
                if data.len() >= 4 && data[..4] == SIGNET_HEADER {
                    *output = commitment.clone();
                    break;
                }
            }
        }
    }

    // Step 8: Recompute merkle root
    let merkle_root = working_block.compute_merkle_root();
    working_block.header.merkle_root = merkle_root;

    Ok(working_block)
}

// ── Tests ────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::signing::{sighash_type, TransactionSignatureChecker};
    use crate::primitives::{BlockHash, BlockHeader};
    use secp256k1::{Keypair, Secp256k1, SecretKey, XOnlyPublicKey};

    // ── Test helpers ──────────────────────────────────────────────

    /// Build a simple coinbase transaction with a BIP34 height-encoded scriptSig.
    fn make_coinbase(height: u32, outputs: Vec<TxOut>) -> Transaction {
        let mut script = Vec::new();
        if height <= 16 {
            script.push(0x50 + height as u8);
        } else {
            let mut h = height;
            let mut buf = Vec::new();
            while h > 0 {
                buf.push((h & 0xff) as u8);
                h >>= 8;
            }
            if buf.last().map_or(false, |&b| b & 0x80 != 0) {
                buf.push(0);
            }
            script.push(buf.len() as u8);
            script.extend_from_slice(&buf);
        }
        while script.len() < 2 {
            script.push(0x00);
        }

        Transaction::coinbase(height, Script::from_bytes(script), outputs)
    }

    /// Build a block with the given coinbase and regtest-like header.
    fn make_test_block(coinbase: Transaction) -> Block {
        let header = BlockHeader::new(
            0x20000000,
            BlockHash::zero(),
            Hash256::zero(),
            1231006505,
            0x207fffff, // regtest difficulty
            0,
        );
        let mut block = Block::new(header, vec![coinbase]);
        let merkle_root = block.compute_merkle_root();
        block.header.merkle_root = merkle_root;
        block
    }

    /// Build a signet commitment output from a witness solution.
    fn make_signet_output(solution: &Witness) -> TxOut {
        build_signet_commitment(solution)
    }

    /// Create a P2WPKH challenge script for a given public key hash.
    fn make_p2wpkh_challenge(pubkey_hash: &[u8; 20]) -> Script {
        let mut bytes = vec![0x00, 0x14]; // OP_0, push 20
        bytes.extend_from_slice(pubkey_hash);
        Script::from_bytes(bytes)
    }

    /// Generate a secp256k1 keypair and return (secret_key, x_only_pubkey_bytes, full_pubkey_bytes).
    fn generate_test_keypair() -> (SecretKey, [u8; 32], Vec<u8>) {
        let secret = SecretKey::from_slice(&[0x42; 32]).unwrap();
        let secp = Secp256k1::new();
        let keypair = Keypair::from_secret_key(&secp, &secret);
        let (xonly, _) = XOnlyPublicKey::from_keypair(&keypair);
        let pubkey = secp256k1::PublicKey::from_secret_key(&secp, &secret);
        let compressed = pubkey.serialize();
        (secret, xonly.serialize(), compressed.to_vec())
    }

    /// Compute hash160 of a compressed pubkey for P2WPKH.
    fn pubkey_hash(compressed_pubkey: &[u8]) -> [u8; 20] {
        crate::crypto::hashing::hash160(compressed_pubkey)
    }

    // ── Tests: extract_signet_solution ────────────────────────────

    #[test]
    fn test_extract_signet_solution_valid() {
        let solution_data = vec![0x01, 0x02, 0x03, 0x04, 0x05];
        let mut commitment_data = SIGNET_HEADER.to_vec();
        commitment_data.extend_from_slice(&solution_data);

        let commitment_script = ScriptBuilder::new()
            .push_opcode(Opcodes::OP_RETURN)
            .push_slice(&commitment_data)
            .build();

        let coinbase = make_coinbase(
            1,
            vec![
                TxOut::new(Amount::from_sat(5_000_000_000), Script::new()),
                TxOut::new(Amount::from_sat(0), commitment_script),
            ],
        );

        let block = make_test_block(coinbase);
        let extracted = extract_signet_solution(&block).unwrap();
        assert_eq!(extracted, solution_data);
    }

    #[test]
    fn test_extract_signet_solution_missing() {
        // Block with no signet commitment
        let coinbase = make_coinbase(
            1,
            vec![TxOut::new(Amount::from_sat(5_000_000_000), Script::new())],
        );
        let block = make_test_block(coinbase);

        let result = extract_signet_solution(&block);
        assert_eq!(result, Err(SignetError::MissingSignetSolution));
    }

    #[test]
    fn test_extract_signet_solution_wrong_header() {
        // OP_RETURN with wrong magic
        let mut wrong_data = vec![0xDE, 0xAD, 0xBE, 0xEF];
        wrong_data.extend_from_slice(&[0x01, 0x02]);

        let script = ScriptBuilder::new()
            .push_opcode(Opcodes::OP_RETURN)
            .push_slice(&wrong_data)
            .build();

        let coinbase = make_coinbase(
            1,
            vec![
                TxOut::new(Amount::from_sat(5_000_000_000), Script::new()),
                TxOut::new(Amount::from_sat(0), script),
            ],
        );
        let block = make_test_block(coinbase);

        let result = extract_signet_solution(&block);
        assert_eq!(result, Err(SignetError::MissingSignetSolution));
    }

    #[test]
    fn test_extract_signet_solution_empty_block() {
        let header = BlockHeader::new(
            0x20000000,
            BlockHash::zero(),
            Hash256::zero(),
            0,
            0x207fffff,
            0,
        );
        let block = Block::new(header, vec![]);
        let result = extract_signet_solution(&block);
        assert_eq!(result, Err(SignetError::EmptyBlock));
    }

    // ── Tests: compute_block_data_hash ───────────────────────────

    #[test]
    fn test_compute_block_data_hash_deterministic() {
        let witness = Witness::new();
        let commitment = make_signet_output(&witness);

        let coinbase = make_coinbase(
            1,
            vec![
                TxOut::new(Amount::from_sat(5_000_000_000), Script::new()),
                commitment,
            ],
        );
        let block = make_test_block(coinbase);

        let hash1 = compute_block_data_hash(&block);
        let hash2 = compute_block_data_hash(&block);
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_compute_block_data_hash_changes_with_different_data() {
        // Two blocks with different timestamps should yield different hashes
        let witness = Witness::new();
        let commitment = make_signet_output(&witness);

        let coinbase = make_coinbase(
            1,
            vec![
                TxOut::new(Amount::from_sat(5_000_000_000), Script::new()),
                commitment.clone(),
            ],
        );

        let header1 = BlockHeader::new(
            0x20000000,
            BlockHash::zero(),
            Hash256::zero(),
            100,
            0x207fffff,
            0,
        );
        let mut block1 = Block::new(header1, vec![coinbase.clone()]);
        block1.header.merkle_root = block1.compute_merkle_root();

        let header2 = BlockHeader::new(
            0x20000000,
            BlockHash::zero(),
            Hash256::zero(),
            200,
            0x207fffff,
            0,
        );
        let mut block2 = Block::new(header2, vec![coinbase]);
        block2.header.merkle_root = block2.compute_merkle_root();

        assert_ne!(
            compute_block_data_hash(&block1),
            compute_block_data_hash(&block2)
        );
    }

    #[test]
    fn test_compute_block_data_hash_strips_signet_data() {
        // Hash should be the same regardless of what solution data is in the commitment
        let mut witness1 = Witness::new();
        witness1.push(vec![0xAA; 64]);
        let commitment1 = make_signet_output(&witness1);

        let mut witness2 = Witness::new();
        witness2.push(vec![0xBB; 64]);
        let commitment2 = make_signet_output(&witness2);

        let coinbase1 = make_coinbase(
            1,
            vec![
                TxOut::new(Amount::from_sat(5_000_000_000), Script::new()),
                commitment1,
            ],
        );
        let coinbase2 = make_coinbase(
            1,
            vec![
                TxOut::new(Amount::from_sat(5_000_000_000), Script::new()),
                commitment2,
            ],
        );

        let block1 = make_test_block(coinbase1);
        let block2 = make_test_block(coinbase2);

        // After stripping the signet data, both should produce the same hash
        // because the commitment output is replaced with bare OP_RETURN
        assert_eq!(
            compute_block_data_hash(&block1),
            compute_block_data_hash(&block2)
        );
    }

    // ── Tests: make_to_spend / make_to_sign structure ────────────

    #[test]
    fn test_make_to_spend_structure() {
        let challenge = Script::from_bytes(vec![0x51]); // OP_1
        let block_data_hash = Hash256::from_bytes([0xAA; 32]);

        let to_spend = make_signet_to_spend(&challenge, &block_data_hash);

        assert_eq!(to_spend.version, 0);
        assert_eq!(to_spend.inputs.len(), 1);
        assert_eq!(to_spend.outputs.len(), 1);
        assert_eq!(to_spend.lock_time, 0);

        // Input: outpoint = (block_data_hash, 0xFFFFFFFF)
        assert_eq!(
            to_spend.inputs[0].previous_output.txid,
            Txid::from_hash(block_data_hash)
        );
        assert_eq!(to_spend.inputs[0].previous_output.vout, 0xFFFFFFFF);
        assert!(to_spend.inputs[0].script_sig.is_empty());
        assert_eq!(to_spend.inputs[0].sequence, 0);

        // Output: value = 0, scriptPubKey = challenge
        assert_eq!(to_spend.outputs[0].value.as_sat(), 0);
        assert_eq!(to_spend.outputs[0].script_pubkey, challenge);
    }

    #[test]
    fn test_make_to_sign_structure() {
        let to_spend_txid = Txid::from_hash(Hash256::from_bytes([0xBB; 32]));
        let mut witness = Witness::new();
        witness.push(vec![0x01, 0x02, 0x03]);

        let to_sign = make_signet_to_sign(to_spend_txid, witness.clone());

        assert_eq!(to_sign.version, 0);
        assert_eq!(to_sign.inputs.len(), 1);
        assert_eq!(to_sign.outputs.len(), 1);
        assert_eq!(to_sign.lock_time, 0);

        // Input: spends to_spend output 0
        assert_eq!(to_sign.inputs[0].previous_output.txid, to_spend_txid);
        assert_eq!(to_sign.inputs[0].previous_output.vout, 0);
        assert!(to_sign.inputs[0].script_sig.is_empty());
        assert_eq!(to_sign.inputs[0].sequence, 0);

        // Witness should match
        assert_eq!(to_sign.inputs[0].witness, witness);

        // Output: OP_RETURN
        assert!(to_sign.outputs[0].script_pubkey.is_op_return());
        assert_eq!(to_sign.outputs[0].value.as_sat(), 0);
    }

    // ── Tests: parse_witness_solution ────────────────────────────

    #[test]
    fn test_parse_witness_solution_empty() {
        // 0 items
        let data = vec![0x00];
        let witness = parse_witness_solution(&data).unwrap();
        assert!(witness.is_empty());
    }

    #[test]
    fn test_parse_witness_solution_single_item() {
        // 1 item, 3 bytes: [0x01, 0x02, 0x03]
        let data = vec![0x01, 0x03, 0x01, 0x02, 0x03];
        let witness = parse_witness_solution(&data).unwrap();
        assert_eq!(witness.len(), 1);
        assert_eq!(witness.get(0), Some(&[0x01, 0x02, 0x03][..]));
    }

    #[test]
    fn test_parse_witness_solution_two_items() {
        // 2 items:
        //   item 0: empty (0 bytes)
        //   item 1: [0xAA, 0xBB] (2 bytes)
        let data = vec![0x02, 0x00, 0x02, 0xAA, 0xBB];
        let witness = parse_witness_solution(&data).unwrap();
        assert_eq!(witness.len(), 2);
        assert_eq!(witness.get(0), Some(&[][..]));
        assert_eq!(witness.get(1), Some(&[0xAA, 0xBB][..]));
    }

    #[test]
    fn test_parse_witness_solution_truncated() {
        // Claims 1 item of 10 bytes but only has 2
        let data = vec![0x01, 0x0A, 0x01, 0x02];
        let result = parse_witness_solution(&data);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_witness_roundtrip() {
        let mut original = Witness::new();
        original.push(vec![]);
        original.push(vec![0x30, 0x44]); // fake DER sig bytes
        original.push(vec![0x02, 0x21]); // fake pubkey bytes

        let serialized = serialize_witness_stack(&original);
        let parsed = parse_witness_solution(&serialized).unwrap();

        assert_eq!(parsed.len(), original.len());
        for i in 0..original.len() {
            assert_eq!(parsed.get(i), original.get(i));
        }
    }

    // ── Tests: build_signet_commitment ───────────────────────────

    #[test]
    fn test_build_signet_commitment() {
        let mut witness = Witness::new();
        witness.push(vec![0xAA; 64]);

        let output = build_signet_commitment(&witness);

        // Should be OP_RETURN with signet header + serialized witness
        assert!(output.script_pubkey.is_op_return());
        assert_eq!(output.value.as_sat(), 0);

        // Extract and verify the data
        let script_bytes = output.script_pubkey.as_bytes();
        let data = extract_push_data(&script_bytes[1..]).unwrap();
        assert_eq!(&data[..4], &SIGNET_HEADER);
    }

    // ── Tests: validate_signet_block (end-to-end) ────────────────

    #[test]
    fn test_validate_signet_block_trivial_challenge() {
        // Use OP_TRUE (OP_1) as the challenge — any solution (even empty) passes
        let challenge = Script::from_bytes(vec![Opcodes::OP_1 as u8]);

        // Build solution: empty witness (OP_TRUE doesn't need witness data)
        let solution = Witness::new();
        let commitment = build_signet_commitment(&solution);

        let coinbase = make_coinbase(
            1,
            vec![
                TxOut::new(Amount::from_sat(5_000_000_000), Script::new()),
                commitment,
            ],
        );
        let block = make_test_block(coinbase);

        let result = validate_signet_block(&block, &challenge);
        assert!(
            result.is_ok(),
            "OP_TRUE challenge should pass: {:?}",
            result
        );
    }

    #[test]
    fn test_validate_signet_block_no_solution() {
        // Block without signet commitment should fail
        let challenge = Script::from_bytes(vec![Opcodes::OP_1 as u8]);

        let coinbase = make_coinbase(
            1,
            vec![TxOut::new(Amount::from_sat(5_000_000_000), Script::new())],
        );
        let block = make_test_block(coinbase);

        let result = validate_signet_block(&block, &challenge);
        assert_eq!(result, Err(SignetError::MissingSignetSolution));
    }

    #[test]
    fn test_validate_signet_block_op_false_challenge_fails() {
        // OP_0 challenge should always fail (pushes false)
        let challenge = Script::from_bytes(vec![Opcodes::OP_0 as u8]);

        let solution = Witness::new();
        let commitment = build_signet_commitment(&solution);

        let coinbase = make_coinbase(
            1,
            vec![
                TxOut::new(Amount::from_sat(5_000_000_000), Script::new()),
                commitment,
            ],
        );
        let block = make_test_block(coinbase);

        let result = validate_signet_block(&block, &challenge);
        assert!(result.is_err(), "OP_FALSE challenge should fail");
    }

    #[test]
    fn test_validate_signet_block_p2wpkh_valid() {
        // Full end-to-end test with P2WPKH challenge:
        // 1. Generate keypair
        // 2. Create P2WPKH challenge
        // 3. Build block with placeholder commitment
        // 4. Compute sighash and sign
        // 5. Rebuild block with real commitment
        // 6. Validate

        let (secret_key, _xonly, compressed_pubkey) = generate_test_keypair();
        let pkh = pubkey_hash(&compressed_pubkey);
        let challenge = make_p2wpkh_challenge(&pkh);

        // Step 1: Build block with empty commitment placeholder
        let placeholder_witness = Witness::new();
        let placeholder_commitment = build_signet_commitment(&placeholder_witness);

        let coinbase_placeholder = make_coinbase(
            1,
            vec![
                TxOut::new(Amount::from_sat(5_000_000_000), Script::new()),
                placeholder_commitment,
            ],
        );
        let block_template = make_test_block(coinbase_placeholder);

        // Step 2: Compute block data hash (same regardless of solution content)
        let block_data_hash = compute_block_data_hash(&block_template);

        // Step 3: Construct virtual transactions
        let to_spend = make_signet_to_spend(&challenge, &block_data_hash);
        let to_spend_txid = to_spend.txid();

        // Step 4: Compute sighash for the to_sign transaction
        // For P2WPKH, we need a BIP143 sighash with the implicit P2PKH script
        let mut p2pkh_script_code = vec![Opcodes::OP_DUP as u8, Opcodes::OP_HASH160 as u8, 20];
        p2pkh_script_code.extend_from_slice(&pkh);
        p2pkh_script_code.push(Opcodes::OP_EQUALVERIFY as u8);
        p2pkh_script_code.push(Opcodes::OP_CHECKSIG as u8);
        let script_code = Script::from_bytes(p2pkh_script_code);

        // Build a temporary to_sign with empty witness to compute sighash
        let temp_to_sign = make_signet_to_sign(to_spend_txid, Witness::new());
        let checker =
            TransactionSignatureChecker::new_witness_v0(&temp_to_sign, 0, Amount::from_sat(0));
        let sighash = checker.compute_sighash_witness_v0(&script_code, sighash_type::SIGHASH_ALL);

        // Step 5: Sign with ECDSA
        let secp = Secp256k1::new();
        let message = secp256k1::Message::from_digest_slice(&sighash).unwrap();
        let ecdsa_sig = secp.sign_ecdsa(&message, &secret_key);
        let mut sig_bytes = ecdsa_sig.serialize_der().to_vec();
        sig_bytes.push(sighash_type::SIGHASH_ALL); // append sighash type

        // Step 6: Build witness solution [signature, pubkey]
        let mut solution = Witness::new();
        solution.push(sig_bytes);
        solution.push(compressed_pubkey.clone());

        // Step 7: Build the real block with the signed commitment
        let real_commitment = build_signet_commitment(&solution);
        let coinbase_real = make_coinbase(
            1,
            vec![
                TxOut::new(Amount::from_sat(5_000_000_000), Script::new()),
                real_commitment,
            ],
        );
        let real_block = make_test_block(coinbase_real);

        // Step 8: Validate
        let result = validate_signet_block(&real_block, &challenge);
        assert!(
            result.is_ok(),
            "P2WPKH signet validation should pass: {:?}",
            result
        );
    }

    #[test]
    fn test_validate_signet_block_p2wpkh_wrong_key() {
        // Sign with wrong key — should fail
        let (_, _, compressed_pubkey) = generate_test_keypair();
        let pkh = pubkey_hash(&compressed_pubkey);
        let challenge = make_p2wpkh_challenge(&pkh);

        // Use a DIFFERENT key to sign
        let wrong_secret = SecretKey::from_slice(&[0x99; 32]).unwrap();
        let secp = Secp256k1::new();
        let wrong_pubkey = secp256k1::PublicKey::from_secret_key(&secp, &wrong_secret);
        let wrong_compressed = wrong_pubkey.serialize().to_vec();

        // Build placeholder block
        let placeholder = build_signet_commitment(&Witness::new());
        let coinbase = make_coinbase(
            1,
            vec![
                TxOut::new(Amount::from_sat(5_000_000_000), Script::new()),
                placeholder,
            ],
        );
        let block_template = make_test_block(coinbase);

        let block_data_hash = compute_block_data_hash(&block_template);
        let to_spend = make_signet_to_spend(&challenge, &block_data_hash);
        let to_spend_txid = to_spend.txid();

        // Compute sighash with the correct P2PKH script code
        let mut p2pkh_script = vec![Opcodes::OP_DUP as u8, Opcodes::OP_HASH160 as u8, 20];
        p2pkh_script.extend_from_slice(&pkh);
        p2pkh_script.push(Opcodes::OP_EQUALVERIFY as u8);
        p2pkh_script.push(Opcodes::OP_CHECKSIG as u8);

        let temp_to_sign = make_signet_to_sign(to_spend_txid, Witness::new());
        let checker =
            TransactionSignatureChecker::new_witness_v0(&temp_to_sign, 0, Amount::from_sat(0));
        let sighash = checker.compute_sighash_witness_v0(
            &Script::from_bytes(p2pkh_script),
            sighash_type::SIGHASH_ALL,
        );

        // Sign with wrong key
        let message = secp256k1::Message::from_digest_slice(&sighash).unwrap();
        let ecdsa_sig = secp.sign_ecdsa(&message, &wrong_secret);
        let mut sig_bytes = ecdsa_sig.serialize_der().to_vec();
        sig_bytes.push(sighash_type::SIGHASH_ALL);

        // Witness with wrong pubkey
        let mut solution = Witness::new();
        solution.push(sig_bytes);
        solution.push(wrong_compressed);

        let commitment = build_signet_commitment(&solution);
        let coinbase_real = make_coinbase(
            1,
            vec![
                TxOut::new(Amount::from_sat(5_000_000_000), Script::new()),
                commitment,
            ],
        );
        let real_block = make_test_block(coinbase_real);

        let result = validate_signet_block(&real_block, &challenge);
        assert!(result.is_err(), "wrong key should fail validation");
    }

    #[test]
    fn test_validate_signet_block_custom_challenge() {
        // Use OP_2 OP_EQUAL as challenge — solution must push 2 onto the stack
        // This is a bare script challenge (not witness program)
        // For bare scripts, the witness data is ignored, so we need the solution
        // pushed via scriptSig. But BIP325 uses witness...
        //
        // For non-witness-program challenges, verification with empty scriptSig
        // and the challenge as scriptPubKey will just evaluate the challenge.
        // If the challenge is self-sufficient (like OP_1), it works without any
        // additional input.
        let challenge = Script::from_bytes(vec![
            Opcodes::OP_1 as u8,
            Opcodes::OP_1 as u8,
            Opcodes::OP_EQUAL as u8,
        ]);

        let solution = Witness::new();
        let commitment = build_signet_commitment(&solution);

        let coinbase = make_coinbase(
            1,
            vec![
                TxOut::new(Amount::from_sat(5_000_000_000), Script::new()),
                commitment,
            ],
        );
        let block = make_test_block(coinbase);

        let result = validate_signet_block(&block, &challenge);
        assert!(
            result.is_ok(),
            "OP_1 OP_1 OP_EQUAL challenge should pass: {:?}",
            result
        );
    }

    // ── Tests: sign_block_p2wpkh ──────────────────────────────────

    #[test]
    fn test_sign_block_p2wpkh_and_validate() {
        // End-to-end: sign a block using sign_block_p2wpkh, then validate it
        let secret_key_bytes = [0x42u8; 32];
        let secret_key = SecretKey::from_slice(&secret_key_bytes).unwrap();
        let secp = Secp256k1::new();
        let pubkey = secp256k1::PublicKey::from_secret_key(&secp, &secret_key);
        let compressed = pubkey.serialize();
        let pkh = pubkey_hash(&compressed);
        let challenge = make_p2wpkh_challenge(&pkh);

        // Build a block with a placeholder commitment
        let placeholder = build_signet_commitment(&Witness::new());
        let coinbase = make_coinbase(
            1,
            vec![
                TxOut::new(Amount::from_sat(5_000_000_000), Script::new()),
                placeholder,
            ],
        );
        let block_template = make_test_block(coinbase);

        // Sign it
        let signed = sign_block_p2wpkh(&block_template, &challenge, &secret_key_bytes).unwrap();

        // Validate it
        let result = validate_signet_block(&signed, &challenge);
        assert!(
            result.is_ok(),
            "sign_block_p2wpkh output should validate: {:?}",
            result
        );
    }

    #[test]
    fn test_sign_block_p2wpkh_no_placeholder() {
        // Block WITHOUT a placeholder commitment — should add one
        let secret_key_bytes = [0x42u8; 32];
        let secret_key = SecretKey::from_slice(&secret_key_bytes).unwrap();
        let secp = Secp256k1::new();
        let pubkey = secp256k1::PublicKey::from_secret_key(&secp, &secret_key);
        let compressed = pubkey.serialize();
        let pkh = pubkey_hash(&compressed);
        let challenge = make_p2wpkh_challenge(&pkh);

        let coinbase = make_coinbase(
            1,
            vec![TxOut::new(Amount::from_sat(5_000_000_000), Script::new())],
        );
        let block_template = make_test_block(coinbase);

        // Sign it — should add commitment
        let signed = sign_block_p2wpkh(&block_template, &challenge, &secret_key_bytes).unwrap();

        // Should have 2 outputs now (subsidy + commitment)
        assert_eq!(signed.transactions[0].outputs.len(), 2);

        // Validate it
        let result = validate_signet_block(&signed, &challenge);
        assert!(
            result.is_ok(),
            "sign_block_p2wpkh should add commitment: {:?}",
            result
        );
    }

    #[test]
    fn test_sign_block_p2wpkh_wrong_key_fails_validation() {
        // Sign with key A, validate against challenge for key B
        let key_a_bytes = [0x42u8; 32];
        let key_a = SecretKey::from_slice(&key_a_bytes).unwrap();
        let secp = Secp256k1::new();
        let pubkey_a = secp256k1::PublicKey::from_secret_key(&secp, &key_a);
        let pkh_a = pubkey_hash(&pubkey_a.serialize());
        let challenge_a = make_p2wpkh_challenge(&pkh_a);

        // Different key for a different challenge
        let key_b_bytes = [0x99u8; 32];
        let key_b = SecretKey::from_slice(&key_b_bytes).unwrap();
        let pubkey_b = secp256k1::PublicKey::from_secret_key(&secp, &key_b);
        let pkh_b = pubkey_hash(&pubkey_b.serialize());
        let challenge_b = make_p2wpkh_challenge(&pkh_b);

        let placeholder = build_signet_commitment(&Witness::new());
        let coinbase = make_coinbase(
            1,
            vec![
                TxOut::new(Amount::from_sat(5_000_000_000), Script::new()),
                placeholder,
            ],
        );
        let block_template = make_test_block(coinbase);

        // Sign with key A
        let signed = sign_block_p2wpkh(&block_template, &challenge_a, &key_a_bytes).unwrap();

        // Validate against challenge B — should fail
        let result = validate_signet_block(&signed, &challenge_b);
        assert!(result.is_err(), "wrong challenge should fail validation");
    }

    // ── Tests: compact size helpers ──────────────────────────────

    #[test]
    fn test_compact_size_roundtrip() {
        for val in [0u64, 1, 252, 253, 0xffff, 0x10000, 0xffffffff, 0x100000000] {
            let encoded = encode_compact_size(val);
            let (decoded, consumed) = read_compact_size(&encoded, 0).unwrap();
            assert_eq!(decoded, val);
            assert_eq!(consumed, encoded.len());
        }
    }
}
