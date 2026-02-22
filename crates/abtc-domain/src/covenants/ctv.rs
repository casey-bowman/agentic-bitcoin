//! BIP119 — OP_CHECKTEMPLATEVERIFY (CTV)
//!
//! CTV allows a scriptPubKey to commit to the exact structure of the
//! spending transaction. The opcode pops a 32-byte hash from the stack
//! and verifies it matches the `DefaultCheckTemplateVerifyHash` computed
//! from the spending transaction.
//!
//! ## Template hash computation
//!
//! The hash commits to (all in little-endian):
//!
//! ```text
//! SHA-256(
//!   nVersion         (4 bytes, LE i32)
//!   nLockTime        (4 bytes, LE u32)
//!   scriptSigs hash  (32 bytes, SHA-256 of all serialized scriptSigs)
//!                    — only if any scriptSig is non-empty
//!   input count      (4 bytes, LE u32)
//!   sequences hash   (32 bytes, SHA-256 of all serialized sequences)
//!   output count     (4 bytes, LE u32)
//!   outputs hash     (32 bytes, SHA-256 of all serialized outputs)
//!   input index      (4 bytes, LE u32)
//! )
//! ```
//!
//! This design ensures the spending transaction matches exactly:
//! the outputs (who gets paid), the locktime, the number of inputs
//! (preventing fee-sniping attacks), and which input is executing.

use crate::crypto::hashing::sha256;
use crate::primitives::{Hash256, Transaction};

/// Compute the BIP119 DefaultCheckTemplateVerifyHash for a transaction.
///
/// This is the hash that OP_CHECKTEMPLATEVERIFY pops from the stack and
/// compares against the spending transaction.
///
/// # Arguments
/// * `tx` — the spending transaction
/// * `input_index` — the index of the input executing the CTV script
pub fn compute_ctv_hash(tx: &Transaction, input_index: u32) -> Hash256 {
    let mut preimage = Vec::with_capacity(200);

    // 1. nVersion (4 bytes LE)
    preimage.extend_from_slice(&tx.version.to_le_bytes());

    // 2. nLockTime (4 bytes LE)
    preimage.extend_from_slice(&tx.lock_time.to_le_bytes());

    // 3. scriptSigs hash — only if any scriptSig is non-empty
    let has_scriptsigs = tx.inputs.iter().any(|inp| !inp.script_sig.is_empty());
    if has_scriptsigs {
        let scriptsigs_hash = hash_scriptsigs(tx);
        preimage.extend_from_slice(scriptsigs_hash.as_bytes());
    }

    // 4. Input count (4 bytes LE)
    preimage.extend_from_slice(&(tx.inputs.len() as u32).to_le_bytes());

    // 5. Sequences hash (SHA-256 of all sequences concatenated)
    let sequences_hash = hash_sequences(tx);
    preimage.extend_from_slice(sequences_hash.as_bytes());

    // 6. Output count (4 bytes LE)
    preimage.extend_from_slice(&(tx.outputs.len() as u32).to_le_bytes());

    // 7. Outputs hash (SHA-256 of all serialized outputs)
    let outputs_hash = hash_outputs(tx);
    preimage.extend_from_slice(outputs_hash.as_bytes());

    // 8. Input index (4 bytes LE)
    preimage.extend_from_slice(&input_index.to_le_bytes());

    sha256(&preimage)
}

/// SHA-256 of all scriptSigs concatenated.
///
/// Each scriptSig is serialized as: `compact_size(len) || bytes`.
fn hash_scriptsigs(tx: &Transaction) -> Hash256 {
    let mut data = Vec::new();
    for input in &tx.inputs {
        let script_bytes = input.script_sig.as_bytes();
        push_compact_size(&mut data, script_bytes.len() as u64);
        data.extend_from_slice(script_bytes);
    }
    sha256(&data)
}

/// SHA-256 of all sequence numbers concatenated (each 4 bytes LE).
fn hash_sequences(tx: &Transaction) -> Hash256 {
    let mut data = Vec::with_capacity(tx.inputs.len() * 4);
    for input in &tx.inputs {
        data.extend_from_slice(&input.sequence.to_le_bytes());
    }
    sha256(&data)
}

/// SHA-256 of all outputs serialized.
///
/// Each output is serialized as: `amount(8 LE) || compact_size(script_len) || script`.
fn hash_outputs(tx: &Transaction) -> Hash256 {
    let mut data = Vec::new();
    for output in &tx.outputs {
        data.extend_from_slice(&output.value.as_sat().to_le_bytes());
        let script_bytes = output.script_pubkey.as_bytes();
        push_compact_size(&mut data, script_bytes.len() as u64);
        data.extend_from_slice(script_bytes);
    }
    sha256(&data)
}

/// Write a Bitcoin compact size integer.
fn push_compact_size(buf: &mut Vec<u8>, n: u64) {
    if n < 253 {
        buf.push(n as u8);
    } else if n <= 0xFFFF {
        buf.push(0xFD);
        buf.extend_from_slice(&(n as u16).to_le_bytes());
    } else if n <= 0xFFFF_FFFF {
        buf.push(0xFE);
        buf.extend_from_slice(&(n as u32).to_le_bytes());
    } else {
        buf.push(0xFF);
        buf.extend_from_slice(&n.to_le_bytes());
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::primitives::{Amount, OutPoint, TxIn, TxOut, Txid};
    use crate::script::Script;

    fn make_simple_tx(
        num_inputs: usize,
        outputs: Vec<TxOut>,
        lock_time: u32,
    ) -> Transaction {
        let inputs: Vec<TxIn> = (0..num_inputs)
            .map(|i| {
                let mut txid_bytes = [0u8; 32];
                txid_bytes[0] = i as u8;
                TxIn::new(
                    OutPoint::new(Txid::from_hash(Hash256::from_bytes(txid_bytes)), 0),
                    Script::new(),
                    0xfffffffe,
                )
            })
            .collect();

        Transaction::new(2, inputs, outputs, lock_time)
    }

    #[test]
    fn test_ctv_hash_deterministic() {
        let tx = make_simple_tx(
            1,
            vec![TxOut::new(Amount::from_sat(100_000), Script::from_bytes(vec![0x51]))],
            0,
        );
        let h1 = compute_ctv_hash(&tx, 0);
        let h2 = compute_ctv_hash(&tx, 0);
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_ctv_hash_changes_with_outputs() {
        let tx1 = make_simple_tx(
            1,
            vec![TxOut::new(Amount::from_sat(100_000), Script::from_bytes(vec![0x51]))],
            0,
        );
        let tx2 = make_simple_tx(
            1,
            vec![TxOut::new(Amount::from_sat(200_000), Script::from_bytes(vec![0x51]))],
            0,
        );
        assert_ne!(compute_ctv_hash(&tx1, 0), compute_ctv_hash(&tx2, 0));
    }

    #[test]
    fn test_ctv_hash_changes_with_locktime() {
        let tx1 = make_simple_tx(
            1,
            vec![TxOut::new(Amount::from_sat(100_000), Script::new())],
            0,
        );
        let tx2 = make_simple_tx(
            1,
            vec![TxOut::new(Amount::from_sat(100_000), Script::new())],
            500_000,
        );
        assert_ne!(compute_ctv_hash(&tx1, 0), compute_ctv_hash(&tx2, 0));
    }

    #[test]
    fn test_ctv_hash_changes_with_input_index() {
        let tx = make_simple_tx(
            2,
            vec![TxOut::new(Amount::from_sat(100_000), Script::new())],
            0,
        );
        let h0 = compute_ctv_hash(&tx, 0);
        let h1 = compute_ctv_hash(&tx, 1);
        assert_ne!(h0, h1);
    }

    #[test]
    fn test_ctv_hash_changes_with_input_count() {
        let tx1 = make_simple_tx(
            1,
            vec![TxOut::new(Amount::from_sat(100_000), Script::new())],
            0,
        );
        let tx2 = make_simple_tx(
            2,
            vec![TxOut::new(Amount::from_sat(100_000), Script::new())],
            0,
        );
        assert_ne!(compute_ctv_hash(&tx1, 0), compute_ctv_hash(&tx2, 0));
    }

    #[test]
    fn test_ctv_hash_changes_with_version() {
        let outputs = vec![TxOut::new(Amount::from_sat(100_000), Script::new())];
        let inputs = vec![TxIn::new(
            OutPoint::new(Txid::zero(), 0),
            Script::new(),
            0xfffffffe,
        )];
        let tx1 = Transaction::new(1, inputs.clone(), outputs.clone(), 0);
        let tx2 = Transaction::new(2, inputs, outputs, 0);
        assert_ne!(compute_ctv_hash(&tx1, 0), compute_ctv_hash(&tx2, 0));
    }

    #[test]
    fn test_ctv_hash_includes_scriptsig_when_nonempty() {
        let outputs = vec![TxOut::new(Amount::from_sat(50_000), Script::new())];
        let mut inputs1 = vec![TxIn::new(
            OutPoint::new(Txid::zero(), 0),
            Script::new(),
            0xfffffffe,
        )];
        let tx1 = Transaction::new(2, inputs1.clone(), outputs.clone(), 0);

        // Add a non-empty scriptSig
        inputs1[0] = TxIn::new(
            OutPoint::new(Txid::zero(), 0),
            Script::from_bytes(vec![0x01, 0x42]),
            0xfffffffe,
        );
        let tx2 = Transaction::new(2, inputs1, outputs, 0);

        // The hashes must differ because tx2 has a non-empty scriptSig
        // which adds the scriptSigs hash to the preimage
        assert_ne!(compute_ctv_hash(&tx1, 0), compute_ctv_hash(&tx2, 0));
    }

    #[test]
    fn test_ctv_hash_changes_with_sequence() {
        let outputs = vec![TxOut::new(Amount::from_sat(50_000), Script::new())];
        let tx1 = Transaction::new(
            2,
            vec![TxIn::new(OutPoint::new(Txid::zero(), 0), Script::new(), 0xfffffffe)],
            outputs.clone(),
            0,
        );
        let tx2 = Transaction::new(
            2,
            vec![TxIn::new(OutPoint::new(Txid::zero(), 0), Script::new(), 0x00000001)],
            outputs,
            0,
        );
        assert_ne!(compute_ctv_hash(&tx1, 0), compute_ctv_hash(&tx2, 0));
    }

    #[test]
    fn test_ctv_hash_nonzero() {
        let tx = make_simple_tx(
            1,
            vec![TxOut::new(Amount::from_sat(1), Script::new())],
            0,
        );
        let hash = compute_ctv_hash(&tx, 0);
        assert_ne!(hash, Hash256::zero());
    }

    #[test]
    fn test_ctv_hash_multiple_outputs() {
        let tx = make_simple_tx(
            1,
            vec![
                TxOut::new(Amount::from_sat(60_000), Script::from_bytes(vec![0x76, 0xa9])),
                TxOut::new(Amount::from_sat(30_000), Script::from_bytes(vec![0x00, 0x14])),
                TxOut::new(Amount::from_sat(10_000), Script::from_bytes(vec![0x6a, 0x04])),
            ],
            0,
        );
        let hash = compute_ctv_hash(&tx, 0);
        assert_ne!(hash, Hash256::zero());

        // Swapping output order changes the hash
        let tx_swapped = make_simple_tx(
            1,
            vec![
                TxOut::new(Amount::from_sat(30_000), Script::from_bytes(vec![0x00, 0x14])),
                TxOut::new(Amount::from_sat(60_000), Script::from_bytes(vec![0x76, 0xa9])),
                TxOut::new(Amount::from_sat(10_000), Script::from_bytes(vec![0x6a, 0x04])),
            ],
            0,
        );
        assert_ne!(compute_ctv_hash(&tx, 0), compute_ctv_hash(&tx_swapped, 0));
    }

    #[test]
    fn test_compact_size_encoding() {
        let mut buf = Vec::new();
        push_compact_size(&mut buf, 0);
        assert_eq!(buf, vec![0x00]);

        buf.clear();
        push_compact_size(&mut buf, 252);
        assert_eq!(buf, vec![252]);

        buf.clear();
        push_compact_size(&mut buf, 253);
        assert_eq!(buf, vec![0xFD, 253, 0]);

        buf.clear();
        push_compact_size(&mut buf, 0xFFFF);
        assert_eq!(buf, vec![0xFD, 0xFF, 0xFF]);

        buf.clear();
        push_compact_size(&mut buf, 0x10000);
        assert_eq!(buf, vec![0xFE, 0x00, 0x00, 0x01, 0x00]);
    }
}
