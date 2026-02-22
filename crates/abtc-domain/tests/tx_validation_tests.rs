//! Transaction validation tests
//!
//! Tests for consensus transaction validation rules matching Bitcoin Core's
//! `tx_valid.json` and `tx_invalid.json` test vectors.

use abtc_domain::consensus::rules;
use abtc_domain::primitives::hash::Hash256;
use abtc_domain::primitives::{Amount, OutPoint, Transaction, TxIn, TxOut, Txid};
use abtc_domain::script::witness::Witness;
use abtc_domain::script::Script;

/// Helper to create a coinbase transaction
fn make_coinbase(value_sat: i64) -> Transaction {
    let inputs = vec![TxIn {
        previous_output: OutPoint {
            txid: Txid::zero(),
            vout: 0xFFFFFFFF,
        },
        script_sig: Script::from_bytes(vec![0x04, 0xFF, 0xFF, 0x00, 0x1D, 0x01, 0x04]),
        sequence: 0xFFFFFFFF,
        witness: Witness::new(),
    }];
    let outputs = vec![TxOut {
        value: Amount::from_sat(value_sat),
        script_pubkey: Script::from_bytes(vec![0x51]), // OP_1
    }];
    Transaction::new(1, inputs, outputs, 0)
}

/// Helper to create a simple non-coinbase transaction
fn make_simple_tx(
    version: i32,
    num_inputs: usize,
    num_outputs: usize,
    output_value: i64,
) -> Transaction {
    let mut inputs = Vec::new();
    for i in 0..num_inputs {
        inputs.push(TxIn {
            previous_output: OutPoint {
                txid: Txid::from_hash(Hash256::from_bytes([i as u8 + 1; 32])),
                vout: 0,
            },
            script_sig: Script::from_bytes(vec![0x51]), // OP_1
            sequence: 0xFFFFFFFF,
            witness: Witness::new(),
        });
    }
    let mut outputs = Vec::new();
    for _ in 0..num_outputs {
        outputs.push(TxOut {
            value: Amount::from_sat(output_value),
            script_pubkey: Script::from_bytes(vec![0x51]), // OP_1
        });
    }
    Transaction::new(version, inputs, outputs, 0)
}

// ========== Valid transaction tests ==========

#[test]
fn test_valid_simple_transaction() {
    let tx = make_simple_tx(1, 1, 1, 50_000);
    assert!(rules::check_transaction(&tx).is_ok());
}

#[test]
fn test_valid_multiple_inputs_outputs() {
    let tx = make_simple_tx(1, 3, 2, 100_000);
    assert!(rules::check_transaction(&tx).is_ok());
}

#[test]
fn test_valid_version_2_transaction() {
    let tx = make_simple_tx(2, 1, 1, 50_000);
    assert!(rules::check_transaction(&tx).is_ok());
}

#[test]
fn test_valid_coinbase() {
    let tx = make_coinbase(5_000_000_000);
    assert!(tx.is_coinbase());
    assert!(rules::check_transaction(&tx).is_ok());
}

#[test]
fn test_valid_zero_output_value() {
    // OP_RETURN outputs can have zero value
    let tx = make_simple_tx(1, 1, 1, 0);
    assert!(rules::check_transaction(&tx).is_ok());
}

// ========== Invalid transaction tests ==========

#[test]
fn test_invalid_no_inputs() {
    let tx = make_simple_tx(1, 0, 1, 50_000);
    assert!(
        rules::check_transaction(&tx).is_err(),
        "Transaction with no inputs should be invalid"
    );
}

#[test]
fn test_invalid_no_outputs() {
    let tx = make_simple_tx(1, 1, 0, 0);
    assert!(
        rules::check_transaction(&tx).is_err(),
        "Transaction with no outputs should be invalid"
    );
}

#[test]
fn test_invalid_negative_output() {
    let mut tx = make_simple_tx(1, 1, 1, 50_000);
    tx.outputs[0].value = Amount::from_sat(-1);
    assert!(
        rules::check_transaction(&tx).is_err(),
        "Negative output value should be invalid"
    );
}

#[test]
fn test_invalid_too_large_output() {
    // Bitcoin has a 21M BTC cap = 2_100_000_000_000_000 satoshis
    let mut tx = make_simple_tx(1, 1, 1, 50_000);
    tx.outputs[0].value = Amount::from_sat(2_100_000_100_000_000);
    assert!(
        rules::check_transaction(&tx).is_err(),
        "Output exceeding 21M BTC should be invalid"
    );
}

#[test]
fn test_invalid_duplicate_inputs() {
    let mut tx = make_simple_tx(1, 2, 1, 50_000);
    // Make both inputs reference the same outpoint
    tx.inputs[1].previous_output = tx.inputs[0].previous_output;
    assert!(
        rules::check_transaction(&tx).is_err(),
        "Duplicate inputs should be invalid"
    );
}

// ========== RBF signal tests ==========

#[test]
fn test_rbf_signaling() {
    use abtc_domain::policy::rbf::SignalsRbf;

    // Sequence < 0xFFFFFFFE signals RBF
    let mut tx = make_simple_tx(2, 1, 1, 50_000);
    tx.inputs[0].sequence = 0xFFFFFFFD;
    assert!(tx.signals_rbf(), "Sequence 0xFFFFFFFD should signal RBF");

    // Sequence = 0xFFFFFFFE does NOT signal
    tx.inputs[0].sequence = 0xFFFFFFFE;
    assert!(
        !tx.signals_rbf(),
        "Sequence 0xFFFFFFFE should NOT signal RBF"
    );

    // Sequence = 0xFFFFFFFF does NOT signal
    tx.inputs[0].sequence = 0xFFFFFFFF;
    assert!(
        !tx.signals_rbf(),
        "Sequence 0xFFFFFFFF should NOT signal RBF"
    );
}

// ========== Policy limit tests ==========

#[test]
fn test_policy_standard_tx_checks() {
    use abtc_domain::policy::limits::{LimitError, MempoolLimits};

    // Dust output check (below 546 satoshis)
    assert!(matches!(
        MempoolLimits::check_standard_tx(400, Amount::from_sat(1000), 400, &[500]),
        Err(LimitError::DustOutput { .. })
    ));

    // Below min relay fee
    assert!(matches!(
        MempoolLimits::check_standard_tx(400, Amount::from_sat(1), 400, &[1000]),
        Err(LimitError::BelowMinRelayFee { .. })
    ));

    // Valid standard tx
    assert!(MempoolLimits::check_standard_tx(400, Amount::from_sat(800), 400, &[1000]).is_ok());
}

// ========== CPFP tests ==========

#[test]
fn test_cpfp_ancestor_fee_rate() {
    use abtc_domain::policy::limits::PackageInfo;

    let pkg = PackageInfo {
        txid: Txid::zero(),
        vsize: 200,
        fee: Amount::from_sat(2000),
        ancestor_count: 3,
        ancestor_size: 600,
        ancestor_fee: Amount::from_sat(6000),
        descendant_count: 1,
        descendant_size: 200,
        descendant_fee: Amount::from_sat(2000),
    };

    // Individual fee rate: 2000/200 = 10 sat/vB
    assert!((pkg.fee_rate() - 10.0).abs() < 0.001);

    // Ancestor fee rate: 6000/600 = 10 sat/vB
    assert!((pkg.ancestor_fee_rate() - 10.0).abs() < 0.001);

    // Descendant fee rate: 2000/200 = 10 sat/vB
    assert!((pkg.descendant_fee_rate() - 10.0).abs() < 0.001);
}

// ========== Witness structure tests ==========

#[test]
fn test_witness_basic_operations() {
    use abtc_domain::script::witness::Witness;

    let mut w = Witness::new();
    assert!(w.is_empty());
    assert_eq!(w.len(), 0);

    w.push(vec![0x01, 0x02]);
    assert!(!w.is_empty());
    assert_eq!(w.len(), 1);
    assert_eq!(w.get(0).unwrap(), &[0x01, 0x02]);

    w.push(vec![0x03]);
    assert_eq!(w.len(), 2);
    assert_eq!(w.get(1).unwrap(), &[0x03]);

    assert!(w.get(2).is_none());
}

// ========== Taproot structure tests ==========

#[test]
fn test_tagged_hash_consistency() {
    use abtc_domain::crypto::taproot::tagged_hash;

    let h1 = tagged_hash("TapLeaf", b"data");
    let h2 = tagged_hash("TapLeaf", b"data");
    assert_eq!(h1, h2, "Tagged hash should be deterministic");

    let h3 = tagged_hash("TapBranch", b"data");
    assert_ne!(h1, h3, "Different tags should produce different hashes");
}

#[test]
fn test_control_block_round_trip() {
    use abtc_domain::crypto::taproot::{ControlBlock, TAPSCRIPT_LEAF_VERSION};

    // Build a control block with 2 merkle nodes
    let mut data = vec![TAPSCRIPT_LEAF_VERSION | 0x01]; // parity = 1
    let internal_key = [0x02u8; 32];
    data.extend_from_slice(&internal_key);
    let node1 = [0xAAu8; 32];
    let node2 = [0xBBu8; 32];
    data.extend_from_slice(&node1);
    data.extend_from_slice(&node2);

    let cb = ControlBlock::parse(&data).unwrap();
    assert_eq!(cb.leaf_version, TAPSCRIPT_LEAF_VERSION);
    assert!(cb.output_key_parity);
    assert_eq!(cb.internal_key, internal_key);
    assert_eq!(cb.merkle_path.len(), 2);
    assert_eq!(cb.merkle_path[0], node1);
    assert_eq!(cb.merkle_path[1], node2);
}

#[test]
fn test_schnorr_signature_parsing() {
    use abtc_domain::crypto::schnorr::{parse_schnorr_signature, sighash_type};

    // 64 bytes = default sighash
    let sig64 = [0xABu8; 64];
    let (sig, ht) = parse_schnorr_signature(&sig64).unwrap();
    assert_eq!(sig.len(), 64);
    assert_eq!(ht, sighash_type::SIGHASH_DEFAULT);

    // 65 bytes with ALL
    let mut sig65 = [0xABu8; 65];
    sig65[64] = sighash_type::SIGHASH_ALL;
    let (sig, ht) = parse_schnorr_signature(&sig65).unwrap();
    assert_eq!(sig.len(), 64);
    assert_eq!(ht, sighash_type::SIGHASH_ALL);

    // 65 bytes with DEFAULT (0x00) explicit — INVALID
    sig65[64] = sighash_type::SIGHASH_DEFAULT;
    assert!(parse_schnorr_signature(&sig65).is_none());

    // Wrong sizes
    assert!(parse_schnorr_signature(&[0u8; 63]).is_none());
    assert!(parse_schnorr_signature(&[0u8; 66]).is_none());
}

// ========== Serialization / Deserialization round-trip tests ==========

#[test]
fn test_serialize_deserialize_legacy_roundtrip() {
    // Build a simple legacy transaction
    let tx = make_simple_tx(1, 2, 2, 50_000);

    // Serialize (legacy, no witness)
    let bytes = tx.serialize_legacy();

    // Deserialize
    let (tx2, consumed) = Transaction::deserialize(&bytes).unwrap();
    assert_eq!(consumed, bytes.len(), "Should consume all bytes");

    // Round-trip check
    assert_eq!(tx.version, tx2.version);
    assert_eq!(tx.lock_time, tx2.lock_time);
    assert_eq!(tx.inputs.len(), tx2.inputs.len());
    assert_eq!(tx.outputs.len(), tx2.outputs.len());

    for (a, b) in tx.inputs.iter().zip(tx2.inputs.iter()) {
        assert_eq!(a.previous_output, b.previous_output);
        assert_eq!(a.script_sig.as_bytes(), b.script_sig.as_bytes());
        assert_eq!(a.sequence, b.sequence);
    }
    for (a, b) in tx.outputs.iter().zip(tx2.outputs.iter()) {
        assert_eq!(a.value, b.value);
        assert_eq!(a.script_pubkey.as_bytes(), b.script_pubkey.as_bytes());
    }

    // Re-serialize should produce identical bytes
    let bytes2 = tx2.serialize_legacy();
    assert_eq!(
        bytes, bytes2,
        "Double round-trip should produce identical bytes"
    );
}

#[test]
fn test_serialize_deserialize_witness_roundtrip() {
    use abtc_domain::script::witness::Witness;

    // Build a witness transaction
    let mut tx = make_simple_tx(2, 1, 1, 100_000);
    let mut witness = Witness::new();
    witness.push(vec![0x30, 0x44]); // fake DER sig
    witness.push(vec![0x02, 0x20]); // fake pubkey
    tx.inputs[0].witness = witness;

    // Full serialize (with witness)
    let bytes = tx.serialize();

    // Should start with version, then marker 0x00, flag 0x01
    assert_eq!(bytes[4], 0x00, "Witness marker should be 0x00");
    assert_eq!(bytes[5], 0x01, "Witness flag should be 0x01");

    // Deserialize
    let (tx2, consumed) = Transaction::deserialize(&bytes).unwrap();
    assert_eq!(consumed, bytes.len());

    // Check witness round-tripped
    assert_eq!(tx2.inputs[0].witness.len(), 2);
    assert_eq!(tx2.inputs[0].witness.get(0).unwrap(), &[0x30, 0x44]);
    assert_eq!(tx2.inputs[0].witness.get(1).unwrap(), &[0x02, 0x20]);

    // Re-serialize should be identical
    let bytes2 = tx2.serialize();
    assert_eq!(bytes, bytes2);
}

#[test]
fn test_deserialize_exact_rejects_trailing_data() {
    use abtc_domain::primitives::transaction::DeserializeError;

    let tx = make_simple_tx(1, 1, 1, 50_000);
    let mut bytes = tx.serialize_legacy();
    bytes.push(0xFF); // trailing garbage

    // deserialize should succeed (returns consumed count)
    let (_, consumed) = Transaction::deserialize(&bytes).unwrap();
    assert_eq!(
        consumed,
        bytes.len() - 1,
        "Should not consume trailing byte"
    );

    // deserialize_exact should fail
    assert_eq!(
        Transaction::deserialize_exact(&bytes),
        Err(DeserializeError::TrailingData),
    );
}

#[test]
fn test_deserialize_empty_fails() {
    assert!(Transaction::deserialize(&[]).is_err());
}

#[test]
fn test_deserialize_coinbase_roundtrip() {
    let tx = make_coinbase(5_000_000_000);
    let bytes = tx.serialize_legacy();
    let tx2 = Transaction::deserialize_exact(&bytes).unwrap();

    assert!(tx2.is_coinbase());
    assert_eq!(tx2.outputs[0].value, Amount::from_sat(5_000_000_000));
}

#[test]
fn test_txid_survives_roundtrip() {
    // Txid is computed from legacy serialization — verify it's stable
    let tx = make_simple_tx(1, 3, 2, 75_000);
    let txid1 = tx.txid();

    let bytes = tx.serialize_legacy();
    let tx2 = Transaction::deserialize_exact(&bytes).unwrap();
    let txid2 = tx2.txid();

    assert_eq!(
        txid1, txid2,
        "Txid should survive serialize/deserialize round-trip"
    );
}

#[test]
fn test_deserialize_real_mainnet_tx() {
    // Bitcoin's genesis coinbase transaction (simplified test)
    // This is a manually constructed minimal valid transaction
    // matching the wire format: version=1, 1 input (coinbase), 1 output, locktime=0
    let mut bytes = Vec::new();

    // Version 1
    bytes.extend_from_slice(&1i32.to_le_bytes());
    // 1 input
    bytes.push(0x01);
    // Coinbase prevout: zero hash
    bytes.extend_from_slice(&[0u8; 32]);
    // Coinbase prevout: index 0xFFFFFFFF
    bytes.extend_from_slice(&0xFFFFFFFFu32.to_le_bytes());
    // Coinbase script: 4 bytes
    bytes.push(0x04);
    bytes.extend_from_slice(&[0xFF, 0xFF, 0x00, 0x1D]);
    // Sequence
    bytes.extend_from_slice(&0xFFFFFFFFu32.to_le_bytes());
    // 1 output
    bytes.push(0x01);
    // 50 BTC = 5,000,000,000 satoshis
    bytes.extend_from_slice(&5_000_000_000i64.to_le_bytes());
    // Output script: 1 byte (OP_1)
    bytes.push(0x01);
    bytes.push(0x51);
    // Locktime
    bytes.extend_from_slice(&0u32.to_le_bytes());

    let tx = Transaction::deserialize_exact(&bytes).unwrap();
    assert!(tx.is_coinbase());
    assert_eq!(tx.version, 1);
    assert_eq!(tx.inputs.len(), 1);
    assert_eq!(tx.outputs.len(), 1);
    assert_eq!(tx.outputs[0].value, Amount::from_sat(5_000_000_000));
    assert_eq!(tx.lock_time, 0);
}

// ========== End-to-end signing + verification tests ==========

use abtc_domain::crypto::signing::{SpentOutput, TransactionSignatureChecker};
use abtc_domain::wallet::keys::PrivateKey;
use abtc_domain::wallet::tx_builder::{
    make_p2pkh_script, make_p2tr_script, make_p2wpkh_script, InputInfo, TransactionBuilder,
};
use abtc_domain::{verify_script, verify_script_with_witness, ScriptFlags};

/// E2E: Generate key → build P2PKH tx → sign → verify script succeeds
#[test]
fn test_e2e_p2pkh_sign_and_verify() {
    // 1. Generate a fresh keypair
    let key = PrivateKey::generate(true, true);
    let pubkey = key.public_key();
    let pubkey_hash = pubkey.pubkey_hash();

    // 2. Create the scriptPubKey that locks the "previous output"
    let script_pubkey = make_p2pkh_script(&pubkey_hash);
    let input_amount = Amount::from_sat(100_000);

    // 3. Build and sign the spending transaction
    let tx = TransactionBuilder::new()
        .version(1)
        .add_input(InputInfo {
            outpoint: OutPoint::new(Txid::from_hash(Hash256::from_bytes([0xAA; 32])), 0),
            script_pubkey: script_pubkey.clone(),
            amount: input_amount,
            signing_key: Some(key),
            sequence: 0xFFFFFFFF,
            tap_script_path: None,
        })
        .add_output(TxOut::new(
            Amount::from_sat(90_000),
            Script::from_bytes(vec![0x51]),
        )) // OP_1
        .sign()
        .unwrap();

    // 4. Verify the scriptSig satisfies the scriptPubKey
    let checker = TransactionSignatureChecker::new(&tx, 0, input_amount);
    let flags = ScriptFlags::new(ScriptFlags::NONE);

    let result = verify_script(&tx.inputs[0].script_sig, &script_pubkey, flags, &checker);
    assert!(
        result.is_ok(),
        "P2PKH script verification failed: {:?}",
        result.err()
    );
}

/// E2E: Generate key → build P2WPKH tx → sign → serialize → deserialize → verify witness
#[test]
fn test_e2e_p2wpkh_sign_serialize_deserialize_verify() {
    // 1. Generate keypair
    let key = PrivateKey::generate(true, true);
    let pubkey = key.public_key();
    let pubkey_hash = pubkey.pubkey_hash();

    // 2. Create SegWit P2WPKH scriptPubKey
    let script_pubkey = make_p2wpkh_script(&pubkey_hash);
    let input_amount = Amount::from_sat(200_000);

    // 3. Build and sign
    let tx = TransactionBuilder::new()
        .version(2)
        .add_input(InputInfo {
            outpoint: OutPoint::new(Txid::from_hash(Hash256::from_bytes([0xBB; 32])), 1),
            script_pubkey: script_pubkey.clone(),
            amount: input_amount,
            signing_key: Some(key),
            sequence: 0xFFFFFFFE,
            tap_script_path: None,
        })
        .add_output(TxOut::new(
            Amount::from_sat(190_000),
            Script::from_bytes(vec![0x51]),
        ))
        .sign()
        .unwrap();

    // 4. Serialize (includes witness data)
    let wire_bytes = tx.serialize();
    assert!(
        wire_bytes.len() > 0,
        "Serialized transaction should not be empty"
    );

    // 5. Deserialize from wire format
    let tx2 = Transaction::deserialize_exact(&wire_bytes).unwrap();

    // 6. Verify structural integrity
    assert_eq!(tx2.version, 2);
    assert_eq!(tx2.inputs.len(), 1);
    assert_eq!(tx2.outputs.len(), 1);
    assert_eq!(tx2.outputs[0].value, Amount::from_sat(190_000));
    assert!(
        tx2.inputs[0].script_sig.is_empty(),
        "P2WPKH should have empty scriptSig"
    );
    assert_eq!(
        tx2.inputs[0].witness.len(),
        2,
        "Witness should have [sig, pubkey]"
    );

    // 7. Verify txids match (txid excludes witness, so both should agree)
    assert_eq!(
        tx.txid(),
        tx2.txid(),
        "Txid should survive serialization round-trip"
    );

    // 8. Verify the witness satisfies the scriptPubKey
    let checker2 = TransactionSignatureChecker::new_witness_v0(&tx2, 0, input_amount);
    let flags = ScriptFlags::new(ScriptFlags::NONE);

    let result = verify_script_with_witness(
        &tx2.inputs[0].script_sig,
        &script_pubkey,
        &tx2.inputs[0].witness,
        flags,
        &checker2,
    );
    assert!(
        result.is_ok(),
        "P2WPKH witness verification failed: {:?}",
        result.err()
    );
}

/// E2E: Sign P2PKH, serialize legacy (no witness), deserialize, verify
#[test]
fn test_e2e_p2pkh_legacy_roundtrip() {
    let key = PrivateKey::generate(true, true);
    let pubkey = key.public_key();
    let pubkey_hash = pubkey.pubkey_hash();
    let script_pubkey = make_p2pkh_script(&pubkey_hash);
    let input_amount = Amount::from_sat(50_000);

    let tx = TransactionBuilder::new()
        .version(1)
        .add_input(InputInfo {
            outpoint: OutPoint::new(Txid::from_hash(Hash256::from_bytes([0xCC; 32])), 0),
            script_pubkey: script_pubkey.clone(),
            amount: input_amount,
            signing_key: Some(key),
            sequence: 0xFFFFFFFF,
            tap_script_path: None,
        })
        .add_output(TxOut::new(
            Amount::from_sat(40_000),
            make_p2pkh_script(&[0x11; 20]),
        ))
        .sign()
        .unwrap();

    // Serialize legacy (no witness marker)
    let legacy_bytes = tx.serialize_legacy();

    // Deserialize
    let tx2 = Transaction::deserialize_exact(&legacy_bytes).unwrap();

    // Txid must match
    assert_eq!(tx.txid(), tx2.txid());

    // Verify script
    let checker = TransactionSignatureChecker::new(&tx2, 0, input_amount);
    let result = verify_script(
        &tx2.inputs[0].script_sig,
        &script_pubkey,
        ScriptFlags::new(ScriptFlags::NONE),
        &checker,
    );
    assert!(
        result.is_ok(),
        "P2PKH legacy roundtrip verification failed: {:?}",
        result.err()
    );
}

/// E2E: Multiple inputs (mixed P2PKH + P2WPKH), sign all, verify all
#[test]
fn test_e2e_multi_input_mixed_signing() {
    let key1 = PrivateKey::generate(true, true);
    let key2 = PrivateKey::generate(true, true);
    let pubkey1 = key1.public_key();
    let pubkey2 = key2.public_key();

    let p2pkh_script = make_p2pkh_script(&pubkey1.pubkey_hash());
    let p2wpkh_script = make_p2wpkh_script(&pubkey2.pubkey_hash());

    let amount1 = Amount::from_sat(100_000);
    let amount2 = Amount::from_sat(200_000);

    let tx = TransactionBuilder::new()
        .version(2)
        .add_input(InputInfo {
            outpoint: OutPoint::new(Txid::from_hash(Hash256::from_bytes([0xDD; 32])), 0),
            script_pubkey: p2pkh_script.clone(),
            amount: amount1,
            signing_key: Some(key1),
            sequence: 0xFFFFFFFF,
            tap_script_path: None,
        })
        .add_input(InputInfo {
            outpoint: OutPoint::new(Txid::from_hash(Hash256::from_bytes([0xEE; 32])), 1),
            script_pubkey: p2wpkh_script.clone(),
            amount: amount2,
            signing_key: Some(key2),
            sequence: 0xFFFFFFFE,
            tap_script_path: None,
        })
        .add_output(TxOut::new(
            Amount::from_sat(250_000),
            Script::from_bytes(vec![0x51]),
        ))
        .sign()
        .unwrap();

    // Verify input 0 (P2PKH - legacy)
    let checker0 = TransactionSignatureChecker::new(&tx, 0, amount1);
    let r0 = verify_script(
        &tx.inputs[0].script_sig,
        &p2pkh_script,
        ScriptFlags::new(ScriptFlags::NONE),
        &checker0,
    );
    assert!(
        r0.is_ok(),
        "Multi-input P2PKH verification failed: {:?}",
        r0.err()
    );

    // Verify input 1 (P2WPKH - witness)
    let checker1 = TransactionSignatureChecker::new_witness_v0(&tx, 1, amount2);
    let r1 = verify_script_with_witness(
        &tx.inputs[1].script_sig,
        &p2wpkh_script,
        &tx.inputs[1].witness,
        ScriptFlags::new(ScriptFlags::NONE),
        &checker1,
    );
    assert!(
        r1.is_ok(),
        "Multi-input P2WPKH verification failed: {:?}",
        r1.err()
    );

    // Serialize round-trip (mixed tx has witness data)
    let wire = tx.serialize();
    let tx2 = Transaction::deserialize_exact(&wire).unwrap();
    assert_eq!(tx.txid(), tx2.txid());
    assert_eq!(tx2.inputs.len(), 2);

    // Verify both inputs after round-trip
    let checker0b = TransactionSignatureChecker::new(&tx2, 0, amount1);
    assert!(
        verify_script(
            &tx2.inputs[0].script_sig,
            &p2pkh_script,
            ScriptFlags::new(ScriptFlags::NONE),
            &checker0b,
        )
        .is_ok(),
        "P2PKH verification failed after round-trip"
    );

    let checker1b = TransactionSignatureChecker::new_witness_v0(&tx2, 1, amount2);
    assert!(
        verify_script_with_witness(
            &tx2.inputs[1].script_sig,
            &p2wpkh_script,
            &tx2.inputs[1].witness,
            ScriptFlags::new(ScriptFlags::NONE),
            &checker1b,
        )
        .is_ok(),
        "P2WPKH verification failed after round-trip"
    );
}

/// E2E: Wrong key should fail verification
#[test]
fn test_e2e_wrong_key_fails_verification() {
    let key = PrivateKey::generate(true, true);
    let wrong_key = PrivateKey::generate(true, true);
    let pubkey = key.public_key();
    let script_pubkey = make_p2pkh_script(&pubkey.pubkey_hash());
    let input_amount = Amount::from_sat(100_000);

    // Sign with a DIFFERENT key but use the original pubkey's scriptPubKey
    // The builder will sign with wrong_key, but the scriptPubKey expects key's pubkey hash
    let tx = TransactionBuilder::new()
        .version(1)
        .add_input(InputInfo {
            outpoint: OutPoint::new(Txid::from_hash(Hash256::from_bytes([0xFF; 32])), 0),
            script_pubkey: script_pubkey.clone(),
            amount: input_amount,
            signing_key: Some(wrong_key),
            sequence: 0xFFFFFFFF,
            tap_script_path: None,
        })
        .add_output(TxOut::new(
            Amount::from_sat(90_000),
            Script::from_bytes(vec![0x51]),
        ))
        .sign()
        .unwrap();

    // Verify should FAIL — signed with wrong key
    let checker = TransactionSignatureChecker::new(&tx, 0, input_amount);
    let result = verify_script(
        &tx.inputs[0].script_sig,
        &script_pubkey,
        ScriptFlags::new(ScriptFlags::NONE),
        &checker,
    );
    assert!(
        result.is_err(),
        "Verification should fail with wrong signing key"
    );
}

// E2E: Generate key → build P2TR tx → sign → serialize → deserialize → verify
#[test]
fn test_e2e_p2tr_sign_serialize_deserialize_verify() {
    use secp256k1::{Keypair, Scalar, Secp256k1, XOnlyPublicKey};

    // 1. Generate keypair and derive P2TR output key
    let key = PrivateKey::generate(true, true);
    let secp = Secp256k1::new();
    let keypair = Keypair::from_secret_key(&secp, key.inner());
    let (internal_xonly, _) = XOnlyPublicKey::from_keypair(&keypair);

    // Compute tweaked output key (key-path-only)
    let tweak = abtc_domain::crypto::taproot::taptweak_hash(&internal_xonly.serialize(), None);
    let scalar = Scalar::from_be_bytes(tweak).unwrap();
    let (output_key, _) = internal_xonly.add_tweak(&secp, &scalar).unwrap();

    let script_pubkey = make_p2tr_script(&output_key.serialize());
    let input_amount = Amount::from_sat(200_000);

    // 2. Build and sign P2TR transaction
    let tx = TransactionBuilder::new()
        .version(2)
        .add_input(InputInfo {
            outpoint: OutPoint::new(Txid::from_hash(Hash256::from_bytes([0xAA; 32])), 0),
            script_pubkey: script_pubkey.clone(),
            amount: input_amount,
            signing_key: Some(key),
            sequence: 0xFFFFFFFE,
            tap_script_path: None,
        })
        .add_output(TxOut::new(
            Amount::from_sat(190_000),
            Script::from_bytes(vec![0x51]),
        ))
        .sign()
        .unwrap();

    // 3. Verify structure
    assert!(
        tx.inputs[0].script_sig.is_empty(),
        "P2TR should have empty scriptSig"
    );
    assert_eq!(
        tx.inputs[0].witness.len(),
        1,
        "P2TR witness should have [signature]"
    );
    assert_eq!(
        tx.inputs[0].witness.get(0).unwrap().len(),
        64,
        "Schnorr sig is 64 bytes"
    );

    // 4. Serialize and deserialize
    let wire_bytes = tx.serialize();
    let tx2 = Transaction::deserialize_exact(&wire_bytes).unwrap();
    assert_eq!(tx.txid(), tx2.txid(), "Txid survives round-trip");
    assert_eq!(tx2.inputs[0].witness.len(), 1);

    // 5. Verify the signature through the script interpreter
    let spent_outputs = vec![SpentOutput {
        amount: input_amount,
        script_pubkey: script_pubkey.clone(),
    }];
    let checker = TransactionSignatureChecker::new_taproot(&tx2, 0, spent_outputs);
    let flags = ScriptFlags::new(ScriptFlags::VERIFY_WITNESS | ScriptFlags::VERIFY_TAPROOT);

    let result = verify_script_with_witness(
        &tx2.inputs[0].script_sig,
        &script_pubkey,
        &tx2.inputs[0].witness,
        flags,
        &checker,
    );
    assert!(
        result.is_ok(),
        "P2TR key-path verification failed: {:?}",
        result.err()
    );
}

// E2E: P2TR address creation → tx signing → verification round-trip
#[test]
fn test_e2e_p2tr_address_to_verification() {
    use abtc_domain::wallet::address::Address;
    use secp256k1::{Keypair, Secp256k1, XOnlyPublicKey};

    let key = PrivateKey::generate(true, true);
    let secp = Secp256k1::new();
    let keypair = Keypair::from_secret_key(&secp, key.inner());
    let (internal_xonly, _) = XOnlyPublicKey::from_keypair(&keypair);

    // Create P2TR address from internal key
    let addr = Address::p2tr_from_internal_key(&internal_xonly.serialize(), true).unwrap();
    assert!(addr.encoded.starts_with("bc1p"));
    assert!(addr.script_pubkey.is_p2tr());

    let input_amount = Amount::from_sat(500_000);

    // Sign transaction spending this P2TR output
    let tx = TransactionBuilder::new()
        .version(2)
        .add_input(InputInfo {
            outpoint: OutPoint::new(Txid::from_hash(Hash256::from_bytes([0xCC; 32])), 0),
            script_pubkey: addr.script_pubkey.clone(),
            amount: input_amount,
            signing_key: Some(key),
            sequence: 0xFFFFFFFE,
            tap_script_path: None,
        })
        .add_output(TxOut::new(
            Amount::from_sat(490_000),
            Script::from_bytes(vec![0x51]),
        ))
        .sign()
        .unwrap();

    // Verify through script interpreter
    let spent_outputs = vec![SpentOutput {
        amount: input_amount,
        script_pubkey: addr.script_pubkey.clone(),
    }];
    let checker = TransactionSignatureChecker::new_taproot(&tx, 0, spent_outputs);
    let flags = ScriptFlags::new(ScriptFlags::VERIFY_WITNESS | ScriptFlags::VERIFY_TAPROOT);

    let result = verify_script_with_witness(
        &tx.inputs[0].script_sig,
        &addr.script_pubkey,
        &tx.inputs[0].witness,
        flags,
        &checker,
    );
    assert!(
        result.is_ok(),
        "P2TR address-based verification failed: {:?}",
        result.err()
    );
}

// ── Taproot script-path spending E2E tests ────────────────────────

// E2E: Build a TapTree with two scripts, spend via script-path leaf 0
#[test]
fn test_e2e_taproot_script_path_single_checksig() {
    use abtc_domain::crypto::taproot::{TapLeaf, TapTree};
    use abtc_domain::wallet::tx_builder::TapScriptPath;
    use secp256k1::{Keypair, Secp256k1, XOnlyPublicKey};

    // 1. Generate keypair
    let key = PrivateKey::generate(true, true);
    let secp = Secp256k1::new();
    let keypair = Keypair::from_secret_key(&secp, key.inner());
    let (internal_xonly, _) = XOnlyPublicKey::from_keypair(&keypair);
    let internal_key = internal_xonly.serialize();

    // 2. Build a tapscript: <pubkey> OP_CHECKSIG
    //    (This is the simplest useful tapscript — single-sig via script-path)
    let mut tap_script_bytes = Vec::new();
    tap_script_bytes.push(0x20); // push 32 bytes
    tap_script_bytes.extend_from_slice(&internal_key);
    tap_script_bytes.push(0xac); // OP_CHECKSIG
    let tap_script = Script::from_bytes(tap_script_bytes.clone());

    // 3. Build TapTree with two leaves: our checksig script + a dummy OP_1
    let tree = TapTree::new(vec![
        TapLeaf::new(tap_script_bytes.clone()),
        TapLeaf::new(vec![0x51]), // OP_1 (alternative spending path)
    ]);

    // 4. Compute output key and control block for leaf 0
    let (output_key, parity) = tree.compute_output_key(&internal_key).unwrap();
    let control = tree.control_block(0, &internal_key, parity).unwrap();
    let control_bytes = TapTree::serialize_control_block(&control);

    let script_pubkey = make_p2tr_script(&output_key);
    let input_amount = Amount::from_sat(300_000);
    let leaf_hash = tree.leaf_hash(0).unwrap();

    // 5. Build and sign transaction using script-path
    let tx = TransactionBuilder::new()
        .version(2)
        .add_input(InputInfo {
            outpoint: OutPoint::new(Txid::from_hash(Hash256::from_bytes([0xDD; 32])), 0),
            script_pubkey: script_pubkey.clone(),
            amount: input_amount,
            signing_key: Some(key),
            sequence: 0xFFFFFFFE,
            tap_script_path: Some(TapScriptPath {
                script: tap_script.clone(),
                control_block: control_bytes.clone(),
                leaf_hash,
            }),
        })
        .add_output(TxOut::new(
            Amount::from_sat(290_000),
            Script::from_bytes(vec![0x51]),
        ))
        .sign()
        .unwrap();

    // 6. Verify witness structure: [signature, script, control_block]
    assert!(
        tx.inputs[0].script_sig.is_empty(),
        "Taproot has empty scriptSig"
    );
    assert_eq!(
        tx.inputs[0].witness.len(),
        3,
        "Script-path witness = [sig, script, control]"
    );
    assert_eq!(
        tx.inputs[0].witness.get(0).unwrap().len(),
        64,
        "Schnorr sig is 64 bytes"
    );
    assert_eq!(
        tx.inputs[0].witness.get(1).unwrap(),
        tap_script_bytes.as_slice()
    );
    assert_eq!(
        tx.inputs[0].witness.get(2).unwrap(),
        control_bytes.as_slice()
    );

    // 7. Verify through the script interpreter
    let spent_outputs = vec![SpentOutput {
        amount: input_amount,
        script_pubkey: script_pubkey.clone(),
    }];
    let checker = TransactionSignatureChecker::new_taproot(&tx, 0, spent_outputs);
    let flags = ScriptFlags::new(ScriptFlags::VERIFY_WITNESS | ScriptFlags::VERIFY_TAPROOT);

    let result = verify_script_with_witness(
        &tx.inputs[0].script_sig,
        &script_pubkey,
        &tx.inputs[0].witness,
        flags,
        &checker,
    );
    assert!(
        result.is_ok(),
        "Taproot script-path verification failed: {:?}",
        result.err()
    );
}

// E2E: Spend via the OP_1 (always-true) leaf — no signature needed
#[test]
fn test_e2e_taproot_script_path_op1_leaf() {
    use abtc_domain::crypto::taproot::{TapLeaf, TapTree};
    use secp256k1::{Secp256k1, SecretKey};

    // 1. Create internal key
    let secp = Secp256k1::new();
    let secret = SecretKey::from_slice(&[0x77; 32]).unwrap();
    let (internal_xonly, _) = secret.x_only_public_key(&secp);
    let internal_key = internal_xonly.serialize();

    // 2. Build tree with OP_1 leaf (always true) and a dummy leaf
    let tree = TapTree::new(vec![
        TapLeaf::new(vec![0x51]), // OP_1 — always passes
        TapLeaf::new(vec![0x52]), // OP_2 — would leave 2 on stack
    ]);

    // 3. Compute output key
    let (output_key, parity) = tree.compute_output_key(&internal_key).unwrap();
    let script_pubkey = make_p2tr_script(&output_key);

    // 4. Build control block for leaf 0 (OP_1)
    let control = tree.control_block(0, &internal_key, parity).unwrap();
    let control_bytes = TapTree::serialize_control_block(&control);

    // 5. Build transaction manually with witness = [OP_1_script, control_block]
    //    No signature needed since OP_1 always succeeds
    let mut tx = Transaction::new(
        2,
        vec![TxIn::new(
            OutPoint::new(Txid::from_hash(Hash256::from_bytes([0xEE; 32])), 0),
            Script::new(), // empty scriptSig
            0xFFFFFFFE,
        )],
        vec![TxOut::new(
            Amount::from_sat(90_000),
            Script::from_bytes(vec![0x51]),
        )],
        0,
    );

    // Witness: [script, control_block] — no args needed for OP_1
    let mut witness = Witness::new();
    witness.push(vec![0x51]); // the OP_1 script
    witness.push(control_bytes);
    tx.inputs[0].witness = witness;

    // 6. Verify through interpreter
    let input_amount = Amount::from_sat(100_000);
    let spent_outputs = vec![SpentOutput {
        amount: input_amount,
        script_pubkey: script_pubkey.clone(),
    }];
    let checker = TransactionSignatureChecker::new_taproot(&tx, 0, spent_outputs);
    let flags = ScriptFlags::new(ScriptFlags::VERIFY_WITNESS | ScriptFlags::VERIFY_TAPROOT);

    let result = verify_script_with_witness(
        &tx.inputs[0].script_sig,
        &script_pubkey,
        &tx.inputs[0].witness,
        flags,
        &checker,
    );
    assert!(
        result.is_ok(),
        "OP_1 script-path should succeed: {:?}",
        result.err()
    );
}

// E2E: Wrong script in witness should fail verification
#[test]
fn test_e2e_taproot_script_path_wrong_script_fails() {
    use abtc_domain::crypto::taproot::{TapLeaf, TapTree};
    use secp256k1::{Secp256k1, SecretKey};

    let secp = Secp256k1::new();
    let secret = SecretKey::from_slice(&[0x77; 32]).unwrap();
    let (internal_xonly, _) = secret.x_only_public_key(&secp);
    let internal_key = internal_xonly.serialize();

    let tree = TapTree::new(vec![
        TapLeaf::new(vec![0x51]), // OP_1
    ]);

    let (output_key, parity) = tree.compute_output_key(&internal_key).unwrap();
    let script_pubkey = make_p2tr_script(&output_key);

    let control = tree.control_block(0, &internal_key, parity).unwrap();
    let control_bytes = TapTree::serialize_control_block(&control);

    // Build transaction with the WRONG script in witness (OP_2 instead of OP_1)
    let mut tx = Transaction::new(
        2,
        vec![TxIn::new(
            OutPoint::new(Txid::from_hash(Hash256::from_bytes([0xFF; 32])), 0),
            Script::new(),
            0xFFFFFFFE,
        )],
        vec![TxOut::new(
            Amount::from_sat(90_000),
            Script::from_bytes(vec![0x51]),
        )],
        0,
    );

    let mut witness = Witness::new();
    witness.push(vec![0x52]); // WRONG: OP_2 instead of OP_1
    witness.push(control_bytes);
    tx.inputs[0].witness = witness;

    let spent_outputs = vec![SpentOutput {
        amount: Amount::from_sat(100_000),
        script_pubkey: script_pubkey.clone(),
    }];
    let checker = TransactionSignatureChecker::new_taproot(&tx, 0, spent_outputs);
    let flags = ScriptFlags::new(ScriptFlags::VERIFY_WITNESS | ScriptFlags::VERIFY_TAPROOT);

    let result = verify_script_with_witness(
        &tx.inputs[0].script_sig,
        &script_pubkey,
        &tx.inputs[0].witness,
        flags,
        &checker,
    );
    // Should fail because OP_2 was not committed in the tree
    assert!(
        result.is_err(),
        "Wrong script should fail merkle commitment"
    );
}
