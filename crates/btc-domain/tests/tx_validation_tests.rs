//! Transaction validation tests
//!
//! Tests for consensus transaction validation rules matching Bitcoin Core's
//! `tx_valid.json` and `tx_invalid.json` test vectors.

use btc_domain::consensus::rules;
use btc_domain::primitives::{Transaction, TxIn, TxOut, OutPoint, Txid, Amount};
use btc_domain::primitives::hash::Hash256;
use btc_domain::script::Script;
use btc_domain::script::witness::Witness;

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
fn make_simple_tx(version: i32, num_inputs: usize, num_outputs: usize, output_value: i64) -> Transaction {
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
    assert!(rules::check_transaction(&tx).is_err(), "Transaction with no inputs should be invalid");
}

#[test]
fn test_invalid_no_outputs() {
    let tx = make_simple_tx(1, 1, 0, 0);
    assert!(rules::check_transaction(&tx).is_err(), "Transaction with no outputs should be invalid");
}

#[test]
fn test_invalid_negative_output() {
    let mut tx = make_simple_tx(1, 1, 1, 50_000);
    tx.outputs[0].value = Amount::from_sat(-1);
    assert!(rules::check_transaction(&tx).is_err(), "Negative output value should be invalid");
}

#[test]
fn test_invalid_too_large_output() {
    // Bitcoin has a 21M BTC cap = 2_100_000_000_000_000 satoshis
    let mut tx = make_simple_tx(1, 1, 1, 50_000);
    tx.outputs[0].value = Amount::from_sat(2_100_000_100_000_000);
    assert!(rules::check_transaction(&tx).is_err(), "Output exceeding 21M BTC should be invalid");
}

#[test]
fn test_invalid_duplicate_inputs() {
    let mut tx = make_simple_tx(1, 2, 1, 50_000);
    // Make both inputs reference the same outpoint
    tx.inputs[1].previous_output = tx.inputs[0].previous_output;
    assert!(rules::check_transaction(&tx).is_err(), "Duplicate inputs should be invalid");
}

// ========== RBF signal tests ==========

#[test]
fn test_rbf_signaling() {
    use btc_domain::policy::rbf::SignalsRbf;

    // Sequence < 0xFFFFFFFE signals RBF
    let mut tx = make_simple_tx(2, 1, 1, 50_000);
    tx.inputs[0].sequence = 0xFFFFFFFD;
    assert!(tx.signals_rbf(), "Sequence 0xFFFFFFFD should signal RBF");

    // Sequence = 0xFFFFFFFE does NOT signal
    tx.inputs[0].sequence = 0xFFFFFFFE;
    assert!(!tx.signals_rbf(), "Sequence 0xFFFFFFFE should NOT signal RBF");

    // Sequence = 0xFFFFFFFF does NOT signal
    tx.inputs[0].sequence = 0xFFFFFFFF;
    assert!(!tx.signals_rbf(), "Sequence 0xFFFFFFFF should NOT signal RBF");
}

// ========== Policy limit tests ==========

#[test]
fn test_policy_standard_tx_checks() {
    use btc_domain::policy::limits::{MempoolLimits, LimitError};

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
    use btc_domain::policy::limits::PackageInfo;

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
    use btc_domain::script::witness::Witness;

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
    use btc_domain::crypto::taproot::tagged_hash;

    let h1 = tagged_hash("TapLeaf", b"data");
    let h2 = tagged_hash("TapLeaf", b"data");
    assert_eq!(h1, h2, "Tagged hash should be deterministic");

    let h3 = tagged_hash("TapBranch", b"data");
    assert_ne!(h1, h3, "Different tags should produce different hashes");
}

#[test]
fn test_control_block_round_trip() {
    use btc_domain::crypto::taproot::{ControlBlock, TAPSCRIPT_LEAF_VERSION};

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
    use btc_domain::crypto::schnorr::{parse_schnorr_signature, sighash_type};

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
