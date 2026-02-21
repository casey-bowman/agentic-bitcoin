//! Block connection and contextual validation tests
//!
//! Tests the full block validation pipeline: non-contextual checks,
//! UTXO lookups, script verification, coinbase maturity, and
//! connect/disconnect round-trips.

use btc_domain::consensus::connect::{
    connect_block, disconnect_block, ConnectBlockError, MemoryUtxoSet, UtxoEntry,
};
use btc_domain::consensus::UtxoView;
use btc_domain::consensus::{ConsensusParams, Network};
use btc_domain::primitives::block::{Block, BlockHeader};
use btc_domain::primitives::hash::{BlockHash, Hash256};
use btc_domain::primitives::{Amount, OutPoint, Transaction, TxIn, TxOut, Txid};
use btc_domain::script::Script;
use btc_domain::wallet::keys::PrivateKey;
use btc_domain::wallet::tx_builder::{
    InputInfo, TransactionBuilder, make_p2pkh_script, make_p2wpkh_script,
};

/// Create a block header that passes PoW validation.
///
/// We use regtest parameters where the target is extremely easy (0x207fffff),
/// so virtually any hash will pass.
fn make_header(prev_hash: BlockHash, merkle_root: Hash256) -> BlockHeader {
    BlockHeader {
        version: 1,
        prev_block_hash: prev_hash,
        merkle_root,
        time: 1231006505,
        bits: 0x207fffff, // regtest difficulty
        nonce: 0,
    }
}

/// Build a coinbase transaction paying `reward` satoshis to a simple OP_1 script.
fn make_coinbase_tx(height: u32, reward: i64) -> Transaction {
    // BIP34: coinbase scriptSig starts with block height
    let mut script_bytes = vec![0x03]; // push 3 bytes
    script_bytes.extend_from_slice(&(height as u32).to_le_bytes()[..3]);

    let input = TxIn {
        previous_output: OutPoint {
            txid: Txid::zero(),
            vout: 0xFFFFFFFF,
        },
        script_sig: Script::from_bytes(script_bytes),
        sequence: 0xFFFFFFFF,
        witness: btc_domain::script::witness::Witness::new(),
    };

    let output = TxOut::new(Amount::from_sat(reward), Script::from_bytes(vec![0x51])); // OP_1

    Transaction::new(1, vec![input], vec![output], 0)
}

/// Create a minimal valid block with just a coinbase transaction.
fn make_block_with_coinbase(prev_hash: BlockHash, height: u32, reward: i64) -> Block {
    let coinbase = make_coinbase_tx(height, reward);
    let txs = vec![coinbase];
    let mut block = Block {
        header: make_header(prev_hash, Hash256::zero()),
        transactions: txs,
    };
    // Fix the merkle root to match the actual transactions
    let merkle_root = block.compute_merkle_root();
    block.header.merkle_root = merkle_root;
    block
}

/// Create a block that also includes a spending transaction.
fn make_block_with_spend(
    prev_hash: BlockHash,
    height: u32,
    subsidy: i64,
    spend_tx: Transaction,
    fee: i64,
) -> Block {
    let coinbase = make_coinbase_tx(height, subsidy + fee);
    let txs = vec![coinbase, spend_tx];
    let mut block = Block {
        header: make_header(prev_hash, Hash256::zero()),
        transactions: txs,
    };
    let merkle_root = block.compute_merkle_root();
    block.header.merkle_root = merkle_root;
    block
}

/// Shorthand to create a BlockHash from raw bytes
fn bh(bytes: [u8; 32]) -> BlockHash {
    BlockHash::from_hash(Hash256::from_bytes(bytes))
}

fn regtest_params() -> ConsensusParams {
    ConsensusParams::for_network(Network::Regtest)
}

// ═══════════════════════════════════════════════════════════════════════
// Basic block connection tests
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn test_connect_coinbase_only_block() {
    let params = regtest_params();
    let utxo_set = MemoryUtxoSet::new();

    let block = make_block_with_coinbase(bh([0u8; 32]), 0, 5_000_000_000);

    let result = connect_block(&block, 0, &utxo_set, &params, false).unwrap();

    // Should create 1 UTXO (coinbase output)
    assert_eq!(result.created.len(), 1, "Should create 1 UTXO");
    assert!(result.spent.is_empty(), "Should not spend anything");
    assert_eq!(result.total_fees.as_sat(), 0, "No fees in coinbase-only block");
}

#[test]
fn test_connect_block_updates_utxo_set() {
    let params = regtest_params();
    let mut utxo_set = MemoryUtxoSet::new();

    // Connect block 0
    let block0 = make_block_with_coinbase(bh([0u8; 32]), 0, 5_000_000_000);
    let result0 = connect_block(&block0, 0, &utxo_set, &params, false).unwrap();
    utxo_set.apply_connect(&result0);

    assert_eq!(utxo_set.len(), 1, "UTXO set should have 1 entry after block 0");

    // Connect block 1
    let block1 = make_block_with_coinbase(bh([0x01; 32]), 1, 5_000_000_000);
    let result1 = connect_block(&block1, 1, &utxo_set, &params, false).unwrap();
    utxo_set.apply_connect(&result1);

    assert_eq!(utxo_set.len(), 2, "UTXO set should have 2 entries after block 1");
}

#[test]
fn test_coinbase_overpay_rejected() {
    let params = regtest_params();
    let utxo_set = MemoryUtxoSet::new();

    // Try to claim more than the subsidy
    let block = make_block_with_coinbase(bh([0u8; 32]), 0, 5_000_000_001);

    let result = connect_block(&block, 0, &utxo_set, &params, false);
    assert!(result.is_err(), "Should reject coinbase overpay");

    match result.unwrap_err() {
        ConnectBlockError::CoinbaseOverpay { allowed, actual } => {
            assert_eq!(allowed, 5_000_000_000);
            assert_eq!(actual, 5_000_000_001);
        }
        e => panic!("Expected CoinbaseOverpay, got: {:?}", e),
    }
}

#[test]
fn test_coinbase_underpay_allowed() {
    let params = regtest_params();
    let utxo_set = MemoryUtxoSet::new();

    // Claiming less than subsidy is fine (miner's loss)
    let block = make_block_with_coinbase(bh([0u8; 32]), 0, 4_999_999_999);
    let result = connect_block(&block, 0, &utxo_set, &params, false);
    assert!(result.is_ok(), "Should allow coinbase underpay");
}

// ═══════════════════════════════════════════════════════════════════════
// UTXO spending tests
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn test_spend_existing_utxo() {
    let params = regtest_params();
    let mut utxo_set = MemoryUtxoSet::new();

    // Create a UTXO at height 0 (non-coinbase, so no maturity wait)
    let prev_txid = Txid::from_hash(Hash256::from_bytes([0xAA; 32]));
    let utxo_script = Script::from_bytes(vec![0x51]); // OP_1 (anyone can spend)
    utxo_set.add(
        OutPoint::new(prev_txid, 0),
        UtxoEntry {
            output: TxOut::new(Amount::from_sat(100_000), utxo_script),
            height: 0,
            is_coinbase: false,
        },
    );

    // Build a transaction that spends the UTXO
    let spend_input = TxIn {
        previous_output: OutPoint::new(prev_txid, 0),
        script_sig: Script::from_bytes(vec![0x51]), // OP_1 satisfies OP_1
        sequence: 0xFFFFFFFF,
        witness: btc_domain::script::witness::Witness::new(),
    };
    let spend_output = TxOut::new(Amount::from_sat(90_000), Script::from_bytes(vec![0x51]));
    let spend_tx = Transaction::new(1, vec![spend_input], vec![spend_output], 0);

    let fee = 10_000i64;
    let block = make_block_with_spend(bh([0u8; 32]), 1, 5_000_000_000, spend_tx, fee);

    let result = connect_block(&block, 1, &utxo_set, &params, false).unwrap();

    // 1 UTXO spent (the 100k one)
    assert_eq!(result.spent.len(), 1, "Should spend 1 UTXO");
    assert!(result.spent.contains_key(&OutPoint::new(prev_txid, 0)));

    // 2 UTXOs created (coinbase output + spend_tx output)
    assert_eq!(result.created.len(), 2, "Should create 2 UTXOs");

    // Fee = 100_000 - 90_000 = 10_000
    assert_eq!(result.total_fees.as_sat(), 10_000, "Fee should be 10k sats");
}

#[test]
fn test_missing_utxo_rejected() {
    let params = regtest_params();
    let utxo_set = MemoryUtxoSet::new(); // empty!

    // Build tx spending a non-existent UTXO
    let spend_input = TxIn {
        previous_output: OutPoint::new(Txid::from_hash(Hash256::from_bytes([0xBB; 32])), 0),
        script_sig: Script::from_bytes(vec![0x51]),
        sequence: 0xFFFFFFFF,
        witness: btc_domain::script::witness::Witness::new(),
    };
    let spend_tx = Transaction::new(
        1,
        vec![spend_input],
        vec![TxOut::new(Amount::from_sat(1000), Script::from_bytes(vec![0x51]))],
        0,
    );

    let block = make_block_with_spend(bh([0u8; 32]), 1, 5_000_000_000, spend_tx, 0);

    let result = connect_block(&block, 1, &utxo_set, &params, false);
    assert!(matches!(result, Err(ConnectBlockError::MissingUtxo(_))));
}

#[test]
fn test_double_spend_in_block_rejected() {
    let params = regtest_params();
    let mut utxo_set = MemoryUtxoSet::new();

    let prev_txid = Txid::from_hash(Hash256::from_bytes([0xCC; 32]));
    utxo_set.add(
        OutPoint::new(prev_txid, 0),
        UtxoEntry {
            output: TxOut::new(Amount::from_sat(100_000), Script::from_bytes(vec![0x51])),
            height: 0,
            is_coinbase: false,
        },
    );

    // Two transactions in the same block both spending the same outpoint
    let spend1 = Transaction::new(
        1,
        vec![TxIn {
            previous_output: OutPoint::new(prev_txid, 0),
            script_sig: Script::from_bytes(vec![0x51]),
            sequence: 0xFFFFFFFF,
            witness: btc_domain::script::witness::Witness::new(),
        }],
        vec![TxOut::new(Amount::from_sat(50_000), Script::from_bytes(vec![0x51]))],
        0,
    );
    let spend2 = Transaction::new(
        1,
        vec![TxIn {
            previous_output: OutPoint::new(prev_txid, 0),
            script_sig: Script::from_bytes(vec![0x51]),
            sequence: 0xFFFFFFFF,
            witness: btc_domain::script::witness::Witness::new(),
        }],
        vec![TxOut::new(Amount::from_sat(40_000), Script::from_bytes(vec![0x51]))],
        0,
    );

    let coinbase = make_coinbase_tx(1, 5_000_000_000 + 10_000);
    let mut block = Block {
        header: make_header(bh([0u8; 32]), Hash256::zero()),
        transactions: vec![coinbase, spend1, spend2],
    };
    block.header.merkle_root = block.compute_merkle_root();

    let result = connect_block(&block, 1, &utxo_set, &params, false);
    assert!(
        matches!(result, Err(ConnectBlockError::DoubleSpendInBlock(_))),
        "Should reject double-spend within block"
    );
}

// ═══════════════════════════════════════════════════════════════════════
// Coinbase maturity tests
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn test_premature_coinbase_spend_rejected() {
    let params = regtest_params();
    let mut utxo_set = MemoryUtxoSet::new();

    // Coinbase UTXO created at height 0
    let coinbase_txid = Txid::from_hash(Hash256::from_bytes([0xDD; 32]));
    utxo_set.add(
        OutPoint::new(coinbase_txid, 0),
        UtxoEntry {
            output: TxOut::new(Amount::from_sat(5_000_000_000), Script::from_bytes(vec![0x51])),
            height: 0,
            is_coinbase: true, // THIS is a coinbase output
        },
    );

    // Try to spend it at height 50 (only 50 confirmations, need 100)
    let spend_tx = Transaction::new(
        1,
        vec![TxIn {
            previous_output: OutPoint::new(coinbase_txid, 0),
            script_sig: Script::from_bytes(vec![0x51]),
            sequence: 0xFFFFFFFF,
            witness: btc_domain::script::witness::Witness::new(),
        }],
        vec![TxOut::new(Amount::from_sat(4_999_990_000), Script::from_bytes(vec![0x51]))],
        0,
    );

    let block = make_block_with_spend(bh([0u8; 32]), 50, 5_000_000_000, spend_tx, 10_000);

    let result = connect_block(&block, 50, &utxo_set, &params, false);
    assert!(
        matches!(result, Err(ConnectBlockError::PrematureCoinbaseSpend { .. })),
        "Should reject premature coinbase spend at height 50"
    );
}

#[test]
fn test_mature_coinbase_spend_accepted() {
    let params = regtest_params();
    let mut utxo_set = MemoryUtxoSet::new();

    // Coinbase UTXO created at height 0
    let coinbase_txid = Txid::from_hash(Hash256::from_bytes([0xEE; 32]));
    utxo_set.add(
        OutPoint::new(coinbase_txid, 0),
        UtxoEntry {
            output: TxOut::new(Amount::from_sat(5_000_000_000), Script::from_bytes(vec![0x51])),
            height: 0,
            is_coinbase: true,
        },
    );

    // Spend at height 100 (exactly 100 confirmations — mature!)
    let spend_tx = Transaction::new(
        1,
        vec![TxIn {
            previous_output: OutPoint::new(coinbase_txid, 0),
            script_sig: Script::from_bytes(vec![0x51]),
            sequence: 0xFFFFFFFF,
            witness: btc_domain::script::witness::Witness::new(),
        }],
        vec![TxOut::new(Amount::from_sat(4_999_990_000), Script::from_bytes(vec![0x51]))],
        0,
    );

    let block = make_block_with_spend(bh([0u8; 32]), 100, 5_000_000_000, spend_tx, 10_000);

    let result = connect_block(&block, 100, &utxo_set, &params, false);
    assert!(result.is_ok(), "Should accept coinbase spend at height 100: {:?}", result.err());
}

// ═══════════════════════════════════════════════════════════════════════
// Connect/Disconnect round-trip
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn test_connect_disconnect_roundtrip() {
    let params = regtest_params();
    let mut utxo_set = MemoryUtxoSet::new();

    // Start with an existing UTXO
    let prev_txid = Txid::from_hash(Hash256::from_bytes([0xFF; 32]));
    utxo_set.add(
        OutPoint::new(prev_txid, 0),
        UtxoEntry {
            output: TxOut::new(Amount::from_sat(100_000), Script::from_bytes(vec![0x51])),
            height: 0,
            is_coinbase: false,
        },
    );
    let initial_len = utxo_set.len();

    // Connect a block that spends the UTXO
    let spend_tx = Transaction::new(
        1,
        vec![TxIn {
            previous_output: OutPoint::new(prev_txid, 0),
            script_sig: Script::from_bytes(vec![0x51]),
            sequence: 0xFFFFFFFF,
            witness: btc_domain::script::witness::Witness::new(),
        }],
        vec![TxOut::new(Amount::from_sat(90_000), Script::from_bytes(vec![0x51]))],
        0,
    );
    let block = make_block_with_spend(bh([0u8; 32]), 1, 5_000_000_000, spend_tx, 10_000);

    let connect_result = connect_block(&block, 1, &utxo_set, &params, false).unwrap();
    utxo_set.apply_connect(&connect_result);

    // The original UTXO should be gone, 2 new ones created
    assert!(utxo_set.get_utxo(&OutPoint::new(prev_txid, 0)).is_none());
    assert_eq!(utxo_set.len(), 2); // coinbase output + spend output

    // Disconnect the block
    let disconnect_result = disconnect_block(&connect_result);
    utxo_set.apply_disconnect(&disconnect_result);

    // Should be back to initial state
    assert_eq!(utxo_set.len(), initial_len);
    assert!(utxo_set.get_utxo(&OutPoint::new(prev_txid, 0)).is_some());
}

// ═══════════════════════════════════════════════════════════════════════
// Script verification during block connection
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn test_connect_block_with_real_p2pkh_scripts() {
    let params = regtest_params();
    let mut utxo_set = MemoryUtxoSet::new();

    // Generate a real keypair and create a P2PKH UTXO
    let key = PrivateKey::generate(true, true);
    let pubkey = key.public_key();
    let script_pubkey = make_p2pkh_script(&pubkey.pubkey_hash());

    let prev_txid = Txid::from_hash(Hash256::from_bytes([0x11; 32]));
    utxo_set.add(
        OutPoint::new(prev_txid, 0),
        UtxoEntry {
            output: TxOut::new(Amount::from_sat(100_000), script_pubkey.clone()),
            height: 0,
            is_coinbase: false,
        },
    );

    // Build and sign a real spending transaction
    let signed_tx = TransactionBuilder::new()
        .version(1)
        .add_input(InputInfo {
            outpoint: OutPoint::new(prev_txid, 0),
            script_pubkey,
            amount: Amount::from_sat(100_000),
            signing_key: Some(key),
            sequence: 0xFFFFFFFF,
        })
        .add_output(TxOut::new(Amount::from_sat(90_000), Script::from_bytes(vec![0x51])))
        .sign()
        .unwrap();

    let fee = 10_000i64;
    let block = make_block_with_spend(bh([0u8; 32]), 1, 5_000_000_000, signed_tx, fee);

    // Connect with script verification ENABLED
    let result = connect_block(&block, 1, &utxo_set, &params, true);
    assert!(result.is_ok(), "P2PKH script verification during block connect failed: {:?}", result.err());
}

#[test]
fn test_connect_block_with_real_p2wpkh_scripts() {
    let params = regtest_params();
    let mut utxo_set = MemoryUtxoSet::new();

    // Generate a keypair and create a P2WPKH UTXO
    let key = PrivateKey::generate(true, true);
    let pubkey = key.public_key();
    let script_pubkey = make_p2wpkh_script(&pubkey.pubkey_hash());

    let prev_txid = Txid::from_hash(Hash256::from_bytes([0x22; 32]));
    utxo_set.add(
        OutPoint::new(prev_txid, 0),
        UtxoEntry {
            output: TxOut::new(Amount::from_sat(200_000), script_pubkey.clone()),
            height: 0,
            is_coinbase: false,
        },
    );

    let signed_tx = TransactionBuilder::new()
        .version(2)
        .add_input(InputInfo {
            outpoint: OutPoint::new(prev_txid, 0),
            script_pubkey,
            amount: Amount::from_sat(200_000),
            signing_key: Some(key),
            sequence: 0xFFFFFFFE,
        })
        .add_output(TxOut::new(Amount::from_sat(190_000), Script::from_bytes(vec![0x51])))
        .sign()
        .unwrap();

    let fee = 10_000i64;
    let block = make_block_with_spend(bh([0u8; 32]), 1, 5_000_000_000, signed_tx, fee);

    let result = connect_block(&block, 1, &utxo_set, &params, true);
    assert!(result.is_ok(), "P2WPKH script verification during block connect failed: {:?}", result.err());
}

#[test]
fn test_connect_block_bad_signature_rejected() {
    let params = regtest_params();
    let mut utxo_set = MemoryUtxoSet::new();

    // Create UTXO locked to key1
    let key1 = PrivateKey::generate(true, true);
    let script_pubkey = make_p2pkh_script(&key1.public_key().pubkey_hash());

    let prev_txid = Txid::from_hash(Hash256::from_bytes([0x33; 32]));
    utxo_set.add(
        OutPoint::new(prev_txid, 0),
        UtxoEntry {
            output: TxOut::new(Amount::from_sat(100_000), script_pubkey.clone()),
            height: 0,
            is_coinbase: false,
        },
    );

    // Sign with WRONG key
    let wrong_key = PrivateKey::generate(true, true);
    let signed_tx = TransactionBuilder::new()
        .version(1)
        .add_input(InputInfo {
            outpoint: OutPoint::new(prev_txid, 0),
            script_pubkey,
            amount: Amount::from_sat(100_000),
            signing_key: Some(wrong_key),
            sequence: 0xFFFFFFFF,
        })
        .add_output(TxOut::new(Amount::from_sat(90_000), Script::from_bytes(vec![0x51])))
        .sign()
        .unwrap();

    let block = make_block_with_spend(bh([0u8; 32]), 1, 5_000_000_000, signed_tx, 10_000);

    let result = connect_block(&block, 1, &utxo_set, &params, true);
    assert!(
        matches!(result, Err(ConnectBlockError::ScriptVerificationFailed { .. })),
        "Should reject block with bad signature: {:?}",
        result
    );
}

// ═══════════════════════════════════════════════════════════════════════
// Multi-block chain test
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn test_multi_block_chain() {
    let params = regtest_params();
    let mut utxo_set = MemoryUtxoSet::new();

    // Connect 5 coinbase-only blocks
    let mut results = Vec::new();
    for height in 0..5u32 {
        let prev = bh([height as u8; 32]);
        let block = make_block_with_coinbase(prev, height, 5_000_000_000);
        let result = connect_block(&block, height, &utxo_set, &params, false).unwrap();
        utxo_set.apply_connect(&result);
        results.push(result);
    }

    // Should have 5 coinbase UTXOs
    assert_eq!(utxo_set.len(), 5);

    // Disconnect the last 2 blocks (simulate reorg)
    for result in results.iter().rev().take(2) {
        let disc = disconnect_block(result);
        utxo_set.apply_disconnect(&disc);
    }

    // Should have 3 coinbase UTXOs
    assert_eq!(utxo_set.len(), 3);
}

#[test]
fn test_halving_reduces_subsidy() {
    let params = regtest_params();
    let utxo_set = MemoryUtxoSet::new();

    // At height 150 on regtest (halving interval = 150), subsidy halves to 25 BTC
    let halving_interval = params.subsidy_halving_interval;

    // Trying to claim 50 BTC after halving should fail
    let block = make_block_with_coinbase(bh([0u8; 32]), halving_interval, 5_000_000_000);
    let result = connect_block(&block, halving_interval, &utxo_set, &params, false);
    assert!(
        matches!(result, Err(ConnectBlockError::CoinbaseOverpay { .. })),
        "Should reject 50 BTC coinbase after halving"
    );

    // Claiming 25 BTC should succeed
    let block = make_block_with_coinbase(bh([0u8; 32]), halving_interval, 2_500_000_000);
    let result = connect_block(&block, halving_interval, &utxo_set, &params, false);
    assert!(result.is_ok(), "25 BTC coinbase should work after halving: {:?}", result.err());
}

// ═══════════════════════════════════════════════════════════════════════
// Input value < output value (inflation bug prevention)
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn test_inflation_rejected() {
    let params = regtest_params();
    let mut utxo_set = MemoryUtxoSet::new();

    let prev_txid = Txid::from_hash(Hash256::from_bytes([0x44; 32]));
    utxo_set.add(
        OutPoint::new(prev_txid, 0),
        UtxoEntry {
            output: TxOut::new(Amount::from_sat(100_000), Script::from_bytes(vec![0x51])),
            height: 0,
            is_coinbase: false,
        },
    );

    // Try to create more value than input (100k in, 200k out)
    let inflate_tx = Transaction::new(
        1,
        vec![TxIn {
            previous_output: OutPoint::new(prev_txid, 0),
            script_sig: Script::from_bytes(vec![0x51]),
            sequence: 0xFFFFFFFF,
            witness: btc_domain::script::witness::Witness::new(),
        }],
        vec![TxOut::new(Amount::from_sat(200_000), Script::from_bytes(vec![0x51]))],
        0,
    );

    // Note: coinbase must cover the "negative fee"
    let coinbase = make_coinbase_tx(1, 5_000_000_000);
    let mut block = Block {
        header: make_header(bh([0u8; 32]), Hash256::zero()),
        transactions: vec![coinbase, inflate_tx],
    };
    block.header.merkle_root = block.compute_merkle_root();

    let result = connect_block(&block, 1, &utxo_set, &params, false);
    assert!(
        matches!(result, Err(ConnectBlockError::InputValueBelowOutput { .. })),
        "Should reject transaction creating value from nothing: {:?}",
        result
    );
}
