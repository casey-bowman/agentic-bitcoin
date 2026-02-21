//! Chain State Manager integration tests
//!
//! Tests the full chain management pipeline: genesis initialisation,
//! sequential block connection, reorgs, side chains, and UTXO tracking.

use btc_application::chain_state::{ChainState, ChainStateError, ProcessBlockResult};
use btc_domain::consensus::{ConsensusParams, Network};
use btc_domain::primitives::block::{Block, BlockHeader};
use btc_domain::primitives::hash::{BlockHash, Hash256};
use btc_domain::primitives::{Amount, OutPoint, Transaction, TxIn, TxOut, Txid};
use btc_domain::script::Script;
use btc_domain::script::witness::Witness;

// ── Helpers ─────────────────────────────────────────────────────────

fn regtest_params() -> ConsensusParams {
    ConsensusParams::for_network(Network::Regtest)
}

fn make_header(prev_hash: BlockHash, merkle_root: Hash256, time: u32) -> BlockHeader {
    BlockHeader {
        version: 1,
        prev_block_hash: prev_hash,
        merkle_root,
        time,
        bits: 0x207fffff, // regtest — any hash passes PoW
        nonce: 0,
    }
}

/// Build a coinbase transaction paying `reward` satoshis to a simple OP_1 script.
fn make_coinbase_tx(height: u32, reward: i64) -> Transaction {
    let mut script_bytes = vec![0x03]; // push 3 bytes
    script_bytes.extend_from_slice(&height.to_le_bytes()[..3]);

    let input = TxIn {
        previous_output: OutPoint {
            txid: Txid::zero(),
            vout: 0xFFFFFFFF,
        },
        script_sig: Script::from_bytes(script_bytes),
        sequence: 0xFFFFFFFF,
        witness: Witness::new(),
    };

    let output = TxOut::new(Amount::from_sat(reward), Script::from_bytes(vec![0x51])); // OP_1

    Transaction::new(1, vec![input], vec![output], 0)
}

/// Create a minimal valid block with just a coinbase.
fn make_block(prev_hash: BlockHash, height: u32, reward: i64, time: u32) -> Block {
    let coinbase = make_coinbase_tx(height, reward);
    let txs = vec![coinbase];
    let mut block = Block {
        header: make_header(prev_hash, Hash256::zero(), time),
        transactions: txs,
    };
    let merkle_root = block.compute_merkle_root();
    block.header.merkle_root = merkle_root;
    block
}

/// Create a block with an additional spending transaction.
fn make_block_with_spend(
    prev_hash: BlockHash,
    height: u32,
    subsidy: i64,
    spend_tx: Transaction,
    fee: i64,
    time: u32,
) -> Block {
    let coinbase = make_coinbase_tx(height, subsidy + fee);
    let txs = vec![coinbase, spend_tx];
    let mut block = Block {
        header: make_header(prev_hash, Hash256::zero(), time),
        transactions: txs,
    };
    let merkle_root = block.compute_merkle_root();
    block.header.merkle_root = merkle_root;
    block
}

/// Simple spending tx: consumes `input_outpoint` (no real sig, script verification off)
fn make_simple_spend(input_outpoint: OutPoint, value: i64) -> Transaction {
    let input = TxIn {
        previous_output: input_outpoint,
        script_sig: Script::from_bytes(vec![0x51]), // OP_1 (trivially true)
        sequence: 0xFFFFFFFF,
        witness: Witness::new(),
    };
    let output = TxOut::new(Amount::from_sat(value), Script::from_bytes(vec![0x51]));
    Transaction::new(1, vec![input], vec![output], 0)
}

const SUBSIDY: i64 = 5_000_000_000;

fn make_genesis() -> Block {
    make_block(BlockHash::zero(), 0, SUBSIDY, 1231006505)
}

// ═══════════════════════════════════════════════════════════════════════
// Genesis and basic connection
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn test_genesis_initialisation() {
    let params = regtest_params();
    let genesis = make_genesis();
    let genesis_hash = genesis.block_hash();

    let cs = ChainState::new(genesis, params).unwrap();

    assert_eq!(cs.tip(), genesis_hash);
    assert_eq!(cs.tip_height(), 0);
    assert_eq!(cs.block_count(), 1);
    // Genesis coinbase creates 1 UTXO
    assert_eq!(cs.utxo_count(), 1);
}

#[test]
fn test_connect_single_block() {
    let params = regtest_params();
    let genesis = make_genesis();
    let genesis_hash = genesis.block_hash();

    let mut cs = ChainState::new(genesis, params).unwrap();
    cs.set_verify_scripts(false);

    let block1 = make_block(genesis_hash, 1, SUBSIDY, 1231006506);
    let block1_hash = block1.block_hash();

    match cs.process_block(block1).unwrap() {
        ProcessBlockResult::Connected { hash, height } => {
            assert_eq!(hash, block1_hash);
            assert_eq!(height, 1);
        }
        other => panic!("Expected Connected, got {:?}", other),
    }

    assert_eq!(cs.tip(), block1_hash);
    assert_eq!(cs.tip_height(), 1);
    // 2 coinbase UTXOs (genesis + block 1)
    assert_eq!(cs.utxo_count(), 2);
}

#[test]
fn test_connect_chain_of_blocks() {
    let params = regtest_params();
    let genesis = make_genesis();

    let mut cs = ChainState::new(genesis, params).unwrap();
    cs.set_verify_scripts(false);

    let mut prev_hash = cs.tip();

    for h in 1..=10 {
        let block = make_block(prev_hash, h, SUBSIDY, 1231006505 + h);
        prev_hash = block.block_hash();
        cs.process_block(block).unwrap();
    }

    assert_eq!(cs.tip_height(), 10);
    // 11 coinbase UTXOs (genesis + 10 blocks)
    assert_eq!(cs.utxo_count(), 11);
}

#[test]
fn test_duplicate_block_ignored() {
    let params = regtest_params();
    let genesis = make_genesis();
    let genesis_hash = genesis.block_hash();

    let mut cs = ChainState::new(genesis, params).unwrap();
    cs.set_verify_scripts(false);

    let block1 = make_block(genesis_hash, 1, SUBSIDY, 1231006506);
    cs.process_block(block1.clone()).unwrap();

    match cs.process_block(block1).unwrap() {
        ProcessBlockResult::AlreadyKnown { .. } => {} // expected
        other => panic!("Expected AlreadyKnown, got {:?}", other),
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Side chains
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn test_side_chain_not_activated() {
    let params = regtest_params();
    let genesis = make_genesis();
    let genesis_hash = genesis.block_hash();

    let mut cs = ChainState::new(genesis, params).unwrap();
    cs.set_verify_scripts(false);

    // Main chain: genesis → A1 → A2
    let a1 = make_block(genesis_hash, 1, SUBSIDY, 1231006506);
    let a1_hash = a1.block_hash();
    cs.process_block(a1).unwrap();

    let a2 = make_block(a1_hash, 2, SUBSIDY, 1231006507);
    let a2_hash = a2.block_hash();
    cs.process_block(a2).unwrap();

    // Side chain: genesis → B1 (shorter, less work)
    let b1 = make_block(genesis_hash, 1, SUBSIDY, 1231009999);
    let b1_hash = b1.block_hash();

    match cs.process_block(b1).unwrap() {
        ProcessBlockResult::SideChain { hash, height } => {
            assert_eq!(hash, b1_hash);
            assert_eq!(height, 1);
        }
        other => panic!("Expected SideChain, got {:?}", other),
    }

    // Tip should remain on chain A
    assert_eq!(cs.tip(), a2_hash);
    assert_eq!(cs.tip_height(), 2);
}

// ═══════════════════════════════════════════════════════════════════════
// Reorgs
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn test_reorg_to_longer_chain() {
    let params = regtest_params();
    let genesis = make_genesis();
    let genesis_hash = genesis.block_hash();

    let mut cs = ChainState::new(genesis, params).unwrap();
    cs.set_verify_scripts(false);

    // Chain A: genesis → A1 → A2 (height 2)
    let a1 = make_block(genesis_hash, 1, SUBSIDY, 1231006506);
    let a1_hash = a1.block_hash();
    cs.process_block(a1).unwrap();

    let a2 = make_block(a1_hash, 2, SUBSIDY, 1231006507);
    let a2_hash = a2.block_hash();
    cs.process_block(a2).unwrap();

    assert_eq!(cs.tip(), a2_hash);
    assert_eq!(cs.tip_height(), 2);

    // Chain B: genesis → B1 → B2 → B3 (height 3, more work)
    let b1 = make_block(genesis_hash, 1, SUBSIDY, 1231009001);
    let b1_hash = b1.block_hash();
    // B1 goes as side chain (less work than A's height 2)
    cs.process_block(b1).unwrap();

    let b2 = make_block(b1_hash, 2, SUBSIDY, 1231009002);
    let b2_hash = b2.block_hash();
    // B2 ties with A2 at height 2, still side chain (equal work, not greater)
    cs.process_block(b2).unwrap();

    let b3 = make_block(b2_hash, 3, SUBSIDY, 1231009003);
    let b3_hash = b3.block_hash();

    // B3 should trigger reorg since B chain now has more work
    match cs.process_block(b3).unwrap() {
        ProcessBlockResult::Reorged {
            hash,
            height,
            disconnected,
            connected,
        } => {
            assert_eq!(hash, b3_hash);
            assert_eq!(height, 3);
            assert_eq!(disconnected, 2, "Should disconnect A2, A1");
            assert_eq!(connected, 3, "Should connect B1, B2, B3");
        }
        other => panic!("Expected Reorged, got {:?}", other),
    }

    assert_eq!(cs.tip(), b3_hash);
    assert_eq!(cs.tip_height(), 3);

    // UTXO count: genesis + B1 + B2 + B3 = 4 coinbase UTXOs
    // (A1, A2 coinbase UTXOs should be gone)
    assert_eq!(cs.utxo_count(), 4);
}

#[test]
fn test_reorg_preserves_utxo_integrity() {
    let params = regtest_params();
    let genesis = make_genesis();
    let genesis_hash = genesis.block_hash();

    let mut cs = ChainState::new(genesis, params).unwrap();
    cs.set_verify_scripts(false);

    // Chain A: genesis → A1
    let a1 = make_block(genesis_hash, 1, SUBSIDY, 1231006506);
    cs.process_block(a1).unwrap();

    // Record the UTXO count after chain A
    let utxos_after_a = cs.utxo_count(); // 2 (genesis + A1)
    assert_eq!(utxos_after_a, 2);

    // Chain B: genesis → B1 → B2 (more work, triggers reorg)
    let b1 = make_block(genesis_hash, 1, SUBSIDY, 1231009001);
    let b1_hash = b1.block_hash();
    cs.process_block(b1).unwrap();

    let b2 = make_block(b1_hash, 2, SUBSIDY, 1231009002);
    cs.process_block(b2).unwrap();

    // After reorg: genesis + B1 + B2 = 3 UTXOs
    assert_eq!(cs.utxo_count(), 3);

    // A1's coinbase UTXO should no longer exist
    // (We can't easily look it up without the txid, but the count confirms)
}

#[test]
fn test_one_block_reorg() {
    let params = regtest_params();
    let genesis = make_genesis();
    let genesis_hash = genesis.block_hash();

    let mut cs = ChainState::new(genesis, params).unwrap();
    cs.set_verify_scripts(false);

    // Chain A: genesis → A1
    let a1 = make_block(genesis_hash, 1, SUBSIDY, 1231006506);
    cs.process_block(a1).unwrap();

    // Chain B: genesis → B1 → B2 (overtakes A)
    let b1 = make_block(genesis_hash, 1, SUBSIDY, 1231009001);
    let b1_hash = b1.block_hash();
    cs.process_block(b1).unwrap();

    let b2 = make_block(b1_hash, 2, SUBSIDY, 1231009002);
    let b2_hash = b2.block_hash();

    match cs.process_block(b2).unwrap() {
        ProcessBlockResult::Reorged {
            disconnected,
            connected,
            ..
        } => {
            assert_eq!(disconnected, 1);
            assert_eq!(connected, 2);
        }
        other => panic!("Expected Reorged, got {:?}", other),
    }

    assert_eq!(cs.tip(), b2_hash);
    assert_eq!(cs.tip_height(), 2);
}

// ═══════════════════════════════════════════════════════════════════════
// Block with spending transactions
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn test_spend_in_subsequent_block() {
    let params = regtest_params();
    let genesis = make_genesis();
    let genesis_hash = genesis.block_hash();

    let mut cs = ChainState::new(genesis, params).unwrap();
    cs.set_verify_scripts(false);

    // Build 100 blocks to mature the genesis coinbase.
    let mut prev = genesis_hash;
    for h in 1..=100 {
        let block = make_block(prev, h, SUBSIDY, 1231006505 + h);
        prev = block.block_hash();
        cs.process_block(block).unwrap();
    }

    assert_eq!(cs.tip_height(), 100);

    // Spend the genesis coinbase (now mature).
    let genesis_block = cs.get_block(&genesis_hash).unwrap();
    let genesis_txid = genesis_block.transactions[0].txid();
    let spend_outpoint = OutPoint::new(genesis_txid, 0);

    let spend_tx = make_simple_spend(spend_outpoint, SUBSIDY - 1000); // 1000 sat fee
    let block101 = make_block_with_spend(prev, 101, SUBSIDY, spend_tx, 1000, 1231006606);

    match cs.process_block(block101).unwrap() {
        ProcessBlockResult::Connected { height, .. } => {
            assert_eq!(height, 101);
        }
        other => panic!("Expected Connected, got {:?}", other),
    }

    // Genesis coinbase UTXO is spent (-1), spend tx creates 1 output (+1),
    // block 101 coinbase creates 1 output (+1).
    // Total: 101 (genesis..block100) - 1 + 1 + 1 = 102
    assert_eq!(cs.utxo_count(), 102);
}

// ═══════════════════════════════════════════════════════════════════════
// Error cases
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn test_orphan_block_rejected() {
    let params = regtest_params();
    let genesis = make_genesis();

    let mut cs = ChainState::new(genesis, params).unwrap();

    // Block with unknown parent
    let orphan = make_block(
        BlockHash::from_hash(Hash256::from_bytes([0xAB; 32])),
        1,
        SUBSIDY,
        1231006506,
    );

    match cs.process_block(orphan) {
        Err(ChainStateError::OrphanBlock) => {} // expected
        other => panic!("Expected OrphanBlock error, got {:?}", other),
    }
}

#[test]
fn test_coinbase_overpay_rejected() {
    let params = regtest_params();
    let genesis = make_genesis();
    let genesis_hash = genesis.block_hash();

    let mut cs = ChainState::new(genesis, params).unwrap();
    cs.set_verify_scripts(false);

    // Block with coinbase claiming more than the subsidy
    let bad_block = make_block(genesis_hash, 1, SUBSIDY + 1, 1231006506);

    match cs.process_block(bad_block) {
        Err(ChainStateError::ValidationFailed(_)) => {} // expected
        other => panic!("Expected ValidationFailed, got {:?}", other),
    }

    // Tip should not have moved
    assert_eq!(cs.tip(), genesis_hash);
    assert_eq!(cs.tip_height(), 0);
}

// ═══════════════════════════════════════════════════════════════════════
// Accessors
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn test_get_block_by_hash() {
    let params = regtest_params();
    let genesis = make_genesis();
    let genesis_hash = genesis.block_hash();

    let mut cs = ChainState::new(genesis, params).unwrap();
    cs.set_verify_scripts(false);

    let block1 = make_block(genesis_hash, 1, SUBSIDY, 1231006506);
    let block1_hash = block1.block_hash();
    cs.process_block(block1).unwrap();

    assert!(cs.get_block(&block1_hash).is_some());
    assert!(cs.get_block(&BlockHash::zero()).is_none());
}

#[test]
fn test_height_lookup_through_index() {
    let params = regtest_params();
    let genesis = make_genesis();
    let genesis_hash = genesis.block_hash();

    let mut cs = ChainState::new(genesis, params).unwrap();
    cs.set_verify_scripts(false);

    let block1 = make_block(genesis_hash, 1, SUBSIDY, 1231006506);
    let block1_hash = block1.block_hash();
    cs.process_block(block1).unwrap();

    assert_eq!(cs.get_block_hash_at_height(0), Some(genesis_hash));
    assert_eq!(cs.get_block_hash_at_height(1), Some(block1_hash));
    assert_eq!(cs.get_block_hash_at_height(2), None);
}

#[test]
fn test_deep_reorg() {
    let params = regtest_params();
    let genesis = make_genesis();
    let genesis_hash = genesis.block_hash();

    let mut cs = ChainState::new(genesis, params).unwrap();
    cs.set_verify_scripts(false);

    // Chain A: 5 blocks
    let mut prev_a = genesis_hash;
    for h in 1..=5 {
        let block = make_block(prev_a, h, SUBSIDY, 1231006505 + h);
        prev_a = block.block_hash();
        cs.process_block(block).unwrap();
    }
    assert_eq!(cs.tip_height(), 5);

    // Chain B: 6 blocks from genesis (overtakes A)
    let mut prev_b = genesis_hash;
    for h in 1..=5 {
        let block = make_block(prev_b, h, SUBSIDY, 1231009000 + h);
        prev_b = block.block_hash();
        cs.process_block(block).unwrap();
    }
    // At this point B has equal work to A (5 blocks each), so still on A.
    assert_eq!(cs.tip_height(), 5);

    // B6 tips it over
    let b6 = make_block(prev_b, 6, SUBSIDY, 1231009006);
    let b6_hash = b6.block_hash();

    match cs.process_block(b6).unwrap() {
        ProcessBlockResult::Reorged {
            disconnected,
            connected,
            ..
        } => {
            assert_eq!(disconnected, 5);
            assert_eq!(connected, 6);
        }
        other => panic!("Expected Reorged, got {:?}", other),
    }

    assert_eq!(cs.tip(), b6_hash);
    assert_eq!(cs.tip_height(), 6);
    // genesis + 6 B-chain coinbases = 7 UTXOs
    assert_eq!(cs.utxo_count(), 7);
}
