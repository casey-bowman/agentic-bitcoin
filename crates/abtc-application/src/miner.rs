//! Block Mining — Nonce Grinding and Block Generation
//!
//! This module provides the core mining functionality:
//!
//! - **`mine_block`** takes a block template and grinds the nonce until the
//!   block hash satisfies the proof-of-work target. For regtest (where the
//!   target is effectively unlimited) this returns almost immediately.
//!
//! - **`generate_blocks`** is the equivalent of Bitcoin Core's `generatetoaddress`
//!   RPC — it mines N blocks sequentially, connecting each to the chain state.
//!   This is indispensable for integration tests and regtest workflows.
//!
//! The mining loop is intentionally single-threaded and synchronous — real miners
//! use ASICs, so there's no point in optimising the nonce search beyond what is
//! needed for testing.

use abtc_domain::consensus::{
    decode_compact, decode_compact_u256, hash_meets_target, ConsensusParams,
};
use abtc_domain::primitives::{Amount, Block, BlockHash, BlockHeader, Hash256, Transaction, TxOut};
use abtc_domain::script::Script;

use crate::chain_state::{ChainState, ChainStateError};

use sha2::{Digest, Sha256};

// ── Mining error ───────────────────────────────────────────────────

/// Errors that can occur during mining.
#[derive(Debug)]
pub enum MiningError {
    /// The nonce space was exhausted without finding a valid hash.
    NonceExhausted,
    /// The mined block failed validation when connected to the chain.
    ChainError(ChainStateError),
    /// Signet block signing failed (BIP325).
    SignetSigningFailed(String),
}

impl std::fmt::Display for MiningError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MiningError::NonceExhausted => write!(f, "nonce space exhausted"),
            MiningError::ChainError(e) => write!(f, "chain error: {}", e),
            MiningError::SignetSigningFailed(reason) => {
                write!(f, "signet signing failed: {}", reason)
            }
        }
    }
}

impl std::error::Error for MiningError {}

impl From<ChainStateError> for MiningError {
    fn from(e: ChainStateError) -> Self {
        MiningError::ChainError(e)
    }
}

// ── Core mining function ───────────────────────────────────────────

/// Mine a block by grinding the nonce until the PoW target is met.
///
/// Takes a mutable block (header + transactions already assembled) and
/// increments `header.nonce` from 0 through `u32::MAX`. For each candidate
/// the 80-byte header is double-SHA256'd and the first 16 bytes are compared
/// (little-endian u128) against the decoded compact target.
///
/// # Performance
///
/// For efficiency the first 76 bytes of the serialised header are computed
/// once, and only the final 4 nonce bytes are varied in the inner loop.
///
/// # Returns
///
/// The block with a valid nonce, or `MiningError::NonceExhausted` if no
/// valid nonce exists (astronomically unlikely on mainnet difficulty, and
/// impossible on regtest where the target is u128::MAX).
pub fn mine_block(mut block: Block) -> Result<Block, MiningError> {
    let target_u256 = decode_compact_u256(block.header.bits);

    // Fast path: regtest target has all bytes at max, any nonce works.
    if target_u256 == [0xff; 32] {
        return Ok(block);
    }

    // Also fast-path for regtest bits like 0x207fffff where the u128 decoding
    // saturated — check if the target is effectively unlimited.
    let target_u128 = decode_compact(block.header.bits);
    if target_u128 == u128::MAX {
        return Ok(block);
    }

    // Pre-compute the first 76 bytes of the header (everything except nonce).
    let prefix = header_prefix(&block.header);

    for nonce in 0..=u32::MAX {
        // Build the full 80-byte header with this nonce.
        let mut header_bytes = prefix.clone();
        header_bytes.extend_from_slice(&nonce.to_le_bytes());

        // Double-SHA256.
        let hash = double_sha256(&header_bytes);

        if hash_meets_target(&hash, &target_u256) {
            block.header.nonce = nonce;
            return Ok(block);
        }
    }

    Err(MiningError::NonceExhausted)
}

// ── Block generation (regtest helper) ──────────────────────────────

/// Mine `count` blocks on top of the current chain, returning their hashes.
///
/// This is the functional equivalent of Bitcoin Core's `generatetoaddress`.
/// Each block contains only a coinbase transaction paying to the given
/// `coinbase_script`. Mempool transaction selection is not performed here —
/// that's the job of `SimpleMiner`/`BlockTemplateProvider`. This function
/// is focused on rapidly extending the chain for testing.
///
/// # Arguments
///
/// * `chain` — mutable reference to the chain state manager.
/// * `count` — number of blocks to mine.
/// * `coinbase_script` — script to use for coinbase outputs.
///
/// # Returns
///
/// A vector of `BlockHash` values for the newly mined blocks.
pub fn generate_blocks(
    chain: &mut ChainState,
    count: u32,
    coinbase_script: &Script,
) -> Result<Vec<BlockHash>, MiningError> {
    let mut hashes = Vec::with_capacity(count as usize);

    for _ in 0..count {
        let block = build_next_block(chain, coinbase_script);
        let mined = mine_block(block)?;
        let hash = mined.block_hash();

        chain.process_block(mined)?;
        hashes.push(hash);
    }

    Ok(hashes)
}

/// Build the next block on top of the current chain tip.
///
/// Creates a proper coinbase with the correct subsidy for the next height
/// and assembles a single-transaction block ready for mining.
fn build_next_block(chain: &ChainState, coinbase_output_script: &Script) -> Block {
    let tip = chain.tip();
    let height = chain.tip_height() + 1;
    let params = chain.params();
    let bits = params.pow_limit_bits;

    // Subsidy calculation (matches SimpleMiner::get_block_subsidy).
    let subsidy = get_block_subsidy(height, params);

    // Build a valid coinbase scriptSig with BIP34 height encoding.
    // The scriptSig must be at least 2 bytes (MIN_COINBASE_SCRIPT_SIZE).
    let coinbase_scriptsig = build_coinbase_script(height);

    // Coinbase transaction.
    let coinbase = Transaction::coinbase(
        height,
        coinbase_scriptsig,
        vec![TxOut::new(subsidy, coinbase_output_script.clone())],
    );

    // Timestamp: current time or, for determinism in tests, just height.
    let time = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as u32;

    // Compute merkle root.
    let temp_block = Block::new(
        BlockHeader::new(0x20000000, tip, Hash256::zero(), time, bits, 0),
        vec![coinbase.clone()],
    );
    let merkle_root = temp_block.compute_merkle_root();

    // Final block.
    let header = BlockHeader::new(0x20000000, tip, merkle_root, time, bits, 0);
    Block::new(header, vec![coinbase])
}

/// Calculate block subsidy following the halving schedule.
///
/// Initial subsidy is 50 BTC = 5,000,000,000 satoshis.
/// Halves every `subsidy_halving_interval` blocks.
/// After 64 halvings the subsidy is zero.
fn get_block_subsidy(height: u32, params: &ConsensusParams) -> Amount {
    let interval = params.subsidy_halving_interval;
    if interval == 0 {
        return Amount::from_sat(5_000_000_000);
    }

    let halvings = height / interval;
    if halvings >= 64 {
        return Amount::from_sat(0);
    }

    let initial: i64 = 50 * 100_000_000;
    Amount::from_sat(initial >> halvings)
}

// ── Coinbase script builder ────────────────────────────────────────

/// Build a BIP34-compliant coinbase scriptSig encoding the block height.
///
/// BIP34 requires the coinbase scriptSig to start with a serialised
/// CScriptNum of the block height. The encoding is:
///   - height 0:       `[OP_0]` (1 byte) — pad to 2 bytes
///   - height 1..16:   `[OP_n]` (1 byte) — pad to 2 bytes
///   - height 17..255: `[0x01, height_byte]` (2 bytes)
///   - height 256..65535: `[0x02, lo, hi]` (3 bytes)
///   - etc.
///
/// We always ensure the result is at least `MIN_COINBASE_SCRIPT_SIZE` (2)
/// bytes by appending a padding byte if needed.
fn build_coinbase_script(height: u32) -> Script {
    let mut script = Vec::new();

    if height == 0 {
        // OP_0
        script.push(0x00);
    } else if height <= 16 {
        // OP_1 through OP_16
        script.push(0x50 + height as u8);
    } else {
        // Serialise height as a minimal CScriptNum push.
        let mut h = height;
        let mut buf = Vec::new();
        while h > 0 {
            buf.push((h & 0xff) as u8);
            h >>= 8;
        }
        // If the top bit is set, add a zero byte to keep it positive.
        if buf.last().is_some_and(|&b| b & 0x80 != 0) {
            buf.push(0);
        }
        script.push(buf.len() as u8); // push length
        script.extend_from_slice(&buf);
    }

    // Pad to minimum 2 bytes if needed (e.g. height 0 or 1..16 produce 1 byte).
    while script.len() < 2 {
        script.push(0x00); // OP_0 padding
    }

    Script::from_bytes(script)
}

// ── Low-level helpers ──────────────────────────────────────────────

/// Serialize the first 76 bytes of a block header (everything except nonce).
fn header_prefix(h: &BlockHeader) -> Vec<u8> {
    let mut data = Vec::with_capacity(76);
    data.extend_from_slice(&h.version.to_le_bytes());
    data.extend_from_slice(h.prev_block_hash.as_bytes());
    data.extend_from_slice(h.merkle_root.as_bytes());
    data.extend_from_slice(&h.time.to_le_bytes());
    data.extend_from_slice(&h.bits.to_le_bytes());
    data
}

/// Double-SHA256 of arbitrary data.
fn double_sha256(data: &[u8]) -> [u8; 32] {
    let first = Sha256::digest(data);
    let second = Sha256::digest(first);
    let mut out = [0u8; 32];
    out.copy_from_slice(&second);
    out
}

// ── Signet block signing (BIP325) ────────────────────────────────

/// Sign a signet block for a P2WPKH challenge script.
///
/// Delegates to `abtc_domain::consensus::signet::sign_block_p2wpkh` for the
/// actual BIP325 signing logic (sighash computation, ECDSA signing, commitment
/// construction). This wrapper maps `SignetError` into `MiningError`.
///
/// The `secret_key_bytes` must be 32 raw bytes of a valid secp256k1 secret key
/// whose compressed public key hashes to the P2WPKH witness program in `challenge`.
///
/// # Returns
///
/// A new block with the signed signet commitment in place and an updated
/// merkle root.
pub fn sign_signet_block_p2wpkh(
    block: &Block,
    challenge: &Script,
    secret_key_bytes: &[u8; 32],
) -> Result<Block, MiningError> {
    abtc_domain::consensus::signet::sign_block_p2wpkh(block, challenge, secret_key_bytes)
        .map_err(|e| MiningError::SignetSigningFailed(e.to_string()))
}

// ── Tests ──────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use abtc_domain::consensus::ConsensusParams;
    use abtc_domain::primitives::{Amount, Block, BlockHash, BlockHeader, Hash256, TxOut};
    use abtc_domain::script::Script;

    /// Helper: create a regtest genesis block.
    fn regtest_genesis() -> Block {
        let params = ConsensusParams::regtest();
        let coinbase = Transaction::coinbase(
            0,
            build_coinbase_script(0),
            vec![TxOut::new(
                Amount::from_sat(50 * 100_000_000),
                Script::new(),
            )],
        );
        let header = BlockHeader::new(
            1,
            BlockHash::zero(),
            Hash256::zero(),
            1296688602, // regtest genesis timestamp
            params.pow_limit_bits,
            0,
        );
        let mut block = Block::new(header, vec![coinbase]);
        let merkle = block.compute_merkle_root();
        block.header.merkle_root = merkle;
        block
    }

    // ── Subsidy tests ──────────────────────────────────────────

    #[test]
    fn test_subsidy_initial() {
        let params = ConsensusParams::mainnet();
        assert_eq!(get_block_subsidy(0, &params).as_sat(), 5_000_000_000);
        assert_eq!(get_block_subsidy(1, &params).as_sat(), 5_000_000_000);
    }

    #[test]
    fn test_subsidy_halving() {
        let params = ConsensusParams::mainnet();
        assert_eq!(get_block_subsidy(210_000, &params).as_sat(), 2_500_000_000);
        assert_eq!(get_block_subsidy(420_000, &params).as_sat(), 1_250_000_000);
        assert_eq!(get_block_subsidy(630_000, &params).as_sat(), 625_000_000);
    }

    #[test]
    fn test_subsidy_regtest() {
        let params = ConsensusParams::regtest();
        // Regtest halves every 150 blocks.
        assert_eq!(get_block_subsidy(0, &params).as_sat(), 5_000_000_000);
        assert_eq!(get_block_subsidy(149, &params).as_sat(), 5_000_000_000);
        assert_eq!(get_block_subsidy(150, &params).as_sat(), 2_500_000_000);
        assert_eq!(get_block_subsidy(300, &params).as_sat(), 1_250_000_000);
    }

    #[test]
    fn test_subsidy_exhausted() {
        let params = ConsensusParams::mainnet();
        assert_eq!(get_block_subsidy(210_000 * 64, &params).as_sat(), 0);
    }

    // ── mine_block tests ───────────────────────────────────────

    #[test]
    fn test_mine_block_regtest() {
        // With regtest difficulty (target = u128::MAX) mining should succeed
        // immediately with nonce 0.
        let genesis = regtest_genesis();
        let params = ConsensusParams::regtest();

        let coinbase = Transaction::coinbase(
            1,
            build_coinbase_script(1),
            vec![TxOut::new(Amount::from_sat(5_000_000_000), Script::new())],
        );
        let header = BlockHeader::new(
            0x20000000,
            genesis.block_hash(),
            Hash256::zero(),
            1296688602 + 1,
            params.pow_limit_bits,
            0,
        );
        let mut block = Block::new(header, vec![coinbase]);
        let merkle = block.compute_merkle_root();
        block.header.merkle_root = merkle;

        let mined = mine_block(block).unwrap();
        assert_eq!(mined.header.nonce, 0); // regtest fast-path
    }

    #[test]
    fn test_mine_block_low_difficulty() {
        // Use a target that exercises the real mining loop but finishes fast.
        // bits = 0x2100ffff: exponent 0x21 = 33, mantissa 0x00ffff.
        // decode_compact_u256 places 0x00ffff at byte offset 33-3 = 30, so
        // the target's byte 31 is 0x00, byte 30 is 0xff, byte 29 is 0xff,
        // and everything below is 0x00. The hash only needs its topmost byte
        // (LE byte 31) to be 0x00, which happens ~1/256 tries — a few hundred
        // nonces at most.
        let coinbase = Transaction::coinbase(
            1,
            build_coinbase_script(1),
            vec![TxOut::new(Amount::from_sat(5_000_000_000), Script::new())],
        );
        let bits = 0x2100ffffu32;
        let header = BlockHeader::new(
            0x20000000,
            BlockHash::zero(),
            Hash256::zero(),
            12345,
            bits,
            0,
        );
        let mut block = Block::new(header, vec![coinbase]);
        let merkle = block.compute_merkle_root();
        block.header.merkle_root = merkle;

        let mined = mine_block(block).unwrap();
        // Verify the mined block actually satisfies PoW (full 256-bit).
        let hash = mined.header.block_hash();
        let target = decode_compact_u256(bits);
        assert!(
            hash_meets_target(hash.as_bytes(), &target),
            "mined block should satisfy PoW"
        );
    }

    // ── generate_blocks tests ──────────────────────────────────

    #[test]
    fn test_generate_single_block() {
        let genesis = regtest_genesis();
        let params = ConsensusParams::regtest();
        let mut chain = ChainState::new(genesis, params).unwrap();

        let hashes = generate_blocks(&mut chain, 1, &Script::new()).unwrap();
        assert_eq!(hashes.len(), 1);
        assert_eq!(chain.tip_height(), 1);
        assert_eq!(chain.tip(), hashes[0]);
    }

    #[test]
    fn test_generate_chain_of_blocks() {
        let genesis = regtest_genesis();
        let params = ConsensusParams::regtest();
        let mut chain = ChainState::new(genesis, params).unwrap();

        let hashes = generate_blocks(&mut chain, 50, &Script::new()).unwrap();
        assert_eq!(hashes.len(), 50);
        assert_eq!(chain.tip_height(), 50);
        assert_eq!(chain.tip(), hashes[49]);

        // Each block should be distinct.
        let unique: std::collections::HashSet<_> = hashes.iter().collect();
        assert_eq!(unique.len(), 50);
    }

    #[test]
    fn test_generate_past_first_halving() {
        // Regtest halves at height 150. Mine 160 blocks and verify the
        // subsidy change is reflected in coinbase values.
        let genesis = regtest_genesis();
        let params = ConsensusParams::regtest();
        let mut chain = ChainState::new(genesis, params).unwrap();

        let hashes = generate_blocks(&mut chain, 160, &Script::new()).unwrap();
        assert_eq!(hashes.len(), 160);
        assert_eq!(chain.tip_height(), 160);

        // Block at height 149 should have 50 BTC coinbase.
        let block_149 = chain.get_block(&hashes[148]).unwrap();
        assert_eq!(
            block_149.transactions[0].total_output_value().as_sat(),
            5_000_000_000
        );

        // Block at height 150 should have 25 BTC coinbase (first halving).
        let block_150 = chain.get_block(&hashes[149]).unwrap();
        assert_eq!(
            block_150.transactions[0].total_output_value().as_sat(),
            2_500_000_000
        );
    }

    #[test]
    fn test_generate_blocks_connect_sequentially() {
        // Verify that each block's prev_block_hash points to the previous tip.
        let genesis = regtest_genesis();
        let genesis_hash = genesis.block_hash();
        let params = ConsensusParams::regtest();
        let mut chain = ChainState::new(genesis, params).unwrap();

        let hashes = generate_blocks(&mut chain, 5, &Script::new()).unwrap();

        // First block should point to genesis.
        let b1 = chain.get_block(&hashes[0]).unwrap();
        assert_eq!(b1.header.prev_block_hash, genesis_hash);

        // Each subsequent block should point to the previous one.
        for i in 1..5 {
            let blk = chain.get_block(&hashes[i]).unwrap();
            assert_eq!(blk.header.prev_block_hash, hashes[i - 1]);
        }
    }

    // ── Signet signing tests ─────────────────────────────────────

    #[test]
    fn test_sign_signet_block_p2wpkh() {
        use abtc_domain::consensus::signet::{build_signet_commitment, validate_signet_block};
        use abtc_domain::crypto::hashing::hash160;
        use abtc_domain::script::Witness;

        // Generate a P2WPKH challenge from a known secret key
        let secret_key_bytes: [u8; 32] = [0x42; 32];
        let secp = abtc_domain::secp256k1::Secp256k1::new();
        let sk = abtc_domain::secp256k1::SecretKey::from_slice(&secret_key_bytes).unwrap();
        let pk = abtc_domain::secp256k1::PublicKey::from_secret_key(&secp, &sk);
        let compressed = pk.serialize();
        let pkh = hash160(&compressed);

        // P2WPKH challenge: OP_0 <20-byte pubkey hash>
        let mut challenge_bytes = vec![0x00, 0x14];
        challenge_bytes.extend_from_slice(&pkh);
        let challenge = Script::from_bytes(challenge_bytes);

        // Build block template with placeholder signet commitment
        let placeholder = build_signet_commitment(&Witness::new());
        let coinbase = Transaction::coinbase(
            1,
            build_coinbase_script(1),
            vec![
                TxOut::new(Amount::from_sat(5_000_000_000), Script::new()),
                placeholder,
            ],
        );
        let header = BlockHeader::new(
            0x20000000,
            BlockHash::zero(),
            Hash256::zero(),
            1231006505,
            0x207fffff,
            0,
        );
        let mut block = Block::new(header, vec![coinbase]);
        let merkle = block.compute_merkle_root();
        block.header.merkle_root = merkle;

        // Sign the block
        let signed = sign_signet_block_p2wpkh(&block, &challenge, &secret_key_bytes).unwrap();

        // Validate it
        let result = validate_signet_block(&signed, &challenge);
        assert!(
            result.is_ok(),
            "signed signet block should validate: {:?}",
            result
        );
    }

    // ── Low-level helper tests ─────────────────────────────────

    #[test]
    fn test_header_prefix_length() {
        let header = BlockHeader::new(1, BlockHash::zero(), Hash256::zero(), 0, 0, 0);
        let prefix = header_prefix(&header);
        assert_eq!(prefix.len(), 76);
    }

    #[test]
    fn test_double_sha256_deterministic() {
        let data = b"hello bitcoin";
        let h1 = double_sha256(data);
        let h2 = double_sha256(data);
        assert_eq!(h1, h2);

        // Different input yields different hash.
        let h3 = double_sha256(b"different data");
        assert_ne!(h1, h3);
    }
}
