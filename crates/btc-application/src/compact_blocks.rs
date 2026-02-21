//! Compact Block Relay (BIP152)
//!
//! Implements the compact block protocol that allows peers to relay blocks
//! using short transaction IDs rather than full transactions. Since most
//! transactions in a new block are already in the receiver's mempool,
//! only a compact summary needs to be sent.
//!
//! ## Protocol Flow
//!
//! 1. Sender constructs a `CompactBlock` from a full block:
//!    - Header + nonce
//!    - Short transaction IDs (first 6 bytes of SipHash)
//!    - A few "prefilled" transactions (always the coinbase, plus any the
//!      sender guesses the receiver doesn't have)
//!
//! 2. Receiver matches short IDs against its mempool:
//!    - If all transactions are found → reconstruct the full block
//!    - If some are missing → send `GetBlockTxn` to request them
//!    - Sender replies with `BlockTxn` containing the missing transactions
//!
//! ## References
//!
//! - BIP152: <https://github.com/bitcoin/bips/blob/master/bip-0152.mediawiki>

use btc_domain::primitives::{Block, BlockHeader, Transaction};
use std::collections::HashMap;

// ── SipHash for short IDs ───────────────────────────────────────────

/// Compute a SipHash-2-4 based short ID for a transaction.
///
/// BIP152 uses SipHash with a key derived from the block header hash and a
/// nonce. We implement a simplified version here.
fn siphash_2_4(key0: u64, key1: u64, data: &[u8]) -> u64 {
    // Simplified SipHash-2-4 implementation
    let mut v0: u64 = 0x736f6d6570736575 ^ key0;
    let mut v1: u64 = 0x646f72616e646f6d ^ key1;
    let mut v2: u64 = 0x6c7967656e657261 ^ key0;
    let mut v3: u64 = 0x7465646279746573 ^ key1;

    // Process 8-byte blocks
    let blocks = data.len() / 8;
    for i in 0..blocks {
        let mut m = 0u64;
        for j in 0..8 {
            m |= (data[i * 8 + j] as u64) << (j * 8);
        }
        v3 ^= m;
        for _ in 0..2 {
            sipround(&mut v0, &mut v1, &mut v2, &mut v3);
        }
        v0 ^= m;
    }

    // Process remaining bytes + length
    let mut last = ((data.len() & 0xff) as u64) << 56;
    let remaining = data.len() % 8;
    for i in 0..remaining {
        last |= (data[blocks * 8 + i] as u64) << (i * 8);
    }

    v3 ^= last;
    for _ in 0..2 {
        sipround(&mut v0, &mut v1, &mut v2, &mut v3);
    }
    v0 ^= last;

    // Finalization
    v2 ^= 0xff;
    for _ in 0..4 {
        sipround(&mut v0, &mut v1, &mut v2, &mut v3);
    }

    v0 ^ v1 ^ v2 ^ v3
}

#[inline]
fn sipround(v0: &mut u64, v1: &mut u64, v2: &mut u64, v3: &mut u64) {
    *v0 = v0.wrapping_add(*v1);
    *v1 = v1.rotate_left(13);
    *v1 ^= *v0;
    *v0 = v0.rotate_left(32);
    *v2 = v2.wrapping_add(*v3);
    *v3 = v3.rotate_left(16);
    *v3 ^= *v2;
    *v0 = v0.wrapping_add(*v3);
    *v3 = v3.rotate_left(21);
    *v3 ^= *v0;
    *v2 = v2.wrapping_add(*v1);
    *v1 = v1.rotate_left(17);
    *v1 ^= *v2;
    *v2 = v2.rotate_left(32);
}

// ── Short ID computation ────────────────────────────────────────────

/// A 6-byte short transaction ID used in compact blocks.
pub type ShortTxId = [u8; 6];

/// Derive SipHash keys from the block header hash and a nonce.
///
/// key0 and key1 are the first and second 8-byte little-endian words of
/// SHA256(SHA256(header) || nonce).
fn compute_siphash_keys(header: &BlockHeader, nonce: u64) -> (u64, u64) {
    use sha2::{Sha256, Digest};

    // SHA256(SHA256(header) || nonce)
    let header_hash = header.block_hash();
    let mut hasher = Sha256::new();
    hasher.update(header_hash.as_bytes());
    hasher.update(&nonce.to_le_bytes());
    let first_hash = hasher.finalize();

    let mut hasher2 = Sha256::new();
    hasher2.update(&first_hash);
    let result = hasher2.finalize();

    let key0 = u64::from_le_bytes(result[0..8].try_into().unwrap());
    let key1 = u64::from_le_bytes(result[8..16].try_into().unwrap());

    (key0, key1)
}

/// Compute a 6-byte short transaction ID for a given txid.
pub fn compute_short_txid(key0: u64, key1: u64, txid_bytes: &[u8]) -> ShortTxId {
    let hash = siphash_2_4(key0, key1, txid_bytes);
    let bytes = hash.to_le_bytes();
    let mut short_id = [0u8; 6];
    short_id.copy_from_slice(&bytes[0..6]);
    short_id
}

// ── Compact Block types ─────────────────────────────────────────────

/// A prefilled transaction: index in the block + the full transaction.
#[derive(Clone, Debug)]
pub struct PrefilledTransaction {
    /// Differential index (gap from last prefilled index).
    pub index: u16,
    /// The full transaction.
    pub tx: Transaction,
}

/// A compact block (BIP152 `cmpctblock`).
///
/// Contains the header, a nonce, short transaction IDs for most transactions,
/// and a few prefilled transactions (always at least the coinbase).
#[derive(Clone, Debug)]
pub struct CompactBlock {
    /// The block header.
    pub header: BlockHeader,
    /// Random nonce used for short ID computation.
    pub nonce: u64,
    /// Short transaction IDs for non-prefilled transactions.
    pub short_ids: Vec<ShortTxId>,
    /// Prefilled transactions (coinbase + any extras).
    pub prefilled_txs: Vec<PrefilledTransaction>,
}

/// A request for missing transactions from a compact block.
#[derive(Clone, Debug)]
pub struct GetBlockTransactions {
    /// Hash of the block.
    pub block_hash: btc_domain::primitives::BlockHash,
    /// Indices of requested transactions.
    pub indices: Vec<u16>,
}

/// Response with the missing transactions.
#[derive(Clone, Debug)]
pub struct BlockTransactions {
    /// Hash of the block.
    pub block_hash: btc_domain::primitives::BlockHash,
    /// The requested transactions in order.
    pub transactions: Vec<Transaction>,
}

/// Result of attempting to reconstruct a block from a compact block.
#[derive(Debug)]
pub enum ReconstructResult {
    /// Successfully reconstructed the full block.
    Success(Block),
    /// Some transactions are missing — need to request them.
    NeedTransactions(GetBlockTransactions),
}

// ── CompactBlock construction ───────────────────────────────────────

impl CompactBlock {
    /// Build a compact block from a full block.
    ///
    /// The coinbase transaction is always prefilled. Additional transactions
    /// may be prefilled if the sender thinks the receiver won't have them.
    pub fn from_block(block: &Block, nonce: u64) -> Self {
        let (key0, key1) = compute_siphash_keys(&block.header, nonce);

        let mut short_ids = Vec::new();
        let mut prefilled_txs = Vec::new();

        for (i, tx) in block.transactions.iter().enumerate() {
            if i == 0 {
                // Always prefill the coinbase.
                prefilled_txs.push(PrefilledTransaction {
                    index: 0,
                    tx: tx.clone(),
                });
            } else {
                let txid = tx.txid();
                let short_id = compute_short_txid(key0, key1, txid.as_bytes());
                short_ids.push(short_id);
            }
        }

        CompactBlock {
            header: block.header.clone(),
            nonce,
            short_ids,
            prefilled_txs,
        }
    }

    /// Attempt to reconstruct the full block using a mempool lookup.
    ///
    /// `mempool_lookup` maps short IDs → transactions. If all transactions
    /// can be resolved, returns the full block. Otherwise, returns a request
    /// for the missing transactions.
    pub fn reconstruct(
        &self,
        mempool_lookup: &HashMap<ShortTxId, Transaction>,
    ) -> ReconstructResult {
        let total_tx_count = self.prefilled_txs.len() + self.short_ids.len();
        let mut transactions: Vec<Option<Transaction>> = vec![None; total_tx_count];
        let mut missing_indices = Vec::new();

        // Place prefilled transactions.
        let mut prefill_offset = 0u16;
        for prefill in &self.prefilled_txs {
            let actual_index = (prefill.index + prefill_offset) as usize;
            if actual_index < total_tx_count {
                transactions[actual_index] = Some(prefill.tx.clone());
            }
            prefill_offset = prefill.index + prefill_offset + 1;
        }

        // Fill in from mempool using short IDs.
        let mut short_id_idx = 0;
        for i in 0..total_tx_count {
            if transactions[i].is_some() {
                continue; // already prefilled
            }

            if short_id_idx >= self.short_ids.len() {
                missing_indices.push(i as u16);
                continue;
            }

            let short_id = &self.short_ids[short_id_idx];
            short_id_idx += 1;

            if let Some(tx) = mempool_lookup.get(short_id) {
                transactions[i] = Some(tx.clone());
            } else {
                missing_indices.push(i as u16);
            }
        }

        if missing_indices.is_empty() {
            // All transactions found — build the block.
            let txs: Vec<Transaction> = transactions
                .into_iter()
                .map(|t| t.expect("all slots filled"))
                .collect();

            ReconstructResult::Success(Block {
                header: self.header.clone(),
                transactions: txs,
            })
        } else {
            ReconstructResult::NeedTransactions(GetBlockTransactions {
                block_hash: self.header.block_hash(),
                indices: missing_indices,
            })
        }
    }

    /// The number of transactions represented (prefilled + short IDs).
    pub fn transaction_count(&self) -> usize {
        self.prefilled_txs.len() + self.short_ids.len()
    }

    /// Build a mempool lookup table for compact block reconstruction.
    ///
    /// Takes an iterator of mempool transactions and returns a map from
    /// short ID → transaction, keyed using this compact block's header and nonce.
    pub fn build_mempool_lookup<'a, I>(&self, mempool_txs: I) -> HashMap<ShortTxId, Transaction>
    where
        I: IntoIterator<Item = &'a Transaction>,
    {
        let (key0, key1) = compute_siphash_keys(&self.header, self.nonce);
        let mut lookup = HashMap::new();

        for tx in mempool_txs {
            let txid = tx.txid();
            let short_id = compute_short_txid(key0, key1, txid.as_bytes());
            lookup.insert(short_id, tx.clone());
        }

        lookup
    }
}

// ── Tests ───────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use btc_domain::primitives::{Amount, BlockHash, Hash256, OutPoint, TxIn, TxOut, Txid};
    use btc_domain::script::Script;

    fn make_test_tx(value: i64) -> Transaction {
        Transaction::v1(
            vec![TxIn::final_input(OutPoint::new(Txid::zero(), 0), Script::new())],
            vec![TxOut::new(Amount::from_sat(value), Script::new())],
            0,
        )
    }

    fn make_test_block(num_txs: usize) -> Block {
        let coinbase = Transaction::v1(
            vec![TxIn::final_input(OutPoint::coinbase(), Script::new())],
            vec![TxOut::new(Amount::from_sat(50_0000_0000), Script::new())],
            0,
        );

        let mut txs = vec![coinbase];
        for i in 1..=num_txs {
            txs.push(make_test_tx(i as i64 * 1000));
        }

        Block {
            header: BlockHeader {
                version: 1,
                prev_block_hash: BlockHash::zero(),
                merkle_root: Hash256::zero(),
                time: 1234567890,
                bits: 0x207fffff,
                nonce: 0,
            },
            transactions: txs,
        }
    }

    #[test]
    fn test_compact_block_from_block() {
        let block = make_test_block(5);
        let compact = CompactBlock::from_block(&block, 42);

        assert_eq!(compact.transaction_count(), 6); // coinbase + 5
        assert_eq!(compact.prefilled_txs.len(), 1); // just coinbase
        assert_eq!(compact.short_ids.len(), 5);
    }

    #[test]
    fn test_compact_block_roundtrip_all_in_mempool() {
        let block = make_test_block(3);
        let compact = CompactBlock::from_block(&block, 42);

        // Build mempool lookup from the non-coinbase transactions.
        let mempool_txs: Vec<&Transaction> = block.transactions[1..].iter().collect();
        let lookup = compact.build_mempool_lookup(mempool_txs);

        match compact.reconstruct(&lookup) {
            ReconstructResult::Success(reconstructed) => {
                assert_eq!(reconstructed.transactions.len(), 4);
                // Verify all txids match.
                for (orig, recon) in block.transactions.iter().zip(reconstructed.transactions.iter()) {
                    assert_eq!(orig.txid(), recon.txid());
                }
            }
            ReconstructResult::NeedTransactions(_) => {
                panic!("Expected successful reconstruction");
            }
        }
    }

    #[test]
    fn test_compact_block_missing_transactions() {
        let block = make_test_block(3);
        let compact = CompactBlock::from_block(&block, 42);

        // Empty mempool — all non-coinbase txs will be missing.
        let empty_lookup = HashMap::new();

        match compact.reconstruct(&empty_lookup) {
            ReconstructResult::NeedTransactions(req) => {
                assert_eq!(req.indices.len(), 3); // 3 missing
                assert_eq!(req.block_hash, block.header.block_hash());
            }
            ReconstructResult::Success(_) => {
                panic!("Expected missing transactions");
            }
        }
    }

    #[test]
    fn test_compact_block_partial_mempool() {
        let block = make_test_block(3);
        let compact = CompactBlock::from_block(&block, 42);

        // Only have the first non-coinbase tx in mempool.
        let partial_mempool = vec![&block.transactions[1]];
        let lookup = compact.build_mempool_lookup(partial_mempool);

        match compact.reconstruct(&lookup) {
            ReconstructResult::NeedTransactions(req) => {
                assert_eq!(req.indices.len(), 2); // 2 missing
            }
            ReconstructResult::Success(_) => {
                panic!("Expected partial miss");
            }
        }
    }

    #[test]
    fn test_short_txid_deterministic() {
        let block = make_test_block(1);
        let (key0, key1) = compute_siphash_keys(&block.header, 42);
        let txid = block.transactions[1].txid();

        let id1 = compute_short_txid(key0, key1, txid.as_bytes());
        let id2 = compute_short_txid(key0, key1, txid.as_bytes());
        assert_eq!(id1, id2);
    }

    #[test]
    fn test_short_txid_different_nonces() {
        let block = make_test_block(1);
        let txid = block.transactions[1].txid();

        let (k0a, k1a) = compute_siphash_keys(&block.header, 42);
        let (k0b, k1b) = compute_siphash_keys(&block.header, 99);

        let id_a = compute_short_txid(k0a, k1a, txid.as_bytes());
        let id_b = compute_short_txid(k0b, k1b, txid.as_bytes());

        // Different nonces should (almost certainly) produce different short IDs.
        assert_ne!(id_a, id_b);
    }

    #[test]
    fn test_short_txid_different_txids() {
        let block = make_test_block(2);
        let (key0, key1) = compute_siphash_keys(&block.header, 42);

        let id1 = compute_short_txid(key0, key1, block.transactions[1].txid().as_bytes());
        let id2 = compute_short_txid(key0, key1, block.transactions[2].txid().as_bytes());

        assert_ne!(id1, id2);
    }

    #[test]
    fn test_coinbase_always_prefilled() {
        let block = make_test_block(10);
        let compact = CompactBlock::from_block(&block, 0);

        assert!(!compact.prefilled_txs.is_empty());
        let coinbase_prefill = &compact.prefilled_txs[0];
        assert_eq!(coinbase_prefill.index, 0);
        assert_eq!(coinbase_prefill.tx.txid(), block.transactions[0].txid());
    }

    #[test]
    fn test_empty_block_compact() {
        // Block with only coinbase.
        let block = make_test_block(0);
        let compact = CompactBlock::from_block(&block, 42);

        assert_eq!(compact.short_ids.len(), 0);
        assert_eq!(compact.prefilled_txs.len(), 1);
        assert_eq!(compact.transaction_count(), 1);

        // Reconstruct with empty mempool should succeed.
        let empty = HashMap::new();
        match compact.reconstruct(&empty) {
            ReconstructResult::Success(recon) => {
                assert_eq!(recon.transactions.len(), 1);
                assert_eq!(recon.transactions[0].txid(), block.transactions[0].txid());
            }
            _ => panic!("Empty block should reconstruct without mempool"),
        }
    }

    #[test]
    fn test_siphash_basic() {
        // Verify siphash produces non-zero output for non-empty data.
        let result = siphash_2_4(0, 0, b"hello");
        assert_ne!(result, 0);

        // Deterministic.
        let result2 = siphash_2_4(0, 0, b"hello");
        assert_eq!(result, result2);

        // Different data → different hash.
        let result3 = siphash_2_4(0, 0, b"world");
        assert_ne!(result, result3);
    }
}
