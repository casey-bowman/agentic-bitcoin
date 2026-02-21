//! RocksDB-backed persistent storage implementations
//!
//! Provides durable, crash-safe storage for the UTXO set, block index, and
//! block data using RocksDB — a high-performance embedded key-value store
//! originally developed at Facebook and used by many blockchain implementations.
//!
//! ## Column families
//!
//! We use separate RocksDB column families for different data types:
//! - `blocks` — full serialized blocks keyed by block hash
//! - `block_heights` — height → block hash mapping
//! - `headers` — block headers keyed by block hash
//! - `utxos` — UTXO entries keyed by (txid, vout)
//! - `meta` — metadata: best block hash, chain tip, etc.

use async_trait::async_trait;
use btc_domain::primitives::{
    Amount, Block, BlockHash, BlockHeader, Hash256, OutPoint,
    Transaction, TxIn, TxOut, Txid, Witness,
};
use btc_domain::Script;
use btc_ports::{BlockStore, ChainStateStore, UtxoEntry};
use rocksdb::{ColumnFamilyDescriptor, Options, DB};
use std::path::Path;
use std::sync::Arc;

/// Column family names
const CF_BLOCKS: &str = "blocks";
const CF_BLOCK_HEIGHTS: &str = "block_heights";
const CF_UTXOS: &str = "utxos";
const CF_META: &str = "meta";

/// Meta keys
const META_BEST_BLOCK_HASH: &[u8] = b"best_block_hash";
const META_CHAIN_TIP_HASH: &[u8] = b"chain_tip_hash";
const META_CHAIN_TIP_HEIGHT: &[u8] = b"chain_tip_height";

/// RocksDB-backed block store.
///
/// Stores full blocks and block headers persistently, surviving process restarts.
/// Uses synchronous RocksDB operations wrapped in tokio's blocking task pool.
pub struct RocksDbBlockStore {
    db: Arc<DB>,
}

impl RocksDbBlockStore {
    /// Open or create a RocksDB block store at the given path.
    pub fn open(path: &Path) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let mut opts = Options::default();
        opts.create_if_missing(true);
        opts.create_missing_column_families(true);

        let cf_descriptors = vec![
            ColumnFamilyDescriptor::new(CF_BLOCKS, Options::default()),
            ColumnFamilyDescriptor::new(CF_BLOCK_HEIGHTS, Options::default()),
            ColumnFamilyDescriptor::new(CF_META, Options::default()),
        ];

        let db = DB::open_cf_descriptors(&opts, path, cf_descriptors)?;

        Ok(RocksDbBlockStore { db: Arc::new(db) })
    }

    /// Initialize with genesis block if store is empty
    pub fn init_with_genesis(
        &self,
        genesis: &Block,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let cf_meta = self.db.cf_handle(CF_META).unwrap();
        let existing = self.db.get_cf(&cf_meta, META_BEST_BLOCK_HASH)?;
        if existing.is_some() {
            return Ok(()); // Already initialized
        }

        let genesis_hash = genesis.block_hash();
        let cf_blocks = self.db.cf_handle(CF_BLOCKS).unwrap();
        let cf_heights = self.db.cf_handle(CF_BLOCK_HEIGHTS).unwrap();

        let block_bytes = serialize_block(genesis);
        self.db
            .put_cf(&cf_blocks, genesis_hash.as_bytes(), &block_bytes)?;
        self.db
            .put_cf(&cf_heights, genesis_hash.as_bytes(), &0u32.to_le_bytes())?;
        self.db
            .put_cf(&cf_meta, META_BEST_BLOCK_HASH, genesis_hash.as_bytes())?;

        tracing::info!(
            "Initialized RocksDB block store with genesis block: {}",
            genesis_hash
        );
        Ok(())
    }
}

#[async_trait]
impl BlockStore for RocksDbBlockStore {
    async fn store_block(
        &self,
        block: &Block,
        height: u32,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let db = self.db.clone();
        let block = block.clone();

        tokio::task::spawn_blocking(move || {
            let block_hash = block.block_hash();
            let cf_blocks = db.cf_handle(CF_BLOCKS).unwrap();
            let cf_heights = db.cf_handle(CF_BLOCK_HEIGHTS).unwrap();
            let cf_meta = db.cf_handle(CF_META).unwrap();

            let block_bytes = serialize_block(&block);
            db.put_cf(&cf_blocks, block_hash.as_bytes(), &block_bytes)?;
            db.put_cf(
                &cf_heights,
                block_hash.as_bytes(),
                &height.to_le_bytes(),
            )?;

            // Update best block hash
            db.put_cf(&cf_meta, META_BEST_BLOCK_HASH, block_hash.as_bytes())?;

            tracing::debug!("Stored block {} at height {} (RocksDB)", block_hash, height);
            Ok(())
        })
        .await?
    }

    async fn get_block(
        &self,
        hash: &BlockHash,
    ) -> Result<Option<Block>, Box<dyn std::error::Error + Send + Sync>> {
        let db = self.db.clone();
        let hash = *hash;

        tokio::task::spawn_blocking(move || {
            let cf_blocks = db.cf_handle(CF_BLOCKS).unwrap();
            match db.get_cf(&cf_blocks, hash.as_bytes())? {
                Some(bytes) => Ok(Some(deserialize_block(&bytes)?)),
                None => Ok(None),
            }
        })
        .await?
    }

    async fn get_block_header(
        &self,
        hash: &BlockHash,
    ) -> Result<Option<BlockHeader>, Box<dyn std::error::Error + Send + Sync>> {
        // Read the full block and extract the header
        let block = self.get_block(hash).await?;
        Ok(block.map(|b| b.header))
    }

    async fn has_block(
        &self,
        hash: &BlockHash,
    ) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
        let db = self.db.clone();
        let hash = *hash;

        tokio::task::spawn_blocking(move || {
            let cf_blocks = db.cf_handle(CF_BLOCKS).unwrap();
            let exists = db.get_cf(&cf_blocks, hash.as_bytes())?.is_some();
            Ok(exists)
        })
        .await?
    }

    async fn get_best_block_hash(
        &self,
    ) -> Result<BlockHash, Box<dyn std::error::Error + Send + Sync>> {
        let db = self.db.clone();

        tokio::task::spawn_blocking(move || {
            let cf_meta = db.cf_handle(CF_META).unwrap();
            match db.get_cf(&cf_meta, META_BEST_BLOCK_HASH)? {
                Some(bytes) => {
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(&bytes);
                    Ok(BlockHash::from_hash(Hash256::from_bytes(arr)))
                }
                None => Ok(BlockHash::zero()),
            }
        })
        .await?
    }

    async fn get_block_height(
        &self,
        hash: &BlockHash,
    ) -> Result<Option<u32>, Box<dyn std::error::Error + Send + Sync>> {
        let db = self.db.clone();
        let hash = *hash;

        tokio::task::spawn_blocking(move || {
            let cf_heights = db.cf_handle(CF_BLOCK_HEIGHTS).unwrap();
            match db.get_cf(&cf_heights, hash.as_bytes())? {
                Some(bytes) => {
                    let height = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
                    Ok(Some(height))
                }
                None => Ok(None),
            }
        })
        .await?
    }
}

/// RocksDB-backed chain state store.
///
/// Persistently stores the UTXO set and chain tip information.
pub struct RocksDbChainStateStore {
    db: Arc<DB>,
}

impl RocksDbChainStateStore {
    /// Open or create a RocksDB chain state store at the given path.
    pub fn open(path: &Path) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let mut opts = Options::default();
        opts.create_if_missing(true);
        opts.create_missing_column_families(true);

        let cf_descriptors = vec![
            ColumnFamilyDescriptor::new(CF_UTXOS, Options::default()),
            ColumnFamilyDescriptor::new(CF_META, Options::default()),
        ];

        let db = DB::open_cf_descriptors(&opts, path, cf_descriptors)?;
        Ok(RocksDbChainStateStore { db: Arc::new(db) })
    }

    /// Initialize with genesis tip if not already initialized
    pub fn init_with_genesis(
        &self,
        genesis_hash: BlockHash,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let cf_meta = self.db.cf_handle(CF_META).unwrap();
        let existing = self.db.get_cf(&cf_meta, META_CHAIN_TIP_HASH)?;
        if existing.is_some() {
            return Ok(());
        }

        self.db
            .put_cf(&cf_meta, META_CHAIN_TIP_HASH, genesis_hash.as_bytes())?;
        self.db
            .put_cf(&cf_meta, META_CHAIN_TIP_HEIGHT, &0u32.to_le_bytes())?;

        tracing::info!(
            "Initialized RocksDB chain state with genesis tip: {}",
            genesis_hash
        );
        Ok(())
    }
}

/// Encode a UTXO key as (txid || vout) — 36 bytes
fn utxo_key(txid: &Txid, vout: u32) -> [u8; 36] {
    let mut key = [0u8; 36];
    key[..32].copy_from_slice(txid.as_bytes());
    key[32..].copy_from_slice(&vout.to_le_bytes());
    key
}

/// Serialize a UtxoEntry to bytes: height(4) + is_coinbase(1) + value(8) + script_len(4) + script
fn serialize_utxo_entry(entry: &UtxoEntry) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(&entry.height.to_le_bytes());
    buf.push(if entry.is_coinbase { 1 } else { 0 });
    buf.extend_from_slice(&entry.output.value.as_sat().to_le_bytes());
    let spk = entry.output.script_pubkey.as_bytes();
    buf.extend_from_slice(&(spk.len() as u32).to_le_bytes());
    buf.extend_from_slice(spk);
    buf
}

/// Deserialize a UtxoEntry from bytes
fn deserialize_utxo_entry(
    bytes: &[u8],
) -> Result<UtxoEntry, Box<dyn std::error::Error + Send + Sync>> {
    if bytes.len() < 13 {
        return Err("utxo entry too short".into());
    }

    let height = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    let is_coinbase = bytes[4] != 0;
    let value = i64::from_le_bytes([
        bytes[5], bytes[6], bytes[7], bytes[8], bytes[9], bytes[10], bytes[11], bytes[12],
    ]);
    let script_len =
        u32::from_le_bytes([bytes[13], bytes[14], bytes[15], bytes[16]]) as usize;
    let script_bytes = &bytes[17..17 + script_len];

    Ok(UtxoEntry {
        output: TxOut::new(Amount::from_sat(value), Script::from_bytes(script_bytes.to_vec())),
        height,
        is_coinbase,
    })
}

#[async_trait]
impl ChainStateStore for RocksDbChainStateStore {
    async fn get_utxo(
        &self,
        txid: &Txid,
        vout: u32,
    ) -> Result<Option<UtxoEntry>, Box<dyn std::error::Error + Send + Sync>> {
        let db = self.db.clone();
        let key = utxo_key(txid, vout);

        tokio::task::spawn_blocking(move || {
            let cf_utxos = db.cf_handle(CF_UTXOS).unwrap();
            match db.get_cf(&cf_utxos, &key)? {
                Some(bytes) => Ok(Some(deserialize_utxo_entry(&bytes)?)),
                None => Ok(None),
            }
        })
        .await?
    }

    async fn has_utxo(
        &self,
        txid: &Txid,
        vout: u32,
    ) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
        let db = self.db.clone();
        let key = utxo_key(txid, vout);

        tokio::task::spawn_blocking(move || {
            let cf_utxos = db.cf_handle(CF_UTXOS).unwrap();
            Ok(db.get_cf(&cf_utxos, &key)?.is_some())
        })
        .await?
    }

    async fn write_utxo_set(
        &self,
        adds: Vec<(Txid, u32, UtxoEntry)>,
        removes: Vec<(Txid, u32)>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let db = self.db.clone();

        tokio::task::spawn_blocking(move || {
            let cf_utxos = db.cf_handle(CF_UTXOS).unwrap();
            let mut batch = rocksdb::WriteBatch::default();

            for (txid, vout, entry) in &adds {
                let key = utxo_key(txid, *vout);
                let value = serialize_utxo_entry(entry);
                batch.put_cf(&cf_utxos, &key, &value);
            }

            for (txid, vout) in &removes {
                let key = utxo_key(txid, *vout);
                batch.delete_cf(&cf_utxos, &key);
            }

            db.write(batch)?;

            tracing::debug!(
                "Updated UTXO set: +{} -{} (RocksDB)",
                adds.len(),
                removes.len()
            );
            Ok(())
        })
        .await?
    }

    async fn get_best_chain_tip(
        &self,
    ) -> Result<(BlockHash, u32), Box<dyn std::error::Error + Send + Sync>> {
        let db = self.db.clone();

        tokio::task::spawn_blocking(move || {
            let cf_meta = db.cf_handle(CF_META).unwrap();

            let hash = match db.get_cf(&cf_meta, META_CHAIN_TIP_HASH)? {
                Some(bytes) => {
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(&bytes);
                    BlockHash::from_hash(Hash256::from_bytes(arr))
                }
                None => BlockHash::zero(),
            };

            let height = match db.get_cf(&cf_meta, META_CHAIN_TIP_HEIGHT)? {
                Some(bytes) => u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
                None => 0,
            };

            Ok((hash, height))
        })
        .await?
    }

    async fn write_chain_tip(
        &self,
        hash: BlockHash,
        height: u32,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let db = self.db.clone();

        tokio::task::spawn_blocking(move || {
            let cf_meta = db.cf_handle(CF_META).unwrap();
            let mut batch = rocksdb::WriteBatch::default();
            batch.put_cf(&cf_meta, META_CHAIN_TIP_HASH, hash.as_bytes());
            batch.put_cf(&cf_meta, META_CHAIN_TIP_HEIGHT, &height.to_le_bytes());
            db.write(batch)?;

            tracing::debug!(
                "Updated chain tip to {} (height {}) (RocksDB)",
                hash,
                height
            );
            Ok(())
        })
        .await?
    }
}

// ---------------------------------------------------------------------------
// Simple block serialization (not Bitcoin wire format — just for storage)
// ---------------------------------------------------------------------------

/// Serialize a block to bytes for storage.
///
/// Format: header(80) + tx_count(4) + [tx_data...]
/// Each tx: version(4) + input_count(4) + [inputs...] + output_count(4) + [outputs...] + locktime(4) + witness_flag(1) + [witness...]
fn serialize_block(block: &Block) -> Vec<u8> {
    let mut buf = Vec::with_capacity(1024);

    // Header: version(4) + prev_hash(32) + merkle_root(32) + time(4) + bits(4) + nonce(4) = 80 bytes
    buf.extend_from_slice(&block.header.version.to_le_bytes());
    buf.extend_from_slice(block.header.prev_block_hash.as_bytes());
    buf.extend_from_slice(block.header.merkle_root.as_bytes());
    buf.extend_from_slice(&block.header.time.to_le_bytes());
    buf.extend_from_slice(&block.header.bits.to_le_bytes());
    buf.extend_from_slice(&block.header.nonce.to_le_bytes());

    // Transaction count
    buf.extend_from_slice(&(block.transactions.len() as u32).to_le_bytes());

    // Transactions
    for tx in &block.transactions {
        serialize_transaction(&mut buf, tx);
    }

    buf
}

fn serialize_transaction(buf: &mut Vec<u8>, tx: &Transaction) {
    buf.extend_from_slice(&tx.version.to_le_bytes());

    // Inputs
    buf.extend_from_slice(&(tx.inputs.len() as u32).to_le_bytes());
    for input in &tx.inputs {
        buf.extend_from_slice(input.previous_output.txid.as_bytes());
        buf.extend_from_slice(&input.previous_output.vout.to_le_bytes());
        let script = input.script_sig.as_bytes();
        buf.extend_from_slice(&(script.len() as u32).to_le_bytes());
        buf.extend_from_slice(script);
        buf.extend_from_slice(&input.sequence.to_le_bytes());
    }

    // Outputs
    buf.extend_from_slice(&(tx.outputs.len() as u32).to_le_bytes());
    for output in &tx.outputs {
        buf.extend_from_slice(&output.value.as_sat().to_le_bytes());
        let script = output.script_pubkey.as_bytes();
        buf.extend_from_slice(&(script.len() as u32).to_le_bytes());
        buf.extend_from_slice(script);
    }

    // Lock time
    buf.extend_from_slice(&tx.lock_time.to_le_bytes());

    // Witness data
    let has_witness = tx.has_witness();
    buf.push(if has_witness { 1 } else { 0 });
    if has_witness {
        for input in &tx.inputs {
            buf.extend_from_slice(&(input.witness.len() as u32).to_le_bytes());
            for item in input.witness.stack() {
                buf.extend_from_slice(&(item.len() as u32).to_le_bytes());
                buf.extend_from_slice(item);
            }
        }
    }
}

/// Deserialize a block from stored bytes
fn deserialize_block(
    bytes: &[u8],
) -> Result<Block, Box<dyn std::error::Error + Send + Sync>> {
    let mut pos = 0;

    // Header
    let version = read_i32(bytes, &mut pos)?;
    let prev_block_hash = read_hash(bytes, &mut pos)?;
    let merkle_root = read_hash(bytes, &mut pos)?;
    let time = read_u32(bytes, &mut pos)?;
    let bits = read_u32(bytes, &mut pos)?;
    let nonce = read_u32(bytes, &mut pos)?;

    let header = BlockHeader {
        version,
        prev_block_hash: BlockHash::from_hash(prev_block_hash),
        merkle_root,
        time,
        bits,
        nonce,
    };

    // Transactions
    let tx_count = read_u32(bytes, &mut pos)? as usize;
    let mut transactions = Vec::with_capacity(tx_count);
    for _ in 0..tx_count {
        transactions.push(deserialize_transaction(bytes, &mut pos)?);
    }

    Ok(Block {
        header,
        transactions,
    })
}

fn deserialize_transaction(
    bytes: &[u8],
    pos: &mut usize,
) -> Result<Transaction, Box<dyn std::error::Error + Send + Sync>> {
    let version = read_i32(bytes, pos)?;

    // Inputs
    let input_count = read_u32(bytes, pos)? as usize;
    let mut inputs = Vec::with_capacity(input_count);
    for _ in 0..input_count {
        let txid = Txid::from_hash(read_hash(bytes, pos)?);
        let vout = read_u32(bytes, pos)?;
        let script_len = read_u32(bytes, pos)? as usize;
        let script_bytes = read_bytes(bytes, pos, script_len)?;
        let sequence = read_u32(bytes, pos)?;
        inputs.push(TxIn::new(
            OutPoint::new(txid, vout),
            Script::from_bytes(script_bytes),
            sequence,
        ));
    }

    // Outputs
    let output_count = read_u32(bytes, pos)? as usize;
    let mut outputs = Vec::with_capacity(output_count);
    for _ in 0..output_count {
        let value = read_i64(bytes, pos)?;
        let script_len = read_u32(bytes, pos)? as usize;
        let script_bytes = read_bytes(bytes, pos, script_len)?;
        outputs.push(TxOut::new(
            Amount::from_sat(value),
            Script::from_bytes(script_bytes),
        ));
    }

    let lock_time = read_u32(bytes, pos)?;

    // Witness
    let has_witness = read_u8(bytes, pos)? != 0;
    if has_witness {
        for input in &mut inputs {
            let witness_count = read_u32(bytes, pos)? as usize;
            let mut witness = Witness::new();
            for _ in 0..witness_count {
                let item_len = read_u32(bytes, pos)? as usize;
                let item = read_bytes(bytes, pos, item_len)?;
                witness.push(item);
            }
            *input = input.clone().with_witness(witness);
        }
    }

    Ok(Transaction::new(version, inputs, outputs, lock_time))
}

// -- Deserialization helpers --

fn read_u8(bytes: &[u8], pos: &mut usize) -> Result<u8, Box<dyn std::error::Error + Send + Sync>> {
    if *pos >= bytes.len() {
        return Err("unexpected end of data".into());
    }
    let val = bytes[*pos];
    *pos += 1;
    Ok(val)
}

fn read_u32(
    bytes: &[u8],
    pos: &mut usize,
) -> Result<u32, Box<dyn std::error::Error + Send + Sync>> {
    if *pos + 4 > bytes.len() {
        return Err("unexpected end of data".into());
    }
    let val = u32::from_le_bytes([bytes[*pos], bytes[*pos + 1], bytes[*pos + 2], bytes[*pos + 3]]);
    *pos += 4;
    Ok(val)
}

fn read_i32(
    bytes: &[u8],
    pos: &mut usize,
) -> Result<i32, Box<dyn std::error::Error + Send + Sync>> {
    if *pos + 4 > bytes.len() {
        return Err("unexpected end of data".into());
    }
    let val = i32::from_le_bytes([bytes[*pos], bytes[*pos + 1], bytes[*pos + 2], bytes[*pos + 3]]);
    *pos += 4;
    Ok(val)
}

fn read_i64(
    bytes: &[u8],
    pos: &mut usize,
) -> Result<i64, Box<dyn std::error::Error + Send + Sync>> {
    if *pos + 8 > bytes.len() {
        return Err("unexpected end of data".into());
    }
    let val = i64::from_le_bytes([
        bytes[*pos],
        bytes[*pos + 1],
        bytes[*pos + 2],
        bytes[*pos + 3],
        bytes[*pos + 4],
        bytes[*pos + 5],
        bytes[*pos + 6],
        bytes[*pos + 7],
    ]);
    *pos += 8;
    Ok(val)
}

fn read_hash(
    bytes: &[u8],
    pos: &mut usize,
) -> Result<Hash256, Box<dyn std::error::Error + Send + Sync>> {
    if *pos + 32 > bytes.len() {
        return Err("unexpected end of data".into());
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes[*pos..*pos + 32]);
    *pos += 32;
    Ok(Hash256::from_bytes(arr))
}

fn read_bytes(
    bytes: &[u8],
    pos: &mut usize,
    len: usize,
) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
    if *pos + len > bytes.len() {
        return Err("unexpected end of data".into());
    }
    let data = bytes[*pos..*pos + len].to_vec();
    *pos += len;
    Ok(data)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_utxo_key_roundtrip() {
        let txid = Txid::zero();
        let vout = 42u32;
        let key = utxo_key(&txid, vout);
        assert_eq!(&key[..32], txid.as_bytes());
        assert_eq!(
            u32::from_le_bytes([key[32], key[33], key[34], key[35]]),
            42
        );
    }

    #[test]
    fn test_utxo_entry_serialization() {
        let entry = UtxoEntry {
            output: TxOut::new(Amount::from_sat(50_000), Script::from_bytes(vec![0x76, 0xa9])),
            height: 100,
            is_coinbase: true,
        };

        let bytes = serialize_utxo_entry(&entry);
        let restored = deserialize_utxo_entry(&bytes).unwrap();
        assert_eq!(restored.height, 100);
        assert!(restored.is_coinbase);
        assert_eq!(restored.output.value.as_sat(), 50_000);
        assert_eq!(restored.output.script_pubkey.as_bytes(), &[0x76, 0xa9]);
    }

    #[test]
    fn test_block_serialization_roundtrip() {
        let genesis = Block {
            header: BlockHeader {
                version: 1,
                prev_block_hash: BlockHash::zero(),
                merkle_root: Hash256::from_bytes([0xab; 32]),
                time: 1231006505,
                bits: 0x1d00ffff,
                nonce: 2083236893,
            },
            transactions: vec![Transaction::coinbase(
                0,
                Script::from_bytes(vec![0x04, 0xff, 0xff, 0x00, 0x1d]),
                vec![TxOut::new(
                    Amount::from_sat(5_000_000_000),
                    Script::from_bytes(vec![0x76, 0xa9, 0x14]),
                )],
            )],
        };

        let serialized = serialize_block(&genesis);
        let deserialized = deserialize_block(&serialized).unwrap();

        assert_eq!(deserialized.header.version, genesis.header.version);
        assert_eq!(deserialized.header.time, genesis.header.time);
        assert_eq!(deserialized.header.nonce, genesis.header.nonce);
        assert_eq!(deserialized.transactions.len(), 1);
        assert!(deserialized.transactions[0].is_coinbase());
    }
}
