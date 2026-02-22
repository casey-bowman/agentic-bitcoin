//! AssumeUTXO snapshot format and metadata
//!
//! Defines the binary snapshot format for serializing the entire UTXO set,
//! the metadata that accompanies a snapshot, and the hardcoded "assume valid"
//! parameters for known-good snapshot heights.
//!
//! ## Snapshot format
//!
//! ```text
//! ┌─────────────────────────────────────────────┐
//! │ version          : u16 (LE)                 │
//! │ network_magic    : [u8; 4]                  │
//! │ block_hash       : [u8; 32]                 │
//! │ block_height     : u32 (LE)                 │
//! │ num_coins        : u64 (LE, varint)         │
//! │ muhash_digest    : [u8; 32]                 │
//! │ coins            : CompressedCoin[]          │
//! └─────────────────────────────────────────────┘
//! ```
//!
//! Each coin is serialized as `txid(32) || varint(vout) || compressed_coin`.

use crate::consensus::connect::UtxoEntry;
use crate::primitives::{BlockHash, Hash256, OutPoint};
use super::coin::{serialize_utxo, deserialize_utxo, push_varint, read_varint};
use super::muhash::MuHash3072;

/// Current snapshot format version.
const SNAPSHOT_VERSION: u16 = 1;

// ---------------------------------------------------------------------------
// SnapshotMetadata
// ---------------------------------------------------------------------------

/// Metadata describing an AssumeUTXO snapshot.
///
/// This metadata is included in the snapshot header and is also hardcoded
/// in the software for known-good snapshot heights to verify integrity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnapshotMetadata {
    /// Snapshot format version
    pub version: u16,
    /// Network magic bytes (e.g. mainnet = 0xf9beb4d9)
    pub network_magic: [u8; 4],
    /// Block hash at the snapshot height
    pub block_hash: BlockHash,
    /// Block height
    pub height: u32,
    /// Number of UTXO entries in the snapshot
    pub num_coins: u64,
    /// MuHash3072 digest of the UTXO set
    pub muhash: Hash256,
}

impl SnapshotMetadata {
    /// Serialize metadata to a binary header.
    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(78);
        buf.extend_from_slice(&self.version.to_le_bytes());
        buf.extend_from_slice(&self.network_magic);
        buf.extend_from_slice(self.block_hash.as_bytes());
        buf.extend_from_slice(&self.height.to_le_bytes());
        push_varint(&mut buf, self.num_coins);
        buf.extend_from_slice(self.muhash.as_bytes());
        buf
    }

    /// Deserialize metadata from a binary header.
    pub fn deserialize(data: &[u8]) -> Result<(Self, usize), &'static str> {
        if data.len() < 2 + 4 + 32 + 4 {
            return Err("snapshot header too short");
        }

        let mut pos = 0;

        let version = u16::from_le_bytes([data[pos], data[pos + 1]]);
        pos += 2;

        let mut network_magic = [0u8; 4];
        network_magic.copy_from_slice(&data[pos..pos + 4]);
        pos += 4;

        let mut hash_bytes = [0u8; 32];
        hash_bytes.copy_from_slice(&data[pos..pos + 32]);
        let block_hash = BlockHash::from_hash(Hash256::from_bytes(hash_bytes));
        pos += 32;

        let height = u32::from_le_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]);
        pos += 4;

        let (num_coins, n) = read_varint(data, pos)?;
        pos += n;

        if pos + 32 > data.len() {
            return Err("snapshot header truncated at muhash");
        }
        let mut muhash_bytes = [0u8; 32];
        muhash_bytes.copy_from_slice(&data[pos..pos + 32]);
        let muhash = Hash256::from_bytes(muhash_bytes);
        pos += 32;

        Ok((
            SnapshotMetadata {
                version,
                network_magic,
                block_hash,
                height,
                num_coins,
                muhash,
            },
            pos,
        ))
    }

    /// Validate this metadata against hardcoded AssumeUTXO parameters.
    pub fn validate_against(&self, params: &AssumeUtxoParams) -> Result<(), SnapshotError> {
        if self.height != params.height {
            return Err(SnapshotError::HeightMismatch {
                expected: params.height,
                got: self.height,
            });
        }
        if self.block_hash != params.block_hash {
            return Err(SnapshotError::BlockHashMismatch);
        }
        if self.num_coins != params.num_coins {
            return Err(SnapshotError::CoinCountMismatch {
                expected: params.num_coins,
                got: self.num_coins,
            });
        }
        if self.muhash != params.muhash {
            return Err(SnapshotError::MuHashMismatch);
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// UtxoSnapshot — the full serialized snapshot
// ---------------------------------------------------------------------------

/// A complete UTXO set snapshot that can be serialized/deserialized.
#[derive(Debug, Clone)]
pub struct UtxoSnapshot {
    /// Snapshot metadata (header)
    pub metadata: SnapshotMetadata,
    /// All UTXO entries: (outpoint, entry)
    pub coins: Vec<(OutPoint, UtxoEntry)>,
}

impl UtxoSnapshot {
    /// Build a snapshot from a UTXO set iterator.
    ///
    /// Computes the MuHash commitment over all entries.
    pub fn build(
        coins: Vec<(OutPoint, UtxoEntry)>,
        block_hash: BlockHash,
        height: u32,
        network_magic: [u8; 4],
    ) -> Self {
        let mut muhash = MuHash3072::new();

        for (outpoint, entry) in &coins {
            let serialized = serialize_utxo(outpoint, entry);
            muhash.insert(&serialized);
        }

        let metadata = SnapshotMetadata {
            version: SNAPSHOT_VERSION,
            network_magic,
            block_hash,
            height,
            num_coins: coins.len() as u64,
            muhash: muhash.finalize(),
        };

        UtxoSnapshot { metadata, coins }
    }

    /// Serialize the full snapshot to binary.
    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = self.metadata.serialize();

        for (outpoint, entry) in &self.coins {
            buf.extend_from_slice(&serialize_utxo(outpoint, entry));
        }

        buf
    }

    /// Deserialize a full snapshot from binary.
    pub fn deserialize(data: &[u8]) -> Result<Self, SnapshotError> {
        let (metadata, mut pos) = SnapshotMetadata::deserialize(data)
            .map_err(|e| SnapshotError::ParseError(e.to_string()))?;

        if metadata.version != SNAPSHOT_VERSION {
            return Err(SnapshotError::UnsupportedVersion(metadata.version));
        }

        let mut coins = Vec::with_capacity(metadata.num_coins as usize);
        for _ in 0..metadata.num_coins {
            let (outpoint, entry, bytes_read) = deserialize_utxo(data, pos)
                .map_err(|e| SnapshotError::ParseError(e.to_string()))?;
            pos += bytes_read;
            coins.push((outpoint, entry));
        }

        Ok(UtxoSnapshot { metadata, coins })
    }

    /// Verify the snapshot's MuHash commitment matches its contents.
    pub fn verify_commitment(&self) -> Result<(), SnapshotError> {
        let mut muhash = MuHash3072::new();

        for (outpoint, entry) in &self.coins {
            let serialized = serialize_utxo(outpoint, entry);
            muhash.insert(&serialized);
        }

        let computed = muhash.finalize();
        if computed != self.metadata.muhash {
            return Err(SnapshotError::MuHashMismatch);
        }

        Ok(())
    }

    /// Verify against hardcoded AssumeUTXO parameters and check commitment.
    pub fn validate(&self, params: &AssumeUtxoParams) -> Result<(), SnapshotError> {
        self.metadata.validate_against(params)?;
        self.verify_commitment()?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// AssumeUtxoParams — hardcoded snapshot parameters
// ---------------------------------------------------------------------------

/// Hardcoded parameters for a known-good UTXO snapshot.
///
/// These are embedded in the node software and verified against any
/// loaded snapshot to ensure it matches the expected state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AssumeUtxoParams {
    /// Block height of the snapshot
    pub height: u32,
    /// Block hash at the snapshot height
    pub block_hash: BlockHash,
    /// Expected number of coins
    pub num_coins: u64,
    /// Expected MuHash commitment
    pub muhash: Hash256,
}

impl AssumeUtxoParams {
    /// Get AssumeUTXO parameters for mainnet at known heights.
    ///
    /// These correspond to Bitcoin Core's `chainparams.cpp` entries.
    pub fn mainnet() -> Vec<AssumeUtxoParams> {
        vec![
            // Height 840,000 (post-4th halving, April 2024)
            AssumeUtxoParams {
                height: 840_000,
                block_hash: BlockHash::from_hash(Hash256::from_bytes([
                    // 0000000000000000000320283a032748cef8227873ff4872689bf23f1cda83a5
                    0xa5, 0x83, 0xda, 0x1c, 0x3f, 0xf2, 0x9b, 0x68,
                    0x72, 0x48, 0xff, 0x73, 0x78, 0x22, 0xf8, 0xce,
                    0x48, 0x27, 0x03, 0x3a, 0x28, 0x20, 0x03, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                ])),
                num_coins: 176_629_079,
                muhash: Hash256::from_bytes([
                    // Placeholder — real value from Bitcoin Core
                    0x00; 32
                ]),
            },
        ]
    }

    /// Get AssumeUTXO parameters for testnet.
    pub fn testnet() -> Vec<AssumeUtxoParams> {
        vec![]
    }

    /// Get AssumeUTXO parameters for signet.
    pub fn signet() -> Vec<AssumeUtxoParams> {
        vec![]
    }
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Errors that can occur during snapshot operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SnapshotError {
    /// Snapshot height doesn't match expected
    HeightMismatch { expected: u32, got: u32 },
    /// Block hash doesn't match expected
    BlockHashMismatch,
    /// Coin count doesn't match expected
    CoinCountMismatch { expected: u64, got: u64 },
    /// MuHash commitment doesn't match
    MuHashMismatch,
    /// Snapshot format version not supported
    UnsupportedVersion(u16),
    /// Failed to parse snapshot data
    ParseError(String),
}

impl std::fmt::Display for SnapshotError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SnapshotError::HeightMismatch { expected, got } => {
                write!(f, "snapshot height mismatch: expected {}, got {}", expected, got)
            }
            SnapshotError::BlockHashMismatch => {
                write!(f, "snapshot block hash does not match expected")
            }
            SnapshotError::CoinCountMismatch { expected, got } => {
                write!(f, "snapshot coin count mismatch: expected {}, got {}", expected, got)
            }
            SnapshotError::MuHashMismatch => {
                write!(f, "snapshot MuHash commitment does not match")
            }
            SnapshotError::UnsupportedVersion(v) => {
                write!(f, "unsupported snapshot version: {}", v)
            }
            SnapshotError::ParseError(msg) => {
                write!(f, "snapshot parse error: {}", msg)
            }
        }
    }
}

impl std::error::Error for SnapshotError {}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::primitives::{Amount, Txid, TxOut};
    use crate::script::Script;

    fn make_test_entry(sat: i64, height: u32, is_coinbase: bool) -> UtxoEntry {
        UtxoEntry {
            output: TxOut::new(
                Amount::from_sat(sat),
                Script::from_bytes(vec![
                    0x76, 0xa9, 0x14,
                    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a,
                    0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14,
                    0x88, 0xac,
                ]),
            ),
            height,
            is_coinbase,
        }
    }

    fn make_test_coins(count: usize) -> Vec<(OutPoint, UtxoEntry)> {
        (0..count)
            .map(|i| {
                let mut txid_bytes = [0u8; 32];
                txid_bytes[0] = (i & 0xFF) as u8;
                txid_bytes[1] = ((i >> 8) & 0xFF) as u8;
                let txid = Txid::from_hash(Hash256::from_bytes(txid_bytes));
                let outpoint = OutPoint::new(txid, 0);
                let entry = make_test_entry(
                    100_000_000 * (i as i64 + 1),
                    500_000 + i as u32,
                    i == 0,
                );
                (outpoint, entry)
            })
            .collect()
    }

    // ── SnapshotMetadata ───────────────────────────────────────────

    #[test]
    fn test_metadata_roundtrip() {
        let metadata = SnapshotMetadata {
            version: 1,
            network_magic: [0xf9, 0xbe, 0xb4, 0xd9],
            block_hash: BlockHash::from_hash(Hash256::from_bytes([0xaa; 32])),
            height: 840_000,
            num_coins: 176_000_000,
            muhash: Hash256::from_bytes([0xbb; 32]),
        };

        let serialized = metadata.serialize();
        let (deserialized, _) = SnapshotMetadata::deserialize(&serialized).unwrap();
        assert_eq!(deserialized, metadata);
    }

    #[test]
    fn test_metadata_validate_against_params() {
        let params = AssumeUtxoParams {
            height: 100,
            block_hash: BlockHash::from_hash(Hash256::from_bytes([0x11; 32])),
            num_coins: 50,
            muhash: Hash256::from_bytes([0x22; 32]),
        };

        let good = SnapshotMetadata {
            version: 1,
            network_magic: [0; 4],
            block_hash: params.block_hash,
            height: params.height,
            num_coins: params.num_coins,
            muhash: params.muhash,
        };
        assert!(good.validate_against(&params).is_ok());

        // Wrong height
        let bad_height = SnapshotMetadata { height: 999, ..good.clone() };
        assert!(matches!(
            bad_height.validate_against(&params),
            Err(SnapshotError::HeightMismatch { .. })
        ));

        // Wrong coin count
        let bad_coins = SnapshotMetadata { num_coins: 999, ..good.clone() };
        assert!(matches!(
            bad_coins.validate_against(&params),
            Err(SnapshotError::CoinCountMismatch { .. })
        ));
    }

    // ── UtxoSnapshot ───────────────────────────────────────────────

    #[test]
    fn test_snapshot_build_and_verify() {
        let coins = make_test_coins(5);
        let block_hash = BlockHash::from_hash(Hash256::from_bytes([0xcc; 32]));

        let snapshot = UtxoSnapshot::build(coins.clone(), block_hash, 500_000, [0xf9, 0xbe, 0xb4, 0xd9]);

        assert_eq!(snapshot.metadata.height, 500_000);
        assert_eq!(snapshot.metadata.num_coins, 5);
        assert_eq!(snapshot.coins.len(), 5);

        // Commitment should verify
        assert!(snapshot.verify_commitment().is_ok());
    }

    #[test]
    fn test_snapshot_serialize_deserialize() {
        let coins = make_test_coins(3);
        let block_hash = BlockHash::from_hash(Hash256::from_bytes([0xdd; 32]));
        let snapshot = UtxoSnapshot::build(coins, block_hash, 100, [0x0b, 0x11, 0x09, 0x07]);

        let serialized = snapshot.serialize();
        let deserialized = UtxoSnapshot::deserialize(&serialized).unwrap();

        assert_eq!(deserialized.metadata, snapshot.metadata);
        assert_eq!(deserialized.coins.len(), snapshot.coins.len());

        // Commitment should still verify after roundtrip
        assert!(deserialized.verify_commitment().is_ok());
    }

    #[test]
    fn test_snapshot_tampered_commitment_fails() {
        let coins = make_test_coins(3);
        let block_hash = BlockHash::from_hash(Hash256::from_bytes([0xee; 32]));
        let mut snapshot = UtxoSnapshot::build(coins, block_hash, 100, [0; 4]);

        // Tamper with the metadata muhash
        snapshot.metadata.muhash = Hash256::from_bytes([0xff; 32]);
        assert!(matches!(
            snapshot.verify_commitment(),
            Err(SnapshotError::MuHashMismatch)
        ));
    }

    #[test]
    fn test_snapshot_validate_full() {
        let coins = make_test_coins(2);
        let block_hash = BlockHash::from_hash(Hash256::from_bytes([0x55; 32]));
        let snapshot = UtxoSnapshot::build(coins, block_hash, 200, [0; 4]);

        let params = AssumeUtxoParams {
            height: 200,
            block_hash,
            num_coins: 2,
            muhash: snapshot.metadata.muhash,
        };

        assert!(snapshot.validate(&params).is_ok());
    }

    #[test]
    fn test_snapshot_empty_set() {
        let coins: Vec<(OutPoint, UtxoEntry)> = vec![];
        let block_hash = BlockHash::from_hash(Hash256::zero());
        let snapshot = UtxoSnapshot::build(coins, block_hash, 0, [0; 4]);

        assert_eq!(snapshot.metadata.num_coins, 0);
        assert!(snapshot.verify_commitment().is_ok());

        let serialized = snapshot.serialize();
        let deserialized = UtxoSnapshot::deserialize(&serialized).unwrap();
        assert_eq!(deserialized.coins.len(), 0);
    }

    #[test]
    fn test_snapshot_preserves_coin_data() {
        let entry = UtxoEntry {
            output: TxOut::new(
                Amount::from_sat(314_159_265),
                Script::from_bytes(vec![0xa9, 0x14,
                    0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11,
                    0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
                    0xaa, 0xbb, 0xcc, 0xdd,
                    0x87]),
            ),
            height: 750_000,
            is_coinbase: true,
        };
        let txid = Txid::from_hash(Hash256::from_bytes([0x42; 32]));
        let outpoint = OutPoint::new(txid, 7);

        let coins = vec![(outpoint, entry.clone())];
        let snapshot = UtxoSnapshot::build(
            coins, BlockHash::zero(), 750_000, [0; 4],
        );

        let serialized = snapshot.serialize();
        let deserialized = UtxoSnapshot::deserialize(&serialized).unwrap();

        let (op, ent) = &deserialized.coins[0];
        assert_eq!(*op, outpoint);
        assert_eq!(ent.height, 750_000);
        assert!(ent.is_coinbase);
        assert_eq!(ent.output.value.as_sat(), 314_159_265);
    }

    // ── AssumeUtxoParams ───────────────────────────────────────────

    #[test]
    fn test_mainnet_params_exist() {
        let params = AssumeUtxoParams::mainnet();
        assert!(!params.is_empty());
        assert_eq!(params[0].height, 840_000);
    }

    #[test]
    fn test_unsupported_version_rejected() {
        let coins = make_test_coins(1);
        let block_hash = BlockHash::zero();
        let mut snapshot = UtxoSnapshot::build(coins, block_hash, 0, [0; 4]);
        snapshot.metadata.version = 99;

        let serialized = snapshot.serialize();
        let result = UtxoSnapshot::deserialize(&serialized);
        assert!(matches!(result, Err(SnapshotError::UnsupportedVersion(99))));
    }
}
