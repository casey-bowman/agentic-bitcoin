//! UTXO Set Commitments & AssumeUTXO
//!
//! This module implements the infrastructure for UTXO set snapshots and
//! commitments used by Bitcoin Core's AssumeUTXO fast-sync feature:
//!
//! - **Coin compression** (`coin.rs`): Bitcoin Core's compact encoding for
//!   amounts and scriptPubKeys, reducing UTXO storage and snapshot sizes.
//!
//! - **MuHash3072** (`muhash.rs`): A rolling (incremental) multiset hash
//!   operating in Z/pZ with a 3072-bit prime. Allows O(1) insertions and
//!   removals without reprocessing the entire set.
//!
//! - **Snapshot** (`snapshot.rs`): AssumeUTXO snapshot metadata, the binary
//!   snapshot format, and hardcoded parameters for known-good snapshots at
//!   specific block heights.
//!
//! # AssumeUTXO overview
//!
//! Traditional IBD (Initial Block Download) replays every block from genesis
//! to build the UTXO set. AssumeUTXO short-circuits this by loading a
//! pre-computed snapshot of the UTXO set at a known height, then:
//!
//! 1. Immediately starts syncing from the snapshot height forward.
//! 2. In the background, validates all blocks from genesis to the snapshot
//!    height, confirming the snapshot was honest.
//!
//! The snapshot's integrity is checked via a MuHash commitment embedded in
//! the node software.

pub mod coin;
pub mod muhash;
pub mod snapshot;

pub use coin::{compress_amount, decompress_amount, CompressedCoin};
pub use muhash::MuHash3072;
pub use snapshot::{AssumeUtxoParams, SnapshotMetadata, UtxoSnapshot};
