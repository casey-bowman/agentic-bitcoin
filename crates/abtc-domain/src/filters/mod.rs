//! BIP158 Compact Block Filters (Neutrino)
//!
//! Implements Golomb-Coded Set (GCS) filters for compact block filtering,
//! allowing light clients to privately determine whether a block contains
//! transactions relevant to their wallet without downloading full blocks.
//!
//! ## Modules
//!
//! - `gcs` — Golomb-Coded Set encoding/decoding, SipHash, BitWriter/BitReader
//! - `block_filter` — BIP158 filter construction from blocks, filter header chain
//! - `messages` — BIP157 P2P message types (getcfilters, cfilters, etc.)

pub mod gcs;
pub mod block_filter;
pub mod messages;

// Re-export key types
pub use gcs::{GcsFilter, BitWriter, BitReader, siphash_2_4, key_from_block_hash, hash_to_range};
pub use gcs::{BASIC_FILTER_M, BASIC_FILTER_P};
pub use block_filter::{BlockFilter, FilterHeader, BASIC_FILTER_TYPE};
pub use block_filter::{compute_filter_header, build_filter_header_chain};
pub use messages::{GetCFilters, CFilter, GetCFHeaders, CFHeaders, GetCFCheckpt, CFCheckpt};
