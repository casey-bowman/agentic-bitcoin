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

pub mod block_filter;
pub mod gcs;
pub mod messages;

// Re-export key types
pub use block_filter::{build_filter_header_chain, compute_filter_header};
pub use block_filter::{BlockFilter, FilterHeader, BASIC_FILTER_TYPE};
pub use gcs::{hash_to_range, key_from_block_hash, siphash_2_4, BitReader, BitWriter, GcsFilter};
pub use gcs::{BASIC_FILTER_M, BASIC_FILTER_P};
pub use messages::{CFCheckpt, CFHeaders, CFilter, GetCFCheckpt, GetCFHeaders, GetCFilters};
