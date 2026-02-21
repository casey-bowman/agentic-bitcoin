//! Bitcoin primitive types
//!
//! Corresponds to Bitcoin Core's primitives/ directory containing basic types
//! like amounts, hashes, transactions, and blocks.

pub mod amount;
pub mod block;
pub mod hash;
pub mod transaction;

pub use amount::{Amount, is_money_range, COIN, MAX_MONEY};
pub use hash::BlockHash;
pub use block::{Block, BlockHeader, BlockLocator};
pub use hash::{Hash256, Txid, Wtxid};
pub use transaction::{DeserializeError, OutPoint, Sequence, Transaction, TxIn, TxOut};
pub use crate::script::Witness;
