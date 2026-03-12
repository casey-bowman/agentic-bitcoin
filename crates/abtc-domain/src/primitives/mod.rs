//! Bitcoin primitive types
//!
//! Corresponds to Bitcoin Core's primitives/ directory containing basic types
//! like amounts, hashes, transactions, and blocks.

pub mod amount;
pub mod block;
pub mod hash;
pub mod public_key;
pub mod script_types;
pub mod transaction;
pub mod witness;

pub use amount::{is_money_range, Amount, COIN, MAX_MONEY};
pub use public_key::{KeyError, PublicKey};
pub use script_types::Script;
pub use witness::Witness;
pub use block::{Block, BlockHeader, BlockLocator};
pub use hash::BlockHash;
pub use hash::{Hash256, Txid, Wtxid};
pub use transaction::{DeserializeError, OutPoint, Sequence, Transaction, TxIn, TxOut};
