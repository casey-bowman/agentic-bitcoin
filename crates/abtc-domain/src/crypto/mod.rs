//! Bitcoin cryptography
//!
//! Corresponds to Bitcoin Core's crypto/ directory containing hashing
//! functions, ECDSA signature verification, and Schnorr/Taproot support.

pub mod bip324;
pub mod hashing;
pub mod schnorr;
pub mod signing;
pub mod taproot;

pub use hashing::{hash160, hash256, hash_sig, sha1, sha256};
pub use schnorr::{parse_schnorr_signature, verify_schnorr};
pub use signing::{verify_ecdsa, SpentOutput, TransactionSignatureChecker};
pub use taproot::{
    tagged_hash, tapbranch_hash, tapleaf_hash, taproot_sighash, taptweak_hash,
    verify_taproot_commitment, ControlBlock, TapLeaf, TapTree, TAPSCRIPT_LEAF_VERSION,
};
