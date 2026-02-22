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
pub use schnorr::{verify_schnorr, parse_schnorr_signature};
pub use signing::{TransactionSignatureChecker, SpentOutput, verify_ecdsa};
pub use taproot::{
    ControlBlock, TapTree, TapLeaf, tagged_hash, tapleaf_hash, tapbranch_hash,
    taptweak_hash, verify_taproot_commitment, taproot_sighash,
    TAPSCRIPT_LEAF_VERSION,
};
