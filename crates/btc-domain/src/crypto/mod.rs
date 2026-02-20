//! Bitcoin cryptography
//!
//! Corresponds to Bitcoin Core's crypto/ directory containing hashing
//! functions and ECDSA signature verification.

pub mod hashing;
pub mod signing;

pub use hashing::{hash160, hash256, hash_sig, sha256};
pub use signing::{TransactionSignatureChecker, verify_ecdsa};
