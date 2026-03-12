//! Re-export hashing functions from the top-level hashing module.
//!
//! The actual implementation lives in `crate::hashing`. This shim preserves
//! backward compatibility so that `crate::hashing::*` paths continue
//! to resolve.

pub use crate::hashing::*;
