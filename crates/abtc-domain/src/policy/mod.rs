//! Transaction and mempool policy rules
//!
//! Implements relay and mempool acceptance policies corresponding to
//! Bitcoin Core's `src/policy/policy.cpp` and `src/policy/rbf.cpp`.
//! These are NOT consensus rules — they are local node policy.

pub mod rbf;
pub mod limits;
pub mod packages;

pub use rbf::{RbfPolicy, RbfError, SignalsRbf};
pub use limits::{MempoolLimits, PackageInfo, LimitError};
pub use packages::{
    TransactionPackage, PackageType, PackageError,
    validate_package, topological_sort, check_package_fee_rate,
    estimate_package_tx_vsize, MAX_PACKAGE_COUNT, MAX_PACKAGE_VSIZE,
};
