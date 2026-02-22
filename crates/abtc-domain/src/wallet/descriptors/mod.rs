// Output descriptors module
//
// Provides structured representation of Bitcoin output descriptors
// (BIP380-386) with parsing, compilation to scripts/addresses,
// key expression handling, and checksum support.

pub mod checksum;
pub mod compiler;
pub mod descriptor;
pub mod key_expr;
pub mod parser;

// Re-export key public types
pub use checksum::{add_checksum, descriptor_checksum, verify_checksum, ChecksumError};
pub use compiler::DescriptorError;
pub use descriptor::{Descriptor, ShInner, TrTree, WshInner};
pub use key_expr::{
    DescriptorKey, ExtendedKey, KeyError, KeyOrigin, SingleKey, Wildcard, XKey, HARDENED_BIT,
};
pub use parser::{parse_descriptor, ParseError};
