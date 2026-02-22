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
pub use descriptor::{Descriptor, ShInner, WshInner, TrTree};
pub use key_expr::{
    DescriptorKey, SingleKey, ExtendedKey, XKey, KeyOrigin, Wildcard, KeyError, HARDENED_BIT,
};
pub use parser::{parse_descriptor, ParseError};
pub use checksum::{descriptor_checksum, verify_checksum, add_checksum, ChecksumError};
pub use compiler::DescriptorError;
