// Miniscript module
//
// Provides a structured representation of Bitcoin Script spending conditions
// that is analyzable, composable, and can be compiled to/from raw Script.
//
// Reference: https://bitcoin.sipa.be/miniscript/

pub mod compiler;
pub mod decode;
pub mod fragment;
pub mod policy;
pub mod types;

// Re-export key public types
pub use decode::DecodeError;
pub use fragment::{Miniscript, Terminal};
pub use policy::{parse_policy, CompileError, Policy, PolicyParseError};
pub use types::{BaseType, MiniscriptType, TypeModifiers};
