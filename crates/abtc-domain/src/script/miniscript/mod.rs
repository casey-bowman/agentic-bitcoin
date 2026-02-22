// Miniscript module
//
// Provides a structured representation of Bitcoin Script spending conditions
// that is analyzable, composable, and can be compiled to/from raw Script.
//
// Reference: https://bitcoin.sipa.be/miniscript/

pub mod types;
pub mod fragment;
pub mod compiler;
pub mod decode;
pub mod policy;

// Re-export key public types
pub use types::{BaseType, TypeModifiers, MiniscriptType};
pub use fragment::{Terminal, Miniscript};
pub use decode::DecodeError;
pub use policy::{Policy, PolicyParseError, CompileError, parse_policy};
