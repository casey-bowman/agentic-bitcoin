//! Bitcoin script handling
//!
//! Corresponds to Bitcoin Core's script/ directory containing script types,
//! opcodes, and the stack-based interpreter.

pub mod interpreter;
pub mod opcodes;
pub mod script;
pub mod witness;

pub use interpreter::{
    ScriptError, ScriptFlags, ScriptInterpreter, SignatureChecker,
    NoSigChecker, verify_script, is_push_only,
};
pub use opcodes::Opcodes;
pub use script::{Script, ScriptBuilder};
pub use witness::Witness;
