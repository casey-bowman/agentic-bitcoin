//! Bitcoin script handling
//!
//! Corresponds to Bitcoin Core's script/ directory containing script types,
//! opcodes, and the stack-based interpreter.

#[allow(clippy::module_inception)]
pub mod script;
pub mod interpreter;
pub mod miniscript;
pub mod opcodes;
pub mod witness;

pub use interpreter::{
    is_push_only, verify_script, verify_script_with_witness, NoSigChecker, ScriptError,
    ScriptFlags, ScriptInterpreter, SignatureChecker,
};
pub use miniscript::{
    BaseType, DecodeError as MiniscriptDecodeError, Miniscript, MiniscriptType, Terminal,
};
pub use opcodes::Opcodes;
pub use script::{Script, ScriptBuilder};
pub use witness::Witness;
