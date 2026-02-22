//! Bitcoin script handling
//!
//! Corresponds to Bitcoin Core's script/ directory containing script types,
//! opcodes, and the stack-based interpreter.

pub mod interpreter;
pub mod miniscript;
pub mod opcodes;
pub mod script;
pub mod witness;

pub use interpreter::{
    ScriptError, ScriptFlags, ScriptInterpreter, SignatureChecker,
    NoSigChecker, verify_script, verify_script_with_witness, is_push_only,
};
pub use miniscript::{Miniscript, Terminal, MiniscriptType, BaseType, DecodeError as MiniscriptDecodeError};
pub use opcodes::Opcodes;
pub use script::{Script, ScriptBuilder};
pub use witness::Witness;
