//! Core Script type definition
//!
//! The bare `Script` newtype lives here in `primitives` so that `transaction`
//! can reference it without pulling in the full `script` module (which depends
//! on `crypto`). All opcode-aware methods remain in `script::script`.

/// Bitcoin Script - sequence of opcodes and data
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Script(pub(crate) Vec<u8>);

impl Script {
    /// Create an empty script
    pub fn new() -> Self {
        Script(Vec::new())
    }

    /// Create a script from bytes
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Script(bytes)
    }

    /// Create a script from a byte slice
    pub fn from_slice(bytes: &[u8]) -> Self {
        Script(bytes.to_vec())
    }

    /// Get the script bytes
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Get the underlying byte vector
    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }

    /// Get the script length
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Check if script is empty
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl Default for Script {
    fn default() -> Self {
        Script::new()
    }
}

