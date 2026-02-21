//! Bitcoin Script type
//!
//! Represents a script as a byte vector with pattern matching and builder support.

use crate::script::Opcodes;
use std::fmt;

/// Bitcoin Script - sequence of opcodes and data
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Script(Vec<u8>);

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

    /// Get the script length
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Check if script is empty
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Check if script is P2PKH (Pay to Public Key Hash)
    /// Pattern: OP_DUP OP_HASH160 <20 bytes> OP_EQUALVERIFY OP_CHECKSIG
    pub fn is_p2pkh(&self) -> bool {
        self.0.len() == 25
            && self.0[0] == Opcodes::OP_DUP as u8
            && self.0[1] == Opcodes::OP_HASH160 as u8
            && self.0[2] == 20
            && self.0[23] == Opcodes::OP_EQUALVERIFY as u8
            && self.0[24] == Opcodes::OP_CHECKSIG as u8
    }

    /// Check if script is P2SH (Pay to Script Hash)
    /// Pattern: OP_HASH160 <20 bytes> OP_EQUAL
    pub fn is_p2sh(&self) -> bool {
        self.0.len() == 23
            && self.0[0] == Opcodes::OP_HASH160 as u8
            && self.0[1] == 20
            && self.0[22] == Opcodes::OP_EQUAL as u8
    }

    /// Check if script is P2WPKH (Pay to Witness Public Key Hash)
    /// Pattern: OP_0 <20 bytes>
    pub fn is_p2wpkh(&self) -> bool {
        self.0.len() == 22 && self.0[0] == 0 && self.0[1] == 20
    }

    /// Check if script is P2WSH (Pay to Witness Script Hash)
    /// Pattern: OP_0 <32 bytes>
    pub fn is_p2wsh(&self) -> bool {
        self.0.len() == 34 && self.0[0] == 0 && self.0[1] == 32
    }

    /// Check if script is P2TR (Pay to Taproot)
    /// Pattern: OP_1 <32 bytes>
    pub fn is_p2tr(&self) -> bool {
        self.0.len() == 34 && self.0[0] == Opcodes::OP_1 as u8 && self.0[1] == 32
    }

    /// Check if script is OP_RETURN (data output)
    pub fn is_op_return(&self) -> bool {
        !self.0.is_empty() && self.0[0] == Opcodes::OP_RETURN as u8
    }

    /// Check if script is a witness program (v0-v16)
    pub fn is_witness_program(&self) -> bool {
        if self.0.len() < 4 || self.0.len() > 42 {
            return false;
        }

        let version = self.0[0];
        if version > (Opcodes::OP_16 as u8) && version < (Opcodes::OP_1 as u8) {
            return false;
        }

        let length = self.0[1] as usize;
        self.0.len() == length + 2
    }

    /// Get witness version (0-16) if this is a witness program
    pub fn witness_version(&self) -> Option<u8> {
        if !self.is_witness_program() {
            return None;
        }

        let version = self.0[0];
        if version == Opcodes::OP_0 as u8 {
            Some(0)
        } else if version >= (Opcodes::OP_1 as u8) && version <= (Opcodes::OP_16 as u8) {
            Some(version - (Opcodes::OP_1 as u8) + 1)
        } else {
            None
        }
    }

    /// Get witness program data if this is a witness program
    pub fn witness_program(&self) -> Option<&[u8]> {
        if !self.is_witness_program() {
            return None;
        }
        Some(&self.0[2..])
    }

    /// Parse script into opcodes and data
    pub fn instructions(&self) -> ScriptInstructions<'_> {
        ScriptInstructions {
            script: &self.0,
            position: 0,
        }
    }
}

impl Default for Script {
    fn default() -> Self {
        Script::new()
    }
}

impl fmt::Display for Script {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut result = String::new();
        for byte in &self.0 {
            if let Some(opcode) = Opcodes::from_u8(*byte) {
                result.push_str(&format!("{:?} ", opcode));
            } else {
                result.push_str(&format!("{:02x} ", byte));
            }
        }
        write!(f, "{}", result.trim())
    }
}

/// Iterator over script instructions
pub struct ScriptInstructions<'a> {
    script: &'a [u8],
    position: usize,
}

impl<'a> Iterator for ScriptInstructions<'a> {
    type Item = ScriptInstruction<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.position >= self.script.len() {
            return None;
        }

        let byte = self.script[self.position];
        self.position += 1;

        // Check for data push opcodes
        if byte <= Opcodes::OP_PUSHDATA4 as u8 && byte != Opcodes::OP_RESERVED as u8 {
            let data_len = match byte {
                0..=75 => byte as usize,
                0x4c => {
                    if self.position >= self.script.len() {
                        return None;
                    }
                    let len = self.script[self.position] as usize;
                    self.position += 1;
                    len
                }
                0x4d => {
                    if self.position + 1 >= self.script.len() {
                        return None;
                    }
                    let len = u16::from_le_bytes([
                        self.script[self.position],
                        self.script[self.position + 1],
                    ]) as usize;
                    self.position += 2;
                    len
                }
                0x4e => {
                    if self.position + 3 >= self.script.len() {
                        return None;
                    }
                    let len = u32::from_le_bytes([
                        self.script[self.position],
                        self.script[self.position + 1],
                        self.script[self.position + 2],
                        self.script[self.position + 3],
                    ]) as usize;
                    self.position += 4;
                    len
                }
                _ => return None,
            };

            if self.position + data_len > self.script.len() {
                return None;
            }

            let data = &self.script[self.position..self.position + data_len];
            self.position += data_len;
            Some(ScriptInstruction::Push(data))
        } else if let Some(opcode) = Opcodes::from_u8(byte) {
            Some(ScriptInstruction::Op(opcode))
        } else {
            Some(ScriptInstruction::Invalid(byte))
        }
    }
}

/// A single script instruction
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScriptInstruction<'a> {
    /// A data push
    Push(&'a [u8]),
    /// An opcode
    Op(Opcodes),
    /// Invalid opcode
    Invalid(u8),
}

/// Builder for constructing scripts
pub struct ScriptBuilder(Vec<u8>);

impl ScriptBuilder {
    /// Create a new script builder
    pub fn new() -> Self {
        ScriptBuilder(Vec::new())
    }

    /// Push an opcode
    pub fn push_opcode(mut self, opcode: Opcodes) -> Self {
        self.0.push(opcode as u8);
        self
    }

    /// Push data
    pub fn push_slice(mut self, data: &[u8]) -> Self {
        if data.len() <= 75 {
            self.0.push(data.len() as u8);
        } else if data.len() <= 0xffff {
            self.0.push(Opcodes::OP_PUSHDATA2 as u8);
            self.0.extend_from_slice(&(data.len() as u16).to_le_bytes());
        } else {
            self.0.push(Opcodes::OP_PUSHDATA4 as u8);
            self.0.extend_from_slice(&(data.len() as u32).to_le_bytes());
        }
        self.0.extend_from_slice(data);
        self
    }

    /// Push a byte
    pub fn push_byte(mut self, byte: u8) -> Self {
        self.0.push(1);
        self.0.push(byte);
        self
    }

    /// Push an integer
    pub fn push_int(self, value: i64) -> Self {
        match value {
            -1 => self.push_opcode(Opcodes::OP_1NEGATE),
            0 => self.push_opcode(Opcodes::OP_0),
            1 => self.push_opcode(Opcodes::OP_1),
            2 => self.push_opcode(Opcodes::OP_2),
            3 => self.push_opcode(Opcodes::OP_3),
            4 => self.push_opcode(Opcodes::OP_4),
            5 => self.push_opcode(Opcodes::OP_5),
            6 => self.push_opcode(Opcodes::OP_6),
            7 => self.push_opcode(Opcodes::OP_7),
            8 => self.push_opcode(Opcodes::OP_8),
            9 => self.push_opcode(Opcodes::OP_9),
            10 => self.push_opcode(Opcodes::OP_10),
            11 => self.push_opcode(Opcodes::OP_11),
            12 => self.push_opcode(Opcodes::OP_12),
            13 => self.push_opcode(Opcodes::OP_13),
            14 => self.push_opcode(Opcodes::OP_14),
            15 => self.push_opcode(Opcodes::OP_15),
            16 => self.push_opcode(Opcodes::OP_16),
            n => {
                let bytes = encode_number(n);
                self.push_slice(&bytes)
            }
        }
    }

    /// Build the script
    pub fn build(self) -> Script {
        Script(self.0)
    }
}

impl Default for ScriptBuilder {
    fn default() -> Self {
        ScriptBuilder::new()
    }
}

/// Encode a number for pushing onto the stack
fn encode_number(value: i64) -> Vec<u8> {
    let mut bytes = Vec::new();

    let negative = value < 0;
    let mut abs = if negative { -value } else { value } as u64;

    while abs > 0xff {
        bytes.push((abs & 0xff) as u8);
        abs >>= 8;
    }

    if abs & 0x80 != 0 {
        bytes.push((abs & 0xff) as u8);
        bytes.push(if negative { 0x80 } else { 0 });
    } else if negative {
        bytes.push(((abs & 0xff) as u8) | 0x80);
    } else {
        bytes.push((abs & 0xff) as u8);
    }

    bytes
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_script_creation() {
        let script = Script::new();
        assert!(script.is_empty());
    }

    #[test]
    fn test_script_p2pkh() {
        let mut script_bytes = vec![
            Opcodes::OP_DUP as u8,
            Opcodes::OP_HASH160 as u8,
            20,
        ];
        script_bytes.extend_from_slice(&[0u8; 20]);
        script_bytes.push(Opcodes::OP_EQUALVERIFY as u8);
        script_bytes.push(Opcodes::OP_CHECKSIG as u8);

        let script = Script::from_bytes(script_bytes);
        assert!(script.is_p2pkh());
    }

    #[test]
    fn test_script_builder() {
        let script = ScriptBuilder::new()
            .push_opcode(Opcodes::OP_DUP)
            .push_opcode(Opcodes::OP_HASH160)
            .push_int(1)
            .build();

        assert!(!script.is_empty());
    }

    #[test]
    fn test_op_return() {
        let script = ScriptBuilder::new()
            .push_opcode(Opcodes::OP_RETURN)
            .push_slice(b"hello")
            .build();

        assert!(script.is_op_return());
    }
}
