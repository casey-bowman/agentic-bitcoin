//! Bitcoin script opcodes
//!
//! Complete enumeration of all Bitcoin opcodes.

/// Bitcoin script opcodes
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[repr(u8)]
#[allow(non_camel_case_types)]
pub enum Opcodes {
    // Data push opcodes
    /// Push nothing
    OP_0 = 0x00,
    /// Push next byte as hex (reserved)
    OP_PUSHDATA1 = 0x4c,
    /// Push next 2 bytes as little-endian (reserved)
    OP_PUSHDATA2 = 0x4d,
    /// Push next 4 bytes as little-endian (reserved)
    OP_PUSHDATA4 = 0x4e,

    // Control flow
    /// Pop and skip next opcode if true
    OP_IF = 0x63,
    /// Pop and skip next opcode if false
    OP_NOTIF = 0x64,
    /// Skip to endif
    OP_ELSE = 0x67,
    /// End of if block
    OP_ENDIF = 0x68,
    /// Mark statement
    OP_VERIFY = 0x69,
    /// Halt and catch fire
    OP_RETURN = 0x6a,

    // Stack manipulation
    /// Move top item to altstack
    OP_TOALTSTACK = 0x6b,
    /// Move top altstack item to main stack
    OP_FROMALTSTACK = 0x6c,
    /// Duplicate top item
    OP_DUP = 0x76,
    /// Remove top item
    OP_DROP = 0x75,
    /// Copy item at depth n to top
    OP_PICK = 0x79,
    /// Remove item at depth n
    OP_ROLL = 0x7a,
    /// Remove top two items
    OP_2DROP = 0x6d,
    /// Duplicate top two items
    OP_2DUP = 0x6e,
    /// Duplicate top three items
    OP_3DUP = 0x6f,
    /// Copy top two items to top
    OP_2OVER = 0x70,
    /// Move top three items to top
    OP_2ROT = 0x71,
    /// Rotate stack
    OP_2SWAP = 0x72,
    /// Rotate stack right
    OP_ROT = 0x7b,
    /// Swap top two items
    OP_SWAP = 0x7c,
    /// Put top item at depth n
    OP_OVER = 0x78,
    /// Duplicate top item if nonzero
    OP_IFDUP = 0x73,
    /// Push number of items on stack
    OP_DEPTH = 0x74,
    /// Rotate stack left
    OP_NIP = 0x77,
    /// Reorder top four items
    OP_TUCK = 0x7d,

    // Arithmetic
    /// 1 + 1
    OP_1ADD = 0x8b,
    /// 1 - 1
    OP_1SUB = 0x8c,
    /// Multiply by 2
    OP_2MUL = 0x8d,
    /// Divide by 2
    OP_2DIV = 0x8e,
    /// Negate
    OP_NEGATE = 0x8f,
    /// Absolute value
    OP_ABS = 0x90,
    /// If zero pop 1 else pop 1
    OP_NOT = 0x91,
    /// If nonzero pop 1 else pop 1
    OP_0NOTEQUAL = 0x92,
    /// Add two numbers
    OP_ADD = 0x93,
    /// Subtract two numbers
    OP_SUB = 0x94,
    /// Multiply two numbers
    OP_MUL = 0x95,
    /// Divide two numbers
    OP_DIV = 0x96,
    /// Modulo operation
    OP_MOD = 0x97,
    /// Modulo remainder
    OP_LSHIFT = 0x98,
    /// Left shift
    OP_RSHIFT = 0x99,
    /// Right shift
    OP_BOOLAND = 0x9a,
    /// Boolean AND
    OP_BOOLOR = 0x9b,
    /// Boolean OR
    OP_EQUAL = 0x87,
    /// Check equality and verify
    OP_EQUALVERIFY = 0x88,
    /// Numbers equal
    OP_NUMEQUAL = 0x9c,
    /// Numbers equal
    OP_NUMEQUALVERIFY = 0x9d,
    /// Numbers equal and verify
    OP_NUMNOTEQUAL = 0x9e,
    /// Numbers not equal
    OP_LESSTHAN = 0x9f,
    /// Less than
    OP_GREATERTHAN = 0xa0,
    /// Greater than
    OP_LESSTHANOREQUAL = 0xa1,
    /// Less than or equal
    OP_GREATERTHANOREQUAL = 0xa2,
    /// Greater than or equal
    OP_MIN = 0xa3,
    /// Minimum value
    OP_MAX = 0xa4,
    /// Maximum value
    OP_WITHIN = 0xa5,
    /// Check if within range

    // Byte string
    /// Push string length
    OP_SIZE = 0x82,

    // Crypto
    /// RIPEMD-160 hash
    OP_RIPEMD160 = 0xa6,
    /// SHA-1 hash
    OP_SHA1 = 0xa7,
    /// SHA-256 hash
    OP_SHA256 = 0xa8,
    /// Double SHA-256 hash
    OP_HASH160 = 0xa9,
    /// SHA-256 then RIPEMD-160
    OP_HASH256 = 0xaa,
    /// Double SHA-256
    OP_CODESEPARATOR = 0xab,
    /// Code separator
    OP_CHECKSIG = 0xac,
    /// Check signature
    OP_CHECKSIGVERIFY = 0xad,
    /// Check signature and verify
    OP_CHECKMULTISIG = 0xae,
    /// Check multisig
    OP_CHECKMULTISIGVERIFY = 0xaf,
    /// Check multisig and verify

    // Constants/pseudo-opcodes
    /// Push the number -1
    OP_1NEGATE = 0x4f,
    /// Push the number 1
    OP_1 = 0x51,
    /// Push the number 2
    OP_2 = 0x52,
    /// Push the number 3
    OP_3 = 0x53,
    /// Push the number 4
    OP_4 = 0x54,
    /// Push the number 5
    OP_5 = 0x55,
    /// Push the number 6
    OP_6 = 0x56,
    /// Push the number 7
    OP_7 = 0x57,
    /// Push the number 8
    OP_8 = 0x58,
    /// Push the number 9
    OP_9 = 0x59,
    /// Push the number 10
    OP_10 = 0x5a,
    /// Push the number 11
    OP_11 = 0x5b,
    /// Push the number 12
    OP_12 = 0x5c,
    /// Push the number 13
    OP_13 = 0x5d,
    /// Push the number 14
    OP_14 = 0x5e,
    /// Push the number 15
    OP_15 = 0x5f,
    /// Push the number 16
    OP_16 = 0x60,

    // Reserved
    /// Reserved
    OP_RESERVED = 0x50,
    /// Reserved
    OP_VER = 0x62,
    /// Reserved
    OP_VERIF = 0x65,
    /// Reserved
    OP_VERNOTIF = 0x66,
    /// Reserved
    OP_RESERVED1 = 0x89,
    /// Reserved
    OP_RESERVED2 = 0x8a,
    /// Reserved
    OP_NOP1 = 0xb0,
    /// Reserved (was NOP1)
    OP_CHECKLOCKTIMEVERIFY = 0xb1,
    /// Check locktime (BIP65)
    OP_CHECKSEQUENCEVERIFY = 0xb2,
    /// Check sequence (BIP112)

    // NOPs
    /// No operation
    OP_NOP = 0x61,
    /// No operation
    OP_NOP4 = 0xb3,
    /// No operation
    OP_NOP5 = 0xb4,
    /// No operation
    OP_NOP6 = 0xb5,
    /// No operation
    OP_NOP7 = 0xb6,
    /// No operation
    OP_NOP8 = 0xb7,
    /// No operation
    OP_NOP9 = 0xb8,
    /// No operation
    OP_NOP10 = 0xb9,

    /// Invalid opcode
    OP_INVALIDOPCODE = 0xff,
}

impl Opcodes {
    /// Convert byte to opcode
    pub fn from_u8(byte: u8) -> Option<Self> {
        match byte {
            0x00 => Some(Opcodes::OP_0),
            0x4c => Some(Opcodes::OP_PUSHDATA1),
            0x4d => Some(Opcodes::OP_PUSHDATA2),
            0x4e => Some(Opcodes::OP_PUSHDATA4),
            0x4f => Some(Opcodes::OP_1NEGATE),
            0x50 => Some(Opcodes::OP_RESERVED),
            0x51 => Some(Opcodes::OP_1),
            0x52 => Some(Opcodes::OP_2),
            0x53 => Some(Opcodes::OP_3),
            0x54 => Some(Opcodes::OP_4),
            0x55 => Some(Opcodes::OP_5),
            0x56 => Some(Opcodes::OP_6),
            0x57 => Some(Opcodes::OP_7),
            0x58 => Some(Opcodes::OP_8),
            0x59 => Some(Opcodes::OP_9),
            0x5a => Some(Opcodes::OP_10),
            0x5b => Some(Opcodes::OP_11),
            0x5c => Some(Opcodes::OP_12),
            0x5d => Some(Opcodes::OP_13),
            0x5e => Some(Opcodes::OP_14),
            0x5f => Some(Opcodes::OP_15),
            0x60 => Some(Opcodes::OP_16),
            0x61 => Some(Opcodes::OP_NOP),
            0x62 => Some(Opcodes::OP_VER),
            0x63 => Some(Opcodes::OP_IF),
            0x64 => Some(Opcodes::OP_NOTIF),
            0x65 => Some(Opcodes::OP_VERIF),
            0x66 => Some(Opcodes::OP_VERNOTIF),
            0x67 => Some(Opcodes::OP_ELSE),
            0x68 => Some(Opcodes::OP_ENDIF),
            0x69 => Some(Opcodes::OP_VERIFY),
            0x6a => Some(Opcodes::OP_RETURN),
            0x6b => Some(Opcodes::OP_TOALTSTACK),
            0x6c => Some(Opcodes::OP_FROMALTSTACK),
            0x6d => Some(Opcodes::OP_2DROP),
            0x6e => Some(Opcodes::OP_2DUP),
            0x6f => Some(Opcodes::OP_3DUP),
            0x70 => Some(Opcodes::OP_2OVER),
            0x71 => Some(Opcodes::OP_2ROT),
            0x72 => Some(Opcodes::OP_2SWAP),
            0x73 => Some(Opcodes::OP_IFDUP),
            0x74 => Some(Opcodes::OP_DEPTH),
            0x75 => Some(Opcodes::OP_DROP),
            0x76 => Some(Opcodes::OP_DUP),
            0x77 => Some(Opcodes::OP_NIP),
            0x78 => Some(Opcodes::OP_OVER),
            0x79 => Some(Opcodes::OP_PICK),
            0x7a => Some(Opcodes::OP_ROLL),
            0x7b => Some(Opcodes::OP_ROT),
            0x7c => Some(Opcodes::OP_SWAP),
            0x7d => Some(Opcodes::OP_TUCK),
            0x82 => Some(Opcodes::OP_SIZE),
            0x8b => Some(Opcodes::OP_1ADD),
            0x8c => Some(Opcodes::OP_1SUB),
            0x8d => Some(Opcodes::OP_2MUL),
            0x8e => Some(Opcodes::OP_2DIV),
            0x8f => Some(Opcodes::OP_NEGATE),
            0x90 => Some(Opcodes::OP_ABS),
            0x91 => Some(Opcodes::OP_NOT),
            0x92 => Some(Opcodes::OP_0NOTEQUAL),
            0x93 => Some(Opcodes::OP_ADD),
            0x94 => Some(Opcodes::OP_SUB),
            0x95 => Some(Opcodes::OP_MUL),
            0x96 => Some(Opcodes::OP_DIV),
            0x97 => Some(Opcodes::OP_MOD),
            0x98 => Some(Opcodes::OP_LSHIFT),
            0x99 => Some(Opcodes::OP_RSHIFT),
            0x9a => Some(Opcodes::OP_BOOLAND),
            0x9b => Some(Opcodes::OP_BOOLOR),
            0x9c => Some(Opcodes::OP_NUMEQUAL),
            0x9d => Some(Opcodes::OP_NUMEQUALVERIFY),
            0x9e => Some(Opcodes::OP_NUMNOTEQUAL),
            0x9f => Some(Opcodes::OP_LESSTHAN),
            0xa0 => Some(Opcodes::OP_GREATERTHAN),
            0xa1 => Some(Opcodes::OP_LESSTHANOREQUAL),
            0xa2 => Some(Opcodes::OP_GREATERTHANOREQUAL),
            0xa3 => Some(Opcodes::OP_MIN),
            0xa4 => Some(Opcodes::OP_MAX),
            0xa5 => Some(Opcodes::OP_WITHIN),
            0xa6 => Some(Opcodes::OP_RIPEMD160),
            0xa7 => Some(Opcodes::OP_SHA1),
            0xa8 => Some(Opcodes::OP_SHA256),
            0xa9 => Some(Opcodes::OP_HASH160),
            0xaa => Some(Opcodes::OP_HASH256),
            0xab => Some(Opcodes::OP_CODESEPARATOR),
            0xac => Some(Opcodes::OP_CHECKSIG),
            0xad => Some(Opcodes::OP_CHECKSIGVERIFY),
            0xae => Some(Opcodes::OP_CHECKMULTISIG),
            0xaf => Some(Opcodes::OP_CHECKMULTISIGVERIFY),
            0x87 => Some(Opcodes::OP_EQUAL),
            0x88 => Some(Opcodes::OP_EQUALVERIFY),
            0x89 => Some(Opcodes::OP_RESERVED1),
            0x8a => Some(Opcodes::OP_RESERVED2),
            0xb0 => Some(Opcodes::OP_NOP1),
            0xb1 => Some(Opcodes::OP_CHECKLOCKTIMEVERIFY),
            0xb2 => Some(Opcodes::OP_CHECKSEQUENCEVERIFY),
            0xb3 => Some(Opcodes::OP_NOP4),
            0xb4 => Some(Opcodes::OP_NOP5),
            0xb5 => Some(Opcodes::OP_NOP6),
            0xb6 => Some(Opcodes::OP_NOP7),
            0xb7 => Some(Opcodes::OP_NOP8),
            0xb8 => Some(Opcodes::OP_NOP9),
            0xb9 => Some(Opcodes::OP_NOP10),
            0xff => Some(Opcodes::OP_INVALIDOPCODE),
            _ => None,
        }
    }

    /// Get the byte value of this opcode
    pub fn to_u8(self) -> u8 {
        self as u8
    }

    /// OP_NOP2 is an alias for OP_CHECKLOCKTIMEVERIFY (BIP65)
    pub const OP_NOP2: Self = Self::OP_CHECKLOCKTIMEVERIFY;

    /// OP_NOP3 is an alias for OP_CHECKSEQUENCEVERIFY (BIP112)
    pub const OP_NOP3: Self = Self::OP_CHECKSEQUENCEVERIFY;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_opcode_from_u8() {
        assert_eq!(Opcodes::from_u8(0x00), Some(Opcodes::OP_0));
        assert_eq!(Opcodes::from_u8(0x51), Some(Opcodes::OP_1));
        assert_eq!(Opcodes::from_u8(0xac), Some(Opcodes::OP_CHECKSIG));
    }

    #[test]
    fn test_opcode_to_u8() {
        assert_eq!(Opcodes::OP_0.to_u8(), 0x00);
        assert_eq!(Opcodes::OP_CHECKSIG.to_u8(), 0xac);
    }

    #[test]
    fn test_invalid_opcode() {
        assert_eq!(Opcodes::from_u8(0xfe), None);
    }
}
