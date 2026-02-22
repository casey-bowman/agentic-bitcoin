// Miniscript decoder — Bitcoin Script → Miniscript AST
//
// Parses raw Bitcoin Script bytes back into a Miniscript AST by
// pattern-matching opcode sequences.  This is essentially the inverse
// of `compiler.rs`.
//
// The decoder works by maintaining a cursor into the script bytes and
// recursively recognizing fragment patterns.
//
// Reference: https://bitcoin.sipa.be/miniscript/

use std::fmt;

use super::fragment::Miniscript;
use crate::script::opcodes::Opcodes;
use crate::script::script::Script;
use crate::wallet::keys::PublicKey;

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Errors that can occur during miniscript decoding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecodeError {
    /// Unexpected end of script.
    UnexpectedEnd,
    /// Unrecognized opcode pattern.
    UnexpectedOpcode(u8),
    /// Expected a specific opcode but found another.
    Expected { expected: u8, found: u8 },
    /// Invalid public key data.
    InvalidKey,
    /// Invalid integer encoding.
    InvalidInteger,
    /// Type-check failed after parsing.
    TypeCheckFailed(String),
    /// Trailing bytes after a complete expression.
    TrailingBytes(usize),
    /// Invalid multi threshold.
    InvalidThreshold,
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DecodeError::UnexpectedEnd => write!(f, "unexpected end of script"),
            DecodeError::UnexpectedOpcode(b) => write!(f, "unexpected opcode: 0x{:02x}", b),
            DecodeError::Expected { expected, found } => {
                write!(f, "expected 0x{:02x}, found 0x{:02x}", expected, found)
            }
            DecodeError::InvalidKey => write!(f, "invalid public key"),
            DecodeError::InvalidInteger => write!(f, "invalid integer encoding"),
            DecodeError::TypeCheckFailed(msg) => write!(f, "type check failed: {}", msg),
            DecodeError::TrailingBytes(n) => write!(f, "{} trailing bytes", n),
            DecodeError::InvalidThreshold => write!(f, "invalid threshold"),
        }
    }
}

impl std::error::Error for DecodeError {}

// ---------------------------------------------------------------------------
// Cursor — byte-level reader over script bytes
// ---------------------------------------------------------------------------

struct Cursor<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, pos: 0 }
    }

    fn remaining(&self) -> usize {
        self.bytes.len() - self.pos
    }

    fn is_empty(&self) -> bool {
        self.pos >= self.bytes.len()
    }

    fn peek(&self) -> Result<u8, DecodeError> {
        if self.pos < self.bytes.len() {
            Ok(self.bytes[self.pos])
        } else {
            Err(DecodeError::UnexpectedEnd)
        }
    }

    fn read_byte(&mut self) -> Result<u8, DecodeError> {
        if self.pos < self.bytes.len() {
            let b = self.bytes[self.pos];
            self.pos += 1;
            Ok(b)
        } else {
            Err(DecodeError::UnexpectedEnd)
        }
    }

    fn read_bytes(&mut self, n: usize) -> Result<&'a [u8], DecodeError> {
        if self.pos + n <= self.bytes.len() {
            let slice = &self.bytes[self.pos..self.pos + n];
            self.pos += n;
            Ok(slice)
        } else {
            Err(DecodeError::UnexpectedEnd)
        }
    }

    fn expect(&mut self, expected: u8) -> Result<(), DecodeError> {
        let found = self.read_byte()?;
        if found == expected {
            Ok(())
        } else {
            Err(DecodeError::Expected { expected, found })
        }
    }

    /// Save the current position for backtracking.
    fn save(&self) -> usize {
        self.pos
    }

    /// Restore a previously saved position.
    fn restore(&mut self, pos: usize) {
        self.pos = pos;
    }
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

impl Miniscript {
    /// Parse a Bitcoin Script into a Miniscript expression.
    ///
    /// Returns an error if the script does not represent a valid miniscript.
    pub fn parse(script: &Script) -> Result<Self, DecodeError> {
        let bytes = script.as_bytes();
        let mut cursor = Cursor::new(bytes);
        let ms = decode_expression(&mut cursor)?;
        if !cursor.is_empty() {
            return Err(DecodeError::TrailingBytes(cursor.remaining()));
        }
        Ok(ms)
    }
}

// ---------------------------------------------------------------------------
// Internal decoder
// ---------------------------------------------------------------------------

/// Read a data push and return the pushed bytes.
/// Handles OP_0..OP_16 as special push opcodes, and standard length prefixes.
fn read_push(cursor: &mut Cursor) -> Result<Vec<u8>, DecodeError> {
    let first = cursor.read_byte()?;
    match first {
        // Direct push: 1..75 bytes
        1..=75 => {
            let data = cursor.read_bytes(first as usize)?;
            Ok(data.to_vec())
        }
        // OP_PUSHDATA1
        0x4c => {
            let len = cursor.read_byte()? as usize;
            let data = cursor.read_bytes(len)?;
            Ok(data.to_vec())
        }
        // OP_PUSHDATA2
        0x4d => {
            let lo = cursor.read_byte()? as usize;
            let hi = cursor.read_byte()? as usize;
            let len = lo | (hi << 8);
            let data = cursor.read_bytes(len)?;
            Ok(data.to_vec())
        }
        _ => Err(DecodeError::UnexpectedOpcode(first)),
    }
}

/// Read a push and interpret it as a CScript number (i64).
fn read_push_num(cursor: &mut Cursor) -> Result<i64, DecodeError> {
    let save = cursor.save();
    let first = cursor.peek()?;

    // OP_0 = 0
    if first == 0x00 {
        cursor.read_byte()?;
        return Ok(0);
    }
    // OP_1NEGATE = -1
    if first == 0x4f {
        cursor.read_byte()?;
        return Ok(-1);
    }
    // OP_1 through OP_16
    if (0x51..=0x60).contains(&first) {
        cursor.read_byte()?;
        return Ok((first - 0x50) as i64);
    }

    // Otherwise it's a data push encoding a number
    cursor.restore(save);
    let data = read_push(cursor)?;
    Ok(decode_script_num(&data))
}

/// Decode a CScript number from its byte representation.
fn decode_script_num(bytes: &[u8]) -> i64 {
    if bytes.is_empty() {
        return 0;
    }
    let mut result: i64 = 0;
    for (i, &b) in bytes.iter().enumerate() {
        result |= (b as i64) << (8 * i);
    }
    // Sign bit is the highest bit of the last byte
    if bytes.last().unwrap() & 0x80 != 0 {
        result &= !(0x80i64 << (8 * (bytes.len() - 1)));
        result = -result;
    }
    result
}

/// Try to read a 33-byte compressed public key.
fn _read_pubkey(cursor: &mut Cursor) -> Result<PublicKey, DecodeError> {
    let data = read_push(cursor)?;
    if data.len() != 33 {
        return Err(DecodeError::InvalidKey);
    }
    PublicKey::from_bytes(&data).map_err(|_| DecodeError::InvalidKey)
}

/// Decode one complete miniscript expression from the cursor.
fn decode_expression(cursor: &mut Cursor) -> Result<Miniscript, DecodeError> {
    if cursor.is_empty() {
        return Err(DecodeError::UnexpectedEnd);
    }

    let _save = cursor.save();
    let first = cursor.peek()?;

    match first {
        // OP_1 → True, or multi(1, ...) if followed by a key push
        0x51 => {
            cursor.read_byte()?; // consume OP_1
                                 // Check if this is the start of multi(1, ...): OP_1 <key1> ...
            if !cursor.is_empty() {
                let peek = cursor.peek()?;
                if peek == 0x21 {
                    // 0x21 = push 33 bytes (compressed pubkey) — likely multi
                    let multi_save = cursor.save();
                    match try_decode_multi(cursor, 1) {
                        Ok(ms) => return Ok(ms),
                        Err(_) => cursor.restore(multi_save),
                    }
                }
            }
            Ok(Miniscript::ms_true())
        }

        // OP_0 → False  (but also could be multi dummy — context dependent)
        0x00 => {
            cursor.read_byte()?;
            Ok(Miniscript::ms_false())
        }

        // OP_IF → or_i(X, Y)
        0x63 => {
            cursor.read_byte()?; // consume OP_IF
            let x = decode_expression(cursor)?;
            cursor.expect(Opcodes::OP_ELSE as u8)?;
            let y = decode_expression(cursor)?;
            cursor.expect(Opcodes::OP_ENDIF as u8)?;
            Ok(Miniscript::or_i(x, y))
        }

        // OP_DUP → either pk_h or d: wrapper
        0x76 => {
            cursor.read_byte()?; // consume OP_DUP
            let next = cursor.peek()?;
            if next == Opcodes::OP_HASH160 as u8 {
                // pk_h: OP_DUP OP_HASH160 <20> <hash> OP_EQUALVERIFY
                cursor.read_byte()?; // OP_HASH160
                let hash_data = read_push(cursor)?;
                if hash_data.len() != 20 {
                    return Err(DecodeError::InvalidKey);
                }
                cursor.expect(Opcodes::OP_EQUALVERIFY as u8)?;
                let mut hash = [0u8; 20];
                hash.copy_from_slice(&hash_data);
                Ok(Miniscript::pk_h(hash))
            } else if next == Opcodes::OP_IF as u8 {
                // d:X → OP_DUP OP_IF [X] OP_ENDIF
                cursor.read_byte()?; // OP_IF
                let inner = decode_expression(cursor)?;
                cursor.expect(Opcodes::OP_ENDIF as u8)?;
                Ok(Miniscript::dupif(inner))
            } else {
                Err(DecodeError::UnexpectedOpcode(next))
            }
        }

        // OP_TOALTSTACK → a:X wrapper
        0x6b => {
            cursor.read_byte()?; // consume OP_TOALTSTACK
            let inner = decode_expression(cursor)?;
            cursor.expect(Opcodes::OP_FROMALTSTACK as u8)?;
            Ok(Miniscript::alt(inner))
        }

        // OP_SWAP → s:X wrapper
        0x7c => {
            cursor.read_byte()?; // consume OP_SWAP
            let inner = decode_expression(cursor)?;
            Ok(Miniscript::swap(inner))
        }

        // OP_SIZE → either j:X wrapper or hash preimage check
        0x82 => {
            cursor.read_byte()?; // consume OP_SIZE
            let next = cursor.peek()?;

            if next == Opcodes::OP_0NOTEQUAL as u8 {
                // j:X → OP_SIZE OP_0NOTEQUAL OP_IF [X] OP_ENDIF
                cursor.read_byte()?; // OP_0NOTEQUAL
                cursor.expect(Opcodes::OP_IF as u8)?;
                let inner = decode_expression(cursor)?;
                cursor.expect(Opcodes::OP_ENDIF as u8)?;
                Ok(Miniscript::nonzero(inner))
            } else {
                // Hash preimage: OP_SIZE <32> OP_EQUALVERIFY <hash_op> <hash> OP_EQUAL
                let size_val = read_push_num(cursor)?;
                if size_val != 32 {
                    return Err(DecodeError::UnexpectedOpcode(0x82));
                }
                cursor.expect(Opcodes::OP_EQUALVERIFY as u8)?;
                let hash_op = cursor.read_byte()?;
                match hash_op {
                    0xa8 => {
                        // OP_SHA256
                        let hash_data = read_push(cursor)?;
                        if hash_data.len() != 32 {
                            return Err(DecodeError::InvalidInteger);
                        }
                        cursor.expect(Opcodes::OP_EQUAL as u8)?;
                        let mut hash = [0u8; 32];
                        hash.copy_from_slice(&hash_data);
                        Ok(Miniscript::sha256(hash))
                    }
                    0xaa => {
                        // OP_HASH256
                        let hash_data = read_push(cursor)?;
                        if hash_data.len() != 32 {
                            return Err(DecodeError::InvalidInteger);
                        }
                        cursor.expect(Opcodes::OP_EQUAL as u8)?;
                        let mut hash = [0u8; 32];
                        hash.copy_from_slice(&hash_data);
                        Ok(Miniscript::hash256(hash))
                    }
                    0xa6 => {
                        // OP_RIPEMD160
                        let hash_data = read_push(cursor)?;
                        if hash_data.len() != 20 {
                            return Err(DecodeError::InvalidInteger);
                        }
                        cursor.expect(Opcodes::OP_EQUAL as u8)?;
                        let mut hash = [0u8; 20];
                        hash.copy_from_slice(&hash_data);
                        Ok(Miniscript::ripemd160(hash))
                    }
                    0xa9 => {
                        // OP_HASH160
                        let hash_data = read_push(cursor)?;
                        if hash_data.len() != 20 {
                            return Err(DecodeError::InvalidInteger);
                        }
                        cursor.expect(Opcodes::OP_EQUAL as u8)?;
                        let mut hash = [0u8; 20];
                        hash.copy_from_slice(&hash_data);
                        Ok(Miniscript::hash160(hash))
                    }
                    _ => Err(DecodeError::UnexpectedOpcode(hash_op)),
                }
            }
        }

        // Data push (1..75 bytes, or OP_1..OP_16) → could be:
        //   - <key> followed by OP_CHECKSIG → pk_k then potentially c: or multi_a
        //   - <n> followed by OP_CSV/CLTV → older/after
        //   - <k> followed by keys → multi(k, ...)
        _ => decode_push_start(cursor),
    }
}

/// Decode an expression that starts with a data push.
/// This handles pk_k, older, after, multi, and multi_a.
fn decode_push_start(cursor: &mut Cursor) -> Result<Miniscript, DecodeError> {
    let save = cursor.save();

    // Try to read a push
    let data = match read_push(cursor) {
        Ok(d) => d,
        Err(_) => {
            cursor.restore(save);
            return Err(DecodeError::UnexpectedOpcode(cursor.peek().unwrap_or(0)));
        }
    };

    if cursor.is_empty() {
        // Just a data push with nothing after it — could be a raw key (pk_k)
        if data.len() == 33 {
            let key = PublicKey::from_bytes(&data).map_err(|_| DecodeError::InvalidKey)?;
            return Ok(Miniscript::pk_k(key));
        }
        cursor.restore(save);
        return Err(DecodeError::UnexpectedEnd);
    }

    let next = cursor.peek()?;

    // 33-byte push followed by OP_CHECKSIG → c:pk_k(key) = pk(key)
    if data.len() == 33 && next == Opcodes::OP_CHECKSIG as u8 {
        let key = PublicKey::from_bytes(&data).map_err(|_| DecodeError::InvalidKey)?;
        cursor.read_byte()?; // consume OP_CHECKSIG

        // Check what follows — could be part of a larger expression
        if !cursor.is_empty() {
            let _after = cursor.peek()?;
            // OP_CHECKSIGADD → this is part of multi_a
            // Actually we don't get here for multi_a — multi_a's first key
            // uses OP_CHECKSIG, rest use OP_CHECKSIGADD
            // Return as pk(key) = c:pk_k(key)
        }
        return Ok(Miniscript::pk(key));
    }

    // 33-byte push followed by OP_CHECKSIGVERIFY → v:c:pk_k(key)
    if data.len() == 33 && next == Opcodes::OP_CHECKSIGVERIFY as u8 {
        let key = PublicKey::from_bytes(&data).map_err(|_| DecodeError::InvalidKey)?;
        cursor.read_byte()?; // consume OP_CHECKSIGVERIFY
        return Ok(Miniscript::verify(Miniscript::pk(key)));
    }

    // 33-byte push (just a key) — pk_k
    if data.len() == 33 {
        let key = PublicKey::from_bytes(&data).map_err(|_| DecodeError::InvalidKey)?;
        return Ok(Miniscript::pk_k(key));
    }

    // Numeric push followed by OP_CHECKSEQUENCEVERIFY → older(n)
    if next == Opcodes::OP_CHECKSEQUENCEVERIFY as u8 {
        let n = decode_script_num(&data);
        if n <= 0 || n > i64::from(u32::MAX >> 1) {
            return Err(DecodeError::InvalidInteger);
        }
        cursor.read_byte()?; // consume OP_CSV
        return Ok(Miniscript::older(n as u32));
    }

    // Numeric push followed by OP_CHECKLOCKTIMEVERIFY → after(n)
    if next == Opcodes::OP_CHECKLOCKTIMEVERIFY as u8 {
        let n = decode_script_num(&data);
        if n <= 0 || n > 500_000_000 {
            return Err(DecodeError::InvalidInteger);
        }
        cursor.read_byte()?; // consume OP_CLTV
        return Ok(Miniscript::after(n as u32));
    }

    // Numeric push followed by key pushes → multi(k, keys...)
    // or OP_1..OP_16 already consumed as data
    if next > 0 && next <= 75 || (0x51..=0x60).contains(&next) {
        // This might be multi: <k> <key1> ... <keyn> <n> OP_CHECKMULTISIG
        let k = decode_script_num(&data);
        if k >= 1 {
            let multi_save = cursor.save();
            match try_decode_multi(cursor, k as usize) {
                Ok(ms) => return Ok(ms),
                Err(_) => cursor.restore(multi_save),
            }
        }
    }

    cursor.restore(save);
    Err(DecodeError::UnexpectedOpcode(cursor.peek().unwrap_or(0)))
}

/// Try to decode a multi(k, keys) assuming k has already been read.
fn try_decode_multi(cursor: &mut Cursor, k: usize) -> Result<Miniscript, DecodeError> {
    let mut keys = Vec::new();
    loop {
        let save = cursor.save();
        // Try reading a 33-byte key
        match read_push(cursor) {
            Ok(data) if data.len() == 33 => {
                let key = PublicKey::from_bytes(&data).map_err(|_| DecodeError::InvalidKey)?;
                keys.push(key);
            }
            _ => {
                cursor.restore(save);
                break;
            }
        }
    }

    if keys.is_empty() {
        return Err(DecodeError::InvalidThreshold);
    }

    // Read n
    let n = read_push_num(cursor)?;
    if n as usize != keys.len() {
        return Err(DecodeError::InvalidThreshold);
    }

    // Expect OP_CHECKMULTISIG
    let op = cursor.read_byte()?;
    if op == Opcodes::OP_CHECKMULTISIG as u8 {
        if k > keys.len() || k == 0 {
            return Err(DecodeError::InvalidThreshold);
        }
        Ok(Miniscript::multi(k, keys))
    } else if op == Opcodes::OP_CHECKMULTISIGVERIFY as u8 {
        if k > keys.len() || k == 0 {
            return Err(DecodeError::InvalidThreshold);
        }
        Ok(Miniscript::verify(Miniscript::multi(k, keys)))
    } else {
        Err(DecodeError::Expected {
            expected: Opcodes::OP_CHECKMULTISIG as u8,
            found: op,
        })
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::super::fragment::Terminal;
    use super::*;
    use crate::wallet::keys::PublicKey;

    fn dummy_key(seed: u8) -> PublicKey {
        use crate::crypto::hashing::sha256;
        let hash = sha256(&[seed]);
        let mut secret = [0u8; 32];
        secret.copy_from_slice(hash.as_bytes());
        secret[0] = seed.wrapping_add(1).max(1);
        let secp = secp256k1::Secp256k1::new();
        let sk = secp256k1::SecretKey::from_slice(&secret).unwrap();
        let pk = secp256k1::PublicKey::from_secret_key(&secp, &sk);
        PublicKey::from_bytes(&pk.serialize()).unwrap()
    }

    // ── Roundtrip tests: construct → encode → parse → compare ─────

    #[test]
    fn test_roundtrip_true() {
        let ms = Miniscript::ms_true();
        let script = ms.encode();
        let parsed = Miniscript::parse(&script).unwrap();
        assert_eq!(ms.node, parsed.node);
    }

    #[test]
    fn test_roundtrip_false() {
        let ms = Miniscript::ms_false();
        let script = ms.encode();
        let parsed = Miniscript::parse(&script).unwrap();
        assert_eq!(ms.node, parsed.node);
    }

    #[test]
    fn test_roundtrip_pk() {
        // pk(key) = c:pk_k(key)
        let key = dummy_key(1);
        let ms = Miniscript::pk(key);
        let script = ms.encode();
        let parsed = Miniscript::parse(&script).unwrap();
        // parsed should be pk(key) — same structure
        match &parsed.node {
            Terminal::Check(inner) => match &inner.node {
                Terminal::PkK(k) => assert_eq!(k, &dummy_key(1)),
                other => panic!("expected PkK, got {:?}", other),
            },
            other => panic!("expected Check, got {:?}", other),
        }
    }

    #[test]
    fn test_roundtrip_pk_h() {
        let hash = [0xab; 20];
        let ms = Miniscript::pk_h(hash);
        let script = ms.encode();
        let parsed = Miniscript::parse(&script).unwrap();
        match &parsed.node {
            Terminal::PkH(h) => assert_eq!(h, &hash),
            other => panic!("expected PkH, got {:?}", other),
        }
    }

    #[test]
    fn test_roundtrip_sha256() {
        let hash = [0x11; 32];
        let ms = Miniscript::sha256(hash);
        let script = ms.encode();
        let parsed = Miniscript::parse(&script).unwrap();
        match &parsed.node {
            Terminal::Sha256(h) => assert_eq!(h, &hash),
            other => panic!("expected Sha256, got {:?}", other),
        }
    }

    #[test]
    fn test_roundtrip_hash256() {
        let hash = [0x22; 32];
        let ms = Miniscript::hash256(hash);
        let script = ms.encode();
        let parsed = Miniscript::parse(&script).unwrap();
        match &parsed.node {
            Terminal::Hash256(h) => assert_eq!(h, &hash),
            other => panic!("expected Hash256, got {:?}", other),
        }
    }

    #[test]
    fn test_roundtrip_ripemd160() {
        let hash = [0x33; 20];
        let ms = Miniscript::ripemd160(hash);
        let script = ms.encode();
        let parsed = Miniscript::parse(&script).unwrap();
        match &parsed.node {
            Terminal::Ripemd160(h) => assert_eq!(h, &hash),
            other => panic!("expected Ripemd160, got {:?}", other),
        }
    }

    #[test]
    fn test_roundtrip_hash160() {
        let hash = [0x44; 20];
        let ms = Miniscript::hash160(hash);
        let script = ms.encode();
        let parsed = Miniscript::parse(&script).unwrap();
        match &parsed.node {
            Terminal::Hash160(h) => assert_eq!(h, &hash),
            other => panic!("expected Hash160, got {:?}", other),
        }
    }

    #[test]
    fn test_roundtrip_or_i() {
        let k1 = dummy_key(10);
        let k2 = dummy_key(11);
        let ms = Miniscript::or_i(Miniscript::pk(k1), Miniscript::pk(k2));
        let script = ms.encode();
        let parsed = Miniscript::parse(&script).unwrap();
        match &parsed.node {
            Terminal::OrI(_, _) => {} // correct structure
            other => panic!("expected OrI, got {:?}", other),
        }
    }

    #[test]
    fn test_roundtrip_multi() {
        let keys = vec![dummy_key(20), dummy_key(21)];
        let ms = Miniscript::multi(1, keys);
        let script = ms.encode();
        let parsed = Miniscript::parse(&script).unwrap();
        match &parsed.node {
            Terminal::Multi(k, ks) => {
                assert_eq!(*k, 1);
                assert_eq!(ks.len(), 2);
            }
            other => panic!("expected Multi, got {:?}", other),
        }
    }

    #[test]
    fn test_decode_error_empty() {
        let script = Script::new();
        let result = Miniscript::parse(&script);
        assert!(result.is_err());
    }

    #[test]
    fn test_decode_error_trailing() {
        // OP_1 OP_1 — the second OP_1 is trailing
        let script = Script::from_bytes(vec![0x51, 0x51]);
        let result = Miniscript::parse(&script);
        assert!(matches!(result, Err(DecodeError::TrailingBytes(_))));
    }

    #[test]
    fn test_decode_script_num() {
        assert_eq!(decode_script_num(&[]), 0);
        assert_eq!(decode_script_num(&[5]), 5);
        assert_eq!(decode_script_num(&[0x90, 0x00]), 144); // 144 in little-endian
        assert_eq!(decode_script_num(&[0x85]), -5); // 0x80 | 5 = negative 5
    }
}
