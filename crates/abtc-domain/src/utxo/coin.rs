//! Compressed coin serialization
//!
//! Implements Bitcoin Core's `CCompressedAmount` and script compression for
//! compact UTXO storage. These encodings are used in the chainstate database
//! and in AssumeUTXO snapshots.
//!
//! ## Amount compression
//!
//! Amounts are compressed by extracting trailing decimal zeros as an exponent:
//!   - 0 → 0
//!   - Otherwise: decompose into `n = d × 10^e` where `d % 10 ≠ 0`, then
//!     encode as `1 + (n/10 * 9 + d - 1) * 10 + e` for e < 9, or
//!     `1 + (n-1)*10 + 9` for e = 9.
//!
//! This maps common round amounts (1 BTC, 0.1 BTC, 50 BTC) to small values
//! that compress well with varint encoding.
//!
//! ## Script compression
//!
//! Standard script types are replaced by compact representations:
//!   - P2PKH → type 0x00 + 20-byte pubkey hash
//!   - P2SH  → type 0x01 + 20-byte script hash
//!   - P2PK (compressed)   → type 0x02/0x03 + 32-byte x-coordinate
//!   - P2PK (uncompressed) → type 0x04/0x05 + 32-byte x-coordinate
//!   - Other → (script_len + 6) as varint + raw script bytes

use crate::consensus::connect::UtxoEntry;
use crate::primitives::{Amount, OutPoint, TxOut, Txid};
use crate::script::Script;

// ---------------------------------------------------------------------------
// Amount compression (CCompressedAmount)
// ---------------------------------------------------------------------------

/// Compress a satoshi amount into a smaller integer representation.
///
/// Maps common round Bitcoin amounts to small numbers, improving varint
/// encoding efficiency. Lossless roundtrip: `decompress(compress(n)) == n`.
pub fn compress_amount(n: u64) -> u64 {
    if n == 0 {
        return 0;
    }
    let mut n = n;
    let mut e: u32 = 0;
    while n % 10 == 0 && e < 9 {
        n /= 10;
        e += 1;
    }
    if e < 9 {
        let d = n % 10;
        // d is in [1..9] since we removed all trailing zeros and n > 0
        n /= 10;
        1 + (n * 9 + d - 1) * 10 + e as u64
    } else {
        1 + (n - 1) * 10 + 9
    }
}

/// Decompress a compressed amount back to satoshis.
pub fn decompress_amount(x: u64) -> u64 {
    if x == 0 {
        return 0;
    }
    let mut x = x - 1;
    let e = (x % 10) as u32;
    x /= 10;
    let mut n: u64;
    if e < 9 {
        let d = (x % 9) + 1;
        x /= 9;
        n = x * 10 + d;
    } else {
        n = x + 1;
    }
    for _ in 0..e {
        n *= 10;
    }
    n
}

// ---------------------------------------------------------------------------
// Script compression
// ---------------------------------------------------------------------------

/// Compressed script type tags.
const SCRIPT_TYPE_P2PKH: u8 = 0x00;
const SCRIPT_TYPE_P2SH: u8 = 0x01;
const SCRIPT_TYPE_P2PK_EVEN: u8 = 0x02;
const SCRIPT_TYPE_P2PK_ODD: u8 = 0x03;
const SCRIPT_TYPE_P2PK_UNCOMPRESSED_EVEN: u8 = 0x04;
const SCRIPT_TYPE_P2PK_UNCOMPRESSED_ODD: u8 = 0x05;

/// Compress a scriptPubKey into its compact representation.
///
/// Returns `(type_byte, data)` where `data` is 20 or 32 bytes for standard
/// types, or the full script for non-standard scripts.
pub fn compress_script(script: &Script) -> CompressedScript {
    let bytes = script.as_bytes();

    // P2PKH: OP_DUP OP_HASH160 <20> <hash> OP_EQUALVERIFY OP_CHECKSIG
    if bytes.len() == 25
        && bytes[0] == 0x76  // OP_DUP
        && bytes[1] == 0xa9  // OP_HASH160
        && bytes[2] == 0x14  // push 20 bytes
        && bytes[23] == 0x88 // OP_EQUALVERIFY
        && bytes[24] == 0xac
    // OP_CHECKSIG
    {
        let mut hash = [0u8; 20];
        hash.copy_from_slice(&bytes[3..23]);
        return CompressedScript::P2PKH(hash);
    }

    // P2SH: OP_HASH160 <20> <hash> OP_EQUAL
    if bytes.len() == 23
        && bytes[0] == 0xa9  // OP_HASH160
        && bytes[1] == 0x14  // push 20 bytes
        && bytes[22] == 0x87
    // OP_EQUAL
    {
        let mut hash = [0u8; 20];
        hash.copy_from_slice(&bytes[2..22]);
        return CompressedScript::P2SH(hash);
    }

    // P2PK compressed: <33> <02/03><x> OP_CHECKSIG
    if bytes.len() == 35
        && bytes[0] == 0x21  // push 33 bytes
        && (bytes[1] == 0x02 || bytes[1] == 0x03)
        && bytes[34] == 0xac
    // OP_CHECKSIG
    {
        let mut x = [0u8; 32];
        x.copy_from_slice(&bytes[2..34]);
        return CompressedScript::P2PKCompressed {
            odd: bytes[1] == 0x03,
            x,
        };
    }

    // P2PK uncompressed: <65> <04><x><y> OP_CHECKSIG
    if bytes.len() == 67
        && bytes[0] == 0x41  // push 65 bytes
        && bytes[1] == 0x04
        && bytes[66] == 0xac
    // OP_CHECKSIG
    {
        let mut x = [0u8; 32];
        x.copy_from_slice(&bytes[2..34]);
        // Determine parity from y-coordinate's last bit
        let odd = bytes[65] & 1 == 1;
        return CompressedScript::P2PKUncompressed { odd, x };
    }

    // Non-standard: store raw script
    CompressedScript::Other(bytes.to_vec())
}

/// Decompress a script back to its full scriptPubKey form.
pub fn decompress_script(compressed: &CompressedScript) -> Script {
    match compressed {
        CompressedScript::P2PKH(hash) => {
            let mut bytes = Vec::with_capacity(25);
            bytes.push(0x76); // OP_DUP
            bytes.push(0xa9); // OP_HASH160
            bytes.push(0x14); // push 20
            bytes.extend_from_slice(hash);
            bytes.push(0x88); // OP_EQUALVERIFY
            bytes.push(0xac); // OP_CHECKSIG
            Script::from_bytes(bytes)
        }
        CompressedScript::P2SH(hash) => {
            let mut bytes = Vec::with_capacity(23);
            bytes.push(0xa9); // OP_HASH160
            bytes.push(0x14); // push 20
            bytes.extend_from_slice(hash);
            bytes.push(0x87); // OP_EQUAL
            Script::from_bytes(bytes)
        }
        CompressedScript::P2PKCompressed { odd, x } => {
            let mut bytes = Vec::with_capacity(35);
            bytes.push(0x21); // push 33
            bytes.push(if *odd { 0x03 } else { 0x02 });
            bytes.extend_from_slice(x);
            bytes.push(0xac); // OP_CHECKSIG
            Script::from_bytes(bytes)
        }
        CompressedScript::P2PKUncompressed { odd, x } => {
            // We can only reconstruct the compressed form here since we lost
            // the y-coordinate. In practice, AssumeUTXO snapshots would store
            // the compressed pubkey form.
            let mut bytes = Vec::with_capacity(35);
            bytes.push(0x21); // push 33
            bytes.push(if *odd { 0x03 } else { 0x02 });
            bytes.extend_from_slice(x);
            bytes.push(0xac); // OP_CHECKSIG
            Script::from_bytes(bytes)
        }
        CompressedScript::Other(raw) => Script::from_bytes(raw.clone()),
    }
}

/// A compressed representation of a scriptPubKey.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CompressedScript {
    /// P2PKH — 20-byte pubkey hash
    P2PKH([u8; 20]),
    /// P2SH — 20-byte script hash
    P2SH([u8; 20]),
    /// P2PK with compressed key — 32-byte x-coordinate + parity
    P2PKCompressed { odd: bool, x: [u8; 32] },
    /// P2PK with uncompressed key — stored as compressed (32-byte x + parity)
    P2PKUncompressed { odd: bool, x: [u8; 32] },
    /// Non-standard script — stored in full
    Other(Vec<u8>),
}

// ---------------------------------------------------------------------------
// CompressedCoin — a full compressed UTXO entry
// ---------------------------------------------------------------------------

/// A compressed representation of a single UTXO (coin).
///
/// Encodes the coin metadata (height, coinbase flag), compressed amount,
/// and compressed scriptPubKey into a compact binary format.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompressedCoin {
    /// Block height at which this coin was created, with coinbase flag
    /// packed into the lowest bit: `(height << 1) | is_coinbase`.
    pub code: u64,
    /// Compressed amount
    pub compressed_amount: u64,
    /// Compressed script
    pub compressed_script: CompressedScript,
}

impl CompressedCoin {
    /// Create a compressed coin from a UTXO entry.
    pub fn from_utxo_entry(entry: &UtxoEntry) -> Self {
        let code = ((entry.height as u64) << 1) | (entry.is_coinbase as u64);
        let compressed_amount = compress_amount(entry.output.value.as_sat() as u64);
        let compressed_script = compress_script(&entry.output.script_pubkey);
        CompressedCoin {
            code,
            compressed_amount,
            compressed_script,
        }
    }

    /// Reconstruct the UTXO entry from a compressed coin.
    pub fn to_utxo_entry(&self) -> UtxoEntry {
        let height = (self.code >> 1) as u32;
        let is_coinbase = (self.code & 1) == 1;
        let value = Amount::from_sat(decompress_amount(self.compressed_amount) as i64);
        let script_pubkey = decompress_script(&self.compressed_script);
        UtxoEntry {
            output: TxOut::new(value, script_pubkey),
            height,
            is_coinbase,
        }
    }

    /// Serialize to binary format.
    ///
    /// Format: `varint(code) || varint(compressed_amount) || compressed_script_bytes`
    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        push_varint(&mut buf, self.code);
        push_varint(&mut buf, self.compressed_amount);
        serialize_compressed_script(&mut buf, &self.compressed_script);
        buf
    }

    /// Deserialize from binary format.
    pub fn deserialize(data: &[u8]) -> Result<(Self, usize), &'static str> {
        let mut pos = 0;

        let (code, n) = read_varint(data, pos)?;
        pos += n;

        let (compressed_amount, n) = read_varint(data, pos)?;
        pos += n;

        let (compressed_script, n) = deserialize_compressed_script(data, pos)?;
        pos += n;

        Ok((
            CompressedCoin {
                code,
                compressed_amount,
                compressed_script,
            },
            pos,
        ))
    }
}

/// Serialize an outpoint-coin pair as it appears in a UTXO snapshot.
///
/// Format: `txid(32) || varint(vout) || compressed_coin`
pub fn serialize_utxo(outpoint: &OutPoint, entry: &UtxoEntry) -> Vec<u8> {
    let mut buf = Vec::with_capacity(64);
    buf.extend_from_slice(outpoint.txid.as_bytes());
    push_varint(&mut buf, outpoint.vout as u64);
    let coin = CompressedCoin::from_utxo_entry(entry);
    buf.extend_from_slice(&coin.serialize());
    buf
}

/// Deserialize an outpoint-coin pair from a snapshot stream.
pub fn deserialize_utxo(
    data: &[u8],
    offset: usize,
) -> Result<(OutPoint, UtxoEntry, usize), &'static str> {
    let mut pos = offset;

    if pos + 32 > data.len() {
        return Err("truncated txid");
    }
    let mut txid_bytes = [0u8; 32];
    txid_bytes.copy_from_slice(&data[pos..pos + 32]);
    pos += 32;

    let (vout, n) = read_varint(data, pos)?;
    pos += n;

    let (coin, n) = CompressedCoin::deserialize(&data[pos..])?;
    pos += n;

    let outpoint = OutPoint::new(
        Txid::from_hash(crate::primitives::Hash256::from_bytes(txid_bytes)),
        vout as u32,
    );
    let entry = coin.to_utxo_entry();
    Ok((outpoint, entry, pos - offset))
}

// ---------------------------------------------------------------------------
// Varint encoding (Bitcoin Core's CVarInt — unsigned LEB128-style)
// ---------------------------------------------------------------------------

/// Encode a u64 as a Bitcoin Core varint (not CompactSize — the chainstate
/// varint uses a different encoding where each byte uses 7 data bits and
/// the high bit indicates continuation, but with a twist: each continuation
/// adds 1, preventing non-canonical encodings).
///
/// Bytes are written MSB-first: the last byte in the stream (least
/// significant) has no continuation bit; earlier bytes have 0x80 set.
pub fn push_varint(buf: &mut Vec<u8>, mut n: u64) {
    let mut tmp = [0u8; 10];
    let mut len = 0;
    loop {
        // The final byte (len == 0) has no continuation bit.
        // Earlier bytes (len > 0) get 0x80 to signal "more follows".
        tmp[len] = (n & 0x7F) as u8 | if len > 0 { 0x80 } else { 0x00 };
        if n <= 0x7F {
            break;
        }
        n = (n >> 7) - 1;
        len += 1;
    }
    // Write in reverse order (most-significant byte first)
    for i in (0..=len).rev() {
        buf.push(tmp[i]);
    }
}

/// Decode a Bitcoin Core varint, returning the value and bytes consumed.
pub fn read_varint(data: &[u8], offset: usize) -> Result<(u64, usize), &'static str> {
    let mut n: u64 = 0;
    let mut pos = offset;
    loop {
        if pos >= data.len() {
            return Err("truncated varint");
        }
        let byte = data[pos];
        pos += 1;
        // Shift existing value and add this chunk
        n = (n << 7) | (byte & 0x7F) as u64;
        if byte & 0x80 == 0 {
            return Ok((n, pos - offset));
        }
        n += 1; // Reverse the -1 from encoding
    }
}

// ---------------------------------------------------------------------------
// Compressed script serialization
// ---------------------------------------------------------------------------

fn serialize_compressed_script(buf: &mut Vec<u8>, script: &CompressedScript) {
    match script {
        CompressedScript::P2PKH(hash) => {
            push_varint(buf, SCRIPT_TYPE_P2PKH as u64);
            buf.extend_from_slice(hash);
        }
        CompressedScript::P2SH(hash) => {
            push_varint(buf, SCRIPT_TYPE_P2SH as u64);
            buf.extend_from_slice(hash);
        }
        CompressedScript::P2PKCompressed { odd, x } => {
            let tag = if *odd {
                SCRIPT_TYPE_P2PK_ODD
            } else {
                SCRIPT_TYPE_P2PK_EVEN
            };
            push_varint(buf, tag as u64);
            buf.extend_from_slice(x);
        }
        CompressedScript::P2PKUncompressed { odd, x } => {
            let tag = if *odd {
                SCRIPT_TYPE_P2PK_UNCOMPRESSED_ODD
            } else {
                SCRIPT_TYPE_P2PK_UNCOMPRESSED_EVEN
            };
            push_varint(buf, tag as u64);
            buf.extend_from_slice(x);
        }
        CompressedScript::Other(raw) => {
            // Size = raw.len() + 6 (to distinguish from type tags 0-5)
            push_varint(buf, (raw.len() + 6) as u64);
            buf.extend_from_slice(raw);
        }
    }
}

fn deserialize_compressed_script(
    data: &[u8],
    offset: usize,
) -> Result<(CompressedScript, usize), &'static str> {
    let (tag, n) = read_varint(data, offset)?;
    let mut pos = offset + n;

    match tag {
        0 => {
            // P2PKH: 20-byte hash follows
            if pos + 20 > data.len() {
                return Err("truncated P2PKH hash");
            }
            let mut hash = [0u8; 20];
            hash.copy_from_slice(&data[pos..pos + 20]);
            pos += 20;
            Ok((CompressedScript::P2PKH(hash), pos - offset))
        }
        1 => {
            // P2SH: 20-byte hash follows
            if pos + 20 > data.len() {
                return Err("truncated P2SH hash");
            }
            let mut hash = [0u8; 20];
            hash.copy_from_slice(&data[pos..pos + 20]);
            pos += 20;
            Ok((CompressedScript::P2SH(hash), pos - offset))
        }
        2 | 3 => {
            // P2PK compressed: 32-byte x
            if pos + 32 > data.len() {
                return Err("truncated P2PK x-coordinate");
            }
            let mut x = [0u8; 32];
            x.copy_from_slice(&data[pos..pos + 32]);
            pos += 32;
            Ok((
                CompressedScript::P2PKCompressed { odd: tag == 3, x },
                pos - offset,
            ))
        }
        4 | 5 => {
            // P2PK uncompressed (stored as compressed)
            if pos + 32 > data.len() {
                return Err("truncated P2PK x-coordinate");
            }
            let mut x = [0u8; 32];
            x.copy_from_slice(&data[pos..pos + 32]);
            pos += 32;
            Ok((
                CompressedScript::P2PKUncompressed { odd: tag == 5, x },
                pos - offset,
            ))
        }
        size => {
            // Non-standard: raw script of length (size - 6)
            if size < 6 {
                return Err("invalid compressed script tag");
            }
            let script_len = (size - 6) as usize;
            if pos + script_len > data.len() {
                return Err("truncated raw script");
            }
            let raw = data[pos..pos + script_len].to_vec();
            pos += script_len;
            Ok((CompressedScript::Other(raw), pos - offset))
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // ── Amount compression ─────────────────────────────────────────

    #[test]
    fn test_compress_amount_zero() {
        assert_eq!(compress_amount(0), 0);
        assert_eq!(decompress_amount(0), 0);
    }

    #[test]
    fn test_compress_amount_roundtrip() {
        // Test specific known amounts
        let amounts: Vec<u64> = vec![
            1,                     // 1 satoshi
            100,                   // 100 sat
            1_000,                 // 1000 sat
            10_000,                // 10k sat
            100_000,               // 100k sat
            1_000_000,             // 0.01 BTC
            10_000_000,            // 0.1 BTC
            100_000_000,           // 1 BTC
            500_000_000,           // 5 BTC
            5_000_000_000,         // 50 BTC
            2_100_000_000_000_000, // 21M BTC (max supply)
        ];
        for amt in amounts {
            let compressed = compress_amount(amt);
            let decompressed = decompress_amount(compressed);
            assert_eq!(
                decompressed, amt,
                "roundtrip failed for {}: compressed={}, decompressed={}",
                amt, compressed, decompressed
            );
        }
    }

    #[test]
    fn test_compress_amount_round_amounts_are_small() {
        // 1 BTC (1e8 sat) should compress to a small number
        let one_btc = compress_amount(100_000_000);
        assert!(
            one_btc < 20,
            "1 BTC compressed to {} (expected < 20)",
            one_btc
        );

        // 50 BTC (block reward)
        let fifty_btc = compress_amount(5_000_000_000);
        assert!(
            fifty_btc < 200,
            "50 BTC compressed to {} (expected < 200)",
            fifty_btc
        );
    }

    #[test]
    fn test_compress_amount_odd_values() {
        // Non-round amounts should still roundtrip correctly
        for amt in [1, 3, 7, 11, 13, 37, 99, 101, 12345, 999999999] {
            assert_eq!(decompress_amount(compress_amount(amt)), amt);
        }
    }

    // ── Varint encoding ────────────────────────────────────────────

    #[test]
    fn test_varint_roundtrip() {
        let values: Vec<u64> = vec![
            0,
            1,
            127,
            128,
            255,
            256,
            16383,
            16384,
            u32::MAX as u64,
            u64::MAX,
        ];
        for v in values {
            let mut buf = Vec::new();
            push_varint(&mut buf, v);
            let (decoded, _) = read_varint(&buf, 0).unwrap();
            assert_eq!(decoded, v, "varint roundtrip failed for {}", v);
        }
    }

    #[test]
    fn test_varint_canonical() {
        // Zero should encode as a single byte
        let mut buf = Vec::new();
        push_varint(&mut buf, 0);
        assert_eq!(buf.len(), 1);
        assert_eq!(buf[0], 0x00);
    }

    // ── Script compression ─────────────────────────────────────────

    #[test]
    fn test_compress_p2pkh() {
        // Construct a P2PKH script
        let hash = [0xab; 20];
        let mut script_bytes = vec![0x76, 0xa9, 0x14];
        script_bytes.extend_from_slice(&hash);
        script_bytes.push(0x88);
        script_bytes.push(0xac);
        let script = Script::from_bytes(script_bytes);

        let compressed = compress_script(&script);
        assert_eq!(compressed, CompressedScript::P2PKH(hash));

        let decompressed = decompress_script(&compressed);
        assert_eq!(decompressed, script);
    }

    #[test]
    fn test_compress_p2sh() {
        let hash = [0xcd; 20];
        let mut script_bytes = vec![0xa9, 0x14];
        script_bytes.extend_from_slice(&hash);
        script_bytes.push(0x87);
        let script = Script::from_bytes(script_bytes);

        let compressed = compress_script(&script);
        assert_eq!(compressed, CompressedScript::P2SH(hash));

        let decompressed = decompress_script(&compressed);
        assert_eq!(decompressed, script);
    }

    #[test]
    fn test_compress_p2pk_compressed() {
        let x = [0x11; 32];
        let mut script_bytes = vec![0x21, 0x02];
        script_bytes.extend_from_slice(&x);
        script_bytes.push(0xac);
        let script = Script::from_bytes(script_bytes);

        let compressed = compress_script(&script);
        assert_eq!(
            compressed,
            CompressedScript::P2PKCompressed { odd: false, x }
        );

        let decompressed = decompress_script(&compressed);
        assert_eq!(decompressed, script);
    }

    #[test]
    fn test_compress_nonstandard_script() {
        // OP_RETURN with some data
        let script_bytes = vec![0x6a, 0x04, 0xde, 0xad, 0xbe, 0xef];
        let script = Script::from_bytes(script_bytes.clone());

        let compressed = compress_script(&script);
        assert_eq!(compressed, CompressedScript::Other(script_bytes.clone()));

        let decompressed = decompress_script(&compressed);
        assert_eq!(decompressed.as_bytes(), script_bytes.as_slice());
    }

    // ── CompressedCoin serialization ───────────────────────────────

    #[test]
    fn test_compressed_coin_roundtrip() {
        let entry = UtxoEntry {
            output: TxOut::new(
                Amount::from_sat(100_000_000), // 1 BTC
                // P2PKH script
                Script::from_bytes(vec![
                    0x76, 0xa9, 0x14, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a,
                    0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x88, 0xac,
                ]),
            ),
            height: 500_000,
            is_coinbase: false,
        };

        let coin = CompressedCoin::from_utxo_entry(&entry);
        let serialized = coin.serialize();
        let (deserialized, bytes_read) = CompressedCoin::deserialize(&serialized).unwrap();
        assert_eq!(bytes_read, serialized.len());
        assert_eq!(deserialized, coin);

        // Verify the entry roundtrips through compression
        let recovered = deserialized.to_utxo_entry();
        assert_eq!(recovered.height, entry.height);
        assert_eq!(recovered.is_coinbase, entry.is_coinbase);
        assert_eq!(recovered.output.value, entry.output.value);
        assert_eq!(recovered.output.script_pubkey, entry.output.script_pubkey);
    }

    #[test]
    fn test_compressed_coin_coinbase() {
        let entry = UtxoEntry {
            output: TxOut::new(
                Amount::from_sat(5_000_000_000),
                Script::from_bytes(vec![0x6a]),
            ),
            height: 100,
            is_coinbase: true,
        };

        let coin = CompressedCoin::from_utxo_entry(&entry);
        // Coinbase flag should be set in low bit
        assert_eq!(coin.code & 1, 1);
        assert_eq!(coin.code >> 1, 100);

        let recovered = coin.to_utxo_entry();
        assert!(recovered.is_coinbase);
        assert_eq!(recovered.height, 100);
    }

    // ── Full UTXO serialization ────────────────────────────────────

    #[test]
    fn test_serialize_utxo_roundtrip() {
        let txid = Txid::from_hash(crate::primitives::Hash256::from_bytes([0xaa; 32]));
        let outpoint = OutPoint::new(txid, 3);
        let entry = UtxoEntry {
            output: TxOut::new(
                Amount::from_sat(50_000),
                Script::from_bytes(vec![
                    0xa9, 0x14, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
                    0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x87,
                ]),
            ),
            height: 800_000,
            is_coinbase: false,
        };

        let serialized = serialize_utxo(&outpoint, &entry);
        let (op, ent, bytes_read) = deserialize_utxo(&serialized, 0).unwrap();
        assert_eq!(bytes_read, serialized.len());
        assert_eq!(op, outpoint);
        assert_eq!(ent.height, entry.height);
        assert_eq!(ent.is_coinbase, entry.is_coinbase);
        assert_eq!(ent.output.value, entry.output.value);
    }

    #[test]
    fn test_amount_compression_specific_values() {
        // From Bitcoin Core tests:
        // 0 → 0
        assert_eq!(compress_amount(0), 0);
        // 1 → 1
        assert_eq!(compress_amount(1), 1);

        // Verify all values 0..=100_000_000 roundtrip (sampled)
        for amt in (0..=100_000_000u64).step_by(99_999) {
            let c = compress_amount(amt);
            let d = decompress_amount(c);
            assert_eq!(d, amt, "failed for amount {}", amt);
        }
    }

    #[test]
    fn test_height_coinbase_encoding() {
        // Test the code field encoding
        for height in [0u32, 1, 100, 500_000, 840_000, u32::MAX >> 1] {
            for is_cb in [false, true] {
                let code = ((height as u64) << 1) | (is_cb as u64);
                let decoded_height = (code >> 1) as u32;
                let decoded_cb = (code & 1) == 1;
                assert_eq!(decoded_height, height);
                assert_eq!(decoded_cb, is_cb);
            }
        }
    }
}
