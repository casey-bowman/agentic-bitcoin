//! Golomb-Coded Set (GCS) — the core data structure for BIP158 compact block filters
//!
//! A Golomb-Coded Set is a space-efficient probabilistic data structure similar to a
//! Bloom filter, but ~40% smaller. It works by:
//!
//! 1. Hashing each element to a uniform value in `[0, N*M)` where N is the number
//!    of elements and M controls the false-positive rate (1/M).
//! 2. Sorting the hashed values.
//! 3. Computing the differences between consecutive sorted values.
//! 4. Encoding each difference with Golomb-Rice coding using parameter P = log2(M).
//!
//! BIP158 uses M = 784931 (≈ 2^19.5) and P = 19 for the basic filter type.
//!
//! ## References
//!
//! - BIP158: <https://github.com/bitcoin/bips/blob/master/bip-0158.mediawiki>
//! - Golomb coding: <https://en.wikipedia.org/wiki/Golomb_coding>

// ---------------------------------------------------------------------------
// BIP158 constants
// ---------------------------------------------------------------------------

/// BIP158 basic filter: false-positive rate parameter M.
/// Probability of false positive = 1/M ≈ 1/784931.
pub const BASIC_FILTER_M: u64 = 784931;

/// BIP158 basic filter: Golomb-Rice coding parameter P = 19.
/// This is floor(log2(M)).
pub const BASIC_FILTER_P: u8 = 19;

// ---------------------------------------------------------------------------
// SipHash-based hashing (BIP158 uses SipHash-2-4 with a key derived from the block hash)
// ---------------------------------------------------------------------------

/// SipHash-2-4 round function.
fn sip_round(v0: &mut u64, v1: &mut u64, v2: &mut u64, v3: &mut u64) {
    *v0 = v0.wrapping_add(*v1);
    *v1 = v1.rotate_left(13);
    *v1 ^= *v0;
    *v0 = v0.rotate_left(32);
    *v2 = v2.wrapping_add(*v3);
    *v3 = v3.rotate_left(16);
    *v3 ^= *v2;
    *v0 = v0.wrapping_add(*v3);
    *v3 = v3.rotate_left(21);
    *v3 ^= *v0;
    *v2 = v2.wrapping_add(*v1);
    *v1 = v1.rotate_left(17);
    *v1 ^= *v2;
    *v2 = v2.rotate_left(32);
}

/// Compute SipHash-2-4 of arbitrary data with the given 128-bit key.
pub fn siphash_2_4(k0: u64, k1: u64, data: &[u8]) -> u64 {
    let mut v0: u64 = 0x736f6d6570736575u64 ^ k0;
    let mut v1: u64 = 0x646f72616e646f6du64 ^ k1;
    let mut v2: u64 = 0x6c7967656e657261u64 ^ k0;
    let mut v3: u64 = 0x7465646279746573u64 ^ k1;

    // Process 8-byte blocks
    let blocks = data.len() / 8;
    for i in 0..blocks {
        let mut m = 0u64;
        for j in 0..8 {
            m |= (data[i * 8 + j] as u64) << (j * 8);
        }
        v3 ^= m;
        sip_round(&mut v0, &mut v1, &mut v2, &mut v3);
        sip_round(&mut v0, &mut v1, &mut v2, &mut v3);
        v0 ^= m;
    }

    // Process remaining bytes + length byte
    let remaining = data.len() % 8;
    let mut last: u64 = ((data.len() & 0xff) as u64) << 56;
    for i in 0..remaining {
        last |= (data[blocks * 8 + i] as u64) << (i * 8);
    }

    v3 ^= last;
    sip_round(&mut v0, &mut v1, &mut v2, &mut v3);
    sip_round(&mut v0, &mut v1, &mut v2, &mut v3);
    v0 ^= last;

    // Finalization
    v2 ^= 0xff;
    sip_round(&mut v0, &mut v1, &mut v2, &mut v3);
    sip_round(&mut v0, &mut v1, &mut v2, &mut v3);
    sip_round(&mut v0, &mut v1, &mut v2, &mut v3);
    sip_round(&mut v0, &mut v1, &mut v2, &mut v3);

    v0 ^ v1 ^ v2 ^ v3
}

/// Derive the SipHash key (k0, k1) from a block hash, per BIP158.
///
/// The key is the first 16 bytes of the block hash interpreted as two
/// little-endian u64 values.
pub fn key_from_block_hash(block_hash: &[u8; 32]) -> (u64, u64) {
    let k0 = u64::from_le_bytes([
        block_hash[0],
        block_hash[1],
        block_hash[2],
        block_hash[3],
        block_hash[4],
        block_hash[5],
        block_hash[6],
        block_hash[7],
    ]);
    let k1 = u64::from_le_bytes([
        block_hash[8],
        block_hash[9],
        block_hash[10],
        block_hash[11],
        block_hash[12],
        block_hash[13],
        block_hash[14],
        block_hash[15],
    ]);
    (k0, k1)
}

/// Hash a data element to a value in `[0, F)` using SipHash, where F = N * M.
///
/// Uses the "fast range reduction" technique: `(siphash * F) >> 64` which maps
/// uniformly to `[0, F)` without bias (for practical purposes).
pub fn hash_to_range(k0: u64, k1: u64, element: &[u8], f: u64) -> u64 {
    let h = siphash_2_4(k0, k1, element);
    // Fast range reduction: (h * f) >> 64
    let product = (h as u128) * (f as u128);
    (product >> 64) as u64
}

// ---------------------------------------------------------------------------
// Bitwriter / Bitreader for Golomb-Rice coding
// ---------------------------------------------------------------------------

/// A bit-level writer that packs bits into bytes (MSB first).
pub struct BitWriter {
    buf: Vec<u8>,
    current: u8,
    bits_in_current: u8,
}

impl BitWriter {
    /// Create a new empty BitWriter.
    pub fn new() -> Self {
        BitWriter {
            buf: Vec::new(),
            current: 0,
            bits_in_current: 0,
        }
    }

    /// Write a single bit (0 or 1).
    pub fn write_bit(&mut self, bit: bool) {
        self.current = (self.current << 1) | (bit as u8);
        self.bits_in_current += 1;
        if self.bits_in_current == 8 {
            self.buf.push(self.current);
            self.current = 0;
            self.bits_in_current = 0;
        }
    }

    /// Write `n` bits from `value` (MSB first).
    pub fn write_bits(&mut self, value: u64, n: u8) {
        for i in (0..n).rev() {
            self.write_bit((value >> i) & 1 == 1);
        }
    }

    /// Write a unary-encoded value: `value` ones followed by a zero.
    pub fn write_unary(&mut self, value: u64) {
        for _ in 0..value {
            self.write_bit(true);
        }
        self.write_bit(false);
    }

    /// Write a Golomb-Rice coded value with parameter P.
    ///
    /// The quotient (value >> P) is unary-coded, and the remainder
    /// (value & ((1 << P) - 1)) is written as P bits.
    pub fn write_golomb_rice(&mut self, value: u64, p: u8) {
        let quotient = value >> p;
        let remainder = value & ((1u64 << p) - 1);
        self.write_unary(quotient);
        self.write_bits(remainder, p);
    }

    /// Flush remaining bits (padded with zeros on the right) and return the buffer.
    pub fn finish(mut self) -> Vec<u8> {
        if self.bits_in_current > 0 {
            self.current <<= 8 - self.bits_in_current;
            self.buf.push(self.current);
        }
        self.buf
    }
}

impl Default for BitWriter {
    fn default() -> Self {
        Self::new()
    }
}

/// A bit-level reader that unpacks bits from bytes (MSB first).
pub struct BitReader<'a> {
    data: &'a [u8],
    byte_pos: usize,
    bit_pos: u8, // 0..8, counts from MSB
}

impl<'a> BitReader<'a> {
    /// Create a new BitReader over the given data.
    pub fn new(data: &'a [u8]) -> Self {
        BitReader {
            data,
            byte_pos: 0,
            bit_pos: 0,
        }
    }

    /// Read a single bit. Returns None if exhausted.
    pub fn read_bit(&mut self) -> Option<bool> {
        if self.byte_pos >= self.data.len() {
            return None;
        }
        let bit = (self.data[self.byte_pos] >> (7 - self.bit_pos)) & 1 == 1;
        self.bit_pos += 1;
        if self.bit_pos == 8 {
            self.bit_pos = 0;
            self.byte_pos += 1;
        }
        Some(bit)
    }

    /// Read `n` bits as a u64 value (MSB first).
    pub fn read_bits(&mut self, n: u8) -> Option<u64> {
        let mut value = 0u64;
        for _ in 0..n {
            let bit = self.read_bit()?;
            value = (value << 1) | (bit as u64);
        }
        Some(value)
    }

    /// Read a unary-encoded value: count ones until a zero is encountered.
    pub fn read_unary(&mut self) -> Option<u64> {
        let mut count = 0u64;
        loop {
            let bit = self.read_bit()?;
            if bit {
                count += 1;
            } else {
                return Some(count);
            }
        }
    }

    /// Read a Golomb-Rice coded value with parameter P.
    pub fn read_golomb_rice(&mut self, p: u8) -> Option<u64> {
        let quotient = self.read_unary()?;
        let remainder = self.read_bits(p)?;
        Some((quotient << p) | remainder)
    }
}

// ---------------------------------------------------------------------------
// GCS construction and querying
// ---------------------------------------------------------------------------

/// A Golomb-Coded Set.
///
/// This is the encoded filter data. The raw sorted hashed values are not stored;
/// only the Golomb-Rice encoded deltas are kept.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GcsFilter {
    /// Number of elements in the set
    pub n: u32,
    /// Golomb-Rice parameter P
    pub p: u8,
    /// The false-positive rate parameter M
    pub m: u64,
    /// Encoded filter data (Golomb-Rice coded deltas)
    pub data: Vec<u8>,
}

impl GcsFilter {
    /// Build a GCS filter from a list of raw data elements.
    ///
    /// Uses SipHash with the provided key to hash each element, then Golomb-Rice
    /// encodes the sorted differences.
    pub fn build(k0: u64, k1: u64, p: u8, m: u64, elements: &[&[u8]]) -> Self {
        let n = elements.len() as u32;
        if n == 0 {
            return GcsFilter {
                n: 0,
                p,
                m,
                data: Vec::new(),
            };
        }

        let f = (n as u64) * m;

        // Hash all elements to [0, F)
        let mut hashed: Vec<u64> = elements
            .iter()
            .map(|elem| hash_to_range(k0, k1, elem, f))
            .collect();

        // Sort and deduplicate
        hashed.sort_unstable();
        hashed.dedup();

        // Encode deltas using Golomb-Rice
        let mut writer = BitWriter::new();
        let mut prev = 0u64;
        for &val in &hashed {
            let delta = val - prev;
            writer.write_golomb_rice(delta, p);
            prev = val;
        }

        let actual_n = hashed.len() as u32;

        GcsFilter {
            n: actual_n,
            p,
            m,
            data: writer.finish(),
        }
    }

    /// Build a BIP158 basic filter from elements using the given block hash as key.
    pub fn build_basic(block_hash: &[u8; 32], elements: &[&[u8]]) -> Self {
        let (k0, k1) = key_from_block_hash(block_hash);
        Self::build(k0, k1, BASIC_FILTER_P, BASIC_FILTER_M, elements)
    }

    /// Query whether an element *might* be in the set.
    ///
    /// Returns `true` if the element matches (possible false positive),
    /// `false` if the element is definitely not in the set.
    pub fn match_any(&self, k0: u64, k1: u64, element: &[u8]) -> bool {
        if self.n == 0 {
            return false;
        }

        let f = (self.n as u64) * self.m;
        let target = hash_to_range(k0, k1, element, f);

        // Decode the sorted values and check if target is present
        let mut reader = BitReader::new(&self.data);
        let mut value = 0u64;

        for _ in 0..self.n {
            let delta = match reader.read_golomb_rice(self.p) {
                Some(d) => d,
                None => return false,
            };
            value += delta;
            if value == target {
                return true;
            }
            if value > target {
                return false;
            }
        }

        false
    }

    /// Query whether *any* element from a set of candidates might be in the filter.
    ///
    /// This is more efficient than calling `match_any` for each candidate
    /// because it decodes the filter only once while doing a merge-intersection
    /// with the sorted candidate hashes.
    pub fn match_any_of(&self, k0: u64, k1: u64, candidates: &[&[u8]]) -> bool {
        if self.n == 0 || candidates.is_empty() {
            return false;
        }

        let f = (self.n as u64) * self.m;

        // Hash and sort candidates
        let mut candidate_hashes: Vec<u64> = candidates
            .iter()
            .map(|c| hash_to_range(k0, k1, c, f))
            .collect();
        candidate_hashes.sort_unstable();
        candidate_hashes.dedup();

        // Merge-intersect the decoded filter values with candidate hashes
        let mut reader = BitReader::new(&self.data);
        let mut filter_val = 0u64;
        let mut cand_idx = 0;
        let mut filter_idx = 0u32;

        // Read first filter value
        let delta = match reader.read_golomb_rice(self.p) {
            Some(d) => d,
            None => return false,
        };
        filter_val += delta;
        filter_idx += 1;

        loop {
            if cand_idx >= candidate_hashes.len() {
                return false;
            }

            let cand = candidate_hashes[cand_idx];

            if filter_val == cand {
                return true;
            } else if filter_val < cand {
                // Advance filter
                if filter_idx >= self.n {
                    return false;
                }
                let delta = match reader.read_golomb_rice(self.p) {
                    Some(d) => d,
                    None => return false,
                };
                filter_val += delta;
                filter_idx += 1;
            } else {
                // filter_val > cand: advance candidates
                cand_idx += 1;
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Serialization (N as CompactSize + raw filter data)
// ---------------------------------------------------------------------------

impl GcsFilter {
    /// Serialize as BIP158 format: CompactSize(N) || filter_data
    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        // N as CompactSize
        crate::protocol::codec::push_compact_size(&mut buf, self.n as u64);
        buf.extend_from_slice(&self.data);
        buf
    }

    /// Deserialize from BIP158 format, given P and M parameters.
    pub fn deserialize(data: &[u8], p: u8, m: u64) -> Result<Self, &'static str> {
        if data.is_empty() {
            return Ok(GcsFilter {
                n: 0,
                p,
                m,
                data: Vec::new(),
            });
        }
        let (n, consumed) =
            crate::protocol::codec::decode_compact_size(data, 0).map_err(|_| "bad compact size")?;
        let n = n as u32;
        let filter_data = data[consumed..].to_vec();
        Ok(GcsFilter {
            n,
            p,
            m,
            data: filter_data,
        })
    }

    /// Deserialize a BIP158 basic filter.
    pub fn deserialize_basic(data: &[u8]) -> Result<Self, &'static str> {
        Self::deserialize(data, BASIC_FILTER_P, BASIC_FILTER_M)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // ── SipHash ─────────────────────────────────────────────────────

    #[test]
    fn test_siphash_deterministic() {
        let h1 = siphash_2_4(0, 0, b"hello");
        let h2 = siphash_2_4(0, 0, b"hello");
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_siphash_different_keys() {
        let h1 = siphash_2_4(0, 0, b"test");
        let h2 = siphash_2_4(1, 0, b"test");
        assert_ne!(h1, h2);
    }

    #[test]
    fn test_siphash_different_data() {
        let h1 = siphash_2_4(42, 43, b"alpha");
        let h2 = siphash_2_4(42, 43, b"beta");
        assert_ne!(h1, h2);
    }

    #[test]
    fn test_siphash_empty() {
        // Should not panic on empty input
        let h = siphash_2_4(0, 0, b"");
        assert_ne!(h, 0); // extremely unlikely to be 0
    }

    #[test]
    fn test_key_from_block_hash() {
        let mut hash = [0u8; 32];
        hash[0] = 0x01;
        hash[8] = 0x02;
        let (k0, k1) = key_from_block_hash(&hash);
        assert_eq!(k0, 1);
        assert_eq!(k1, 2);
    }

    #[test]
    fn test_hash_to_range() {
        let f = 1000u64;
        let val = hash_to_range(0, 0, b"test", f);
        assert!(val < f);
    }

    #[test]
    fn test_hash_to_range_uniform() {
        // Hash many values and check they're all in range
        let f = 10000u64;
        for i in 0u8..200 {
            let val = hash_to_range(42, 43, &[i], f);
            assert!(val < f, "hash_to_range produced {} >= {}", val, f);
        }
    }

    // ── BitWriter / BitReader ───────────────────────────────────────

    #[test]
    fn test_bitwriter_single_bits() {
        let mut w = BitWriter::new();
        w.write_bit(true);
        w.write_bit(false);
        w.write_bit(true);
        w.write_bit(true);
        w.write_bit(false);
        w.write_bit(false);
        w.write_bit(true);
        w.write_bit(false);
        let buf = w.finish();
        assert_eq!(buf, vec![0b10110010]);
    }

    #[test]
    fn test_bitwriter_partial_byte() {
        let mut w = BitWriter::new();
        w.write_bit(true);
        w.write_bit(true);
        let buf = w.finish();
        // 11 padded to 11000000
        assert_eq!(buf, vec![0b11000000]);
    }

    #[test]
    fn test_bitwriter_write_bits() {
        let mut w = BitWriter::new();
        w.write_bits(0b1010, 4);
        w.write_bits(0b1100, 4);
        let buf = w.finish();
        assert_eq!(buf, vec![0b10101100]);
    }

    #[test]
    fn test_bitreader_single_bits() {
        let data = vec![0b10110010];
        let mut r = BitReader::new(&data);
        assert_eq!(r.read_bit(), Some(true));
        assert_eq!(r.read_bit(), Some(false));
        assert_eq!(r.read_bit(), Some(true));
        assert_eq!(r.read_bit(), Some(true));
        assert_eq!(r.read_bit(), Some(false));
        assert_eq!(r.read_bit(), Some(false));
        assert_eq!(r.read_bit(), Some(true));
        assert_eq!(r.read_bit(), Some(false));
        assert_eq!(r.read_bit(), None);
    }

    #[test]
    fn test_bitreader_read_bits() {
        let data = vec![0b10101100];
        let mut r = BitReader::new(&data);
        assert_eq!(r.read_bits(4), Some(0b1010));
        assert_eq!(r.read_bits(4), Some(0b1100));
    }

    // ── Golomb-Rice coding roundtrip ────────────────────────────────

    #[test]
    fn test_golomb_rice_roundtrip() {
        let p = 4u8;
        let values = vec![0, 1, 5, 15, 16, 17, 100, 1000];

        for &val in &values {
            let mut w = BitWriter::new();
            w.write_golomb_rice(val, p);
            let encoded = w.finish();

            let mut r = BitReader::new(&encoded);
            let decoded = r.read_golomb_rice(p).unwrap();
            assert_eq!(
                decoded, val,
                "Golomb-Rice roundtrip failed for value {}",
                val
            );
        }
    }

    #[test]
    fn test_golomb_rice_multiple_values() {
        let p = 4u8;
        let values = vec![3, 7, 15, 0, 100];

        let mut w = BitWriter::new();
        for &val in &values {
            w.write_golomb_rice(val, p);
        }
        let encoded = w.finish();

        let mut r = BitReader::new(&encoded);
        for &expected in &values {
            let decoded = r.read_golomb_rice(p).unwrap();
            assert_eq!(decoded, expected);
        }
    }

    #[test]
    fn test_golomb_rice_bip158_params() {
        // Test with actual BIP158 P=19
        let p = BASIC_FILTER_P;
        let values = vec![0, 1, 500, 100_000, 784_930];

        let mut w = BitWriter::new();
        for &val in &values {
            w.write_golomb_rice(val, p);
        }
        let encoded = w.finish();

        let mut r = BitReader::new(&encoded);
        for &expected in &values {
            let decoded = r.read_golomb_rice(p).unwrap();
            assert_eq!(decoded, expected);
        }
    }

    // ── GCS filter construction and querying ────────────────────────

    #[test]
    fn test_gcs_empty() {
        let filter = GcsFilter::build(0, 0, BASIC_FILTER_P, BASIC_FILTER_M, &[]);
        assert_eq!(filter.n, 0);
        assert!(filter.data.is_empty());
        assert!(!filter.match_any(0, 0, b"anything"));
    }

    #[test]
    fn test_gcs_single_element() {
        let elem = b"hello world";
        let filter = GcsFilter::build(42, 43, BASIC_FILTER_P, BASIC_FILTER_M, &[elem.as_ref()]);
        assert_eq!(filter.n, 1);
        assert!(filter.match_any(42, 43, elem));
        // "goodbye" should (almost certainly) not match
        assert!(!filter.match_any(42, 43, b"goodbye"));
    }

    #[test]
    fn test_gcs_multiple_elements() {
        let elements: Vec<&[u8]> = vec![b"alice", b"bob", b"charlie", b"dave"];
        let filter = GcsFilter::build(1, 2, BASIC_FILTER_P, BASIC_FILTER_M, &elements);
        assert_eq!(filter.n, 4);

        // All inserted elements should match
        for elem in &elements {
            assert!(filter.match_any(1, 2, elem), "should match {:?}", elem);
        }

        // Non-inserted elements should (almost certainly) not match
        assert!(!filter.match_any(1, 2, b"eve"));
        assert!(!filter.match_any(1, 2, b"frank"));
    }

    #[test]
    fn test_gcs_match_any_of() {
        let elements: Vec<&[u8]> = vec![b"one", b"two", b"three"];
        let filter = GcsFilter::build(10, 20, BASIC_FILTER_P, BASIC_FILTER_M, &elements);

        // Should match when one candidate is in the filter
        let candidates: Vec<&[u8]> = vec![b"zero", b"two", b"four"];
        assert!(filter.match_any_of(10, 20, &candidates));

        // Should not match when no candidates are in the filter
        let non_candidates: Vec<&[u8]> = vec![b"zero", b"four", b"five"];
        assert!(!filter.match_any_of(10, 20, &non_candidates));
    }

    #[test]
    fn test_gcs_match_any_of_empty() {
        let elements: Vec<&[u8]> = vec![b"a", b"b"];
        let filter = GcsFilter::build(1, 2, BASIC_FILTER_P, BASIC_FILTER_M, &elements);
        assert!(!filter.match_any_of(1, 2, &[]));

        let empty_filter = GcsFilter::build(1, 2, BASIC_FILTER_P, BASIC_FILTER_M, &[]);
        assert!(!empty_filter.match_any_of(1, 2, &[b"a"]));
    }

    #[test]
    fn test_gcs_deduplication() {
        // Duplicate elements should be deduped
        let elements: Vec<&[u8]> = vec![b"same", b"same", b"same"];
        let filter = GcsFilter::build(0, 0, BASIC_FILTER_P, BASIC_FILTER_M, &elements);
        assert_eq!(filter.n, 1);
    }

    #[test]
    fn test_gcs_wrong_key_no_match() {
        let elem = b"secret";
        let filter = GcsFilter::build(1, 2, BASIC_FILTER_P, BASIC_FILTER_M, &[elem.as_ref()]);
        // Querying with wrong key should not match
        assert!(!filter.match_any(3, 4, elem));
    }

    // ── GCS serialization ───────────────────────────────────────────

    #[test]
    fn test_gcs_serialize_empty() {
        let filter = GcsFilter::build(0, 0, BASIC_FILTER_P, BASIC_FILTER_M, &[]);
        let serialized = filter.serialize();
        assert_eq!(serialized, vec![0]); // CompactSize(0)

        let deserialized = GcsFilter::deserialize_basic(&serialized).unwrap();
        assert_eq!(deserialized.n, 0);
    }

    #[test]
    fn test_gcs_serialize_roundtrip() {
        let elements: Vec<&[u8]> = vec![b"foo", b"bar", b"baz"];
        let filter = GcsFilter::build_basic(&[0x11; 32], &elements);

        let serialized = filter.serialize();
        let deserialized = GcsFilter::deserialize_basic(&serialized).unwrap();

        assert_eq!(deserialized.n, filter.n);
        assert_eq!(deserialized.data, filter.data);

        // Deserialized filter should still match original elements
        let (k0, k1) = key_from_block_hash(&[0x11; 32]);
        for elem in &elements {
            assert!(deserialized.match_any(k0, k1, elem));
        }
    }

    #[test]
    fn test_gcs_build_basic() {
        let block_hash = [0xaa; 32];
        let elements: Vec<&[u8]> = vec![b"script1", b"script2"];
        let filter = GcsFilter::build_basic(&block_hash, &elements);
        assert_eq!(filter.n, 2);
        assert_eq!(filter.p, BASIC_FILTER_P);
        assert_eq!(filter.m, BASIC_FILTER_M);

        let (k0, k1) = key_from_block_hash(&block_hash);
        assert!(filter.match_any(k0, k1, b"script1"));
        assert!(filter.match_any(k0, k1, b"script2"));
        assert!(!filter.match_any(k0, k1, b"script3"));
    }

    // ── Unary coding edge cases ─────────────────────────────────────

    #[test]
    fn test_unary_coding_roundtrip() {
        for val in [0, 1, 2, 7, 15, 31] {
            let mut w = BitWriter::new();
            w.write_unary(val);
            let encoded = w.finish();

            let mut r = BitReader::new(&encoded);
            let decoded = r.read_unary().unwrap();
            assert_eq!(decoded, val, "unary roundtrip failed for {}", val);
        }
    }

    #[test]
    fn test_larger_filter() {
        // Build a filter with many elements and verify no false negatives
        let elements: Vec<Vec<u8>> = (0u16..200).map(|i| i.to_le_bytes().to_vec()).collect();
        let elem_refs: Vec<&[u8]> = elements.iter().map(|e| e.as_slice()).collect();

        let filter = GcsFilter::build(100, 200, BASIC_FILTER_P, BASIC_FILTER_M, &elem_refs);
        assert_eq!(filter.n, 200);

        // All elements must match (zero false negatives)
        for elem in &elements {
            assert!(
                filter.match_any(100, 200, elem),
                "false negative for {:?}",
                elem
            );
        }
    }
}
