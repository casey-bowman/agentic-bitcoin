//! MuHash3072 — Rolling (incremental) multiset hash
//!
//! Implements the 3072-bit multiplicative hash used by Bitcoin Core to compute
//! an incremental commitment over the UTXO set (introduced in Bitcoin Core
//! 0.21 / `gettxoutsetinfo "muhash"`).
//!
//! # Algorithm
//!
//! MuHash operates in the multiplicative group (Z/pZ)* where
//! `p = 2^3072 − 1103717` (a safe prime).
//!
//! Each data element is hashed to a group element by:
//! 1. SHA-256 the input data to get a 32-byte seed.
//! 2. Expand that seed to 384 bytes (3072 bits) by computing
//!    `SHA-256(seed || le32(i))` for i = 0..11.
//! 3. Interpret the 384 bytes as a little-endian integer and reduce mod p.
//!
//! The set hash maintains two accumulators — a numerator and denominator:
//! - **Insert**: `numerator *= hash_to_element(data)`
//! - **Remove**: `denominator *= hash_to_element(data)`
//! - **Finalize**: `SHA-256(numerator * denominator^{-1} mod p)`
//!
//! This allows O(1) insertions and removals without reprocessing the set.
//!
//! # Big integer arithmetic
//!
//! A 3072-bit integer is represented as 48 × u64 limbs in little-endian
//! order. The prime's special form `2^3072 − c` allows efficient modular
//! reduction via Barrett-style folding.

use crate::hashing::sha256;
use crate::primitives::Hash256;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Number of u64 limbs in a 3072-bit number.
const LIMBS: usize = 48;

/// The small constant c such that p = 2^3072 - c.
const PRIME_DIFF: u64 = 1103717;

// ---------------------------------------------------------------------------
// Num3072 — 3072-bit unsigned integer
// ---------------------------------------------------------------------------

/// A 3072-bit unsigned integer stored as 48 little-endian u64 limbs.
#[derive(Clone)]
struct Num3072 {
    limbs: [u64; LIMBS],
}

impl std::fmt::Debug for Num3072 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Num3072([{:#x}, ...])", self.limbs[0])
    }
}

impl PartialEq for Num3072 {
    fn eq(&self, other: &Self) -> bool {
        self.limbs == other.limbs
    }
}
impl Eq for Num3072 {}

impl Num3072 {
    /// Zero.
    const fn zero() -> Self {
        Num3072 {
            limbs: [0u64; LIMBS],
        }
    }

    /// One (the multiplicative identity).
    fn one() -> Self {
        let mut n = Self::zero();
        n.limbs[0] = 1;
        n
    }

    /// Create from a little-endian byte slice (up to 384 bytes).
    fn from_le_bytes(bytes: &[u8]) -> Self {
        let mut n = Self::zero();
        for (i, chunk) in bytes.chunks(8).enumerate() {
            if i >= LIMBS {
                break;
            }
            let mut buf = [0u8; 8];
            buf[..chunk.len()].copy_from_slice(chunk);
            n.limbs[i] = u64::from_le_bytes(buf);
        }
        n
    }

    /// Serialize to 384 little-endian bytes.
    fn to_le_bytes(&self) -> [u8; 384] {
        let mut bytes = [0u8; 384];
        for (i, limb) in self.limbs.iter().enumerate() {
            bytes[i * 8..(i + 1) * 8].copy_from_slice(&limb.to_le_bytes());
        }
        bytes
    }

    /// Check if this number is zero.
    fn is_zero(&self) -> bool {
        self.limbs.iter().all(|&x| x == 0)
    }

    /// Reduce mod p = 2^3072 − PRIME_DIFF.
    ///
    /// Assumes `self` is at most 2 * p (i.e. the result of an addition or
    /// a reduction step). For post-multiplication reduction, use
    /// `reduce_wide`.
    fn reduce_mod_p(&mut self) {
        // If self >= p, subtract p (i.e. add PRIME_DIFF and clear the carry)
        // Check if self >= 2^3072 - PRIME_DIFF
        // First check if all limbs are max: if the top bits are all 1s
        // and the low part >= 2^3072 - PRIME_DIFF

        // Simple approach: try subtracting p, check for underflow
        let mut tmp = [0u64; LIMBS];

        // p = 2^3072 - PRIME_DIFF. In 48 little-endian u64 limbs:
        //   limbs[0] = 2^64 - PRIME_DIFF, limbs[1..47] = u64::MAX
        // We compute self - p and check for underflow.

        // Subtraction: self - p
        let p0: u64 = 0u64.wrapping_sub(PRIME_DIFF); // 2^64 - PRIME_DIFF
        let (d, b) = self.limbs[0].overflowing_sub(p0);
        tmp[0] = d;
        let mut borrow = b as u64;

        for (i, tmp_i) in tmp[1..LIMBS].iter_mut().enumerate() {
            let i = i + 1;
            let (d, b1) = self.limbs[i].overflowing_sub(u64::MAX);
            let (d, b2) = d.overflowing_sub(borrow);
            *tmp_i = d;
            borrow = (b1 as u64) + (b2 as u64);
        }

        // If borrow == 0, self >= p, so use tmp; otherwise keep self
        if borrow == 0 {
            self.limbs = tmp;
        }
    }

    /// Multiply self by other mod p.
    ///
    /// Uses schoolbook multiplication into a double-width product,
    /// then reduces mod p using the special prime form.
    fn mul_mod_p(&self, other: &Num3072) -> Num3072 {
        // Double-width product: 96 limbs
        let mut product = [0u64; LIMBS * 2];

        // Schoolbook multiply
        for i in 0..LIMBS {
            let mut carry: u64 = 0;
            for j in 0..LIMBS {
                let (lo, hi) = mul_u64(self.limbs[i], other.limbs[j]);
                let (sum, c1) = product[i + j].overflowing_add(lo);
                let (sum, c2) = sum.overflowing_add(carry);
                product[i + j] = sum;
                carry = hi + (c1 as u64) + (c2 as u64);
            }
            product[i + LIMBS] = carry;
        }

        // Reduce mod p = 2^3072 - PRIME_DIFF
        // product = product_hi * 2^3072 + product_lo
        // ≡ product_lo + product_hi * PRIME_DIFF (mod p)
        // Since product_hi can be up to 3072 bits and PRIME_DIFF is small,
        // the result of product_hi * PRIME_DIFF fits in ~3072+21 bits,
        // so we may need one more reduction step.
        reduce_wide(&product)
    }

    /// Compute modular inverse: self^{-1} mod p using Fermat's little theorem.
    ///
    /// a^{-1} = a^{p-2} mod p.
    ///
    /// Uses a square-and-multiply chain optimized for p - 2 = 2^3072 - 1103719.
    fn mod_inverse(&self) -> Num3072 {
        if self.is_zero() {
            // Inverse of zero doesn't exist; return one as a sentinel
            return Num3072::one();
        }

        // p - 2 = 2^3072 - PRIME_DIFF - 2 = 2^3072 - 1103719
        // We need self^(p-2) mod p.
        //
        // Strategy: compute self^(2^3072 - 1) using repeated squaring,
        // then divide by self^(PRIME_DIFF + 1) = self^1103718.
        //
        // But that still requires computing self^1103718. Instead, let's
        // use a direct square-and-multiply approach on the exponent p-2.
        //
        // p - 2 in binary is 3072 bits of all 1s, minus 1103719 which
        // flips a few low bits. Since this is complex, we'll use a
        // generic binary exponentiation.

        // Actually, let's use a simpler approach:
        // p - 2 = (2^3072 - 1) - (PRIME_DIFF + 1)
        // = (2^3072 - 1) - 1103718
        //
        // The exponent as a Num3072:
        let mut exp = Num3072::zero();
        // Set all bits: 2^3072 - 1
        for limb in exp.limbs.iter_mut() {
            *limb = u64::MAX;
        }
        // Subtract (PRIME_DIFF + 1) = 1103718
        // exp.limbs[0] = u64::MAX - 1103718 + 1... wait, we want (2^3072 - 1) - 1103718
        // = 2^3072 - 1103719 = 2^3072 - (PRIME_DIFF + 2)
        // So exp = all 1s, minus 1103718 from the bottom
        let sub_val: u64 = PRIME_DIFF + 1; // 1103718
        let (result, borrow) = exp.limbs[0].overflowing_sub(sub_val);
        exp.limbs[0] = result;
        if borrow {
            // Propagate borrow
            for i in 1..LIMBS {
                if exp.limbs[i] > 0 {
                    exp.limbs[i] -= 1;
                    break;
                }
                exp.limbs[i] = u64::MAX;
            }
        }

        // Binary exponentiation: result = self^exp mod p
        self.pow_mod_p(&exp)
    }

    /// Compute self^exp mod p using binary (square-and-multiply) exponentiation.
    fn pow_mod_p(&self, exp: &Num3072) -> Num3072 {
        let mut result = Num3072::one();
        let mut base = self.clone();

        // Iterate over bits from LSB to MSB
        for i in 0..LIMBS {
            let mut word = exp.limbs[i];
            for _ in 0..64 {
                if word & 1 == 1 {
                    result = result.mul_mod_p(&base);
                }
                base = base.mul_mod_p(&base);
                word >>= 1;
            }
        }

        result
    }
}

/// Multiply two u64 values, returning (lo, hi) of the 128-bit result.
#[inline(always)]
fn mul_u64(a: u64, b: u64) -> (u64, u64) {
    let result = (a as u128) * (b as u128);
    (result as u64, (result >> 64) as u64)
}

/// Reduce a double-width product (96 limbs) modulo p = 2^3072 - PRIME_DIFF.
///
/// Uses the identity: `x * 2^3072 ≡ x * PRIME_DIFF (mod p)`.
fn reduce_wide(product: &[u64; LIMBS * 2]) -> Num3072 {
    // Split into lo (limbs 0..47) and hi (limbs 48..95)
    // result = lo + hi * PRIME_DIFF
    let mut result = Num3072::zero();

    // Start with lo
    result.limbs.copy_from_slice(&product[..LIMBS]);

    // Add hi * PRIME_DIFF
    let mut carry: u128 = 0;
    for i in 0..LIMBS {
        let hi_limb = product[LIMBS + i] as u128;
        let prod = hi_limb * (PRIME_DIFF as u128) + (result.limbs[i] as u128) + carry;
        result.limbs[i] = prod as u64;
        carry = prod >> 64;
    }

    // carry might be nonzero — it represents overflow above 2^3072.
    // Apply the identity again: carry * 2^3072 ≡ carry * PRIME_DIFF
    while carry > 0 {
        let mut c2: u128 = carry * (PRIME_DIFF as u128);
        for i in 0..LIMBS {
            c2 += result.limbs[i] as u128;
            result.limbs[i] = c2 as u64;
            c2 >>= 64;
            if c2 == 0 && i > 0 {
                break;
            }
        }
        carry = c2;
    }

    // Final reduction: ensure result < p
    result.reduce_mod_p();
    result
}

// ---------------------------------------------------------------------------
// Hash data to a 3072-bit group element
// ---------------------------------------------------------------------------

/// Hash arbitrary data to a Num3072 element in [1, p-1].
///
/// 1. Compute `seed = SHA-256(data)`.
/// 2. Expand to 384 bytes: for i in 0..12, compute `SHA-256(seed || le32(i))`.
/// 3. Interpret as little-endian integer and reduce mod p.
/// 4. If result is zero (astronomically unlikely), return 1.
fn hash_to_num3072(data: &[u8]) -> Num3072 {
    let seed = sha256(data);
    let seed_bytes = seed.as_bytes();

    // Expand to 384 bytes
    let mut expanded = [0u8; 384];
    for i in 0u32..12 {
        let mut input = Vec::with_capacity(36);
        input.extend_from_slice(seed_bytes);
        input.extend_from_slice(&i.to_le_bytes());
        let chunk_hash = sha256(&input);
        expanded[i as usize * 32..(i as usize + 1) * 32].copy_from_slice(chunk_hash.as_bytes());
    }

    let mut num = Num3072::from_le_bytes(&expanded);
    num.reduce_mod_p();

    // Ensure nonzero (probability of zero is negligible, but be safe)
    if num.is_zero() {
        return Num3072::one();
    }
    num
}

// ---------------------------------------------------------------------------
// MuHash3072 — the public API
// ---------------------------------------------------------------------------

/// A rolling multiset hash over 3072-bit multiplicative group.
///
/// Supports O(1) insertion and removal of elements, and produces a
/// 256-bit digest of the entire set.
///
/// # Example
///
/// ```ignore
/// let mut hash = MuHash3072::new();
/// hash.insert(b"utxo_1_data");
/// hash.insert(b"utxo_2_data");
/// let digest = hash.finalize();
///
/// // Removing an element is also O(1):
/// hash.remove(b"utxo_1_data");
/// ```
#[derive(Debug, Clone)]
pub struct MuHash3072 {
    numerator: Num3072,
    denominator: Num3072,
}

impl MuHash3072 {
    /// Create a new empty MuHash (identity element).
    pub fn new() -> Self {
        MuHash3072 {
            numerator: Num3072::one(),
            denominator: Num3072::one(),
        }
    }

    /// Insert a data element into the multiset.
    pub fn insert(&mut self, data: &[u8]) {
        let elem = hash_to_num3072(data);
        self.numerator = self.numerator.mul_mod_p(&elem);
    }

    /// Remove a data element from the multiset.
    ///
    /// The element must have been previously inserted; otherwise the
    /// resulting hash will be meaningless (but not undefined).
    pub fn remove(&mut self, data: &[u8]) {
        let elem = hash_to_num3072(data);
        self.denominator = self.denominator.mul_mod_p(&elem);
    }

    /// Combine two MuHash states (union of multisets).
    pub fn combine(&mut self, other: &MuHash3072) {
        self.numerator = self.numerator.mul_mod_p(&other.numerator);
        self.denominator = self.denominator.mul_mod_p(&other.denominator);
    }

    /// Compute the 256-bit digest of the current multiset.
    ///
    /// Computes `SHA-256(numerator * denominator^{-1} mod p)` serialized
    /// as 384 little-endian bytes.
    pub fn finalize(&self) -> Hash256 {
        let inv = self.denominator.mod_inverse();
        let result = self.numerator.mul_mod_p(&inv);
        let bytes = result.to_le_bytes();
        sha256(&bytes)
    }

    /// Check if this is the empty (identity) hash.
    pub fn is_empty(&self) -> bool {
        self.numerator == self.denominator
    }
}

impl Default for MuHash3072 {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_num3072_one_is_multiplicative_identity() {
        let one = Num3072::one();
        let a = hash_to_num3072(b"test_data");
        let result = a.mul_mod_p(&one);
        assert_eq!(result, a);
    }

    #[test]
    fn test_num3072_mul_commutative() {
        let a = hash_to_num3072(b"alpha");
        let b = hash_to_num3072(b"beta");
        let ab = a.mul_mod_p(&b);
        let ba = b.mul_mod_p(&a);
        assert_eq!(ab, ba);
    }

    #[test]
    fn test_num3072_mod_inverse() {
        let a = hash_to_num3072(b"test_inverse");
        let a_inv = a.mod_inverse();
        let product = a.mul_mod_p(&a_inv);
        // product should be 1 mod p
        assert_eq!(product, Num3072::one());
    }

    #[test]
    fn test_muhash_empty() {
        let h = MuHash3072::new();
        assert!(h.is_empty());
    }

    #[test]
    fn test_muhash_deterministic() {
        let mut h1 = MuHash3072::new();
        h1.insert(b"element_a");
        h1.insert(b"element_b");

        let mut h2 = MuHash3072::new();
        h2.insert(b"element_a");
        h2.insert(b"element_b");

        assert_eq!(h1.finalize(), h2.finalize());
    }

    #[test]
    fn test_muhash_order_independent() {
        let mut h1 = MuHash3072::new();
        h1.insert(b"element_a");
        h1.insert(b"element_b");
        h1.insert(b"element_c");

        let mut h2 = MuHash3072::new();
        h2.insert(b"element_c");
        h2.insert(b"element_a");
        h2.insert(b"element_b");

        assert_eq!(h1.finalize(), h2.finalize());
    }

    #[test]
    fn test_muhash_insert_remove() {
        let mut h = MuHash3072::new();
        h.insert(b"keep_me");
        h.insert(b"remove_me");
        h.remove(b"remove_me");

        let mut h_single = MuHash3072::new();
        h_single.insert(b"keep_me");

        assert_eq!(h.finalize(), h_single.finalize());
    }

    #[test]
    fn test_muhash_insert_all_remove_all_is_empty() {
        let mut h = MuHash3072::new();
        h.insert(b"one");
        h.insert(b"two");
        h.insert(b"three");

        h.remove(b"one");
        h.remove(b"two");
        h.remove(b"three");

        let empty = MuHash3072::new();
        assert_eq!(h.finalize(), empty.finalize());
    }

    #[test]
    fn test_muhash_different_sets_different_hashes() {
        let mut h1 = MuHash3072::new();
        h1.insert(b"set_1_element");

        let mut h2 = MuHash3072::new();
        h2.insert(b"set_2_element");

        assert_ne!(h1.finalize(), h2.finalize());
    }

    #[test]
    fn test_muhash_combine() {
        // h1 = {a, b}
        let mut h1 = MuHash3072::new();
        h1.insert(b"a");
        h1.insert(b"b");

        // h2 = {c}
        let mut h2 = MuHash3072::new();
        h2.insert(b"c");

        // combined = {a, b, c}
        let mut combined = h1.clone();
        combined.combine(&h2);

        // direct = {a, b, c}
        let mut direct = MuHash3072::new();
        direct.insert(b"a");
        direct.insert(b"b");
        direct.insert(b"c");

        assert_eq!(combined.finalize(), direct.finalize());
    }

    #[test]
    fn test_muhash_single_element() {
        let mut h = MuHash3072::new();
        h.insert(b"hello world");
        let digest = h.finalize();
        // Just verify it produces a non-zero 32-byte hash
        assert_ne!(digest, Hash256::zero());
    }

    #[test]
    fn test_varint_roundtrip_in_hash() {
        // Verify that encoding data into the hash produces consistent results
        let mut h1 = MuHash3072::new();
        let data1 = vec![1u8, 2, 3, 4, 5];
        h1.insert(&data1);

        let mut h2 = MuHash3072::new();
        h2.insert(&[1u8, 2, 3, 4, 5]);

        assert_eq!(h1.finalize(), h2.finalize());
    }

    #[test]
    fn test_num3072_reduce_mod_p() {
        // Create a number equal to p (should reduce to 0)
        let mut p = Num3072::zero();
        for limb in p.limbs.iter_mut() {
            *limb = u64::MAX;
        }
        // p = 2^3072 - 1 in limbs, but actual p = 2^3072 - PRIME_DIFF
        // So 2^3072 - 1 = p + PRIME_DIFF - 1, which should reduce to PRIME_DIFF - 1
        p.reduce_mod_p();
        assert_eq!(p.limbs[0], PRIME_DIFF - 1);
        for i in 1..LIMBS {
            assert_eq!(p.limbs[i], 0);
        }
    }

    #[test]
    fn test_hash_to_num3072_nonzero() {
        // Many different inputs should all produce nonzero elements
        for i in 0..20 {
            let data = format!("test_element_{}", i);
            let num = hash_to_num3072(data.as_bytes());
            assert!(
                !num.is_zero(),
                "hash_to_num3072 produced zero for: {}",
                data
            );
        }
    }

    #[test]
    fn test_muhash_incremental_matches_batch() {
        // Build a set incrementally vs. all at once
        let elements: Vec<Vec<u8>> = (0..10)
            .map(|i| format!("utxo_{}", i).into_bytes())
            .collect();

        // Incremental
        let mut incremental = MuHash3072::new();
        for elem in &elements {
            incremental.insert(elem);
        }

        // Batch (same order — should be identical since MuHash is order-independent)
        let mut batch = MuHash3072::new();
        for elem in elements.iter().rev() {
            batch.insert(elem);
        }

        assert_eq!(incremental.finalize(), batch.finalize());
    }
}
