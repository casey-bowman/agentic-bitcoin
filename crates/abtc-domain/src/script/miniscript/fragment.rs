// Miniscript fragment AST
//
// Defines the Terminal enum representing all miniscript fragment types,
// and the Miniscript struct which pairs a fragment with its inferred type.
//
// Reference: https://bitcoin.sipa.be/miniscript/

use std::fmt;

use crate::wallet::keys::PublicKey;
use super::types::{MiniscriptType, BaseType};

// ---------------------------------------------------------------------------
// Terminal — every possible miniscript fragment
// ---------------------------------------------------------------------------

/// A miniscript terminal (fragment node).
///
/// Each variant corresponds to one of the fragment types defined in the
/// miniscript specification.  Recursive variants box their children to
/// keep the enum size bounded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Terminal {
    // ── Atoms ──────────────────────────────────────────────────────────

    /// `1` — always true (OP_1)
    True,

    /// `0` — always false (OP_0)
    False,

    /// `pk_k(key)` — push key, OP_CHECKSIG  (type K)
    PkK(PublicKey),

    /// `pk_h(hash)` — OP_DUP OP_HASH160 <hash> OP_EQUALVERIFY OP_CHECKSIG  (type K)
    PkH([u8; 20]),

    /// `older(n)` — <n> OP_CHECKSEQUENCEVERIFY  (type B)
    Older(u32),

    /// `after(n)` — <n> OP_CHECKLOCKTIMEVERIFY  (type B)
    After(u32),

    /// `sha256(h)` — OP_SIZE <32> OP_EQUALVERIFY OP_SHA256 <hash> OP_EQUAL  (type B)
    Sha256([u8; 32]),

    /// `hash256(h)` — OP_SIZE <32> OP_EQUALVERIFY OP_HASH256 <hash> OP_EQUAL  (type B)
    Hash256([u8; 32]),

    /// `ripemd160(h)` — OP_SIZE <32> OP_EQUALVERIFY OP_RIPEMD160 <hash> OP_EQUAL  (type B)
    Ripemd160([u8; 20]),

    /// `hash160(h)` — OP_SIZE <32> OP_EQUALVERIFY OP_HASH160 <hash> OP_EQUAL  (type B)
    Hash160([u8; 20]),

    // ── Combinators ───────────────────────────────────────────────────

    /// `and_v(X,Y)` — [X] [Y]  (V ∧ B/K/V)
    AndV(Box<Miniscript>, Box<Miniscript>),

    /// `and_b(X,Y)` — [X] [Y] OP_BOOLAND  (B ∧ W → B)
    AndB(Box<Miniscript>, Box<Miniscript>),

    /// `or_b(X,Y)` — [X] [Y] OP_BOOLOR  (Bd ∧ Wd → Bdu)
    OrB(Box<Miniscript>, Box<Miniscript>),

    /// `or_c(X,Y)` — [X] OP_NOTIF [Y] OP_ENDIF  (Bdu ∧ V → B)
    OrC(Box<Miniscript>, Box<Miniscript>),

    /// `or_d(X,Y)` — [X] OP_IFDUP OP_NOTIF [Y] OP_ENDIF  (Bdu ∧ B → B)
    OrD(Box<Miniscript>, Box<Miniscript>),

    /// `or_i(X,Y)` — OP_IF [X] OP_ELSE [Y] OP_ENDIF
    OrI(Box<Miniscript>, Box<Miniscript>),

    /// `thresh(k, X1, X2, ...)` — [X1] [X2] OP_ADD ... <k> OP_EQUAL
    Thresh(usize, Vec<Miniscript>),

    /// `multi(k, key1, key2, ...)` — <k> <keys...> <n> OP_CHECKMULTISIG  (type B)
    Multi(usize, Vec<PublicKey>),

    /// `multi_a(k, key1, key2, ...)` — Tapscript CHECKSIGADD-based multi  (type B)
    /// <key1> OP_CHECKSIG <key2> OP_CHECKSIGADD ... <k> OP_NUMEQUAL
    MultiA(usize, Vec<PublicKey>),

    // ── Wrappers (single-child type converters) ───────────────────────

    /// `a:X` — OP_TOALTSTACK [X] OP_FROMALTSTACK  (B → W)
    Alt(Box<Miniscript>),

    /// `s:X` — OP_SWAP [X]  (Bo → W)
    Swap(Box<Miniscript>),

    /// `c:X` — [X] OP_CHECKSIG  (K → B)
    Check(Box<Miniscript>),

    /// `d:X` — OP_DUP OP_IF [X] OP_ENDIF  (V → Bdu)
    DupIf(Box<Miniscript>),

    /// `v:X` — [X] OP_VERIFY (or merged EQUALVERIFY, etc.)  (B → V)
    Verify(Box<Miniscript>),

    /// `j:X` — OP_SIZE OP_0NOTEQUAL OP_IF [X] OP_ENDIF  (Bn → Bd)
    NonZero(Box<Miniscript>),

    /// `n:X` — [X] OP_0NOTEQUAL  (B → Bu)
    ZeroNotEqual(Box<Miniscript>),
}

// ---------------------------------------------------------------------------
// Miniscript — a typed fragment tree
// ---------------------------------------------------------------------------

/// A miniscript expression: a fragment node annotated with its inferred type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Miniscript {
    /// The fragment at this node.
    pub node: Terminal,
    /// The inferred miniscript type.
    pub ty: MiniscriptType,
}

impl Miniscript {
    // ── Atom constructors ─────────────────────────────────────────────

    /// Construct `1` (always-true).
    pub fn ms_true() -> Self {
        Self {
            node: Terminal::True,
            ty: super::types::type_true(),
        }
    }

    /// Construct `0` (always-false).
    pub fn ms_false() -> Self {
        Self {
            node: Terminal::False,
            ty: super::types::type_false(),
        }
    }

    /// Construct `pk_k(key)`.
    pub fn pk_k(key: PublicKey) -> Self {
        Self {
            node: Terminal::PkK(key),
            ty: super::types::type_pk_k(),
        }
    }

    /// Construct `pk_h(hash)`.
    pub fn pk_h(hash: [u8; 20]) -> Self {
        Self {
            node: Terminal::PkH(hash),
            ty: super::types::type_pk_h(),
        }
    }

    /// Construct `older(n)`.  Panics if n == 0 or bit 31 is set.
    pub fn older(n: u32) -> Self {
        assert!(n > 0 && n & (1 << 31) == 0, "older: n must be in 1..2^31");
        Self {
            node: Terminal::Older(n),
            ty: super::types::type_older(),
        }
    }

    /// Construct `after(n)`.  Panics if n == 0 or n > 500_000_000.
    pub fn after(n: u32) -> Self {
        assert!(n > 0 && n <= 500_000_000, "after: n must be in 1..=500_000_000");
        Self {
            node: Terminal::After(n),
            ty: super::types::type_after(),
        }
    }

    /// Construct `sha256(hash)`.
    pub fn sha256(hash: [u8; 32]) -> Self {
        Self {
            node: Terminal::Sha256(hash),
            ty: super::types::type_hash(),
        }
    }

    /// Construct `hash256(hash)`.
    pub fn hash256(hash: [u8; 32]) -> Self {
        Self {
            node: Terminal::Hash256(hash),
            ty: super::types::type_hash(),
        }
    }

    /// Construct `ripemd160(hash)`.
    pub fn ripemd160(hash: [u8; 20]) -> Self {
        Self {
            node: Terminal::Ripemd160(hash),
            ty: super::types::type_hash(),
        }
    }

    /// Construct `hash160(hash)`.
    pub fn hash160(hash: [u8; 20]) -> Self {
        Self {
            node: Terminal::Hash160(hash),
            ty: super::types::type_hash(),
        }
    }

    /// Construct `multi(k, keys)`.
    pub fn multi(k: usize, keys: Vec<PublicKey>) -> Self {
        assert!(k >= 1 && k <= keys.len(), "multi: k must be in 1..=n");
        assert!(keys.len() <= 20, "multi: at most 20 keys");
        Self {
            node: Terminal::Multi(k, keys),
            ty: super::types::type_multi(),
        }
    }

    /// Construct `multi_a(k, keys)` (Tapscript).
    pub fn multi_a(k: usize, keys: Vec<PublicKey>) -> Self {
        assert!(k >= 1 && k <= keys.len(), "multi_a: k must be in 1..=n");
        Self {
            node: Terminal::MultiA(k, keys),
            ty: super::types::type_multi_a(),
        }
    }

    // ── Combinator constructors ───────────────────────────────────────

    /// Construct `and_v(X, Y)`.
    pub fn and_v(left: Miniscript, right: Miniscript) -> Self {
        let ty = super::types::type_and_v(&left.ty, &right.ty)
            .expect("and_v: type check failed");
        Self {
            node: Terminal::AndV(Box::new(left), Box::new(right)),
            ty,
        }
    }

    /// Construct `and_b(X, Y)`.
    pub fn and_b(left: Miniscript, right: Miniscript) -> Self {
        let ty = super::types::type_and_b(&left.ty, &right.ty)
            .expect("and_b: type check failed");
        Self {
            node: Terminal::AndB(Box::new(left), Box::new(right)),
            ty,
        }
    }

    /// Construct `or_b(X, Y)`.
    pub fn or_b(left: Miniscript, right: Miniscript) -> Self {
        let ty = super::types::type_or_b(&left.ty, &right.ty)
            .expect("or_b: type check failed");
        Self {
            node: Terminal::OrB(Box::new(left), Box::new(right)),
            ty,
        }
    }

    /// Construct `or_c(X, Y)`.
    pub fn or_c(left: Miniscript, right: Miniscript) -> Self {
        let ty = super::types::type_or_c(&left.ty, &right.ty)
            .expect("or_c: type check failed");
        Self {
            node: Terminal::OrC(Box::new(left), Box::new(right)),
            ty,
        }
    }

    /// Construct `or_d(X, Y)`.
    pub fn or_d(left: Miniscript, right: Miniscript) -> Self {
        let ty = super::types::type_or_d(&left.ty, &right.ty)
            .expect("or_d: type check failed");
        Self {
            node: Terminal::OrD(Box::new(left), Box::new(right)),
            ty,
        }
    }

    /// Construct `or_i(X, Y)`.
    pub fn or_i(left: Miniscript, right: Miniscript) -> Self {
        let ty = super::types::type_or_i(&left.ty, &right.ty)
            .expect("or_i: type check failed");
        Self {
            node: Terminal::OrI(Box::new(left), Box::new(right)),
            ty,
        }
    }

    /// Construct `thresh(k, subs)`.
    pub fn thresh(k: usize, subs: Vec<Miniscript>) -> Self {
        assert!(k >= 1 && k <= subs.len(), "thresh: k must be in 1..=n");
        let sub_types: Vec<_> = subs.iter().map(|s| s.ty.clone()).collect();
        let ty = super::types::type_thresh(k, &sub_types)
            .expect("thresh: type check failed");
        Self {
            node: Terminal::Thresh(k, subs),
            ty,
        }
    }

    // ── Wrapper constructors ──────────────────────────────────────────

    /// Construct `a:X` (alt-stack wrapper).
    pub fn alt(inner: Miniscript) -> Self {
        let ty = super::types::type_alt(&inner.ty)
            .expect("alt: type check failed");
        Self {
            node: Terminal::Alt(Box::new(inner)),
            ty,
        }
    }

    /// Construct `s:X` (swap wrapper).
    pub fn swap(inner: Miniscript) -> Self {
        let ty = super::types::type_swap(&inner.ty)
            .expect("swap: type check failed");
        Self {
            node: Terminal::Swap(Box::new(inner)),
            ty,
        }
    }

    /// Construct `c:X` (checksig wrapper, K → B).
    pub fn check(inner: Miniscript) -> Self {
        let ty = super::types::type_check(&inner.ty)
            .expect("check: type check failed");
        Self {
            node: Terminal::Check(Box::new(inner)),
            ty,
        }
    }

    /// Construct `d:X` (dup-if wrapper).
    pub fn dupif(inner: Miniscript) -> Self {
        let ty = super::types::type_dupif(&inner.ty)
            .expect("dupif: type check failed");
        Self {
            node: Terminal::DupIf(Box::new(inner)),
            ty,
        }
    }

    /// Construct `v:X` (verify wrapper, B → V).
    pub fn verify(inner: Miniscript) -> Self {
        let ty = super::types::type_verify(&inner.ty)
            .expect("verify: type check failed");
        Self {
            node: Terminal::Verify(Box::new(inner)),
            ty,
        }
    }

    /// Construct `j:X` (non-zero wrapper).
    pub fn nonzero(inner: Miniscript) -> Self {
        let ty = super::types::type_nonzero(&inner.ty)
            .expect("nonzero: type check failed");
        Self {
            node: Terminal::NonZero(Box::new(inner)),
            ty,
        }
    }

    /// Construct `n:X` (zero-not-equal wrapper).
    pub fn zero_not_equal(inner: Miniscript) -> Self {
        let ty = super::types::type_zero_not_equal(&inner.ty)
            .expect("zero_not_equal: type check failed");
        Self {
            node: Terminal::ZeroNotEqual(Box::new(inner)),
            ty,
        }
    }

    // ── Convenience helpers ───────────────────────────────────────────

    /// `pk(key)` = `c:pk_k(key)` — the most common single-key check.
    pub fn pk(key: PublicKey) -> Self {
        Self::check(Self::pk_k(key))
    }

    /// `pkh(hash)` = `c:pk_h(hash)` — pubkey-hash check.
    pub fn pkh(hash: [u8; 20]) -> Self {
        Self::check(Self::pk_h(hash))
    }

    /// Returns the base type of this expression.
    pub fn base_type(&self) -> BaseType {
        self.ty.base
    }

    /// Returns true if this expression is guaranteed to leave a
    /// non-zero value on the stack upon satisfaction.
    pub fn is_non_zero_on_satisfy(&self) -> bool {
        self.ty.modifiers.u
    }
}

// ---------------------------------------------------------------------------
// Display — human-readable miniscript notation
// ---------------------------------------------------------------------------

impl fmt::Display for Miniscript {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.node.fmt(f)
    }
}

impl fmt::Display for Terminal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            // Atoms
            Terminal::True => write!(f, "1"),
            Terminal::False => write!(f, "0"),
            Terminal::PkK(key) => write!(f, "pk_k({})", hex::encode(&key.serialize())),
            Terminal::PkH(hash) => write!(f, "pk_h({})", hex::encode(hash)),
            Terminal::Older(n) => write!(f, "older({})", n),
            Terminal::After(n) => write!(f, "after({})", n),
            Terminal::Sha256(h) => write!(f, "sha256({})", hex::encode(h)),
            Terminal::Hash256(h) => write!(f, "hash256({})", hex::encode(h)),
            Terminal::Ripemd160(h) => write!(f, "ripemd160({})", hex::encode(h)),
            Terminal::Hash160(h) => write!(f, "hash160({})", hex::encode(h)),

            // Combinators
            Terminal::AndV(x, y) => write!(f, "and_v({},{})", x, y),
            Terminal::AndB(x, y) => write!(f, "and_b({},{})", x, y),
            Terminal::OrB(x, y) => write!(f, "or_b({},{})", x, y),
            Terminal::OrC(x, y) => write!(f, "or_c({},{})", x, y),
            Terminal::OrD(x, y) => write!(f, "or_d({},{})", x, y),
            Terminal::OrI(x, y) => write!(f, "or_i({},{})", x, y),
            Terminal::Thresh(k, subs) => {
                write!(f, "thresh({}", k)?;
                for sub in subs {
                    write!(f, ",{}", sub)?;
                }
                write!(f, ")")
            }
            Terminal::Multi(k, keys) => {
                write!(f, "multi({}", k)?;
                for key in keys {
                    write!(f, ",{}", hex::encode(&key.serialize()))?;
                }
                write!(f, ")")
            }
            Terminal::MultiA(k, keys) => {
                write!(f, "multi_a({}", k)?;
                for key in keys {
                    write!(f, ",{}", hex::encode(&key.serialize()))?;
                }
                write!(f, ")")
            }

            // Wrappers
            Terminal::Alt(x) => write!(f, "a:{}", x),
            Terminal::Swap(x) => write!(f, "s:{}", x),
            Terminal::Check(x) => write!(f, "c:{}", x),
            Terminal::DupIf(x) => write!(f, "d:{}", x),
            Terminal::Verify(x) => write!(f, "v:{}", x),
            Terminal::NonZero(x) => write!(f, "j:{}", x),
            Terminal::ZeroNotEqual(x) => write!(f, "n:{}", x),
        }
    }
}

// ---------------------------------------------------------------------------
// Hex helper (no external crate needed — project already has this pattern)
// ---------------------------------------------------------------------------

mod hex {
    /// Encode bytes as lowercase hex.
    pub fn encode(bytes: &[u8]) -> String {
        let mut s = String::with_capacity(bytes.len() * 2);
        for b in bytes {
            s.push_str(&format!("{:02x}", b));
        }
        s
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wallet::keys::PublicKey;

    /// Helper: create a dummy compressed public key from a byte seed.
    fn dummy_key(seed: u8) -> PublicKey {
        use crate::crypto::hashing::sha256;
        let hash = sha256(&[seed]);
        let mut secret = [0u8; 32];
        secret.copy_from_slice(hash.as_bytes());
        // Ensure valid scalar (set high byte to reasonable range)
        secret[0] = seed.wrapping_add(1).max(1);

        let secp = secp256k1::Secp256k1::new();
        let sk = secp256k1::SecretKey::from_slice(&secret)
            .expect("valid secret key");
        let pk = secp256k1::PublicKey::from_secret_key(&secp, &sk);
        PublicKey::from_bytes(&pk.serialize()).unwrap()
    }

    #[test]
    fn test_construct_true_false() {
        let t = Miniscript::ms_true();
        assert_eq!(t.base_type(), BaseType::B);
        let f = Miniscript::ms_false();
        assert_eq!(f.base_type(), BaseType::B);
    }

    #[test]
    fn test_construct_pk_k() {
        let key = dummy_key(1);
        let ms = Miniscript::pk_k(key);
        assert_eq!(ms.base_type(), BaseType::K);
    }

    #[test]
    fn test_construct_pk_convenience() {
        // pk(key) = c:pk_k(key) → type B
        let key = dummy_key(2);
        let ms = Miniscript::pk(key);
        assert_eq!(ms.base_type(), BaseType::B);
    }

    #[test]
    fn test_construct_pk_h() {
        let ms = Miniscript::pk_h([0xab; 20]);
        assert_eq!(ms.base_type(), BaseType::K);
    }

    #[test]
    fn test_construct_older_after() {
        let o = Miniscript::older(144);
        assert_eq!(o.base_type(), BaseType::B);
        let a = Miniscript::after(500_000_000);
        assert_eq!(a.base_type(), BaseType::B);
    }

    #[test]
    #[should_panic]
    fn test_older_zero_panics() {
        let _ = Miniscript::older(0);
    }

    #[test]
    #[should_panic]
    fn test_after_zero_panics() {
        let _ = Miniscript::after(0);
    }

    #[test]
    fn test_construct_hashes() {
        let s = Miniscript::sha256([0x11; 32]);
        assert_eq!(s.base_type(), BaseType::B);
        let h = Miniscript::hash256([0x22; 32]);
        assert_eq!(h.base_type(), BaseType::B);
        let r = Miniscript::ripemd160([0x33; 20]);
        assert_eq!(r.base_type(), BaseType::B);
        let h160 = Miniscript::hash160([0x44; 20]);
        assert_eq!(h160.base_type(), BaseType::B);
    }

    #[test]
    fn test_construct_multi() {
        let keys = vec![dummy_key(10), dummy_key(11), dummy_key(12)];
        let ms = Miniscript::multi(2, keys);
        assert_eq!(ms.base_type(), BaseType::B);
    }

    #[test]
    fn test_construct_multi_a() {
        let keys = vec![dummy_key(20), dummy_key(21)];
        let ms = Miniscript::multi_a(1, keys);
        assert_eq!(ms.base_type(), BaseType::B);
    }

    #[test]
    fn test_and_v_combinator() {
        // and_v(v:pk(key), older(144)) → type B
        let key = dummy_key(3);
        let left = Miniscript::verify(Miniscript::pk(key));
        let right = Miniscript::older(144);
        let ms = Miniscript::and_v(left, right);
        assert_eq!(ms.base_type(), BaseType::B);
    }

    #[test]
    fn test_and_b_combinator() {
        // and_b(pk(k1), s:pk(k2)) → type B
        let k1 = dummy_key(4);
        let k2 = dummy_key(5);
        let left = Miniscript::pk(k1);
        let right = Miniscript::swap(Miniscript::pk(k2));
        let ms = Miniscript::and_b(left, right);
        assert_eq!(ms.base_type(), BaseType::B);
    }

    #[test]
    fn test_or_i_combinator() {
        // or_i(pk(k1), pk(k2))
        let k1 = dummy_key(6);
        let k2 = dummy_key(7);
        let ms = Miniscript::or_i(
            Miniscript::pk(k1),
            Miniscript::pk(k2),
        );
        assert_eq!(ms.base_type(), BaseType::B);
    }

    #[test]
    fn test_thresh() {
        // thresh(2, pk(k1), s:pk(k2), s:pk(k3))
        let subs = vec![
            Miniscript::pk(dummy_key(30)),
            Miniscript::swap(Miniscript::pk(dummy_key(31))),
            Miniscript::swap(Miniscript::pk(dummy_key(32))),
        ];
        let ms = Miniscript::thresh(2, subs);
        assert_eq!(ms.base_type(), BaseType::B);
    }

    #[test]
    fn test_display_atoms() {
        let t = Miniscript::ms_true();
        assert_eq!(t.to_string(), "1");

        let f = Miniscript::ms_false();
        assert_eq!(f.to_string(), "0");

        let o = Miniscript::older(144);
        assert_eq!(o.to_string(), "older(144)");

        let a = Miniscript::after(1000);
        assert_eq!(a.to_string(), "after(1000)");
    }

    #[test]
    fn test_display_sha256() {
        let ms = Miniscript::sha256([0xaa; 32]);
        let s = ms.to_string();
        assert!(s.starts_with("sha256("));
        assert!(s.ends_with(")"));
        assert_eq!(s.len(), 7 + 64 + 1); // "sha256(" + 64 hex + ")"
    }

    #[test]
    fn test_display_wrappers() {
        let key = dummy_key(50);
        let ms = Miniscript::pk(key); // c:pk_k(key)
        let s = ms.to_string();
        assert!(s.starts_with("c:pk_k("));
    }

    #[test]
    fn test_display_and_v() {
        let key = dummy_key(60);
        let ms = Miniscript::and_v(
            Miniscript::verify(Miniscript::pk(key)),
            Miniscript::older(10),
        );
        let s = ms.to_string();
        assert!(s.starts_with("and_v(v:c:pk_k("));
        assert!(s.ends_with(",older(10))"));
    }

    #[test]
    fn test_display_multi() {
        let keys = vec![dummy_key(70), dummy_key(71)];
        let ms = Miniscript::multi(1, keys);
        let s = ms.to_string();
        assert!(s.starts_with("multi(1,"));
        assert!(s.ends_with(")"));
    }

    #[test]
    fn test_clone_eq() {
        let ms = Miniscript::older(100);
        let ms2 = ms.clone();
        assert_eq!(ms, ms2);
    }
}
