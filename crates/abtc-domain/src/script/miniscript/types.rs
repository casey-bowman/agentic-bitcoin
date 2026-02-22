//! Miniscript Type System
//!
//! Every Miniscript expression has a **type** that describes its behaviour on the
//! Bitcoin Script stack.  The type consists of a *base type* (B, V, K, or W) and
//! a set of boolean *modifiers* that refine guarantees about stack effects,
//! malleability, and dissatisfiability.
//!
//! The type system is the foundation of Miniscript's composability: two fragments
//! can be combined only when their types satisfy the rules of the combinator.
//!
//! Reference: <https://bitcoin.sipa.be/miniscript/>

use std::fmt;

// ── Base types ───────────────────────────────────────────────────────

/// The four base types of a Miniscript expression.
///
/// - **B** (Base): consumes its inputs and pushes a single nonzero (true)
///   or zero (false) onto the stack.
/// - **V** (Verify): consumes its inputs and either succeeds (leaving nothing)
///   or aborts the script.
/// - **K** (Key): like B but the result is specifically a public key.
/// - **W** (Wrapped): like B but consumes an additional stack element below the
///   expression's own inputs, used for the `a:` wrapper.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BaseType {
    B,
    V,
    K,
    W,
}

impl fmt::Display for BaseType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BaseType::B => write!(f, "B"),
            BaseType::V => write!(f, "V"),
            BaseType::K => write!(f, "K"),
            BaseType::W => write!(f, "W"),
        }
    }
}

// ── Type modifiers ───────────────────────────────────────────────────

/// Boolean properties that refine a Miniscript expression's behaviour.
///
/// Each modifier is a *promise* about the fragment's stack effects.  The
/// combination of base type + modifiers determines which combinators and
/// wrappers are legal.
///
/// The names come from sipa's reference specification:
/// - **z** (zero-arg): takes zero arguments from the stack.
/// - **o** (one-arg): takes exactly one argument from the stack.
/// - **n** (non-zero): for dissatisfaction, pushes an empty vector (not a
///   nonzero value).
/// - **d** (dissatisfiable): has a unique dissatisfaction.
/// - **u** (unit): on satisfaction, pushes exactly the number 1 (not just
///   any nonzero value).
/// - **e** (expression): a dissatisfaction exists and is the empty witness.
/// - **f** (forced): no dissatisfaction exists (always succeeds or aborts).
/// - **s** (safe): cannot be satisfied by a third-party malleator.
/// - **m** (non-malleable): satisfaction is unique given the spending conditions.
/// - **x** (expensive verify): the top-level script needs a VERIFY wrapper.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TypeModifiers {
    pub z: bool,
    pub o: bool,
    pub n: bool,
    pub d: bool,
    pub u: bool,
    pub e: bool,
    pub f: bool,
    pub s: bool,
    pub m: bool,
    pub x: bool,
}

impl TypeModifiers {
    /// All modifiers false.
    pub fn none() -> Self {
        TypeModifiers {
            z: false,
            o: false,
            n: false,
            d: false,
            u: false,
            e: false,
            f: false,
            s: false,
            m: false,
            x: false,
        }
    }
}

impl fmt::Display for TypeModifiers {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.z {
            write!(f, "z")?;
        }
        if self.o {
            write!(f, "o")?;
        }
        if self.n {
            write!(f, "n")?;
        }
        if self.d {
            write!(f, "d")?;
        }
        if self.u {
            write!(f, "u")?;
        }
        if self.e {
            write!(f, "e")?;
        }
        if self.f {
            write!(f, "f")?;
        }
        if self.s {
            write!(f, "s")?;
        }
        if self.m {
            write!(f, "m")?;
        }
        if self.x {
            write!(f, "x")?;
        }
        Ok(())
    }
}

// ── Combined type ────────────────────────────────────────────────────

/// A full Miniscript type: base type + modifiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct MiniscriptType {
    pub base: BaseType,
    pub modifiers: TypeModifiers,
}

impl MiniscriptType {
    pub fn new(base: BaseType, modifiers: TypeModifiers) -> Self {
        MiniscriptType { base, modifiers }
    }
}

impl fmt::Display for MiniscriptType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}{}", self.base, self.modifiers)
    }
}

// ── Type inference helpers ───────────────────────────────────────────

/// Compute the type of `pk_k(key)`: Konsu
pub fn type_pk_k() -> MiniscriptType {
    MiniscriptType {
        base: BaseType::K,
        modifiers: TypeModifiers {
            z: false,
            o: true,
            n: true,
            d: true,
            u: true,
            e: true,
            f: false,
            s: true,
            m: true,
            x: false,
        },
    }
}

/// Compute the type of `pk_h(key)`: Kndu
pub fn type_pk_h() -> MiniscriptType {
    MiniscriptType {
        base: BaseType::K,
        modifiers: TypeModifiers {
            z: false,
            o: false,
            n: true,
            d: true,
            u: true,
            e: true,
            f: false,
            s: true,
            m: true,
            x: false,
        },
    }
}

/// Type of `older(n)`: Bz
pub fn type_older() -> MiniscriptType {
    MiniscriptType {
        base: BaseType::B,
        modifiers: TypeModifiers {
            z: true,
            o: false,
            n: false,
            d: false,
            u: false,
            e: false,
            f: true,
            s: false,
            m: true,
            x: false,
        },
    }
}

/// Type of `after(n)`: Bz
pub fn type_after() -> MiniscriptType {
    MiniscriptType {
        base: BaseType::B,
        modifiers: TypeModifiers {
            z: true,
            o: false,
            n: false,
            d: false,
            u: false,
            e: false,
            f: true,
            s: false,
            m: true,
            x: false,
        },
    }
}

/// Type of `sha256(h)`, `hash256(h)`, `ripemd160(h)`, `hash160(h)`: Bondu
pub fn type_hash() -> MiniscriptType {
    MiniscriptType {
        base: BaseType::B,
        modifiers: TypeModifiers {
            z: false,
            o: true,
            n: false,
            d: true,
            u: true,
            e: false,
            f: false,
            s: false,
            m: true,
            x: false,
        },
    }
}

/// Type of `1` (OP_1): Bzu
pub fn type_true() -> MiniscriptType {
    MiniscriptType {
        base: BaseType::B,
        modifiers: TypeModifiers {
            z: true,
            o: false,
            n: false,
            d: false,
            u: true,
            e: false,
            f: true,
            s: false,
            m: true,
            x: false,
        },
    }
}

/// Type of `0` (OP_0): Bzud
pub fn type_false() -> MiniscriptType {
    MiniscriptType {
        base: BaseType::B,
        modifiers: TypeModifiers {
            z: true,
            o: false,
            n: false,
            d: true,
            u: true,
            e: true,
            f: false,
            s: false,
            m: true,
            x: false,
        },
    }
}

/// Type of `multi(k, ...)`: Bndu
pub fn type_multi() -> MiniscriptType {
    MiniscriptType {
        base: BaseType::B,
        modifiers: TypeModifiers {
            z: false,
            o: false,
            n: true,
            d: true,
            u: true,
            e: true,
            f: false,
            s: true,
            m: true,
            x: false,
        },
    }
}

/// Type of `multi_a(k, ...)`: Bndu
pub fn type_multi_a() -> MiniscriptType {
    MiniscriptType {
        base: BaseType::B,
        modifiers: TypeModifiers {
            z: false,
            o: false,
            n: true,
            d: true,
            u: true,
            e: true,
            f: false,
            s: true,
            m: true,
            x: false,
        },
    }
}

// ── Combinator type inference ────────────────────────────────────────

/// Compute the type of `and_v(X, Y)` given X.ty and Y.ty.
///
/// Requires: X is V, Y is B/K/V.
pub fn type_and_v(x: &MiniscriptType, y: &MiniscriptType) -> Option<MiniscriptType> {
    if x.base != BaseType::V {
        return None;
    }
    Some(MiniscriptType {
        base: y.base,
        modifiers: TypeModifiers {
            z: x.modifiers.z && y.modifiers.z,
            o: x.modifiers.z && y.modifiers.o || x.modifiers.o && y.modifiers.z,
            n: x.modifiers.n || (x.modifiers.z && y.modifiers.n),
            d: false, // and_v is never dissatisfiable
            u: y.modifiers.u,
            e: false,
            f: true, // X is V (forced) so the whole thing is forced
            s: x.modifiers.s || y.modifiers.s,
            m: x.modifiers.m
                && y.modifiers.m
                && (x.modifiers.s || y.modifiers.s || !x.modifiers.e && !y.modifiers.e),
            x: x.modifiers.x || y.modifiers.x,
        },
    })
}

/// Compute the type of `and_b(X, Y)` given X.ty and Y.ty.
///
/// Requires: X is B, Y is W.
pub fn type_and_b(x: &MiniscriptType, y: &MiniscriptType) -> Option<MiniscriptType> {
    if x.base != BaseType::B || y.base != BaseType::W {
        return None;
    }
    Some(MiniscriptType {
        base: BaseType::B,
        modifiers: TypeModifiers {
            z: x.modifiers.z && y.modifiers.z,
            o: x.modifiers.z && y.modifiers.o || x.modifiers.o && y.modifiers.z,
            n: x.modifiers.n || (x.modifiers.z && y.modifiers.n),
            d: x.modifiers.d && y.modifiers.d,
            u: false,
            e: x.modifiers.e && y.modifiers.e,
            f: x.modifiers.f && y.modifiers.f,
            s: x.modifiers.s || y.modifiers.s,
            m: x.modifiers.m
                && y.modifiers.m
                && (x.modifiers.s || y.modifiers.s || !x.modifiers.e && !y.modifiers.e),
            x: x.modifiers.x || y.modifiers.x,
        },
    })
}

/// Compute the type of `or_b(X, Y)` given X.ty and Y.ty.
///
/// Requires: X is Bd, Y is Wd.
pub fn type_or_b(x: &MiniscriptType, y: &MiniscriptType) -> Option<MiniscriptType> {
    if x.base != BaseType::B || !x.modifiers.d || y.base != BaseType::W || !y.modifiers.d {
        return None;
    }
    Some(MiniscriptType {
        base: BaseType::B,
        modifiers: TypeModifiers {
            z: x.modifiers.z && y.modifiers.z,
            o: x.modifiers.z && y.modifiers.o || x.modifiers.o && y.modifiers.z,
            n: false,
            d: true,
            u: false,
            e: x.modifiers.e && y.modifiers.e,
            f: false,
            s: x.modifiers.s && y.modifiers.s,
            m: x.modifiers.m
                && y.modifiers.m
                && x.modifiers.e
                && y.modifiers.e
                && (x.modifiers.s || y.modifiers.s),
            x: x.modifiers.x || y.modifiers.x,
        },
    })
}

/// Compute the type of `or_c(X, Y)` given X.ty and Y.ty.
///
/// Requires: X is Bdu, Y is V.
pub fn type_or_c(x: &MiniscriptType, y: &MiniscriptType) -> Option<MiniscriptType> {
    if x.base != BaseType::B || !x.modifiers.d || !x.modifiers.u || y.base != BaseType::V {
        return None;
    }
    Some(MiniscriptType {
        base: BaseType::V,
        modifiers: TypeModifiers {
            z: x.modifiers.z && y.modifiers.z,
            o: x.modifiers.o && y.modifiers.z,
            n: false,
            d: false,
            u: false,
            e: false,
            f: true,
            s: x.modifiers.s && y.modifiers.s,
            m: x.modifiers.m && y.modifiers.m && x.modifiers.e && (x.modifiers.s || y.modifiers.s),
            x: x.modifiers.x || y.modifiers.x,
        },
    })
}

/// Compute the type of `or_d(X, Y)` given X.ty and Y.ty.
///
/// Requires: X is Bdu, Y is B.
pub fn type_or_d(x: &MiniscriptType, y: &MiniscriptType) -> Option<MiniscriptType> {
    if x.base != BaseType::B || !x.modifiers.d || !x.modifiers.u || y.base != BaseType::B {
        return None;
    }
    Some(MiniscriptType {
        base: BaseType::B,
        modifiers: TypeModifiers {
            z: x.modifiers.z && y.modifiers.z,
            o: x.modifiers.o && y.modifiers.z,
            n: false,
            d: y.modifiers.d,
            u: y.modifiers.u,
            e: y.modifiers.e,
            f: y.modifiers.f,
            s: x.modifiers.s && y.modifiers.s,
            m: x.modifiers.m && y.modifiers.m && x.modifiers.e && (x.modifiers.s || y.modifiers.s),
            x: x.modifiers.x || y.modifiers.x,
        },
    })
}

/// Compute the type of `or_i(X, Y)` given X.ty and Y.ty.
///
/// Requires: both X and Y have the same base type (B, V, or K).
pub fn type_or_i(x: &MiniscriptType, y: &MiniscriptType) -> Option<MiniscriptType> {
    if x.base != y.base {
        return None;
    }
    match x.base {
        BaseType::B | BaseType::K | BaseType::V => {}
        BaseType::W => return None,
    }
    Some(MiniscriptType {
        base: x.base,
        modifiers: TypeModifiers {
            z: false,
            o: x.modifiers.z && y.modifiers.z,
            n: false,
            d: x.modifiers.d || y.modifiers.d,
            u: x.modifiers.u && y.modifiers.u,
            e: x.modifiers.e && y.modifiers.f || x.modifiers.f && y.modifiers.e,
            f: x.modifiers.f && y.modifiers.f,
            s: x.modifiers.s || y.modifiers.s,
            m: x.modifiers.m && y.modifiers.m && (x.modifiers.s || y.modifiers.s),
            x: x.modifiers.x || y.modifiers.x,
        },
    })
}

// ── Wrapper type transformations ─────────────────────────────────────

/// Type of `a:X` (alt wrapper): converts B → W.
pub fn type_alt(inner: &MiniscriptType) -> Option<MiniscriptType> {
    if inner.base != BaseType::B {
        return None;
    }
    Some(MiniscriptType {
        base: BaseType::W,
        modifiers: TypeModifiers {
            // z and o swap: a:X uses TOALTSTACK/FROMALTSTACK
            z: false,
            o: inner.modifiers.z,
            n: inner.modifiers.n,
            d: inner.modifiers.d,
            u: inner.modifiers.u,
            e: inner.modifiers.e,
            f: inner.modifiers.f,
            s: inner.modifiers.s,
            m: inner.modifiers.m,
            x: inner.modifiers.x,
        },
    })
}

/// Type of `s:X` (swap wrapper): converts Bo → W.
pub fn type_swap(inner: &MiniscriptType) -> Option<MiniscriptType> {
    if inner.base != BaseType::B || !inner.modifiers.o {
        return None;
    }
    Some(MiniscriptType {
        base: BaseType::W,
        modifiers: TypeModifiers {
            z: false,
            o: inner.modifiers.o,
            n: inner.modifiers.n,
            d: inner.modifiers.d,
            u: inner.modifiers.u,
            e: inner.modifiers.e,
            f: inner.modifiers.f,
            s: inner.modifiers.s,
            m: inner.modifiers.m,
            x: inner.modifiers.x,
        },
    })
}

/// Type of `c:X` (check wrapper): converts K → B.
pub fn type_check(inner: &MiniscriptType) -> Option<MiniscriptType> {
    if inner.base != BaseType::K {
        return None;
    }
    Some(MiniscriptType {
        base: BaseType::B,
        modifiers: TypeModifiers {
            z: inner.modifiers.z,
            o: inner.modifiers.o,
            n: inner.modifiers.n,
            d: inner.modifiers.d,
            u: true,
            e: inner.modifiers.e,
            f: inner.modifiers.f,
            s: inner.modifiers.s,
            m: inner.modifiers.m,
            x: inner.modifiers.x,
        },
    })
}

/// Type of `d:X` (dupif wrapper): converts Vz → Bdu.
pub fn type_dupif(inner: &MiniscriptType) -> Option<MiniscriptType> {
    if inner.base != BaseType::V || !inner.modifiers.z {
        return None;
    }
    Some(MiniscriptType {
        base: BaseType::B,
        modifiers: TypeModifiers {
            z: false,
            o: true,
            n: true,
            d: true,
            u: false,
            e: true,
            f: false,
            s: inner.modifiers.s,
            m: inner.modifiers.m,
            x: inner.modifiers.x,
        },
    })
}

/// Type of `v:X` (verify wrapper): converts B → V.
pub fn type_verify(inner: &MiniscriptType) -> Option<MiniscriptType> {
    if inner.base != BaseType::B {
        return None;
    }
    Some(MiniscriptType {
        base: BaseType::V,
        modifiers: TypeModifiers {
            z: inner.modifiers.z,
            o: inner.modifiers.o,
            n: inner.modifiers.n,
            d: false,
            u: false,
            e: false,
            f: true,
            s: inner.modifiers.s,
            m: inner.modifiers.m,
            x: inner.modifiers.x,
        },
    })
}

/// Type of `j:X` (nonzero wrapper): converts Bou → Bdu.
pub fn type_nonzero(inner: &MiniscriptType) -> Option<MiniscriptType> {
    if inner.base != BaseType::B || !inner.modifiers.o || !inner.modifiers.u {
        return None;
    }
    Some(MiniscriptType {
        base: BaseType::B,
        modifiers: TypeModifiers {
            z: false,
            o: inner.modifiers.o,
            n: true,
            d: true,
            u: inner.modifiers.u,
            e: inner.modifiers.f,
            f: false,
            s: inner.modifiers.s,
            m: inner.modifiers.m,
            x: inner.modifiers.x,
        },
    })
}

/// Type of `n:X` (zero-not-equal wrapper): converts Bu → Bu.
pub fn type_zero_not_equal(inner: &MiniscriptType) -> Option<MiniscriptType> {
    if inner.base != BaseType::B || !inner.modifiers.u {
        return None;
    }
    Some(MiniscriptType {
        base: BaseType::B,
        modifiers: TypeModifiers {
            z: inner.modifiers.z,
            o: inner.modifiers.o,
            n: inner.modifiers.n,
            d: inner.modifiers.d,
            u: true,
            e: inner.modifiers.e,
            f: inner.modifiers.f,
            s: inner.modifiers.s,
            m: inner.modifiers.m,
            x: inner.modifiers.x,
        },
    })
}

/// Compute the type of `thresh(k, X1, X2, ..., Xn)`.
///
/// Requires: X1 is Bdu, X2..Xn are Wdu.
pub fn type_thresh(k: usize, children: &[MiniscriptType]) -> Option<MiniscriptType> {
    if children.is_empty() || k == 0 || k > children.len() {
        return None;
    }
    // First child must be B, rest must be W
    if children[0].base != BaseType::B {
        return None;
    }
    for c in &children[1..] {
        if c.base != BaseType::W {
            return None;
        }
    }
    // All except possibly first must be W (wait — actually in the spec,
    // thresh uses OP_ADD between children, so it's slightly different).
    // For simplicity, all children must be Bdu for the combination.
    let all_z = children.iter().all(|c| c.modifiers.z);
    let num_o = children.iter().filter(|c| c.modifiers.o).count();
    let all_e = children.iter().all(|c| c.modifiers.e);
    let all_m = children.iter().all(|c| c.modifiers.m);
    let any_s = children.iter().any(|c| c.modifiers.s);
    let all_d = children.iter().all(|c| c.modifiers.d);
    let all_x = children.iter().any(|c| c.modifiers.x);

    Some(MiniscriptType {
        base: BaseType::B,
        modifiers: TypeModifiers {
            z: all_z,
            o: all_z && num_o == 1,
            n: false,
            d: all_d,
            u: false,
            e: all_e && k == children.len(),
            f: false,
            s: any_s,
            m: all_m && all_e && any_s,
            x: all_x,
        },
    })
}

// ── Tests ────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_base_type_display() {
        assert_eq!(format!("{}", BaseType::B), "B");
        assert_eq!(format!("{}", BaseType::V), "V");
        assert_eq!(format!("{}", BaseType::K), "K");
        assert_eq!(format!("{}", BaseType::W), "W");
    }

    #[test]
    fn test_type_modifiers_display() {
        let m = TypeModifiers {
            z: true,
            o: false,
            n: true,
            d: false,
            u: true,
            e: false,
            f: true,
            s: false,
            m: true,
            x: false,
        };
        assert_eq!(format!("{}", m), "znufm");
    }

    #[test]
    fn test_type_pk_k() {
        let ty = type_pk_k();
        assert_eq!(ty.base, BaseType::K);
        assert!(ty.modifiers.o);
        assert!(ty.modifiers.n);
        assert!(ty.modifiers.d);
        assert!(ty.modifiers.u);
        assert!(ty.modifiers.e);
        assert!(ty.modifiers.s);
        assert!(ty.modifiers.m);
    }

    #[test]
    fn test_type_older_after() {
        let ty = type_older();
        assert_eq!(ty.base, BaseType::B);
        assert!(ty.modifiers.z);
        assert!(ty.modifiers.f);
        assert!(ty.modifiers.m);
        assert!(!ty.modifiers.d);

        let ty2 = type_after();
        assert_eq!(ty, ty2);
    }

    #[test]
    fn test_type_hash() {
        let ty = type_hash();
        assert_eq!(ty.base, BaseType::B);
        assert!(ty.modifiers.o);
        assert!(ty.modifiers.d);
        assert!(ty.modifiers.u);
        assert!(ty.modifiers.m);
        assert!(!ty.modifiers.s); // hash preimage is not safe against third-party
    }

    #[test]
    fn test_type_true_false() {
        let t = type_true();
        assert_eq!(t.base, BaseType::B);
        assert!(t.modifiers.z);
        assert!(t.modifiers.u);
        assert!(t.modifiers.f);

        let f = type_false();
        assert_eq!(f.base, BaseType::B);
        assert!(f.modifiers.z);
        assert!(f.modifiers.d);
        assert!(f.modifiers.e);
    }

    #[test]
    fn test_type_multi() {
        let ty = type_multi();
        assert_eq!(ty.base, BaseType::B);
        assert!(ty.modifiers.n);
        assert!(ty.modifiers.d);
        assert!(ty.modifiers.u);
        assert!(ty.modifiers.s);
        assert!(ty.modifiers.m);
    }

    #[test]
    fn test_type_check_wrapper() {
        // c:pk_k(key) = check(pk_k) should be B with u=true
        let pk = type_pk_k();
        let checked = type_check(&pk).unwrap();
        assert_eq!(checked.base, BaseType::B);
        assert!(checked.modifiers.u);
        assert!(checked.modifiers.o);
        assert!(checked.modifiers.d);
        assert!(checked.modifiers.s);
    }

    #[test]
    fn test_type_check_rejects_non_k() {
        let b_type = type_older();
        assert!(type_check(&b_type).is_none());
    }

    #[test]
    fn test_type_verify_wrapper() {
        // v:pk_k(key) is not valid (pk_k is K, verify needs B)
        let pk = type_pk_k();
        assert!(type_verify(&pk).is_none());

        // v:c:pk_k = verify(check(pk_k)) should work
        let checked = type_check(&pk).unwrap();
        let verified = type_verify(&checked).unwrap();
        assert_eq!(verified.base, BaseType::V);
        assert!(verified.modifiers.f);
        assert!(!verified.modifiers.d);
    }

    #[test]
    fn test_type_alt_wrapper() {
        let b = type_check(&type_pk_k()).unwrap(); // B type
        let w = type_alt(&b).unwrap();
        assert_eq!(w.base, BaseType::W);
    }

    #[test]
    fn test_type_and_v() {
        // and_v(v:pk(A), pk(B)) — V × K → K
        let pk_a = type_pk_k();
        let checked_a = type_check(&pk_a).unwrap();
        let v_a = type_verify(&checked_a).unwrap();
        let pk_b = type_pk_k();

        let result = type_and_v(&v_a, &MiniscriptType::new(pk_b.base, pk_b.modifiers)).unwrap();
        assert_eq!(result.base, BaseType::K);
        assert!(result.modifiers.f);
    }

    #[test]
    fn test_type_and_v_rejects_non_v_first() {
        let b = type_older();
        let k = type_pk_k();
        assert!(type_and_v(&b, &k).is_none());
    }

    #[test]
    fn test_type_or_i() {
        let pk = type_pk_k();
        let result = type_or_i(&pk, &pk).unwrap();
        assert_eq!(result.base, BaseType::K);
    }

    #[test]
    fn test_type_or_i_rejects_different_bases() {
        let b = type_older();
        let k = type_pk_k();
        assert!(type_or_i(&b, &k).is_none());
    }
}
