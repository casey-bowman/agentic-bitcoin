//! Spending policy language — high-level DSL that compiles to Miniscript.
//!
//! ## Pipeline
//!
//! ```text
//! Policy string  ──►  parse_policy()  ──►  Policy AST
//!                                             │
//!                                         compile()
//!                                             │
//!                                             ▼
//!                                        Miniscript AST  ──►  encode()  ──►  Script
//! ```
//!
//! ## Syntax
//!
//! ```text
//! pk(KEY)                  — single pubkey signature
//! pkh(HASH)                — pubkey hash (reveal key to spend)
//! older(N)                 — relative timelock (N blocks)
//! after(N)                 — absolute timelock (height or timestamp)
//! sha256(H)                — SHA-256 preimage required
//! hash256(H)               — double-SHA-256 preimage required
//! ripemd160(H)             — RIPEMD-160 preimage required
//! hash160(H)               — HASH160 preimage required
//! and(P1, P2)              — both policies must be satisfied
//! or(P1, P2)               — either policy (equal probability)
//! or(W1@P1, W2@P2)         — weighted or (probability hints)
//! thresh(K, P1, P2, ...)   — k-of-n policies
//! multi(K, KEY1, KEY2, ..) — k-of-n multisig
//! ```

use std::fmt;

use crate::wallet::keys::PublicKey;
use super::fragment::Miniscript;
use super::types::{BaseType, MiniscriptType};

// ---------------------------------------------------------------------------
// Policy AST
// ---------------------------------------------------------------------------

/// A spending policy — human-readable spending conditions that compile to
/// Miniscript.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Policy {
    /// `pk(key)` — single public key signature required.
    PubKey(PublicKey),

    /// `pkh(hash)` — pubkey hash check (must reveal the actual key).
    PubKeyHash([u8; 20]),

    /// `older(n)` — relative timelock: n blocks must have passed since the
    /// UTXO was mined.
    Older(u32),

    /// `after(n)` — absolute timelock: block height or median-time-past.
    After(u32),

    /// `sha256(h)` — preimage of SHA-256 hash.
    Sha256([u8; 32]),

    /// `hash256(h)` — preimage of double-SHA-256 hash.
    Hash256([u8; 32]),

    /// `ripemd160(h)` — preimage of RIPEMD-160 hash.
    Ripemd160([u8; 20]),

    /// `hash160(h)` — preimage of HASH160.
    Hash160([u8; 20]),

    /// `and(P1, P2)` — both policies must be satisfied.
    And(Box<Policy>, Box<Policy>),

    /// `or(P1, P2)` — either policy can be satisfied (equal weight).
    Or(Box<Policy>, Box<Policy>),

    /// `or(W1@P1, W2@P2, ...)` — weighted or with probability hints.
    /// Weights guide the compiler to put higher-probability branches in
    /// cheaper positions.
    WeightedOr(Vec<(u32, Policy)>),

    /// `thresh(k, [P1, P2, ..., Pn])` — k of n policies must be satisfied.
    Thresh(usize, Vec<Policy>),

    /// `multi(k, [KEY1, KEY2, ..., KEYN])` — k-of-n multisig.
    Multi(usize, Vec<PublicKey>),
}

// ---------------------------------------------------------------------------
// Display — round-trip formatting
// ---------------------------------------------------------------------------

impl fmt::Display for Policy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Policy::PubKey(key) => write!(f, "pk({})", hex_encode(&key.serialize())),
            Policy::PubKeyHash(h) => write!(f, "pkh({})", hex_encode(h)),
            Policy::Older(n) => write!(f, "older({})", n),
            Policy::After(n) => write!(f, "after({})", n),
            Policy::Sha256(h) => write!(f, "sha256({})", hex_encode(h)),
            Policy::Hash256(h) => write!(f, "hash256({})", hex_encode(h)),
            Policy::Ripemd160(h) => write!(f, "ripemd160({})", hex_encode(h)),
            Policy::Hash160(h) => write!(f, "hash160({})", hex_encode(h)),
            Policy::And(l, r) => write!(f, "and({},{})", l, r),
            Policy::Or(l, r) => write!(f, "or({},{})", l, r),
            Policy::WeightedOr(entries) => {
                write!(f, "or(")?;
                for (i, (w, p)) in entries.iter().enumerate() {
                    if i > 0 { write!(f, ",")?; }
                    write!(f, "{}@{}", w, p)?;
                }
                write!(f, ")")
            }
            Policy::Thresh(k, subs) => {
                write!(f, "thresh({}", k)?;
                for s in subs {
                    write!(f, ",{}", s)?;
                }
                write!(f, ")")
            }
            Policy::Multi(k, keys) => {
                write!(f, "multi({}", k)?;
                for key in keys {
                    write!(f, ",{}", hex_encode(&key.serialize()))?;
                }
                write!(f, ")")
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Policy parse error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyParseError {
    /// Unexpected end of input.
    UnexpectedEnd,
    /// Expected a specific character.
    Expected(char, Option<char>),
    /// Unknown function name.
    UnknownFunction(String),
    /// Invalid hex-encoded key.
    InvalidKey(String),
    /// Invalid hex-encoded hash.
    InvalidHash(String),
    /// Invalid number.
    InvalidNumber(String),
    /// Invalid threshold (k > n or k == 0).
    InvalidThreshold { k: usize, n: usize },
    /// Invalid weight in weighted or.
    InvalidWeight(String),
    /// Trailing characters after a complete policy.
    TrailingChars(String),
}

impl fmt::Display for PolicyParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnexpectedEnd => write!(f, "unexpected end of input"),
            Self::Expected(exp, got) => match got {
                Some(c) => write!(f, "expected '{}', found '{}'", exp, c),
                None => write!(f, "expected '{}', found end of input", exp),
            },
            Self::UnknownFunction(s) => write!(f, "unknown function '{}'", s),
            Self::InvalidKey(s) => write!(f, "invalid key: {}", s),
            Self::InvalidHash(s) => write!(f, "invalid hash: {}", s),
            Self::InvalidNumber(s) => write!(f, "invalid number: {}", s),
            Self::InvalidThreshold { k, n } => {
                write!(f, "invalid threshold: k={} n={}", k, n)
            }
            Self::InvalidWeight(s) => write!(f, "invalid weight: {}", s),
            Self::TrailingChars(s) => write!(f, "trailing characters: '{}'", s),
        }
    }
}

impl std::error::Error for PolicyParseError {}

/// Policy compilation error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CompileError {
    /// Invalid threshold parameters.
    InvalidThreshold { k: usize, n: usize },
    /// Empty weighted-or list.
    EmptyWeightedOr,
    /// Too many keys for multi (limit: 20).
    TooManyKeys(usize),
    /// Internal type-check failure.
    TypeCheckFailed(String),
}

impl fmt::Display for CompileError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidThreshold { k, n } => {
                write!(f, "invalid threshold: k={} n={}", k, n)
            }
            Self::EmptyWeightedOr => write!(f, "empty weighted-or"),
            Self::TooManyKeys(n) => write!(f, "too many keys: {} (max 20)", n),
            Self::TypeCheckFailed(s) => write!(f, "type check failed: {}", s),
        }
    }
}

impl std::error::Error for CompileError {}

// ---------------------------------------------------------------------------
// Parser
// ---------------------------------------------------------------------------

/// Parse a policy string into a `Policy` AST.
pub fn parse_policy(input: &str) -> Result<Policy, PolicyParseError> {
    let mut parser = PolicyParser::new(input);
    parser.skip_whitespace();
    let policy = parser.parse_expr()?;
    parser.skip_whitespace();
    if !parser.is_empty() {
        return Err(PolicyParseError::TrailingChars(
            parser.remaining().to_string(),
        ));
    }
    Ok(policy)
}

struct PolicyParser<'a> {
    input: &'a str,
    pos: usize,
}

impl<'a> PolicyParser<'a> {
    fn new(input: &'a str) -> Self {
        PolicyParser { input, pos: 0 }
    }

    fn remaining(&self) -> &'a str {
        &self.input[self.pos..]
    }

    fn is_empty(&self) -> bool {
        self.pos >= self.input.len()
    }

    fn peek(&self) -> Option<char> {
        self.remaining().chars().next()
    }

    fn advance(&mut self, n: usize) {
        self.pos += n;
    }

    fn skip_whitespace(&mut self) {
        while let Some(c) = self.peek() {
            if c.is_ascii_whitespace() {
                self.advance(c.len_utf8());
            } else {
                break;
            }
        }
    }

    fn expect_char(&mut self, c: char) -> Result<(), PolicyParseError> {
        self.skip_whitespace();
        match self.peek() {
            Some(found) if found == c => {
                self.advance(c.len_utf8());
                Ok(())
            }
            other => Err(PolicyParseError::Expected(c, other)),
        }
    }

    fn read_ident(&mut self) -> &'a str {
        let start = self.pos;
        while let Some(c) = self.peek() {
            if c.is_ascii_alphanumeric() || c == '_' {
                self.advance(1);
            } else {
                break;
            }
        }
        &self.input[start..self.pos]
    }

    fn read_number(&mut self) -> Result<u64, PolicyParseError> {
        self.skip_whitespace();
        let start = self.pos;
        while let Some(c) = self.peek() {
            if c.is_ascii_digit() {
                self.advance(1);
            } else {
                break;
            }
        }
        let s = &self.input[start..self.pos];
        if s.is_empty() {
            return Err(PolicyParseError::InvalidNumber("empty".to_string()));
        }
        s.parse::<u64>()
            .map_err(|_| PolicyParseError::InvalidNumber(s.to_string()))
    }

    fn read_hex(&mut self, expected_bytes: usize) -> Result<Vec<u8>, PolicyParseError> {
        self.skip_whitespace();
        let hex_len = expected_bytes * 2;
        let rem = self.remaining();
        if rem.len() < hex_len {
            return Err(PolicyParseError::InvalidHash(format!(
                "expected {} hex chars, got {}",
                hex_len,
                rem.len()
            )));
        }
        let hex_str = &rem[..hex_len];
        let bytes = hex_decode(hex_str).map_err(|e| PolicyParseError::InvalidHash(e))?;
        self.advance(hex_len);
        Ok(bytes)
    }

    fn read_pubkey(&mut self) -> Result<PublicKey, PolicyParseError> {
        self.skip_whitespace();
        // Compressed pubkey: 33 bytes = 66 hex chars
        let rem = self.remaining();
        if rem.len() < 66 {
            return Err(PolicyParseError::InvalidKey(
                "expected 66 hex chars for compressed pubkey".to_string(),
            ));
        }
        let hex_str = &rem[..66];
        let bytes = hex_decode(hex_str).map_err(|e| PolicyParseError::InvalidKey(e))?;
        let key = PublicKey::from_bytes(&bytes)
            .map_err(|_| PolicyParseError::InvalidKey("invalid pubkey bytes".to_string()))?;
        self.advance(66);
        Ok(key)
    }

    /// Parse a single policy expression (function call).
    fn parse_expr(&mut self) -> Result<Policy, PolicyParseError> {
        self.skip_whitespace();
        let ident = self.read_ident();
        if ident.is_empty() {
            return Err(PolicyParseError::UnexpectedEnd);
        }

        match ident {
            "pk" => {
                self.expect_char('(')?;
                let key = self.read_pubkey()?;
                self.expect_char(')')?;
                Ok(Policy::PubKey(key))
            }
            "pkh" => {
                self.expect_char('(')?;
                let hash_bytes = self.read_hex(20)?;
                let mut hash = [0u8; 20];
                hash.copy_from_slice(&hash_bytes);
                self.expect_char(')')?;
                Ok(Policy::PubKeyHash(hash))
            }
            "older" => {
                self.expect_char('(')?;
                let n = self.read_number()? as u32;
                self.expect_char(')')?;
                Ok(Policy::Older(n))
            }
            "after" => {
                self.expect_char('(')?;
                let n = self.read_number()? as u32;
                self.expect_char(')')?;
                Ok(Policy::After(n))
            }
            "sha256" => {
                self.expect_char('(')?;
                let h = self.read_hex(32)?;
                let mut hash = [0u8; 32];
                hash.copy_from_slice(&h);
                self.expect_char(')')?;
                Ok(Policy::Sha256(hash))
            }
            "hash256" => {
                self.expect_char('(')?;
                let h = self.read_hex(32)?;
                let mut hash = [0u8; 32];
                hash.copy_from_slice(&h);
                self.expect_char(')')?;
                Ok(Policy::Hash256(hash))
            }
            "ripemd160" => {
                self.expect_char('(')?;
                let h = self.read_hex(20)?;
                let mut hash = [0u8; 20];
                hash.copy_from_slice(&h);
                self.expect_char(')')?;
                Ok(Policy::Ripemd160(hash))
            }
            "hash160" => {
                self.expect_char('(')?;
                let h = self.read_hex(20)?;
                let mut hash = [0u8; 20];
                hash.copy_from_slice(&h);
                self.expect_char(')')?;
                Ok(Policy::Hash160(hash))
            }
            "and" => {
                self.expect_char('(')?;
                let left = self.parse_expr()?;
                self.expect_char(',')?;
                let right = self.parse_expr()?;
                self.expect_char(')')?;
                Ok(Policy::And(Box::new(left), Box::new(right)))
            }
            "or" => {
                self.expect_char('(')?;
                // Try weighted or first: W@P, W@P, ...
                let saved_pos = self.pos;
                match self.try_parse_weighted_or() {
                    Ok(entries) => Ok(Policy::WeightedOr(entries)),
                    Err(_) => {
                        // Fall back to simple or(P1, P2)
                        self.pos = saved_pos;
                        let left = self.parse_expr()?;
                        self.expect_char(',')?;
                        let right = self.parse_expr()?;
                        self.expect_char(')')?;
                        Ok(Policy::Or(Box::new(left), Box::new(right)))
                    }
                }
            }
            "thresh" => {
                self.expect_char('(')?;
                let k = self.read_number()? as usize;
                let mut subs = Vec::new();
                loop {
                    self.expect_char(',')?;
                    subs.push(self.parse_expr()?);
                    self.skip_whitespace();
                    if self.peek() == Some(')') {
                        break;
                    }
                }
                self.expect_char(')')?;
                if k == 0 || k > subs.len() {
                    return Err(PolicyParseError::InvalidThreshold {
                        k,
                        n: subs.len(),
                    });
                }
                Ok(Policy::Thresh(k, subs))
            }
            "multi" => {
                self.expect_char('(')?;
                let k = self.read_number()? as usize;
                let mut keys = Vec::new();
                loop {
                    self.expect_char(',')?;
                    keys.push(self.read_pubkey()?);
                    self.skip_whitespace();
                    if self.peek() == Some(')') {
                        break;
                    }
                }
                self.expect_char(')')?;
                if k == 0 || k > keys.len() {
                    return Err(PolicyParseError::InvalidThreshold {
                        k,
                        n: keys.len(),
                    });
                }
                Ok(Policy::Multi(k, keys))
            }
            other => Err(PolicyParseError::UnknownFunction(other.to_string())),
        }
    }

    /// Try to parse the interior of or(...) as weighted entries: W@P, W@P, ...
    /// Returns Ok(entries) and has consumed up through the closing ')'.
    fn try_parse_weighted_or(&mut self) -> Result<Vec<(u32, Policy)>, PolicyParseError> {
        let mut entries = Vec::new();
        loop {
            self.skip_whitespace();
            // Read weight number
            let w = self.read_number().map_err(|_| {
                PolicyParseError::InvalidWeight("expected weight number".to_string())
            })? as u32;
            // Expect '@'
            self.skip_whitespace();
            match self.peek() {
                Some('@') => self.advance(1),
                _ => {
                    return Err(PolicyParseError::InvalidWeight(
                        "expected '@' after weight".to_string(),
                    ))
                }
            }
            // Parse the policy
            let policy = self.parse_expr()?;
            entries.push((w, policy));
            self.skip_whitespace();
            match self.peek() {
                Some(',') => {
                    self.advance(1);
                    continue;
                }
                Some(')') => {
                    self.advance(1);
                    break;
                }
                other => {
                    return Err(PolicyParseError::Expected(')', other));
                }
            }
        }
        if entries.len() < 2 {
            return Err(PolicyParseError::InvalidWeight(
                "weighted or needs at least 2 entries".to_string(),
            ));
        }
        Ok(entries)
    }
}

// ---------------------------------------------------------------------------
// Compiler — Policy → Miniscript
// ---------------------------------------------------------------------------

/// Compile a `Policy` to an optimized `Miniscript`.
pub fn compile(policy: &Policy) -> Result<Miniscript, CompileError> {
    compile_to_b(policy)
}

/// Compile a policy to a Miniscript with base type B (the standard return type).
fn compile_to_b(policy: &Policy) -> Result<Miniscript, CompileError> {
    match policy {
        // ── Atoms ──────────────────────────────────────────────────
        Policy::PubKey(key) => Ok(Miniscript::pk(key.clone())),
        Policy::PubKeyHash(hash) => Ok(Miniscript::pkh(*hash)),
        Policy::Older(n) => Ok(Miniscript::older(*n)),
        Policy::After(n) => Ok(Miniscript::after(*n)),
        Policy::Sha256(h) => Ok(Miniscript::sha256(*h)),
        Policy::Hash256(h) => Ok(Miniscript::hash256(*h)),
        Policy::Ripemd160(h) => Ok(Miniscript::ripemd160(*h)),
        Policy::Hash160(h) => Ok(Miniscript::hash160(*h)),

        // ── Multi ──────────────────────────────────────────────────
        Policy::Multi(k, keys) => {
            if keys.len() > 20 {
                return Err(CompileError::TooManyKeys(keys.len()));
            }
            Ok(Miniscript::multi(*k, keys.clone()))
        }

        // ── And ────────────────────────────────────────────────────
        Policy::And(left, right) => compile_and(left, right),

        // ── Or ─────────────────────────────────────────────────────
        Policy::Or(left, right) => compile_or(left, right),

        // ── Weighted Or ────────────────────────────────────────────
        Policy::WeightedOr(entries) => compile_weighted_or(entries),

        // ── Thresh ─────────────────────────────────────────────────
        Policy::Thresh(k, subs) => compile_thresh(*k, subs),
    }
}

/// Compile `and(P1, P2)` — choose the best AND variant.
///
/// Strategy:
///   Preferred: `and_v(v:LEFT, RIGHT)` — the left side is wrapped to V type,
///   the right side stays B.  This is the most compact encoding.
///
///   Fallback: `and_b(LEFT, s:RIGHT)` — when v-wrapping fails.
fn compile_and(left: &Policy, right: &Policy) -> Result<Miniscript, CompileError> {
    let left_ms = compile_to_b(left)?;
    let right_ms = compile_to_b(right)?;

    // Try and_v(v:left, right): need left to be B (wrappable to V)
    if left_ms.ty.base == BaseType::B {
        let left_v = Miniscript::verify(left_ms);
        return Ok(Miniscript::and_v(left_v, right_ms));
    }

    // Fallback: and_b(left, s:right): need right to be B with 'o' (wrappable to W)
    let right_w = Miniscript::swap(right_ms);
    Ok(Miniscript::and_b(left_ms, right_w))
}

/// Compile `or(P1, P2)` — choose the best OR variant.
///
/// Priority order (most efficient first):
///   1. `or_d(LEFT, RIGHT)` — requires LEFT is Bdu, RIGHT is B
///   2. `or_i(LEFT, RIGHT)` — universal fallback, no type requirements
fn compile_or(left: &Policy, right: &Policy) -> Result<Miniscript, CompileError> {
    let left_ms = compile_to_b(left)?;
    let right_ms = compile_to_b(right)?;

    try_compile_or_pair(left_ms, right_ms)
}

/// Try to build the most efficient OR from two already-compiled Miniscripts.
fn try_compile_or_pair(
    left: Miniscript,
    right: Miniscript,
) -> Result<Miniscript, CompileError> {
    // 1. or_d: left must be Bdu, right must be B
    if is_bdu(&left.ty) && right.ty.base == BaseType::B {
        return Ok(Miniscript::or_d(left, right));
    }

    // 2. or_i: always works (wraps in IF/ELSE/ENDIF)
    Ok(Miniscript::or_i(left, right))
}

/// Compile weighted-or: sort by weight (descending), chain binary or calls.
fn compile_weighted_or(entries: &[(u32, Policy)]) -> Result<Miniscript, CompileError> {
    if entries.is_empty() {
        return Err(CompileError::EmptyWeightedOr);
    }
    if entries.len() == 1 {
        return compile_to_b(&entries[0].1);
    }

    // Sort by weight descending — higher weight = more likely = goes left
    let mut sorted: Vec<_> = entries.to_vec();
    sorted.sort_by(|a, b| b.0.cmp(&a.0));

    // Chain left-associatively
    let mut result = compile_to_b(&sorted[0].1)?;
    for (_, policy) in &sorted[1..] {
        let right = compile_to_b(policy)?;
        result = try_compile_or_pair(result, right)?;
    }

    Ok(result)
}

/// Compile thresh(k, subs).
fn compile_thresh(k: usize, subs: &[Policy]) -> Result<Miniscript, CompileError> {
    if k == 0 || k > subs.len() || subs.is_empty() {
        return Err(CompileError::InvalidThreshold { k, n: subs.len() });
    }

    // Special case: thresh(1, P) = just P
    if subs.len() == 1 && k == 1 {
        return compile_to_b(&subs[0]);
    }

    // Special case: thresh(n, P1..Pn) where k == n → chain of and()
    if k == subs.len() {
        let mut result = compile_to_b(&subs[0])?;
        for sub in &subs[1..] {
            let right = compile_to_b(sub)?;
            // Use and_v(v:left, right) which is the standard and
            if result.ty.base == BaseType::B {
                let left_v = Miniscript::verify(result);
                result = Miniscript::and_v(left_v, right);
            } else {
                let right_w = Miniscript::swap(right);
                result = Miniscript::and_b(result, right_w);
            }
        }
        return Ok(result);
    }

    // General case: compile each sub, first one stays B, rest become W via s:
    let first = compile_to_b(&subs[0])?;
    let mut compiled = vec![first];
    for sub in &subs[1..] {
        let ms = compile_to_b(sub)?;
        // Wrap in s: (swap) to convert B → W for thresh requirements
        compiled.push(Miniscript::swap(ms));
    }

    Ok(Miniscript::thresh(k, compiled))
}

/// Check if a type is Bdu (Base + dissatisfiable + unit).
fn is_bdu(ty: &MiniscriptType) -> bool {
    ty.base == BaseType::B && ty.modifiers.d && ty.modifiers.u
}

// ---------------------------------------------------------------------------
// Hex helpers
// ---------------------------------------------------------------------------

fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

fn hex_decode(hex: &str) -> Result<Vec<u8>, String> {
    if hex.len() % 2 != 0 {
        return Err("odd hex length".to_string());
    }
    let mut bytes = Vec::with_capacity(hex.len() / 2);
    for i in (0..hex.len()).step_by(2) {
        let byte = u8::from_str_radix(&hex[i..i + 2], 16)
            .map_err(|_| format!("invalid hex at position {}", i))?;
        bytes.push(byte);
    }
    Ok(bytes)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::hashing::sha256;
    use super::super::types::BaseType;

    /// Helper: create a dummy compressed public key from a byte seed.
    fn dummy_key(seed: u8) -> PublicKey {
        let hash = sha256(&[seed]);
        let mut secret = [0u8; 32];
        secret.copy_from_slice(hash.as_bytes());
        secret[0] = seed.wrapping_add(1).max(1);
        let secp = secp256k1::Secp256k1::new();
        let sk = secp256k1::SecretKey::from_slice(&secret).expect("valid secret key");
        let pk = secp256k1::PublicKey::from_secret_key(&secp, &sk);
        PublicKey::from_bytes(&pk.serialize()).unwrap()
    }

    fn dummy_key_hex(seed: u8) -> String {
        hex_encode(&dummy_key(seed).serialize())
    }

    // ── Parse: atoms ──────────────────────────────────────────────

    #[test]
    fn test_parse_pk() {
        let hex = dummy_key_hex(1);
        let policy = parse_policy(&format!("pk({})", hex)).unwrap();
        assert!(matches!(policy, Policy::PubKey(_)));
    }

    #[test]
    fn test_parse_pkh() {
        let hash_hex = hex_encode(&[0xab; 20]);
        let policy = parse_policy(&format!("pkh({})", hash_hex)).unwrap();
        match policy {
            Policy::PubKeyHash(h) => assert_eq!(h, [0xab; 20]),
            _ => panic!("expected PubKeyHash"),
        }
    }

    #[test]
    fn test_parse_older() {
        let policy = parse_policy("older(144)").unwrap();
        assert_eq!(policy, Policy::Older(144));
    }

    #[test]
    fn test_parse_after() {
        let policy = parse_policy("after(500000000)").unwrap();
        assert_eq!(policy, Policy::After(500_000_000));
    }

    #[test]
    fn test_parse_sha256() {
        let hash_hex = hex_encode(&[0x11; 32]);
        let policy = parse_policy(&format!("sha256({})", hash_hex)).unwrap();
        match policy {
            Policy::Sha256(h) => assert_eq!(h, [0x11; 32]),
            _ => panic!("expected Sha256"),
        }
    }

    #[test]
    fn test_parse_hash256() {
        let hash_hex = hex_encode(&[0x22; 32]);
        let policy = parse_policy(&format!("hash256({})", hash_hex)).unwrap();
        assert!(matches!(policy, Policy::Hash256(_)));
    }

    #[test]
    fn test_parse_ripemd160() {
        let hash_hex = hex_encode(&[0x33; 20]);
        let policy = parse_policy(&format!("ripemd160({})", hash_hex)).unwrap();
        assert!(matches!(policy, Policy::Ripemd160(_)));
    }

    #[test]
    fn test_parse_hash160() {
        let hash_hex = hex_encode(&[0x44; 20]);
        let policy = parse_policy(&format!("hash160({})", hash_hex)).unwrap();
        assert!(matches!(policy, Policy::Hash160(_)));
    }

    // ── Parse: combinators ────────────────────────────────────────

    #[test]
    fn test_parse_and() {
        let k1 = dummy_key_hex(10);
        let input = format!("and(pk({}),older(144))", k1);
        let policy = parse_policy(&input).unwrap();
        assert!(matches!(policy, Policy::And(_, _)));
    }

    #[test]
    fn test_parse_or() {
        let k1 = dummy_key_hex(20);
        let k2 = dummy_key_hex(21);
        let input = format!("or(pk({}),pk({}))", k1, k2);
        let policy = parse_policy(&input).unwrap();
        assert!(matches!(policy, Policy::Or(_, _)));
    }

    #[test]
    fn test_parse_thresh() {
        let k1 = dummy_key_hex(30);
        let k2 = dummy_key_hex(31);
        let k3 = dummy_key_hex(32);
        let input = format!("thresh(2,pk({}),pk({}),pk({}))", k1, k2, k3);
        let policy = parse_policy(&input).unwrap();
        match policy {
            Policy::Thresh(k, subs) => {
                assert_eq!(k, 2);
                assert_eq!(subs.len(), 3);
            }
            _ => panic!("expected Thresh"),
        }
    }

    #[test]
    fn test_parse_multi() {
        let k1 = dummy_key_hex(40);
        let k2 = dummy_key_hex(41);
        let input = format!("multi(1,{},{})", k1, k2);
        let policy = parse_policy(&input).unwrap();
        match policy {
            Policy::Multi(k, keys) => {
                assert_eq!(k, 1);
                assert_eq!(keys.len(), 2);
            }
            _ => panic!("expected Multi"),
        }
    }

    #[test]
    fn test_parse_weighted_or() {
        let k1 = dummy_key_hex(50);
        let k2 = dummy_key_hex(51);
        let input = format!("or(3@pk({}),1@pk({}))", k1, k2);
        let policy = parse_policy(&input).unwrap();
        match policy {
            Policy::WeightedOr(entries) => {
                assert_eq!(entries.len(), 2);
                assert_eq!(entries[0].0, 3);
                assert_eq!(entries[1].0, 1);
            }
            _ => panic!("expected WeightedOr"),
        }
    }

    #[test]
    fn test_parse_nested() {
        let k1 = dummy_key_hex(60);
        let k2 = dummy_key_hex(61);
        let input = format!("and(pk({}),or(older(144),pk({})))", k1, k2);
        let policy = parse_policy(&input).unwrap();
        match policy {
            Policy::And(_, right) => {
                assert!(matches!(*right, Policy::Or(_, _)));
            }
            _ => panic!("expected And"),
        }
    }

    // ── Parse: errors ─────────────────────────────────────────────

    #[test]
    fn test_parse_error_unknown_function() {
        let result = parse_policy("foobar(123)");
        assert!(matches!(result, Err(PolicyParseError::UnknownFunction(_))));
    }

    #[test]
    fn test_parse_error_trailing_chars() {
        let result = parse_policy("older(144) extra");
        assert!(matches!(result, Err(PolicyParseError::TrailingChars(_))));
    }

    #[test]
    fn test_parse_error_bad_number() {
        let result = parse_policy("older()");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_error_bad_hash() {
        let result = parse_policy("sha256(not_hex)");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_error_bad_threshold() {
        let k1 = dummy_key_hex(70);
        let result = parse_policy(&format!("thresh(5,pk({}))", k1));
        assert!(matches!(
            result,
            Err(PolicyParseError::InvalidThreshold { k: 5, n: 1 })
        ));
    }

    // ── Compile: atoms ────────────────────────────────────────────

    #[test]
    fn test_compile_pk() {
        let key = dummy_key(80);
        let ms = compile(&Policy::PubKey(key)).unwrap();
        // pk(K) = c:pk_k(K) → type B
        assert_eq!(ms.base_type(), BaseType::B);
    }

    #[test]
    fn test_compile_older() {
        let ms = compile(&Policy::Older(144)).unwrap();
        assert_eq!(ms.base_type(), BaseType::B);
    }

    #[test]
    fn test_compile_after() {
        let ms = compile(&Policy::After(500_000_000)).unwrap();
        assert_eq!(ms.base_type(), BaseType::B);
    }

    #[test]
    fn test_compile_sha256() {
        let ms = compile(&Policy::Sha256([0xaa; 32])).unwrap();
        assert_eq!(ms.base_type(), BaseType::B);
    }

    #[test]
    fn test_compile_multi() {
        let keys = vec![dummy_key(81), dummy_key(82), dummy_key(83)];
        let ms = compile(&Policy::Multi(2, keys)).unwrap();
        assert_eq!(ms.base_type(), BaseType::B);
    }

    // ── Compile: combinators ──────────────────────────────────────

    #[test]
    fn test_compile_and() {
        let policy = Policy::And(
            Box::new(Policy::PubKey(dummy_key(90))),
            Box::new(Policy::Older(144)),
        );
        let ms = compile(&policy).unwrap();
        assert_eq!(ms.base_type(), BaseType::B);
        // Should be and_v(v:pk(K), older(144))
        let s = ms.to_string();
        assert!(s.contains("and_v"));
    }

    #[test]
    fn test_compile_or() {
        let policy = Policy::Or(
            Box::new(Policy::PubKey(dummy_key(91))),
            Box::new(Policy::PubKey(dummy_key(92))),
        );
        let ms = compile(&policy).unwrap();
        assert_eq!(ms.base_type(), BaseType::B);
    }

    #[test]
    fn test_compile_weighted_or() {
        let entries = vec![
            (3, Policy::PubKey(dummy_key(93))),
            (1, Policy::Older(144)),
        ];
        let ms = compile(&Policy::WeightedOr(entries)).unwrap();
        assert_eq!(ms.base_type(), BaseType::B);
    }

    #[test]
    fn test_compile_thresh() {
        let policy = Policy::Thresh(
            2,
            vec![
                Policy::PubKey(dummy_key(94)),
                Policy::PubKey(dummy_key(95)),
                Policy::PubKey(dummy_key(96)),
            ],
        );
        let ms = compile(&policy).unwrap();
        assert_eq!(ms.base_type(), BaseType::B);
    }

    #[test]
    fn test_compile_thresh_all_required() {
        // thresh(3, P1, P2, P3) with k==n → chain of and_v
        let policy = Policy::Thresh(
            3,
            vec![
                Policy::PubKey(dummy_key(97)),
                Policy::PubKey(dummy_key(98)),
                Policy::PubKey(dummy_key(99)),
            ],
        );
        let ms = compile(&policy).unwrap();
        assert_eq!(ms.base_type(), BaseType::B);
        let s = ms.to_string();
        assert!(s.contains("and_v"));
    }

    // ── Display roundtrip ─────────────────────────────────────────

    #[test]
    fn test_display_roundtrip_atoms() {
        let key = dummy_key(100);
        let policy = Policy::PubKey(key);
        let s = policy.to_string();
        let reparsed = parse_policy(&s).unwrap();
        assert_eq!(policy, reparsed);
    }

    #[test]
    fn test_display_roundtrip_older() {
        let policy = Policy::Older(288);
        let s = policy.to_string();
        let reparsed = parse_policy(&s).unwrap();
        assert_eq!(policy, reparsed);
    }

    #[test]
    fn test_display_roundtrip_and() {
        let policy = Policy::And(
            Box::new(Policy::Older(144)),
            Box::new(Policy::After(1000)),
        );
        let s = policy.to_string();
        let reparsed = parse_policy(&s).unwrap();
        assert_eq!(policy, reparsed);
    }

    #[test]
    fn test_display_roundtrip_multi() {
        let keys = vec![dummy_key(110), dummy_key(111)];
        let policy = Policy::Multi(1, keys);
        let s = policy.to_string();
        let reparsed = parse_policy(&s).unwrap();
        assert_eq!(policy, reparsed);
    }

    // ── Full pipeline ─────────────────────────────────────────────

    #[test]
    fn test_full_pipeline_simple() {
        let key_hex = dummy_key_hex(120);
        let input = format!("pk({})", key_hex);
        let policy = parse_policy(&input).unwrap();
        let ms = compile(&policy).unwrap();
        let script = ms.encode();
        assert!(!script.is_empty());
    }

    #[test]
    fn test_full_pipeline_complex() {
        let k1 = dummy_key_hex(121);
        let k2 = dummy_key_hex(122);
        let input = format!("and(pk({}),or(older(144),pk({})))", k1, k2);
        let policy = parse_policy(&input).unwrap();
        let ms = compile(&policy).unwrap();
        assert_eq!(ms.base_type(), BaseType::B);
        let script = ms.encode();
        assert!(!script.is_empty());
    }

    #[test]
    fn test_full_pipeline_thresh() {
        let k1 = dummy_key_hex(123);
        let k2 = dummy_key_hex(124);
        let k3 = dummy_key_hex(125);
        let input = format!("thresh(2,pk({}),pk({}),pk({}))", k1, k2, k3);
        let policy = parse_policy(&input).unwrap();
        let ms = compile(&policy).unwrap();
        assert_eq!(ms.base_type(), BaseType::B);
        let script = ms.encode();
        assert!(!script.is_empty());
    }

    // ── Compile errors ────────────────────────────────────────────

    #[test]
    fn test_compile_error_bad_threshold() {
        let result = compile(&Policy::Thresh(5, vec![Policy::Older(1)]));
        assert!(matches!(result, Err(CompileError::InvalidThreshold { .. })));
    }

    #[test]
    fn test_compile_error_empty_weighted_or() {
        let result = compile(&Policy::WeightedOr(vec![]));
        assert!(matches!(result, Err(CompileError::EmptyWeightedOr)));
    }

    // ── Whitespace tolerance ──────────────────────────────────────

    #[test]
    fn test_parse_with_whitespace() {
        let k = dummy_key_hex(130);
        let input = format!("  and( pk({}) , older(144) )  ", k);
        let policy = parse_policy(&input).unwrap();
        assert!(matches!(policy, Policy::And(_, _)));
    }
}
