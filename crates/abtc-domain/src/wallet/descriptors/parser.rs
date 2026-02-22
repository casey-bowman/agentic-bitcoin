// Descriptor parser — String → Descriptor AST
//
// Recursive descent parser for output descriptor strings.
// Handles: pk(), pkh(), wpkh(), sh(), wsh(), tr(), multi(), sortedmulti(), multi_a()
// Key expressions: raw hex pubkeys, xpub/xprv with derivation paths, origin info.
// Optional '#checksum' suffix.
//
// Reference: BIP380-386

use std::fmt;

use crate::wallet::keys::PublicKey;
use crate::wallet::hd::{ExtendedPublicKey, ExtendedPrivateKey};
use crate::script::miniscript::Miniscript;

use super::checksum;
use super::descriptor::{Descriptor, ShInner, WshInner, TrTree};
use super::key_expr::{
    DescriptorKey, SingleKey, ExtendedKey, XKey, KeyOrigin, Wildcard, HARDENED_BIT,
};

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Errors from descriptor parsing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseError {
    /// Unexpected end of input.
    UnexpectedEnd,
    /// Expected a specific character.
    Expected(char, Option<char>),
    /// Unknown function name.
    UnknownFunction(String),
    /// Invalid key expression.
    InvalidKey(String),
    /// Invalid threshold value.
    InvalidThreshold(String),
    /// Checksum verification failed.
    Checksum(String),
    /// Nesting error.
    InvalidNesting(String),
    /// General parse error.
    Other(String),
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ParseError::UnexpectedEnd => write!(f, "unexpected end of descriptor"),
            ParseError::Expected(exp, got) => match got {
                Some(g) => write!(f, "expected '{}', found '{}'", exp, g),
                None => write!(f, "expected '{}'", exp),
            },
            ParseError::UnknownFunction(name) => write!(f, "unknown function: {}", name),
            ParseError::InvalidKey(msg) => write!(f, "invalid key: {}", msg),
            ParseError::InvalidThreshold(msg) => write!(f, "invalid threshold: {}", msg),
            ParseError::Checksum(msg) => write!(f, "checksum error: {}", msg),
            ParseError::InvalidNesting(msg) => write!(f, "invalid nesting: {}", msg),
            ParseError::Other(msg) => write!(f, "{}", msg),
        }
    }
}

impl std::error::Error for ParseError {}

// ---------------------------------------------------------------------------
// Parser state
// ---------------------------------------------------------------------------

struct Parser<'a> {
    input: &'a str,
    pos: usize,
}

impl<'a> Parser<'a> {
    fn new(input: &'a str) -> Self {
        Self { input, pos: 0 }
    }

    fn remaining(&self) -> &'a str {
        &self.input[self.pos..]
    }

    fn is_empty(&self) -> bool {
        self.pos >= self.input.len()
    }

    fn peek(&self) -> Option<char> {
        self.input[self.pos..].chars().next()
    }

    fn advance(&mut self, n: usize) {
        self.pos += n;
    }

    fn expect_char(&mut self, c: char) -> Result<(), ParseError> {
        match self.peek() {
            Some(ch) if ch == c => {
                self.advance(ch.len_utf8());
                Ok(())
            }
            other => Err(ParseError::Expected(c, other)),
        }
    }

    fn read_until(&mut self, stop: impl Fn(char) -> bool) -> &'a str {
        let start = self.pos;
        while self.pos < self.input.len() {
            let ch = self.input[self.pos..].chars().next().unwrap();
            if stop(ch) {
                break;
            }
            self.pos += ch.len_utf8();
        }
        &self.input[start..self.pos]
    }

    fn read_ident(&mut self) -> &'a str {
        self.read_until(|c| !c.is_ascii_alphanumeric() && c != '_')
    }

    fn read_number(&mut self) -> Result<usize, ParseError> {
        let num_str = self.read_until(|c| !c.is_ascii_digit());
        if num_str.is_empty() {
            return Err(ParseError::Other("expected number".to_string()));
        }
        num_str.parse::<usize>()
            .map_err(|_| ParseError::InvalidThreshold(num_str.to_string()))
    }
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Parse a descriptor string into a Descriptor AST.
///
/// Accepts descriptors with or without a '#checksum' suffix.
pub fn parse_descriptor(input: &str) -> Result<Descriptor, ParseError> {
    // Strip checksum if present
    let body = if let Some(hash_pos) = input.rfind('#') {
        let checksum_str = &input[hash_pos + 1..];
        if checksum_str.len() == 8 {
            // Verify the checksum
            let body = &input[..hash_pos];
            checksum::verify_checksum(input)
                .map_err(|e| ParseError::Checksum(e.to_string()))?;
            body
        } else {
            input
        }
    } else {
        input
    };

    let mut parser = Parser::new(body);
    let desc = parse_top_level(&mut parser)?;

    if !parser.is_empty() {
        return Err(ParseError::Other(format!(
            "trailing characters: '{}'",
            parser.remaining()
        )));
    }

    Ok(desc)
}

// ---------------------------------------------------------------------------
// Internal parsing
// ---------------------------------------------------------------------------

fn parse_top_level(p: &mut Parser) -> Result<Descriptor, ParseError> {
    let func = p.read_ident();
    match func {
        "pk" => {
            p.expect_char('(')?;
            let key = parse_key_expr(p)?;
            p.expect_char(')')?;
            Ok(Descriptor::Pk(key))
        }
        "pkh" => {
            p.expect_char('(')?;
            let key = parse_key_expr(p)?;
            p.expect_char(')')?;
            Ok(Descriptor::Pkh(key))
        }
        "wpkh" => {
            p.expect_char('(')?;
            let key = parse_key_expr(p)?;
            p.expect_char(')')?;
            Ok(Descriptor::Wpkh(key))
        }
        "sh" => {
            p.expect_char('(')?;
            let inner_func = p.read_ident();
            match inner_func {
                "wpkh" => {
                    p.expect_char('(')?;
                    let key = parse_key_expr(p)?;
                    p.expect_char(')')?;
                    p.expect_char(')')?;
                    Ok(Descriptor::ShWpkh(key))
                }
                "wsh" => {
                    p.expect_char('(')?;
                    let inner = parse_wsh_inner(p)?;
                    p.expect_char(')')?;
                    p.expect_char(')')?;
                    Ok(Descriptor::ShWsh(inner))
                }
                "multi" => {
                    p.expect_char('(')?;
                    let (k, keys) = parse_multi_args(p)?;
                    p.expect_char(')')?;
                    p.expect_char(')')?;
                    Ok(Descriptor::Sh(ShInner::Multi(k, keys)))
                }
                "sortedmulti" => {
                    p.expect_char('(')?;
                    let (k, keys) = parse_multi_args(p)?;
                    p.expect_char(')')?;
                    p.expect_char(')')?;
                    Ok(Descriptor::Sh(ShInner::SortedMulti(k, keys)))
                }
                _ => Err(ParseError::InvalidNesting(format!(
                    "sh({}) is not valid",
                    inner_func
                ))),
            }
        }
        "wsh" => {
            p.expect_char('(')?;
            let inner = parse_wsh_inner(p)?;
            p.expect_char(')')?;
            Ok(Descriptor::Wsh(inner))
        }
        "tr" => {
            p.expect_char('(')?;
            let key = parse_key_expr(p)?;
            let tree = if p.peek() == Some(',') {
                p.advance(1);
                Some(parse_tr_tree(p)?)
            } else {
                None
            };
            p.expect_char(')')?;
            Ok(Descriptor::Tr(key, tree))
        }
        _ => Err(ParseError::UnknownFunction(func.to_string())),
    }
}

fn parse_wsh_inner(p: &mut Parser) -> Result<WshInner, ParseError> {
    let func = p.read_ident();
    match func {
        "multi" => {
            p.expect_char('(')?;
            let (k, keys) = parse_multi_args(p)?;
            p.expect_char(')')?;
            Ok(WshInner::Multi(k, keys))
        }
        "sortedmulti" => {
            p.expect_char('(')?;
            let (k, keys) = parse_multi_args(p)?;
            p.expect_char(')')?;
            Ok(WshInner::SortedMulti(k, keys))
        }
        _ => {
            // For now, we don't support parsing arbitrary miniscript from
            // descriptor strings (that would require a full miniscript
            // string parser).  Return an error for unrecognized inner content.
            Err(ParseError::Other(format!(
                "miniscript string parsing not yet supported in wsh({}...)",
                func
            )))
        }
    }
}

fn parse_multi_args(p: &mut Parser) -> Result<(usize, Vec<DescriptorKey>), ParseError> {
    let k = p.read_number()?;
    let mut keys = Vec::new();
    while p.peek() == Some(',') {
        p.advance(1); // skip ','
        let key = parse_key_expr(p)?;
        keys.push(key);
    }
    if keys.is_empty() {
        return Err(ParseError::InvalidThreshold("no keys in multi".to_string()));
    }
    if k == 0 || k > keys.len() {
        return Err(ParseError::InvalidThreshold(format!(
            "k={} with {} keys",
            k,
            keys.len()
        )));
    }
    Ok((k, keys))
}

fn parse_tr_tree(p: &mut Parser) -> Result<TrTree, ParseError> {
    if p.peek() == Some('{') {
        // Branch: {left,right}
        p.advance(1); // skip '{'
        let left = parse_tr_tree(p)?;
        p.expect_char(',')?;
        let right = parse_tr_tree(p)?;
        p.expect_char('}')?;
        Ok(TrTree::Branch(Box::new(left), Box::new(right)))
    } else {
        // Leaf: a miniscript expression
        // For now, we support pk(key) as a leaf expression
        let func = p.read_ident();
        match func {
            "pk" => {
                p.expect_char('(')?;
                let key = parse_key_expr(p)?;
                p.expect_char(')')?;
                let pk = key.derive_public_key(0)
                    .map_err(|e| ParseError::InvalidKey(e.to_string()))?;
                Ok(TrTree::Leaf(Miniscript::pk(pk)))
            }
            "pk_k" => {
                p.expect_char('(')?;
                let key = parse_key_expr(p)?;
                p.expect_char(')')?;
                let pk = key.derive_public_key(0)
                    .map_err(|e| ParseError::InvalidKey(e.to_string()))?;
                Ok(TrTree::Leaf(Miniscript::pk_k(pk)))
            }
            _ => Err(ParseError::Other(format!(
                "unsupported tapscript leaf: {}",
                func
            ))),
        }
    }
}

// ---------------------------------------------------------------------------
// Key expression parsing
// ---------------------------------------------------------------------------

fn parse_key_expr(p: &mut Parser) -> Result<DescriptorKey, ParseError> {
    // Check for origin: [fingerprint/path]
    let origin = if p.peek() == Some('[') {
        Some(parse_key_origin(p)?)
    } else {
        None
    };

    // Read the key material — everything up to the next delimiter
    let _key_start = p.pos;
    let key_str = p.read_until(|c| c == ')' || c == ',' || c == '#');

    if key_str.is_empty() {
        return Err(ParseError::InvalidKey("empty key expression".to_string()));
    }

    // Try to parse as xpub/xprv (starts with xpub, xprv, tpub, tprv)
    if key_str.starts_with("xpub") || key_str.starts_with("tpub")
        || key_str.starts_with("xprv") || key_str.starts_with("tprv")
    {
        return parse_extended_key(key_str, origin);
    }

    // Otherwise, try to parse as a hex public key
    let hex_part = key_str;
    let bytes = hex_decode(hex_part)
        .map_err(|_| ParseError::InvalidKey(format!("invalid hex: {}", hex_part)))?;

    if bytes.len() == 33 {
        let pk = PublicKey::from_bytes(&bytes)
            .map_err(|_| ParseError::InvalidKey("invalid pubkey".to_string()))?;
        Ok(DescriptorKey::Single(SingleKey { key: pk, origin }))
    } else {
        Err(ParseError::InvalidKey(format!(
            "expected 33-byte compressed pubkey, got {} bytes",
            bytes.len()
        )))
    }
}

fn parse_key_origin(p: &mut Parser) -> Result<KeyOrigin, ParseError> {
    p.expect_char('[')?;

    // Read 8 hex chars for fingerprint
    let fp_str = &p.remaining()[..8.min(p.remaining().len())];
    if fp_str.len() < 8 {
        return Err(ParseError::InvalidKey("fingerprint too short".to_string()));
    }
    let fp_bytes = hex_decode(fp_str)
        .map_err(|_| ParseError::InvalidKey("invalid fingerprint hex".to_string()))?;
    p.advance(8);

    let mut fingerprint = [0u8; 4];
    fingerprint.copy_from_slice(&fp_bytes);

    let mut path = Vec::new();
    while p.peek() == Some('/') {
        p.advance(1); // skip '/'
        let idx = p.read_number()?;
        let hardened = match p.peek() {
            Some('h') | Some('\'') | Some('H') => {
                p.advance(1);
                true
            }
            _ => false,
        };
        let value = if hardened {
            (idx as u32) | HARDENED_BIT
        } else {
            idx as u32
        };
        path.push(value);
    }

    p.expect_char(']')?;

    Ok(KeyOrigin { fingerprint, path })
}

fn parse_extended_key(
    key_str: &str,
    origin: Option<KeyOrigin>,
) -> Result<DescriptorKey, ParseError> {
    // Split on '/' to separate base58 from derivation path
    let parts: Vec<&str> = key_str.splitn(2, '/').collect();
    let base58 = parts[0];

    // Parse the xkey
    let xkey = if base58.starts_with("xpub") || base58.starts_with("tpub") {
        let xpub = ExtendedPublicKey::from_base58(base58)
            .map_err(|e| ParseError::InvalidKey(format!("invalid xpub: {}", e)))?;
        XKey::Pub(xpub)
    } else {
        let xprv = ExtendedPrivateKey::from_base58(base58)
            .map_err(|e| ParseError::InvalidKey(format!("invalid xprv: {}", e)))?;
        XKey::Priv(xprv)
    };

    // Parse derivation path and wildcard
    let mut derivation_path = Vec::new();
    let mut wildcard = Wildcard::None;

    if parts.len() > 1 {
        let path_str = parts[1];
        for segment in path_str.split('/') {
            if segment == "*" {
                wildcard = Wildcard::Unhardened;
            } else if segment == "*h" || segment == "*'" || segment == "*H" {
                wildcard = Wildcard::Hardened;
            } else {
                let (num_str, hardened) = if segment.ends_with('h')
                    || segment.ends_with('\'')
                    || segment.ends_with('H')
                {
                    (&segment[..segment.len() - 1], true)
                } else {
                    (segment, false)
                };
                let idx: u32 = num_str
                    .parse()
                    .map_err(|_| ParseError::InvalidKey(format!("bad path index: {}", segment)))?;
                let value = if hardened { idx | HARDENED_BIT } else { idx };
                derivation_path.push(value);
            }
        }
    }

    Ok(DescriptorKey::Extended(ExtendedKey {
        xkey,
        origin,
        derivation_path,
        wildcard,
    }))
}

// ---------------------------------------------------------------------------
// Hex helper
// ---------------------------------------------------------------------------

fn hex_decode(s: &str) -> Result<Vec<u8>, ()> {
    if s.len() % 2 != 0 {
        return Err(());
    }
    let mut bytes = Vec::with_capacity(s.len() / 2);
    for i in (0..s.len()).step_by(2) {
        let byte = u8::from_str_radix(&s[i..i + 2], 16).map_err(|_| ())?;
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

    fn dummy_key_hex(seed: u8) -> String {
        use crate::crypto::hashing::sha256;
        let hash = sha256(&[seed]);
        let mut secret = [0u8; 32];
        secret.copy_from_slice(hash.as_bytes());
        secret[0] = seed.wrapping_add(1).max(1);
        let secp = secp256k1::Secp256k1::new();
        let sk = secp256k1::SecretKey::from_slice(&secret).unwrap();
        let pk = secp256k1::PublicKey::from_secret_key(&secp, &sk);
        let bytes = pk.serialize();
        bytes.iter().map(|b| format!("{:02x}", b)).collect()
    }

    #[test]
    fn test_parse_pkh() {
        let hex = dummy_key_hex(1);
        let desc_str = format!("pkh({})", hex);
        let desc = parse_descriptor(&desc_str).unwrap();
        match desc {
            Descriptor::Pkh(_) => {}
            _ => panic!("expected Pkh"),
        }
    }

    #[test]
    fn test_parse_wpkh() {
        let hex = dummy_key_hex(2);
        let desc_str = format!("wpkh({})", hex);
        let desc = parse_descriptor(&desc_str).unwrap();
        match desc {
            Descriptor::Wpkh(_) => {}
            _ => panic!("expected Wpkh"),
        }
    }

    #[test]
    fn test_parse_sh_wpkh() {
        let hex = dummy_key_hex(3);
        let desc_str = format!("sh(wpkh({}))", hex);
        let desc = parse_descriptor(&desc_str).unwrap();
        match desc {
            Descriptor::ShWpkh(_) => {}
            _ => panic!("expected ShWpkh"),
        }
    }

    #[test]
    fn test_parse_sh_multi() {
        let k1 = dummy_key_hex(10);
        let k2 = dummy_key_hex(11);
        let desc_str = format!("sh(multi(1,{},{}))", k1, k2);
        let desc = parse_descriptor(&desc_str).unwrap();
        match desc {
            Descriptor::Sh(ShInner::Multi(k, keys)) => {
                assert_eq!(k, 1);
                assert_eq!(keys.len(), 2);
            }
            _ => panic!("expected Sh(Multi)"),
        }
    }

    #[test]
    fn test_parse_wsh_sortedmulti() {
        let k1 = dummy_key_hex(20);
        let k2 = dummy_key_hex(21);
        let k3 = dummy_key_hex(22);
        let desc_str = format!("wsh(sortedmulti(2,{},{},{}))", k1, k2, k3);
        let desc = parse_descriptor(&desc_str).unwrap();
        match desc {
            Descriptor::Wsh(WshInner::SortedMulti(k, keys)) => {
                assert_eq!(k, 2);
                assert_eq!(keys.len(), 3);
            }
            _ => panic!("expected Wsh(SortedMulti)"),
        }
    }

    #[test]
    fn test_parse_tr_key_only() {
        let hex = dummy_key_hex(30);
        let desc_str = format!("tr({})", hex);
        let desc = parse_descriptor(&desc_str).unwrap();
        match desc {
            Descriptor::Tr(_, None) => {}
            _ => panic!("expected Tr with no tree"),
        }
    }

    #[test]
    fn test_parse_tr_with_tree() {
        let k1 = dummy_key_hex(30);
        let k2 = dummy_key_hex(31);
        let k3 = dummy_key_hex(32);
        let desc_str = format!("tr({},{{pk({}),pk({})}})", k1, k2, k3);
        let desc = parse_descriptor(&desc_str).unwrap();
        match desc {
            Descriptor::Tr(_, Some(TrTree::Branch(_, _))) => {}
            _ => panic!("expected Tr with branch tree"),
        }
    }

    #[test]
    fn test_parse_with_origin() {
        let hex = dummy_key_hex(40);
        let desc_str = format!("wpkh([deadbeef/44h/0h/0h]{})", hex);
        let desc = parse_descriptor(&desc_str).unwrap();
        match desc {
            Descriptor::Wpkh(DescriptorKey::Single(sk)) => {
                let origin = sk.origin.unwrap();
                assert_eq!(origin.fingerprint, [0xde, 0xad, 0xbe, 0xef]);
                assert_eq!(origin.path.len(), 3);
                assert_eq!(origin.path[0], 44 | HARDENED_BIT);
            }
            _ => panic!("expected Wpkh with origin"),
        }
    }

    #[test]
    fn test_parse_with_xpub() {
        // Create a real xpub
        let seed = [0x42u8; 64];
        let xprv = ExtendedPrivateKey::from_seed(&seed, true).unwrap();
        let xpub = xprv.to_extended_public_key();
        let xpub_str = xpub.to_base58();

        let desc_str = format!("wpkh({}/0/*)", xpub_str);
        let desc = parse_descriptor(&desc_str).unwrap();
        match desc {
            Descriptor::Wpkh(DescriptorKey::Extended(ek)) => {
                assert_eq!(ek.derivation_path, vec![0]);
                assert_eq!(ek.wildcard, Wildcard::Unhardened);
            }
            _ => panic!("expected Wpkh with extended key"),
        }
    }

    #[test]
    fn test_parse_with_checksum() {
        let hex = dummy_key_hex(50);
        let desc_body = format!("wpkh({})", hex);
        let full = checksum::add_checksum(&desc_body).unwrap();
        let desc = parse_descriptor(&full).unwrap();
        match desc {
            Descriptor::Wpkh(_) => {}
            _ => panic!("expected Wpkh"),
        }
    }

    #[test]
    fn test_parse_bad_checksum() {
        let hex = dummy_key_hex(51);
        let desc_str = format!("wpkh({})#qqqqqqqq", hex);
        let result = parse_descriptor(&desc_str);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_unknown_function() {
        let result = parse_descriptor("foobar(key)");
        assert!(matches!(result, Err(ParseError::UnknownFunction(_))));
    }

    #[test]
    fn test_parse_invalid_multi_threshold() {
        let k1 = dummy_key_hex(60);
        // k=0 is invalid
        let desc_str = format!("sh(multi(0,{}))", k1);
        let result = parse_descriptor(&desc_str);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_sh_wsh() {
        let k1 = dummy_key_hex(70);
        let k2 = dummy_key_hex(71);
        let desc_str = format!("sh(wsh(multi(1,{},{})))", k1, k2);
        let desc = parse_descriptor(&desc_str).unwrap();
        match desc {
            Descriptor::ShWsh(WshInner::Multi(k, keys)) => {
                assert_eq!(k, 1);
                assert_eq!(keys.len(), 2);
            }
            _ => panic!("expected ShWsh(Multi)"),
        }
    }

    #[test]
    fn test_hex_decode() {
        assert_eq!(hex_decode("deadbeef").unwrap(), vec![0xde, 0xad, 0xbe, 0xef]);
        assert!(hex_decode("xyz").is_err());
        assert!(hex_decode("0").is_err()); // odd length
    }
}
