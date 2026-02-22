// Output descriptor types
//
// Defines the Descriptor enum and its nested structures representing
// all standard output descriptor types (BIP380-386).
//
// Reference:
//   BIP380: Output Script Descriptors General Operation
//   BIP381: Non-Segwit Output Script Descriptors (pk, pkh, sh)
//   BIP382: Segwit Output Script Descriptors (wpkh, wsh)
//   BIP383: Multisig Output Script Descriptors (multi, sortedmulti)
//   BIP384: sh(wpkh) Combo Output Script Descriptors
//   BIP385: raw() and addr() Descriptors (not implemented)
//   BIP386: tr() Output Script Descriptors

use std::fmt;

use crate::script::miniscript::Miniscript;
use super::key_expr::DescriptorKey;

// ---------------------------------------------------------------------------
// Descriptor — the top-level enum
// ---------------------------------------------------------------------------

/// A parsed output descriptor.
#[derive(Debug, Clone)]
pub enum Descriptor {
    /// `pk(key)` — Pay-to-pubkey (bare, rarely used).
    Pk(DescriptorKey),

    /// `pkh(key)` — Pay-to-pubkey-hash (P2PKH, legacy).
    Pkh(DescriptorKey),

    /// `wpkh(key)` — Pay-to-witness-pubkey-hash (P2WPKH, native segwit).
    Wpkh(DescriptorKey),

    /// `sh(wpkh(key))` — P2SH-wrapped P2WPKH.
    ShWpkh(DescriptorKey),

    /// `sh(...)` — Pay-to-script-hash with inner content.
    Sh(ShInner),

    /// `wsh(...)` — Pay-to-witness-script-hash (native segwit).
    Wsh(WshInner),

    /// `sh(wsh(...))` — P2SH-wrapped P2WSH.
    ShWsh(WshInner),

    /// `tr(key)` or `tr(key, tree)` — Pay-to-taproot (BIP341).
    Tr(DescriptorKey, Option<TrTree>),
}

// ---------------------------------------------------------------------------
// ShInner — what goes inside sh()
// ---------------------------------------------------------------------------

/// The inner content of a `sh()` descriptor.
#[derive(Debug, Clone)]
pub enum ShInner {
    /// `sh(wpkh(key))`  (canonically represented as ShWpkh at the top level,
    /// but this variant exists for completeness in parsing)
    Wpkh(DescriptorKey),

    /// `sh(wsh(...))`  (canonically represented as ShWsh at the top level)
    Wsh(WshInner),

    /// `sh(multi(k, keys...))`
    Multi(usize, Vec<DescriptorKey>),

    /// `sh(sortedmulti(k, keys...))`
    SortedMulti(usize, Vec<DescriptorKey>),
}

// ---------------------------------------------------------------------------
// WshInner — what goes inside wsh()
// ---------------------------------------------------------------------------

/// The inner content of a `wsh()` descriptor.
#[derive(Debug, Clone)]
pub enum WshInner {
    /// `wsh(multi(k, keys...))`
    Multi(usize, Vec<DescriptorKey>),

    /// `wsh(sortedmulti(k, keys...))`
    SortedMulti(usize, Vec<DescriptorKey>),

    /// `wsh(<miniscript>)` — a generic miniscript expression.
    Miniscript(Miniscript),
}

// ---------------------------------------------------------------------------
// TrTree — Taproot script tree
// ---------------------------------------------------------------------------

/// A Taproot script tree.
///
/// Represents the binary tree of TapLeaf scripts used in `tr()` descriptors.
/// Each leaf contains a miniscript expression; branches are pairs of subtrees.
#[derive(Debug, Clone)]
pub enum TrTree {
    /// A single leaf containing a miniscript expression.
    Leaf(Miniscript),

    /// A branch with two child subtrees.
    Branch(Box<TrTree>, Box<TrTree>),
}

// ---------------------------------------------------------------------------
// Display
// ---------------------------------------------------------------------------

impl fmt::Display for Descriptor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Descriptor::Pk(key) => write!(f, "pk({})", key),
            Descriptor::Pkh(key) => write!(f, "pkh({})", key),
            Descriptor::Wpkh(key) => write!(f, "wpkh({})", key),
            Descriptor::ShWpkh(key) => write!(f, "sh(wpkh({}))", key),
            Descriptor::Sh(inner) => write!(f, "sh({})", inner),
            Descriptor::Wsh(inner) => write!(f, "wsh({})", inner),
            Descriptor::ShWsh(inner) => write!(f, "sh(wsh({}))", inner),
            Descriptor::Tr(key, tree) => {
                write!(f, "tr({}", key)?;
                if let Some(tree) = tree {
                    write!(f, ",{}", tree)?;
                }
                write!(f, ")")
            }
        }
    }
}

impl fmt::Display for ShInner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ShInner::Wpkh(key) => write!(f, "wpkh({})", key),
            ShInner::Wsh(inner) => write!(f, "wsh({})", inner),
            ShInner::Multi(k, keys) => {
                write!(f, "multi({}", k)?;
                for key in keys {
                    write!(f, ",{}", key)?;
                }
                write!(f, ")")
            }
            ShInner::SortedMulti(k, keys) => {
                write!(f, "sortedmulti({}", k)?;
                for key in keys {
                    write!(f, ",{}", key)?;
                }
                write!(f, ")")
            }
        }
    }
}

impl fmt::Display for WshInner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            WshInner::Multi(k, keys) => {
                write!(f, "multi({}", k)?;
                for key in keys {
                    write!(f, ",{}", key)?;
                }
                write!(f, ")")
            }
            WshInner::SortedMulti(k, keys) => {
                write!(f, "sortedmulti({}", k)?;
                for key in keys {
                    write!(f, ",{}", key)?;
                }
                write!(f, ")")
            }
            WshInner::Miniscript(ms) => write!(f, "{}", ms),
        }
    }
}

impl fmt::Display for TrTree {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TrTree::Leaf(ms) => write!(f, "{}", ms),
            TrTree::Branch(left, right) => write!(f, "{{{},{}}}", left, right),
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wallet::keys::PublicKey;
    use crate::wallet::descriptors::key_expr::{SingleKey, DescriptorKey};

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

    fn single_dk(seed: u8) -> DescriptorKey {
        DescriptorKey::Single(SingleKey {
            key: dummy_key(seed),
            origin: None,
        })
    }

    #[test]
    fn test_display_pk() {
        let desc = Descriptor::Pk(single_dk(1));
        let s = desc.to_string();
        assert!(s.starts_with("pk("));
        assert!(s.ends_with(")"));
    }

    #[test]
    fn test_display_pkh() {
        let desc = Descriptor::Pkh(single_dk(2));
        let s = desc.to_string();
        assert!(s.starts_with("pkh("));
    }

    #[test]
    fn test_display_wpkh() {
        let desc = Descriptor::Wpkh(single_dk(3));
        let s = desc.to_string();
        assert!(s.starts_with("wpkh("));
    }

    #[test]
    fn test_display_sh_wpkh() {
        let desc = Descriptor::ShWpkh(single_dk(4));
        let s = desc.to_string();
        assert!(s.starts_with("sh(wpkh("));
        assert!(s.ends_with("))"));
    }

    #[test]
    fn test_display_sh_multi() {
        let desc = Descriptor::Sh(ShInner::Multi(
            2,
            vec![single_dk(10), single_dk(11), single_dk(12)],
        ));
        let s = desc.to_string();
        assert!(s.starts_with("sh(multi(2,"));
        assert!(s.ends_with("))"));
    }

    #[test]
    fn test_display_wsh_sortedmulti() {
        let desc = Descriptor::Wsh(WshInner::SortedMulti(
            1,
            vec![single_dk(20), single_dk(21)],
        ));
        let s = desc.to_string();
        assert!(s.starts_with("wsh(sortedmulti(1,"));
    }

    #[test]
    fn test_display_tr_key_only() {
        let desc = Descriptor::Tr(single_dk(30), None);
        let s = desc.to_string();
        assert!(s.starts_with("tr("));
        assert!(s.ends_with(")"));
        // No comma for key-only
        assert!(!s.contains(",{"));
    }

    #[test]
    fn test_display_tr_with_tree() {
        use crate::script::miniscript::fragment::Miniscript as Ms;
        let tree = TrTree::Branch(
            Box::new(TrTree::Leaf(Ms::pk(dummy_key(40)))),
            Box::new(TrTree::Leaf(Ms::pk(dummy_key(41)))),
        );
        let desc = Descriptor::Tr(single_dk(30), Some(tree));
        let s = desc.to_string();
        assert!(s.starts_with("tr("));
        assert!(s.contains(",{"));
    }
}
