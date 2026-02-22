// Descriptor compiler — Descriptor → Script / Address
//
// Given a parsed descriptor and an index (for wildcard substitution),
// produces the scriptPubKey, witness script, redeem script, and address.
//
// Reference: BIP380-386

use std::fmt;

use crate::crypto::hashing::{hash160, sha256};
use crate::script::opcodes::Opcodes;
use crate::script::script::{Script, ScriptBuilder};
use crate::wallet::address::Address;

use super::descriptor::{Descriptor, ShInner, WshInner, TrTree};
use super::key_expr::{DescriptorKey, KeyError};

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Errors that can occur during descriptor compilation.
#[derive(Debug, Clone)]
pub enum DescriptorError {
    /// Key derivation failed.
    Key(KeyError),
    /// Address encoding failed.
    Address(String),
    /// Unsupported descriptor type or combination.
    Unsupported(String),
}

impl fmt::Display for DescriptorError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DescriptorError::Key(e) => write!(f, "key error: {}", e),
            DescriptorError::Address(e) => write!(f, "address error: {}", e),
            DescriptorError::Unsupported(msg) => write!(f, "unsupported: {}", msg),
        }
    }
}

impl std::error::Error for DescriptorError {}

impl From<KeyError> for DescriptorError {
    fn from(e: KeyError) -> Self {
        DescriptorError::Key(e)
    }
}

// ---------------------------------------------------------------------------
// Compilation methods on Descriptor
// ---------------------------------------------------------------------------

impl Descriptor {
    /// Derive the scriptPubKey for this descriptor at the given index.
    ///
    /// The index is used for wildcard substitution in extended keys.
    /// For descriptors without wildcards, the index is ignored.
    pub fn script_pubkey(&self, index: u32) -> Result<Script, DescriptorError> {
        match self {
            // pk(key) → <key> OP_CHECKSIG
            Descriptor::Pk(key) => {
                let pk = key.derive_public_key(index)?;
                let script = ScriptBuilder::new()
                    .push_slice(&pk.serialize())
                    .push_opcode(Opcodes::OP_CHECKSIG)
                    .build();
                Ok(script)
            }

            // pkh(key) → OP_DUP OP_HASH160 <hash160(key)> OP_EQUALVERIFY OP_CHECKSIG
            Descriptor::Pkh(key) => {
                let pk = key.derive_public_key(index)?;
                let pkh = pk.pubkey_hash();
                let script = ScriptBuilder::new()
                    .push_opcode(Opcodes::OP_DUP)
                    .push_opcode(Opcodes::OP_HASH160)
                    .push_slice(&pkh)
                    .push_opcode(Opcodes::OP_EQUALVERIFY)
                    .push_opcode(Opcodes::OP_CHECKSIG)
                    .build();
                Ok(script)
            }

            // wpkh(key) → OP_0 <hash160(key)>
            Descriptor::Wpkh(key) => {
                let pk = key.derive_public_key(index)?;
                let pkh = pk.pubkey_hash();
                let script = ScriptBuilder::new()
                    .push_opcode(Opcodes::OP_0)
                    .push_slice(&pkh)
                    .build();
                Ok(script)
            }

            // sh(wpkh(key)) → OP_HASH160 <hash160(witness_program)> OP_EQUAL
            Descriptor::ShWpkh(key) => {
                let pk = key.derive_public_key(index)?;
                let pkh = pk.pubkey_hash();
                // The witness program is: OP_0 <pkh>
                let witness_program = ScriptBuilder::new()
                    .push_opcode(Opcodes::OP_0)
                    .push_slice(&pkh)
                    .build();
                let script_hash = hash160(witness_program.as_bytes());
                let script = ScriptBuilder::new()
                    .push_opcode(Opcodes::OP_HASH160)
                    .push_slice(&script_hash)
                    .push_opcode(Opcodes::OP_EQUAL)
                    .build();
                Ok(script)
            }

            // sh(...) → OP_HASH160 <hash160(redeemscript)> OP_EQUAL
            Descriptor::Sh(inner) => {
                let redeem = compile_sh_inner(inner, index)?;
                let script_hash = hash160(redeem.as_bytes());
                let script = ScriptBuilder::new()
                    .push_opcode(Opcodes::OP_HASH160)
                    .push_slice(&script_hash)
                    .push_opcode(Opcodes::OP_EQUAL)
                    .build();
                Ok(script)
            }

            // wsh(...) → OP_0 <sha256(witness_script)>
            Descriptor::Wsh(inner) => {
                let witness_script = compile_wsh_inner(inner, index)?;
                let script_hash = sha256_raw(witness_script.as_bytes());
                let script = ScriptBuilder::new()
                    .push_opcode(Opcodes::OP_0)
                    .push_slice(&script_hash)
                    .build();
                Ok(script)
            }

            // sh(wsh(...)) → OP_HASH160 <hash160(OP_0 <sha256(ws)>)> OP_EQUAL
            Descriptor::ShWsh(inner) => {
                let witness_script = compile_wsh_inner(inner, index)?;
                let ws_hash = sha256_raw(witness_script.as_bytes());
                let witness_program = ScriptBuilder::new()
                    .push_opcode(Opcodes::OP_0)
                    .push_slice(&ws_hash)
                    .build();
                let script_hash = hash160(witness_program.as_bytes());
                let script = ScriptBuilder::new()
                    .push_opcode(Opcodes::OP_HASH160)
                    .push_slice(&script_hash)
                    .push_opcode(Opcodes::OP_EQUAL)
                    .build();
                Ok(script)
            }

            // tr(key) → OP_1 <32-byte tweaked output key>
            // tr(key, tree) → OP_1 <32-byte tweaked output key>
            Descriptor::Tr(key, tree) => {
                let pk = key.derive_public_key(index)?;
                let pk_bytes = pk.serialize();
                // x-only pubkey: drop the first byte (prefix)
                let mut x_only = [0u8; 32];
                x_only.copy_from_slice(&pk_bytes[1..33]);

                if tree.is_none() {
                    // Key-path only: tweak the internal key with empty script tree
                    // Use BIP341 key tweaking
                    let tweaked = tweak_pubkey(&x_only, None)?;
                    let script = ScriptBuilder::new()
                        .push_opcode(Opcodes::OP_1)
                        .push_slice(&tweaked)
                        .build();
                    Ok(script)
                } else {
                    // Script-path: compute merkle root from tree, tweak with it
                    let merkle_root = compute_tr_tree_hash(tree.as_ref().unwrap(), index)?;
                    let tweaked = tweak_pubkey(&x_only, Some(&merkle_root))?;
                    let script = ScriptBuilder::new()
                        .push_opcode(Opcodes::OP_1)
                        .push_slice(&tweaked)
                        .build();
                    Ok(script)
                }
            }
        }
    }

    /// Derive the address for this descriptor at the given index.
    pub fn address(&self, index: u32, mainnet: bool) -> Result<Address, DescriptorError> {
        match self {
            Descriptor::Pkh(key) => {
                let pk = key.derive_public_key(index)?;
                Ok(Address::p2pkh(&pk, mainnet))
            }
            Descriptor::Wpkh(key) => {
                let pk = key.derive_public_key(index)?;
                Address::p2wpkh(&pk, mainnet)
                    .map_err(|e| DescriptorError::Address(e.to_string()))
            }
            Descriptor::ShWpkh(key) => {
                let pk = key.derive_public_key(index)?;
                Address::p2sh_p2wpkh(&pk, mainnet)
                    .map_err(|e| DescriptorError::Address(e.to_string()))
            }
            Descriptor::Tr(key, _) => {
                let pk = key.derive_public_key(index)?;
                let pk_bytes = pk.serialize();
                let mut x_only = [0u8; 32];
                x_only.copy_from_slice(&pk_bytes[1..33]);

                let tweaked = if let Some(tree) = self.tr_tree() {
                    let merkle_root = compute_tr_tree_hash(tree, index)?;
                    tweak_pubkey(&x_only, Some(&merkle_root))?
                } else {
                    tweak_pubkey(&x_only, None)?
                };

                Ok(Address::p2tr(&tweaked, mainnet))
            }
            _ => {
                // For sh/wsh/pk, compute from scriptPubKey
                // This is a simplified approach — in practice you'd match
                // the script type to derive the correct address format
                Err(DescriptorError::Unsupported(
                    "address derivation for this descriptor type".to_string(),
                ))
            }
        }
    }

    /// Get the witness script for P2WSH/P2SH-P2WSH descriptors.
    pub fn witness_script(&self, index: u32) -> Result<Option<Script>, DescriptorError> {
        match self {
            Descriptor::Wsh(inner) | Descriptor::ShWsh(inner) => {
                let ws = compile_wsh_inner(inner, index)?;
                Ok(Some(ws))
            }
            _ => Ok(None),
        }
    }

    /// Get the redeem script for P2SH variants.
    pub fn redeem_script(&self, index: u32) -> Result<Option<Script>, DescriptorError> {
        match self {
            Descriptor::ShWpkh(key) => {
                let pk = key.derive_public_key(index)?;
                let pkh = pk.pubkey_hash();
                let redeem = ScriptBuilder::new()
                    .push_opcode(Opcodes::OP_0)
                    .push_slice(&pkh)
                    .build();
                Ok(Some(redeem))
            }
            Descriptor::Sh(inner) => {
                let redeem = compile_sh_inner(inner, index)?;
                Ok(Some(redeem))
            }
            Descriptor::ShWsh(inner) => {
                let ws = compile_wsh_inner(inner, index)?;
                let ws_hash = sha256_raw(ws.as_bytes());
                let redeem = ScriptBuilder::new()
                    .push_opcode(Opcodes::OP_0)
                    .push_slice(&ws_hash)
                    .build();
                Ok(Some(redeem))
            }
            _ => Ok(None),
        }
    }

    /// Helper to get the TrTree reference.
    fn tr_tree(&self) -> Option<&TrTree> {
        match self {
            Descriptor::Tr(_, tree) => tree.as_ref(),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Compile the inner content of a sh() descriptor to its redeem script.
fn compile_sh_inner(inner: &ShInner, index: u32) -> Result<Script, DescriptorError> {
    match inner {
        ShInner::Wpkh(key) => {
            let pk = key.derive_public_key(index)?;
            let pkh = pk.pubkey_hash();
            Ok(ScriptBuilder::new()
                .push_opcode(Opcodes::OP_0)
                .push_slice(&pkh)
                .build())
        }
        ShInner::Wsh(wsh_inner) => {
            let ws = compile_wsh_inner(wsh_inner, index)?;
            let ws_hash = sha256_raw(ws.as_bytes());
            Ok(ScriptBuilder::new()
                .push_opcode(Opcodes::OP_0)
                .push_slice(&ws_hash)
                .build())
        }
        ShInner::Multi(k, keys) => compile_multi(*k, keys, index, false),
        ShInner::SortedMulti(k, keys) => compile_multi(*k, keys, index, true),
    }
}

/// Compile the inner content of a wsh() descriptor to its witness script.
fn compile_wsh_inner(inner: &WshInner, index: u32) -> Result<Script, DescriptorError> {
    match inner {
        WshInner::Multi(k, keys) => compile_multi(*k, keys, index, false),
        WshInner::SortedMulti(k, keys) => compile_multi(*k, keys, index, true),
        WshInner::Miniscript(ms) => Ok(ms.encode()),
    }
}

/// Compile a multi/sortedmulti expression to a raw multisig script.
fn compile_multi(
    k: usize,
    keys: &[DescriptorKey],
    index: u32,
    sorted: bool,
) -> Result<Script, DescriptorError> {
    let mut derived_keys: Vec<Vec<u8>> = Vec::with_capacity(keys.len());
    for key in keys {
        let pk = key.derive_public_key(index)?;
        derived_keys.push(pk.serialize().to_vec());
    }

    if sorted {
        derived_keys.sort();
    }

    let mut builder = ScriptBuilder::new().push_int(k as i64);
    for key_bytes in &derived_keys {
        builder = builder.push_slice(key_bytes);
    }
    builder = builder
        .push_int(derived_keys.len() as i64)
        .push_opcode(Opcodes::OP_CHECKMULTISIG);

    Ok(builder.build())
}

/// Tweak a 32-byte x-only public key with an optional merkle root.
///
/// Implements BIP341 key tweaking:
///   t = tagged_hash("TapTweak", internal_key || merkle_root)
///   output_key = internal_key + t*G
fn tweak_pubkey(
    x_only_key: &[u8; 32],
    merkle_root: Option<&[u8; 32]>,
) -> Result<[u8; 32], DescriptorError> {
    // tagged_hash("TapTweak", data) = SHA256(SHA256("TapTweak") || SHA256("TapTweak") || data)
    let tag_hash = sha256_raw(b"TapTweak");
    let mut preimage = Vec::with_capacity(64 + 32 + 32);
    preimage.extend_from_slice(&tag_hash);
    preimage.extend_from_slice(&tag_hash);
    preimage.extend_from_slice(x_only_key);
    if let Some(root) = merkle_root {
        preimage.extend_from_slice(root);
    }
    let tweak_bytes = sha256_raw(&preimage);

    // Perform the EC point addition: output = internal + tweak*G
    let secp = secp256k1::Secp256k1::new();

    let tweak = secp256k1::SecretKey::from_slice(&tweak_bytes)
        .map_err(|e| DescriptorError::Address(format!("invalid tweak: {}", e)))?;

    // Reconstruct the full pubkey from x-only (assume even Y)
    let mut full_key = [0u8; 33];
    full_key[0] = 0x02; // even Y
    full_key[1..].copy_from_slice(x_only_key);

    let mut pk = secp256k1::PublicKey::from_slice(&full_key)
        .map_err(|e| DescriptorError::Address(format!("invalid pubkey: {}", e)))?;

    pk = pk.combine(&secp256k1::PublicKey::from_secret_key(&secp, &tweak))
        .map_err(|e| DescriptorError::Address(format!("tweak failed: {}", e)))?;

    // Extract x-only from the tweaked key
    let serialized = pk.serialize();
    let mut output = [0u8; 32];
    output.copy_from_slice(&serialized[1..33]);

    Ok(output)
}

/// Compute the Taproot tree hash for a TrTree.
fn compute_tr_tree_hash(tree: &TrTree, index: u32) -> Result<[u8; 32], DescriptorError> {
    match tree {
        TrTree::Leaf(ms) => {
            // TapLeaf hash = tagged_hash("TapLeaf", leaf_version || compact_size(script) || script)
            let script = ms.encode();
            let script_bytes = script.as_bytes();

            let tag_hash = sha256_raw(b"TapLeaf");
            let mut preimage = Vec::new();
            preimage.extend_from_slice(&tag_hash);
            preimage.extend_from_slice(&tag_hash);
            preimage.push(0xc0); // leaf version
            // compact_size encoding of script length
            encode_compact_size(&mut preimage, script_bytes.len());
            preimage.extend_from_slice(script_bytes);

            Ok(sha256_raw(&preimage))
        }
        TrTree::Branch(left, right) => {
            let left_hash = compute_tr_tree_hash(left, index)?;
            let right_hash = compute_tr_tree_hash(right, index)?;

            // TapBranch hash = tagged_hash("TapBranch", min(left, right) || max(left, right))
            let tag_hash = sha256_raw(b"TapBranch");
            let mut preimage = Vec::with_capacity(64 + 64);
            preimage.extend_from_slice(&tag_hash);
            preimage.extend_from_slice(&tag_hash);

            // Lexicographic ordering
            if left_hash <= right_hash {
                preimage.extend_from_slice(&left_hash);
                preimage.extend_from_slice(&right_hash);
            } else {
                preimage.extend_from_slice(&right_hash);
                preimage.extend_from_slice(&left_hash);
            }

            Ok(sha256_raw(&preimage))
        }
    }
}

/// SHA-256 returning a raw 32-byte array (unwrapping our Hash256 wrapper).
fn sha256_raw(data: &[u8]) -> [u8; 32] {
    *sha256(data).as_bytes()
}

/// Encode a compact size integer.
fn encode_compact_size(buf: &mut Vec<u8>, n: usize) {
    if n < 253 {
        buf.push(n as u8);
    } else if n <= 0xffff {
        buf.push(0xfd);
        buf.extend_from_slice(&(n as u16).to_le_bytes());
    } else if n <= 0xffff_ffff {
        buf.push(0xfe);
        buf.extend_from_slice(&(n as u32).to_le_bytes());
    } else {
        buf.push(0xff);
        buf.extend_from_slice(&(n as u64).to_le_bytes());
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use crate::wallet::keys::PublicKey;
    use crate::wallet::descriptors::key_expr::{
        SingleKey, DescriptorKey, ExtendedKey, XKey, Wildcard,
    };
    use crate::wallet::hd::ExtendedPrivateKey;
    use crate::wallet::descriptors::descriptor::{Descriptor, WshInner};

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
    fn test_pkh_script_pubkey() {
        let desc = Descriptor::Pkh(single_dk(1));
        let script = desc.script_pubkey(0).unwrap();
        let bytes = script.as_bytes();
        // P2PKH: OP_DUP OP_HASH160 <20> <hash> OP_EQUALVERIFY OP_CHECKSIG
        assert_eq!(bytes[0], 0x76); // OP_DUP
        assert_eq!(bytes[1], 0xa9); // OP_HASH160
        assert_eq!(bytes[2], 20);   // push 20
        assert_eq!(bytes[23], 0x88); // OP_EQUALVERIFY
        assert_eq!(bytes[24], 0xac); // OP_CHECKSIG
        assert_eq!(bytes.len(), 25);
    }

    #[test]
    fn test_wpkh_script_pubkey() {
        let desc = Descriptor::Wpkh(single_dk(2));
        let script = desc.script_pubkey(0).unwrap();
        let bytes = script.as_bytes();
        // P2WPKH: OP_0 <20> <hash>
        assert_eq!(bytes[0], 0x00); // OP_0
        assert_eq!(bytes[1], 20);   // push 20
        assert_eq!(bytes.len(), 22);
    }

    #[test]
    fn test_sh_wpkh_script_pubkey() {
        let desc = Descriptor::ShWpkh(single_dk(3));
        let script = desc.script_pubkey(0).unwrap();
        let bytes = script.as_bytes();
        // P2SH: OP_HASH160 <20> <hash> OP_EQUAL
        assert_eq!(bytes[0], 0xa9); // OP_HASH160
        assert_eq!(bytes[1], 20);
        assert_eq!(bytes[22], 0x87); // OP_EQUAL
        assert_eq!(bytes.len(), 23);
    }

    #[test]
    fn test_wsh_multi_script_pubkey() {
        let desc = Descriptor::Wsh(WshInner::Multi(
            2,
            vec![single_dk(10), single_dk(11), single_dk(12)],
        ));
        let script = desc.script_pubkey(0).unwrap();
        let bytes = script.as_bytes();
        // P2WSH: OP_0 <32> <sha256>
        assert_eq!(bytes[0], 0x00); // OP_0
        assert_eq!(bytes[1], 32);
        assert_eq!(bytes.len(), 34);
    }

    #[test]
    fn test_sh_wsh_multi_script_pubkey() {
        let desc = Descriptor::ShWsh(WshInner::Multi(
            1,
            vec![single_dk(20), single_dk(21)],
        ));
        let script = desc.script_pubkey(0).unwrap();
        let bytes = script.as_bytes();
        // P2SH: OP_HASH160 <20> <hash> OP_EQUAL
        assert_eq!(bytes[0], 0xa9);
        assert_eq!(bytes.len(), 23);
    }

    #[test]
    fn test_tr_key_only_script_pubkey() {
        let desc = Descriptor::Tr(single_dk(30), None);
        let script = desc.script_pubkey(0).unwrap();
        let bytes = script.as_bytes();
        // P2TR: OP_1 <32> <tweaked-key>
        assert_eq!(bytes[0], 0x51); // OP_1
        assert_eq!(bytes[1], 32);
        assert_eq!(bytes.len(), 34);
    }

    #[test]
    fn test_pkh_address() {
        let desc = Descriptor::Pkh(single_dk(1));
        let addr = desc.address(0, true).unwrap();
        let addr_str = addr.to_string();
        assert!(addr_str.starts_with('1')); // mainnet P2PKH
    }

    #[test]
    fn test_wpkh_address() {
        let desc = Descriptor::Wpkh(single_dk(2));
        let addr = desc.address(0, true).unwrap();
        let addr_str = addr.to_string();
        assert!(addr_str.starts_with("bc1q")); // mainnet P2WPKH
    }

    #[test]
    fn test_wpkh_testnet_address() {
        let desc = Descriptor::Wpkh(single_dk(2));
        let addr = desc.address(0, false).unwrap();
        let addr_str = addr.to_string();
        assert!(addr_str.starts_with("tb1q")); // testnet P2WPKH
    }

    #[test]
    fn test_sh_wpkh_address() {
        let desc = Descriptor::ShWpkh(single_dk(3));
        let addr = desc.address(0, true).unwrap();
        let addr_str = addr.to_string();
        assert!(addr_str.starts_with('3')); // mainnet P2SH
    }

    #[test]
    fn test_tr_address() {
        let desc = Descriptor::Tr(single_dk(30), None);
        let addr = desc.address(0, true).unwrap();
        let addr_str = addr.to_string();
        assert!(addr_str.starts_with("bc1p")); // mainnet P2TR
    }

    #[test]
    fn test_witness_script_wsh() {
        let desc = Descriptor::Wsh(WshInner::Multi(
            1,
            vec![single_dk(40), single_dk(41)],
        ));
        let ws = desc.witness_script(0).unwrap();
        assert!(ws.is_some());
        let ws_bytes = ws.unwrap();
        // Should be a valid multisig: <1> <key1> <key2> <2> OP_CHECKMULTISIG
        let bytes = ws_bytes.as_bytes();
        assert_eq!(*bytes.last().unwrap(), 0xae); // OP_CHECKMULTISIG
    }

    #[test]
    fn test_witness_script_none_for_non_wsh() {
        let desc = Descriptor::Wpkh(single_dk(42));
        let ws = desc.witness_script(0).unwrap();
        assert!(ws.is_none());
    }

    #[test]
    fn test_redeem_script_sh_wpkh() {
        let desc = Descriptor::ShWpkh(single_dk(50));
        let rs = desc.redeem_script(0).unwrap();
        assert!(rs.is_some());
        let rs_bytes = rs.unwrap();
        let bytes = rs_bytes.as_bytes();
        // OP_0 <20> <hash>
        assert_eq!(bytes[0], 0x00);
        assert_eq!(bytes[1], 20);
        assert_eq!(bytes.len(), 22);
    }

    #[test]
    fn test_sorted_multi_keys_are_sorted() {
        // Two keys — sortedmulti should produce the same script regardless of key order
        let k1 = single_dk(60);
        let k2 = single_dk(61);

        let desc1 = Descriptor::Wsh(WshInner::SortedMulti(1, vec![k1.clone(), k2.clone()]));
        let desc2 = Descriptor::Wsh(WshInner::SortedMulti(1, vec![k2, k1]));

        let script1 = desc1.script_pubkey(0).unwrap();
        let script2 = desc2.script_pubkey(0).unwrap();
        assert_eq!(script1.as_bytes(), script2.as_bytes());
    }

    #[test]
    fn test_wildcard_derivation_different_indices() {
        let seed = [0x55u8; 64];
        let xprv = ExtendedPrivateKey::from_seed(&seed, true).unwrap();
        let xpub = xprv.to_extended_public_key();

        let ek = DescriptorKey::Extended(ExtendedKey {
            xkey: XKey::Pub(xpub),
            origin: None,
            derivation_path: vec![0],
            wildcard: Wildcard::Unhardened,
        });

        let desc = Descriptor::Wpkh(ek);

        let script0 = desc.script_pubkey(0).unwrap();
        let script1 = desc.script_pubkey(1).unwrap();
        assert_ne!(script0.as_bytes(), script1.as_bytes());
    }
}
