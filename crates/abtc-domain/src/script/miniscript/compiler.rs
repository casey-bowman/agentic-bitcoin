// Miniscript compiler — Miniscript AST → Bitcoin Script
//
// Each Terminal variant maps to a specific sequence of opcodes as defined
// in the miniscript specification.  Compilation is a straightforward
// recursive traversal.
//
// Reference: https://bitcoin.sipa.be/miniscript/

use super::fragment::{Miniscript, Terminal};
use crate::script::opcodes::Opcodes;
use crate::script::script::{Script, ScriptBuilder};

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

impl Miniscript {
    /// Compile this miniscript expression to a Bitcoin Script.
    pub fn encode(&self) -> Script {
        let mut builder = ScriptBuilder::new();
        builder = encode_into(builder, &self.node);
        builder.build()
    }
}

// ---------------------------------------------------------------------------
// Recursive encoder
// ---------------------------------------------------------------------------

fn encode_into(mut b: ScriptBuilder, node: &Terminal) -> ScriptBuilder {
    match node {
        // ── Atoms ──────────────────────────────────────────────────────

        // 1  →  OP_1
        Terminal::True => {
            b = b.push_opcode(Opcodes::OP_1);
        }

        // 0  →  OP_0
        Terminal::False => {
            b = b.push_opcode(Opcodes::OP_0);
        }

        // pk_k(key)  →  <key> OP_CHECKSIG
        Terminal::PkK(key) => {
            b = b.push_slice(&key.serialize());
            // Note: OP_CHECKSIG is NOT added here — pk_k is type K, not B.
            // The `c:` wrapper adds OP_CHECKSIG to make it type B.
        }

        // pk_h(hash)  →  OP_DUP OP_HASH160 <hash> OP_EQUALVERIFY OP_CHECKSIG
        //
        // Like pk_k, this is type K — it leaves the key on the stack.
        // Actually per spec pk_h is:
        //   OP_DUP OP_HASH160 <hash> OP_EQUALVERIFY
        // and the `c:` wrapper adds OP_CHECKSIG.
        Terminal::PkH(hash) => {
            b = b
                .push_opcode(Opcodes::OP_DUP)
                .push_opcode(Opcodes::OP_HASH160)
                .push_slice(hash)
                .push_opcode(Opcodes::OP_EQUALVERIFY);
        }

        // older(n)  →  <n> OP_CHECKSEQUENCEVERIFY
        Terminal::Older(n) => {
            b = b
                .push_int(*n as i64)
                .push_opcode(Opcodes::OP_CHECKSEQUENCEVERIFY);
        }

        // after(n)  →  <n> OP_CHECKLOCKTIMEVERIFY
        Terminal::After(n) => {
            b = b
                .push_int(*n as i64)
                .push_opcode(Opcodes::OP_CHECKLOCKTIMEVERIFY);
        }

        // sha256(h)  →  OP_SIZE <32> OP_EQUALVERIFY OP_SHA256 <hash> OP_EQUAL
        Terminal::Sha256(hash) => {
            b = b
                .push_opcode(Opcodes::OP_SIZE)
                .push_int(32)
                .push_opcode(Opcodes::OP_EQUALVERIFY)
                .push_opcode(Opcodes::OP_SHA256)
                .push_slice(hash)
                .push_opcode(Opcodes::OP_EQUAL);
        }

        // hash256(h)  →  OP_SIZE <32> OP_EQUALVERIFY OP_HASH256 <hash> OP_EQUAL
        Terminal::Hash256(hash) => {
            b = b
                .push_opcode(Opcodes::OP_SIZE)
                .push_int(32)
                .push_opcode(Opcodes::OP_EQUALVERIFY)
                .push_opcode(Opcodes::OP_HASH256)
                .push_slice(hash)
                .push_opcode(Opcodes::OP_EQUAL);
        }

        // ripemd160(h)  →  OP_SIZE <32> OP_EQUALVERIFY OP_RIPEMD160 <hash> OP_EQUAL
        Terminal::Ripemd160(hash) => {
            b = b
                .push_opcode(Opcodes::OP_SIZE)
                .push_int(32)
                .push_opcode(Opcodes::OP_EQUALVERIFY)
                .push_opcode(Opcodes::OP_RIPEMD160)
                .push_slice(hash)
                .push_opcode(Opcodes::OP_EQUAL);
        }

        // hash160(h)  →  OP_SIZE <32> OP_EQUALVERIFY OP_HASH160 <hash> OP_EQUAL
        Terminal::Hash160(hash) => {
            b = b
                .push_opcode(Opcodes::OP_SIZE)
                .push_int(32)
                .push_opcode(Opcodes::OP_EQUALVERIFY)
                .push_opcode(Opcodes::OP_HASH160)
                .push_slice(hash)
                .push_opcode(Opcodes::OP_EQUAL);
        }

        // ── Combinators ───────────────────────────────────────────────

        // and_v(X, Y)  →  [X] [Y]
        Terminal::AndV(x, y) => {
            b = encode_into(b, &x.node);
            b = encode_into(b, &y.node);
        }

        // and_b(X, Y)  →  [X] [Y] OP_BOOLAND
        Terminal::AndB(x, y) => {
            b = encode_into(b, &x.node);
            b = encode_into(b, &y.node);
            b = b.push_opcode(Opcodes::OP_BOOLAND);
        }

        // or_b(X, Y)  →  [X] [Y] OP_BOOLOR
        Terminal::OrB(x, y) => {
            b = encode_into(b, &x.node);
            b = encode_into(b, &y.node);
            b = b.push_opcode(Opcodes::OP_BOOLOR);
        }

        // or_c(X, Y)  →  [X] OP_NOTIF [Y] OP_ENDIF
        Terminal::OrC(x, y) => {
            b = encode_into(b, &x.node);
            b = b.push_opcode(Opcodes::OP_NOTIF);
            b = encode_into(b, &y.node);
            b = b.push_opcode(Opcodes::OP_ENDIF);
        }

        // or_d(X, Y)  →  [X] OP_IFDUP OP_NOTIF [Y] OP_ENDIF
        Terminal::OrD(x, y) => {
            b = encode_into(b, &x.node);
            b = b
                .push_opcode(Opcodes::OP_IFDUP)
                .push_opcode(Opcodes::OP_NOTIF);
            b = encode_into(b, &y.node);
            b = b.push_opcode(Opcodes::OP_ENDIF);
        }

        // or_i(X, Y)  →  OP_IF [X] OP_ELSE [Y] OP_ENDIF
        Terminal::OrI(x, y) => {
            b = b.push_opcode(Opcodes::OP_IF);
            b = encode_into(b, &x.node);
            b = b.push_opcode(Opcodes::OP_ELSE);
            b = encode_into(b, &y.node);
            b = b.push_opcode(Opcodes::OP_ENDIF);
        }

        // thresh(k, X1, X2, ..., Xn)  →  [X1] [X2] OP_ADD [X3] OP_ADD ... <k> OP_EQUAL
        Terminal::Thresh(k, subs) => {
            for (i, sub) in subs.iter().enumerate() {
                b = encode_into(b, &sub.node);
                if i > 0 {
                    b = b.push_opcode(Opcodes::OP_ADD);
                }
            }
            b = b.push_int(*k as i64).push_opcode(Opcodes::OP_EQUAL);
        }

        // multi(k, key1, ..., keyn)  →  <k> <key1> ... <keyn> <n> OP_CHECKMULTISIG
        Terminal::Multi(k, keys) => {
            b = b.push_int(*k as i64);
            for key in keys {
                b = b.push_slice(&key.serialize());
            }
            b = b
                .push_int(keys.len() as i64)
                .push_opcode(Opcodes::OP_CHECKMULTISIG);
        }

        // multi_a(k, key1, ..., keyn)  →
        //   <key1> OP_CHECKSIG <key2> OP_CHECKSIGADD ... <keyn> OP_CHECKSIGADD <k> OP_NUMEQUAL
        Terminal::MultiA(k, keys) => {
            for (i, key) in keys.iter().enumerate() {
                b = b.push_slice(&key.serialize());
                if i == 0 {
                    b = b.push_opcode(Opcodes::OP_CHECKSIG);
                } else {
                    b = b.push_opcode(Opcodes::OP_CHECKSIGADD);
                }
            }
            b = b.push_int(*k as i64).push_opcode(Opcodes::OP_NUMEQUAL);
        }

        // ── Wrappers ─────────────────────────────────────────────────

        // a:X  →  OP_TOALTSTACK [X] OP_FROMALTSTACK
        Terminal::Alt(x) => {
            b = b.push_opcode(Opcodes::OP_TOALTSTACK);
            b = encode_into(b, &x.node);
            b = b.push_opcode(Opcodes::OP_FROMALTSTACK);
        }

        // s:X  →  OP_SWAP [X]
        Terminal::Swap(x) => {
            b = b.push_opcode(Opcodes::OP_SWAP);
            b = encode_into(b, &x.node);
        }

        // c:X  →  [X] OP_CHECKSIG
        Terminal::Check(x) => {
            b = encode_into(b, &x.node);
            b = b.push_opcode(Opcodes::OP_CHECKSIG);
        }

        // d:X  →  OP_DUP OP_IF [X] OP_ENDIF
        Terminal::DupIf(x) => {
            b = b.push_opcode(Opcodes::OP_DUP).push_opcode(Opcodes::OP_IF);
            b = encode_into(b, &x.node);
            b = b.push_opcode(Opcodes::OP_ENDIF);
        }

        // v:X  →  [X] OP_VERIFY
        //
        // Optimization: if X ends with OP_EQUAL, OP_CHECKSIG, or
        // OP_CHECKMULTISIG, we merge them into the VERIFY variant
        // (e.g. OP_CHECKSIGVERIFY) to save a byte.
        //
        // We determine this at the AST level by inspecting the child's
        // terminal type rather than manipulating raw bytes.
        Terminal::Verify(x) => {
            b = encode_verify_child(b, x);
        }

        // j:X  →  OP_SIZE OP_0NOTEQUAL OP_IF [X] OP_ENDIF
        Terminal::NonZero(x) => {
            b = b
                .push_opcode(Opcodes::OP_SIZE)
                .push_opcode(Opcodes::OP_0NOTEQUAL)
                .push_opcode(Opcodes::OP_IF);
            b = encode_into(b, &x.node);
            b = b.push_opcode(Opcodes::OP_ENDIF);
        }

        // n:X  →  [X] OP_0NOTEQUAL
        Terminal::ZeroNotEqual(x) => {
            b = encode_into(b, &x.node);
            b = b.push_opcode(Opcodes::OP_0NOTEQUAL);
        }
    }

    b
}

/// Encode a child of the `v:` (verify) wrapper with the VERIFY-merge
/// optimization.  If the child's last opcode is one that has a *VERIFY
/// variant (OP_CHECKSIG → OP_CHECKSIGVERIFY, OP_EQUAL → OP_EQUALVERIFY,
/// OP_CHECKMULTISIG → OP_CHECKMULTISIGVERIFY), we emit the merged form
/// to save one byte.  Otherwise we emit the child followed by OP_VERIFY.
fn encode_verify_child(mut b: ScriptBuilder, child: &Miniscript) -> ScriptBuilder {
    match &child.node {
        // c:X ends with OP_CHECKSIG → replace with OP_CHECKSIGVERIFY
        Terminal::Check(inner) => {
            b = encode_into(b, &inner.node);
            b = b.push_opcode(Opcodes::OP_CHECKSIGVERIFY);
        }

        // Hash atoms end with OP_EQUAL → replace with OP_EQUALVERIFY
        Terminal::Sha256(hash) => {
            b = b
                .push_opcode(Opcodes::OP_SIZE)
                .push_int(32)
                .push_opcode(Opcodes::OP_EQUALVERIFY)
                .push_opcode(Opcodes::OP_SHA256)
                .push_slice(hash)
                .push_opcode(Opcodes::OP_EQUALVERIFY);
        }
        Terminal::Hash256(hash) => {
            b = b
                .push_opcode(Opcodes::OP_SIZE)
                .push_int(32)
                .push_opcode(Opcodes::OP_EQUALVERIFY)
                .push_opcode(Opcodes::OP_HASH256)
                .push_slice(hash)
                .push_opcode(Opcodes::OP_EQUALVERIFY);
        }
        Terminal::Ripemd160(hash) => {
            b = b
                .push_opcode(Opcodes::OP_SIZE)
                .push_int(32)
                .push_opcode(Opcodes::OP_EQUALVERIFY)
                .push_opcode(Opcodes::OP_RIPEMD160)
                .push_slice(hash)
                .push_opcode(Opcodes::OP_EQUALVERIFY);
        }
        Terminal::Hash160(hash) => {
            b = b
                .push_opcode(Opcodes::OP_SIZE)
                .push_int(32)
                .push_opcode(Opcodes::OP_EQUALVERIFY)
                .push_opcode(Opcodes::OP_HASH160)
                .push_slice(hash)
                .push_opcode(Opcodes::OP_EQUALVERIFY);
        }

        // multi(k, keys) ends with OP_CHECKMULTISIG → OP_CHECKMULTISIGVERIFY
        Terminal::Multi(k, keys) => {
            b = b.push_int(*k as i64);
            for key in keys {
                b = b.push_slice(&key.serialize());
            }
            b = b
                .push_int(keys.len() as i64)
                .push_opcode(Opcodes::OP_CHECKMULTISIGVERIFY);
        }

        // thresh(k, subs) ends with OP_EQUAL → OP_EQUALVERIFY
        Terminal::Thresh(k, subs) => {
            for (i, sub) in subs.iter().enumerate() {
                b = encode_into(b, &sub.node);
                if i > 0 {
                    b = b.push_opcode(Opcodes::OP_ADD);
                }
            }
            b = b.push_int(*k as i64).push_opcode(Opcodes::OP_EQUALVERIFY);
        }

        // Everything else: compile normally, then append OP_VERIFY
        _ => {
            b = encode_into(b, &child.node);
            b = b.push_opcode(Opcodes::OP_VERIFY);
        }
    }
    b
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
        secret[0] = seed.wrapping_add(1).max(1);
        let secp = secp256k1::Secp256k1::new();
        let sk = secp256k1::SecretKey::from_slice(&secret).unwrap();
        let pk = secp256k1::PublicKey::from_secret_key(&secp, &sk);
        PublicKey::from_bytes(&pk.serialize()).unwrap()
    }

    #[test]
    fn test_encode_true() {
        let ms = Miniscript::ms_true();
        let script = ms.encode();
        assert_eq!(script.as_bytes(), &[0x51]); // OP_1
    }

    #[test]
    fn test_encode_false() {
        let ms = Miniscript::ms_false();
        let script = ms.encode();
        assert_eq!(script.as_bytes(), &[0x00]); // OP_0
    }

    #[test]
    fn test_encode_pk_k() {
        let key = dummy_key(1);
        let ms = Miniscript::pk_k(key.clone());
        let script = ms.encode();
        let bytes = script.as_bytes();
        // Should be: <33> <pubkey_bytes>  (no OP_CHECKSIG — that's c:)
        assert_eq!(bytes[0], 33); // push 33 bytes
        assert_eq!(&bytes[1..34], &key.serialize());
        assert_eq!(bytes.len(), 34);
    }

    #[test]
    fn test_encode_pk() {
        // pk(key) = c:pk_k(key) → <key> OP_CHECKSIG
        let key = dummy_key(2);
        let ms = Miniscript::pk(key.clone());
        let script = ms.encode();
        let bytes = script.as_bytes();
        assert_eq!(bytes[0], 33); // push 33 bytes
        assert_eq!(&bytes[1..34], &key.serialize());
        assert_eq!(bytes[34], 0xac); // OP_CHECKSIG
        assert_eq!(bytes.len(), 35);
    }

    #[test]
    fn test_encode_pk_h() {
        let hash = [0xab; 20];
        let ms = Miniscript::pk_h(hash);
        let script = ms.encode();
        let bytes = script.as_bytes();
        // OP_DUP OP_HASH160 <20> <hash> OP_EQUALVERIFY
        assert_eq!(bytes[0], 0x76); // OP_DUP
        assert_eq!(bytes[1], 0xa9); // OP_HASH160
        assert_eq!(bytes[2], 20); // push 20 bytes
        assert_eq!(&bytes[3..23], &hash);
        assert_eq!(bytes[23], 0x88); // OP_EQUALVERIFY
        assert_eq!(bytes.len(), 24);
    }

    #[test]
    fn test_encode_older() {
        let ms = Miniscript::older(144);
        let script = ms.encode();
        let bytes = script.as_bytes();
        // <144> OP_CHECKSEQUENCEVERIFY
        let last = *bytes.last().unwrap();
        assert_eq!(last, 0xb2); // OP_CHECKSEQUENCEVERIFY
    }

    #[test]
    fn test_encode_after() {
        let ms = Miniscript::after(500_000_000);
        let script = ms.encode();
        let bytes = script.as_bytes();
        let last = *bytes.last().unwrap();
        assert_eq!(last, 0xb1); // OP_CHECKLOCKTIMEVERIFY
    }

    #[test]
    fn test_encode_sha256() {
        let hash = [0x11; 32];
        let ms = Miniscript::sha256(hash);
        let script = ms.encode();
        let bytes = script.as_bytes();
        // OP_SIZE <32> OP_EQUALVERIFY OP_SHA256 <hash> OP_EQUAL
        assert_eq!(bytes[0], 0x82); // OP_SIZE
                                    // push_int(32) → OP_PUSH1 0x20  (since 32 > 16)
                                    // then OP_EQUALVERIFY (0x88)
                                    // then OP_SHA256 (0xa8)
                                    // then <32 bytes hash>
                                    // then OP_EQUAL (0x87)
        let last = *bytes.last().unwrap();
        assert_eq!(last, 0x87); // OP_EQUAL
                                // Check OP_SHA256 is somewhere in there
        assert!(bytes.contains(&0xa8));
    }

    #[test]
    fn test_encode_multi() {
        let keys = vec![dummy_key(10), dummy_key(11)];
        let ms = Miniscript::multi(1, keys.clone());
        let script = ms.encode();
        let bytes = script.as_bytes();
        // <1> <key1> <key2> <2> OP_CHECKMULTISIG
        assert_eq!(bytes[0], 0x51); // OP_1 (push_int(1) for small ints)
        let last = *bytes.last().unwrap();
        assert_eq!(last, 0xae); // OP_CHECKMULTISIG
    }

    #[test]
    fn test_encode_multi_a() {
        let keys = vec![dummy_key(20), dummy_key(21)];
        let ms = Miniscript::multi_a(1, keys.clone());
        let script = ms.encode();
        let bytes = script.as_bytes();
        // <key1> OP_CHECKSIG <key2> OP_CHECKSIGADD <1> OP_NUMEQUAL
        assert!(bytes.contains(&0xac)); // OP_CHECKSIG
        assert!(bytes.contains(&0xba)); // OP_CHECKSIGADD
        let last = *bytes.last().unwrap();
        assert_eq!(last, 0x9c); // OP_NUMEQUAL
    }

    #[test]
    fn test_encode_and_v() {
        // and_v(v:pk(k), older(10))
        let key = dummy_key(30);
        let ms = Miniscript::and_v(
            Miniscript::verify(Miniscript::pk(key)),
            Miniscript::older(10),
        );
        let script = ms.encode();
        let bytes = script.as_bytes();
        // Should contain OP_CHECKSIGVERIFY (optimized) and OP_CHECKSEQUENCEVERIFY
        assert!(bytes.contains(&0xad)); // OP_CHECKSIGVERIFY
        assert!(bytes.contains(&0xb2)); // OP_CHECKSEQUENCEVERIFY
    }

    #[test]
    fn test_encode_and_b() {
        let k1 = dummy_key(40);
        let k2 = dummy_key(41);
        let ms = Miniscript::and_b(Miniscript::pk(k1), Miniscript::swap(Miniscript::pk(k2)));
        let script = ms.encode();
        let bytes = script.as_bytes();
        let last = *bytes.last().unwrap();
        assert_eq!(last, 0x9a); // OP_BOOLAND
    }

    #[test]
    fn test_encode_or_b() {
        let k1 = dummy_key(42);
        let k2 = dummy_key(43);
        let ms = Miniscript::or_b(Miniscript::pk(k1), Miniscript::swap(Miniscript::pk(k2)));
        let script = ms.encode();
        let bytes = script.as_bytes();
        let last = *bytes.last().unwrap();
        assert_eq!(last, 0x9b); // OP_BOOLOR
    }

    #[test]
    fn test_encode_or_c() {
        let k1 = dummy_key(44);
        let ms = Miniscript::or_c(
            Miniscript::pk(k1),
            Miniscript::verify(Miniscript::ms_true()),
        );
        let script = ms.encode();
        let bytes = script.as_bytes();
        assert!(bytes.contains(&0x64)); // OP_NOTIF
        let last = *bytes.last().unwrap();
        assert_eq!(last, 0x68); // OP_ENDIF
    }

    #[test]
    fn test_encode_or_d() {
        let k1 = dummy_key(45);
        let ms = Miniscript::or_d(Miniscript::pk(k1), Miniscript::ms_true());
        let script = ms.encode();
        let bytes = script.as_bytes();
        assert!(bytes.contains(&0x73)); // OP_IFDUP
        assert!(bytes.contains(&0x64)); // OP_NOTIF
        let last = *bytes.last().unwrap();
        assert_eq!(last, 0x68); // OP_ENDIF
    }

    #[test]
    fn test_encode_or_i() {
        let k1 = dummy_key(46);
        let k2 = dummy_key(47);
        let ms = Miniscript::or_i(Miniscript::pk(k1), Miniscript::pk(k2));
        let script = ms.encode();
        let bytes = script.as_bytes();
        assert_eq!(bytes[0], 0x63); // OP_IF
        assert!(bytes.contains(&0x67)); // OP_ELSE
        let last = *bytes.last().unwrap();
        assert_eq!(last, 0x68); // OP_ENDIF
    }

    #[test]
    fn test_encode_thresh() {
        let subs = vec![
            Miniscript::pk(dummy_key(50)),
            Miniscript::swap(Miniscript::pk(dummy_key(51))),
            Miniscript::swap(Miniscript::pk(dummy_key(52))),
        ];
        let ms = Miniscript::thresh(2, subs);
        let script = ms.encode();
        let bytes = script.as_bytes();
        let len = bytes.len();
        // Ending pattern: ... OP_ADD <2> OP_EQUAL
        assert_eq!(bytes[len - 1], 0x87); // OP_EQUAL
        assert_eq!(bytes[len - 2], 0x52); // OP_2
        assert_eq!(bytes[len - 3], 0x93); // OP_ADD
    }

    #[test]
    fn test_encode_alt_wrapper() {
        let key = dummy_key(60);
        let ms = Miniscript::alt(Miniscript::pk(key));
        let script = ms.encode();
        let bytes = script.as_bytes();
        assert_eq!(bytes[0], 0x6b); // OP_TOALTSTACK
        let last = *bytes.last().unwrap();
        assert_eq!(last, 0x6c); // OP_FROMALTSTACK
    }

    #[test]
    fn test_encode_swap_wrapper() {
        let key = dummy_key(61);
        let ms = Miniscript::swap(Miniscript::pk(key));
        let script = ms.encode();
        let bytes = script.as_bytes();
        assert_eq!(bytes[0], 0x7c); // OP_SWAP
    }

    #[test]
    fn test_encode_dupif_wrapper() {
        // d: requires Vz input — v:1 is Vz (verify(ms_true()) = V with z=true)
        let ms = Miniscript::dupif(Miniscript::verify(Miniscript::ms_true()));
        let script = ms.encode();
        let bytes = script.as_bytes();
        assert_eq!(bytes[0], 0x76); // OP_DUP
        assert_eq!(bytes[1], 0x63); // OP_IF
        let last = *bytes.last().unwrap();
        assert_eq!(last, 0x68); // OP_ENDIF
    }

    #[test]
    fn test_encode_nonzero_wrapper() {
        let key = dummy_key(63);
        let ms = Miniscript::nonzero(Miniscript::pk(key));
        let script = ms.encode();
        let bytes = script.as_bytes();
        assert_eq!(bytes[0], 0x82); // OP_SIZE
        assert_eq!(bytes[1], 0x92); // OP_0NOTEQUAL
        assert_eq!(bytes[2], 0x63); // OP_IF
        let last = *bytes.last().unwrap();
        assert_eq!(last, 0x68); // OP_ENDIF
    }

    #[test]
    fn test_encode_zero_not_equal_wrapper() {
        let key = dummy_key(64);
        let ms = Miniscript::zero_not_equal(Miniscript::pk(key));
        let script = ms.encode();
        let bytes = script.as_bytes();
        let last = *bytes.last().unwrap();
        assert_eq!(last, 0x92); // OP_0NOTEQUAL
    }

    #[test]
    fn test_verify_optimization_checksig() {
        // v:pk(key)  should produce OP_CHECKSIGVERIFY, not OP_CHECKSIG OP_VERIFY
        let key = dummy_key(70);
        let ms = Miniscript::verify(Miniscript::pk(key));
        let script = ms.encode();
        let bytes = script.as_bytes();
        assert!(bytes.contains(&0xad)); // OP_CHECKSIGVERIFY
        assert!(!bytes.contains(&0xac)); // NOT plain OP_CHECKSIG
        assert!(!bytes.contains(&0x69)); // NOT separate OP_VERIFY
    }

    #[test]
    fn test_verify_optimization_equal() {
        // v:sha256(h) should end with OP_EQUALVERIFY, not OP_EQUAL OP_VERIFY
        let ms = Miniscript::verify(Miniscript::sha256([0xbb; 32]));
        let script = ms.encode();
        let bytes = script.as_bytes();
        let last = *bytes.last().unwrap();
        assert_eq!(last, 0x88); // OP_EQUALVERIFY
                                // Should NOT contain plain OP_EQUAL (0x87) at the end
        assert!(!bytes.contains(&0x69)); // no separate OP_VERIFY
    }

    #[test]
    fn test_encode_complex_expression() {
        // and_v(v:pk(k1), or_d(pk(k2), older(100)))
        let k1 = dummy_key(80);
        let k2 = dummy_key(81);
        let ms = Miniscript::and_v(
            Miniscript::verify(Miniscript::pk(k1)),
            Miniscript::or_d(Miniscript::pk(k2), Miniscript::older(100)),
        );
        let script = ms.encode();
        let bytes = script.as_bytes();
        // Should contain key material, OP_CHECKSIGVERIFY, OP_IFDUP, OP_NOTIF, CSV, OP_ENDIF
        assert!(bytes.contains(&0xad)); // OP_CHECKSIGVERIFY
        assert!(bytes.contains(&0x73)); // OP_IFDUP
        assert!(bytes.contains(&0xb2)); // OP_CHECKSEQUENCEVERIFY
    }
}
