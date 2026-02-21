//! Benchmarks for Bitcoin script execution and cryptographic operations
//!
//! Uses Rust's built-in benchmark framework (requires nightly) or can be
//! run as a simple timing harness on stable Rust via `cargo test --release`.
//!
//! To run as timing tests:
//!   cargo test --release -p abtc-domain bench_ -- --nocapture

use abtc_domain::crypto::hashing;
use abtc_domain::crypto::taproot::{tagged_hash, tapleaf_hash, tapbranch_hash, TAPSCRIPT_LEAF_VERSION};
use abtc_domain::script::{Script, ScriptFlags, NoSigChecker, verify_script};
use abtc_domain::script::Opcodes;
use std::time::Instant;

/// Simple timing helper for stable Rust benchmarks
fn bench(name: &str, iterations: u32, f: impl Fn()) {
    // Warm up
    for _ in 0..100 {
        f();
    }

    let start = Instant::now();
    for _ in 0..iterations {
        f();
    }
    let elapsed = start.elapsed();
    let per_op = elapsed / iterations;

    println!(
        "  {:<45} {:>8} iterations  {:>12?} total  {:>10?}/op",
        name, iterations, elapsed, per_op
    );
}

#[test]
fn bench_hashing_operations() {
    println!("\n=== Hashing Benchmarks ===");

    let data = vec![0u8; 32]; // Typical 32-byte input

    bench("SHA-256 (32 bytes)", 100_000, || {
        let _ = hashing::sha256(&data);
    });

    bench("SHA-1 (32 bytes)", 100_000, || {
        let _ = hashing::sha1(&data);
    });

    bench("Double SHA-256 / hash256 (32 bytes)", 100_000, || {
        let _ = hashing::hash256(&data);
    });

    bench("HASH160 / RIPEMD160(SHA256) (32 bytes)", 100_000, || {
        let _ = hashing::hash160(&data);
    });

    let large_data = vec![0u8; 1024];
    bench("SHA-256 (1 KB)", 50_000, || {
        let _ = hashing::sha256(&large_data);
    });

    bench("Double SHA-256 (1 KB)", 50_000, || {
        let _ = hashing::hash256(&large_data);
    });
}

#[test]
fn bench_taproot_tagged_hashes() {
    println!("\n=== Taproot Tagged Hash Benchmarks ===");

    let data = vec![0u8; 64];

    bench("tagged_hash(\"TapLeaf\", 64B)", 100_000, || {
        let _ = tagged_hash("TapLeaf", &data);
    });

    bench("tagged_hash(\"TapBranch\", 64B)", 100_000, || {
        let _ = tagged_hash("TapBranch", &data);
    });

    bench("tagged_hash(\"TapTweak\", 64B)", 100_000, || {
        let _ = tagged_hash("TapTweak", &data);
    });

    let script = vec![0x51u8; 100]; // 100-byte script
    bench("tapleaf_hash (100B script)", 100_000, || {
        let _ = tapleaf_hash(TAPSCRIPT_LEAF_VERSION, &script);
    });

    let a = [0x01u8; 32];
    let b = [0x02u8; 32];
    bench("tapbranch_hash", 100_000, || {
        let _ = tapbranch_hash(&a, &b);
    });
}

#[test]
fn bench_script_execution() {
    println!("\n=== Script Execution Benchmarks ===");

    let flags = ScriptFlags::new(ScriptFlags::NONE);

    // Simple OP_1 (trivial script)
    let sig = Script::new();
    let pubkey = Script::from_bytes(vec![Opcodes::OP_1 as u8]);
    bench("OP_1 (trivial true)", 100_000, || {
        let _ = verify_script(&sig, &pubkey, flags, &NoSigChecker);
    });

    // Arithmetic: 2 + 3 = 5
    let sig = Script::from_bytes(vec![Opcodes::OP_2 as u8, Opcodes::OP_3 as u8]);
    let pubkey = Script::from_bytes(vec![
        Opcodes::OP_ADD as u8,
        Opcodes::OP_5 as u8,
        Opcodes::OP_EQUAL as u8,
    ]);
    bench("OP_2 OP_3 | OP_ADD OP_5 OP_EQUAL", 100_000, || {
        let _ = verify_script(&sig, &pubkey, flags, &NoSigChecker);
    });

    // Hash chain: SHA256 10 times then check non-empty via 0NOTEQUAL
    let hash_chain_bytes = vec![Opcodes::OP_1 as u8]; // scriptSig pushes 1
    let mut chain_pubkey = Vec::new();
    for _ in 0..10 {
        chain_pubkey.push(Opcodes::OP_SHA256 as u8);
    }
    // The result is a 32-byte hash; OP_0NOTEQUAL will treat it as a number.
    // A non-zero value leaves true on stack.
    chain_pubkey.push(Opcodes::OP_0NOTEQUAL as u8);

    let sig = Script::from_bytes(hash_chain_bytes);
    let pubkey = Script::from_bytes(chain_pubkey);
    bench("10x SHA256 chain", 50_000, || {
        let _ = verify_script(&sig, &pubkey, flags, &NoSigChecker);
    });

    // Stack-heavy: push 100 items then drop them
    let mut heavy_bytes = Vec::new();
    for _ in 0..100 {
        heavy_bytes.push(Opcodes::OP_1 as u8);
    }
    for _ in 0..99 {
        heavy_bytes.push(Opcodes::OP_DROP as u8);
    }
    let sig = Script::new();
    let pubkey = Script::from_bytes(heavy_bytes);
    bench("Push 100 + Drop 99 (stack heavy)", 50_000, || {
        let _ = verify_script(&sig, &pubkey, flags, &NoSigChecker);
    });

    // Conditional branching
    let sig = Script::from_bytes(vec![Opcodes::OP_1 as u8]);
    let pubkey = Script::from_bytes(vec![
        Opcodes::OP_IF as u8,
        Opcodes::OP_1 as u8,
        Opcodes::OP_IF as u8,
        Opcodes::OP_1 as u8,
        Opcodes::OP_IF as u8,
        Opcodes::OP_1 as u8,
        Opcodes::OP_ELSE as u8,
        Opcodes::OP_0 as u8,
        Opcodes::OP_ENDIF as u8,
        Opcodes::OP_ENDIF as u8,
        Opcodes::OP_ENDIF as u8,
    ]);
    bench("3-deep nested IF/ELSE/ENDIF", 100_000, || {
        let _ = verify_script(&sig, &pubkey, flags, &NoSigChecker);
    });

    // DUP + arithmetic chain
    let sig = Script::from_bytes(vec![Opcodes::OP_5 as u8]);
    let pubkey = Script::from_bytes(vec![
        Opcodes::OP_DUP as u8,
        Opcodes::OP_ADD as u8,    // 10
        Opcodes::OP_DUP as u8,
        Opcodes::OP_ADD as u8,    // 20
        Opcodes::OP_DUP as u8,
        Opcodes::OP_ADD as u8,    // 40
        Opcodes::OP_DUP as u8,
        Opcodes::OP_ADD as u8,    // 80
        0x01, 0x50,               // push 80
        Opcodes::OP_EQUAL as u8,
    ]);
    bench("DUP+ADD chain (5->80)", 100_000, || {
        let _ = verify_script(&sig, &pubkey, flags, &NoSigChecker);
    });
}

#[test]
fn bench_secp256k1_operations() {
    println!("\n=== secp256k1 Benchmarks ===");

    use secp256k1::{Secp256k1, SecretKey, PublicKey, Message};

    let secp = Secp256k1::new();
    let secret_key = SecretKey::from_slice(&[0x01; 32]).unwrap();
    let public_key = PublicKey::from_secret_key(&secp, &secret_key);
    let msg = Message::from_digest_slice(&[0xAB; 32]).unwrap();

    // ECDSA sign
    bench("ECDSA sign", 10_000, || {
        let _ = secp.sign_ecdsa(&msg, &secret_key);
    });

    // ECDSA verify
    let ecdsa_sig = secp.sign_ecdsa(&msg, &secret_key);
    bench("ECDSA verify", 10_000, || {
        let _ = secp.verify_ecdsa(&msg, &ecdsa_sig, &public_key);
    });

    // Schnorr sign (using keypair)
    let keypair = secp256k1::Keypair::from_secret_key(&secp, &secret_key);
    bench("Schnorr sign", 10_000, || {
        let _ = secp.sign_schnorr_no_aux_rand(&msg, &keypair);
    });

    // Schnorr verify
    let schnorr_sig = secp.sign_schnorr_no_aux_rand(&msg, &keypair);
    let (xonly, _) = public_key.x_only_public_key();
    bench("Schnorr verify", 10_000, || {
        let _ = secp.verify_schnorr(&schnorr_sig, &msg, &xonly);
    });

    // Key generation
    bench("Generate keypair", 10_000, || {
        let sk = SecretKey::from_slice(&[0x02; 32]).unwrap();
        let _ = PublicKey::from_secret_key(&secp, &sk);
    });
}
