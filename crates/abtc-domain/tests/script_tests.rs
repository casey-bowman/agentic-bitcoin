//! Bitcoin Core-style script test vector runner
//!
//! Parses a JSON array of test vectors in Bitcoin Core's `script_tests.json` format
//! and runs them against our script interpreter.
//!
//! Format: [scriptSig, scriptPubKey, flags, expected_result, comment]
//! - scriptSig/scriptPubKey are human-readable opcode strings (e.g., "OP_1 OP_ADD")
//!   with hex data push support (e.g., "0x01 0xFF" pushes 1 byte = 0xFF)
//! - flags is comma-separated: P2SH,WITNESS,DERSIG,CHECKLOCKTIMEVERIFY,...
//! - expected_result is "OK" or the expected error variant name

use abtc_domain::script::{verify_script, NoSigChecker, Script, ScriptError, ScriptFlags};

/// Parse an opcode name like "OP_1" or "OP_ADD" to its byte value.
fn opcode_from_name(name: &str) -> Option<u8> {
    match name {
        "OP_0" | "OP_FALSE" => Some(0x00),
        "OP_PUSHDATA1" => Some(0x4c),
        "OP_PUSHDATA2" => Some(0x4d),
        "OP_PUSHDATA4" => Some(0x4e),
        "OP_1NEGATE" => Some(0x4f),
        "OP_RESERVED" => Some(0x50),
        "OP_1" | "OP_TRUE" => Some(0x51),
        "OP_2" => Some(0x52),
        "OP_3" => Some(0x53),
        "OP_4" => Some(0x54),
        "OP_5" => Some(0x55),
        "OP_6" => Some(0x56),
        "OP_7" => Some(0x57),
        "OP_8" => Some(0x58),
        "OP_9" => Some(0x59),
        "OP_10" => Some(0x5a),
        "OP_11" => Some(0x5b),
        "OP_12" => Some(0x5c),
        "OP_13" => Some(0x5d),
        "OP_14" => Some(0x5e),
        "OP_15" => Some(0x5f),
        "OP_16" => Some(0x60),
        "OP_NOP" => Some(0x61),
        "OP_VER" => Some(0x62),
        "OP_IF" => Some(0x63),
        "OP_NOTIF" => Some(0x64),
        "OP_VERIF" => Some(0x65),
        "OP_VERNOTIF" => Some(0x66),
        "OP_ELSE" => Some(0x67),
        "OP_ENDIF" => Some(0x68),
        "OP_VERIFY" => Some(0x69),
        "OP_RETURN" => Some(0x6a),
        "OP_TOALTSTACK" => Some(0x6b),
        "OP_FROMALTSTACK" => Some(0x6c),
        "OP_2DROP" => Some(0x6d),
        "OP_2DUP" => Some(0x6e),
        "OP_3DUP" => Some(0x6f),
        "OP_2OVER" => Some(0x70),
        "OP_2ROT" => Some(0x71),
        "OP_2SWAP" => Some(0x72),
        "OP_IFDUP" => Some(0x73),
        "OP_DEPTH" => Some(0x74),
        "OP_DROP" => Some(0x75),
        "OP_DUP" => Some(0x76),
        "OP_NIP" => Some(0x77),
        "OP_OVER" => Some(0x78),
        "OP_PICK" => Some(0x79),
        "OP_ROLL" => Some(0x7a),
        "OP_ROT" => Some(0x7b),
        "OP_SWAP" => Some(0x7c),
        "OP_TUCK" => Some(0x7d),
        "OP_CAT" => Some(0x7e),
        "OP_SUBSTR" => Some(0x7f),
        "OP_LEFT" => Some(0x80),
        "OP_RIGHT" => Some(0x81),
        "OP_SIZE" => Some(0x82),
        "OP_INVERT" => Some(0x83),
        "OP_AND" => Some(0x84),
        "OP_OR" => Some(0x85),
        "OP_XOR" => Some(0x86),
        "OP_EQUAL" => Some(0x87),
        "OP_EQUALVERIFY" => Some(0x88),
        "OP_RESERVED1" => Some(0x89),
        "OP_RESERVED2" => Some(0x8a),
        "OP_1ADD" => Some(0x8b),
        "OP_1SUB" => Some(0x8c),
        "OP_2MUL" => Some(0x8d),
        "OP_2DIV" => Some(0x8e),
        "OP_NEGATE" => Some(0x8f),
        "OP_ABS" => Some(0x90),
        "OP_NOT" => Some(0x91),
        "OP_0NOTEQUAL" => Some(0x92),
        "OP_ADD" => Some(0x93),
        "OP_SUB" => Some(0x94),
        "OP_MUL" => Some(0x95),
        "OP_DIV" => Some(0x96),
        "OP_MOD" => Some(0x97),
        "OP_LSHIFT" => Some(0x98),
        "OP_RSHIFT" => Some(0x99),
        "OP_BOOLAND" => Some(0x9a),
        "OP_BOOLOR" => Some(0x9b),
        "OP_NUMEQUAL" => Some(0x9c),
        "OP_NUMEQUALVERIFY" => Some(0x9d),
        "OP_NUMNOTEQUAL" => Some(0x9e),
        "OP_LESSTHAN" => Some(0x9f),
        "OP_GREATERTHAN" => Some(0xa0),
        "OP_LESSTHANOREQUAL" => Some(0xa1),
        "OP_GREATERTHANOREQUAL" => Some(0xa2),
        "OP_MIN" => Some(0xa3),
        "OP_MAX" => Some(0xa4),
        "OP_WITHIN" => Some(0xa5),
        "OP_RIPEMD160" => Some(0xa6),
        "OP_SHA1" => Some(0xa7),
        "OP_SHA256" => Some(0xa8),
        "OP_HASH160" => Some(0xa9),
        "OP_HASH256" => Some(0xaa),
        "OP_CODESEPARATOR" => Some(0xab),
        "OP_CHECKSIG" => Some(0xac),
        "OP_CHECKSIGVERIFY" => Some(0xad),
        "OP_CHECKMULTISIG" => Some(0xae),
        "OP_CHECKMULTISIGVERIFY" => Some(0xaf),
        "OP_NOP1" => Some(0xb0),
        "OP_CHECKLOCKTIMEVERIFY" | "OP_CLTV" => Some(0xb1),
        "OP_CHECKSEQUENCEVERIFY" | "OP_CSV" => Some(0xb2),
        "OP_NOP4" => Some(0xb3),
        "OP_NOP5" => Some(0xb4),
        "OP_NOP6" => Some(0xb5),
        "OP_NOP7" => Some(0xb6),
        "OP_NOP8" => Some(0xb7),
        "OP_NOP9" => Some(0xb8),
        "OP_NOP10" => Some(0xb9),
        _ => None,
    }
}

/// Parse a human-readable script string into raw bytes.
///
/// Supports:
/// - Opcode names: "OP_1", "OP_ADD", etc.
/// - Hex data pushes: "0x01 0xFF" pushes 1 byte followed by its value
/// - The format "0xNN 0xHH..." means push NN bytes of hex data
fn parse_script(s: &str) -> Vec<u8> {
    let s = s.trim();
    if s.is_empty() {
        return vec![];
    }

    let mut bytes = Vec::new();
    let tokens: Vec<&str> = s.split_whitespace().collect();
    let mut i = 0;

    while i < tokens.len() {
        let token = tokens[i];

        if token.starts_with("0x") || token.starts_with("0X") {
            // Hex literal: could be a data push size or raw data
            let hex_val = &token[2..];
            if let Ok(val) = u8::from_str_radix(hex_val, 16) {
                bytes.push(val);
            } else {
                // Try as multi-byte hex
                if let Ok(decoded) = hex::decode(hex_val) {
                    bytes.extend_from_slice(&decoded);
                }
            }
        } else if let Some(opcode) = opcode_from_name(token) {
            bytes.push(opcode);
        } else if token.starts_with('\'') && token.ends_with('\'') {
            // String literal push
            let string_data = &token[1..token.len() - 1];
            let data_bytes = string_data.as_bytes();
            if data_bytes.len() < 76 {
                bytes.push(data_bytes.len() as u8);
                bytes.extend_from_slice(data_bytes);
            }
        } else {
            panic!("Unknown token in script: '{}'", token);
        }

        i += 1;
    }

    bytes
}

/// Parse flags string into ScriptFlags
fn parse_flags(flags_str: &str) -> ScriptFlags {
    if flags_str.is_empty() {
        return ScriptFlags::new(ScriptFlags::NONE);
    }

    let mut flags = 0u32;
    for flag in flags_str.split(',') {
        match flag.trim() {
            "P2SH" => flags |= ScriptFlags::VERIFY_P2SH,
            "WITNESS" => flags |= ScriptFlags::VERIFY_WITNESS,
            "DERSIG" | "STRICTENC" => flags |= ScriptFlags::VERIFY_DERSIG,
            "CHECKLOCKTIMEVERIFY" => flags |= ScriptFlags::VERIFY_CHECKLOCKTIMEVERIFY,
            "CHECKSEQUENCEVERIFY" => flags |= ScriptFlags::VERIFY_CHECKSEQUENCEVERIFY,
            "NULLDUMMY" => flags |= ScriptFlags::VERIFY_NULLDUMMY,
            "MINIMALDATA" => flags |= ScriptFlags::VERIFY_MINIMALDATA,
            "CLEANSTACK" => {} // Not a separate flag, implied by evaluation
            "NONE" | "" => {}
            f => panic!("Unknown flag: {}", f),
        }
    }

    ScriptFlags::new(flags)
}

/// Map an expected error string to a ScriptError match
fn matches_expected_error(err: &ScriptError, expected: &str) -> bool {
    match expected {
        "EVAL_FALSE" => matches!(err, ScriptError::EvalFalse),
        "VERIFY" => matches!(err, ScriptError::VerifyFailed),
        "OP_RETURN" => matches!(err, ScriptError::OpReturn),
        "STACK_UNDERFLOW" => matches!(err, ScriptError::StackUnderflow),
        "STACK_OVERFLOW" => matches!(err, ScriptError::StackOverflow),
        "SCRIPT_SIZE" => matches!(err, ScriptError::ScriptSize),
        "PUSH_SIZE" => matches!(err, ScriptError::PushSize),
        "OP_COUNT" => matches!(err, ScriptError::OpCount),
        "NUMBER_OVERFLOW" => matches!(err, ScriptError::NumberOverflow),
        "DISABLED_OPCODE" => matches!(err, ScriptError::DisabledOpcode),
        "INVALID_OPCODE" => matches!(err, ScriptError::InvalidOpcode),
        "UNBALANCED_CONDITIONAL" => matches!(err, ScriptError::UnbalancedConditional),
        "NEGATIVE_LOCKTIME" => matches!(err, ScriptError::NegativeLocktime),
        "UNSATISFIED_LOCKTIME" => matches!(err, ScriptError::UnsatisfiedLocktime),
        "BAD_OPCODE" => matches!(err, ScriptError::BadOpcode),
        "SIG_BAD_ENCODING" | "SIG_DER" => matches!(err, ScriptError::SigBadEncoding),
        "PUBKEY_BAD_ENCODING" => matches!(err, ScriptError::PubKeyBadEncoding),
        "SIG_VERIFY_FAILED" | "CHECKSIGVERIFY" => matches!(err, ScriptError::SigVerifyFailed),
        "MULTISIG_NOT_ENOUGH_SIGS" => matches!(err, ScriptError::MultisigNotEnoughSigs),
        "MULTISIG_TOO_MANY_KEYS" => matches!(err, ScriptError::MultisigTooManyKeys),
        "NULLDUMMY" => matches!(err, ScriptError::NullDummy),
        "MINIMALDATA" => matches!(err, ScriptError::MinimalData),
        "WITNESS_PROGRAM_MISMATCH" => matches!(err, ScriptError::WitnessProgramMismatch),
        "WITNESS_PROGRAM_WRONG_LENGTH" => matches!(err, ScriptError::WitnessProgramWrongLength),
        "WITNESS_UNEXPECTED" => matches!(err, ScriptError::WitnessUnexpected),
        "CLEANSTACK" => matches!(err, ScriptError::CleanStack),
        "EQUALVERIFY" => matches!(err, ScriptError::VerifyFailed | ScriptError::EvalFalse),
        "NUMEQUALVERIFY" => matches!(err, ScriptError::VerifyFailed | ScriptError::EvalFalse),
        _ => {
            eprintln!("  Unknown expected error: '{}', got {:?}", expected, err);
            false
        }
    }
}

#[test]
fn test_script_vectors() {
    let json_data = include_str!("data/script_tests.json");
    let tests: serde_json::Value =
        serde_json::from_str(json_data).expect("Failed to parse script_tests.json");

    let tests = tests.as_array().expect("Top-level should be an array");

    let mut total = 0;
    let mut passed = 0;
    let mut skipped = 0;
    let mut failed_tests = Vec::new();

    for (line_num, test) in tests.iter().enumerate() {
        let arr = match test.as_array() {
            Some(a) => a,
            None => continue,
        };

        // Skip comments (arrays with 1 or 2 elements)
        if arr.len() < 4 {
            continue;
        }

        // Skip if first element is a comment string
        if arr.len() == 5
            && arr[0].as_str() == Some("")
            && arr[1]
                .as_str()
                .map_or(false, |s| !s.starts_with("OP_") && !s.starts_with("0x"))
        {
            // This is a section header comment
            skipped += 1;
            continue;
        }

        let script_sig_str = arr[0].as_str().unwrap_or("");
        let script_pubkey_str = arr[1].as_str().unwrap_or("");
        let flags_str = arr[2].as_str().unwrap_or("");
        let expected = arr[3].as_str().unwrap_or("OK");
        let comment = if arr.len() > 4 {
            arr[4].as_str().unwrap_or("")
        } else {
            ""
        };

        // Skip section header comments
        if script_sig_str.is_empty()
            && !script_pubkey_str.is_empty()
            && !script_pubkey_str.starts_with("OP_")
            && !script_pubkey_str.starts_with("0x")
        {
            skipped += 1;
            continue;
        }

        total += 1;

        let script_sig_bytes = parse_script(script_sig_str);
        let script_pubkey_bytes = parse_script(script_pubkey_str);

        let script_sig = Script::from_bytes(script_sig_bytes);
        let script_pubkey = Script::from_bytes(script_pubkey_bytes);
        let flags = parse_flags(flags_str);

        let result = verify_script(&script_sig, &script_pubkey, flags, &NoSigChecker);

        let test_passed = if expected == "OK" {
            match &result {
                Ok(()) => true,
                Err(_) => false,
            }
        } else {
            match &result {
                Ok(()) => false,
                Err(e) => matches_expected_error(e, expected),
            }
        };

        if test_passed {
            passed += 1;
        } else {
            failed_tests.push(format!(
                "  Line {}: [sig='{}', pubkey='{}', flags='{}', expected='{}', comment='{}'] => got {:?}",
                line_num + 1, script_sig_str, script_pubkey_str, flags_str, expected, comment, result
            ));
        }
    }

    println!("\n=== Script Test Vector Results ===");
    println!("Total:   {}", total);
    println!("Passed:  {}", passed);
    println!("Failed:  {}", failed_tests.len());
    println!("Skipped: {}", skipped);

    if !failed_tests.is_empty() {
        println!("\nFailed tests:");
        for f in &failed_tests {
            println!("{}", f);
        }
    }

    assert!(
        failed_tests.is_empty(),
        "{} of {} script tests failed",
        failed_tests.len(),
        total
    );
}

/// Additional targeted tests for edge cases not easily expressed in JSON
#[cfg(test)]
mod targeted_tests {
    use abtc_domain::crypto::hashing;
    use abtc_domain::script::*;

    #[test]
    fn test_sha1_known_vector() {
        // SHA-1("") = da39a3ee5e6b4b0d3255bfef95601890afd80709
        let script_sig = Script::from_bytes(vec![0x00]); // push empty string
        let script_pubkey = Script::from_bytes(vec![
            Opcodes::OP_SHA1 as u8,
            0x14, // push 20 bytes
            0xda,
            0x39,
            0xa3,
            0xee,
            0x5e,
            0x6b,
            0x4b,
            0x0d,
            0x32,
            0x55,
            0xbf,
            0xef,
            0x95,
            0x60,
            0x18,
            0x90,
            0xaf,
            0xd8,
            0x07,
            0x09,
            Opcodes::OP_EQUAL as u8,
        ]);

        let result = verify_script(
            &script_sig,
            &script_pubkey,
            ScriptFlags::new(ScriptFlags::NONE),
            &NoSigChecker,
        );
        assert!(result.is_ok(), "SHA1 known vector failed: {:?}", result);
    }

    #[test]
    fn test_sha256_known_vector() {
        // SHA-256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
        let script_sig = Script::from_bytes(vec![0x00]); // push empty
        let hash = hashing::sha256(&[]);
        let mut pubkey_bytes = vec![Opcodes::OP_SHA256 as u8, 0x20]; // push 32 bytes
        pubkey_bytes.extend_from_slice(hash.as_bytes());
        pubkey_bytes.push(Opcodes::OP_EQUAL as u8);
        let script_pubkey = Script::from_bytes(pubkey_bytes);

        let result = verify_script(
            &script_sig,
            &script_pubkey,
            ScriptFlags::new(ScriptFlags::NONE),
            &NoSigChecker,
        );
        assert!(result.is_ok(), "SHA256 known vector failed: {:?}", result);
    }

    #[test]
    fn test_hash160_known_vector() {
        // HASH160("") = b472a266d0bd89c13706a4132ccfb16f7c3b9fcb
        let script_sig = Script::from_bytes(vec![0x00]); // push empty
        let hash = hashing::hash160(&[]);
        let mut pubkey_bytes = vec![Opcodes::OP_HASH160 as u8, 0x14]; // push 20 bytes
        pubkey_bytes.extend_from_slice(&hash);
        pubkey_bytes.push(Opcodes::OP_EQUAL as u8);
        let script_pubkey = Script::from_bytes(pubkey_bytes);

        let result = verify_script(
            &script_sig,
            &script_pubkey,
            ScriptFlags::new(ScriptFlags::NONE),
            &NoSigChecker,
        );
        assert!(result.is_ok(), "HASH160 known vector failed: {:?}", result);
    }

    #[test]
    fn test_hash256_known_vector() {
        // HASH256("") = 5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456
        let script_sig = Script::from_bytes(vec![0x00]); // push empty
        let hash = hashing::hash256(&[]);
        let mut pubkey_bytes = vec![Opcodes::OP_HASH256 as u8, 0x20]; // push 32 bytes
        pubkey_bytes.extend_from_slice(hash.as_bytes());
        pubkey_bytes.push(Opcodes::OP_EQUAL as u8);
        let script_pubkey = Script::from_bytes(pubkey_bytes);

        let result = verify_script(
            &script_sig,
            &script_pubkey,
            ScriptFlags::new(ScriptFlags::NONE),
            &NoSigChecker,
        );
        assert!(result.is_ok(), "HASH256 known vector failed: {:?}", result);
    }

    #[test]
    fn test_ripemd160_known_vector() {
        // RIPEMD160("") = 9c1185a5c5e9fc54612808977ee8f548b2258d31
        let ripemd_empty: [u8; 20] = [
            0x9c, 0x11, 0x85, 0xa5, 0xc5, 0xe9, 0xfc, 0x54, 0x61, 0x28, 0x08, 0x97, 0x7e, 0xe8,
            0xf5, 0x48, 0xb2, 0x25, 0x8d, 0x31,
        ];
        let script_sig = Script::from_bytes(vec![0x00]); // push empty
        let mut pubkey_bytes = vec![Opcodes::OP_RIPEMD160 as u8, 0x14];
        pubkey_bytes.extend_from_slice(&ripemd_empty);
        pubkey_bytes.push(Opcodes::OP_EQUAL as u8);
        let script_pubkey = Script::from_bytes(pubkey_bytes);

        let result = verify_script(
            &script_sig,
            &script_pubkey,
            ScriptFlags::new(ScriptFlags::NONE),
            &NoSigChecker,
        );
        assert!(
            result.is_ok(),
            "RIPEMD160 known vector failed: {:?}",
            result
        );
    }

    #[test]
    fn test_nested_if_else() {
        // Test deeply nested conditionals
        // OP_1 OP_IF OP_1 OP_IF OP_1 OP_IF OP_1 OP_ELSE OP_0 OP_ENDIF OP_ENDIF OP_ENDIF
        let script_sig = Script::from_bytes(vec![Opcodes::OP_1 as u8]);
        let script_pubkey = Script::from_bytes(vec![
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

        let result = verify_script(
            &script_sig,
            &script_pubkey,
            ScriptFlags::new(ScriptFlags::NONE),
            &NoSigChecker,
        );
        assert!(result.is_ok(), "Nested IF failed: {:?}", result);
    }

    #[test]
    fn test_large_stack() {
        // Push 200 items via OP_1 (doesn't count toward op limit since <= OP_16),
        // then drop 199 via OP_DROP (each counts as 1 op, 199 < 201 limit).
        let mut script_bytes = Vec::new();
        for _ in 0..200 {
            script_bytes.push(Opcodes::OP_1 as u8);
        }
        // Drop all but one
        for _ in 0..199 {
            script_bytes.push(Opcodes::OP_DROP as u8);
        }
        let script_sig = Script::new();
        let script_pubkey = Script::from_bytes(script_bytes);

        let result = verify_script(
            &script_sig,
            &script_pubkey,
            ScriptFlags::new(ScriptFlags::NONE),
            &NoSigChecker,
        );
        assert!(result.is_ok(), "Large stack test failed: {:?}", result);
    }
}
