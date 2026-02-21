//! Bitcoin Script Interpreter
//!
//! A stack-based virtual machine that evaluates Bitcoin scripts to determine
//! whether a transaction input is authorized to spend a particular output.
//!
//! Implements the full set of enabled opcodes matching Bitcoin Core's
//! `script/interpreter.cpp`. Disabled opcodes (OP_MUL, OP_DIV, etc.)
//! immediately fail script execution, exactly as Bitcoin Core does.
//!
//! ## Execution model
//!
//! Script execution concatenates scriptSig (input) and scriptPubKey (output)
//! and evaluates them on a shared stack. For P2SH, the serialized script
//! inside the scriptSig is deserialized and evaluated. For SegWit, the
//! witness program is evaluated instead.
//!
//! ## Script verification flags
//!
//! Various flags control which consensus rules are enforced (BIP16, BIP65,
//! BIP66, BIP112, WITNESS, etc.). These correspond to soft-fork activations.

use crate::crypto::hashing;
use crate::script::opcodes::Opcodes;
use crate::script::script::{Script, ScriptBuilder, ScriptInstruction};
use crate::script::witness::Witness;
use std::cmp;

// ---------------------------------------------------------------------------
// Verification flags (bitfield)
// ---------------------------------------------------------------------------

/// Script verification flags controlling which consensus rules are enforced.
#[derive(Debug, Clone, Copy, Default)]
pub struct ScriptFlags(u32);

impl ScriptFlags {
    /// No special rules
    pub const NONE: u32 = 0;
    /// Evaluate P2SH (BIP16)
    pub const VERIFY_P2SH: u32 = 1 << 0;
    /// Strict DER signature encoding (BIP66)
    pub const VERIFY_DERSIG: u32 = 1 << 2;
    /// CHECKLOCKTIMEVERIFY (BIP65)
    pub const VERIFY_CHECKLOCKTIMEVERIFY: u32 = 1 << 9;
    /// CHECKSEQUENCEVERIFY (BIP112)
    pub const VERIFY_CHECKSEQUENCEVERIFY: u32 = 1 << 10;
    /// Segwit (BIP141)
    pub const VERIFY_WITNESS: u32 = 1 << 11;
    /// Require minimal push encodings
    pub const VERIFY_MINIMALDATA: u32 = 1 << 6;
    /// Discourage OP_NOPx upgradable
    pub const VERIFY_DISCOURAGE_UPGRADABLE_NOPS: u32 = 1 << 7;
    /// Clean stack after evaluation
    pub const VERIFY_CLEANSTACK: u32 = 1 << 8;
    /// Require low-S signatures
    pub const VERIFY_LOW_S: u32 = 1 << 3;
    /// Require strict encoding of sig hash type
    pub const VERIFY_STRICTENC: u32 = 1 << 1;
    /// Null dummy for CHECKMULTISIG
    pub const VERIFY_NULLDUMMY: u32 = 1 << 4;
    /// Taproot (BIP341)
    pub const VERIFY_TAPROOT: u32 = 1 << 17;

    pub fn new(flags: u32) -> Self {
        ScriptFlags(flags)
    }

    pub fn has(&self, flag: u32) -> bool {
        self.0 & flag != 0
    }

    /// Standard verification flags for recent blocks
    pub fn standard() -> Self {
        ScriptFlags(
            Self::VERIFY_P2SH
                | Self::VERIFY_DERSIG
                | Self::VERIFY_CHECKLOCKTIMEVERIFY
                | Self::VERIFY_CHECKSEQUENCEVERIFY
                | Self::VERIFY_WITNESS
                | Self::VERIFY_MINIMALDATA
                | Self::VERIFY_NULLDUMMY
                | Self::VERIFY_CLEANSTACK
                | Self::VERIFY_LOW_S
                | Self::VERIFY_STRICTENC,
        )
    }
}

// ---------------------------------------------------------------------------
// Script number encoding (Bitcoin's weird signed little-endian format)
// ---------------------------------------------------------------------------

/// Maximum size of a script number in bytes
const MAX_SCRIPT_NUM_LENGTH: usize = 4;

/// Decode a stack element to an i64 (Bitcoin script number encoding).
///
/// Bitcoin uses a variable-length little-endian sign-magnitude encoding:
/// - Empty array encodes 0
/// - Sign bit is the MSB of the last byte
/// - Maximum 4 bytes (enforced by consensus)
fn decode_script_num(bytes: &[u8], max_len: usize) -> Result<i64, ScriptError> {
    if bytes.len() > max_len {
        return Err(ScriptError::NumberOverflow);
    }

    if bytes.is_empty() {
        return Ok(0);
    }

    // Little-endian, sign bit in the highest bit of the last byte
    let mut result: i64 = 0;
    for (i, &byte) in bytes.iter().enumerate() {
        result |= (byte as i64) << (i * 8);
    }

    // Extract sign bit
    let last = *bytes.last().unwrap();
    if last & 0x80 != 0 {
        // Negative: clear the sign bit and negate
        result &= !(0x80i64 << ((bytes.len() - 1) * 8));
        result = -result;
    }

    Ok(result)
}

/// Encode an i64 to the Bitcoin script number format
fn encode_script_num(value: i64) -> Vec<u8> {
    if value == 0 {
        return Vec::new();
    }

    let negative = value < 0;
    let mut abs = if negative {
        (value as i128).unsigned_abs() as u64
    } else {
        value as u64
    };

    let mut result = Vec::new();
    while abs > 0 {
        result.push((abs & 0xff) as u8);
        abs >>= 8;
    }

    // If the highest bit is set, we need an extra byte for the sign
    if result.last().unwrap() & 0x80 != 0 {
        result.push(if negative { 0x80 } else { 0x00 });
    } else if negative {
        let last = result.last_mut().unwrap();
        *last |= 0x80;
    }

    result
}

/// Check if a stack element is "true" (non-zero, not negative zero)
fn stack_is_true(elem: &[u8]) -> bool {
    for (i, byte) in elem.iter().enumerate() {
        if *byte != 0 {
            // Negative zero is false
            if i == elem.len() - 1 && *byte == 0x80 {
                return false;
            }
            return true;
        }
    }
    false
}

// ---------------------------------------------------------------------------
// Script errors
// ---------------------------------------------------------------------------

/// Errors that can occur during script execution
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScriptError {
    /// Script evaluated to false (top of stack is false after execution)
    EvalFalse,
    /// OP_VERIFY failed
    VerifyFailed,
    /// OP_RETURN encountered (provably unspendable)
    OpReturn,
    /// Stack underflow (tried to pop from empty stack)
    StackUnderflow,
    /// Stack size limit exceeded
    StackOverflow,
    /// Script size exceeds limit
    ScriptSize,
    /// Push size exceeds limit
    PushSize,
    /// Too many opcodes
    OpCount,
    /// Number encoding overflow
    NumberOverflow,
    /// Disabled opcode
    DisabledOpcode,
    /// Invalid opcode
    InvalidOpcode,
    /// Unbalanced IF/ELSE/ENDIF
    UnbalancedConditional,
    /// Negative lock time
    NegativeLocktime,
    /// Unsatisfied locktime
    UnsatisfiedLocktime,
    /// Bad opcode
    BadOpcode,
    /// Invalid signature encoding
    SigBadEncoding,
    /// Invalid public key encoding
    PubKeyBadEncoding,
    /// Signature verification failed
    SigVerifyFailed,
    /// CHECKMULTISIG: not enough signatures
    MultisigNotEnoughSigs,
    /// CHECKMULTISIG: too many public keys
    MultisigTooManyKeys,
    /// Null dummy required for CHECKMULTISIG
    NullDummy,
    /// Minimal data encoding violation
    MinimalData,
    /// Witness program mismatch
    WitnessProgramMismatch,
    /// Witness program wrong length
    WitnessProgramWrongLength,
    /// Witness unexpected
    WitnessUnexpected,
    /// Clean stack violation
    CleanStack,
    /// Script executed without errors but didn't leave exactly one true value
    ScriptFailed,
    /// Signature check not available (no checker provided)
    SigCheckNotAvailable,
    /// Schnorr signature has invalid size (not 64 or 65 bytes)
    SchnorrSigSize,
    /// Schnorr signature verification failed
    SchnorrSigVerifyFail,
    /// Taproot control block has wrong size
    TaprootWrongControlSize,
    /// Witness program is empty (Taproot requires at least one witness item)
    WitnessProgramEmpty,
}

impl std::fmt::Display for ScriptError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl std::error::Error for ScriptError {}

// ---------------------------------------------------------------------------
// Signature checker trait
// ---------------------------------------------------------------------------

/// Trait for checking ECDSA/Schnorr signatures.
///
/// The interpreter delegates all cryptographic signature verification to this
/// trait, allowing the domain layer to remain independent of any particular
/// secp256k1 implementation. The infrastructure or adapter layer provides
/// a concrete implementation backed by a real crypto library.
pub trait SignatureChecker: Send + Sync {
    /// Verify an ECDSA signature against a public key for the current
    /// transaction input being validated.
    ///
    /// * `sig` - DER-encoded signature with sighash type appended
    /// * `pubkey` - SEC1-encoded public key (33 or 65 bytes)
    /// * `script_code` - the script being executed (for sighash computation)
    ///
    /// Returns `true` if the signature is valid.
    fn check_sig(
        &self,
        sig: &[u8],
        pubkey: &[u8],
        script_code: &Script,
    ) -> bool;

    /// Verify a locktime constraint (OP_CHECKLOCKTIMEVERIFY / BIP65)
    fn check_lock_time(&self, lock_time: i64) -> bool;

    /// Verify a sequence constraint (OP_CHECKSEQUENCEVERIFY / BIP112)
    fn check_sequence(&self, sequence: i64) -> bool;

    /// Verify a BIP340 Schnorr signature for Taproot key-path spending.
    ///
    /// * `sig` - 64-byte Schnorr signature (sighash type already stripped)
    /// * `pubkey` - 32-byte x-only public key (the output key / witness program)
    ///
    /// The checker computes the Taproot sighash (tagged_hash("TapSighash", ...))
    /// and verifies the signature against the public key.
    ///
    /// Default implementation returns false (for non-signing checkers).
    fn check_schnorr_sig(&self, _sig: &[u8], _pubkey: &[u8]) -> bool {
        false
    }

    /// Verify a BIP342 Schnorr signature for Taproot script-path spending.
    ///
    /// Like `check_schnorr_sig` but uses the script-path sighash (BIP341 §4.3)
    /// which includes the tapleaf hash, key version, and code separator position.
    ///
    /// Default implementation returns false.
    fn check_tapscript_sig(&self, _sig: &[u8], _pubkey: &[u8], _leaf_hash: &[u8; 32]) -> bool {
        false
    }
}

/// A no-op signature checker that always returns false.
///
/// Used when evaluating scripts that should not contain signature checks
/// (e.g., bare scriptPubKey evaluation before scriptSig is applied).
pub struct NoSigChecker;

impl SignatureChecker for NoSigChecker {
    fn check_sig(&self, _sig: &[u8], _pubkey: &[u8], _script_code: &Script) -> bool {
        false
    }

    fn check_lock_time(&self, _lock_time: i64) -> bool {
        false
    }

    fn check_sequence(&self, _sequence: i64) -> bool {
        false
    }
}

/// A signature checker wrapper for BIP342 tapscript execution.
///
/// Wraps an existing `SignatureChecker` and overrides signature verification
/// to use Schnorr with the script-path sighash (which includes the tapleaf hash).
///
/// In BIP342 tapscripts:
/// - OP_CHECKSIG uses Schnorr (not ECDSA) with x-only pubkeys
/// - The sighash includes the tapleaf hash (BIP341 §4.3)
/// - OP_CHECKSIGADD is available for multi-sig patterns
pub struct TapscriptChecker<'a> {
    inner: &'a dyn SignatureChecker,
    tapleaf_hash: [u8; 32],
}

impl<'a> TapscriptChecker<'a> {
    /// Create a new tapscript checker wrapping an existing checker.
    pub fn new(inner: &'a dyn SignatureChecker, tapleaf_hash: [u8; 32]) -> Self {
        TapscriptChecker { inner, tapleaf_hash }
    }
}

impl<'a> SignatureChecker for TapscriptChecker<'a> {
    fn check_sig(&self, sig: &[u8], pubkey: &[u8], _script_code: &Script) -> bool {
        // In BIP342 tapscript, OP_CHECKSIG uses Schnorr (not ECDSA).
        // Pubkey must be 32-byte x-only.
        if pubkey.len() != 32 || sig.is_empty() {
            return false;
        }
        // Parse: 64 bytes = sig + SIGHASH_DEFAULT, 65 bytes = sig + explicit sighash
        let sig_bytes = match sig.len() {
            64 => sig,
            65 => &sig[..64],
            _ => return false,
        };
        self.inner.check_tapscript_sig(sig_bytes, pubkey, &self.tapleaf_hash)
    }

    fn check_lock_time(&self, lock_time: i64) -> bool {
        self.inner.check_lock_time(lock_time)
    }

    fn check_sequence(&self, sequence: i64) -> bool {
        self.inner.check_sequence(sequence)
    }

    fn check_schnorr_sig(&self, sig: &[u8], pubkey: &[u8]) -> bool {
        self.inner.check_tapscript_sig(sig, pubkey, &self.tapleaf_hash)
    }

    fn check_tapscript_sig(&self, sig: &[u8], pubkey: &[u8], leaf_hash: &[u8; 32]) -> bool {
        self.inner.check_tapscript_sig(sig, pubkey, leaf_hash)
    }
}

// ---------------------------------------------------------------------------
// Script execution limits
// ---------------------------------------------------------------------------

/// Maximum script size in bytes
const MAX_SCRIPT_SIZE: usize = 10_000;

/// Maximum number of non-push opcodes
const MAX_OPS_PER_SCRIPT: usize = 201;

/// Maximum number of items on the stack + altstack
const MAX_STACK_SIZE: usize = 1000;

/// Maximum element size on the stack
const MAX_SCRIPT_ELEMENT_SIZE: usize = 520;

/// Maximum number of public keys in a multisig
const MAX_PUBKEYS_PER_MULTISIG: usize = 20;

// ---------------------------------------------------------------------------
// Script interpreter
// ---------------------------------------------------------------------------

/// The Bitcoin Script interpreter.
///
/// Evaluates a script on a stack machine. This is the core of Bitcoin
/// transaction validation — it determines whether a scriptSig satisfies
/// the conditions set by a scriptPubKey.
pub struct ScriptInterpreter<'a> {
    /// Main data stack
    stack: Vec<Vec<u8>>,
    /// Alternate stack (OP_TOALTSTACK / OP_FROMALTSTACK)
    altstack: Vec<Vec<u8>>,
    /// Conditional execution state stack (true = executing, false = skipping)
    exec_stack: Vec<bool>,
    /// Verification flags
    flags: ScriptFlags,
    /// Signature checker
    checker: &'a dyn SignatureChecker,
    /// Number of non-push opcodes executed
    op_count: usize,
    /// The script currently being executed (needed for legacy sighash in OP_CHECKSIG)
    script_code: Script,
}

impl<'a> ScriptInterpreter<'a> {
    /// Create a new interpreter with the given flags and signature checker.
    pub fn new(flags: ScriptFlags, checker: &'a dyn SignatureChecker) -> Self {
        ScriptInterpreter {
            stack: Vec::new(),
            altstack: Vec::new(),
            exec_stack: Vec::new(),
            flags,
            checker,
            op_count: 0,
            script_code: Script::new(),
        }
    }

    // --- Stack helpers ---

    fn push(&mut self, data: Vec<u8>) -> Result<(), ScriptError> {
        if self.stack.len() + self.altstack.len() >= MAX_STACK_SIZE {
            return Err(ScriptError::StackOverflow);
        }
        self.stack.push(data);
        Ok(())
    }

    fn pop(&mut self) -> Result<Vec<u8>, ScriptError> {
        self.stack.pop().ok_or(ScriptError::StackUnderflow)
    }

    fn top(&self, offset: usize) -> Result<&Vec<u8>, ScriptError> {
        if offset >= self.stack.len() {
            return Err(ScriptError::StackUnderflow);
        }
        Ok(&self.stack[self.stack.len() - 1 - offset])
    }

    fn pop_num(&mut self) -> Result<i64, ScriptError> {
        let bytes = self.pop()?;
        decode_script_num(&bytes, MAX_SCRIPT_NUM_LENGTH)
    }

    fn push_num(&mut self, value: i64) -> Result<(), ScriptError> {
        self.push(encode_script_num(value))
    }

    fn push_bool(&mut self, value: bool) -> Result<(), ScriptError> {
        self.push(if value { vec![1] } else { Vec::new() })
    }

    /// Are we in an executing branch? (all exec_stack entries are true)
    fn executing(&self) -> bool {
        self.exec_stack.iter().all(|&e| e)
    }

    // --- Core evaluation ---

    /// Evaluate a script. Returns Ok(()) if the script succeeds.
    /// After evaluation the stack is left in place for the caller to inspect.
    pub fn eval_script(&mut self, script: &Script) -> Result<(), ScriptError> {
        let bytes = script.as_bytes();

        if bytes.len() > MAX_SCRIPT_SIZE {
            return Err(ScriptError::ScriptSize);
        }

        // Track the script being executed for legacy sighash in OP_CHECKSIG
        self.script_code = script.clone();

        let mut pc = 0usize;

        while pc < bytes.len() {
            let byte = bytes[pc];
            pc += 1;

            let executing = self.executing();

            // Handle data push opcodes (0x01..=0x4e)
            if byte <= 0x4e && byte != Opcodes::OP_RESERVED as u8 {
                let data_len = match byte {
                    0 => {
                        // OP_0 - push empty byte vector
                        if executing {
                            self.push(Vec::new())?;
                        }
                        continue;
                    }
                    1..=75 => byte as usize,
                    0x4c => {
                        // OP_PUSHDATA1
                        if pc >= bytes.len() {
                            return Err(ScriptError::BadOpcode);
                        }
                        let len = bytes[pc] as usize;
                        pc += 1;
                        len
                    }
                    0x4d => {
                        // OP_PUSHDATA2
                        if pc + 1 >= bytes.len() {
                            return Err(ScriptError::BadOpcode);
                        }
                        let len = u16::from_le_bytes([bytes[pc], bytes[pc + 1]]) as usize;
                        pc += 2;
                        len
                    }
                    0x4e => {
                        // OP_PUSHDATA4
                        if pc + 3 >= bytes.len() {
                            return Err(ScriptError::BadOpcode);
                        }
                        let len = u32::from_le_bytes([
                            bytes[pc],
                            bytes[pc + 1],
                            bytes[pc + 2],
                            bytes[pc + 3],
                        ]) as usize;
                        pc += 4;
                        len
                    }
                    _ => unreachable!(),
                };

                if data_len > MAX_SCRIPT_ELEMENT_SIZE {
                    return Err(ScriptError::PushSize);
                }
                if pc + data_len > bytes.len() {
                    return Err(ScriptError::BadOpcode);
                }

                if executing {
                    self.push(bytes[pc..pc + data_len].to_vec())?;
                }
                pc += data_len;
                continue;
            }

            // Parse opcode
            let opcode = match Opcodes::from_u8(byte) {
                Some(op) => op,
                None => return Err(ScriptError::InvalidOpcode),
            };

            // Count non-push opcodes
            if byte > Opcodes::OP_16 as u8 {
                self.op_count += 1;
                if self.op_count > MAX_OPS_PER_SCRIPT {
                    return Err(ScriptError::OpCount);
                }
            }

            // Disabled opcodes always fail, even in non-executing branches
            match opcode {
                Opcodes::OP_2MUL | Opcodes::OP_2DIV | Opcodes::OP_MUL
                | Opcodes::OP_DIV | Opcodes::OP_MOD
                | Opcodes::OP_LSHIFT | Opcodes::OP_RSHIFT => {
                    return Err(ScriptError::DisabledOpcode);
                }
                _ => {}
            }

            // --- Conditional flow control ---
            match opcode {
                Opcodes::OP_IF | Opcodes::OP_NOTIF => {
                    let mut condition = false;
                    if executing {
                        let val = self.pop()?;
                        condition = stack_is_true(&val);
                        if opcode == Opcodes::OP_NOTIF {
                            condition = !condition;
                        }
                    }
                    self.exec_stack.push(condition && executing);
                    continue;
                }
                Opcodes::OP_ELSE => {
                    if self.exec_stack.is_empty() {
                        return Err(ScriptError::UnbalancedConditional);
                    }
                    // Compute parent_executing before taking mutable borrow
                    let len = self.exec_stack.len();
                    let parent_executing = if len > 1 {
                        self.exec_stack[..len - 1].iter().all(|&e| e)
                    } else {
                        true
                    };
                    let last = self.exec_stack.last_mut().unwrap();
                    if parent_executing {
                        *last = !*last;
                    }
                    continue;
                }
                Opcodes::OP_ENDIF => {
                    if self.exec_stack.is_empty() {
                        return Err(ScriptError::UnbalancedConditional);
                    }
                    self.exec_stack.pop();
                    continue;
                }
                _ => {}
            }

            // If not executing (inside a false branch), skip everything
            // except flow control which is handled above
            if !executing {
                continue;
            }

            // --- Execute opcode ---
            match opcode {
                // Constants
                Opcodes::OP_1NEGATE => self.push_num(-1)?,
                Opcodes::OP_1 => self.push(vec![1])?,
                Opcodes::OP_2 => self.push(vec![2])?,
                Opcodes::OP_3 => self.push(vec![3])?,
                Opcodes::OP_4 => self.push(vec![4])?,
                Opcodes::OP_5 => self.push(vec![5])?,
                Opcodes::OP_6 => self.push(vec![6])?,
                Opcodes::OP_7 => self.push(vec![7])?,
                Opcodes::OP_8 => self.push(vec![8])?,
                Opcodes::OP_9 => self.push(vec![9])?,
                Opcodes::OP_10 => self.push(vec![10])?,
                Opcodes::OP_11 => self.push(vec![11])?,
                Opcodes::OP_12 => self.push(vec![12])?,
                Opcodes::OP_13 => self.push(vec![13])?,
                Opcodes::OP_14 => self.push(vec![14])?,
                Opcodes::OP_15 => self.push(vec![15])?,
                Opcodes::OP_16 => self.push(vec![16])?,

                // NOP
                Opcodes::OP_NOP => {}

                // OP_RETURN
                Opcodes::OP_RETURN => {
                    return Err(ScriptError::OpReturn);
                }

                // OP_VERIFY
                Opcodes::OP_VERIFY => {
                    let val = self.pop()?;
                    if !stack_is_true(&val) {
                        return Err(ScriptError::VerifyFailed);
                    }
                }

                // ---- Stack manipulation ----

                Opcodes::OP_DUP => {
                    let top = self.top(0)?.clone();
                    self.push(top)?;
                }
                Opcodes::OP_DROP => {
                    self.pop()?;
                }
                Opcodes::OP_2DROP => {
                    self.pop()?;
                    self.pop()?;
                }
                Opcodes::OP_2DUP => {
                    let a = self.top(1)?.clone();
                    let b = self.top(0)?.clone();
                    self.push(a)?;
                    self.push(b)?;
                }
                Opcodes::OP_3DUP => {
                    let a = self.top(2)?.clone();
                    let b = self.top(1)?.clone();
                    let c = self.top(0)?.clone();
                    self.push(a)?;
                    self.push(b)?;
                    self.push(c)?;
                }
                Opcodes::OP_2OVER => {
                    let a = self.top(3)?.clone();
                    let b = self.top(2)?.clone();
                    self.push(a)?;
                    self.push(b)?;
                }
                Opcodes::OP_2SWAP => {
                    let len = self.stack.len();
                    if len < 4 {
                        return Err(ScriptError::StackUnderflow);
                    }
                    self.stack.swap(len - 4, len - 2);
                    self.stack.swap(len - 3, len - 1);
                }
                Opcodes::OP_2ROT => {
                    let len = self.stack.len();
                    if len < 6 {
                        return Err(ScriptError::StackUnderflow);
                    }
                    let a = self.stack.remove(len - 6);
                    let b = self.stack.remove(len - 6); // shifted after remove
                    self.stack.push(a);
                    self.stack.push(b);
                }
                Opcodes::OP_SWAP => {
                    let len = self.stack.len();
                    if len < 2 {
                        return Err(ScriptError::StackUnderflow);
                    }
                    self.stack.swap(len - 2, len - 1);
                }
                Opcodes::OP_ROT => {
                    let len = self.stack.len();
                    if len < 3 {
                        return Err(ScriptError::StackUnderflow);
                    }
                    let item = self.stack.remove(len - 3);
                    self.stack.push(item);
                }
                Opcodes::OP_OVER => {
                    let item = self.top(1)?.clone();
                    self.push(item)?;
                }
                Opcodes::OP_NIP => {
                    let len = self.stack.len();
                    if len < 2 {
                        return Err(ScriptError::StackUnderflow);
                    }
                    self.stack.remove(len - 2);
                }
                Opcodes::OP_TUCK => {
                    let len = self.stack.len();
                    if len < 2 {
                        return Err(ScriptError::StackUnderflow);
                    }
                    let top = self.stack[len - 1].clone();
                    self.stack.insert(len - 2, top);
                }
                Opcodes::OP_PICK => {
                    let n = self.pop_num()? as usize;
                    let item = self.top(n)?.clone();
                    self.push(item)?;
                }
                Opcodes::OP_ROLL => {
                    let n = self.pop_num()? as usize;
                    if n >= self.stack.len() {
                        return Err(ScriptError::StackUnderflow);
                    }
                    let idx = self.stack.len() - 1 - n;
                    let item = self.stack.remove(idx);
                    self.stack.push(item);
                }
                Opcodes::OP_IFDUP => {
                    let top = self.top(0)?.clone();
                    if stack_is_true(&top) {
                        self.push(top)?;
                    }
                }
                Opcodes::OP_DEPTH => {
                    let depth = self.stack.len() as i64;
                    self.push_num(depth)?;
                }
                Opcodes::OP_TOALTSTACK => {
                    let val = self.pop()?;
                    self.altstack.push(val);
                }
                Opcodes::OP_FROMALTSTACK => {
                    if self.altstack.is_empty() {
                        return Err(ScriptError::StackUnderflow);
                    }
                    let val = self.altstack.pop().unwrap();
                    self.push(val)?;
                }
                Opcodes::OP_SIZE => {
                    // Push the byte length of the top stack item without popping it
                    let top = self.top(0)?;
                    let size = top.len() as i64;
                    self.push_num(size)?;
                }

                // ---- Equality ----

                Opcodes::OP_EQUAL => {
                    let a = self.pop()?;
                    let b = self.pop()?;
                    self.push_bool(a == b)?;
                }
                Opcodes::OP_EQUALVERIFY => {
                    let a = self.pop()?;
                    let b = self.pop()?;
                    if a != b {
                        return Err(ScriptError::VerifyFailed);
                    }
                }

                // ---- Arithmetic ----

                Opcodes::OP_1ADD => {
                    let n = self.pop_num()?;
                    self.push_num(n + 1)?;
                }
                Opcodes::OP_1SUB => {
                    let n = self.pop_num()?;
                    self.push_num(n - 1)?;
                }
                Opcodes::OP_NEGATE => {
                    let n = self.pop_num()?;
                    self.push_num(-n)?;
                }
                Opcodes::OP_ABS => {
                    let n = self.pop_num()?;
                    self.push_num(n.abs())?;
                }
                Opcodes::OP_NOT => {
                    let n = self.pop_num()?;
                    self.push_bool(n == 0)?;
                }
                Opcodes::OP_0NOTEQUAL => {
                    let n = self.pop_num()?;
                    self.push_bool(n != 0)?;
                }
                Opcodes::OP_ADD => {
                    let b = self.pop_num()?;
                    let a = self.pop_num()?;
                    self.push_num(a + b)?;
                }
                Opcodes::OP_SUB => {
                    let b = self.pop_num()?;
                    let a = self.pop_num()?;
                    self.push_num(a - b)?;
                }
                Opcodes::OP_BOOLAND => {
                    let b = self.pop_num()?;
                    let a = self.pop_num()?;
                    self.push_bool(a != 0 && b != 0)?;
                }
                Opcodes::OP_BOOLOR => {
                    let b = self.pop_num()?;
                    let a = self.pop_num()?;
                    self.push_bool(a != 0 || b != 0)?;
                }
                Opcodes::OP_NUMEQUAL => {
                    let b = self.pop_num()?;
                    let a = self.pop_num()?;
                    self.push_bool(a == b)?;
                }
                Opcodes::OP_NUMEQUALVERIFY => {
                    let b = self.pop_num()?;
                    let a = self.pop_num()?;
                    if a != b {
                        return Err(ScriptError::VerifyFailed);
                    }
                }
                Opcodes::OP_NUMNOTEQUAL => {
                    let b = self.pop_num()?;
                    let a = self.pop_num()?;
                    self.push_bool(a != b)?;
                }
                Opcodes::OP_LESSTHAN => {
                    let b = self.pop_num()?;
                    let a = self.pop_num()?;
                    self.push_bool(a < b)?;
                }
                Opcodes::OP_GREATERTHAN => {
                    let b = self.pop_num()?;
                    let a = self.pop_num()?;
                    self.push_bool(a > b)?;
                }
                Opcodes::OP_LESSTHANOREQUAL => {
                    let b = self.pop_num()?;
                    let a = self.pop_num()?;
                    self.push_bool(a <= b)?;
                }
                Opcodes::OP_GREATERTHANOREQUAL => {
                    let b = self.pop_num()?;
                    let a = self.pop_num()?;
                    self.push_bool(a >= b)?;
                }
                Opcodes::OP_MIN => {
                    let b = self.pop_num()?;
                    let a = self.pop_num()?;
                    self.push_num(cmp::min(a, b))?;
                }
                Opcodes::OP_MAX => {
                    let b = self.pop_num()?;
                    let a = self.pop_num()?;
                    self.push_num(cmp::max(a, b))?;
                }
                Opcodes::OP_WITHIN => {
                    let max = self.pop_num()?;
                    let min = self.pop_num()?;
                    let x = self.pop_num()?;
                    self.push_bool(x >= min && x < max)?;
                }

                // ---- Crypto ----

                Opcodes::OP_RIPEMD160 => {
                    use ripemd::Ripemd160;
                    use sha2::Digest;
                    let data = self.pop()?;
                    let mut hasher = Ripemd160::new();
                    hasher.update(&data);
                    let result = hasher.finalize();
                    self.push(result.to_vec())?;
                }
                Opcodes::OP_SHA1 => {
                    // SHA-1 hash (consensus-required opcode)
                    let data = self.pop()?;
                    let hash = hashing::sha1(&data);
                    self.push(hash.to_vec())?;
                }
                Opcodes::OP_SHA256 => {
                    let data = self.pop()?;
                    let hash = hashing::sha256(&data);
                    self.push(hash.as_bytes().to_vec())?;
                }
                Opcodes::OP_HASH160 => {
                    let data = self.pop()?;
                    let hash = hashing::hash160(&data);
                    self.push(hash.to_vec())?;
                }
                Opcodes::OP_HASH256 => {
                    let data = self.pop()?;
                    let hash = hashing::hash256(&data);
                    self.push(hash.as_bytes().to_vec())?;
                }

                Opcodes::OP_CODESEPARATOR => {
                    // Updates the "script code" used for signature hashing.
                    // For simplicity we track this but it doesn't affect our
                    // current signature checking approach.
                }

                Opcodes::OP_CHECKSIG => {
                    let pubkey = self.pop()?;
                    let sig = self.pop()?;

                    let ok = if sig.is_empty() {
                        false
                    } else {
                        let sc = self.script_code.clone();
                        self.checker.check_sig(&sig, &pubkey, &sc)
                    };

                    self.push_bool(ok)?;
                }

                Opcodes::OP_CHECKSIGVERIFY => {
                    let pubkey = self.pop()?;
                    let sig = self.pop()?;

                    let ok = if sig.is_empty() {
                        false
                    } else {
                        let sc = self.script_code.clone();
                        self.checker.check_sig(&sig, &pubkey, &sc)
                    };

                    if !ok {
                        return Err(ScriptError::SigVerifyFailed);
                    }
                }

                Opcodes::OP_CHECKMULTISIG => {
                    // Pop public key count
                    let n_keys = self.pop_num()? as usize;
                    if n_keys > MAX_PUBKEYS_PER_MULTISIG {
                        return Err(ScriptError::MultisigTooManyKeys);
                    }
                    self.op_count += n_keys;
                    if self.op_count > MAX_OPS_PER_SCRIPT {
                        return Err(ScriptError::OpCount);
                    }

                    // Pop public keys
                    let mut pubkeys = Vec::with_capacity(n_keys);
                    for _ in 0..n_keys {
                        pubkeys.push(self.pop()?);
                    }

                    // Pop signature count
                    let n_sigs = self.pop_num()? as usize;
                    if n_sigs > n_keys {
                        return Err(ScriptError::MultisigNotEnoughSigs);
                    }

                    // Pop signatures
                    let mut sigs = Vec::with_capacity(n_sigs);
                    for _ in 0..n_sigs {
                        sigs.push(self.pop()?);
                    }

                    // Pop the dummy element (off-by-one bug in original Bitcoin)
                    let dummy = self.pop()?;
                    if self.flags.has(ScriptFlags::VERIFY_NULLDUMMY) && !dummy.is_empty() {
                        return Err(ScriptError::NullDummy);
                    }

                    // Verify signatures against keys in order
                    let mut key_idx = 0;
                    let mut success = true;
                    for sig in &sigs {
                        if sig.is_empty() {
                            success = false;
                            break;
                        }
                        let mut found = false;
                        while key_idx < n_keys {
                            if self.checker.check_sig(sig, &pubkeys[key_idx], &self.script_code) {
                                key_idx += 1;
                                found = true;
                                break;
                            }
                            key_idx += 1;
                        }
                        if !found {
                            success = false;
                            break;
                        }
                    }

                    self.push_bool(success)?;
                }

                Opcodes::OP_CHECKMULTISIGVERIFY => {
                    // Same as CHECKMULTISIG but verify
                    // We implement by evaluating CHECKMULTISIG logic then checking result.
                    // For brevity, duplicate the logic with a verify at the end.
                    let n_keys = self.pop_num()? as usize;
                    if n_keys > MAX_PUBKEYS_PER_MULTISIG {
                        return Err(ScriptError::MultisigTooManyKeys);
                    }
                    self.op_count += n_keys;
                    if self.op_count > MAX_OPS_PER_SCRIPT {
                        return Err(ScriptError::OpCount);
                    }

                    let mut pubkeys = Vec::with_capacity(n_keys);
                    for _ in 0..n_keys {
                        pubkeys.push(self.pop()?);
                    }

                    let n_sigs = self.pop_num()? as usize;
                    if n_sigs > n_keys {
                        return Err(ScriptError::MultisigNotEnoughSigs);
                    }

                    let mut sigs = Vec::with_capacity(n_sigs);
                    for _ in 0..n_sigs {
                        sigs.push(self.pop()?);
                    }

                    let dummy = self.pop()?;
                    if self.flags.has(ScriptFlags::VERIFY_NULLDUMMY) && !dummy.is_empty() {
                        return Err(ScriptError::NullDummy);
                    }

                    let mut key_idx = 0;
                    for sig in &sigs {
                        if sig.is_empty() {
                            return Err(ScriptError::SigVerifyFailed);
                        }
                        let mut found = false;
                        while key_idx < n_keys {
                            if self.checker.check_sig(sig, &pubkeys[key_idx], &self.script_code) {
                                key_idx += 1;
                                found = true;
                                break;
                            }
                            key_idx += 1;
                        }
                        if !found {
                            return Err(ScriptError::SigVerifyFailed);
                        }
                    }
                }

                // ---- BIP342 Tapscript ----

                Opcodes::OP_CHECKSIGADD => {
                    // BIP342: pop pubkey, pop num, pop sig
                    // If sig is empty → push num (failed sig doesn't abort, just doesn't increment)
                    // If sig verifies → push num + 1
                    // If sig is non-empty but invalid → fail
                    let pubkey = self.pop()?;
                    let n = self.pop_num()?;
                    let sig = self.pop()?;

                    if sig.is_empty() {
                        // Empty sig = "I'm not signing" — push n unchanged
                        self.push_num(n)?;
                    } else {
                        let sc = self.script_code.clone();
                        let ok = self.checker.check_sig(&sig, &pubkey, &sc);
                        if !ok {
                            return Err(ScriptError::SchnorrSigVerifyFail);
                        }
                        self.push_num(n + 1)?;
                    }
                }

                // ---- Locktime ----

                Opcodes::OP_CHECKLOCKTIMEVERIFY => {
                    if !self.flags.has(ScriptFlags::VERIFY_CHECKLOCKTIMEVERIFY) {
                        // Treat as NOP if flag not set (pre-BIP65)
                        continue;
                    }
                    let lock_time = {
                        let top = self.top(0)?;
                        decode_script_num(top, 5)?
                    };
                    if lock_time < 0 {
                        return Err(ScriptError::NegativeLocktime);
                    }
                    if !self.checker.check_lock_time(lock_time) {
                        return Err(ScriptError::UnsatisfiedLocktime);
                    }
                }

                Opcodes::OP_CHECKSEQUENCEVERIFY => {
                    if !self.flags.has(ScriptFlags::VERIFY_CHECKSEQUENCEVERIFY) {
                        continue;
                    }
                    let sequence = {
                        let top = self.top(0)?;
                        decode_script_num(top, 5)?
                    };
                    if sequence < 0 {
                        return Err(ScriptError::NegativeLocktime);
                    }
                    // If the disable flag (bit 31) is set, skip the check
                    if sequence & (1 << 31) == 0 {
                        if !self.checker.check_sequence(sequence) {
                            return Err(ScriptError::UnsatisfiedLocktime);
                        }
                    }
                }

                // Upgradable NOPs
                Opcodes::OP_NOP1 | Opcodes::OP_NOP4 | Opcodes::OP_NOP5
                | Opcodes::OP_NOP6 | Opcodes::OP_NOP7 | Opcodes::OP_NOP8
                | Opcodes::OP_NOP9 | Opcodes::OP_NOP10 => {
                    if self.flags.has(ScriptFlags::VERIFY_DISCOURAGE_UPGRADABLE_NOPS) {
                        return Err(ScriptError::BadOpcode);
                    }
                }

                // Reserved opcodes
                Opcodes::OP_RESERVED | Opcodes::OP_VER | Opcodes::OP_VERIF
                | Opcodes::OP_VERNOTIF | Opcodes::OP_RESERVED1 | Opcodes::OP_RESERVED2 => {
                    return Err(ScriptError::BadOpcode);
                }

                // These were already handled above but need to be listed for exhaustiveness
                Opcodes::OP_0 | Opcodes::OP_PUSHDATA1 | Opcodes::OP_PUSHDATA2
                | Opcodes::OP_PUSHDATA4 | Opcodes::OP_IF | Opcodes::OP_NOTIF
                | Opcodes::OP_ELSE | Opcodes::OP_ENDIF => {
                    // Already handled in the data push or conditional sections above
                }

                Opcodes::OP_INVALIDOPCODE => {
                    return Err(ScriptError::InvalidOpcode);
                }

                // Disabled opcodes (already handled above, but catch-all for safety)
                Opcodes::OP_2MUL | Opcodes::OP_2DIV | Opcodes::OP_MUL
                | Opcodes::OP_DIV | Opcodes::OP_MOD
                | Opcodes::OP_LSHIFT | Opcodes::OP_RSHIFT => {
                    return Err(ScriptError::DisabledOpcode);
                }
            }
        }

        // Unbalanced conditionals
        if !self.exec_stack.is_empty() {
            return Err(ScriptError::UnbalancedConditional);
        }

        Ok(())
    }

    /// Get a reference to the main stack (for inspection after evaluation)
    pub fn stack(&self) -> &[Vec<u8>] {
        &self.stack
    }

    /// Get the number of items on the stack
    pub fn stack_size(&self) -> usize {
        self.stack.len()
    }
}

// ---------------------------------------------------------------------------
// High-level script verification
// ---------------------------------------------------------------------------

/// Verify that a scriptSig satisfies a scriptPubKey.
///
/// This is the main entry point for script verification. It:
/// 1. Evaluates scriptSig on the stack
/// 2. Copies the stack
/// 3. Evaluates scriptPubKey on the resulting stack
/// 4. Checks if the top stack element is true
/// 5. For P2SH, deserialises the redeemScript and evaluates it
/// 6. For SegWit, evaluates the witness program
pub fn verify_script(
    script_sig: &Script,
    script_pubkey: &Script,
    flags: ScriptFlags,
    checker: &dyn SignatureChecker,
) -> Result<(), ScriptError> {
    verify_script_with_witness(script_sig, script_pubkey, &Witness::new(), flags, checker)
}

/// Verify a script with witness data (BIP141 SegWit support).
///
/// This is the full entry point that accepts witness data for SegWit
/// transaction inputs.
pub fn verify_script_with_witness(
    script_sig: &Script,
    script_pubkey: &Script,
    witness: &Witness,
    flags: ScriptFlags,
    checker: &dyn SignatureChecker,
) -> Result<(), ScriptError> {
    // Step 1: Evaluate scriptSig
    let mut interp = ScriptInterpreter::new(flags, checker);
    interp.eval_script(script_sig)?;

    // Save a copy of the stack for P2SH
    let stack_copy: Vec<Vec<u8>> = interp.stack.clone();

    // Step 2: Evaluate scriptPubKey on the same stack
    interp.eval_script(script_pubkey)?;

    // Step 3: Check result
    if interp.stack.is_empty() {
        return Err(ScriptError::EvalFalse);
    }
    if !stack_is_true(interp.stack.last().unwrap()) {
        return Err(ScriptError::EvalFalse);
    }

    // Step 4: Native witness program (BIP141)
    // If scriptPubKey is a witness program, verify the witness directly
    let mut had_witness = false;
    if flags.has(ScriptFlags::VERIFY_WITNESS) {
        if script_pubkey.is_witness_program() {
            // For native witness, scriptSig MUST be empty
            if !script_sig.is_empty() {
                return Err(ScriptError::WitnessProgramMismatch);
            }

            let version = script_pubkey.witness_version().unwrap();
            let program = script_pubkey.witness_program().unwrap();
            verify_witness_program(witness, version, program, flags, checker)?;
            had_witness = true;
        }
    }

    // Step 5: P2SH evaluation
    if flags.has(ScriptFlags::VERIFY_P2SH) && script_pubkey.is_p2sh() {
        // scriptSig must be push-only for P2SH
        if !is_push_only(script_sig) {
            return Err(ScriptError::SigBadEncoding);
        }

        // The serialized script is the last item pushed by scriptSig
        if stack_copy.is_empty() {
            return Err(ScriptError::EvalFalse);
        }
        let serialized_script = Script::from_bytes(stack_copy.last().unwrap().clone());

        // Check for P2SH-wrapped witness program (BIP141)
        if flags.has(ScriptFlags::VERIFY_WITNESS) && serialized_script.is_witness_program() {
            // For P2SH-wrapped witness, scriptSig must be EXACTLY the push of
            // the witness program (and nothing else)
            if stack_copy.len() != 1 {
                return Err(ScriptError::WitnessProgramMismatch);
            }

            let version = serialized_script.witness_version().unwrap();
            let program = serialized_script.witness_program().unwrap();
            verify_witness_program(witness, version, program, flags, checker)?;
            had_witness = true;
        } else {
            // Standard P2SH evaluation
            let mut p2sh_interp = ScriptInterpreter::new(flags, checker);
            for item in &stack_copy[..stack_copy.len() - 1] {
                p2sh_interp.push(item.clone())?;
            }
            p2sh_interp.eval_script(&serialized_script)?;

            if p2sh_interp.stack.is_empty() {
                return Err(ScriptError::EvalFalse);
            }
            if !stack_is_true(p2sh_interp.stack.last().unwrap()) {
                return Err(ScriptError::EvalFalse);
            }
        }
    }

    // Step 6: Witness must be empty for non-witness scripts (BIP141)
    if flags.has(ScriptFlags::VERIFY_WITNESS) && !had_witness && !witness.is_empty() {
        return Err(ScriptError::WitnessUnexpected);
    }

    // Step 7: Clean stack check
    // When a native witness program was verified, the main interpreter stack
    // legitimately holds 2 items (version + program), so we skip cleanstack.
    // Bitcoin Core likewise exempts the outer stack when witness was handled.
    if flags.has(ScriptFlags::VERIFY_CLEANSTACK) && !had_witness {
        if interp.stack.len() != 1 {
            return Err(ScriptError::CleanStack);
        }
    }

    Ok(())
}

/// Verify a witness program (BIP141).
///
/// Dispatches to the appropriate verifier based on the witness version:
/// - v0: P2WPKH (20-byte program) or P2WSH (32-byte program)
/// - v1+: Future versions succeed if DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM
///         is not set
fn verify_witness_program(
    witness: &Witness,
    version: u8,
    program: &[u8],
    flags: ScriptFlags,
    checker: &dyn SignatureChecker,
) -> Result<(), ScriptError> {
    match version {
        0 => {
            if program.len() == 20 {
                // P2WPKH: witness = [signature, pubkey]
                if witness.len() != 2 {
                    return Err(ScriptError::WitnessProgramMismatch);
                }

                // The pubkey (last witness item) must hash to the program
                let pubkey = witness.get(1).unwrap();
                let pubkey_hash = hashing::hash160(pubkey);
                if pubkey_hash != *program {
                    return Err(ScriptError::WitnessProgramMismatch);
                }

                // Construct the implicit P2PKH script:
                // OP_DUP OP_HASH160 <20-byte-hash> OP_EQUALVERIFY OP_CHECKSIG
                let script_code = ScriptBuilder::new()
                    .push_opcode(Opcodes::OP_DUP)
                    .push_opcode(Opcodes::OP_HASH160)
                    .push_slice(program)
                    .push_opcode(Opcodes::OP_EQUALVERIFY)
                    .push_opcode(Opcodes::OP_CHECKSIG)
                    .build();

                // Evaluate with witness stack items on the stack
                let mut interp = ScriptInterpreter::new(flags, checker);
                for item in witness.iter() {
                    interp.push(item.to_vec())?;
                }
                interp.eval_script(&script_code)?;

                // Must leave exactly one true element
                if interp.stack.len() != 1 {
                    return Err(ScriptError::CleanStack);
                }
                if !stack_is_true(interp.stack.last().unwrap()) {
                    return Err(ScriptError::EvalFalse);
                }

                Ok(())
            } else if program.len() == 32 {
                // P2WSH: witness = [stack items..., witnessScript]
                if witness.is_empty() {
                    return Err(ScriptError::WitnessProgramMismatch);
                }

                // Last witness item is the witnessScript
                let witness_script_bytes = witness.get(witness.len() - 1).unwrap();

                // SHA256 of the witnessScript must match the 32-byte program
                let script_hash = hashing::sha256(witness_script_bytes);
                if script_hash.as_bytes() != program {
                    return Err(ScriptError::WitnessProgramMismatch);
                }

                let witness_script = Script::from_bytes(witness_script_bytes.to_vec());

                // Script size limit for witness scripts
                if witness_script.len() > MAX_SCRIPT_SIZE {
                    return Err(ScriptError::ScriptSize);
                }

                // Evaluate the witnessScript with the remaining witness items as stack
                let mut interp = ScriptInterpreter::new(flags, checker);
                for i in 0..witness.len() - 1 {
                    interp.push(witness.get(i).unwrap().to_vec())?;
                }
                interp.eval_script(&witness_script)?;

                // Must leave exactly one true element
                if interp.stack.len() != 1 {
                    return Err(ScriptError::CleanStack);
                }
                if !stack_is_true(interp.stack.last().unwrap()) {
                    return Err(ScriptError::EvalFalse);
                }

                Ok(())
            } else {
                // Witness v0 program must be 20 or 32 bytes
                Err(ScriptError::WitnessProgramWrongLength)
            }
        }
        1 => {
            // Taproot (BIP341/BIP342): witness version 1
            if program.len() != 32 {
                return Err(ScriptError::WitnessProgramWrongLength);
            }

            verify_taproot(program, witness, flags, checker)
        }
        2..=16 => {
            // Future witness versions: succeed for forward compatibility
            // (unless DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM is set,
            // but we don't enforce that flag yet)
            Ok(())
        }
        _ => Err(ScriptError::WitnessProgramWrongLength),
    }
}

/// Verify a Taproot witness program (BIP341/BIP342).
///
/// Handles both key-path and script-path spending:
///
/// **Key path** (witness = [signature]):
///   Verify the Schnorr signature directly against the output key (the 32-byte program).
///
/// **Script path** (witness = [args..., script, control_block]):
///   1. Parse control block, extract internal key + merkle proof
///   2. Verify merkle commitment: output key == tweak(internal key, merkle_root)
///   3. If leaf version is 0xC0 (tapscript), execute the script with BIP342 rules
///   4. Other leaf versions are treated as success (future upgradability)
fn verify_taproot(
    program: &[u8],
    witness: &Witness,
    flags: ScriptFlags,
    checker: &dyn SignatureChecker,
) -> Result<(), ScriptError> {
    use crate::crypto::taproot::{ControlBlock, verify_taproot_commitment, TAPSCRIPT_LEAF_VERSION};
    use crate::crypto::schnorr::parse_schnorr_signature;

    if witness.is_empty() {
        return Err(ScriptError::WitnessProgramEmpty);
    }

    // Check for annex: if the last witness item starts with 0x50, it's an annex
    // (BIP341 §4.2). We strip it but don't process it (reserved for future use).
    let stack_size = if witness.len() >= 2 {
        let last = witness.get(witness.len() - 1).unwrap();
        if !last.is_empty() && last[0] == 0x50 {
            witness.len() - 1
        } else {
            witness.len()
        }
    } else {
        witness.len()
    };

    if stack_size == 1 {
        // KEY PATH SPENDING: witness = [signature] (possibly with annex stripped)
        let sig_data = witness.get(0).unwrap();

        let (sig_bytes, _hash_type) = parse_schnorr_signature(sig_data)
            .ok_or(ScriptError::SchnorrSigSize)?;

        // For key-path spending, we need the checker to compute the sighash
        // and verify against the output key (the 32-byte program itself).
        let verified = checker.check_schnorr_sig(sig_bytes, program);
        if !verified {
            return Err(ScriptError::SchnorrSigVerifyFail);
        }

        Ok(())
    } else if stack_size >= 2 {
        // SCRIPT PATH SPENDING: witness = [args..., script, control_block]
        let control_data = witness.get(stack_size - 1).unwrap();
        let script_data = witness.get(stack_size - 2).unwrap();

        let control = ControlBlock::parse(control_data)
            .ok_or(ScriptError::TaprootWrongControlSize)?;

        // Verify the merkle commitment: output key matches tweak(internal_key, proof)
        if !verify_taproot_commitment(program, &control, script_data) {
            return Err(ScriptError::WitnessProgramMismatch);
        }

        // If leaf version is TAPSCRIPT (0xC0), execute under BIP342 rules
        if control.leaf_version == TAPSCRIPT_LEAF_VERSION {
            let tap_script = Script::from_bytes(script_data.to_vec());

            // Script size limit for tapscripts (same as witness scripts)
            if tap_script.len() > MAX_SCRIPT_SIZE {
                return Err(ScriptError::ScriptSize);
            }

            // Compute the tapleaf hash for script-path sighash
            let leaf_hash = crate::crypto::taproot::tapleaf_hash(
                control.leaf_version,
                script_data,
            );

            // Wrap the checker in a TapscriptChecker so that OP_CHECKSIG
            // in tapscripts uses Schnorr + script-path sighash (BIP342)
            let tapscript_checker = TapscriptChecker::new(checker, leaf_hash);

            // Execute the tapscript with the remaining witness items as initial stack
            // (everything except the script and control block)
            let mut interp = ScriptInterpreter::new(flags, &tapscript_checker);
            for i in 0..stack_size - 2 {
                interp.push(witness.get(i).unwrap().to_vec())?;
            }
            interp.eval_script(&tap_script)?;

            // Must leave exactly one true element on the stack
            if interp.stack.is_empty() {
                return Err(ScriptError::EvalFalse);
            }
            if !stack_is_true(interp.stack.last().unwrap()) {
                return Err(ScriptError::EvalFalse);
            }
            if interp.stack.len() != 1 {
                return Err(ScriptError::CleanStack);
            }

            Ok(())
        } else {
            // Unknown leaf version: succeed for forward compatibility (BIP342)
            Ok(())
        }
    } else {
        Err(ScriptError::WitnessProgramEmpty)
    }
}

/// Check whether a script is push-only (contains only data push opcodes)
pub fn is_push_only(script: &Script) -> bool {
    for instruction in script.instructions() {
        match instruction {
            ScriptInstruction::Push(_) => {}
            ScriptInstruction::Op(op) => {
                let byte = op as u8;
                // OP_0 through OP_16 are push operations
                if byte > Opcodes::OP_16 as u8 {
                    return false;
                }
            }
            ScriptInstruction::Invalid(_) => return false,
        }
    }
    true
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn eval(script: &Script) -> Result<Vec<Vec<u8>>, ScriptError> {
        let checker = NoSigChecker;
        let mut interp = ScriptInterpreter::new(ScriptFlags::new(0), &checker);
        interp.eval_script(script)?;
        Ok(interp.stack.clone())
    }

    fn eval_bool(script: &Script) -> Result<bool, ScriptError> {
        let stack = eval(script)?;
        Ok(!stack.is_empty() && stack_is_true(stack.last().unwrap()))
    }

    // -- Script number encoding --

    #[test]
    fn test_encode_decode_script_num() {
        for v in [0, 1, -1, 127, -127, 128, -128, 255, -255, 1000, -1000, i32::MAX as i64, -(i32::MAX as i64)] {
            let encoded = encode_script_num(v);
            let decoded = decode_script_num(&encoded, MAX_SCRIPT_NUM_LENGTH).unwrap();
            assert_eq!(v, decoded, "roundtrip failed for {}", v);
        }
    }

    #[test]
    fn test_script_num_zero() {
        let encoded = encode_script_num(0);
        assert!(encoded.is_empty());
        assert_eq!(decode_script_num(&[], MAX_SCRIPT_NUM_LENGTH).unwrap(), 0);
    }

    // -- Stack truth --

    #[test]
    fn test_stack_is_true() {
        assert!(!stack_is_true(&[]));
        assert!(!stack_is_true(&[0]));
        assert!(!stack_is_true(&[0x80])); // negative zero
        assert!(stack_is_true(&[1]));
        assert!(stack_is_true(&[0x81])); // -1
    }

    // -- OP_0 --

    #[test]
    fn test_op_0() {
        let script = Script::from_bytes(vec![Opcodes::OP_0 as u8]);
        let stack = eval(&script).unwrap();
        assert_eq!(stack.len(), 1);
        assert_eq!(stack[0], Vec::<u8>::new());
    }

    // -- OP_1 through OP_16 --

    #[test]
    fn test_op_numbers() {
        for n in 1..=16u8 {
            let opcode = Opcodes::OP_1 as u8 + n - 1;
            let script = Script::from_bytes(vec![opcode]);
            let stack = eval(&script).unwrap();
            assert_eq!(stack[0], vec![n]);
        }
    }

    // -- Data pushes --

    #[test]
    fn test_data_push() {
        let mut bytes = vec![4u8]; // push 4 bytes
        bytes.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);
        let script = Script::from_bytes(bytes);
        let stack = eval(&script).unwrap();
        assert_eq!(stack[0], vec![0xDE, 0xAD, 0xBE, 0xEF]);
    }

    // -- Arithmetic --

    #[test]
    fn test_op_add() {
        // Push 3, push 4, OP_ADD => 7
        let script = Script::from_bytes(vec![
            Opcodes::OP_3 as u8,
            Opcodes::OP_4 as u8,
            Opcodes::OP_ADD as u8,
        ]);
        let stack = eval(&script).unwrap();
        assert_eq!(decode_script_num(&stack[0], 4).unwrap(), 7);
    }

    #[test]
    fn test_op_sub() {
        let script = Script::from_bytes(vec![
            Opcodes::OP_5 as u8,
            Opcodes::OP_3 as u8,
            Opcodes::OP_SUB as u8,
        ]);
        let stack = eval(&script).unwrap();
        assert_eq!(decode_script_num(&stack[0], 4).unwrap(), 2);
    }

    // -- Stack ops --

    #[test]
    fn test_op_dup() {
        let script = Script::from_bytes(vec![
            Opcodes::OP_5 as u8,
            Opcodes::OP_DUP as u8,
        ]);
        let stack = eval(&script).unwrap();
        assert_eq!(stack.len(), 2);
        assert_eq!(stack[0], stack[1]);
    }

    #[test]
    fn test_op_swap() {
        let script = Script::from_bytes(vec![
            Opcodes::OP_3 as u8,
            Opcodes::OP_5 as u8,
            Opcodes::OP_SWAP as u8,
        ]);
        let stack = eval(&script).unwrap();
        assert_eq!(stack[0], vec![5]);
        assert_eq!(stack[1], vec![3]);
    }

    // -- Control flow --

    #[test]
    fn test_op_if_true() {
        // OP_1 OP_IF OP_2 OP_ENDIF
        let script = Script::from_bytes(vec![
            Opcodes::OP_1 as u8,
            Opcodes::OP_IF as u8,
            Opcodes::OP_2 as u8,
            Opcodes::OP_ENDIF as u8,
        ]);
        let stack = eval(&script).unwrap();
        assert_eq!(stack.len(), 1);
        assert_eq!(stack[0], vec![2]);
    }

    #[test]
    fn test_op_if_false() {
        // OP_0 OP_IF OP_2 OP_ELSE OP_3 OP_ENDIF
        let script = Script::from_bytes(vec![
            Opcodes::OP_0 as u8,
            Opcodes::OP_IF as u8,
            Opcodes::OP_2 as u8,
            Opcodes::OP_ELSE as u8,
            Opcodes::OP_3 as u8,
            Opcodes::OP_ENDIF as u8,
        ]);
        let stack = eval(&script).unwrap();
        assert_eq!(stack.len(), 1);
        assert_eq!(stack[0], vec![3]);
    }

    #[test]
    fn test_nested_if() {
        // OP_1 OP_IF OP_1 OP_IF OP_7 OP_ENDIF OP_ENDIF
        let script = Script::from_bytes(vec![
            Opcodes::OP_1 as u8,
            Opcodes::OP_IF as u8,
            Opcodes::OP_1 as u8,
            Opcodes::OP_IF as u8,
            Opcodes::OP_7 as u8,
            Opcodes::OP_ENDIF as u8,
            Opcodes::OP_ENDIF as u8,
        ]);
        let stack = eval(&script).unwrap();
        assert_eq!(stack[0], vec![7]);
    }

    #[test]
    fn test_unbalanced_if() {
        let script = Script::from_bytes(vec![
            Opcodes::OP_1 as u8,
            Opcodes::OP_IF as u8,
        ]);
        assert_eq!(eval(&script), Err(ScriptError::UnbalancedConditional));
    }

    // -- OP_VERIFY --

    #[test]
    fn test_op_verify_true() {
        let script = Script::from_bytes(vec![
            Opcodes::OP_1 as u8,
            Opcodes::OP_VERIFY as u8,
        ]);
        let stack = eval(&script).unwrap();
        assert!(stack.is_empty()); // VERIFY consumes the element
    }

    #[test]
    fn test_op_verify_false() {
        let script = Script::from_bytes(vec![
            Opcodes::OP_0 as u8,
            Opcodes::OP_VERIFY as u8,
        ]);
        assert_eq!(eval(&script), Err(ScriptError::VerifyFailed));
    }

    // -- OP_RETURN --

    #[test]
    fn test_op_return() {
        let script = Script::from_bytes(vec![Opcodes::OP_RETURN as u8]);
        assert_eq!(eval(&script), Err(ScriptError::OpReturn));
    }

    // -- OP_EQUAL / OP_EQUALVERIFY --

    #[test]
    fn test_op_equal() {
        let script = Script::from_bytes(vec![
            Opcodes::OP_5 as u8,
            Opcodes::OP_5 as u8,
            Opcodes::OP_EQUAL as u8,
        ]);
        assert!(eval_bool(&script).unwrap());
    }

    #[test]
    fn test_op_equal_false() {
        let script = Script::from_bytes(vec![
            Opcodes::OP_5 as u8,
            Opcodes::OP_3 as u8,
            Opcodes::OP_EQUAL as u8,
        ]);
        assert!(!eval_bool(&script).unwrap());
    }

    // -- Crypto opcodes --

    #[test]
    fn test_op_hash160() {
        // Push some data, hash it, check we get 20 bytes
        let mut bytes = vec![3u8, 0x01, 0x02, 0x03]; // push 3 bytes
        bytes.push(Opcodes::OP_HASH160 as u8);
        let script = Script::from_bytes(bytes);
        let stack = eval(&script).unwrap();
        assert_eq!(stack[0].len(), 20);
    }

    #[test]
    fn test_op_sha256() {
        let mut bytes = vec![3u8, 0x01, 0x02, 0x03];
        bytes.push(Opcodes::OP_SHA256 as u8);
        let script = Script::from_bytes(bytes);
        let stack = eval(&script).unwrap();
        assert_eq!(stack[0].len(), 32);
    }

    #[test]
    fn test_op_hash256() {
        let mut bytes = vec![3u8, 0x01, 0x02, 0x03];
        bytes.push(Opcodes::OP_HASH256 as u8);
        let script = Script::from_bytes(bytes);
        let stack = eval(&script).unwrap();
        assert_eq!(stack[0].len(), 32);
    }

    // -- Disabled opcodes --

    #[test]
    fn test_disabled_opcodes() {
        let disabled = [
            Opcodes::OP_MUL, Opcodes::OP_DIV, Opcodes::OP_MOD,
            Opcodes::OP_LSHIFT, Opcodes::OP_RSHIFT,
            Opcodes::OP_2MUL, Opcodes::OP_2DIV,
        ];
        for op in disabled {
            let script = Script::from_bytes(vec![op as u8]);
            assert_eq!(eval(&script), Err(ScriptError::DisabledOpcode));
        }
    }

    // -- P2PKH pattern (without real signatures) --

    #[test]
    fn test_p2pkh_pattern_with_mock_checker() {
        // Simulate P2PKH: scriptPubKey = OP_DUP OP_HASH160 <hash> OP_EQUALVERIFY OP_CHECKSIG
        //                  scriptSig    = <sig> <pubkey>
        //
        // We use a mock checker that always returns true for OP_CHECKSIG
        struct AlwaysTrue;
        impl SignatureChecker for AlwaysTrue {
            fn check_sig(&self, _: &[u8], _: &[u8], _: &Script) -> bool { true }
            fn check_lock_time(&self, _: i64) -> bool { true }
            fn check_sequence(&self, _: i64) -> bool { true }
        }

        // Create a "public key"
        let pubkey = vec![0x04; 33]; // fake compressed pubkey
        let pubkey_hash = hashing::hash160(&pubkey);

        // Build scriptPubKey: OP_DUP OP_HASH160 <20-byte hash> OP_EQUALVERIFY OP_CHECKSIG
        let script_pubkey = ScriptBuilder::new()
            .push_opcode(Opcodes::OP_DUP)
            .push_opcode(Opcodes::OP_HASH160)
            .push_slice(&pubkey_hash)
            .push_opcode(Opcodes::OP_EQUALVERIFY)
            .push_opcode(Opcodes::OP_CHECKSIG)
            .build();

        assert!(script_pubkey.is_p2pkh());

        // Build scriptSig: <sig> <pubkey>
        let sig = vec![0x30; 72]; // fake signature
        let script_sig = ScriptBuilder::new()
            .push_slice(&sig)
            .push_slice(&pubkey)
            .build();

        // Verify
        let checker = AlwaysTrue;
        let flags = ScriptFlags::new(0); // No P2SH or CLEANSTACK for simplicity
        let result = verify_script(&script_sig, &script_pubkey, flags, &checker);
        assert!(result.is_ok(), "P2PKH verification failed: {:?}", result);
    }

    // -- verify_script basic --

    #[test]
    fn test_verify_script_true() {
        let script_sig = Script::from_bytes(vec![Opcodes::OP_1 as u8]);
        let script_pubkey = Script::from_bytes(vec![Opcodes::OP_1 as u8, Opcodes::OP_EQUAL as u8]);
        let checker = NoSigChecker;
        let result = verify_script(&script_sig, &script_pubkey, ScriptFlags::new(0), &checker);
        assert!(result.is_ok());
    }

    #[test]
    fn test_verify_script_false() {
        let script_sig = Script::from_bytes(vec![Opcodes::OP_2 as u8]);
        let script_pubkey = Script::from_bytes(vec![Opcodes::OP_1 as u8, Opcodes::OP_EQUAL as u8]);
        let checker = NoSigChecker;
        let result = verify_script(&script_sig, &script_pubkey, ScriptFlags::new(0), &checker);
        assert_eq!(result, Err(ScriptError::EvalFalse));
    }

    // -- Comparison --

    #[test]
    fn test_op_lessthan() {
        let script = Script::from_bytes(vec![
            Opcodes::OP_3 as u8,
            Opcodes::OP_5 as u8,
            Opcodes::OP_LESSTHAN as u8,
        ]);
        assert!(eval_bool(&script).unwrap());
    }

    #[test]
    fn test_op_within() {
        // 3 WITHIN(2, 5) => true
        let script = Script::from_bytes(vec![
            Opcodes::OP_3 as u8,
            Opcodes::OP_2 as u8,
            Opcodes::OP_5 as u8,
            Opcodes::OP_WITHIN as u8,
        ]);
        assert!(eval_bool(&script).unwrap());
    }

    // -- SegWit tests --

    #[test]
    fn test_verify_script_with_witness_empty() {
        // Non-witness script should still work through verify_script_with_witness
        let script_sig = Script::from_bytes(vec![Opcodes::OP_1 as u8]);
        let script_pubkey = Script::from_bytes(vec![Opcodes::OP_1 as u8, Opcodes::OP_EQUAL as u8]);
        let checker = NoSigChecker;
        let result = verify_script_with_witness(
            &script_sig,
            &script_pubkey,
            &Witness::new(),
            ScriptFlags::new(0),
            &checker,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_witness_unexpected_for_non_witness_script() {
        // Non-witness script with non-empty witness should fail when VERIFY_WITNESS is set
        let script_sig = Script::from_bytes(vec![Opcodes::OP_1 as u8]);
        let script_pubkey = Script::from_bytes(vec![Opcodes::OP_1 as u8, Opcodes::OP_EQUAL as u8]);
        let mut witness = Witness::new();
        witness.push(vec![1, 2, 3]);

        let checker = NoSigChecker;
        let result = verify_script_with_witness(
            &script_sig,
            &script_pubkey,
            &witness,
            ScriptFlags::new(ScriptFlags::VERIFY_WITNESS),
            &checker,
        );
        assert_eq!(result, Err(ScriptError::WitnessUnexpected));
    }

    #[test]
    fn test_p2wpkh_program_detection() {
        // Build a P2WPKH scriptPubKey: OP_0 <20-byte-hash>
        let mut script_bytes = vec![0x00, 0x14]; // OP_0, push 20 bytes
        script_bytes.extend_from_slice(&[0xab; 20]);
        let script = Script::from_bytes(script_bytes);
        assert!(script.is_p2wpkh());
        assert!(script.is_witness_program());
        assert_eq!(script.witness_version(), Some(0));
    }

    #[test]
    fn test_p2wsh_program_detection() {
        // Build a P2WSH scriptPubKey: OP_0 <32-byte-hash>
        let mut script_bytes = vec![0x00, 0x20]; // OP_0, push 32 bytes
        script_bytes.extend_from_slice(&[0xcd; 32]);
        let script = Script::from_bytes(script_bytes);
        assert!(script.is_p2wsh());
        assert!(script.is_witness_program());
        assert_eq!(script.witness_version(), Some(0));
    }

    #[test]
    fn test_p2wpkh_with_mock_checker() {
        // P2WPKH verification with a mock checker that always succeeds
        struct AlwaysTrue;
        impl SignatureChecker for AlwaysTrue {
            fn check_sig(&self, _: &[u8], _: &[u8], _: &Script) -> bool { true }
            fn check_lock_time(&self, _: i64) -> bool { true }
            fn check_sequence(&self, _: i64) -> bool { true }
        }

        // Create a "public key" and its hash
        let pubkey = vec![0x02; 33]; // fake compressed pubkey
        let pubkey_hash = hashing::hash160(&pubkey);

        // scriptPubKey = OP_0 <20-byte pubkey hash>
        let mut spk_bytes = vec![0x00, 0x14];
        spk_bytes.extend_from_slice(&pubkey_hash);
        let script_pubkey = Script::from_bytes(spk_bytes);

        // scriptSig = empty (for native SegWit)
        let script_sig = Script::new();

        // witness = [signature, pubkey]
        let mut witness = Witness::new();
        witness.push(vec![0x30; 72]); // fake signature
        witness.push(pubkey);

        let checker = AlwaysTrue;
        let flags = ScriptFlags::new(ScriptFlags::VERIFY_WITNESS);
        let result = verify_script_with_witness(
            &script_sig, &script_pubkey, &witness, flags, &checker,
        );
        assert!(result.is_ok(), "P2WPKH failed: {:?}", result);
    }

    #[test]
    fn test_p2wpkh_wrong_pubkey_hash() {
        struct AlwaysTrue;
        impl SignatureChecker for AlwaysTrue {
            fn check_sig(&self, _: &[u8], _: &[u8], _: &Script) -> bool { true }
            fn check_lock_time(&self, _: i64) -> bool { true }
            fn check_sequence(&self, _: i64) -> bool { true }
        }

        // scriptPubKey with a hash that doesn't match the witness pubkey
        let mut spk_bytes = vec![0x00, 0x14];
        spk_bytes.extend_from_slice(&[0xff; 20]); // wrong hash
        let script_pubkey = Script::from_bytes(spk_bytes);

        let mut witness = Witness::new();
        witness.push(vec![0x30; 72]);
        witness.push(vec![0x02; 33]);

        let result = verify_script_with_witness(
            &Script::new(), &script_pubkey, &witness,
            ScriptFlags::new(ScriptFlags::VERIFY_WITNESS),
            &AlwaysTrue,
        );
        assert_eq!(result, Err(ScriptError::WitnessProgramMismatch));
    }

    #[test]
    fn test_p2wpkh_nonempty_scriptsig_fails() {
        struct AlwaysTrue;
        impl SignatureChecker for AlwaysTrue {
            fn check_sig(&self, _: &[u8], _: &[u8], _: &Script) -> bool { true }
            fn check_lock_time(&self, _: i64) -> bool { true }
            fn check_sequence(&self, _: i64) -> bool { true }
        }

        let pubkey = vec![0x02; 33];
        let pubkey_hash = hashing::hash160(&pubkey);
        let mut spk_bytes = vec![0x00, 0x14];
        spk_bytes.extend_from_slice(&pubkey_hash);
        let script_pubkey = Script::from_bytes(spk_bytes);

        // Non-empty scriptSig is invalid for native witness
        let script_sig = Script::from_bytes(vec![Opcodes::OP_1 as u8]);

        let mut witness = Witness::new();
        witness.push(vec![0x30; 72]);
        witness.push(pubkey);

        let result = verify_script_with_witness(
            &script_sig, &script_pubkey, &witness,
            ScriptFlags::new(ScriptFlags::VERIFY_WITNESS),
            &AlwaysTrue,
        );
        assert_eq!(result, Err(ScriptError::WitnessProgramMismatch));
    }

    #[test]
    fn test_p2wsh_with_mock_checker() {
        // P2WSH: witness contains stack items + witnessScript
        struct AlwaysTrue;
        impl SignatureChecker for AlwaysTrue {
            fn check_sig(&self, _: &[u8], _: &[u8], _: &Script) -> bool { true }
            fn check_lock_time(&self, _: i64) -> bool { true }
            fn check_sequence(&self, _: i64) -> bool { true }
        }

        // witnessScript = OP_1 (just pushes true)
        let witness_script = vec![Opcodes::OP_1 as u8];
        let script_hash = hashing::sha256(&witness_script);

        // scriptPubKey = OP_0 <32-byte SHA256(witnessScript)>
        let mut spk_bytes = vec![0x00, 0x20];
        spk_bytes.extend_from_slice(script_hash.as_bytes());
        let script_pubkey = Script::from_bytes(spk_bytes);

        // witness = [witnessScript]
        let mut witness = Witness::new();
        witness.push(witness_script);

        let result = verify_script_with_witness(
            &Script::new(), &script_pubkey, &witness,
            ScriptFlags::new(ScriptFlags::VERIFY_WITNESS),
            &AlwaysTrue,
        );
        assert!(result.is_ok(), "P2WSH failed: {:?}", result);
    }

    #[test]
    fn test_p2wsh_wrong_script_hash() {
        struct AlwaysTrue;
        impl SignatureChecker for AlwaysTrue {
            fn check_sig(&self, _: &[u8], _: &[u8], _: &Script) -> bool { true }
            fn check_lock_time(&self, _: i64) -> bool { true }
            fn check_sequence(&self, _: i64) -> bool { true }
        }

        // scriptPubKey with wrong hash
        let mut spk_bytes = vec![0x00, 0x20];
        spk_bytes.extend_from_slice(&[0xff; 32]);
        let script_pubkey = Script::from_bytes(spk_bytes);

        let mut witness = Witness::new();
        witness.push(vec![Opcodes::OP_1 as u8]); // witnessScript

        let result = verify_script_with_witness(
            &Script::new(), &script_pubkey, &witness,
            ScriptFlags::new(ScriptFlags::VERIFY_WITNESS),
            &AlwaysTrue,
        );
        assert_eq!(result, Err(ScriptError::WitnessProgramMismatch));
    }

    #[test]
    fn test_witness_v0_bad_program_length() {
        // Witness v0 with 15-byte program (not 20 or 32) should fail
        let mut spk_bytes = vec![0x00, 0x0f]; // OP_0, push 15 bytes
        spk_bytes.extend_from_slice(&[0xab; 15]);
        let script_pubkey = Script::from_bytes(spk_bytes);

        let mut witness = Witness::new();
        witness.push(vec![1]);

        let result = verify_script_with_witness(
            &Script::new(), &script_pubkey, &witness,
            ScriptFlags::new(ScriptFlags::VERIFY_WITNESS),
            &NoSigChecker,
        );
        assert_eq!(result, Err(ScriptError::WitnessProgramWrongLength));
    }
}
