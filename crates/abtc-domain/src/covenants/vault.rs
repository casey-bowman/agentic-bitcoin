//! BIP345 — OP_VAULT / OP_VAULT_RECOVER
//!
//! Implements the domain logic for Bitcoin's native vault construction.
//!
//! ## Vault lifecycle
//!
//! ```text
//!   [Vault UTXO]
//!       │
//!       ├── OP_VAULT (trigger) ──► [Timelocked output]
//!       │                               │
//!       │                               └── (after delay) ──► [Withdrawal]
//!       │
//!       └── OP_VAULT_RECOVER ──► [Recovery address] (immediate)
//! ```
//!
//! ## OP_VAULT semantics
//!
//! The vault opcode verifies that the spending transaction creates a
//! specific "trigger" output that:
//!
//! 1. Preserves the vault amount (minus optional fee contribution)
//! 2. Locks funds behind a timelock (OP_CSV) followed by the authorized
//!    spend path
//! 3. Retains the recovery path so the owner can still claw back
//!
//! Stack inputs (bottom to top):
//! - `leaf-update-script-body`: the script fragment for the authorized
//!   spend path (placed after the OP_CSV timelock in the trigger output)
//! - `target-output-index`: which output in the spending transaction is
//!   the trigger output
//!
//! ## OP_VAULT_RECOVER semantics
//!
//! Allows immediate recovery to a pre-committed recovery scriptPubKey.
//! Verifies that the spending transaction sends funds to the recovery
//! address.
//!
//! Stack inputs (bottom to top):
//! - `recovery-spk-hash`: SHA-256 hash of the expected recovery
//!   scriptPubKey
//! - `target-output-index`: which output receives the recovered funds

use crate::hashing::sha256;
use crate::primitives::{Amount, Hash256, Transaction};
use crate::primitives::Script;

// ---------------------------------------------------------------------------
// Vault parameters
// ---------------------------------------------------------------------------

/// Parameters extracted from a vault script for verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VaultParams {
    /// The recovery scriptPubKey hash (SHA-256).
    /// Committed in the vault script so the recovery path is always available.
    pub recovery_spk_hash: Hash256,
    /// Minimum number of blocks before the trigger output can be spent.
    pub spend_delay: u32,
}

impl VaultParams {
    /// Create new vault parameters.
    pub fn new(recovery_spk_hash: Hash256, spend_delay: u32) -> Self {
        VaultParams {
            recovery_spk_hash,
            spend_delay,
        }
    }

    /// Hash a recovery scriptPubKey to produce the commitment.
    pub fn hash_recovery_spk(spk: &Script) -> Hash256 {
        sha256(spk.as_bytes())
    }
}

// ---------------------------------------------------------------------------
// Vault trigger verification
// ---------------------------------------------------------------------------

/// Information about a vault trigger output for verification.
#[derive(Debug, Clone)]
pub struct VaultTriggerInfo {
    /// The target output index in the spending transaction.
    pub target_output_index: u32,
    /// The script body for the authorized spend path (placed after CSV).
    pub leaf_update_script_body: Vec<u8>,
}

/// Verify that a transaction's output correctly implements a vault trigger.
///
/// Checks:
/// 1. The target output index is valid.
/// 2. The target output's scriptPubKey matches the expected trigger script
///    structure: `<spend_delay> OP_CSV OP_DROP <leaf-update-script-body>`.
/// 3. The output amount preserves the vault value (>= input amount minus
///    a configurable fee tolerance).
///
/// Returns `Ok(())` if the trigger is valid, `Err` with a description otherwise.
pub fn verify_vault_trigger(
    tx: &Transaction,
    trigger: &VaultTriggerInfo,
    vault_amount: Amount,
    spend_delay: u32,
    fee_tolerance: Amount,
) -> Result<(), VaultError> {
    // Check output index is valid
    let idx = trigger.target_output_index as usize;
    if idx >= tx.outputs.len() {
        return Err(VaultError::InvalidTargetIndex {
            index: idx,
            num_outputs: tx.outputs.len(),
        });
    }

    let target_output = &tx.outputs[idx];

    // Check the output amount preserves the vault value
    let min_amount = vault_amount - fee_tolerance;
    if target_output.value.as_sat() < min_amount.as_sat() {
        return Err(VaultError::InsufficientTriggerAmount {
            expected_min: min_amount.as_sat(),
            actual: target_output.value.as_sat(),
        });
    }

    // Build the expected trigger script:
    //   <spend_delay> OP_CHECKSEQUENCEVERIFY OP_DROP <leaf-update-script-body>
    let expected_script = build_trigger_script(spend_delay, &trigger.leaf_update_script_body);

    if target_output.script_pubkey.as_bytes() != expected_script.as_bytes() {
        return Err(VaultError::TriggerScriptMismatch);
    }

    Ok(())
}

/// Build the expected trigger output script.
///
/// Format: `<spend_delay> OP_CHECKSEQUENCEVERIFY OP_DROP <leaf_update_body>`
pub fn build_trigger_script(spend_delay: u32, leaf_update_body: &[u8]) -> Script {
    let mut bytes = Vec::new();

    // Push spend_delay as a script number
    push_script_number(&mut bytes, spend_delay as i64);

    // OP_CHECKSEQUENCEVERIFY (0xb2)
    bytes.push(0xb2);

    // OP_DROP (0x75)
    bytes.push(0x75);

    // Append the leaf-update script body
    bytes.extend_from_slice(leaf_update_body);

    Script::from_bytes(bytes)
}

// ---------------------------------------------------------------------------
// Vault recovery verification
// ---------------------------------------------------------------------------

/// Verify that a transaction correctly implements vault recovery.
///
/// Checks:
/// 1. The target output index is valid.
/// 2. The target output's scriptPubKey hashes to the committed recovery hash.
/// 3. The output amount preserves the vault value (minus fee tolerance).
pub fn verify_vault_recover(
    tx: &Transaction,
    target_output_index: u32,
    recovery_spk_hash: &Hash256,
    vault_amount: Amount,
    fee_tolerance: Amount,
) -> Result<(), VaultError> {
    let idx = target_output_index as usize;
    if idx >= tx.outputs.len() {
        return Err(VaultError::InvalidTargetIndex {
            index: idx,
            num_outputs: tx.outputs.len(),
        });
    }

    let target_output = &tx.outputs[idx];

    // Verify the scriptPubKey matches the committed recovery hash
    let actual_hash = sha256(target_output.script_pubkey.as_bytes());
    if actual_hash != *recovery_spk_hash {
        return Err(VaultError::RecoveryScriptMismatch);
    }

    // Verify amount preservation
    let min_amount = vault_amount - fee_tolerance;
    if target_output.value.as_sat() < min_amount.as_sat() {
        return Err(VaultError::InsufficientRecoveryAmount {
            expected_min: min_amount.as_sat(),
            actual: target_output.value.as_sat(),
        });
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Vault script construction helpers
// ---------------------------------------------------------------------------

/// Construct a vault locking script (the scriptPubKey for a vault output).
///
/// A complete vault script typically looks like (as a Taproot leaf):
/// ```text
/// OP_VAULT <spend_delay> <recovery_spk_hash>
/// ```
///
/// For our implementation, we model the vault as a script fragment that
/// can be embedded in a Taproot script tree alongside the recovery leaf.
pub fn build_vault_script(recovery_spk_hash: &Hash256, spend_delay: u32) -> Script {
    let mut bytes = Vec::new();

    // Push recovery SPK hash (32 bytes)
    bytes.push(0x20); // push 32 bytes
    bytes.extend_from_slice(recovery_spk_hash.as_bytes());

    // Push spend delay
    push_script_number(&mut bytes, spend_delay as i64);

    // OP_VAULT (0xbb)
    bytes.push(0xbb);

    Script::from_bytes(bytes)
}

/// Construct a vault recovery script (Taproot leaf for immediate recovery).
///
/// ```text
/// <recovery_spk_hash> OP_VAULT_RECOVER
/// ```
pub fn build_recovery_script(recovery_spk_hash: &Hash256) -> Script {
    let mut bytes = Vec::new();

    // Push recovery SPK hash (32 bytes)
    bytes.push(0x20); // push 32 bytes
    bytes.extend_from_slice(recovery_spk_hash.as_bytes());

    // OP_VAULT_RECOVER (0xbc)
    bytes.push(0xbc);

    Script::from_bytes(bytes)
}

/// Construct a complete vault output with both spend and recovery paths.
///
/// Returns the two Taproot leaf scripts: (vault_leaf, recovery_leaf).
pub fn build_vault_taproot_leaves(
    recovery_spk_hash: &Hash256,
    spend_delay: u32,
) -> (Script, Script) {
    let vault_leaf = build_vault_script(recovery_spk_hash, spend_delay);
    let recovery_leaf = build_recovery_script(recovery_spk_hash);
    (vault_leaf, recovery_leaf)
}

// ---------------------------------------------------------------------------
// Script number encoding helper
// ---------------------------------------------------------------------------

/// Push a number onto a script as a minimal push.
fn push_script_number(bytes: &mut Vec<u8>, n: i64) {
    if n == 0 {
        bytes.push(0x00); // OP_0
        return;
    }
    if (1..=16).contains(&n) {
        bytes.push(0x50 + n as u8); // OP_1 .. OP_16
        return;
    }
    if n == -1 {
        bytes.push(0x4f); // OP_1NEGATE
        return;
    }

    // Encode as a minimal script number push
    let negative = n < 0;
    let mut abs_val = if negative { (-n) as u64 } else { n as u64 };
    let mut num_bytes = Vec::new();

    while abs_val > 0 {
        num_bytes.push((abs_val & 0xFF) as u8);
        abs_val >>= 8;
    }

    // If the top bit of the last byte is set, we need an extra byte for the sign
    if let Some(last) = num_bytes.last() {
        if last & 0x80 != 0 {
            num_bytes.push(if negative { 0x80 } else { 0x00 });
        } else if negative {
            let len = num_bytes.len();
            num_bytes[len - 1] |= 0x80;
        }
    }

    // Direct push: length byte + data
    bytes.push(num_bytes.len() as u8);
    bytes.extend_from_slice(&num_bytes);
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Errors from vault operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VaultError {
    /// Target output index is out of bounds.
    InvalidTargetIndex { index: usize, num_outputs: usize },
    /// Trigger output amount is too low.
    InsufficientTriggerAmount { expected_min: i64, actual: i64 },
    /// Trigger output script doesn't match expected structure.
    TriggerScriptMismatch,
    /// Recovery output scriptPubKey doesn't match committed hash.
    RecoveryScriptMismatch,
    /// Recovery output amount is too low.
    InsufficientRecoveryAmount { expected_min: i64, actual: i64 },
}

impl std::fmt::Display for VaultError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VaultError::InvalidTargetIndex { index, num_outputs } => {
                write!(
                    f,
                    "target output index {} out of range (tx has {} outputs)",
                    index, num_outputs
                )
            }
            VaultError::InsufficientTriggerAmount {
                expected_min,
                actual,
            } => {
                write!(
                    f,
                    "trigger output amount {} < minimum {}",
                    actual, expected_min
                )
            }
            VaultError::TriggerScriptMismatch => {
                write!(f, "trigger output script does not match expected structure")
            }
            VaultError::RecoveryScriptMismatch => {
                write!(
                    f,
                    "recovery output scriptPubKey does not match committed hash"
                )
            }
            VaultError::InsufficientRecoveryAmount {
                expected_min,
                actual,
            } => {
                write!(
                    f,
                    "recovery output amount {} < minimum {}",
                    actual, expected_min
                )
            }
        }
    }
}

impl std::error::Error for VaultError {}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::primitives::{OutPoint, TxIn, TxOut, Txid};

    fn make_vault_tx(outputs: Vec<TxOut>) -> Transaction {
        Transaction::new(
            2,
            vec![TxIn::new(
                OutPoint::new(Txid::zero(), 0),
                Script::new(),
                0xfffffffe,
            )],
            outputs,
            0,
        )
    }

    // ── VaultParams ────────────────────────────────────────────────

    #[test]
    fn test_vault_params_creation() {
        let spk = Script::from_bytes({
            let mut v = vec![0x00, 0x14];
            v.extend_from_slice(&[0xab; 20]);
            v
        });
        let hash = VaultParams::hash_recovery_spk(&spk);
        let params = VaultParams::new(hash, 144);
        assert_eq!(params.spend_delay, 144);
        assert_ne!(params.recovery_spk_hash, Hash256::zero());
    }

    #[test]
    fn test_recovery_spk_hash_deterministic() {
        let spk = Script::from_bytes(vec![0x76, 0xa9, 0x14]);
        let h1 = VaultParams::hash_recovery_spk(&spk);
        let h2 = VaultParams::hash_recovery_spk(&spk);
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_recovery_spk_hash_different_scripts() {
        let spk1 = Script::from_bytes(vec![0x00, 0x14]);
        let spk2 = Script::from_bytes(vec![0x00, 0x20]);
        assert_ne!(
            VaultParams::hash_recovery_spk(&spk1),
            VaultParams::hash_recovery_spk(&spk2),
        );
    }

    // ── Trigger script construction ────────────────────────────────

    #[test]
    fn test_build_trigger_script() {
        let body = vec![0xac]; // OP_CHECKSIG
        let script = build_trigger_script(144, &body);
        let bytes = script.as_bytes();

        // Should contain: <144> OP_CSV OP_DROP OP_CHECKSIG
        // 144 = 0x90, which needs 2 bytes in script number encoding:
        // push 2 bytes: [0x02, 0x90, 0x00] (0x90 has high bit set, needs sign byte)
        assert!(bytes.contains(&0xb2)); // OP_CHECKSEQUENCEVERIFY
        assert!(bytes.contains(&0x75)); // OP_DROP
        assert_eq!(*bytes.last().unwrap(), 0xac); // OP_CHECKSIG at end
    }

    #[test]
    fn test_build_trigger_script_small_delay() {
        let body = vec![0x51]; // OP_1
        let script = build_trigger_script(10, &body);
        let bytes = script.as_bytes();

        // 10 = OP_10 (0x5a)
        assert_eq!(bytes[0], 0x5a); // OP_10
        assert_eq!(bytes[1], 0xb2); // OP_CSV
        assert_eq!(bytes[2], 0x75); // OP_DROP
        assert_eq!(bytes[3], 0x51); // OP_1
    }

    // ── Trigger verification ───────────────────────────────────────

    #[test]
    fn test_verify_vault_trigger_valid() {
        let spend_delay = 10u32;
        let leaf_body = vec![0x51]; // OP_1
        let expected_script = build_trigger_script(spend_delay, &leaf_body);
        let vault_amount = Amount::from_sat(1_000_000);

        let tx = make_vault_tx(vec![TxOut::new(vault_amount, expected_script)]);

        let trigger = VaultTriggerInfo {
            target_output_index: 0,
            leaf_update_script_body: leaf_body,
        };

        assert!(verify_vault_trigger(
            &tx,
            &trigger,
            vault_amount,
            spend_delay,
            Amount::from_sat(0),
        )
        .is_ok());
    }

    #[test]
    fn test_verify_vault_trigger_insufficient_amount() {
        let spend_delay = 10u32;
        let leaf_body = vec![0x51];
        let expected_script = build_trigger_script(spend_delay, &leaf_body);
        let vault_amount = Amount::from_sat(1_000_000);

        let tx = make_vault_tx(vec![TxOut::new(Amount::from_sat(500_000), expected_script)]);

        let trigger = VaultTriggerInfo {
            target_output_index: 0,
            leaf_update_script_body: leaf_body,
        };

        let result = verify_vault_trigger(
            &tx,
            &trigger,
            vault_amount,
            spend_delay,
            Amount::from_sat(0),
        );
        assert!(matches!(
            result,
            Err(VaultError::InsufficientTriggerAmount { .. })
        ));
    }

    #[test]
    fn test_verify_vault_trigger_with_fee_tolerance() {
        let spend_delay = 10u32;
        let leaf_body = vec![0x51];
        let expected_script = build_trigger_script(spend_delay, &leaf_body);
        let vault_amount = Amount::from_sat(1_000_000);

        // Output is 999,000 — less than vault amount but within tolerance
        let tx = make_vault_tx(vec![TxOut::new(Amount::from_sat(999_000), expected_script)]);

        let trigger = VaultTriggerInfo {
            target_output_index: 0,
            leaf_update_script_body: leaf_body,
        };

        // With 2000 sat fee tolerance, this should pass
        assert!(verify_vault_trigger(
            &tx,
            &trigger,
            vault_amount,
            spend_delay,
            Amount::from_sat(2_000),
        )
        .is_ok());
    }

    #[test]
    fn test_verify_vault_trigger_script_mismatch() {
        let vault_amount = Amount::from_sat(1_000_000);

        // Wrong script in the output
        let tx = make_vault_tx(vec![TxOut::new(
            vault_amount,
            Script::from_bytes(vec![0x51]),
        )]);

        let trigger = VaultTriggerInfo {
            target_output_index: 0,
            leaf_update_script_body: vec![0xac],
        };

        let result = verify_vault_trigger(&tx, &trigger, vault_amount, 10, Amount::from_sat(0));
        assert!(matches!(result, Err(VaultError::TriggerScriptMismatch)));
    }

    #[test]
    fn test_verify_vault_trigger_invalid_index() {
        let tx = make_vault_tx(vec![TxOut::new(Amount::from_sat(100_000), Script::new())]);

        let trigger = VaultTriggerInfo {
            target_output_index: 5, // out of bounds
            leaf_update_script_body: vec![],
        };

        let result = verify_vault_trigger(
            &tx,
            &trigger,
            Amount::from_sat(100_000),
            10,
            Amount::from_sat(0),
        );
        assert!(matches!(result, Err(VaultError::InvalidTargetIndex { .. })));
    }

    // ── Recovery verification ──────────────────────────────────────

    #[test]
    fn test_verify_vault_recover_valid() {
        let recovery_spk = Script::from_bytes(vec![
            0x00, 0x14, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
            0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14,
        ]);
        let recovery_hash = VaultParams::hash_recovery_spk(&recovery_spk);
        let vault_amount = Amount::from_sat(1_000_000);

        let tx = make_vault_tx(vec![TxOut::new(vault_amount, recovery_spk)]);

        assert!(
            verify_vault_recover(&tx, 0, &recovery_hash, vault_amount, Amount::from_sat(0),)
                .is_ok()
        );
    }

    #[test]
    fn test_verify_vault_recover_wrong_script() {
        let recovery_spk = Script::from_bytes({
            let mut v = vec![0x00, 0x14];
            v.extend_from_slice(&[0xab; 20]);
            v
        });
        let recovery_hash = VaultParams::hash_recovery_spk(&recovery_spk);

        // Wrong script in output
        let wrong_spk = Script::from_bytes({
            let mut v = vec![0x00, 0x14];
            v.extend_from_slice(&[0xcd; 20]);
            v
        });
        let tx = make_vault_tx(vec![TxOut::new(Amount::from_sat(1_000_000), wrong_spk)]);

        let result = verify_vault_recover(
            &tx,
            0,
            &recovery_hash,
            Amount::from_sat(1_000_000),
            Amount::from_sat(0),
        );
        assert!(matches!(result, Err(VaultError::RecoveryScriptMismatch)));
    }

    #[test]
    fn test_verify_vault_recover_insufficient_amount() {
        let recovery_spk = Script::from_bytes(vec![0x51]);
        let recovery_hash = VaultParams::hash_recovery_spk(&recovery_spk);

        let tx = make_vault_tx(vec![TxOut::new(Amount::from_sat(500_000), recovery_spk)]);

        let result = verify_vault_recover(
            &tx,
            0,
            &recovery_hash,
            Amount::from_sat(1_000_000),
            Amount::from_sat(0),
        );
        assert!(matches!(
            result,
            Err(VaultError::InsufficientRecoveryAmount { .. })
        ));
    }

    // ── Script construction ────────────────────────────────────────

    #[test]
    fn test_build_vault_script() {
        let hash = Hash256::from_bytes([0xaa; 32]);
        let script = build_vault_script(&hash, 144);
        let bytes = script.as_bytes();

        // Should contain: push32(hash) push(144) OP_VAULT
        assert_eq!(bytes[0], 0x20); // push 32 bytes
        assert_eq!(&bytes[1..33], hash.as_bytes());
        assert_eq!(*bytes.last().unwrap(), 0xbb); // OP_VAULT
    }

    #[test]
    fn test_build_recovery_script() {
        let hash = Hash256::from_bytes([0xbb; 32]);
        let script = build_recovery_script(&hash);
        let bytes = script.as_bytes();

        assert_eq!(bytes[0], 0x20); // push 32 bytes
        assert_eq!(&bytes[1..33], hash.as_bytes());
        assert_eq!(bytes[33], 0xbc); // OP_VAULT_RECOVER
    }

    #[test]
    fn test_build_vault_taproot_leaves() {
        let hash = Hash256::from_bytes([0xcc; 32]);
        let (vault_leaf, recovery_leaf) = build_vault_taproot_leaves(&hash, 288);

        // Both should reference the same recovery hash
        assert!(vault_leaf
            .as_bytes()
            .windows(32)
            .any(|w| w == hash.as_bytes()));
        assert!(recovery_leaf
            .as_bytes()
            .windows(32)
            .any(|w| w == hash.as_bytes()));

        // Vault leaf ends with OP_VAULT, recovery with OP_VAULT_RECOVER
        assert_eq!(*vault_leaf.as_bytes().last().unwrap(), 0xbb);
        assert_eq!(*recovery_leaf.as_bytes().last().unwrap(), 0xbc);
    }

    // ── Script number encoding ─────────────────────────────────────

    #[test]
    fn test_push_script_number_small() {
        let mut bytes = Vec::new();
        push_script_number(&mut bytes, 0);
        assert_eq!(bytes, vec![0x00]); // OP_0

        bytes.clear();
        push_script_number(&mut bytes, 1);
        assert_eq!(bytes, vec![0x51]); // OP_1

        bytes.clear();
        push_script_number(&mut bytes, 16);
        assert_eq!(bytes, vec![0x60]); // OP_16
    }

    #[test]
    fn test_push_script_number_larger() {
        let mut bytes = Vec::new();
        push_script_number(&mut bytes, 17);
        assert_eq!(bytes, vec![0x01, 17]); // push 1 byte: 17

        bytes.clear();
        push_script_number(&mut bytes, 127);
        assert_eq!(bytes, vec![0x01, 127]); // push 1 byte: 127

        bytes.clear();
        push_script_number(&mut bytes, 128);
        // 128 = 0x80, but 0x80 has the sign bit set, so need extra byte
        assert_eq!(bytes, vec![0x02, 0x80, 0x00]);
    }

    #[test]
    fn test_push_script_number_negative() {
        let mut bytes = Vec::new();
        push_script_number(&mut bytes, -1);
        assert_eq!(bytes, vec![0x4f]); // OP_1NEGATE

        bytes.clear();
        push_script_number(&mut bytes, -2);
        assert_eq!(bytes, vec![0x01, 0x82]); // push 1 byte: 2 with sign bit
    }

    // ── Error display ──────────────────────────────────────────────

    #[test]
    fn test_vault_error_display() {
        let err = VaultError::InvalidTargetIndex {
            index: 5,
            num_outputs: 2,
        };
        let msg = format!("{}", err);
        assert!(msg.contains("5"));
        assert!(msg.contains("2"));
    }
}
