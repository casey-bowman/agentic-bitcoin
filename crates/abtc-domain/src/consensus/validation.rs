//! Transaction and block validation types
//!
//! Defines validation result types and validation state enums.

use std::fmt;

/// Result of validation - Ok or error with reason code
pub type ValidationResult<T> = Result<T, ValidationError>;

/// Validation states
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ValidationState {
    /// Transaction or block is valid
    Valid,
    /// Transaction or block is invalid (consensus rule violation)
    Invalid,
    /// Validation error (not consensus rule)
    Error,
}

/// Validation error codes
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ValidationError {
    // Transaction errors
    TxEmpty,
    TxInputsEmpty,
    TxOutputsEmpty,
    TxOutputsNegative,
    TxOutputsTooLarge,
    TxInputsDuplicate,
    TxCoinbaseScriptSizeTooSmall,
    TxCoinbaseScriptSizeTooLarge,
    TxSizeTooLarge,

    // Block errors
    BlockHeaderInvalid,
    BlockProofOfWorkInvalid,
    BlockMerkleRootInvalid,
    BlockSizeTooLarge,
    BlockWeightTooLarge,
    BlockNoTransactions,
    BlockCoinbaseNotFirst,
    BlockCoinbaseMultiple,
    BlockSigopsTooCostly,

    // Locktime/sequence errors
    LockTimeInvalid,
    SequenceInvalid,

    // Script errors
    ScriptInvalid,
    PushDataSizeInvalid,

    // Witness errors
    WitnessInvalid,
    WitnessMissingSignature,

    // Generic errors
    Unknown,
}

impl fmt::Display for ValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ValidationError::TxEmpty => write!(f, "Transaction is empty"),
            ValidationError::TxInputsEmpty => write!(f, "Transaction has no inputs"),
            ValidationError::TxOutputsEmpty => write!(f, "Transaction has no outputs"),
            ValidationError::TxOutputsNegative => write!(f, "Transaction has negative outputs"),
            ValidationError::TxOutputsTooLarge => write!(f, "Transaction output sum too large"),
            ValidationError::TxInputsDuplicate => write!(f, "Transaction has duplicate inputs"),
            ValidationError::TxCoinbaseScriptSizeTooSmall => {
                write!(f, "Coinbase script too small")
            }
            ValidationError::TxCoinbaseScriptSizeTooLarge => {
                write!(f, "Coinbase script too large")
            }
            ValidationError::TxSizeTooLarge => write!(f, "Transaction size exceeds maximum"),
            ValidationError::BlockHeaderInvalid => write!(f, "Block header is invalid"),
            ValidationError::BlockProofOfWorkInvalid => write!(f, "Block proof of work is invalid"),
            ValidationError::BlockMerkleRootInvalid => write!(f, "Block merkle root is invalid"),
            ValidationError::BlockSizeTooLarge => write!(f, "Block size exceeds maximum"),
            ValidationError::BlockWeightTooLarge => write!(f, "Block weight exceeds maximum"),
            ValidationError::BlockNoTransactions => write!(f, "Block has no transactions"),
            ValidationError::BlockCoinbaseNotFirst => write!(f, "Block first transaction is not coinbase"),
            ValidationError::BlockCoinbaseMultiple => write!(f, "Block has multiple coinbase transactions"),
            ValidationError::BlockSigopsTooCostly => write!(f, "Block sigops exceed limit"),
            ValidationError::LockTimeInvalid => write!(f, "Locktime is invalid"),
            ValidationError::SequenceInvalid => write!(f, "Sequence is invalid"),
            ValidationError::ScriptInvalid => write!(f, "Script is invalid"),
            ValidationError::PushDataSizeInvalid => write!(f, "Push data size is invalid"),
            ValidationError::WitnessInvalid => write!(f, "Witness is invalid"),
            ValidationError::WitnessMissingSignature => write!(f, "Witness missing signature"),
            ValidationError::Unknown => write!(f, "Unknown validation error"),
        }
    }
}

impl std::error::Error for ValidationError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validation_error_display() {
        let err = ValidationError::TxInputsEmpty;
        assert_eq!(err.to_string(), "Transaction has no inputs");
    }

    #[test]
    fn test_all_tx_error_variants_display() {
        let errors = vec![
            (ValidationError::TxEmpty, "empty"),
            (ValidationError::TxInputsEmpty, "no inputs"),
            (ValidationError::TxOutputsEmpty, "no outputs"),
            (ValidationError::TxOutputsNegative, "negative"),
            (ValidationError::TxOutputsTooLarge, "too large"),
            (ValidationError::TxInputsDuplicate, "duplicate"),
            (ValidationError::TxCoinbaseScriptSizeTooSmall, "too small"),
            (ValidationError::TxCoinbaseScriptSizeTooLarge, "too large"),
            (ValidationError::TxSizeTooLarge, "exceeds"),
        ];
        for (err, expected_substr) in errors {
            let msg = err.to_string();
            assert!(
                msg.to_lowercase().contains(expected_substr),
                "{:?} display '{}' should contain '{}'",
                err,
                msg,
                expected_substr
            );
        }
    }

    #[test]
    fn test_all_block_error_variants_display() {
        let errors = vec![
            ValidationError::BlockHeaderInvalid,
            ValidationError::BlockProofOfWorkInvalid,
            ValidationError::BlockMerkleRootInvalid,
            ValidationError::BlockSizeTooLarge,
            ValidationError::BlockWeightTooLarge,
            ValidationError::BlockNoTransactions,
            ValidationError::BlockCoinbaseNotFirst,
            ValidationError::BlockCoinbaseMultiple,
            ValidationError::BlockSigopsTooCostly,
        ];
        for err in errors {
            let msg = err.to_string();
            assert!(!msg.is_empty(), "{:?} should have non-empty display", err);
        }
    }

    #[test]
    fn test_validation_error_is_std_error() {
        let err: Box<dyn std::error::Error> = Box::new(ValidationError::Unknown);
        assert!(err.to_string().contains("Unknown"));
    }

    #[test]
    fn test_validation_state_equality() {
        assert_eq!(ValidationState::Valid, ValidationState::Valid);
        assert_ne!(ValidationState::Valid, ValidationState::Invalid);
        assert_ne!(ValidationState::Invalid, ValidationState::Error);
    }

    #[test]
    fn test_validation_error_clone_and_copy() {
        let err = ValidationError::ScriptInvalid;
        let cloned = err.clone();
        let copied = err;
        assert_eq!(err, cloned);
        assert_eq!(err, copied);
    }

    #[test]
    fn test_validation_error_hash() {
        use std::collections::HashSet;
        let mut set = HashSet::new();
        set.insert(ValidationError::TxEmpty);
        set.insert(ValidationError::TxEmpty); // duplicate
        set.insert(ValidationError::ScriptInvalid);
        assert_eq!(set.len(), 2);
    }
}
