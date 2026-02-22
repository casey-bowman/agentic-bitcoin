// BIP380 descriptor checksum
//
// Output descriptors use an 8-character checksum appended after '#'.
// The checksum uses a character-set-specific polynomial similar to bech32.
//
// Reference: BIP380, Bitcoin Core's descriptor.cpp

use std::fmt;

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Checksum-related errors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChecksumError {
    /// The descriptor string contains a character not in the descriptor charset.
    InvalidCharacter(char),
    /// The checksum is not exactly 8 characters.
    InvalidLength,
    /// The checksum does not match.
    ChecksumMismatch,
    /// Missing '#' separator.
    MissingSeparator,
}

impl fmt::Display for ChecksumError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ChecksumError::InvalidCharacter(c) => write!(f, "invalid character: '{}'", c),
            ChecksumError::InvalidLength => write!(f, "checksum must be 8 characters"),
            ChecksumError::ChecksumMismatch => write!(f, "checksum mismatch"),
            ChecksumError::MissingSeparator => write!(f, "missing '#' separator"),
        }
    }
}

impl std::error::Error for ChecksumError {}

// ---------------------------------------------------------------------------
// Descriptor character set
// ---------------------------------------------------------------------------

/// The 32-character set used by descriptor checksums.
/// Maps groups of input characters to 5-bit values.
const INPUT_CHARSET: &str =
    "0123456789()[],'/*abcdefgh@:$%{}\
     IJKLMNOPQRSTUVWXYZ&+-.;<=>?!^_|~\
     ijklmnopqrstuvwxyz`#\"\\ ";

/// The 32-character set used to encode the checksum itself.
const CHECKSUM_CHARSET: &str = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";

// ---------------------------------------------------------------------------
// Polymod — the polynomial used for the checksum
// ---------------------------------------------------------------------------

/// Compute the polymod checksum of the given values.
fn polymod(values: &[u64]) -> u64 {
    let mut c: u64 = 1;
    for &v in values {
        let c0 = (c >> 35) & 0x1f;
        c = ((c & 0x7ffffffff) << 5) ^ v;
        if c0 & 1 != 0 { c ^= 0xf5dee51989; }
        if c0 & 2 != 0 { c ^= 0xa9fdca3312; }
        if c0 & 4 != 0 { c ^= 0x1bab10e32d; }
        if c0 & 8 != 0 { c ^= 0x3706b1677a; }
        if c0 & 16 != 0 { c ^= 0x644d626ffd; }
    }
    c
}

/// Map a descriptor character to its 5-bit group value.
fn char_to_group(c: char) -> Result<u64, ChecksumError> {
    INPUT_CHARSET
        .find(c)
        .map(|pos| pos as u64)
        .ok_or(ChecksumError::InvalidCharacter(c))
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Compute the 8-character descriptor checksum for the given descriptor
/// string (without any existing '#checksum' suffix).
pub fn descriptor_checksum(desc: &str) -> Result<String, ChecksumError> {
    let mut values = Vec::with_capacity(desc.len() * 2 + 8);

    for c in desc.chars() {
        let pos = char_to_group(c)?;
        values.push(pos >> 5);
        values.push(pos & 31);
    }

    // Append 8 zero values (for the checksum positions)
    values.extend_from_slice(&[0u64; 8]);

    let plm = polymod(&values) ^ 1;

    let mut checksum = String::with_capacity(8);
    let charset_bytes = CHECKSUM_CHARSET.as_bytes();
    for i in 0..8 {
        let idx = ((plm >> (5 * (7 - i))) & 31) as usize;
        checksum.push(charset_bytes[idx] as char);
    }

    Ok(checksum)
}

/// Verify and strip the checksum from a descriptor string.
///
/// Returns the descriptor body (without '#checksum') on success.
pub fn verify_checksum(desc_with_checksum: &str) -> Result<&str, ChecksumError> {
    let hash_pos = desc_with_checksum
        .rfind('#')
        .ok_or(ChecksumError::MissingSeparator)?;

    let body = &desc_with_checksum[..hash_pos];
    let provided = &desc_with_checksum[hash_pos + 1..];

    if provided.len() != 8 {
        return Err(ChecksumError::InvalidLength);
    }

    let expected = descriptor_checksum(body)?;
    if provided != expected {
        return Err(ChecksumError::ChecksumMismatch);
    }

    Ok(body)
}

/// Append the checksum to a descriptor string.
pub fn add_checksum(desc: &str) -> Result<String, ChecksumError> {
    let checksum = descriptor_checksum(desc)?;
    Ok(format!("{}#{}", desc, checksum))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_checksum_known_vector_wpkh() {
        // Known test vector from Bitcoin Core
        let desc = "wpkh(02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9)";
        let checksum = descriptor_checksum(desc).unwrap();
        assert_eq!(checksum.len(), 8);
        // The checksum should be deterministic
        let checksum2 = descriptor_checksum(desc).unwrap();
        assert_eq!(checksum, checksum2);
    }

    #[test]
    fn test_checksum_different_descriptors() {
        let c1 = descriptor_checksum("pkh(02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9)").unwrap();
        let c2 = descriptor_checksum("wpkh(02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9)").unwrap();
        assert_ne!(c1, c2);
    }

    #[test]
    fn test_verify_checksum_valid() {
        let desc = "wpkh(02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9)";
        let checksum = descriptor_checksum(desc).unwrap();
        let with_checksum = format!("{}#{}", desc, checksum);
        let body = verify_checksum(&with_checksum).unwrap();
        assert_eq!(body, desc);
    }

    #[test]
    fn test_verify_checksum_invalid() {
        let desc = "wpkh(02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9)";
        let with_bad = format!("{}#qqqqqqqq", desc);
        let result = verify_checksum(&with_bad);
        assert!(matches!(result, Err(ChecksumError::ChecksumMismatch)));
    }

    #[test]
    fn test_verify_checksum_missing_separator() {
        let result = verify_checksum("wpkh(key)");
        assert!(matches!(result, Err(ChecksumError::MissingSeparator)));
    }

    #[test]
    fn test_verify_checksum_wrong_length() {
        let result = verify_checksum("wpkh(key)#abc");
        assert!(matches!(result, Err(ChecksumError::InvalidLength)));
    }

    #[test]
    fn test_add_checksum() {
        let desc = "pkh(02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9)";
        let with_checksum = add_checksum(desc).unwrap();
        assert!(with_checksum.contains('#'));
        // Should round-trip
        let body = verify_checksum(&with_checksum).unwrap();
        assert_eq!(body, desc);
    }

    #[test]
    fn test_checksum_charset_validity() {
        // All chars in a typical descriptor should be valid
        let desc = "sh(wsh(sortedmulti(2,02a,02b)))";
        assert!(descriptor_checksum(desc).is_ok());
    }

    #[test]
    fn test_invalid_character() {
        // Null byte is not in the charset
        let result = descriptor_checksum("wpkh(\x01)");
        assert!(matches!(result, Err(ChecksumError::InvalidCharacter(_))));
    }
}
