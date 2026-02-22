//! Witness data for segregated witness transactions
//!
//! Represents the witness stack for a transaction input (BIP141).

use std::fmt;

/// Witness data - stack of byte vectors for signature verification
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Witness {
    stack: Vec<Vec<u8>>,
}

impl Witness {
    /// Create an empty witness
    pub fn new() -> Self {
        Witness { stack: Vec::new() }
    }

    /// Create witness from stack
    pub fn from_stack(stack: Vec<Vec<u8>>) -> Self {
        Witness { stack }
    }

    /// Add an item to the witness stack
    pub fn push(&mut self, item: Vec<u8>) {
        self.stack.push(item);
    }

    /// Get witness stack as slice
    pub fn stack(&self) -> &[Vec<u8>] {
        &self.stack
    }

    /// Check if witness is empty
    pub fn is_empty(&self) -> bool {
        self.stack.is_empty()
    }

    /// Get number of witness items
    pub fn len(&self) -> usize {
        self.stack.len()
    }

    /// Clear the witness
    pub fn clear(&mut self) {
        self.stack.clear();
    }

    /// Get witness item by index
    pub fn get(&self, index: usize) -> Option<&[u8]> {
        self.stack.get(index).map(|v| v.as_slice())
    }

    /// Iterate over witness items
    pub fn iter(&self) -> impl Iterator<Item = &[u8]> {
        self.stack.iter().map(|v| v.as_slice())
    }
}

impl Default for Witness {
    fn default() -> Self {
        Witness::new()
    }
}

impl fmt::Display for Witness {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Witness[")?;
        for (i, item) in self.stack.iter().enumerate() {
            if i > 0 {
                write!(f, ", ")?;
            }
            write!(f, "{}", hex::encode(item))?;
        }
        write!(f, "]")
    }
}

impl From<Vec<Vec<u8>>> for Witness {
    fn from(stack: Vec<Vec<u8>>) -> Self {
        Witness::from_stack(stack)
    }
}

impl IntoIterator for Witness {
    type Item = Vec<u8>;
    type IntoIter = std::vec::IntoIter<Vec<u8>>;

    fn into_iter(self) -> Self::IntoIter {
        self.stack.into_iter()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_witness_creation() {
        let witness = Witness::new();
        assert!(witness.is_empty());
        assert_eq!(witness.len(), 0);
    }

    #[test]
    fn test_witness_push() {
        let mut witness = Witness::new();
        witness.push(vec![1, 2, 3]);
        assert_eq!(witness.len(), 1);
        assert!(!witness.is_empty());
        assert_eq!(witness.get(0), Some(&[1, 2, 3][..]));
    }

    #[test]
    fn test_witness_from_stack() {
        let stack = vec![vec![1, 2, 3], vec![4, 5, 6]];
        let witness = Witness::from_stack(stack);
        assert_eq!(witness.len(), 2);
    }
}
