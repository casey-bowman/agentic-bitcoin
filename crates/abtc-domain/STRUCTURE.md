# BTC-Domain Crate Structure

This is the INNERMOST layer of the hexagonal architecture - pure domain logic with ZERO infrastructure dependencies.

## Directory Structure

```
btc-domain/
├── Cargo.toml
├── src/
│   ├── lib.rs                          # Main entry point, re-exports
│   ├── primitives/
│   │   ├── mod.rs                      # Module declarations
│   │   ├── amount.rs                   # Amount type (satoshis), COIN, MAX_MONEY
│   │   ├── hash.rs                     # Hash256, Txid, Wtxid, BlockHash types
│   │   ├── transaction.rs              # Transaction, TxIn, TxOut, OutPoint, Witness, Sequence
│   │   └── block.rs                    # BlockHeader, Block, BlockLocator
│   ├── consensus/
│   │   ├── mod.rs                      # Module declarations
│   │   ├── params.rs                   # ConsensusParams, Network, per-network configs
│   │   ├── validation.rs               # ValidationResult, ValidationState, ValidationError
│   │   └── rules.rs                    # check_transaction, check_block, check_block_header
│   ├── script/
│   │   ├── mod.rs                      # Module declarations
│   │   ├── opcodes.rs                  # Opcodes enum (all Bitcoin opcodes)
│   │   ├── script.rs                   # Script type, ScriptBuilder, pattern matching
│   │   └── witness.rs                  # Witness type (witness stack)
│   ├── crypto/
│   │   ├── mod.rs                      # Module declarations
│   │   └── hashing.rs                  # hash256, hash160, sha256, hash_sig
│   └── chain_params/
│       └── mod.rs                      # ChainParams, genesis blocks, network config
└── tests/
    └── integration.rs                  # Integration tests
```

## Key Types and Modules

### primitives/
- **Amount**: Represents satoshi values (i64)
- **Hash256**: 256-bit hash wrapper with Display and hex encoding
- **Txid/Wtxid/BlockHash**: Newtype wrappers around Hash256
- **Transaction**: Complete transaction with inputs, outputs, version, locktime
- **TxIn/TxOut**: Transaction input and output
- **OutPoint**: Reference to a previous transaction output
- **Witness**: Segregated witness data (BIP141)
- **Block/BlockHeader/BlockLocator**: Block representation and merkle root computation

### consensus/
- **ConsensusParams**: Network-specific parameters (mainnet, testnet, regtest, signet)
- **ValidationError/ValidationResult**: Error types for validation
- **Validation rules**: check_transaction, check_block, check_block_header with pure validation logic

### script/
- **Opcodes**: Complete enumeration of all ~100+ Bitcoin opcodes
- **Script**: Script as byte vector with pattern matching (P2PKH, P2SH, P2WPKH, P2WSH, P2TR, OP_RETURN)
- **ScriptBuilder**: Builder pattern for constructing scripts
- **Witness**: Witness data stack

### crypto/
- **hash256**: Double-SHA256 hashing
- **hash160**: SHA256 then RIPEMD160
- **sha256**: Single SHA256
- **hash_sig**: Signature hashing (alias for hash256)

### chain_params/
- **ChainParams**: Network-specific configuration
- **Network**: Enum for Mainnet, Testnet, Regtest, Signet
- **Genesis blocks**: Per-network genesis block generation

## Dependencies

- `sha2`: SHA256 hashing
- `ripemd`: RIPEMD-160 hashing
- `hex`: Hex encoding/decoding

NO database, NO networking, NO async, NO external I/O

## Design Principles

1. **Pure Domain Logic**: No infrastructure dependencies
2. **Idiomatic Rust**: Derives (Debug, Clone, PartialEq, Eq, Hash), proper error handling
3. **Type Safety**: Strong typing for amounts, hashes, transactions
4. **Faithfulness**: Accurately represents Bitcoin's data model
5. **Documentation**: Extensive doc comments and tests

## Re-exports from lib.rs

The main lib.rs re-exports all public types for convenience:
- ChainParams, Network
- ConsensusParams, ValidationResult, ValidationState
- Amount, Block, BlockHash, BlockHeader, BlockLocator, Hash256, OutPoint, Sequence, Transaction, TxIn, TxOut, Txid, Witness, Wtxid
- Opcodes, Script, ScriptBuilder
