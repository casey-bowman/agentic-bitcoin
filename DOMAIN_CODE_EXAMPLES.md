# Domain Layer - Code Examples

## Core Types

### Amount (Satoshis)
```rust
use btc_domain::*;

// Create amounts
let one_btc = Amount::from_sat(COIN);  // 100_000_000 satoshis
let half_btc = Amount::from_btc(0.5)?;

// Arithmetic
let total = one_btc + half_btc;
let difference = one_btc - half_btc;
let doubled = one_btc * 2;

// Validation
assert!(one_btc.is_money_range());
assert!(!Amount::from_sat(-1).is_money_range());
```

### Hashes
```rust
// Hash256 - Base hash type
let hash = Hash256::from_hex("abc123...")?;
println!("{}", hash.to_hex_reversed());  // Display format

// Txid - Transaction hash
let txid = Txid::from_hex("...")?;

// BlockHash - Block hash
let block_hash = BlockHash::genesis_mainnet();

// Computing hashes
let data = b"some transaction";
let tx_hash = hash256(data);
```

### Transaction

```rust
// Create a transaction
let input = TxIn::final_input(
    OutPoint::new(Txid::zero(), 0),
    Script::new()
);

let output = TxOut::new(
    Amount::from_sat(100_000),
    ScriptBuilder::new()
        .push_opcode(Opcodes::OP_RETURN)
        .push_slice(b"hello")
        .build()
);

let tx = Transaction::v1(
    vec![input],
    vec![output],
    0  // locktime
);

// Transaction analysis
let txid = tx.txid();
let wtxid = tx.wtxid();
assert!(tx.is_final());
assert!(!tx.is_coinbase());
assert_eq!(tx.total_output_value().as_sat(), 100_000);
```

### Coinbase Transaction
```rust
let coinbase = Transaction::coinbase(
    1,  // height
    ScriptBuilder::new()
        .push_int(1)  // block height
        .build(),
    vec![
        TxOut::new(
            Amount::from_sat(5000000000),  // 50 BTC subsidy
            Script::new()
        )
    ]
);

assert!(coinbase.is_coinbase());
```

### Block

```rust
let header = BlockHeader::new(
    1,                           // version
    BlockHash::zero(),           // prev block hash
    Hash256::zero(),             // merkle root
    1231006505,                  // timestamp
    0x207fffff,                  // bits (difficulty)
    2083236893                   // nonce
);

let block = Block::new(header, vec![coinbase_tx]);

// Block operations
let block_hash = block.block_hash();
let merkle_root = block.compute_merkle_root();
assert!(block.verify_merkle_root());
```

## Script Handling

### Pattern Recognition
```rust
let script = /* some script */;

if script.is_p2pkh() {
    // Standard Pay-to-PubKey-Hash
} else if script.is_p2sh() {
    // Standard Pay-to-Script-Hash
} else if script.is_p2wpkh() {
    // Native SegWit v0 (pubkey hash)
} else if script.is_p2wsh() {
    // Native SegWit v0 (script hash)
} else if script.is_p2tr() {
    // Taproot
} else if script.is_op_return() {
    // OP_RETURN data output
}
```

### Building Scripts
```rust
// Simple script
let script = ScriptBuilder::new()
    .push_opcode(Opcodes::OP_DUP)
    .push_opcode(Opcodes::OP_HASH160)
    .push_slice(&hash160_value)
    .push_opcode(Opcodes::OP_EQUALVERIFY)
    .push_opcode(Opcodes::OP_CHECKSIG)
    .build();

// Script with data
let data_script = ScriptBuilder::new()
    .push_opcode(Opcodes::OP_RETURN)
    .push_slice(b"my application data")
    .build();

// Script with integers
let numeric_script = ScriptBuilder::new()
    .push_int(1)
    .push_int(2)
    .push_opcode(Opcodes::OP_ADD)
    .build();
```

### Script Iteration
```rust
use btc_domain::script::ScriptInstruction;

for instruction in script.instructions() {
    match instruction {
        ScriptInstruction::Push(data) => {
            println!("Push {} bytes", data.len());
        },
        ScriptInstruction::Op(opcode) => {
            println!("Opcode: {:?}", opcode);
        },
        ScriptInstruction::Invalid(byte) => {
            eprintln!("Invalid opcode: 0x{:02x}", byte);
        }
    }
}
```

## Consensus Parameters

### Network Configuration
```rust
// Get parameters for mainnet
let mainnet = ConsensusParams::mainnet();
assert_eq!(mainnet.subsidy_halving_interval, 210_000);
assert!(mainnet.is_bip65_enabled(388_381));

// Testnet
let testnet = ConsensusParams::testnet();
assert!(testnet.allow_min_difficulty);

// Regtest (for local testing)
let regtest = ConsensusParams::regtest();
assert!(regtest.no_retargeting);

// Signet (staging network)
let signet = ConsensusParams::signet();

// Get params for a specific network
let params = ConsensusParams::for_network(Network::Mainnet);
```

### Block Subsidy
```rust
let params = ConsensusParams::mainnet();

// Height 0-209,999: 50 BTC
assert_eq!(params.get_block_subsidy(0), 5_000_000_000);

// Height 210,000-419,999: 25 BTC (first halving)
assert_eq!(params.get_block_subsidy(210_000), 2_500_000_000);

// Height 420,000+: 12.5 BTC (second halving)
assert_eq!(params.get_block_subsidy(420_000), 1_250_000_000);

// After 64 halvings: 0 BTC
assert_eq!(params.get_block_subsidy(64 * 210_000), 0);
```

## Validation

### Transaction Validation
```rust
use btc_domain::consensus::rules::check_transaction;

match check_transaction(&tx) {
    Ok(_) => println!("Transaction is valid"),
    Err(ValidationError::TxInputsEmpty) => {
        eprintln!("Transaction has no inputs");
    },
    Err(ValidationError::TxOutputsTooLarge) => {
        eprintln!("Total outputs exceed MAX_MONEY");
    },
    Err(e) => eprintln!("Validation error: {}", e),
}
```

### Block Validation
```rust
use btc_domain::consensus::rules::check_block;

let params = ConsensusParams::mainnet();

match check_block(&block, &params) {
    Ok(_) => println!("Block is valid"),
    Err(ValidationError::BlockCoinbaseNotFirst) => {
        eprintln!("First transaction must be coinbase");
    },
    Err(ValidationError::BlockMerkleRootInvalid) => {
        eprintln!("Merkle root doesn't match transactions");
    },
    Err(e) => eprintln!("Block error: {}", e),
}
```

## Chain Parameters

### Network Setup
```rust
let chain_params = ChainParams::mainnet();

assert_eq!(chain_params.magic_bytes, [0xf9, 0xbe, 0xb4, 0xd9]);
assert_eq!(chain_params.p2p_port, 8333);
assert_eq!(chain_params.rpc_port, 8332);

println!("DNS Seeds:");
for seed in &chain_params.dns_seeds {
    println!("  {}", seed);
}

// Get testnet parameters
let testnet = ChainParams::testnet();
assert_eq!(testnet.p2p_port, 18333);
assert_eq!(testnet.rpc_port, 18332);
```

### Genesis Block
```rust
let chain_params = ChainParams::mainnet();
let genesis = chain_params.genesis_block();

println!("Genesis block hash: {}", genesis.block_hash());
println!("Timestamp: {}", genesis.header.time);
```

## Witness Data (SegWit)

```rust
let mut witness = Witness::new();
assert!(witness.is_empty());

// Add signature
witness.push(vec![
    0x30, 0x44, 0x02, 0x20,  // DER signature start
    // ... 71 bytes total ...
]);

// Add pubkey
witness.push(vec![
    0x21,  // Push 33 bytes
    // ... 33-byte compressed pubkey ...
]);

assert_eq!(witness.len(), 2);

// Add to input
let mut input = TxIn::final_input(outpoint, script_sig);
input = input.with_witness(witness);

// Transaction with witness
let tx = Transaction::v1(vec![input], outputs, 0);
assert!(tx.has_witness());

// Weight and vsize
let weight = tx.compute_weight();
let vsize = tx.compute_vsize();
```

## Complete Example: Create and Validate a Transaction

```rust
use btc_domain::*;
use btc_domain::consensus::rules::check_transaction;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create input
    let input = TxIn::final_input(
        OutPoint::new(Txid::zero(), 0),
        Script::new()
    );

    // Create outputs
    let outputs = vec![
        TxOut::new(
            Amount::from_sat(1000),
            ScriptBuilder::new()
                .push_opcode(Opcodes::OP_DUP)
                .build()
        ),
        TxOut::new(
            Amount::from_sat(500),
            ScriptBuilder::new()
                .push_opcode(Opcodes::OP_RETURN)
                .push_slice(b"test")
                .build()
        ),
    ];

    // Create transaction
    let tx = Transaction::v1(vec![input], outputs, 0);

    // Get transaction ID
    let txid = tx.txid();
    println!("TXID: {}", txid);

    // Validate
    check_transaction(&tx)?;
    println!("Transaction validated successfully");

    // Get transaction size
    println!("Size: {} bytes", tx.compute_vsize());

    Ok(())
}
```

## Memory Safety Notes

All types leverage Rust's memory safety:
- No unsafe code in domain logic
- All allocations managed by Rust
- No buffer overflows possible
- Type system prevents invalid states
