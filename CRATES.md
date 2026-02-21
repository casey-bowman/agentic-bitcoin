# Crate Guide

agentic-bitcoin is published as a family of crates under the `abtc-` namespace, with the top-level binary retaining the full `agentic-bitcoin` name. Each crate corresponds to a layer in the hexagonal architecture, and you can depend on exactly the layers you need.

## The Crates

| Crate | crates.io | What it provides |
|-------|-----------|-----------------|
| `abtc-domain` | [crates.io](https://crates.io/crates/abtc-domain) | Pure Bitcoin domain logic — types, consensus rules, script interpreter, crypto, wallet primitives. No I/O, no async, no infrastructure dependencies. |
| `abtc-ports` | [crates.io](https://crates.io/crates/abtc-ports) | Trait definitions (interfaces) for storage, mempool, wallet, mining, network, and RPC. Depend on this if you're writing your own adapter. |
| `abtc-adapters` | [crates.io](https://crates.io/crates/abtc-adapters) | In-memory implementations of all port traits. Good for testing, prototyping, and lightweight applications. |
| `abtc-application` | [crates.io](https://crates.io/crates/abtc-application) | Services and use cases — chain state, P2P processing, block templates, mining, fee estimation, mempool acceptance, compact blocks, and more. |
| `abtc-infrastructure` | [crates.io](https://crates.io/crates/abtc-infrastructure) | Full node composition. Wires all layers together into a runnable node. |
| `agentic-bitcoin` | [crates.io](https://crates.io/crates/agentic-bitcoin) | The binary. Runs the node. |

## Which Crate Do I Need?

### "I want Bitcoin primitives and crypto for my own project"

Depend on **`abtc-domain`** only. This is the most commonly useful crate. It gives you:

- Transaction, block, and script types with serialization/deserialization
- SHA-256, RIPEMD-160, HASH-160, double-SHA-256
- secp256k1 operations (key generation, ECDSA signing, Schnorr/BIP340 signing)
- Taproot (BIP341/BIP342) — TapTree construction, control blocks, script-path and key-path sighash
- HD key derivation (BIP32/BIP44) with xprv/xpub serialization
- PSBT (BIP174) — create, sign, combine, finalize, extract
- Address encoding/decoding (P2PKH, P2SH, P2WPKH, P2TR, bech32, bech32m)
- Coin selection algorithms
- Transaction builder with automatic signing for all output types
- Consensus validation rules
- Full script interpreter with all opcodes

```toml
[dependencies]
abtc-domain = "0.1"
```

```rust
use abtc_domain::wallet::keys::SecretKey;
use abtc_domain::wallet::address::Address;
use abtc_domain::wallet::tx_builder::TransactionBuilder;
use abtc_domain::crypto::schnorr;
use abtc_domain::crypto::taproot::TapTree;
```

This crate has zero infrastructure dependencies. It compiles fast, has no async runtime requirement, and is safe to use in embedded or WASM contexts (with appropriate feature gating in the future).

### "I want to write a custom storage backend or network layer"

Depend on **`abtc-ports`** alongside `abtc-domain`. The ports crate defines the trait interfaces that adapters implement:

```toml
[dependencies]
abtc-domain = "0.1"
abtc-ports = "0.1"
```

Implement the traits for your backend — for example, a PostgreSQL-backed UTXO store, a RocksDB block store, or a custom P2P transport — and plug it into the application layer.

### "I want to test against Bitcoin validation logic"

Depend on **`abtc-domain`** and **`abtc-adapters`**. The adapters give you in-memory implementations of all storage and mempool traits, so you can construct test scenarios without any disk I/O:

```toml
[dependencies]
abtc-domain = "0.1"
abtc-adapters = "0.1"
```

This combination is ideal for building test harnesses, fuzz targets, or simulation environments.

### "I want chain state management and P2P logic without running a full node"

Depend on **`abtc-application`**, which pulls in domain, ports, and adapters transitively:

```toml
[dependencies]
abtc-application = "0.1"
```

This gives you chain state management (connect/disconnect blocks, UTXO tracking, reorg handling), mempool acceptance with policy checks, fee estimation, compact block reconstruction, peer scoring, and the full RPC handler framework. You supply the I/O layer.

### "I want to run a node"

Use the **`agentic-bitcoin`** binary or depend on **`abtc-infrastructure`**:

```toml
[dependencies]
abtc-infrastructure = "0.1"
```

This wires everything together — domain logic, in-memory adapters, application services — into a composable `Node` struct.

## Dependency Graph

```
agentic-bitcoin (binary)
  └── abtc-infrastructure
        ├── abtc-application
        │     ├── abtc-adapters
        │     │     ├── abtc-ports
        │     │     │     └── abtc-domain
        │     │     └── abtc-domain
        │     ├── abtc-ports
        │     └── abtc-domain
        └── abtc-domain
```

Each layer only depends on layers below it. `abtc-domain` is the leaf — it depends on nothing else in the workspace (only `sha2`, `ripemd`, and `hex` for core cryptography).

## Versioning

All crates in the workspace share the same version number and are released together. A version bump in any crate bumps all of them to keep the dependency graph consistent.

## Feature Flags (Planned)

Future releases may include feature flags on `abtc-domain` for:

- `std` (default) — standard library support
- `no_std` — embedded/WASM compatibility
- `serde` — serde Serialize/Deserialize on all domain types
