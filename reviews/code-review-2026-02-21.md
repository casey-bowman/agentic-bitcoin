# Code Review: Agentic Bitcoin

**Date:** 2026-02-21
**Reviewer:** Claude Opus 4.6
**Project:** From-scratch Rust reimplementation of Bitcoin Core using hexagonal architecture
**Size:** ~34,000 lines across 5 crates, 612 tests

## Build Status

- **Tests:** 612 tests, 0 failures across all workspace crates.
- **Clippy:** 24 warnings in `abtc-application` -- mostly redundant closures in `handlers.rs` and a duplicated `if_same_then_else` branch in `services.rs`. No errors.

---

## Architecture Assessment

The hexagonal (ports-and-adapters) architecture is well-realized:

```
domain -> ports -> adapters -> application -> infrastructure
```

Each layer depends only on layers below it. The domain crate has zero I/O dependencies. Port traits are pure interfaces with no implementations. Adapters implement those traits. The infrastructure crate serves as the composition root with dependency injection via `Arc<dyn Trait>`. This is clean and testable.

---

## Critical Issues

These are correctness bugs that would cause consensus divergence or protocol failures.

### 1. Taproot inputs get wrong signature checker

**File:** `crates/abtc-domain/src/consensus/connect.rs:236-239`

The block connection logic uses `input.witness.is_empty()` to choose between legacy and SegWit v0 signature checking. Taproot (witness v1) inputs also have non-empty witnesses but require BIP341 sighash, not BIP143. A Taproot input would silently get the wrong sighash algorithm, producing invalid verification results. The code should inspect the `script_pubkey` witness version, not just witness emptiness.

### 2. Taproot sighash hard-codes hash_type=0x00

**File:** `crates/abtc-domain/src/crypto/signing.rs:227,318`

Both key-path and script-path Taproot sighash computation hard-code `SIGHASH_DEFAULT (0x00)`. Any signature using `SIGHASH_ALL (0x01)`, `SIGHASH_NONE`, or `SIGHASH_SINGLE` would produce an incorrect hash. The hash type should be extracted from the signature and passed as a parameter.

### 3. Taproot sighash silently uses zero amounts for missing data

**File:** `crates/abtc-domain/src/crypto/signing.rs:161-172`

When `spent_outputs` is `None`, the code substitutes `0i64` for all amounts instead of returning an error. BIP341 requires all spent output amounts to be committed. This silently produces wrong sighashes.

### 4. PoW comparison truncates to 128 bits

**File:** `crates/abtc-domain/src/consensus/rules.rs:432-439`

`hash_to_u128` uses only the first 16 bytes of the 32-byte block hash. Bitcoin requires a full 256-bit comparison. For low-difficulty targets (testnet, regtest, early mainnet), this truncation could accept blocks that don't actually meet the target.

### 5. No PoW validation in header acceptance

**File:** `crates/abtc-application/src/block_index.rs:112-174`

`add_header` computes cumulative work but never verifies that the block hash actually meets the target encoded in `bits`. Headers with artificially low difficulty would be accepted as long as they have a valid parent link. An attacker could submit easy-difficulty headers to build a fake longest chain.

### 6. P2P checksum uses SipHash instead of SHA-256

**File:** `crates/abtc-adapters/src/network/mod.rs:87-102`

The network adapter uses `DefaultHasher` (SipHash) for message checksums. The Bitcoin P2P protocol requires double-SHA256. This makes the node unable to communicate with any real Bitcoin peer.

### 7. Mempool fee always set to zero

**File:** `crates/abtc-adapters/src/mempool/mod.rs:431`

`add_transaction` hardcodes `fee = Amount::from_sat(0)`, breaking RBF replacement checks, fee estimation, and mining transaction selection. All fee-dependent features are non-functional.

### 8. InMemoryBlockStore::store_block never updates best block hash

**File:** `crates/abtc-adapters/src/storage/mod.rs:64-77`

After storing a block, the best block hash remains at the genesis/zero hash. `get_best_block_hash()` always returns the wrong value.

### 9. Coinbase output script is empty

**File:** `crates/abtc-adapters/src/mining/mod.rs:152-156`

The miner creates coinbase transactions with `Script::new()` as the output script, making the block reward unspendable. The `coinbase_script` parameter is only used for the input (arbitrary data field), not the output.

### 10. BIP152 compact block key derivation hashes the wrong data

**File:** `crates/abtc-application/src/compact_blocks.rs:108-112`

The SipHash key is derived from `SHA256(block_hash || nonce)` but BIP152 specifies `SHA256(header || nonce)` -- the full 80-byte serialized header, not the 32-byte hash.

---

## High-Severity Issues

### 11. unwrap() calls in reorg path

**File:** `crates/abtc-application/src/chain_state.rs:266,268,305,316`

The `activate_best_chain` method uses `.unwrap()` for block index lookups during chain reorganization. A panic here would leave the chain state partially disconnected. The `ChainStateError::MissingBlockData` variant exists but isn't used for these lookups.

### 12. MAX_BLOCK_SIGOPS_COST is 20,000,000 instead of 80,000

**File:** `crates/abtc-domain/src/consensus/rules.rs:20`

Off by 250x. The constant is currently unused (no sigops counting exists), but when sigops enforcement is added, this value would effectively disable the limit.

### 13. RocksDB store unconditionally overwrites best block on every store

**File:** `crates/abtc-adapters/src/storage/rocksdb_store.rs:120`

Storing an orphan or alternate-chain block incorrectly updates the best block pointer. Only blocks that extend the best chain should update this.

### 14. ScriptFlags::standard() omits VERIFY_TAPROOT

**File:** `crates/abtc-domain/src/script/interpreter.rs:73-86`

The default standard flag set doesn't include Taproot verification, meaning Taproot outputs would not be validated by default.

### 15. Tapscript incorrectly subject to legacy limits

**File:** `crates/abtc-domain/src/script/interpreter.rs:388,391`

BIP342 removes the 10,000-byte script size limit and 201-opcode limit for tapscripts. The current code applies both limits to tapscript execution.

### 16. Hardcoded ConsensusParams::mainnet() in services

**File:** `crates/abtc-application/src/services.rs:66`

`BlockchainService` always applies mainnet consensus rules regardless of the configured network. Testnet/regtest/signet would fail validation.

### 17. Multiple independent RwLock fields create deadlock risk

**File:** `crates/abtc-adapters/src/mempool/mod.rs`

`InMemoryMempool` has 5 separate `Arc<RwLock<_>>` fields acquired in different orders across methods. `remove_entry` acquires all 5 write locks sequentially. Any concurrent access with different lock ordering will deadlock.

---

## Medium-Severity Issues

### 18. Wallet double-counts immature coinbase in confirmed balance

**File:** `crates/abtc-adapters/src/wallet/mod.rs:127-150`

Coinbase UTXOs with 1-99 confirmations are counted in both `confirmed` and `immature` totals.

### 19. ECDSA verification falls back to compact signatures

**File:** `crates/abtc-domain/src/crypto/signing.rs:688-696`

After failing DER parse, the code tries `from_compact()`. BIP66/STRICTENC requires DER. Accepting compact signatures is non-standard.

### 20. P2WSH addresses (32-byte v0 program) fail to decode

**File:** `crates/abtc-domain/src/wallet/address.rs:365-370`

Bech32 decode for witness v0 only handles 20-byte programs (P2WPKH), rejecting valid P2WSH addresses.

### 21. Network messages send empty payloads for tx/block/addr

**File:** `crates/abtc-adapters/src/network/mod.rs:616-624`

`encode_network_message` returns empty byte vectors for `Tx`, `Block`, and `Addr` messages -- protocol violations that would cause peer disconnection.

### 22. No locktime/sequence validation in mempool

**File:** `crates/abtc-application/src/mempool_acceptance.rs`

BIP65/BIP68/BIP112 time-lock checks are not performed during mempool acceptance.

### 23. No chained unconfirmed transaction support

**File:** `crates/abtc-application/src/mempool_acceptance.rs`

UTXO lookups only query chain state, not mempool. A transaction spending an unconfirmed output will be rejected.

### 24. Duplicated utility functions

`is_p2sh_witness`, `build_coinbase_script`, and `get_block_subsidy` are duplicated between `services.rs`/`mempool_acceptance.rs` and `miner.rs`/`block_template.rs`.

### 25. Box<dyn Error> everywhere in port traits

All port trait methods return `Box<dyn Error + Send + Sync>` instead of typed error enums. `thiserror` is a dependency but unused. Callers cannot match on error variants without downcasting.

### 26. HTTP response body corruption

**File:** `crates/abtc-adapters/src/rpc/mod.rs:100-117`

The format string in `build_http_response` injects whitespace before the JSON body due to Rust string continuation indentation.

### 27. RocksDB UTXO deserialization can panic on corrupt data

**File:** `crates/abtc-adapters/src/storage/rocksdb_store.rs:291`

`bytes[17..17 + script_len]` will panic if `script_len` exceeds remaining bytes. No bounds check before indexing.

---

## Low-Severity Issues

- `WalletPort::send_transaction` returns `String` instead of `Txid` (`crates/abtc-ports/src/wallet/mod.rs`)
- `MempoolInfo::min_relay_fee` uses `f64` for financial values (`crates/abtc-ports/src/mempool/mod.rs:46`)
- `RPC_IN_WARMUP` constant has wrong value `-32603` (`crates/abtc-ports/src/rpc/mod.rs:242`)
- `BlockIndexEntry` defined in ports but never used by any trait
- Handshake doesn't parse peer's version message -- `PeerInfo` contains our own values for every peer
- `send_transaction` in wallet never broadcasts to network or tracks change outputs
- `recently_seen_txids` cleared entirely at 50k instead of LRU eviction
- Orphan eviction uses oldest-first instead of random (attackable)
- `getmininginfo` RPC returns hardcoded zeros
- O(n^2) duplicate input check in `rules.rs` (should use `HashSet`)
- `secp256k1` context created per signature verification instead of cached
- `net_processing.rs` at ~2500 lines should be split into sub-modules
- No `[workspace.dependencies]` -- versions repeated across crate Cargo.tomls
- `async-trait` could be replaced with native async traits (Rust 1.75+)
- Background `tokio::spawn` tasks store no `JoinHandle` -- no graceful shutdown
- `CliArgs` uses `String` for enum-like fields instead of `clap::ValueEnum`
- Boolean CLI flags use `default_value = "false"` instead of idiomatic flag syntax

---

## Summary

| Severity | Count | Key Areas |
|----------|-------|-----------|
| Critical | 10 | Taproot sighash, PoW validation, P2P checksum, mempool fees |
| High | 7 | Reorg panics, sigops limit, deadlock risk, network params |
| Medium | 10 | Wallet balance, address decoding, missing validation, code duplication |
| Low | 17 | API design, performance, CLI ergonomics, maintainability |

The architecture is well-designed with clean layer separation, strong test coverage (612 tests), and faithful adherence to Bitcoin Core's structural patterns. The critical issues cluster in three areas: **Taproot support** (sighash computation, script flag inclusion, signature checker selection), **proof-of-work validation** (128-bit truncation, missing PoW checks in header acceptance), and **adapter correctness** (P2P checksums, mempool fees, block storage). The domain-layer consensus and script code is the strongest part of the codebase, while the adapter implementations have the most gaps -- consistent with the project's bottom-up development approach.
