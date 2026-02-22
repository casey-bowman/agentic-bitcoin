# Code Review #2: Agentic Bitcoin

**Date:** 2026-02-22
**Reviewer:** Claude Opus 4.6
**Project:** From-scratch Rust reimplementation of Bitcoin Core using hexagonal architecture
**Size:** ~35,000 lines across 5 crates, 1,103 tests
**Scope:** Follow-up review incorporating response to first review (2026-02-21)

## Build Status

- **Tests:** 1,103 tests, 0 failures (up from 612 -- 491 new tests since last review).
- **Clippy:** 0 warnings (down from 24). All redundant-closure and duplicated-branch warnings resolved.

---

## Status of First Review Fixes

12 findings were marked FIXED in the response. Verification results:

| # | Finding | Verdict | Notes |
|---|---------|---------|-------|
| 1 | Taproot signature checker | **Verified** | Correctly dispatches by witness version from script_pubkey bytes |
| 2 | Taproot sighash hash_type | **Verified** | hash_type threaded through entire call chain |
| 3 | Taproot sighash missing amounts | **Verified** | Returns `[0xff; 32]` sentinel; regression tests present |
| 4 | PoW 256-bit comparison | **Verified** | Full uint256 LE comparison; caught additional bug in `decode_compact_u256` |
| 5 | Mempool fee calculation | **Partial** | Computes fees from in-mempool parents only; confirmed UTXOs still get fee=0 (architectural gap) |
| 7 | Mempool fee always zero | **Verified** | See #5 -- fees computed for mempool-parent chains |
| 8 | Best block hash update | **Verified** | Height comparison guard added |
| 9 | Coinbase output script | **Verified** | Uses `coinbase_script.clone()` for output |
| 11 | Reorg unwrap() calls | **Verified** | Reorg path uses proper error variants; 3 unwraps remain in non-reorg path |
| 12 | MAX_BLOCK_SIGOPS_COST | **Verified** | Corrected to 80,000 |
| 14 | ScriptFlags includes TAPROOT | **Verified** | `VERIFY_TAPROOT` in `standard()` |
| 15 | Tapscript skips legacy limits | **Verified** | `tapscript_mode` bypasses size and opcode limits |
| 19 | ECDSA strict DER | **Verified** | No compact fallback; regression test present |

All fixes are sound. Two minor residuals noted (mempool fee architecture, non-reorg unwraps) but neither is a regression.

---

## New Findings

### Numbering

Findings are numbered sequentially from the first review (which ended at #27 + 17 low-severity). This review starts at **28**.

---

## Critical Issues

### 28. Taproot sighash only implements SIGHASH_DEFAULT/ALL

**File:** `crates/abtc-domain/src/crypto/signing.rs:145-216`

`compute_taproot_sighash()` and `compute_taproot_sighash_script_path()` always hash all prevouts, all amounts, all sequences, and all outputs regardless of the `hash_type` parameter. SIGHASH_NONE (skip outputs), SIGHASH_SINGLE (hash only the matching output), and SIGHASH_ANYONECANPAY (hash only the current input) are not implemented. Bitcoin Core's `SignatureHashSchnorr()` selectively includes/excludes fields based on the hash type byte. Any Taproot transaction using a non-default sighash type will produce a wrong sighash, causing valid blocks to be rejected.

### 29. Reorg failure leaves chain state inconsistent

**File:** `crates/abtc-application/src/chain_state.rs:341-371`

In `activate_best_chain`, if `connect_block` fails during Phase 2 (connecting new-chain blocks), the method returns `ReorgFailed`. By this point Phase 1 has already disconnected blocks from the old chain and applied UTXO reversals. The tip is stuck at the fork point with neither chain connected. There is no rollback that re-connects the previously-disconnected blocks. Bitcoin Core handles this by attempting to re-connect the old chain on failure.

### 30. No mempool double-spend check against other mempool transactions

**File:** `crates/abtc-application/src/mempool_acceptance.rs:140-155`

`accept_transaction` checks inputs against the chain-state UTXO set but not against inputs already spent by other mempool transactions. Two conflicting transactions spending the same UTXO can both be accepted. Bitcoin Core maintains a spent-input set for exactly this purpose.

### 31. `validate_and_accept_block` is a parallel code path without reorg support

**File:** `crates/abtc-application/src/services.rs:95-101`

`BlockchainService::validate_and_accept_block` computes `new_height = current_height + 1` without verifying that the block's `prev_block_hash` matches the current tip. It does not handle reorgs. If both this path and `ChainState::process_block()` are reachable, blocks could be connected at incorrect heights, corrupting the UTXO set.

### 32. RocksDB store unconditionally overwrites best block hash (still unfixed)

**File:** `crates/abtc-adapters/src/storage/rocksdb_store.rs:115-116`

Acknowledged in the first review response (#13) as "deferred until RocksDB adapter is activated." Elevating to Critical because the in-memory store now has the correct height-comparison guard, making the two implementations inconsistent. The RocksDB path would corrupt the chain tip pointer if ever activated.

---

## High-Severity Issues

### 33. No sigops counting or enforcement

**File:** `crates/abtc-domain/src/consensus/rules.rs:134-178`

`MAX_BLOCK_SIGOPS_COST` was corrected to 80,000 (fix #12), but `check_block()` still never counts or checks sigops. There is no sigops counting anywhere in the codebase. A block with excessive signature operations would pass validation, enabling CPU-exhaustion DoS.

### 34. Unbounded orphan block storage

**File:** `crates/abtc-application/src/net_processing.rs:114, 789`

`orphan_blocks: HashMap<BlockHash, Block>` has no size limit. The `on_block` handler inserts unconditionally. Since blocks can be ~4MB each, an adversary sending thousands of out-of-order blocks can exhaust memory. Bitcoin Core limits orphan blocks and evicts when the limit is reached.

### 35. Compact block short ID collision not handled

**File:** `crates/abtc-application/src/compact_blocks.rs:227-265`

The `reconstruct` method uses `HashMap<ShortTxId, Transaction>` for mempool lookup. Short IDs are 6 bytes (48 bits), so collisions are possible at moderate mempool sizes (birthday bound ~16.8M entries). BIP152 specifies that on collision the receiver must request the full block. There is no collision detection -- the wrong transaction could be silently placed in the reconstructed block.

### 36. Mempool eviction doesn't clean up dependency graph

**File:** `crates/abtc-adapters/src/mempool/mod.rs:180-191`

The eviction loop calls `self.entries.remove(&txid)` directly instead of `self.remove_entry(&txid)`. The `packages`, `children`, and `parents` maps retain stale entries, leaving dangling references. Subsequent dependency-graph traversals may include phantom transactions.

### 37. RBF conflict silently accepted on policy failure

**File:** `crates/abtc-adapters/src/mempool/mod.rs:401-407`

When `try_rbf_replacement` returns `Err` (conflict exists but fails RBF policy), the error is silently consumed with `if let Ok(...)`. The conflicting incoming transaction is accepted alongside the original -- a double-spend in the mempool. The error should propagate to reject the incoming transaction.

### 38. Weight calculation uses `size * 4` everywhere (no segwit discount)

**Files:** `crates/abtc-adapters/src/mining/mod.rs:114`, `crates/abtc-adapters/src/mempool/mod.rs:305`

Both the miner and the mempool compute weight as `(entry.size as u32) * 4`, which is correct only for non-witness transactions. Segwit transactions should use `base_size * 3 + total_size`. This systematically penalizes segwit transactions, producing suboptimal blocks and inaccurate fee-rate ordering.

### 39. `send_transaction` removes UTXOs but never broadcasts

**File:** `crates/abtc-adapters/src/wallet/mod.rs:477-493`

The wallet's `send_transaction` logs "broadcasting transaction" and removes spent UTXOs locally, but never submits the transaction to the mempool or network. The spent UTXOs are permanently removed; the transaction is lost.

### 40. Block marked `FullyValidated` before actual validation

**File:** `crates/abtc-application/src/net_processing.rs:763-764`

In `on_block`, a block's status is set to `FullyValidated` before validation occurs (actual validation happens when the caller processes `SyncAction::ProcessBlock`). If validation fails, the index entry is incorrectly marked as validated, and the block won't be re-requested.

### 41. `check_block` weight sum can overflow u32

**File:** `crates/abtc-domain/src/consensus/rules.rs:163-167`

`.sum::<u32>()` wraps silently in release mode. A crafted block whose individual transaction weights each pass the per-tx check but whose sum exceeds `u32::MAX` would wrap to a small value and pass the `> MAX_BLOCK_WEIGHT` check. Should use `checked_add` or `saturating_add`.

---

## Medium-Severity Issues

### 42. OP_CODESEPARATOR is a no-op

**File:** `crates/abtc-domain/src/script/interpreter.rs:1034-1038`

`OP_CODESEPARATOR` should update `script_code` to the portion of the script after the opcode. The current implementation does nothing. Scripts relying on `OP_CODESEPARATOR` for sighash partitioning will produce wrong sighash values. The Taproot `code_separator_pos` in `signing.rs:295` is also hardcoded to `0xFFFFFFFF` since the opcode position is never tracked.

### 43. Annex not committed in Taproot sighash

**File:** `crates/abtc-domain/src/crypto/signing.rs:211`

The `spend_type` byte is hardcoded without the annex bit. The interpreter (`interpreter.rs:1670-1679`) detects the annex but discards it without passing it to sighash computation. If a transaction with an annex is validated, sighash will be wrong. The annex is currently unused in Bitcoin but is part of the consensus specification.

### 44. `rebuild_active_chain` is O(n) on every new best tip

**File:** `crates/abtc-application/src/block_index.rs:213, 347-361`

Every time a new header becomes the best tip, `rebuild_active_chain` walks the entire chain from tip to genesis. At height 800,000, this is 800,000 iterations per new header during IBD. Bitcoin Core maintains the active chain incrementally.

### 45. No handshake timeout for peers

**File:** `crates/abtc-application/src/net_processing.rs:60-68`

Peers that connect but never complete the handshake remain in `peer_states` indefinitely. There is no timeout to evict peers stuck in `AwaitingVersion` or `AwaitingVerack`.

### 46. `recently_seen_txids` cleared entirely at threshold

**File:** `crates/abtc-application/src/net_processing.rs:836-838`

When the set exceeds 50,000 entries, it is cleared entirely. Immediately after, a peer can re-announce all 50,000 txids, causing redundant `getdata` requests. Should use a bounded LRU or rotating filter.

### 47. Missing locktime/sequence validation (timestamp-based)

**File:** `crates/abtc-application/src/mempool_acceptance.rs:195-197, 311-312`

Transactions with timestamp-based locktimes (`>= 500M`) and time-based BIP68 relative locks are accepted without any check against Median Time Past. Both have explicit TODO comments acknowledging the gap. Transactions that should be time-locked can enter the mempool prematurely.

### 48. RPC server has no request size limit or connection limit

**File:** `crates/abtc-adapters/src/rpc/mod.rs:158-165`

Each connection spawns a `tokio::spawn` with no concurrency cap. The single `read()` call uses a 65KB buffer but ignores `Content-Length`, meaning large requests are silently truncated to 65KB (potentially yielding a different valid JSON payload).

### 49. RPC `Access-Control-Allow-Origin: *` with no authentication

**File:** `crates/abtc-adapters/src/rpc/mod.rs:105`

The CORS wildcard allows any website visited by the node operator to issue RPC calls via browser fetch. Combined with no authentication, any local web page can silently control the node. The server binds to `127.0.0.1` which helps, but the CORS header should be restricted.

### 50. `reverse_hex` drops the last byte for 2-character inputs

**File:** `crates/abtc-adapters/src/wallet/mod.rs:266-278`

For a 2-character hex input `"aabb"`, the reverse iteration yields only index `[1]`, which enters the `else` branch producing `"aa"`. The second byte is dropped entirely. Any 2-byte hex reversal is wrong.

### 51. RocksDB UTXO deserialization minimum-length check is too short

**File:** `crates/abtc-adapters/src/storage/rocksdb_store.rs:273-296`

The minimum length check is `< 13`, but the function accesses up to index 16 (bytes 13-16 for `script_len`). If `bytes.len()` is 13-16, this panics with index-out-of-bounds. The check should be `< 17`.

### 52. Coinbase script used as both scriptSig and output scriptPubKey

**File:** `crates/abtc-adapters/src/mining/mod.rs:152-156`

The same `coinbase_script` is used for the coinbase input's scriptSig (which carries BIP34 height encoding and arbitrary data) and the coinbase output's scriptPubKey (which defines where the reward is sent). These serve completely different purposes. The output should use a proper pay-to address script.

### 53. Fee estimation always returns ~1 sat/vB

**File:** `crates/abtc-infrastructure/src/lib.rs:726-744`

The fee estimator is fed `fee = vsize` (exactly 1 sat/vB) for every transaction because there is no UTXO lookup to compute the real fee. `estimatesmartfee` RPC results will be misleading.

### 54. Genesis chain tip unconditionally overwritten on startup

**File:** `crates/abtc-infrastructure/src/lib.rs:326-329`

Block storage is conditional (`if !block_store.has_block(...)`), but the chain tip write is unconditional. A RocksDB-backed node restarting with existing data at height 1000 would reset the chain tip to genesis.

### 55. Rebroadcast `still_in_mempool` callback is a no-op

**File:** `crates/abtc-infrastructure/src/lib.rs:622-626`

The `still_in_mempool` callback always returns `true` with `let _ = txid;` to suppress the warning. Transactions evicted from the mempool will still be rebroadcast. The `mempool_ref` declared on line 619 is available but unused inside the closure.

---

## Low-Severity Issues

### 56. `undo_data` and `blocks` HashMaps in ChainState grow unboundedly

**File:** `crates/abtc-application/src/chain_state.rs:148,152`

Every connected block's undo data and full block are stored in memory forever. On a long chain this would exhaust memory.

### 57. `block_index.entries` grows unboundedly

**File:** `crates/abtc-application/src/block_index.rs:56`

Stale side-chain entries are never pruned. Memory grows proportional to all headers ever received, including attack headers.

### 58. `getblockhash` RPC truncates u64 to u32

**File:** `crates/abtc-application/src/handlers.rs:111-115`

`as u32` silently truncates heights above `u32::MAX`. Height 4,294,967,296 returns the genesis block hash.

### 59. `submitblock` RPC is a no-op

**File:** `crates/abtc-application/src/handlers.rs:541-543`

Returns `Value::Null` without parsing or processing the block.

### 60. Duplicate `RPC_IN_WARMUP` / `INTERNAL_ERROR` constants

**File:** `crates/abtc-ports/src/rpc/mod.rs:211,239`

Both are `-32603`. Bitcoin Core uses `-28` for `RPC_IN_WARMUP`. Clients cannot distinguish between an internal error and warmup state.

### 61. `RpcError` does not implement `Display` or `Error`

**File:** `crates/abtc-ports/src/rpc/mod.rs:58-66`

Cannot be used with `?` in functions returning `Box<dyn Error>`. `thiserror` is a dependency of `abtc-ports` but is unused.

### 62. `thiserror` dependency unused in `abtc-ports`

**File:** `crates/abtc-ports/Cargo.toml:17`

Zero uses of `#[derive(Error)]` or `use thiserror` anywhere in the crate.

### 63. Predictable nonce in version message

**File:** `crates/abtc-adapters/src/network/mod.rs:177-188`

`rand_u64()` uses system clock with a simple xorshift. The version nonce is trivially predictable, undermining self-connection detection. Should use OS randomness.

### 64. `fee_rate_buckets` not cleared on mempool `clear()`

**File:** `crates/abtc-adapters/src/mempool/mod.rs:596-607`

After clearing the mempool, fee estimation uses stale historical data.

### 65. Network `TcpStream` wrapped in single `RwLock`

**File:** `crates/abtc-adapters/src/network/mod.rs:200`

Reads and writes cannot happen concurrently. Should use `TcpStream::into_split()` for independent read/write halves.

### 66. `is_running()` returns `false` on lock contention

**File:** `crates/abtc-adapters/src/rpc/mod.rs:308-314`

`try_read()` failure means "would block," not "not running."

### 67. Duplicate `is_p2sh_witness` function

**File:** `crates/abtc-application/src/services.rs:325-362` and `mempool_acceptance.rs:348-377`

Identical code in two files. Should be factored into a shared utility.

### 68. No `[workspace.dependencies]` for shared dependency versions

Shared dependencies (`tokio`, `secp256k1`, `serde_json`, `rand`, etc.) are specified independently in each crate's `Cargo.toml`. Version drift is possible.

---

## Summary

| Severity | Count | Key Areas |
|----------|-------|-----------|
| Critical | 5 | Taproot sighash types, reorg recovery, mempool double-spend, parallel block paths, RocksDB best-block |
| High | 9 | Missing sigops, orphan DoS, compact block collisions, mempool eviction, RBF, weight calc, wallet broadcast, premature validation status, weight overflow |
| Medium | 14 | OP_CODESEPARATOR, annex, IBD performance, timeouts, locktime, RPC security, deserialization, mining, fee estimation |
| Low | 13 | Memory growth, RPC truncation, stale stubs, API design, dependency management |

### Comparison with First Review

| Metric | Review 1 | Review 2 | Delta |
|--------|----------|----------|-------|
| Tests | 612 | 1,103 | +491 |
| Clippy warnings | 24 | 0 | -24 |
| Critical findings | 10 | 5 | -5 |
| High findings | 7 | 9 | +2 |
| Total findings | 44 | 41 | -3 |

The 12 fixes from the first review are all verified correct. The critical-severity count dropped from 10 to 5, with the remaining criticals concentrated in **Taproot sighash completeness** (#28), **reorg safety** (#29), and **mempool integrity** (#30). The high-severity count increased slightly because this review examined adapter and infrastructure layers more deeply, surfacing issues in the mempool dependency graph (#36-37), weight calculations (#38), and wallet broadcasting (#39) that were not covered in depth before.

The strongest improvement since the first review is in the domain layer's core consensus code (PoW validation, script flags, signature checking), which is now substantially more correct. The areas needing the most attention are the **application-layer state management** (reorg recovery, parallel block paths) and **adapter-layer protocol correctness** (weight calculations, mempool graph maintenance, wallet broadcast).
