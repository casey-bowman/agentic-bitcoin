# Code Review - agentic-bitcoin (Redo, Extra-High Pass)

Date: 2026-02-22
Reviewer: Codex

## Findings

### 1) [P1] `validate_and_accept_block` can accept disconnected/orphan blocks as new tip
- File: `crates/abtc-application/src/services.rs:95`
- Severity rationale: chain validity can be violated in the production acceptance path.
- Evidence:
  - New height is derived only from current tip height (`current_height + 1`) at `crates/abtc-application/src/services.rs:95` and `crates/abtc-application/src/services.rs:100`.
  - There is no check that `block.header.prev_block_hash` matches the current tip or even exists on a known chain before tip update.
  - Tip is then written unconditionally to the incoming block at `crates/abtc-application/src/services.rs:197`.
  - This path is exercised by networking at `crates/abtc-infrastructure/src/lib.rs:720`.
- Impact:
  - A structurally valid but disconnected block can become canonical tip.
  - Chain continuity assumptions in downstream components become invalid.
- Recommendation:
  - Enforce parent linkage check before acceptance (at minimum parent must exist; ideally integrate with chain-work selection/reorg logic from `chain_state`).

### 2) [P1] Block transaction validation is not context-correct within a block (same-block spends / double-spends)
- File: `crates/abtc-application/src/services.rs:107`
- Severity rationale: valid blocks can be rejected and invalid blocks can be accepted.
- Evidence:
  - All input UTXOs are validated against pre-block chain state (`get_utxo`) during first pass at `crates/abtc-application/src/services.rs:114`.
  - Actual spend removals are deferred to a later batch at `crates/abtc-application/src/services.rs:160`-`crates/abtc-application/src/services.rs:170`.
- Consequences:
  - A valid tx spending an output created earlier in the same block is rejected as missing UTXO.
  - Two transactions in the same block spending the same prior output can both pass validation before removals are applied.
- Recommendation:
  - Validate via an incremental per-block UTXO view (or reuse the `chain_state` block-connect logic that handles per-block ordering/consistency).

### 3) [P1] Chain state updates are non-atomic across stores, risking persistent inconsistency
- File: `crates/abtc-application/src/services.rs:185`
- Severity rationale: crash/error in the middle of block commit can leave durable state corrupted.
- Evidence:
  - `write_utxo_set` occurs first at `crates/abtc-application/src/services.rs:186`.
  - `store_block` occurs second at `crates/abtc-application/src/services.rs:192`.
  - `write_chain_tip` occurs third at `crates/abtc-application/src/services.rs:198`.
  - These are independent operations with no transaction boundary.
- Impact:
  - If operation N+1 fails, operation N remains committed, producing mismatched UTXO/block/tip state.
- Recommendation:
  - Introduce an atomic commit abstraction (single transactional store operation for “apply block delta + persist block + move tip”), or compensating rollback with idempotent replay semantics.

### 4) [P2] Node lifecycle state can become inconsistent on startup failure
- File: `crates/abtc-infrastructure/src/lib.rs:465`
- Severity rationale: health/running semantics can diverge from actual runtime state.
- Evidence:
  - `running` is set true before `rpc_server.start()` at `crates/abtc-infrastructure/src/lib.rs:465`-`crates/abtc-infrastructure/src/lib.rs:468`.
  - If RPC start fails, method returns error with `running` still true.
- Impact:
  - Observability/health checks can report running=true although startup failed.
- Recommendation:
  - Set `running = true` only after all mandatory startup steps succeed, or roll back flag on error paths.

### 5) [P2] Stop/start cycle is broken because shutdown signal is latched and never reset
- Files:
  - `crates/abtc-infrastructure/src/lib.rs:431`
  - `crates/abtc-infrastructure/src/lib.rs:510`
  - `crates/abtc-infrastructure/src/lib.rs:808`
- Severity rationale: restartability is a core runtime expectation.
- Evidence:
  - A single watch channel is created once in `new()` (`false` initial state).
  - `stop()` sends `true` at `crates/abtc-infrastructure/src/lib.rs:808`.
  - Background tasks exit on `shutdown.changed()` (e.g., `crates/abtc-infrastructure/src/lib.rs:510`).
  - `start()` does not recreate/reset shutdown channel before spawning tasks.
- Impact:
  - On subsequent `start()`, tasks observe shutdown already signaled and terminate quickly; node appears started but background loops are effectively dead.
- Recommendation:
  - Reinitialize shutdown signaling per start cycle or make node single-use and enforce that contract.

### 6) [P2] RPC HTTP request framing is incomplete (single-read + no Content-Length enforcement)
- File: `crates/abtc-adapters/src/rpc/mod.rs:166`
- Severity rationale: unreliable behavior under normal TCP segmentation and large payloads.
- Evidence:
  - Server performs a single `stream.read` into fixed buffer at `crates/abtc-adapters/src/rpc/mod.rs:166`.
  - `parse_http_body` returns all bytes after header separator and does not actually parse/enforce `Content-Length` despite docs claiming it does (`crates/abtc-adapters/src/rpc/mod.rs:45`, implementation `crates/abtc-adapters/src/rpc/mod.rs:46`-`crates/abtc-adapters/src/rpc/mod.rs:57`).
- Impact:
  - Partial reads can generate parse errors for otherwise valid requests.
  - Behavior is brittle for clients that send body across multiple TCP frames.
- Recommendation:
  - Implement header parse + explicit body-length read loop; reject malformed/oversized requests deterministically.

## Testing / Validation Notes

Commands executed:
- `cargo test -p abtc-application` (pass)
- `cargo test -p abtc-infrastructure --lib` (fails in this sandbox due `PermissionDenied` on local bind during startup tests)

Observed test gap relevant to above findings:
- `BlockchainService::validate_and_accept_block` has no dedicated unit tests in `services.rs`; current unit tests only cover `ChainInfo` construction (`crates/abtc-application/src/services.rs:513`).

## Summary

The highest-risk issues are in the block acceptance path (`BlockchainService`): missing contextual chain checks, incorrect per-block spend semantics, and non-atomic persistence updates. These are consensus/path-correctness issues, not just code quality concerns, and should be prioritized before expanding node/network behavior.
