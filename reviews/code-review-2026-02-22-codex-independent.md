# Independent Code Review - agentic-bitcoin

Date: 2026-02-22
Reviewer: Codex (independent review; existing review files were not consulted)

## Findings

### 1) [High] Persistent chain state is reset to genesis on every node startup
- File: `crates/abtc-infrastructure/src/lib.rs:326`
- Code path: `BitcoinNode::new`
- Details: Startup always executes `chain_state.write_chain_tip(genesis_hash, 0)` unconditionally, even when using persistent storage (`rocksdb`) and an existing best tip is already present.
- Impact: On restart, the persisted chain tip is overwritten to height 0. This can make node state regress, break continuity assumptions, and create inconsistency between stored blocks and selected tip.
- Recommendation: Read existing tip first; only initialize genesis when chain state is empty/uninitialized.

### 2) [Medium] Node `running` flag is set before startup succeeds, leaving inconsistent health state on failure
- File: `crates/abtc-infrastructure/src/lib.rs:465`
- Code path: `BitcoinNode::start`
- Details: `self.running.store(true, ...)` is called before `self.rpc_server.start().await?`. If RPC bind/start fails, `start()` returns `Err` while `running` remains `true`.
- Impact: `health()` can report `is_running=true` when the node never successfully started. This is observable in restricted environments where bind fails (e.g., `PermissionDenied`).
- Recommendation: Set `running=true` only after all required startup steps succeed, or roll it back on error.

### 3) [Medium] Stop/start lifecycle is not re-entrant because shutdown watch channel is never reset
- Files:
  - `crates/abtc-infrastructure/src/lib.rs:431`
  - `crates/abtc-infrastructure/src/lib.rs:808`
  - `crates/abtc-infrastructure/src/lib.rs:497`
- Code path: `BitcoinNode::{new,start,stop,start_background_tasks}`
- Details: A single watch channel is created in `new()` with initial `false`. `stop()` sends `true`. Subsequent `start()` calls reuse the same receiver; new background tasks immediately observe shutdown and exit.
- Impact: Node appears started but background maintenance/reporting tasks are effectively dead after first stop/start cycle.
- Recommendation: Recreate/reset shutdown signaling on each start cycle, or construct a fresh node per lifecycle.

## Test Evidence

I ran:
- `cargo test --workspace`

Result summary:
- Most crates/tests pass.
- `abtc-infrastructure` had 7 failing tests (`test_node_start_sets_running`, `test_node_stop_clears_running`, `test_shutdown_signal_stops_tasks`, `test_health_after_start`, `test_health_after_stop`, `test_node_health_fields_consistent`, `test_double_stop_is_safe`) failing with `PermissionDenied` during `node.start().await.unwrap()`.

This failure mode is consistent with finding #2 (state may still mark running on startup error), and it also indicates tests currently depend on network bind capability.

## Residual Risk / Coverage Notes

- This review focused on correctness and lifecycle risks in infra startup/shutdown and persistence paths.
- I did not use existing review files to avoid cross-contamination.
