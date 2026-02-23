# Documentation Fixes — Pending

Date: 2026-02-22
Source: Codex markdown reviews (`claude-markdown-comments-2026-02-22-codex.md`, `all-markdown-comments-2026-02-22-codex.md`)

These are concrete documentation inaccuracies identified by Codex that should be fixed in a future session.

---

## High Priority

### 1. README.md — stale test count
- Line 69 says "612 tests" — should be 1,103.
- Roadmap section (lines 98-100) lists features already implemented.

### 2. CRATES.md — stale versions and incorrect dependency graph
- Lines 36, 55, 67, 79, 90 use `"0.1"` version examples — should be `"0.2"`.
- Line 75 claims `abtc-application` pulls adapters transitively — wrong; adapters is only a dev-dependency (`crates/abtc-application/Cargo.toml:27`).
- Dependency graph (lines 100-104) encodes the same incorrect edge.

### 3. DOMAIN_CODE_EXAMPLES.md — non-compiling API examples
- Lines 435-437: `address::create_address(...)` does not exist. Check actual address API in `crates/abtc-domain/src/wallet/address.rs` and fix.
- Line 444: `CoinSelector::new(...)` does not exist. `CoinSelector` has static selection methods only (`crates/abtc-domain/src/wallet/coin_selection.rs:46-49, 61`).
- Line 466: `OutputDescriptor::parse(...)` should be `parse_descriptor(...)` (`crates/abtc-domain/src/wallet/descriptors/mod.rs:20`).

### 4. crates/abtc-domain/README.md — inaccurate dependencies and test commands
- Lines 113-117 claim only `sha2`, `ripemd`, `hex` as dependencies. Actual deps also include `sha1`, `hmac`, `serde`, `thiserror`, `secp256k1`, `chacha20poly1305`, `hkdf`, `rand`.
- Line 122 suggests `cargo test --test integration` — no such test target exists. Fix to match actual test file names.

---

## Medium Priority

### 5. crates/abtc-application/README.md — API shape drift
- Lines 62-69: usage section claims `ChainState` and `MempoolAcceptor` are generic over adapters. They are concrete structs (`chain_state.rs:139`, `mempool_acceptance.rs:79`).

### 6. crates/abtc-ports/README.md — describes capabilities beyond trait surface
- Line 35: mentions mining candidate selection and ancestor/descendant tracking in `MempoolPort`. Check actual trait signature in `crates/abtc-ports/src/mempool/mod.rs` and tighten wording.

### 7. TESTING.md — future-world pseudocode uses non-existent types
- Lines 124-130: `ChainStateManager`, `InMemoryUtxoStore` are not real types. Mark section as pseudocode/hypothetical.

### 8. DOMAIN_LAYER_OVERVIEW.md — test command names may not match file names
- Lines 250-251: verify `cargo test --test tx_validation` and `cargo test --test block_validation` match actual test file names (may need `_tests` suffix).

---

## Low Priority

### 9. SESSION_NOTES.md — consider adding a pointer at top
- Currently mixes historical and current-state claims. Consider adding a note at top: "Current status: see README.md and TESTING.md."

### 10. Review response risk calibration
- `code-review-response-2026-02-22.md` line 37: checksum dismissal may be too soft (real TcpPeerManager path exists).
- Line 81: hardcoded `ConsensusParams::mainnet()` in services deserves stronger caution.
