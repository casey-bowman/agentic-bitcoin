# Code Review Response Notes — For Future Sessions

Date: 2026-02-22
Covers: All review documents from 2026-02-22 (excluding the first review from 2026-02-21 and its response, which were already addressed)

---

## Review Documents

1. **code-review-2026-02-22.md** — Claude Opus follow-up review (#28-68)
2. **code-review-2026-02-22-codex-independent.md** — Codex independent review (3 findings)
3. **code-review-2026-02-22-codex-extra-high.md** — Codex extra-high pass (6 findings)
4. **architecture-review-2026-02-22-codex.md** — Codex architecture review (5 findings)
5. **architecture-implementation-plan-2026-02-22-codex.md** — Codex implementation plan (5 workstreams)
6. **claude-markdown-comments-2026-02-22-codex.md** — Codex comments on Claude markdown files
7. **all-markdown-comments-2026-02-22-codex.md** — Codex comments on all markdown files

---

## Cross-Review Consensus (findings flagged by multiple independent reviewers)

These have the highest confidence:

- **Genesis tip overwrite on restart** — flagged by Claude (#54), Codex independent (#1), Codex extra-high (#implicit in #1), and architecture review (#1). Four independent flags.
- **`validate_and_accept_block` is a broken parallel code path** — Claude (#31), Codex extra-high (#1, #2, #3). Missing parent linkage check, no per-block UTXO view, non-atomic persistence.
- **Node lifecycle: running flag set before startup succeeds** — Codex independent (#2) and Codex extra-high (#4).
- **Watch channel latch prevents restart** — Codex independent (#3) and Codex extra-high (#5).

---

## Suggested Fix Priority (combining all reviews)

### Tier 1 — Consensus Correctness
- **#28** Taproot sighash: implement SIGHASH_NONE, SIGHASH_SINGLE, ANYONECANPAY
- **#30** Mempool double-spend check against other mempool transactions
- **#31/#Codex-1/#Codex-2/#Codex-3** Fix or remove `validate_and_accept_block` — either integrate with ChainState or add parent checks + per-block UTXO view + atomic commits
- **#33** Sigops counting and enforcement
- **#41** Weight sum overflow (use checked_add/saturating_add)

### Tier 2 — State Integrity
- **#29** Reorg failure recovery — re-connect old chain on new-chain connect failure
- **#32** RocksDB best block hash guard (match in-memory store behavior)
- **#54/Codex-arch-1** Genesis tip overwrite — read existing tip first, only init when empty
- **#36** Mempool eviction: use `remove_entry()` not direct `entries.remove()`
- **#37** RBF conflict: propagate error to reject incoming tx

### Tier 3 — Protocol Correctness
- **#38** Segwit weight calculation (`base_size * 3 + total_size`)
- **#39** Wallet `send_transaction` — actually broadcast to mempool/network
- **#40** Block validation status — don't mark FullyValidated before validation
- **#42** OP_CODESEPARATOR — update script_code and track position
- **#35** Compact block short ID collision detection

### Tier 4 — Robustness
- **#34** Orphan block storage limit
- **#45** Handshake timeout for peers
- **#46** recently_seen_txids — use LRU instead of full clear
- **#47** Timestamp-based locktime/BIP68 validation against MTP
- **#48** RPC request size limit and connection limit
- **Codex-infra-3/5** Watch channel reset for stop/start lifecycle
- **Codex-infra-2/4** Running flag: set only after startup succeeds

### Tier 5 — Architecture (from Codex implementation plan)
- **Workstream A** — Startup/persistence bootstrap correctness
- **Workstream B** — Adapter abstraction at node boundary (trait objects)
- **Workstream C** — Decouple JSON-RPC from application handlers
- **Workstream D** — CQRS: integrate or remove
- **Workstream E** — Typed port errors

### Tier 6 — Polish
- Low-severity items (#56-68): unbounded maps, RPC truncation, stale stubs, dependency management
- **#43** Annex handling in taproot sighash (unused in Bitcoin today but spec-required)
- **#44** rebuild_active_chain O(n) — matters for IBD, not urgent for regtest
- **#52** Coinbase script used as both scriptSig and scriptPubKey
- **#53** Fee estimation always returns ~1 sat/vB
- **#55** Rebroadcast still_in_mempool is a no-op

---

## Notes on the Architecture Implementation Plan

The plan (architecture-implementation-plan-2026-02-22-codex.md) proposes 5 workstreams in 7 PRs. The plan is sound but should be weighed against consensus correctness work. Recommendation: do Workstream A (bootstrap) first since it overlaps with Tier 2 fixes, then prioritize Tier 1-3 code fixes before the larger architectural refactors (Workstreams B-E).

---

## Documentation Fixes

See `documentation-fixes-pending.md` in this folder for the specific list.
