# Comments on All Markdown Files (Active Workspace)

Date: 2026-02-22
Reviewer: Codex

## Scope

Reviewed every `.md` file in the active workspace tree (excluding `.git/`, `target/`, and `.claude/worktrees/` snapshot mirrors).

## Cross-File Observations

1. Current-state facts drift quickly across docs (test counts, warnings, roadmap status).
2. Example-heavy docs need automated validation (snippet compile checks or doctests) to avoid API drift.
3. Architecture narrative is strong and consistent, but dependency/version snippets are stale in a few key places.
4. Review artifacts are high-signal, but they should explicitly separate “current state” vs “historical at review date.”

## Per-File Comments

| File | Comment | Suggested Action |
|---|---|---|
| `CRATES.md` | Strong crate-orientation doc, but version snippets are stale (`0.1` at lines 36/55/67/79/90) and dependency direction is inaccurate (`abtc-application` does not pull adapters transitively despite line 75 and graph lines 100-104). | Update version snippets to `0.2.x` and fix graph to match `crates/abtc-application/Cargo.toml:14-16,27`. |
| `DOMAIN_CODE_EXAMPLES.md` | Best breadth of examples, but several snippets do not match current API (`create_address` usage at lines 435-437, `CoinSelector::new` at line 444, `OutputDescriptor::parse` at line 466). | Convert examples to current APIs and add CI snippet checks. |
| `DOMAIN_LAYER_OVERVIEW.md` | Excellent structural map, but some commands are stale (`cargo test --test tx_validation` / `block_validation` at lines 250-251 do not match file names). Hard-coded file stats likely to drift. | Fix test command names and auto-generate stats section. |
| `README.md` | Good onboarding and architecture summary. Current-state section is stale (`612 tests` at line 69) and roadmap includes features already implemented (lines 98-100). | Refresh test/feature status and replace static counts with generated values or “as of commit/date”. |
| `SESSION_NOTES.md` | Very strong engineering journal with deep context. As a living doc, it mixes historical and current-state claims (e.g., test-count snapshots at lines 48-52). | Keep as historical log but add a “Current status moved to README/TESTING” pointer at top. |
| `TESTING.md` | Strong testing philosophy and future strategy. Current-state number at line 5 is stale, and future-world sample uses non-existent type names (`ChainStateManager`, `InMemoryUtxoStore` at lines 124-130). | Mark pseudocode explicitly and update current metrics from real runs. |
| `crates/abtc-adapters/README.md` | Clear and concise crate README. Mostly accurate. | Minor: add explicit note on what is production-ready vs stub/simplified paths. |
| `crates/abtc-application/README.md` | Good module-level explanation. Usage section claims service generics that no longer match code (`ChainState`/`MempoolAcceptor` are concrete). | Update usage text to current concrete APIs and keep generic-language to trait boundaries only. |
| `crates/abtc-domain/README.md` | Good high-level intro. Dependency section is inaccurate (`sha2/ripemd/hex only` claim at lines 113-117), and test command `--test integration` (line 122) is not valid. | Sync dependency/testing sections with `crates/abtc-domain/Cargo.toml` and real test targets. |
| `crates/abtc-infrastructure/README.md` | Clean and practical. Mostly accurate at current scope. | Minor: mention known restart/lifecycle caveats if those behaviors are intentionally pending. |
| `crates/abtc-ports/README.md` | Good conceptual framing of ports. Some capability descriptions are implementation-level, not trait-level (e.g., mempool ancestor/descendant/mining candidate wording at line 35). | Tighten wording to exact trait surface in `crates/abtc-ports/src/*`. |
| `reviews/architecture-implementation-plan-2026-02-22-codex.md` | Actionable, well-sequenced implementation plan. | Keep; this is a solid execution guide. |
| `reviews/architecture-review-2026-02-22-codex.md` | Clear architecture findings with practical prioritization. | Keep; use as baseline for architecture refactors. |
| `reviews/claude-markdown-comments-2026-02-22-codex.md` | Useful first pass, but narrower than “all markdown files.” | Supersede with this document. |
| `reviews/code-review-2026-02-21.md` | Broad and detailed first audit with many meaningful catches. Historical metrics are stale now. | Keep for audit history; optionally add “historical snapshot” banner. |
| `reviews/code-review-2026-02-22-codex-extra-high.md` | High-signal, severity-focused and actionable. | Keep as current technical baseline. |
| `reviews/code-review-2026-02-22-codex-independent.md` | Concise independent review; still useful as corroborating signal. | Keep as secondary corroboration. |
| `reviews/code-review-2026-02-22.md` | Very comprehensive follow-up review. Good depth; large volume makes triage harder without grouping by subsystem owner. | Keep, but add a small triage index by subsystem/owner/severity. |
| `reviews/code-review-response-2026-02-22.md` | Strong transparency on disposition. A few risk justifications are optimistic and should be revisited as implementation evolves. | Keep and append “revalidation status” updates as fixes land. |

## Final Recommendation

Short-term documentation cleanup should focus on four files first: `CRATES.md`, `README.md`, `DOMAIN_CODE_EXAMPLES.md`, and `crates/abtc-domain/README.md`. These are the highest-impact for external users and currently contain the most actionable drift.
