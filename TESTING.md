# Agentic Bitcoin — Testing Strategy

## Current Approach

The test suite (995+ tests, 0 failures) is organised into three layers that reflect the hexagonal architecture.

### Unit tests (inline `#[cfg(test)]` modules)

Every source file with meaningful logic has a co-located test module. These tests exercise the public and `pub(crate)` API surface of the module they live in, using hand-constructed inputs and checking outputs directly. They run fast, have no I/O, and depend only on the crate they belong to. Roughly 96 files across the four main crates carry `#[cfg(test)]` modules.

Most of these tests are original to this implementation — they were written to exercise *our* type signatures and domain boundaries, not ported from Bitcoin Core. The exception is `script_tests.json`, a set of script evaluation vectors taken directly from Core's test data, which verifies opcode-level compatibility.

### Integration tests (`tests/` directories)

Five test files live in crate-level `tests/` directories.

In abtc-domain: `block_validation_tests.rs` (16 tests) constructs multi-block chains with real scripts and validates connect/disconnect round-trips. `tx_validation_tests.rs` (34 tests) covers serialisation, signing, and policy enforcement including P2TR script-path spends. `script_tests.rs` (8 tests) drives the Core-format JSON vectors. `benchmarks.rs` (4 tests) measures hashing, secp256k1, script execution, and taproot throughput.

In abtc-application: `chain_state_tests.rs` (20 tests) stands up a full chain-state manager against the in-memory adapters and exercises genesis initialisation, sequential block connection, reorgs, side chains, and UTXO tracking.

### Regression tests (Session 14, code-review fixes)

Twenty-three tests were added during Session 14 to guard against specific bugs found in code review. Every regression test function is prefixed `regression_` and each file carries an `═══` banner block explaining that these are *not* ports of Bitcoin Core test vectors. They cover the 256-bit PoW comparison, taproot sighash hash_type threading, strict DER enforcement, tapscript limit gating, block-store best-hash updates, and reorg error handling, among others.

### What the current tests do well

They catch regressions at the unit level quickly, they validate algorithmic correctness against Core's script vectors, and they give reasonable end-to-end coverage of the consensus and chain-state paths. Because they test against *our* trait boundaries, they survive internal refactors cleanly.

### What the current tests do not cover

They don't express *protocol-level invariants* in a way that's independent of our internal types. A test like `regression_256bit_pow_rejects_truncation_bug` exercises a specific function signature; it would break if we renamed the function, even though the underlying rule ("a block whose hash exceeds the target must be rejected") hasn't changed. The tests also don't capture multi-step user-facing workflows — "mine a block, spend its coinbase after 100 confirmations, verify the UTXO set" — as first-class specifications.

---

## Future: Scenario Tests with Cucumber-rs

The next testing layer will express Bitcoin's consensus and wallet rules as plain-English specifications, translated into Gherkin scenarios and executed by [cucumber-rs](https://github.com/cucumber-rs/cucumber).

### Why Gherkin

Gherkin scenarios describe *what Bitcoin requires*, not *how this codebase implements it*. A scenario like "a transaction spending a P2TR output with an invalid Schnorr signature is rejected" is true of any correct Bitcoin implementation. This makes the specs durable across refactors and potentially reusable as a conformance suite against other implementations.

The three-layer mapping — English spec, Gherkin scenario, step implementation — also creates a natural review surface. The English spec can be reviewed for correctness against BIPs without reading Rust. The Gherkin scenario can be reviewed for coverage without understanding the step implementations. The step code is the only layer that touches internal types.

### Example mapping

Before writing scenarios, each feature area goes through example mapping to discover the concrete cases that matter. An example map for a feature like "coinbase maturity" might look like:

**Rule:** Coinbase outputs cannot be spent until they have 100 confirmations.

| Example | Outcome |
|---------|---------|
| Spend a coinbase at height 50 when it was mined at height 1 | Rejected (only 49 confirmations) |
| Spend a coinbase at height 101 when it was mined at height 1 | Accepted (exactly 100 confirmations) |
| Spend a coinbase at height 101 when it was mined at height 1, but a reorg reduces the tip to height 99 | Rejected (coinbase no longer has 100 confirmations) |
| Spend a coinbase in the same block it was mined | Rejected |

Each row becomes a Gherkin scenario. Edge cases and questions discovered during mapping ("does a reorg that reconnects the same blocks reset the count?") feed back into the spec.

### Proposed directory structure

```
tests/
  scenarios/
    features/
      consensus/
        block_validation.feature
        coinbase_maturity.feature
        proof_of_work.feature
        script_execution.feature
        taproot.feature
        segwit.feature
      mempool/
        acceptance.feature
        rbf.feature
        fee_estimation.feature
      wallet/
        coin_selection.feature
        psbt.feature
        hd_derivation.feature
      p2p/
        handshake.feature
        block_relay.feature
        compact_blocks.feature
    steps/
      consensus_steps.rs
      mempool_steps.rs
      wallet_steps.rs
      p2p_steps.rs
    world.rs          # shared test world (adapters, chain state)
    main.rs           # cucumber runner entry point
```

### Sample feature file

```gherkin
Feature: Proof of work validation
  As a node operator
  I want blocks with insufficient proof of work to be rejected
  So that the chain remains secure against hash-rate attacks

  Background:
    Given a regtest chain initialised to height 0

  Scenario: Block hash exactly meets the target
    Given the current target requires a hash below "00000000ffff..."
    When a miner produces a block whose hash is "00000000fffe..."
    Then the block is accepted

  Scenario: Block hash exceeds the target
    Given the current target requires a hash below "00000000ffff..."
    When a miner produces a block whose hash is "000000010000..."
    Then the block is rejected with error "BlockProofOfWorkInvalid"

  Scenario: Target is validated with full 256-bit precision
    Given a target that differs from the block hash only in the 17th byte
    When the block is validated
    Then the full 256-bit comparison catches the difference
    And the block is rejected with error "BlockProofOfWorkInvalid"
```

### Shared test world

The cucumber world struct would compose the same in-memory adapters the integration tests already use, behind the port traits. This means scenarios interact with `ChainStateManager`, `MempoolAcceptance`, etc. through the application layer, not by constructing domain objects directly. A step like "Given a regtest chain initialised to height 0" would set up the full adapter stack once per scenario.

```rust
#[derive(Debug, cucumber::World)]
pub struct BitcoinWorld {
    pub chain_state: ChainStateManager<InMemoryBlockStore, InMemoryUtxoStore>,
    pub mempool: InMemoryMempool,
    pub wallet: InMemoryWallet,
    pub last_error: Option<String>,
    pub last_block: Option<Block>,
}
```

### Feature areas to cover first

The highest-value scenarios are those that express rules people argue about or get wrong — the ones where a code reviewer found a bug. Working from the Session 14 code review, the initial feature files would cover proof-of-work validation (256-bit precision), taproot signature verification (hash_type threading, script-path vs key-path), coinbase maturity and spending, mempool fee calculation, and chain reorganisation (UTXO rollback, fork-point detection). These directly correspond to the bugs that were caught and fixed, turning each fix into a durable, architecture-independent specification.

### Lesson from Session 14: regression tests validating the validator

When we added 23 regression tests for the code-review fixes, two of them immediately caught real bugs in the code they were guarding. `regression_decode_compact_u256_small_target` revealed that `decode_compact_u256` silently dropped the third mantissa byte when the exponent was exactly 3. `regression_256bit_pow_rejects_truncation_bug` exposed a flaw in our own reasoning about how 256-bit integer comparison short-circuits at the MSB — the original test assumed per-byte independence, but the comparison exits early when the most significant byte already determines the result.

This is exactly the kind of thing Gherkin scenarios would express more durably. A scenario like "a block whose hash exceeds the target only in byte 17 is rejected" captures the *rule* without depending on the name of an internal function. When we build out the scenario suite, these two cases should be among the first ported — they demonstrate that the value of scenarios is not just in catching bugs, but in forcing us to articulate the semantics precisely enough that the test actually tests what we think it tests.
