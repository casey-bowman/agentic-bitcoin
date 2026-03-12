# abtc_domain — Dependency Cycle Resolution

Resolved all internal module cycles in `abtc-domain` using arch-view-rs.
Three cycles were identified and eliminated. All top-level nodes now show
blue (concrete, no cycle) or green (abstract, no cycle).

## Cycle 1: `crypto ↔ script`

**Edges:**
- `crypto → script`: `crypto/signing.rs` imported `SignatureChecker` from
  `script::interpreter` and `Script` from `script::script`.
- `script → crypto`: `script/interpreter.rs` imported `schnorr` and
  `taproot` verification functions from `crypto`.

**Fix — move trait impl out of crypto:**

Created `script/checker_impl.rs` containing the
`impl SignatureChecker for TransactionSignatureChecker` block (previously
in `crypto/signing.rs`). Changed `crypto/signing.rs` to import `Script`
from `crate::primitives` instead of `crate::script::script`.

Now `crypto` has zero imports from `script`. The natural dependency
direction (`script → crypto`) is preserved.

**Files changed:**
- `crypto/signing.rs` — removed `use crate::script::*` imports; removed
  the entire `impl SignatureChecker for TransactionSignatureChecker` block;
  changed `Script` import to `crate::primitives::Script`; widened struct
  fields to `pub(crate)` so the external impl can access them.
- `script/checker_impl.rs` *(new)* — contains the trait impl, importing
  `TransactionSignatureChecker` and `verify_ecdsa` from `crate::crypto`,
  `verify_schnorr` from `crate::crypto::schnorr`, and covenant functions
  from `crate::covenants`.
- `script/mod.rs` — added `mod checker_impl;`.

## Cycle 2: `crypto → covenants` (resolved as side-effect of Cycle 1)

**Edge:**
- `crypto/signing.rs` had inline `use crate::covenants::ctv::compute_ctv_hash`
  and `use crate::covenants::vault::{verify_vault_trigger, ...}` inside the
  `check_ctv`, `check_vault`, and `check_vault_recover` methods.

**Fix:**

These methods moved with the trait impl into `script/checker_impl.rs`.
The `script → covenants` edge that replaced it is non-cyclic because
`covenants` only depends on `hashing` and `primitives` (both leaf
modules).

## Cycle 3: `script ↔ wallet`

**Edges:**
- `script → wallet`: miniscript modules (`fragment.rs`, `decode.rs`,
  `policy.rs`, `compiler.rs`) imported `PublicKey` from
  `crate::wallet::keys`.
- `wallet → script`: `psbt.rs`, `tx_builder.rs`, `address.rs`, and
  `descriptors/` imported `Script`, `ScriptBuilder`, `Opcodes`, and
  `Miniscript` from `crate::script`.

**Fix — move PublicKey to primitives:**

Created `primitives/public_key.rs` with the `PublicKey` struct, its
methods, and `KeyError`. Updated all miniscript files to import from
`crate::primitives::PublicKey`. Made `wallet/keys.rs` a re-export shim
(`pub use crate::primitives::public_key::{KeyError, PublicKey}`).

Now `script` has zero imports from `wallet`. The natural dependency
direction (`wallet → script`) is preserved.

**Files changed:**
- `primitives/public_key.rs` *(new)* — canonical `PublicKey` and `KeyError`
  definitions; added `from_inner` constructor for wallet use.
- `primitives/mod.rs` — added `pub mod public_key` and re-exports.
- `wallet/keys.rs` — removed `PublicKey` struct, `KeyError` enum, and
  `impl PublicKey` block; added re-export from primitives; changed
  `PrivateKey::public_key()` to use `PublicKey::from_inner()`.
- `script/miniscript/fragment.rs` — `crate::wallet::keys::PublicKey` →
  `crate::primitives::PublicKey`.
- `script/miniscript/decode.rs` — same.
- `script/miniscript/policy.rs` — same.
- `script/miniscript/compiler.rs` — same (test module).

## Supporting changes (hashing and primitives extraction)

These were done earlier in the session to shorten cycle paths before the
three main fixes above.

- `src/hashing.rs` *(new)* — moved from `crypto/hashing.rs`; also
  absorbed the `Hash256` struct definition (previously in
  `primitives/hash.rs`) so that `hashing` has zero intra-crate
  dependencies.
- `crypto/hashing.rs` — became a re-export shim (`pub use crate::hashing::*`).
- `primitives/hash.rs` — removed `Hash256` definition; now re-exports
  from `crate::hashing::Hash256`; changed direct constructors to
  `Hash256::from_bytes(...)`.
- `primitives/script_types.rs` *(new)* — bare `Script` struct with basic
  methods, breaking `primitives → script`.
- `primitives/witness.rs` *(new)* — `Witness` struct (pure data type),
  breaking `primitives → script`.
- `script/script.rs` — removed `Script` struct definition; re-exports
  from `crate::primitives::script_types::Script`.
- `script/witness.rs` — became a re-export shim from
  `crate::primitives::witness::Witness`.
- `primitives/block.rs`, `primitives/transaction.rs` — changed
  self-referential `crate::primitives::` imports to `super::` relative
  imports.
- `covenants/vault.rs`, `covenants/ctv.rs` — changed
  `crate::script::Script` to `crate::primitives::Script`; changed
  `crate::crypto::hashing::sha256` to `crate::hashing::sha256`.
- All files across the crate — bulk-redirected `crate::crypto::hashing`
  to `crate::hashing` (20+ files).

## Resulting dependency order

```
hashing          (leaf — no intra-crate deps)
  ↑
primitives       (depends on hashing only)
  ↑
covenants        (depends on hashing, primitives)
crypto           (depends on hashing, primitives)
  ↑
script           (depends on crypto, covenants, primitives, hashing)
  ↑
wallet           (depends on script, crypto, primitives, hashing)
consensus, protocol, filters, utxo, policy, chain_params  (various deps)
```

All edges are unidirectional. No cycles remain.
