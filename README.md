# agentic-bitcoin

A from-scratch reimplementation of Bitcoin Core in Rust, built using hexagonal (ports-and-adapters) architecture.

> **WARNING: EXPERIMENTAL SOFTWARE — NOT FOR PRODUCTION USE**
>
> This project is an educational and research implementation. It has **not** been audited, fuzzed at scale, or battle-tested against adversarial inputs. **Do not use this software to operate a Bitcoin node, manage real funds, or for any purpose involving real money.** Doing so could result in loss of funds, consensus failures, or security vulnerabilities. Use Bitcoin Core or another well-established implementation for anything involving mainnet bitcoin.

## What Is This?

agentic-bitcoin is a clean-room Rust implementation of Bitcoin's core subsystems — consensus rules, script interpreter, transaction signing, wallet operations, P2P networking, and block validation — structured as a modular workspace of five crates organized around hexagonal architecture. The domain logic contains zero infrastructure dependencies, making it straightforward to test, reason about, and extend.

The project was built collaboratively between a human and an AI pair-programming partner, session by session, with each session adding a new subsystem or capability.

## Architecture

```
┌─────────────────────────────────────────────────────┐
│              abtc-infrastructure                     │
│            (Node wiring, composition)                │
├──────────────────────┬──────────────────────────────┤
│   abtc-application   │       abtc-adapters           │
│  (Services, use      │  (In-memory implementations   │
│   cases, handlers)   │   of port traits)             │
├──────────────────────┴──────────────────────────────┤
│                   abtc-ports                          │
│           (Trait interfaces only)                     │
├─────────────────────────────────────────────────────┤
│                   abtc-domain                         │
│  (Pure domain logic: primitives, consensus, script,  │
│   crypto, wallet — zero infrastructure deps)         │
└─────────────────────────────────────────────────────┘
```

The five crates, from innermost to outermost:

- **abtc-domain** — Core types, consensus rules, script interpreter (all opcodes including SegWit v0 and v1), wallet (HD/BIP32/BIP44, PSBT/BIP174, coin selection, transaction builder), and crypto (SHA-256, RIPEMD-160, secp256k1, Schnorr/BIP340, Taproot/BIP341/BIP342). Pure logic with no I/O.
- **abtc-ports** — Trait definitions for storage, mempool, wallet, mining, network, and RPC. No implementations.
- **abtc-adapters** — In-memory implementations of all port traits. Suitable for testing and lightweight usage.
- **abtc-application** — Services and use cases: chain state management, P2P message processing, block templates, mining, fee estimation, mempool acceptance, compact blocks (BIP152), download scheduling, peer scoring, orphan pool, transaction rebroadcast, RPC handlers, and chain event notifications.
- **abtc-infrastructure** — Top-level node composition that wires everything together.

See [CRATES.md](CRATES.md) for a detailed guide on which crate to depend on for your use case.

## What's Implemented

- **Full script interpreter** with all standard opcodes, including SegWit v0 (P2WPKH, P2WSH) and SegWit v1 (P2TR key-path and script-path)
- **Taproot (BIP341/BIP342)** — TapTree construction, script-path sighash, OP_CHECKSIGADD, control blocks, Schnorr signing (tweaked and untweaked)
- **Schnorr signatures (BIP340)** — sign, verify, key tweaking, x-only pubkeys
- **HD wallets (BIP32/BIP44)** — master key derivation, hardened/normal child keys, xprv/xpub/tprv serialization, multi-account derivation paths
- **PSBT (BIP174)** — create, add inputs/outputs, sign, combine multi-signer, finalize (legacy, witness, and Taproot), serialize/deserialize, extract final transaction
- **Transaction builder** — P2PKH, P2WPKH, P2SH-P2WPKH, and P2TR signing with automatic script construction
- **Coin selection** — largest-first, smallest-first, closest-match strategies with change calculation
- **Address encoding** — P2PKH, P2SH, P2WPKH (bech32/BIP173), P2TR (bech32m/BIP350), with mainnet/testnet/regtest support
- **Block validation** — full block connection/disconnection with UTXO set management, merkle root verification, subsidy checks, coinbase maturity
- **P2P networking** — version handshake, peer discovery, block/transaction relay, inv/getdata/getblocks message handling
- **Compact blocks (BIP152)** — SipHash-based short txids, block reconstruction from mempool
- **Fee estimation** — sliding window of block median fee rates
- **Mempool** — ancestor/descendant tracking, RBF (BIP125), CPFP, eviction, mining candidate selection
- **Peer scoring** — misbehavior tracking with cumulative scoring, automatic banning, ban expiry
- **Download scheduler** — peer selection, inflight tracking, timeout detection, stale tip monitoring
- **Orphan pool** — orphan transaction management with peer tracking and expiry
- **Rebroadcast manager** — automatic transaction rebroadcast with attempt limits
- **Chain events** — publish/subscribe notification bus for block connected/disconnected and transaction events
- **RPC handler framework** — JSON-RPC dispatch with getblock, getrawtransaction, estimatesmartfee, and more

## Test Suite

612 tests across all crates, all passing with zero warnings.

```
abtc-domain                266 tests
abtc-application (unit)    178 tests
abtc-application (integ)    20 tests
abtc-adapters               76 tests
abtc-infrastructure         10 tests
block_validation_tests      16 tests
tx_validation_tests         34 tests
script_tests                 8 tests
benchmarks                   4 tests
```

## Building and Testing

```bash
cargo check --workspace
cargo test --workspace
```

## Lite vs Full

The current implementation (the "Lite" variant) prioritizes correctness over production-scale performance. Every algorithm, validation rule, and protocol behavior matches Bitcoin Core — but the backing data structures are in-memory HashMaps rather than disk-optimized databases, and execution is single-threaded rather than parallel.

A future "Full" variant will add the infrastructure needed for mainnet-scale load (~180M UTXOs, thousands of peers, multi-GB block storage). The hexagonal architecture makes this feasible: most upgrades are new adapters behind existing port traits, with no changes to domain logic or consensus rules. See SESSION_NOTES.md for the detailed upgrade path for each subsystem.

## Roadmap

- Wallet persistence (serialize/deserialize wallet state to disk)
- BIP325 Signet support (custom signets with challenge scripts)
- Miniscript and output descriptors (policy compilation, descriptor parsing, script generation)

## License

MIT — see [LICENSE](LICENSE) for details.
