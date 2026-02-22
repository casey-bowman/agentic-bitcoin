//! # agentic-bitcoin
//!
//! A from-scratch reimplementation of the Bitcoin protocol in Rust, built using
//! hexagonal (ports-and-adapters) architecture.
//!
//! > **WARNING: EXPERIMENTAL SOFTWARE — NOT FOR PRODUCTION USE**
//! >
//! > This project is an educational and research implementation. It has not been audited,
//! > fuzzed at scale, or battle-tested against adversarial inputs. Do not use this software
//! > to operate a Bitcoin node, manage real funds, or for any purpose involving real money.
//!
//! ## Overview
//!
//! agentic-bitcoin is a clean-room Rust implementation of Bitcoin's core subsystems —
//! consensus rules, script interpreter, transaction signing, wallet operations, P2P networking,
//! and block validation — structured as a modular workspace of five crates. The domain logic
//! contains zero infrastructure dependencies, making it straightforward to test, reason about,
//! and extend.
//!
//! ## Architecture
//!
//! The project follows hexagonal (ports-and-adapters) architecture, organized as five crates
//! from innermost (pure logic) to outermost (wiring and I/O):
//!
//! ```text
//! ┌─────────────────────────────────────────────────────┐
//! │              abtc-infrastructure                     │
//! │            (Node wiring, composition)                │
//! ├──────────────────────┬──────────────────────────────┤
//! │   abtc-application   │       abtc-adapters           │
//! │  (Services, use      │  (In-memory implementations   │
//! │   cases, handlers)   │   of port traits)             │
//! ├──────────────────────┴──────────────────────────────┤
//! │                   abtc-ports                          │
//! │           (Trait interfaces only)                     │
//! ├─────────────────────────────────────────────────────┤
//! │                   abtc-domain                         │
//! │  (Pure domain logic: primitives, consensus, script,  │
//! │   crypto, wallet — zero infrastructure deps)         │
//! └─────────────────────────────────────────────────────┘
//! ```
//!
//! ## Workspace Crates
//!
//! ### [`abtc_domain`] — Domain Layer (innermost)
//!
//! Pure domain logic with zero infrastructure dependencies. Contains:
//!
//! - **Primitives**: [`Block`](abtc_domain::Block), [`Transaction`](abtc_domain::Transaction),
//!   [`Amount`](abtc_domain::Amount), [`BlockHeader`](abtc_domain::BlockHeader), and all core types
//! - **Consensus**: validation rules, network parameters, block connection/disconnection, signet support
//! - **Script**: full interpreter with all opcodes including SegWit v0/v1, Taproot (BIP341/342),
//!   and Miniscript support
//! - **Crypto**: SHA-256, RIPEMD-160, secp256k1, Schnorr/BIP340, tagged hashes, sighash computation
//! - **Wallet**: HD keys (BIP32/44), PSBT (BIP174), coin selection, transaction builder,
//!   bech32/bech32m address encoding
//! - **Filters**: BIP158 Golomb-coded set (GCS) compact block filters
//! - **Covenants**: OP_VAULT (BIP345) experimental support
//!
//! ### [`abtc_ports`] — Ports Layer
//!
//! Trait definitions (interfaces) that sit between the domain and adapters. Defines
//! contracts for storage, mempool, wallet, mining, network, and RPC — with no concrete
//! implementations.
//!
//! ### [`abtc_adapters`] — Adapter Layer
//!
//! Concrete implementations of the port traits:
//!
//! - [`InMemoryBlockStore`](abtc_adapters::InMemoryBlockStore) /
//!   [`InMemoryChainStateStore`](abtc_adapters::InMemoryChainStateStore) — hash-map-backed storage
//! - [`InMemoryMempool`](abtc_adapters::InMemoryMempool) — full mempool with ancestor/descendant
//!   tracking, RBF (BIP125), and CPFP
//! - [`InMemoryWallet`](abtc_adapters::InMemoryWallet) /
//!   [`PersistentWallet`](abtc_adapters::PersistentWallet) — wallet implementations
//! - [`TcpPeerManager`](abtc_adapters::TcpPeerManager) — real TCP P2P networking
//! - [`JsonRpcServer`](abtc_adapters::JsonRpcServer) — JSON-RPC server
//! - [`SimpleMiner`](abtc_adapters::SimpleMiner) — block template creation and mining
//!
//! ### [`abtc_application`] — Application Layer
//!
//! Services and use cases that orchestrate domain logic through the ports:
//!
//! - **Chain state**: block connection/disconnection with automatic reorg handling
//! - **Mempool acceptance**: transaction validation against consensus rules and policy
//! - **P2P sync**: version handshake, block download scheduling, header-first sync,
//!   compact blocks (BIP152)
//! - **Mining**: block template assembly with fee-maximizing transaction selection
//! - **Fee estimation**: sliding-window median fee rate tracking
//! - **RPC handlers**: JSON-RPC dispatch for `getblock`, `getrawtransaction`,
//!   `estimatesmartfee`, `sendrawtransaction`, and more
//! - **Peer scoring**: misbehavior tracking with automatic banning
//! - **Package relay**: BIP331 transaction package support
//!
//! ### [`abtc_infrastructure`] — Infrastructure Layer (outermost)
//!
//! Composition root that wires all crates together into a running Bitcoin node.
//! Handles CLI argument parsing, dependency injection, background task management,
//! and graceful shutdown via SIGINT/SIGTERM.
//!
//! ## What's Implemented
//!
//! - Full script interpreter with all standard opcodes, SegWit v0 (P2WPKH, P2WSH),
//!   and SegWit v1 (P2TR key-path and script-path)
//! - Taproot (BIP341/BIP342) — TapTree construction, script-path sighash,
//!   OP_CHECKSIGADD, control blocks
//! - Schnorr signatures (BIP340) — sign, verify, key tweaking, x-only pubkeys
//! - HD wallets (BIP32/BIP44) — master key derivation, hardened/normal child keys,
//!   xprv/xpub serialization
//! - PSBT (BIP174) — create, sign, combine, finalize, extract
//! - Coin selection — largest-first, smallest-first, closest-match strategies
//! - Address encoding — P2PKH, P2SH, P2WPKH (bech32), P2TR (bech32m)
//! - Block validation — full UTXO-set-based connection/disconnection
//! - P2P networking — version handshake, peer discovery, block/transaction relay
//! - Compact blocks (BIP152) — SipHash short txids, mempool reconstruction
//! - Mempool — ancestor/descendant tracking, RBF (BIP125), CPFP, eviction
//! - Fee estimation — sliding window of block median fee rates
//! - Peer scoring — misbehavior tracking with cumulative scoring and auto-banning
//! - Chain events — publish/subscribe notification bus
//! - JSON-RPC handler framework
//!
//! ## Quick Start
//!
//! ```bash,ignore
//! # Build the project
//! cargo build --workspace
//!
//! # Run all tests
//! cargo test --workspace
//!
//! # Start a regtest node
//! cargo run -- --network regtest
//!
//! # Generate API documentation
//! cargo doc --no-deps --workspace --open
//! ```
//!
//! ## License
//!
//! MIT — see the LICENSE-MIT file for details.
