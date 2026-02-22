//! Bitcoin chain parameters
//!
//! Network-specific configuration including magic bytes, ports, DNS seeds, and genesis blocks.

use crate::consensus::ConsensusParams;
pub use crate::consensus::Network;
use crate::primitives::hash::BlockHash;
use crate::primitives::Amount;
use crate::primitives::{Block, BlockHeader, Hash256, Transaction, TxOut};
use crate::script::Script;

/// A hardcoded checkpoint: a known-good (height, block hash) pair.
///
/// These protect against long-range attacks by ensuring the node cannot
/// be fed an alternative chain that diverges before a checkpoint.
#[derive(Debug, Clone)]
pub struct Checkpoint {
    /// Block height of the checkpoint.
    pub height: u32,
    /// Expected block hash at that height (big-endian hex).
    pub hash_hex: &'static str,
}

/// Bitcoin chain parameters for a specific network
#[derive(Debug, Clone)]
pub struct ChainParams {
    /// Network type
    pub network: Network,

    /// Network magic bytes for P2P protocol
    pub magic_bytes: [u8; 4],

    /// Default P2P port
    pub p2p_port: u16,

    /// Default RPC port
    pub rpc_port: u16,

    /// DNS seeds for peer discovery
    pub dns_seeds: Vec<&'static str>,

    /// Consensus parameters
    pub consensus: ConsensusParams,

    /// Hardcoded checkpoints for this network.
    ///
    /// During header validation, the block index verifies that headers at
    /// checkpoint heights match the expected hash, preventing long-range
    /// alternative-chain attacks.
    pub checkpoints: Vec<Checkpoint>,
}

impl ChainParams {
    /// Get chain parameters for mainnet
    pub fn mainnet() -> Self {
        ChainParams {
            network: Network::Mainnet,
            magic_bytes: [0xf9, 0xbe, 0xb4, 0xd9],
            p2p_port: 8333,
            rpc_port: 8332,
            dns_seeds: vec![
                "seed.bitcoin.sipa.be",
                "dnsseed.bluematt.me",
                "dnsseed.bitcoin.dashjr.org",
                "seed.bitcoinstats.com",
                "seed.bitcoin.jonasschnelli.ch",
                "seed.btc.petertodd.org",
                "seed.bitcoin.sprovoost.nl",
                "dnsseed.emzy.de",
                "seed.bitcoin.wiz.biz",
                "seeds.bitcoin.petertodd.org",
            ],
            consensus: ConsensusParams::mainnet(),
            checkpoints: vec![
                Checkpoint {
                    height: 11111,
                    hash_hex: "0000000069e244f73d78e8fd29ba2fd2ed618bd6fa2ee92559f542fdb26e7c1d",
                },
                Checkpoint {
                    height: 33333,
                    hash_hex: "000000002dd5588a74784eaa7ab0507a18ad16a236e7b1ce69f00d7ddfb5d0a6",
                },
                Checkpoint {
                    height: 74000,
                    hash_hex: "0000000000573993a3c9e41ce34471c079dcf5f52a0e824a81e7f953b8661a20",
                },
                Checkpoint {
                    height: 105000,
                    hash_hex: "00000000000291ce28027faea320c8d2b054b2e0fe44a773f3eefb151d6bdc97",
                },
                Checkpoint {
                    height: 134444,
                    hash_hex: "00000000000005b12ffd4cd315cd34ffd4a594f430ac814c91184a0d42d2b0fe",
                },
                Checkpoint {
                    height: 168000,
                    hash_hex: "000000000000099e61ea72015e79632f216fe6cb33d7899acb35b75c8303b763",
                },
                Checkpoint {
                    height: 193000,
                    hash_hex: "000000000000059f452a5f7340de6682a977387c17010ff6e6c3bd83ca8b1317",
                },
                Checkpoint {
                    height: 210000,
                    hash_hex: "000000000000048b95347e83192f69cf0366076336c639f9b7228e9ba171342e",
                },
                Checkpoint {
                    height: 216116,
                    hash_hex: "00000000000001b4f4b433e81ee46494af945cf96014816a4e2370f11b23df4e",
                },
                Checkpoint {
                    height: 225430,
                    hash_hex: "00000000000001c108384350f74090433e7fcf79a606b8e797f065b130575932",
                },
                Checkpoint {
                    height: 250000,
                    hash_hex: "000000000000003887df1f29024b06fc2200b55f8af8f35453d7be294df2d214",
                },
                Checkpoint {
                    height: 279000,
                    hash_hex: "0000000000000001ae8c72a0b0c301f67e3afca10e819efa9041e458e9bd7e40",
                },
                Checkpoint {
                    height: 295000,
                    hash_hex: "00000000000000004d9b4ef50f0f9d686fd69db2e03af35a100370c64632473f",
                },
            ],
        }
    }

    /// Get chain parameters for testnet
    pub fn testnet() -> Self {
        ChainParams {
            network: Network::Testnet,
            magic_bytes: [0x0b, 0x11, 0x09, 0x07],
            p2p_port: 18333,
            rpc_port: 18332,
            dns_seeds: vec![
                "testnet-seed.bitcoin.jonasschnelli.ch",
                "seed.tbtc.petertodd.org",
                "testnet-seed.bluematt.me",
                "testnet-seed.bitcoin.schildbach.de",
            ],
            consensus: ConsensusParams::testnet(),
            checkpoints: vec![Checkpoint {
                height: 546,
                hash_hex: "000000002a936ca763904c3c35fce2f3556c559c0214345d31b1bcebf76acb70",
            }],
        }
    }

    /// Get chain parameters for regtest
    pub fn regtest() -> Self {
        ChainParams {
            network: Network::Regtest,
            magic_bytes: [0xfa, 0xbf, 0xb5, 0xda],
            p2p_port: 18444,
            rpc_port: 18443,
            dns_seeds: vec![],
            consensus: ConsensusParams::regtest(),
            checkpoints: vec![],
        }
    }

    /// Get chain parameters for signet
    pub fn signet() -> Self {
        ChainParams {
            network: Network::Signet,
            magic_bytes: [0x0a, 0x03, 0xcf, 0x40],
            p2p_port: 38333,
            rpc_port: 38332,
            dns_seeds: vec!["signet-seed.example.com"],
            consensus: ConsensusParams::signet(),
            checkpoints: vec![],
        }
    }

    /// Get chain parameters for a network
    pub fn for_network(network: Network) -> Self {
        match network {
            Network::Mainnet => ChainParams::mainnet(),
            Network::Testnet => ChainParams::testnet(),
            Network::Regtest => ChainParams::regtest(),
            Network::Signet => ChainParams::signet(),
        }
    }

    /// Get the checkpoint hash for a given height, if one exists.
    pub fn get_checkpoint(&self, height: u32) -> Option<&str> {
        self.checkpoints
            .iter()
            .find(|cp| cp.height == height)
            .map(|cp| cp.hash_hex)
    }

    /// Get the highest checkpoint height, or 0 if there are none.
    pub fn last_checkpoint_height(&self) -> u32 {
        self.checkpoints
            .iter()
            .map(|cp| cp.height)
            .max()
            .unwrap_or(0)
    }

    /// Verify that a block hash at a given height matches the checkpoint.
    ///
    /// Returns `true` if there is no checkpoint at that height, or if the
    /// hash matches. Returns `false` only when there IS a checkpoint and
    /// the hash does NOT match.
    pub fn verify_checkpoint(&self, height: u32, hash: &BlockHash) -> bool {
        match self.get_checkpoint(height) {
            Some(expected_hex) => hash.to_hex_reversed() == expected_hex,
            None => true, // No checkpoint at this height → OK
        }
    }

    /// Get the genesis block for this network
    pub fn genesis_block(&self) -> Block {
        match self.network {
            Network::Mainnet => genesis_mainnet(),
            Network::Testnet => genesis_testnet(),
            Network::Regtest => genesis_regtest(),
            Network::Signet => genesis_signet(),
        }
    }
}

impl Default for ChainParams {
    fn default() -> Self {
        ChainParams::mainnet()
    }
}

/// Generate the Bitcoin mainnet genesis block
fn genesis_mainnet() -> Block {
    let header = BlockHeader::new(
        1,
        BlockHash::zero(),
        Hash256::zero(),
        1231006505, // Jan 3, 2009
        0x207fffff,
        2083236893,
    );

    let coinbase = Transaction::coinbase(
        1,
        Script::from_slice(b""),
        vec![TxOut::new(
            Amount::from_sat(5000000000),
            Script::from_slice(b""),
        )],
    );

    Block::new(header, vec![coinbase])
}

/// Generate the Bitcoin testnet genesis block
fn genesis_testnet() -> Block {
    let header = BlockHeader::new(
        1,
        BlockHash::zero(),
        Hash256::zero(),
        1296688602,
        0x207fffff,
        414098458,
    );

    let coinbase = Transaction::coinbase(
        1,
        Script::from_slice(b""),
        vec![TxOut::new(
            Amount::from_sat(5000000000),
            Script::from_slice(b""),
        )],
    );

    Block::new(header, vec![coinbase])
}

/// Generate the Bitcoin regtest genesis block
fn genesis_regtest() -> Block {
    let header = BlockHeader::new(
        1,
        BlockHash::zero(),
        Hash256::zero(),
        1296688602,
        0x207fffff,
        2,
    );

    let coinbase = Transaction::coinbase(
        1,
        Script::from_slice(&[0x04, 0x23, 0x61, 0x30]),
        vec![TxOut::new(
            Amount::from_sat(5000000000),
            Script::from_slice(b""),
        )],
    );

    Block::new(header, vec![coinbase])
}

/// Generate the Bitcoin signet genesis block
fn genesis_signet() -> Block {
    let header = BlockHeader::new(
        0x20000000,
        BlockHash::zero(),
        Hash256::zero(),
        1598918400,
        0x1d00ffff,
        52613,
    );

    let coinbase = Transaction::coinbase(
        1,
        Script::from_slice(b""),
        vec![TxOut::new(
            Amount::from_sat(5000000000),
            Script::from_slice(b""),
        )],
    );

    Block::new(header, vec![coinbase])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mainnet_params() {
        let params = ChainParams::mainnet();
        assert_eq!(params.network, Network::Mainnet);
        assert_eq!(params.magic_bytes, [0xf9, 0xbe, 0xb4, 0xd9]);
        assert_eq!(params.p2p_port, 8333);
    }

    #[test]
    fn test_testnet_params() {
        let params = ChainParams::testnet();
        assert_eq!(params.network, Network::Testnet);
        assert_eq!(params.magic_bytes, [0x0b, 0x11, 0x09, 0x07]);
        assert_eq!(params.p2p_port, 18333);
    }

    #[test]
    fn test_regtest_params() {
        let params = ChainParams::regtest();
        assert_eq!(params.network, Network::Regtest);
        assert_eq!(params.magic_bytes, [0xfa, 0xbf, 0xb5, 0xda]);
    }

    #[test]
    fn test_for_network() {
        let mainnet = ChainParams::for_network(Network::Mainnet);
        assert_eq!(mainnet.network, Network::Mainnet);
    }

    #[test]
    fn test_mainnet_has_checkpoints() {
        let params = ChainParams::mainnet();
        assert!(!params.checkpoints.is_empty());
        assert!(params.checkpoints.len() >= 10);
    }

    #[test]
    fn test_regtest_has_no_checkpoints() {
        let params = ChainParams::regtest();
        assert!(params.checkpoints.is_empty());
    }

    #[test]
    fn test_last_checkpoint_height() {
        let params = ChainParams::mainnet();
        assert!(params.last_checkpoint_height() > 0);
        assert_eq!(params.last_checkpoint_height(), 295000);
    }

    #[test]
    fn test_get_checkpoint() {
        let params = ChainParams::mainnet();
        let cp = params.get_checkpoint(11111);
        assert!(cp.is_some());
        assert!(cp.unwrap().starts_with("0000000069e2"));
    }

    #[test]
    fn test_get_checkpoint_nonexistent() {
        let params = ChainParams::mainnet();
        assert!(params.get_checkpoint(12345).is_none());
    }
}
