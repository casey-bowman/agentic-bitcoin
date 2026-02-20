//! Bitcoin chain parameters
//!
//! Network-specific configuration including magic bytes, ports, DNS seeds, and genesis blocks.

pub use crate::consensus::Network;
use crate::consensus::ConsensusParams;
use crate::primitives::{Block, BlockHeader, Hash256, Transaction, TxOut};
use crate::primitives::hash::BlockHash;
use crate::primitives::Amount;
use crate::script::Script;

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
        }
    }

    /// Get chain parameters for signet
    pub fn signet() -> Self {
        ChainParams {
            network: Network::Signet,
            magic_bytes: [0x0a, 0x03, 0xcf, 0x40],
            p2p_port: 38333,
            rpc_port: 38332,
            dns_seeds: vec![
                "signet-seed.example.com",
            ],
            consensus: ConsensusParams::signet(),
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
        vec![
            TxOut::new(
                Amount::from_sat(5000000000),
                Script::from_slice(b""),
            ),
        ],
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
        vec![
            TxOut::new(
                Amount::from_sat(5000000000),
                Script::from_slice(b""),
            ),
        ],
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
        vec![
            TxOut::new(
                Amount::from_sat(5000000000),
                Script::from_slice(b""),
            ),
        ],
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
        vec![
            TxOut::new(
                Amount::from_sat(5000000000),
                Script::from_slice(b""),
            ),
        ],
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
}
