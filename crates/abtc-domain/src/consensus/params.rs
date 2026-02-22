//! Bitcoin consensus parameters
//!
//! Contains all consensus parameters for different networks (mainnet, testnet, regtest, signet).

use crate::primitives::hash::BlockHash;

/// Network types for Bitcoin
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Network {
    /// Bitcoin Mainnet
    Mainnet,
    /// Bitcoin Testnet (v3)
    Testnet,
    /// Regression Test Network
    Regtest,
    /// Signet (BIP325)
    Signet,
}

impl std::fmt::Display for Network {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Network::Mainnet => write!(f, "mainnet"),
            Network::Testnet => write!(f, "testnet3"),
            Network::Regtest => write!(f, "regtest"),
            Network::Signet => write!(f, "signet"),
        }
    }
}

/// Bitcoin consensus parameters
#[derive(Debug, Clone)]
pub struct ConsensusParams {
    /// Network type
    pub network: Network,

    // Block and transaction parameters
    /// Genesis block hash
    pub genesis_hash: BlockHash,

    /// Block subsidy halving interval (210,000 blocks)
    pub subsidy_halving_interval: u32,

    /// BIP34 activation height
    pub bip34_height: u32,

    /// BIP65 (CLTV) activation height
    pub bip65_height: u32,

    /// BIP66 (DER signatures) activation height
    pub bip66_height: u32,

    /// Check sequence verify (BIP112) activation height
    pub csv_height: u32,

    /// SegWit (BIP141) activation height
    pub segwit_height: u32,

    // Proof of Work parameters
    /// Maximum target (minimum difficulty) in compact nBits format
    pub pow_limit_bits: u32,

    /// Target timespan for difficulty adjustment (2 weeks in seconds)
    pub pow_target_timespan: u32,

    /// Target block spacing (10 minutes in seconds)
    pub pow_target_spacing: u32,

    /// Whether to allow minimum difficulty blocks
    pub allow_min_difficulty: bool,

    /// Whether retargeting is disabled
    pub no_retargeting: bool,

    // Chain validation parameters
    /// Minimum chain work for syncing
    pub minimum_chain_work: u128,

    /// Default assume valid block hash
    pub default_assume_valid: Option<BlockHash>,

    // Signet parameters
    /// Signet challenge
    pub signet_challenge: Option<Vec<u8>>,
}

impl ConsensusParams {
    /// Create parameters for mainnet
    pub fn mainnet() -> Self {
        ConsensusParams {
            network: Network::Mainnet,
            genesis_hash: BlockHash::genesis_mainnet(),
            subsidy_halving_interval: 210_000,
            bip34_height: 227_931,
            bip65_height: 388_381,
            bip66_height: 363_725,
            csv_height: 419_328,
            segwit_height: 481_824,
            pow_limit_bits: 0x1d00ffff,
            pow_target_timespan: 14 * 24 * 60 * 60, // 2 weeks
            pow_target_spacing: 10 * 60,            // 10 minutes
            allow_min_difficulty: false,
            no_retargeting: false,
            minimum_chain_work: 0,
            default_assume_valid: Some(
                BlockHash::from_hex(
                    "0000000000000000000b9835120b6817ee0e5ff0bcc6749265323a75713baf5d",
                )
                .unwrap(),
            ),
            signet_challenge: None,
        }
    }

    /// Create parameters for testnet
    pub fn testnet() -> Self {
        ConsensusParams {
            network: Network::Testnet,
            genesis_hash: BlockHash::from_hex(
                "000000000933ea01ad0ee984209779bafec8473f9f36e6e15d2d241ebee8ce3c",
            )
            .unwrap(),
            subsidy_halving_interval: 210_000,
            bip34_height: 21_111,
            bip65_height: 581_885,
            bip66_height: 330_776,
            csv_height: 770_113,
            segwit_height: 834_624,
            pow_limit_bits: 0x1d00ffff,
            pow_target_timespan: 14 * 24 * 60 * 60, // 2 weeks
            pow_target_spacing: 10 * 60,            // 10 minutes
            allow_min_difficulty: true,
            no_retargeting: false,
            minimum_chain_work: 0,
            default_assume_valid: Some(
                BlockHash::from_hex(
                    "000000000000004f465f02e037194370514122bf7a898e59fce40f48b47ca267",
                )
                .unwrap(),
            ),
            signet_challenge: None,
        }
    }

    /// Create parameters for regtest
    pub fn regtest() -> Self {
        ConsensusParams {
            network: Network::Regtest,
            genesis_hash: BlockHash::from_hex(
                "06226b7fb5f6ea97eac9a6405e773f6a14ee45dafaf8e1f4e79f7ef2e1f62f27",
            )
            .unwrap(),
            subsidy_halving_interval: 150,
            bip34_height: 100_000_000,
            bip65_height: 1_351_,
            bip66_height: 1_251_,
            csv_height: 432_,
            segwit_height: 0,
            pow_limit_bits: 0x207fffff,
            pow_target_timespan: 14 * 24 * 60 * 60,
            pow_target_spacing: 10 * 60,
            allow_min_difficulty: true,
            no_retargeting: true,
            minimum_chain_work: 0,
            default_assume_valid: None,
            signet_challenge: None,
        }
    }

    /// Create parameters for signet
    pub fn signet() -> Self {
        ConsensusParams {
            network: Network::Signet,
            genesis_hash: BlockHash::from_hex(
                "f61eee3b63a380a477a063af32c9cdca5ccdcdfaacf412cdf5056924f45ceae0",
            )
            .unwrap(),
            subsidy_halving_interval: 210_000,
            bip34_height: 0,
            bip65_height: 0,
            bip66_height: 0,
            csv_height: 1,
            segwit_height: 0,
            pow_limit_bits: 0x1e0377ae,
            pow_target_timespan: 14 * 24 * 60 * 60,
            pow_target_spacing: 10 * 60,
            allow_min_difficulty: false,
            no_retargeting: false,
            minimum_chain_work: 0,
            default_assume_valid: Some(
                BlockHash::from_hex(
                    "03fcc5b66f08588bbfdcf1b7e9c80e1b8d70d7c8f18e2e9a3b4c5d6e7f8a9b0c",
                )
                .unwrap(),
            ),
            signet_challenge: Some(vec![
                0x51, 0x21, // OP_1 + push 33 bytes
                0xaa, 0x21, 0xa9, 0xed, 0x75, 0x2f, 0xd4, 0xa7, 0x34, 0xbd, 0xef, 0xbc, 0xaa, 0xd6,
                0xcf, 0x9b, 0x5f, 0x01, 0x3a, 0x51, 0x2e, 0xf1, 0xb7, 0x42, 0x7c, 0xef, 0xc8, 0xc7,
                0x27, 0x80, 0x62, 0x96, 0x92, 0x55, // pubkey
                0x51, // OP_1
            ]),
        }
    }

    /// Get consensus params for a network
    pub fn for_network(network: Network) -> Self {
        match network {
            Network::Mainnet => ConsensusParams::mainnet(),
            Network::Testnet => ConsensusParams::testnet(),
            Network::Regtest => ConsensusParams::regtest(),
            Network::Signet => ConsensusParams::signet(),
        }
    }

    /// Get subsidy for a given block height
    pub fn get_block_subsidy(&self, height: u32) -> u64 {
        let halving = height / self.subsidy_halving_interval;
        if halving >= 64 {
            return 0;
        }
        5_000_000_000 >> halving
    }

    /// Check if feature is enabled at height
    pub fn is_bip34_enabled(&self, height: u32) -> bool {
        height >= self.bip34_height
    }

    pub fn is_bip65_enabled(&self, height: u32) -> bool {
        height >= self.bip65_height
    }

    pub fn is_bip66_enabled(&self, height: u32) -> bool {
        height >= self.bip66_height
    }

    pub fn is_csv_enabled(&self, height: u32) -> bool {
        height >= self.csv_height
    }

    pub fn is_segwit_enabled(&self, height: u32) -> bool {
        height >= self.segwit_height
    }
}

impl Default for ConsensusParams {
    fn default() -> Self {
        ConsensusParams::mainnet()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mainnet_params() {
        let params = ConsensusParams::mainnet();
        assert_eq!(params.network, Network::Mainnet);
        assert_eq!(params.subsidy_halving_interval, 210_000);
    }

    #[test]
    fn test_network_for_network() {
        let mainnet = ConsensusParams::for_network(Network::Mainnet);
        assert_eq!(mainnet.network, Network::Mainnet);
    }

    #[test]
    fn test_block_subsidy() {
        let params = ConsensusParams::mainnet();
        // Block 0
        assert_eq!(params.get_block_subsidy(0), 5_000_000_000);
        // Block 210,000 (first halving)
        assert_eq!(params.get_block_subsidy(210_000), 2_500_000_000);
        // Block 420,000 (second halving)
        assert_eq!(params.get_block_subsidy(420_000), 1_250_000_000);
    }
}
