//! Network parameters: mainnet, testnet, or a local regtest chain with chosen activation heights.

use anyhow::{anyhow, bail};
use serde::Deserialize;
use std::path::Path;
use zcash_protocol::consensus::{BlockHeight, Network, NetworkType, NetworkUpgrade, Parameters};
use zcash_protocol::local_consensus::LocalNetwork;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Net {
    Main,
    Test,
    Regtest(LocalNetwork),
}

impl Parameters for Net {
    fn network_type(&self) -> NetworkType {
        match self {
            Net::Main => NetworkType::Main,
            Net::Test => NetworkType::Test,
            Net::Regtest(_) => NetworkType::Regtest,
        }
    }
    fn activation_height(&self, nu: NetworkUpgrade) -> Option<BlockHeight> {
        match self {
            Net::Main => Network::MainNetwork.activation_height(nu),
            Net::Test => Network::TestNetwork.activation_height(nu),
            Net::Regtest(l) => l.activation_height(nu),
        }
    }
}

impl Net {
    pub fn coin_type(&self) -> u32 {
        match self {
            Net::Main => receipts_core::COIN_TYPE_MAINNET,
            _ => receipts_core::COIN_TYPE_TESTNET,
        }
    }
    pub fn name(&self) -> &'static str {
        match self {
            Net::Main => "mainnet",
            Net::Test => "testnet",
            Net::Regtest(_) => "regtest",
        }
    }
    pub fn default_server(&self) -> &'static str {
        match self {
            Net::Main => "zec.rocks:443",
            Net::Test => "testnet.zec.rocks:443",
            Net::Regtest(_) => "127.0.0.1:9067",
        }
    }
}

/// Activation heights in zcash-devtool's format (`nu5 = 1`, `nu6_3 = 1`, or `"never"`).
#[derive(Deserialize, Default)]
pub struct Heights {
    overwinter: Option<toml::Value>,
    sapling: Option<toml::Value>,
    blossom: Option<toml::Value>,
    heartwood: Option<toml::Value>,
    canopy: Option<toml::Value>,
    nu5: Option<toml::Value>,
    nu6: Option<toml::Value>,
    nu6_1: Option<toml::Value>,
    nu6_2: Option<toml::Value>,
    nu6_3: Option<toml::Value>,
    nu7: Option<toml::Value>,
}

impl Heights {
    pub fn to_local(&self) -> LocalNetwork {
        let h = |v: &Option<toml::Value>| v.as_ref().and_then(|v| v.as_integer()).map(|i| BlockHeight::from_u32(i as u32));
        LocalNetwork {
            overwinter: h(&self.overwinter),
            sapling: h(&self.sapling),
            blossom: h(&self.blossom),
            heartwood: h(&self.heartwood),
            canopy: h(&self.canopy),
            nu5: h(&self.nu5),
            nu6: h(&self.nu6),
            nu6_1: h(&self.nu6_1),
            nu6_2: h(&self.nu6_2),
            nu6_3: h(&self.nu6_3),
            nu7: h(&self.nu7),
        }
    }
}

pub fn regtest_from_file(path: &Path) -> anyhow::Result<Net> {
    let h: Heights = toml::from_str(&std::fs::read_to_string(path)?).map_err(|e| anyhow!("parsing {}: {e}", path.display()))?;
    Ok(Net::Regtest(h.to_local()))
}

/// The network the verifier expects (`main` or `test`), when it said so.
pub static EXPECTED: std::sync::OnceLock<&'static str> = std::sync::OnceLock::new();

/// The network a receipt was made for. Regtest receipts carry the testnet coin type, so the
/// caller says explicitly when it is verifying against a local chain.
pub fn for_receipt(coin_type: u32, regtest: Option<&Path>) -> anyhow::Result<Net> {
    // A verifier that said which network it works on (`--network`) refuses artifacts of the other:
    // a mainnet airdrop must not accept a testnet claim.
    if let (Some(want), None) = (EXPECTED.get(), regtest) {
        let have = if coin_type == receipts_core::COIN_TYPE_MAINNET { "main" } else { "test" };
        if have != *want {
            bail!("this is a {have}net artifact, but --network {want} was given");
        }
    }
    if let Some(p) = regtest {
        return regtest_from_file(p);
    }
    match coin_type {
        receipts_core::COIN_TYPE_MAINNET => Ok(Net::Main),
        receipts_core::COIN_TYPE_TESTNET => Ok(Net::Test),
        c => bail!("unknown coin type {c}"),
    }
}
