//! Exchange deposits across the ZIP 320 TEX two-step, verified against the chain. The offline
//! check is `zceipt_core::deposit`.

use crate::{chain, net::Net};
use anyhow::anyhow;
use zceipt_core::Receipt;
use zcash_protocol::consensus::NetworkType;

pub use zceipt_core::deposit::{check, deposit_claim, tex_p2pkh, Deposit, WARNING};

/// Verifies a deposit receipt against the chain: the spend proof for tx1, then the TEX hop.
pub async fn verify_against_chain(receipt: &Receipt, server: Option<&str>, regtest: Option<&std::path::Path>) -> anyhow::Result<(chain::Report, Deposit)> {
    let net = crate::net::for_receipt(receipt.unsigned.coin_type, regtest)?;
    let mut report = chain::verify_against_chain(receipt, server, regtest).await?;
    let (_, tx2_id) = deposit_claim(&report.message).ok_or_else(|| anyhow!("this receipt does not sign a TEX deposit"))?;
    let (tx1, _) = chain::fetch_mined_tx(net, server, receipt.unsigned.txid).await?;
    let mut id = [0u8; 32];
    hex::decode_to_slice(&tx2_id, &mut id).map_err(|_| anyhow!("bad second-tx id"))?;
    id.reverse();
    let (tx2, h2) = chain::fetch_mined_tx(net, server, id).await?;
    // The deposit is only as final as its later hop.
    report.mined_height = report.mined_height.max(h2);
    let d = check(receipt, &report.message, network_type(net), &tx1, &tx2).map_err(|e| anyhow!(e))?;
    Ok((report, d))
}

pub fn network_type(net: Net) -> NetworkType {
    match net {
        Net::Main => NetworkType::Main,
        Net::Test => NetworkType::Test,
        Net::Regtest(_) => NetworkType::Regtest,
    }
}
