//! Exchange deposits across the ZIP 320 TEX two-step.
//!
//! Exchanges with TEX addresses only accept funds from transparent inputs. A shielded wallet
//! pays one in two transactions: tx1 spends shielded notes to a fresh ephemeral transparent
//! address, tx2 spends that output to the TEX's P2PKH. Both are public on chain, but nothing
//! links them to the sender. A deposit receipt is a receipt for tx1 whose signed message names
//! the TEX address and tx2 (`tex-deposit:<tex>` and `second-tx:<txid>`); the verifier checks
//! the spend proof for tx1, that tx2 spends tx1's ephemeral output, and how much reached the TEX.
//!
//! Warning: the receipt proves that the holder of the shielded funds made this exchange
//! deposit. Whoever sees it (the exchange, a support agent) learns that link.

use crate::{display_txid, Receipt};
use zcash_address::{ConversionError, TryFromAddress, ZcashAddress};
use zcash_primitives::transaction::Transaction;
use zcash_protocol::consensus::NetworkType;

pub const WARNING: &str = "This receipt links the sender's shielded funds to an exchange deposit. Share it only with the exchange (or whoever must clear the deposit).";

struct Tex([u8; 20]);

impl TryFromAddress for Tex {
    type Error = ();
    fn try_from_tex(_net: NetworkType, data: [u8; 20]) -> Result<Self, ConversionError<Self::Error>> {
        Ok(Tex(data))
    }
}

/// The P2PKH hash inside a TEX address for `net`.
pub fn tex_p2pkh(tex: &str, net: NetworkType) -> Result<[u8; 20], String> {
    let a = ZcashAddress::try_from_encoded(tex).map_err(|e| format!("not a Zcash address: {e}"))?;
    let t: Tex = a.convert_if_network(net).map_err(|e| format!("{tex} is not a TEX address for this network: {e:?}"))?;
    Ok(t.0)
}

#[derive(Debug, Clone)]
pub struct Deposit {
    pub tex_address: String,
    pub deposit_zatoshis: u64,
    pub first_tx: String,
    pub second_tx: String,
    pub ephemeral_outputs: Vec<u32>,
    pub warning: &'static str,
}

/// The `tex-deposit:` and `second-tx:` lines a deposit receipt signs.
pub fn deposit_claim(message: &str) -> Option<(String, String)> {
    let tex = message.lines().find_map(|l| l.strip_prefix("tex-deposit:"))?.trim().to_string();
    let tx2 = message.lines().find_map(|l| l.strip_prefix("second-tx:"))?.trim().to_lowercase();
    Some((tex, tx2))
}

/// Checks the deposit claim against tx1 (the receipt's transaction) and tx2. Offline.
pub fn check(receipt: &Receipt, message: &str, net: NetworkType, tx1: &Transaction, tx2: &Transaction) -> Result<Deposit, String> {
    let (tex, tx2_id) = deposit_claim(message).ok_or_else(|| format!("this receipt does not sign a TEX deposit (no tex-deposit:/second-tx: lines)"))?;
    if display_txid(tx2.txid().as_ref()) != tx2_id {
        return Err("the second transaction is not the one the receipt names".into());
    }
    if tx1.txid().as_ref() != &receipt.unsigned.txid {
        return Err("the first transaction is not the receipt's".into());
    }
    let hash = tex_p2pkh(&tex, net)?;
    let t1 = tx1.transparent_bundle().ok_or_else(|| format!("the first transaction has no transparent output to an ephemeral address"))?;
    let t2 = tx2.transparent_bundle().ok_or_else(|| format!("the second transaction has no transparent part"))?;
    let mut spent = Vec::new();
    for i in &t2.vin {
        let p = i.prevout();
        if p.txid().as_ref() != &receipt.unsigned.txid {
            return Err("the second transaction also spends funds that did not come from the first one".into());
        }
        let n = p.n();
        t1.vout.get(n as usize).ok_or_else(|| format!("the second transaction spends an output the first one doesn't have"))?;
        spent.push(n);
    }
    if spent.is_empty() {
        return Err("the second transaction does not spend the first one's output".into());
    }
    let to_tex: u64 = t2
        .vout
        .iter()
        .filter(|o| matches!(o.recipient_address(), Some(zcash_transparent::address::TransparentAddress::PublicKeyHash(h)) if h == hash))
        .map(|o| u64::from(o.value()))
        .sum();
    if to_tex == 0 {
        return Err("the second transaction pays nothing to {tex}".into());
    }
    Ok(Deposit {
        tex_address: tex,
        deposit_zatoshis: to_tex,
        first_tx: display_txid(&receipt.unsigned.txid),
        second_tx: tx2_id,
        ephemeral_outputs: spent,
        warning: WARNING,
    })
}

impl Deposit {
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "tex_address": self.tex_address, "deposit_zatoshis": self.deposit_zatoshis, "first_tx": self.first_tx,
            "second_tx": self.second_tx, "ephemeral_outputs": self.ephemeral_outputs, "warning": self.warning,
        })
    }
}
