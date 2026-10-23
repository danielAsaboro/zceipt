//! Receipts for mobile wallets, over uniffi: the calls a wallet's signer and a verifier need,
//! with Swift and Kotlin bindings generated into `bindings/` (see README.md).
//!
//! Making the proofs needs the wallet's notes and their Merkle paths, which live in the wallet's
//! own Rust core; that half stays in Rust (`receipts_core::ReceiptBuilder`). What crosses the
//! boundary is text: the `zip311u1…` prepared receipt in, the `zip311r1…` receipt out.

uniffi::setup_scaffolding!();

#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum ReceiptError {
    #[error("{reason}")]
    Refused { reason: String },
}

fn refused(e: impl std::fmt::Display) -> ReceiptError {
    ReceiptError::Refused { reason: e.to_string() }
}

/// Signs a prepared receipt (`zip311u1…`, from `ReceiptBuilder::prepare` on the watch-only side)
/// with the 32-byte Orchard spending key, after checking that this key made its spends. With
/// `message`, signs for that message instead of the prepared one. Returns `zip311r1…` text.
#[uniffi::export]
pub fn sign_prepared(prepared: String, spending_key: Vec<u8>, message: Option<String>) -> Result<String, ReceiptError> {
    let mut p = receipts_core::PreparedReceipt::from_text(&prepared).map_err(refused)?;
    if let Some(m) = message {
        p = p.with_message(m.as_bytes()).map_err(refused)?;
    }
    let key: [u8; 32] = spending_key.try_into().map_err(|_| refused("the spending key is 32 bytes"))?;
    let sk = Option::from(orchard::keys::SpendingKey::from_bytes(key)).ok_or_else(|| refused("not an Orchard spending key"))?;
    let asks = vec![orchard::keys::SpendAuthorizingKey::from(&sk); p.unsigned().spends.len()];
    let sigs = receipts_core::sign_prepared(p.unsigned(), p.alphas(), &asks, rand::rand_core::UnwrapErr(rand::rngs::SysRng)).map_err(refused)?;
    Ok(p.apply_signatures(sigs).map_err(refused)?.to_text())
}

/// What a prepared receipt will disclose, as JSON, for the signer's confirmation screen:
/// `{ network, txid, message, outputs, spends }`.
#[uniffi::export]
pub fn describe_prepared(prepared: String) -> Result<String, ReceiptError> {
    let p = receipts_core::PreparedReceipt::from_text(&prepared).map_err(refused)?;
    let u = p.unsigned();
    Ok(serde_json::json!({
        "network": if u.coin_type == receipts_core::COIN_TYPE_MAINNET { "mainnet" } else { "testnet" },
        "txid": receipts_core::display_txid(&u.txid),
        "message": String::from_utf8_lossy(&u.msg),
        "outputs": u.outputs.len(),
        "spends": u.spends.len(),
    })
    .to_string())
}

/// Verifies a receipt against the raw transaction (hex) mined at `height`, which the caller
/// fetched itself. Returns the report as JSON (`valid`, `outputs`, `message`, …).
#[uniffi::export]
pub fn verify_receipt(receipt: String, raw_tx_hex: String, height: u32) -> Result<String, ReceiptError> {
    let text = receipt.find("zip311r1").map(|i| &receipt[i..]).ok_or_else(|| refused("no zip311r1… receipt in the input"))?;
    let text = text.split(|c: char| !(c.is_ascii_alphanumeric() || c == '_' || c == '-')).next().unwrap_or("");
    let r = receipts_core::Receipt::from_text(text).map_err(refused)?;
    let report = receipts_chain::chain::verify_offline(&r, &raw_tx_hex, height, None).map_err(refused)?;
    serde_json::to_string(&report).map_err(refused)
}

/// The challenge a receipt's message carries (ZIP311-ORCHARD.md), if any.
#[uniffi::export]
pub fn challenge_of(message: String) -> Option<String> {
    receipts_core::challenge_of(&message)
}

#[cfg(test)]
mod tests {
    use super::*;
    const DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../examples/testnet/demo/");

    fn read(f: &str) -> String {
        std::fs::read_to_string(format!("{DIR}{f}")).unwrap().trim().to_string()
    }

    #[test]
    fn signs_and_verifies_the_demo_payment() {
        let key = read("orchard-spending-key.hex");
        let key: Vec<u8> = (0..key.len()).step_by(2).map(|i| u8::from_str_radix(&key[i..i + 2], 16).unwrap()).collect();
        let about: serde_json::Value = serde_json::from_str(&describe_prepared(read("prepared.txt")).unwrap()).unwrap();
        assert_eq!(about["spends"], 1);
        let receipt = sign_prepared(read("prepared.txt"), key.clone(), Some("challenge:0ff1ce".into())).unwrap();
        let report: serde_json::Value = serde_json::from_str(&verify_receipt(receipt, read("tx.hex"), 4_532_976).unwrap()).unwrap();
        assert_eq!(report["message"], "challenge:0ff1ce");
        assert_eq!(report["public_demo"], true);
        assert_eq!(challenge_of(report["message"].as_str().unwrap().into()).as_deref(), Some("0ff1ce"));
        let mut wrong = key;
        wrong[0] ^= 1;
        assert!(sign_prepared(read("prepared.txt"), wrong, None).is_err());
    }
}
