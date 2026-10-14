//! Verifying receipts against the chain, with every failure mapped to a stable error code.

use crate::error::ApiError;
use receipts_chain::{chain, Net};
use receipts_core::{batch_position, display_txid, Pool, Receipt, ReceiptBatch, COIN_TYPE_MAINNET};
use serde::Serialize;
use std::sync::OnceLock;

fn vk() -> &'static orchard::circuit::VerifyingKey {
    static VK: OnceLock<orchard::circuit::VerifyingKey> = OnceLock::new();
    VK.get_or_init(receipts_core::verifying_key)
}

fn verify_slots() -> &'static tokio::sync::Semaphore {
    static S: OnceLock<tokio::sync::Semaphore> = OnceLock::new();
    S.get_or_init(|| tokio::sync::Semaphore::new(std::thread::available_parallelism().map(|n| n.get()).unwrap_or(4)))
}

/// Builds the verifying key on a blocking thread, so the first request is fast.
pub async fn warm_up() {
    let _ = tokio::task::spawn_blocking(|| {
        vk();
    })
    .await;
}

#[derive(Serialize, Clone, Debug)]
pub struct Output {
    pub action: u32,
    pub recipient: String,
    #[serde(skip)]
    pub recipient_raw: [u8; 43],
    pub zatoshis: u64,
    pub memo: Option<String>,
}

#[derive(Serialize, Clone, Debug)]
pub struct Verification {
    pub object: &'static str,
    pub valid: bool,
    pub livemode: bool,
    pub network: &'static str,
    pub pool: &'static str,
    pub txid: String,
    pub mined_height: u32,
    pub message: String,
    /// The `challenge:<code>` the receipt signs, if any.
    pub challenge: Option<String>,
    /// `{ id, position, total }` if the receipt is part of a batch.
    pub batch: Option<serde_json::Value>,
    pub sender_addresses: Vec<String>,
    pub outputs: Vec<Output>,
    /// `valid` once the transaction has FINALITY_CONFIRMATIONS confirmations, `valid_provisional` before.
    pub verdict: &'static str,
    /// What was checked, one level per property (fills ZIP 311's "validity levels" TODO).
    pub checks: serde_json::Value,
    /// For an exchange-deposit receipt (ZIP 320 TEX two-step): the checked deposit.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deposit: Option<serde_json::Value>,
}

/// Builds the `checks` object and verdict for a verification.
pub fn levels(mined_height: u32, tip: Option<u32>, outputs: usize, spends: usize, challenge: Option<&str>, expected_challenge: Option<&str>, sender_addresses: usize) -> (&'static str, serde_json::Value) {
    let confirmations = tip.map(|t| t.saturating_sub(mined_height) + 1);
    let fin = receipts_chain::chain::FINALITY_CONFIRMATIONS;
    let finality = match confirmations {
        Some(c) if c >= fin => "final",
        Some(_) => "provisional",
        None => "unknown",
    };
    let challenge_level = match (challenge, expected_challenge) {
        (Some(c), Some(e)) if c == e => "matched",
        (_, Some(_)) => "mismatch",
        (Some(_), None) => "present",
        (None, None) => "none",
    };
    let verdict = if finality == "provisional" { "valid_provisional" } else { "valid" };
    (
        verdict,
        serde_json::json!({
            "spend_authority": { "level": "proven", "actions": spends },
            "outputs": { "level": "opened", "count": outputs },
            "confirmations": confirmations,
            "finality": finality,
            "finality_threshold": fin,
            "challenge": challenge_level,
            "sender_address": if sender_addresses > 0 { "proven" } else { "not_disclosed" },
        }),
    )
}

/// The `challenge:<hex>` line a receipt signs, if any.
pub fn challenge_of(msg: &str) -> Option<String> {
    msg.lines()
        .find_map(|l| l.strip_prefix("challenge:"))
        .filter(|c| (6..=64).contains(&c.len()) && c.chars().all(|x| x.is_ascii_hexdigit()))
        .map(str::to_string)
}

pub fn extract(text: &str, prefix: &str) -> Option<String> {
    let i = text.find(prefix)?;
    Some(text[i..].chars().take_while(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_').collect())
}

/// Verifies one receipt. `net` is the network the API key's mode serves.
pub async fn verify_receipt(net: Net, server: Option<&str>, text: &str) -> Result<Verification, ApiError> {
    let body = extract(text, "zrcpt1").ok_or_else(|| ApiError::invalid("receipt_malformed", "no zrcpt1… receipt found").param("receipt"))?;
    let receipt = Receipt::from_text(&body).map_err(|e| ApiError::invalid("receipt_malformed", e.to_string()).param("receipt"))?;
    verify_parsed(net, server, &receipt).await
}

pub async fn verify_parsed(net: Net, server: Option<&str>, receipt: &Receipt) -> Result<Verification, ApiError> {
    let u = &receipt.unsigned;
    let receipt_is_main = u.coin_type == COIN_TYPE_MAINNET;
    if receipt_is_main != (net == Net::Main) {
        return Err(ApiError::invalid(
            "receipt_network_mismatch",
            format!("this receipt is for {}, but the key serves {}", if receipt_is_main { "mainnet" } else { "testnet" }, net.name()),
        )
        .param("receipt"));
    }
    let (tx, height) = chain::fetch_mined_tx(net, server, u.txid).await.map_err(|e| {
        let m = e.to_string();
        if m.contains("not mined") {
            ApiError::verification("transaction_not_mined", m)
        } else if m.contains("could not find") || m.contains("NotFound") || m.contains("not found") {
            ApiError::verification("transaction_not_found", m)
        } else {
            ApiError::chain(m)
        }
    })?;
    let bundle = match u.pool {
        Pool::Ironwood => tx.ironwood_bundle(),
        Pool::Orchard => tx.orchard_bundle(),
    }
    .ok_or_else(|| ApiError::verification("receipt_invalid", "the transaction has no bundle in the receipt's pool"))?;
    let receipt_owned = receipt.clone();
    let v = {
        let coin = u.coin_type;
        let pool = u.pool;
        let txid = u.txid;
        // Proof verification is CPU-bound; keep it off the async workers, and bound how many
        // run at once so a burst of submissions queues instead of starving the server.
        let bundle = bundle.clone();
        let _permit = verify_slots().acquire().await.map_err(|e| ApiError::internal(e.to_string()))?;
        tokio::task::spawn_blocking(move || receipts_core::verify(vk(), &receipt_owned, coin, pool, txid, &bundle))
            .await
            .map_err(|e| ApiError::internal(e.to_string()))?
            .map_err(|e| ApiError::verification("receipt_invalid", e.to_string()))?
    };
    let message = String::from_utf8_lossy(&v.msg).into_owned();
    let tip = chain::chain_tip(net, server).await.ok();
    let (verdict, checks) = levels(height, tip, v.outputs.len(), v.proven_spends.len(), challenge_of(&message).as_deref(), None, v.proven_addresses.len());
    let deposit = match receipts_chain::deposit::deposit_claim(&message) {
        None => None,
        Some((_, tx2_id)) => {
            let mut id = [0u8; 32];
            hex::decode_to_slice(&tx2_id, &mut id).map_err(|_| ApiError::verification("receipt_invalid", "bad second-tx id"))?;
            id.reverse();
            let (tx2, _) = chain::fetch_mined_tx(net, server, id).await.map_err(|e| ApiError::verification("transaction_not_found", format!("the deposit's second transaction: {e}")))?;
            let d = receipts_chain::deposit::check(receipt, &message, receipts_chain::deposit::network_type(net), &tx, &tx2)
                .map_err(|e| ApiError::verification("receipt_invalid", format!("exchange deposit: {e}")))?;
            Some(d.to_json())
        }
    };
    Ok(Verification {
        verdict,
        checks,
        deposit,
        object: "verification",
        valid: true,
        livemode: net == Net::Main,
        network: net.name(),
        pool: if v.pool == Pool::Ironwood { "ironwood" } else { "orchard" },
        txid: display_txid(&v.txid),
        mined_height: height,
        challenge: challenge_of(&message),
        batch: batch_position(&v.msg).map(|(id, i, n)| serde_json::json!({ "id": id, "position": i, "total": n })),
        message,
        sender_addresses: v.proven_addresses.iter().map(|(_, a)| chain::encode_orchard_receiver(net, *a)).collect(),
        outputs: v
            .outputs
            .iter()
            .map(|o| Output {
                action: o.index,
                recipient: chain::encode_orchard_receiver(net, o.recipient),
                recipient_raw: o.recipient,
                zatoshis: o.value,
                memo: chain::memo_text(&o.memo),
            })
            .collect(),
    })
}

/// Verifies a `zrcptb1…` batch: completeness first, then every receipt.
pub async fn verify_batch(net: Net, server: Option<&str>, text: &str) -> Result<serde_json::Value, ApiError> {
    let body = extract(text, "zrcptb1").ok_or_else(|| ApiError::invalid("receipt_malformed", "no zrcptb1… batch found").param("receipt"))?;
    let batch = ReceiptBatch::from_text(&body).map_err(|e| ApiError::invalid("receipt_malformed", e.to_string()).param("receipt"))?;
    let id = receipts_core::check_batch(&batch).map_err(|e| ApiError::verification("batch_invalid", e))?;
    let mut results = Vec::new();
    for r in &batch.receipts {
        results.push(verify_parsed(net, server, r).await?);
    }
    let mut totals = serde_json::Map::new();
    for v in &results {
        for o in &v.outputs {
            let cur = totals.get(&o.recipient).and_then(|x| x.as_u64()).unwrap_or(0);
            totals.insert(o.recipient.clone(), (cur + o.zatoshis).into());
        }
    }
    Ok(serde_json::json!({
        "object": "batch_verification",
        "valid": true,
        "livemode": net == Net::Main,
        "id": id,
        "total_zatoshis": results.iter().flat_map(|v| v.outputs.iter()).map(|o| o.zatoshis).sum::<u64>(),
        "totals_by_recipient": totals,
        "receipts": results,
    }))
}

/// Total paid to `payee` (compared by Orchard receiver) in a verification.
pub fn paid_to(v: &Verification, payee: &str, param: &'static str) -> Result<u64, ApiError> {
    let want = chain::orchard_receiver_of(payee).map_err(|e| ApiError::invalid("parameter_invalid", e.to_string()).param(param))?;
    Ok(v.outputs.iter().filter(|o| o.recipient_raw == want).map(|o| o.zatoshis).sum())
}

pub fn txid_short(t: &[u8; 32]) -> String {
    display_txid(t)
}

/// Internal txid bytes from the display (block-explorer) hex.
pub fn parse_display_txid(s: &str) -> Result<[u8; 32], ApiError> {
    let mut b = [0u8; 32];
    hex::decode_to_slice(s, &mut b).map_err(|_| ApiError::invalid("parameter_invalid", "bad txid"))?;
    b.reverse();
    Ok(b)
}
