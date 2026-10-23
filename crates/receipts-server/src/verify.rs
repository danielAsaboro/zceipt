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
    /// The sender disclosed this output without its memo.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub memo_withheld: bool,
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
    /// Signed with the public demo wallet's key (`receipts_core::PUBLIC_DEMO_TXIDS`): anyone can.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub public_demo: bool,
    pub message: String,
    /// The `challenge:<code>` the receipt signs, if any.
    pub challenge: Option<String>,
    /// `{ id, position, total }` if the receipt is part of a batch.
    pub batch: Option<serde_json::Value>,
    pub sender_addresses: Vec<String>,
    /// Where spent notes came from, for spends whose source the sender proved (see
    /// `receipts_chain::chain::ReportSource`). Empty unless the sender chose to.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub sources: Vec<serde_json::Value>,
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
pub fn levels(
    mined_height: u32,
    tip: Option<u32>,
    outputs: usize,
    spends: usize,
    challenge: Option<&str>,
    expected_challenge: Option<&str>,
    sender_addresses: usize,
) -> (&'static str, serde_json::Value) {
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
    // Without the tip there is no confirmation count, so nothing says the payment is settled.
    let verdict = if finality == "final" { "valid" } else { "valid_provisional" };
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
/// The challenge a receipt signs: the first line starting `challenge:`, if its value is 6 to 64
/// lowercase hex digits (the page and npm read it the same way; lines end at `\n` or `\r\n`).
pub fn challenge_of(msg: &str) -> Option<String> {
    receipts_core::challenge_of(msg)
}

pub fn extract(text: &str, prefix: &str) -> Option<String> {
    let i = text.find(prefix)?;
    Some(text[i..].chars().take_while(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_').collect())
}

/// What kind of receipt a request carries.
#[derive(Debug, PartialEq)]
pub enum Kind {
    Receipt,
    Batch,
    Incoming,
}

/// Classifies the input by the one receipt prefix it contains. Inputs with none, or with more
/// than one receipt (of any kind), are refused, so no input can be routed past a check.
pub fn receipt_kind(text: &str) -> Result<Kind, ApiError> {
    let count = |p: &str| text.matches(p).count();
    let (r, b, i) = (count("zip311r1"), count("zip311b1"), count(receipts_core::incoming::INCOMING_TEXT_PREFIX));
    match (r, b, i) {
        (1, 0, 0) => Ok(Kind::Receipt),
        (0, 1, 0) => Ok(Kind::Batch),
        (0, 0, 1) => Ok(Kind::Incoming),
        (0, 0, 0) => Err(ApiError::invalid("receipt_malformed", "no zip311r1…, zip311b1… or zrcin1… receipt found").param("receipt")),
        _ => Err(ApiError::invalid("receipt_malformed", "the input holds more than one receipt; send one per request").param("receipt")),
    }
}

/// Checks a caller asks for on top of validity.
#[derive(Clone, Copy, Default)]
pub struct Expect<'a> {
    pub address: Option<&'a str>,
    pub min_zatoshis: Option<u64>,
    pub challenge: Option<&'a str>,
}

/// Verifies a batch and applies `expect`: the expected address must have received at least
/// `min_zatoshis` across the batch, and every receipt in it must sign the challenge.
pub async fn verify_batch_checked(net: Net, server: Option<&str>, text: &str, expect: Expect<'_>) -> Result<serde_json::Value, ApiError> {
    let (mut body, results) = verify_batch_results(net, server, text).await?;
    if let Some(c) = expect.challenge {
        if results.iter().any(|v| v.challenge.as_deref() != Some(c)) {
            return Err(ApiError::verification("challenge_mismatch", "not every receipt in the batch signs this challenge"));
        }
        body["checks"] = serde_json::json!({ "challenge": "matched" });
    }
    if let Some(addr) = expect.address {
        let mut paid = 0u64;
        for v in &results {
            paid += paid_to(v, addr, "expect_address")?;
        }
        if paid == 0 {
            return Err(ApiError::verification("wrong_payee", "no disclosed output in the batch paid expect_address"));
        }
        if expect.min_zatoshis.is_some_and(|m| paid < m) {
            return Err(ApiError::verification(
                "insufficient_amount",
                format!("the batch paid {paid} zatoshis to expect_address, less than {}", expect.min_zatoshis.unwrap()),
            ));
        }
        body["paid_to_expected"] = paid.into();
    }
    Ok(body)
}

/// Verifies one receipt. `net` is the network the API key's mode serves.
pub async fn verify_receipt(net: Net, server: Option<&str>, text: &str) -> Result<Verification, ApiError> {
    let body = extract(text, "zip311r1").ok_or_else(|| ApiError::invalid("receipt_malformed", "no zip311r1… receipt found").param("receipt"))?;
    let receipt = Receipt::from_text(&body).map_err(|e| ApiError::invalid("receipt_malformed", e.to_string()).param("receipt"))?;
    // A link's `h=` hint lets the server fetch the payment among others from its block, so the
    // chain server doesn't learn which transaction this API is checking.
    verify_parsed_hinted(net, server, &receipt, chain::height_hint(text)).await
}

pub async fn verify_parsed(net: Net, server: Option<&str>, receipt: &Receipt) -> Result<Verification, ApiError> {
    verify_parsed_hinted(net, server, receipt, None).await
}

pub async fn verify_parsed_hinted(net: Net, server: Option<&str>, receipt: &Receipt, hint: Option<u32>) -> Result<Verification, ApiError> {
    let u = &receipt.unsigned;
    let receipt_is_main = u.coin_type == COIN_TYPE_MAINNET;
    if receipt_is_main != (net == Net::Main) {
        return Err(ApiError::invalid(
            "receipt_network_mismatch",
            format!("this receipt is for {}, but the key serves {}", if receipt_is_main { "mainnet" } else { "testnet" }, net.name()),
        )
        .param("receipt"));
    }
    let fetched = match hint {
        Some(h) => chain::fetch_mined_tx_in_block(net, server, u.txid, h).await.map(|(tx, height, _)| (tx, height)),
        None => chain::fetch_mined_tx(net, server, u.txid).await,
    };
    let (tx, height) = fetched.map_err(|e| {
        let m = e.to_string();
        if m.contains("not mined") {
            ApiError::verification("transaction_not_mined", m)
        } else if m.contains("could not find") || m.contains("NotFound") || m.contains("not found") || m.contains("is not in block") {
            ApiError::verification("transaction_not_found", m)
        } else {
            ApiError::chain(m)
        }
    })?;
    let sources = chain::fetch_sources(receipt, net, server).await.map_err(|e| ApiError::verification("source_not_found", e.to_string()))?;
    let source_cmx: std::collections::BTreeMap<([u8; 32], u8, u32), [u8; 32]> = sources
        .iter()
        .filter(|(id, s)| s.height <= height && **id != u.txid)
        .flat_map(|(id, s)| {
            let o =
                s.tx.orchard_bundle()
                    .into_iter()
                    .flat_map(move |b| b.actions().iter().enumerate().map(move |(i, a)| ((*id, 0u8, i as u32), a.cmx().to_bytes())));
            let w =
                s.tx.ironwood_bundle()
                    .into_iter()
                    .flat_map(move |b| b.actions().iter().enumerate().map(move |(i, a)| ((*id, 1u8, i as u32), a.cmx().to_bytes())));
            o.chain(w).collect::<Vec<_>>()
        })
        .collect();
    let receipt_owned = receipt.clone();
    let v = {
        let coin = u.coin_type;
        let txid = u.txid;
        // Proof verification is CPU-bound; keep it off the async workers, and bound how many
        // run at once so a burst of submissions queues instead of starving the server.
        let (orchard, ironwood) = (tx.orchard_bundle().cloned(), tx.ironwood_bundle().cloned());
        let _permit = verify_slots().acquire().await.map_err(|e| ApiError::internal(e.to_string()))?;
        tokio::task::spawn_blocking(move || {
            let lookup = |pool: Pool, id: &[u8; 32], index: u32| source_cmx.get(&(*id, u8::from(pool == Pool::Ironwood), index)).copied();
            receipts_core::verify_tx_bundles_with_sources(vk(), &receipt_owned, coin, txid, orchard.as_ref(), ironwood.as_ref(), &lookup)
        })
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?
        .map_err(|e| ApiError::verification("receipt_invalid", e.to_string()))?
    };
    let message = String::from_utf8_lossy(&v.msg).into_owned();
    let tip = chain::chain_tip(net, server).await.ok();
    let (verdict, mut checks) = levels(height, tip, v.outputs.len(), v.proven_spends.len(), challenge_of(&message).as_deref(), None, v.proven_addresses.len());
    checks["source_of_funds"] = if v.sources.is_empty() { "not_disclosed" } else { "proven" }.into();
    let source_json: Vec<serde_json::Value> = v
        .sources
        .iter()
        .map(|s| {
            let stx = &sources[&s.txid];
            serde_json::json!({
                "spend_action": s.spend,
                "source_txid": display_txid(&s.txid),
                "source_action": s.index,
                "source_height": stx.height,
                "zatoshis": s.value,
                "transparent_inputs": stx.transparent_inputs.iter().map(|t| serde_json::json!({ "prevout_txid": t.prevout_txid, "prevout_index": t.prevout_index, "address": t.address, "zatoshis": t.zatoshis })).collect::<Vec<_>>(),
                "net_into_shielded_zatoshis": chain::net_into_shielded(&stx.tx),
            })
        })
        .collect();
    let deposit = match receipts_chain::deposit::deposit_claim(&message) {
        None => None,
        Some((_, tx2_id)) => {
            let mut id = [0u8; 32];
            hex::decode_to_slice(&tx2_id, &mut id).map_err(|_| ApiError::verification("receipt_invalid", "bad second-tx id"))?;
            id.reverse();
            let (tx2, _) = chain::fetch_mined_tx(net, server, id)
                .await
                .map_err(|e| ApiError::verification("transaction_not_found", format!("the deposit's second transaction: {e}")))?;
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
        pool: match (v.pool, v.output_pool) {
            (Pool::Orchard, Some(Pool::Ironwood)) => "orchard_to_ironwood",
            (Pool::Ironwood, Some(Pool::Orchard)) => "ironwood_to_orchard",
            (Pool::Ironwood, _) => "ironwood",
            (Pool::Orchard, _) => "orchard",
        },
        txid: display_txid(&v.txid),
        mined_height: height,
        public_demo: receipts_core::is_public_demo(&v.txid),
        challenge: challenge_of(&message),
        batch: batch_position(&v.msg).map(|(id, i, n)| serde_json::json!({ "id": id, "position": i, "total": n })),
        message,
        sender_addresses: v.proven_addresses.iter().map(|(_, a)| chain::encode_orchard_receiver(net, *a)).collect(),
        sources: source_json,
        outputs: v
            .outputs
            .iter()
            .map(|o| Output {
                action: o.index,
                recipient: chain::encode_orchard_receiver(net, o.recipient),
                recipient_raw: o.recipient,
                zatoshis: o.value,
                memo: if o.memo_withheld { None } else { chain::memo_text(&o.memo) },
                memo_withheld: o.memo_withheld,
            })
            .collect(),
    })
}

/// Verifies an incoming receipt (`zrcin1…`: the recipient proves it was paid).
pub async fn verify_incoming(
    net: Net,
    server: Option<&str>,
    text: &str,
    expect_address: Option<&str>,
    challenge: Option<&str>,
    min_zatoshis: Option<u64>,
) -> Result<serde_json::Value, ApiError> {
    let body = extract(text, receipts_core::incoming::INCOMING_TEXT_PREFIX)
        .ok_or_else(|| ApiError::invalid("receipt_malformed", "no zrcin1… receipt found").param("receipt"))?;
    let r = receipts_core::incoming::IncomingReceipt::from_text(&body)
        .ok_or_else(|| ApiError::invalid("receipt_malformed", "malformed incoming receipt").param("receipt"))?;
    if (r.coin_type == COIN_TYPE_MAINNET) != (net == Net::Main) {
        return Err(ApiError::invalid("receipt_network_mismatch", "this receipt is for another network than the key serves").param("receipt"));
    }
    let fetched = match chain::height_hint(text) {
        Some(h) => chain::fetch_mined_tx_in_block(net, server, r.txid, h).await.map(|(tx, height, _)| (tx, height)),
        None => chain::fetch_mined_tx(net, server, r.txid).await,
    };
    let (tx, height) = fetched.map_err(|e| ApiError::verification("transaction_not_found", e.to_string()))?;
    let bundle = match r.pool {
        Pool::Orchard => tx.orchard_bundle().cloned(),
        Pool::Ironwood => tx.ironwood_bundle().cloned(),
    }
    .ok_or_else(|| ApiError::verification("receipt_invalid", "the transaction has no bundle in the receipt's pool"))?;
    let _permit = verify_slots().acquire().await.map_err(|e| ApiError::internal(e.to_string()))?;
    let r2 = r.clone();
    let v = tokio::task::spawn_blocking(move || receipts_core::incoming::verify_incoming(vk(), &r2, r2.coin_type, r2.txid, &bundle))
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?
        .map_err(|e| ApiError::verification("receipt_invalid", e.to_string()))?;
    let message = String::from_utf8_lossy(&v.msg).into_owned();
    if let Some(c) = challenge {
        if challenge_of(&message).as_deref() != Some(c) {
            return Err(ApiError::verification("challenge_mismatch", "the receipt does not sign this challenge"));
        }
    }
    let recipient = chain::encode_orchard_receiver(net, v.recipient);
    if let Some(want) = expect_address {
        if chain::orchard_receiver_on(net.name(), want).map_err(|e| ApiError::invalid("address_invalid", e.to_string()).param("expect_address"))? != v.recipient
        {
            return Err(ApiError::verification("address_mismatch", "the receipt proves a different receiving address"));
        }
    }
    let total: u64 = v.outputs.iter().map(|o| o.value).sum();
    if min_zatoshis.is_some_and(|m| total < m) {
        return Err(ApiError::verification("insufficient_amount", format!("the receipt shows {total} zatoshis received, less than {}", min_zatoshis.unwrap())));
    }
    let tip = chain::chain_tip(net, server).await.ok();
    let (verdict, _) = levels(height, tip, v.outputs.len(), 0, challenge_of(&message).as_deref(), challenge, 1);
    Ok(serde_json::json!({
        "object": "incoming_verification",
        "valid": true,
        "verdict": verdict,
        "livemode": net == Net::Main,
        "network": net.name(),
        "pool": if r.pool == Pool::Orchard { "orchard" } else { "ironwood" },
        "txid": display_txid(&v.txid),
        "mined_height": height,
        "message": message,
        "recipient": recipient,
        "recipient_control": "proven",
        "total_zatoshis": v.outputs.iter().map(|o| o.value).sum::<u64>(),
        "outputs": v.outputs.iter().map(|o| serde_json::json!({ "action": o.index, "zatoshis": o.value, "memo": chain::memo_text(&o.memo) })).collect::<Vec<_>>(),
    }))
}

/// Verifies a `zip311b1…` batch: completeness first, then every receipt.
pub async fn verify_batch(net: Net, server: Option<&str>, text: &str) -> Result<serde_json::Value, ApiError> {
    Ok(verify_batch_results(net, server, text).await?.0)
}

async fn verify_batch_results(net: Net, server: Option<&str>, text: &str) -> Result<(serde_json::Value, Vec<Verification>), ApiError> {
    let body = extract(text, "zip311b1").ok_or_else(|| ApiError::invalid("receipt_malformed", "no zip311b1… batch found").param("receipt"))?;
    let batch = ReceiptBatch::from_text(&body).map_err(|e| ApiError::invalid("receipt_malformed", e.to_string()).param("receipt"))?;
    let id = receipts_core::check_batch(&batch).map_err(|e| ApiError::verification("batch_invalid", e))?;
    // Fetch and verify the receipts concurrently (proof checks are bounded by verify_slots).
    // `h=` block hints, one per receipt, keep the chain server from learning the batch's txids.
    let hints = chain::height_hints(text).filter(|h| h.len() == batch.receipts.len());
    let mut set = tokio::task::JoinSet::new();
    for (i, r) in batch.receipts.iter().cloned().enumerate() {
        let server = server.map(str::to_string);
        let hint = hints.as_ref().map(|h| h[i]);
        set.spawn(async move { (i, verify_parsed_hinted(net, server.as_deref(), &r, hint).await) });
    }
    let mut slots: Vec<Option<Verification>> = vec![None; batch.receipts.len()];
    while let Some(done) = set.join_next().await {
        let (i, v) = done.map_err(|e| ApiError::internal(e.to_string()))?;
        slots[i] = Some(v?);
    }
    let results: Vec<Verification> = slots.into_iter().map(|v| v.expect("every task reports")).collect();
    let mut totals = serde_json::Map::new();
    for v in &results {
        for o in v.outputs.iter().filter(|o| !o.memo_withheld) {
            let cur = totals.get(&o.recipient).and_then(|x| x.as_u64()).unwrap_or(0);
            totals.insert(o.recipient.clone(), (cur + o.zatoshis).into());
        }
    }
    let body = serde_json::json!({
        "object": "batch_verification",
        "valid": true,
        "livemode": net == Net::Main,
        "id": id,
        // Outputs disclosed without their memo are listed but not counted.
        "total_zatoshis": results.iter().flat_map(|v| v.outputs.iter()).filter(|o| !o.memo_withheld).map(|o| o.zatoshis).sum::<u64>(),
        "totals_by_recipient": totals,
        "receipts": results,
    });
    Ok((body, results))
}

/// Total paid to `payee` (compared by Orchard receiver) in a verification.
/// Outputs disclosed without their memo (v5) don't count: they don't show the payee can receive
/// the note. The address must be on the payment's network.
pub fn paid_to(v: &Verification, payee: &str, param: &'static str) -> Result<u64, ApiError> {
    let want = chain::orchard_receiver_on(v.network, payee).map_err(|e| ApiError::invalid("parameter_invalid", e.to_string()).param(param))?;
    Ok(v.outputs.iter().filter(|o| o.recipient_raw == want && !o.memo_withheld).map(|o| o.zatoshis).sum())
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn one_receipt_per_request_routed_by_its_own_prefix() {
        assert_eq!(receipt_kind("https://x/verify/#zip311r1Abc&h=1").unwrap(), Kind::Receipt);
        assert_eq!(receipt_kind("zip311b1Abc").unwrap(), Kind::Batch);
        assert_eq!(receipt_kind("zrcin1Abc").unwrap(), Kind::Incoming);
        // A receipt with a batch pasted after it used to take the batch path and skip the
        // caller's expect_address / min_zatoshis / challenge checks.
        assert_eq!(receipt_kind("zip311r1Abc zip311b1Def").unwrap_err().code, "receipt_malformed");
        assert_eq!(receipt_kind("zip311r1Abc zip311r1Def").unwrap_err().code, "receipt_malformed");
        assert_eq!(receipt_kind("nothing").unwrap_err().code, "receipt_malformed");
    }

    #[test]
    fn validity_levels() {
        let (v, c) = levels(100, Some(109), 1, 1, Some("ab12cd"), Some("ab12cd"), 0);
        assert_eq!((v, c["finality"].as_str(), c["confirmations"].as_u64(), c["challenge"].as_str()), ("valid", Some("final"), Some(10), Some("matched")));
        let (v, c) = levels(100, Some(108), 1, 1, Some("ab12cd"), Some("ffffff"), 1);
        assert_eq!(
            (v, c["finality"].as_str(), c["challenge"].as_str(), c["sender_address"].as_str()),
            ("valid_provisional", Some("provisional"), Some("mismatch"), Some("proven"))
        );
        let (v, c) = levels(100, None, 0, 1, None, None, 0);
        assert_eq!((v, c["finality"].as_str(), c["challenge"].as_str()), ("valid_provisional", Some("unknown"), Some("none")));
        assert_eq!(levels(100, Some(100), 1, 1, Some("ab12cd"), None, 0).1["challenge"], "present");
    }

    #[test]
    fn message_helpers() {
        assert_eq!(challenge_of("Order 7\nchallenge:00aa11bb\nrefund-to:x"), Some("00aa11bb".into()));
        assert_eq!(challenge_of("challenge:xyz"), None, "not hex");
        assert_eq!(challenge_of("challenge:abc"), None, "too short");
        assert_eq!(extract("https://x/#zip311r1Abc_-9&h=12", "zip311r1"), Some("zip311r1Abc_-9".into()));
        assert_eq!(extract("nothing here", "zip311r1"), None);
        let id = parse_display_txid("571de6e4cc96b64c0d849cc172905449011b195e521532d78fe9c29a149e0e73").unwrap();
        assert_eq!(display_txid(&id), "571de6e4cc96b64c0d849cc172905449011b195e521532d78fe9c29a149e0e73");
        assert!(parse_display_txid("zz").is_err());
    }
}
