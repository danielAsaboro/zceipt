//! Browser verifier for Zcash payment receipts.
//!
//! The page fetches the raw transaction itself (grpc-web to a lightwalletd of the viewer's
//! choice, or pasted hex) and hands it here with the receipt. Verification runs entirely in
//! the browser: the receipt never leaves the page.

use receipts_core::{display_txid, Pool, Receipt, COIN_TYPE_MAINNET, COIN_TYPE_TESTNET};
use serde::Serialize;
use std::cell::OnceCell;
use wasm_bindgen::prelude::*;
use zcash_address::unified::{self, Encoding};
use zcash_primitives::transaction::Transaction;
use zcash_protocol::consensus::{BlockHeight, BranchId, Network, NetworkType};

thread_local! {
    static VK: OnceCell<orchard::circuit::VerifyingKey> = const { OnceCell::new() };
}

#[derive(Serialize)]
struct Summary {
    network: &'static str,
    pool: &'static str,
    txid: String,
    message: String,
    outputs: usize,
    spends: usize,
    bytes: usize,
}

#[derive(Serialize)]
struct Output {
    action: u32,
    recipient: String,
    zatoshis: u64,
    memo: Option<String>,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    memo_withheld: bool,
}

#[derive(Serialize)]
struct Verified {
    valid: bool,
    network: &'static str,
    pool: &'static str,
    txid: String,
    mined_height: u32,
    message: String,
    proven_spend_actions: Vec<u32>,
    sender_addresses: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    sources: Vec<Source>,
    outputs: Vec<Output>,
}

/// A proven source of a spent note (see `receipts_core::SourceProof`).
#[derive(Serialize)]
struct Source {
    spend_action: u32,
    source_txid: String,
    source_action: u32,
    source_height: u32,
    zatoshis: Option<u64>,
    /// The source transaction's transparent inputs, as outpoints (`source_funding` reads them).
    transparent_inputs: Vec<Outpoint>,
    net_into_shielded_zatoshis: i64,
}

#[derive(Serialize)]
struct Outpoint {
    prevout_txid: String,
    prevout_index: u32,
}

#[derive(serde::Deserialize)]
struct SourceTxIn {
    /// Raw transaction, hex.
    raw: String,
    height: u32,
}

fn net_of(coin_type: u32) -> Result<(Network, NetworkType, &'static str), JsError> {
    match coin_type {
        COIN_TYPE_MAINNET => Ok((Network::MainNetwork, NetworkType::Main, "mainnet")),
        COIN_TYPE_TESTNET => Ok((Network::TestNetwork, NetworkType::Test, "testnet")),
        c => Err(JsError::new(&format!("unknown coin type {c}"))),
    }
}

fn pool_name(p: Pool) -> &'static str {
    match p {
        Pool::Orchard => "Orchard",
        Pool::Ironwood => "Ironwood",
    }
}

fn memo_text(memo: &[u8; 512]) -> Option<String> {
    if memo[0] > 0xf4 {
        return None;
    }
    let end = memo.iter().rposition(|&b| b != 0).map(|i| i + 1).unwrap_or(0);
    if end == 0 {
        return None;
    }
    std::str::from_utf8(&memo[..end]).ok().map(str::to_string)
}

fn parse(receipt: &str) -> Result<Receipt, JsError> {
    Receipt::from_text(receipt).map_err(|e| JsError::new(&e.to_string()))
}

/// Decodes a receipt without verifying it. Returns JSON.
#[wasm_bindgen]
pub fn inspect(receipt: &str) -> Result<String, JsError> {
    console_error_panic_hook::set_once();
    let r = parse(receipt)?;
    let u = &r.unsigned;
    let (_, _, name) = net_of(u.coin_type)?;
    Ok(serde_json::to_string(&Summary {
        network: name,
        pool: pool_name(u.pool),
        txid: display_txid(&u.txid),
        message: String::from_utf8_lossy(&u.msg).into_owned(),
        outputs: u.outputs.len(),
        spends: u.spends.len(),
        bytes: r.to_bytes().len(),
    })?)
}

/// Builds the verifying key now (a few seconds), so `verify` is fast later.
#[wasm_bindgen]
pub fn warm_up() {
    console_error_panic_hook::set_once();
    VK.with(|vk| {
        vk.get_or_init(receipts_core::verifying_key);
    });
}

/// The source transactions a receipt's source proofs name (explorer-order txids), as a JSON
/// array, so the page can fetch them before calling `verify`.
#[wasm_bindgen]
pub fn source_txids(receipt: &str) -> Result<String, JsError> {
    let r = parse(receipt)?;
    let mut ids: Vec<String> = r.unsigned.spends.iter().filter_map(|s| s.source.as_ref()).map(|s| display_txid(&s.txid)).collect();
    ids.dedup();
    Ok(serde_json::to_string(&ids)?)
}

/// Reads output `index` of a transparent transaction output (`raw_tx`, mined at `height`):
/// JSON `{ address, zatoshis }`, for showing who funded a source transaction.
#[wasm_bindgen]
pub fn transparent_output(raw_tx: &[u8], height: u32, index: u32, coin_type: u32, regtest: bool) -> Result<String, JsError> {
    use zcash_address::ToAddress;
    use zcash_transparent::address::TransparentAddress;
    let (net, mut nt, _) = net_of(coin_type)?;
    if regtest {
        nt = NetworkType::Regtest;
    }
    let tx = Transaction::read(raw_tx, BranchId::for_height(&net, BlockHeight::from_u32(height))).map_err(|e| JsError::new(&format!("bad transaction: {e}")))?;
    let out = tx.transparent_bundle().and_then(|b| b.vout.get(index as usize)).ok_or_else(|| JsError::new("no such transparent output"))?;
    let address = match out.recipient_address() {
        Some(TransparentAddress::PublicKeyHash(h)) => Some(zcash_address::ZcashAddress::from_transparent_p2pkh(nt, h).encode()),
        Some(TransparentAddress::ScriptHash(h)) => Some(zcash_address::ZcashAddress::from_transparent_p2sh(nt, h).encode()),
        None => None,
    };
    Ok(serde_json::json!({ "address": address, "zatoshis": u64::from(out.value()) }).to_string())
}

/// Verifies `receipt` against `raw_tx` (the transaction bytes) mined at `height`.
/// `regtest` marks a local test chain (receipts there carry the testnet coin type).
/// `sources`, for receipts with source proofs, is JSON `[{ "raw": "<hex>", "height": n }]`
/// holding each source transaction (see `source_txids`); without it such receipts are refused.
/// Returns JSON describing what the receipt proves, or throws why it is invalid.
#[wasm_bindgen]
pub fn verify(receipt: &str, raw_tx: &[u8], height: u32, regtest: bool, sources: Option<String>) -> Result<String, JsError> {
    console_error_panic_hook::set_once();
    let r = parse(receipt)?;
    let u = &r.unsigned;
    let (net, mut nt, mut name) = net_of(u.coin_type)?;
    if regtest {
        if u.coin_type != COIN_TYPE_TESTNET {
            return Err(JsError::new("a regtest receipt must carry the testnet coin type"));
        }
        nt = NetworkType::Regtest;
        name = "regtest";
    }
    if height == 0 {
        return Err(JsError::new("the transaction is not mined"));
    }
    let branch = BranchId::for_height(&net, BlockHeight::from_u32(height));
    let tx = Transaction::read(raw_tx, branch).map_err(|e| JsError::new(&format!("bad transaction: {e}")))?;
    if tx.txid().as_ref() != &u.txid {
        return Err(JsError::new("the fetched transaction does not match the receipt's txid"));
    }
    let mut stxs: std::collections::BTreeMap<[u8; 32], (Transaction, u32)> = Default::default();
    if let Some(json) = sources.filter(|s| !s.is_empty()) {
        let list: Vec<SourceTxIn> = serde_json::from_str(&json).map_err(|e| JsError::new(&format!("bad sources: {e}")))?;
        for s in list {
            let raw = hex::decode(s.raw.trim()).map_err(|_| JsError::new("bad source transaction hex"))?;
            let stx = Transaction::read(&raw[..], BranchId::for_height(&net, BlockHeight::from_u32(s.height))).map_err(|e| JsError::new(&format!("bad source transaction: {e}")))?;
            stxs.insert(*stx.txid().as_ref(), (stx, s.height));
        }
    }
    let lookup = |pool: Pool, txid: &[u8; 32], index: u32| {
        let (stx, h) = stxs.get(txid)?;
        if *h > height || txid == &u.txid {
            return None;
        }
        let b = match pool {
            Pool::Orchard => stx.orchard_bundle(),
            Pool::Ironwood => stx.ironwood_bundle(),
        }?;
        receipts_core::output_cmx(b, index)
    };
    let v = VK.with(|vk| {
        let vk = vk.get_or_init(receipts_core::verifying_key);
        receipts_core::verify_tx_bundles_with_sources(vk, &r, u.coin_type, u.txid, tx.orchard_bundle(), tx.ironwood_bundle(), &lookup)
    })
    .map_err(|e| JsError::new(&e.to_string()))?;
    let sources_out = v
        .sources
        .iter()
        .map(|s| {
            let (stx, h) = &stxs[&s.txid];
            let vb = |b: Option<i64>| b.unwrap_or(0);
            let net_in = -(vb(stx.orchard_bundle().map(|b| i64::from(*b.value_balance())))
                + vb(stx.ironwood_bundle().map(|b| i64::from(*b.value_balance())))
                + vb(stx.sapling_bundle().map(|b| i64::from(*b.value_balance()))));
            Source {
                spend_action: s.spend,
                source_txid: display_txid(&s.txid),
                source_action: s.index,
                source_height: *h,
                zatoshis: s.value,
                transparent_inputs: stx
                    .transparent_bundle()
                    .map(|b| b.vin.iter().map(|i| Outpoint { prevout_txid: display_txid(i.prevout().hash()), prevout_index: i.prevout().n() }).collect())
                    .unwrap_or_default(),
                net_into_shielded_zatoshis: net_in,
            }
        })
        .collect();
    Ok(serde_json::to_string(&Verified {
        valid: true,
        network: name,
        pool: match u.output_pool {
            Some(o) if o != u.pool => if u.pool == Pool::Orchard { "Orchard to Ironwood" } else { "Ironwood to Orchard" },
            _ => pool_name(u.pool),
        },
        txid: display_txid(&u.txid),
        mined_height: height,
        message: String::from_utf8_lossy(&v.msg).into_owned(),
        proven_spend_actions: v.proven_spends,
        sender_addresses: v
            .proven_addresses
            .iter()
            .map(|(_, a)| {
                unified::Address::try_from_items(unified::Revision::R0, vec![unified::Uitem::Data(unified::Receiver::Orchard(*a))])
                    .map(|ua| ua.encode(&nt))
                    .unwrap_or_default()
            })
            .collect(),
        sources: sources_out,
        outputs: v
            .outputs
            .iter()
            .map(|o| Output {
                action: o.index,
                recipient: unified::Address::try_from_items(unified::Revision::R0, vec![unified::Uitem::Data(unified::Receiver::Orchard(o.recipient))])
                    .map(|a| a.encode(&nt))
                    .unwrap_or_default(),
                zatoshis: o.value,
                memo: if o.memo_withheld { None } else { memo_text(&o.memo) },
                memo_withheld: o.memo_withheld,
            })
            .collect(),
    })?)
}

/// The Orchard receiver of a unified address, hex-encoded, for "is this address paid?" checks.
#[wasm_bindgen]
pub fn orchard_receiver_hex(ua: &str) -> Result<String, JsError> {
    use zcash_address::unified::Container;
    let (_, _, a) = unified::Address::decode(ua).map_err(|e| JsError::new(&e.to_string()))?;
    a.items()
        .into_iter()
        .find_map(|r| match r {
            unified::Receiver::Orchard(b) => Some(hex::encode(b)),
            _ => None,
        })
        .ok_or_else(|| JsError::new("no Orchard receiver in that address"))
}

/// Splits a `zrcptb1…` batch into its receipts after checking it is complete and consistent.
/// Returns JSON `{ "id": "<batch id>", "receipts": ["zrcpt1…", …] }`.
#[wasm_bindgen]
pub fn open_batch(batch: &str) -> Result<String, JsError> {
    console_error_panic_hook::set_once();
    let b = receipts_core::ReceiptBatch::from_text(batch).map_err(|e| JsError::new(&e.to_string()))?;
    let id = receipts_core::check_batch(&b).map_err(|e| JsError::new(&e))?;
    let receipts: Vec<String> = b.receipts.iter().map(|r| r.to_text()).collect();
    Ok(serde_json::json!({ "id": id, "receipts": receipts }).to_string())
}

/// If `text` contains a viewing key, spending key or seed phrase, its kind; otherwise "".
#[wasm_bindgen]
pub fn secret_kind(text: &str) -> String {
    receipts_core::tripwire::secret_kind(text).unwrap_or_default().to_string()
}

/// Checks a `zsig1…` "Sign in with Zcash" proof for `domain` and `nonce`, offline: no chain
/// and no server. Returns JSON `{ "address": "u1…|utest1…", "network", "issued_at" }` or throws.
/// The caller must still make sure the nonce was its own, unexpired and is used only once.
#[wasm_bindgen]
pub fn verify_sign_in(sign_in: &str, domain: &str, nonce: &str) -> Result<String, JsError> {
    console_error_panic_hook::set_once();
    let s = receipts_core::signin::SignIn::from_text(sign_in).ok_or_else(|| JsError::new("not a zsig1… sign-in"))?;
    let (_, nt, name) = net_of(s.coin_type)?;
    let address = VK.with(|vk| {
        let vk = vk.get_or_init(receipts_core::verifying_key);
        receipts_core::signin::verify_sign_in(vk, &s, s.coin_type, domain, nonce)
    })
    .map_err(|e| JsError::new(&format!("sign-in does not check out for {domain}: {e}")))?;
    let ua = unified::Address::try_from_items(unified::Revision::R0, vec![unified::Uitem::Data(unified::Receiver::Orchard(address))])
        .map(|a| a.encode(&nt))
        .map_err(|e| JsError::new(&e.to_string()))?;
    Ok(serde_json::json!({ "address": ua, "network": name, "issued_at": s.issued_at }).to_string())
}

/// Lints a ZIP-321 payment URI (see `receipts_core::preflight`). `network` may be "".
/// Returns JSON `{ ok, payments, total_zatoshis, qr, findings }`.
#[wasm_bindgen]
pub fn check_payment_uri(uri: &str, network: &str) -> String {
    receipts_core::preflight::check_payment_uri(uri, (!network.is_empty()).then_some(network)).to_string()
}

/// For a deposit receipt (it signs `tex-deposit:` and `second-tx:`): checks that `tx2_raw` (the
/// second ZIP 320 step, mined at `tx2_height`) spends the receipt's transaction `tx1_raw` and
/// pays the TEX address. Call `verify` on the receipt first; this adds the TEX hop.
/// Returns JSON `{ tex_address, deposit_zatoshis, first_tx, second_tx, warning }`.
#[wasm_bindgen]
pub fn check_tex_deposit(receipt: &str, tx1_raw: &[u8], tx1_height: u32, tx2_raw: &[u8], tx2_height: u32, regtest: bool) -> Result<String, JsError> {
    console_error_panic_hook::set_once();
    let r = parse(receipt)?;
    let (net, mut nt, _) = net_of(r.unsigned.coin_type)?;
    if regtest {
        nt = NetworkType::Regtest;
    }
    let read = |raw: &[u8], h: u32| Transaction::read(raw, BranchId::for_height(&net, BlockHeight::from_u32(h))).map_err(|e| JsError::new(&format!("bad transaction: {e}")));
    let (tx1, tx2) = (read(tx1_raw, tx1_height)?, read(tx2_raw, tx2_height)?);
    let msg = String::from_utf8_lossy(&r.unsigned.msg).into_owned();
    let d = receipts_core::deposit::check(&r, &msg, nt, &tx1, &tx2).map_err(|e| JsError::new(&e))?;
    Ok(d.to_json().to_string())
}

/// Verifies an incoming receipt (`zrcin1…`: the recipient proves it was paid) against `raw_tx`
/// mined at `height`. Returns JSON `{ valid, kind: "incoming", network, pool, txid, mined_height,
/// message, recipient, outputs: [{ action, recipient, zatoshis, memo }] }` or throws.
#[wasm_bindgen]
pub fn verify_incoming(receipt: &str, raw_tx: &[u8], height: u32, regtest: bool) -> Result<String, JsError> {
    console_error_panic_hook::set_once();
    let r = receipts_core::incoming::IncomingReceipt::from_text(receipt).ok_or_else(|| JsError::new("not a valid zrcin1… incoming receipt"))?;
    let (net, mut nt, mut name) = net_of(r.coin_type)?;
    if regtest {
        nt = NetworkType::Regtest;
        name = "regtest";
    }
    if height == 0 {
        return Err(JsError::new("the transaction is not mined"));
    }
    let tx = Transaction::read(raw_tx, BranchId::for_height(&net, BlockHeight::from_u32(height))).map_err(|e| JsError::new(&format!("bad transaction: {e}")))?;
    if tx.txid().as_ref() != &r.txid {
        return Err(JsError::new("the fetched transaction does not match the receipt's txid"));
    }
    let bundle = match r.pool {
        Pool::Orchard => tx.orchard_bundle(),
        Pool::Ironwood => tx.ironwood_bundle(),
    }
    .ok_or_else(|| JsError::new("the transaction has no bundle in the receipt's pool"))?;
    let v = VK.with(|vk| receipts_core::incoming::verify_incoming(vk.get_or_init(receipts_core::verifying_key), &r, r.coin_type, r.txid, bundle)).map_err(|e| JsError::new(&e.to_string()))?;
    let ua = |raw: [u8; 43]| unified::Address::try_from_items(unified::Revision::R0, vec![unified::Uitem::Data(unified::Receiver::Orchard(raw))]).map(|a| a.encode(&nt)).unwrap_or_default();
    Ok(serde_json::json!({
        "valid": true,
        "kind": "incoming",
        "network": name,
        "pool": pool_name(r.pool),
        "txid": display_txid(&r.txid),
        "mined_height": height,
        "message": String::from_utf8_lossy(&v.msg),
        "recipient": ua(v.recipient),
        "outputs": v.outputs.iter().map(|o| serde_json::json!({ "action": o.index, "recipient": ua(o.recipient), "zatoshis": o.value, "memo": memo_text(&o.memo) })).collect::<Vec<_>>(),
    })
    .to_string())
}

/// Decodes an incoming receipt without verifying it: JSON `{ network, pool, txid, message, outputs, bytes }`.
#[wasm_bindgen]
pub fn inspect_incoming(receipt: &str) -> Result<String, JsError> {
    let r = receipts_core::incoming::IncomingReceipt::from_text(receipt).ok_or_else(|| JsError::new("not a valid zrcin1… incoming receipt"))?;
    let (_, _, name) = net_of(r.coin_type)?;
    Ok(serde_json::json!({ "network": name, "pool": pool_name(r.pool), "txid": display_txid(&r.txid), "message": String::from_utf8_lossy(&r.msg), "outputs": r.outputs.len(), "bytes": r.to_bytes().len(), "kind": "incoming" }).to_string())
}

/// Checks a signed payment request (`zreq1…`) at Unix time `now`: the signature, that its signer
/// controls the payee address, and the expiry. Returns JSON `{ payee, domain, amount_zatoshis,
/// memo, code, expires_at, network, well_known }`; the caller should still confirm that
/// `well_known` (the domain's list of payees) contains `payee`.
#[wasm_bindgen]
pub fn verify_payment_request(request: &str, now: f64) -> Result<String, JsError> {
    console_error_panic_hook::set_once();
    let r = receipts_core::payreq::PaymentRequest::from_text(request).ok_or_else(|| JsError::new("not a valid zreq1… signed payment request"))?;
    let (_, nt, name) = net_of(r.coin_type)?;
    let raw = VK.with(|vk| receipts_core::payreq::verify_request(vk.get_or_init(receipts_core::verifying_key), &r, r.coin_type, now as u64)).map_err(|e| JsError::new(&e.to_string()))?;
    let payee = unified::Address::try_from_items(unified::Revision::R0, vec![unified::Uitem::Data(unified::Receiver::Orchard(raw))]).map(|a| a.encode(&nt)).unwrap_or_default();
    let host = r.domain.split(':').next().unwrap_or(&r.domain);
    let scheme = if matches!(host, "localhost" | "127.0.0.1") { "http" } else { "https" };
    Ok(serde_json::json!({
        "payee": payee, "domain": r.domain, "amount_zatoshis": r.amount, "memo": r.memo, "code": r.code,
        "expires_at": r.expires_at, "network": name,
        "well_known": format!("{scheme}://{}/.well-known/zcash-receipts.json", r.domain),
    })
    .to_string())
}
