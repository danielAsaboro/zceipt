//! Browser verifier for Zcash payment receipts.
//!
//! The page fetches the raw transaction itself (grpc-web to a lightwalletd of the viewer's
//! choice, or pasted hex) and hands it here with the receipt. Verification runs entirely in
//! the browser: the receipt never leaves the page.

use serde::Serialize;
use std::cell::OnceCell;
use wasm_bindgen::prelude::*;
use zcash_address::unified::{self, Encoding};
use zcash_primitives::transaction::Transaction;
use zcash_protocol::consensus::{BlockHeight, BranchId, Network, NetworkType};
use zceipt_core::{display_txid, Pool, Receipt, COIN_TYPE_MAINNET, COIN_TYPE_TESTNET};

mod maker;
pub use maker::{
    describe_prepared, seed_from_phrase, sign_with_phrase, sign_with_seed, viewing_key_from_phrase, viewing_key_from_seed, warm_up_prover, ReceiptMaker,
};

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
    /// Signed with the public demo wallet's key: anyone can.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    public_demo: bool,
    message: String,
    proven_spend_actions: Vec<u32>,
    sender_addresses: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    sources: Vec<Source>,
    outputs: Vec<Output>,
}

/// A proven source of a spent note (see `zceipt_core::SourceProof`).
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
        vk.get_or_init(zceipt_core::verifying_key);
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
    let tx =
        Transaction::read(raw_tx, BranchId::for_height(&net, BlockHeight::from_u32(height))).map_err(|e| JsError::new(&format!("bad transaction: {e}")))?;
    let out = tx.transparent_bundle().and_then(|b| b.vout.get(index as usize)).ok_or_else(|| JsError::new("no such transparent output"))?;
    let address = match out.recipient_address() {
        Some(TransparentAddress::PublicKeyHash(h)) => Some(zcash_address::ZcashAddress::from_transparent_p2pkh(nt, h).encode()),
        Some(TransparentAddress::ScriptHash(h)) => Some(zcash_address::ZcashAddress::from_transparent_p2sh(nt, h).encode()),
        None => None,
    };
    Ok(serde_json::json!({ "address": address, "zatoshis": u64::from(out.value()) }).to_string())
}

/// The txid (block-explorer hex) of `raw_tx`, mined at `height`: lets the block-level fetch
/// check that each transaction a server sent is the one asked for, not a stand-in.
#[wasm_bindgen]
pub fn txid_of(raw_tx: &[u8], height: u32, coin_type: u32) -> Result<String, JsError> {
    let (net, _, _) = net_of(coin_type)?;
    let tx =
        Transaction::read(raw_tx, BranchId::for_height(&net, BlockHeight::from_u32(height))).map_err(|e| JsError::new(&format!("bad transaction: {e}")))?;
    Ok(tx.txid().to_string())
}

/// Verifies `receipt` against `raw_tx` (the transaction bytes) mined at `height`.
/// `regtest` marks a local test chain (receipts there carry the testnet coin type).
/// `sources`, for receipts with source proofs, is JSON `[{ "raw": "<hex>", "height": n }]`
/// holding each source transaction (see `source_txids`); without it such receipts are refused.
/// Returns JSON describing what the receipt proves, or throws why it is invalid.
#[wasm_bindgen]
pub fn verify(receipt: &str, raw_tx: &[u8], height: u32, regtest: bool, sources: Option<String>) -> Result<String, JsError> {
    verify_inner(parse(receipt)?, raw_tx, height, regtest, sources, None, Auth::Signed)
}

/// Verifies a receipt made for one verifier (`zip311d1…`), with that verifier's secret key (hex,
/// from `zceipt verifier-key`): a receipt for another key proves nothing to it. Returns what
/// [`verify`] returns.
#[wasm_bindgen]
pub fn verify_designated(text: &str, verifier_secret: &str, raw_tx: &[u8], height: u32, regtest: bool) -> Result<String, JsError> {
    let d = zceipt_core::designated::DesignatedReceipt::from_text(text).map_err(|e| JsError::new(&e.to_string()))?;
    let y: [u8; 32] = hex::decode(verifier_secret.trim()).ok().and_then(|b| b.try_into().ok()).ok_or_else(|| JsError::new("not a verifier key"))?;
    if zceipt_core::designated::public_key(&y).map_err(|_| JsError::new("not a verifier key"))? != d.verifier {
        return Err(JsError::new("this receipt was made for another verifier's key, so it proves nothing to you"));
    }
    verify_inner(d.receipt.clone(), raw_tx, height, regtest, None, None, Auth::Designated(&d))
}

/// Verifies a delegated receipt (`zip311a1…`): its certificate, links, session signature and
/// policy, then the receipt. Returns what [`verify`] returns, with `delegation` added.
#[wasm_bindgen]
pub fn verify_delegated(text: &str, raw_tx: &[u8], height: u32, regtest: bool) -> Result<String, JsError> {
    let d = zceipt_core::delegated::DelegatedReceipt::from_text(text).map_err(|e| JsError::new(&e.to_string()))?;
    let out = verify_inner(d.receipt.clone(), raw_tx, height, regtest, None, None, Auth::Delegated(&d))?;
    let mut v: serde_json::Value = serde_json::from_str(&out)?;
    v["delegation"] = serde_json::json!({ "max_zatoshis": d.cert.max_zats, "until_height": d.cert.until_height, "payees": d.cert.payees.len() });
    Ok(v.to_string())
}

/// Checks a payer tag (`zip311t1…` with no snapshot) for `domain` against the payment it names
/// (`raw_tx` mined at `height`). Returns `{ txid, tag }`: payments with different tags in one
/// domain were made by different wallets.
#[wasm_bindgen]
pub fn verify_payer_tag(text: &str, domain: &str, raw_tx: &[u8], height: u32) -> Result<String, JsError> {
    console_error_panic_hook::set_once();
    let c = zceipt_core::claim::Claim::from_text(text).map_err(|e| JsError::new(&e.to_string()))?;
    let (net, _, _) = net_of(c.coin_type)?;
    let tx =
        Transaction::read(raw_tx, BranchId::for_height(&net, BlockHeight::from_u32(height))).map_err(|e| JsError::new(&format!("bad transaction: {e}")))?;
    let txid: [u8; 32] = *tx.txid().as_ref();
    let bundle = match c.pool {
        Pool::Orchard => tx.orchard_bundle(),
        Pool::Ironwood => tx.ironwood_bundle(),
    }
    .ok_or_else(|| JsError::new("the payment has no bundle in the tag's pool"))?;
    let nfs: Vec<[u8; 32]> = bundle.actions().iter().map(|a| a.nullifier().to_bytes()).collect();
    let tag = zceipt_core::claim::verify_payer_tag(&c, domain.as_bytes(), &txid, &bundle.anchor().to_bytes(), &nfs)
        .map_err(|_| JsError::new("the payer tag doesn't hold for this payment and domain"))?;
    Ok(serde_json::json!({ "valid": true, "kind": "payer_tag", "txid": zceipt_core::display_txid(&txid), "domain": domain, "tag": hex::encode(tag) })
        .to_string())
}

/// What a payer tag names, to fetch before [`verify_payer_tag`]: `{ txid, network, domain }`.
#[wasm_bindgen]
pub fn inspect_payer_tag(text: &str) -> Result<String, JsError> {
    let c = zceipt_core::claim::Claim::from_text(text).map_err(|e| JsError::new(&e.to_string()))?;
    let txid = std::str::from_utf8(&c.msg).ok().and_then(|m| m.strip_prefix("payer-tag:")).ok_or_else(|| JsError::new("not a payer tag"))?;
    let (_, _, network) = net_of(c.coin_type)?;
    Ok(serde_json::json!({ "txid": txid, "network": network, "domain": String::from_utf8_lossy(&c.domain) }).to_string())
}

/// The receipt inside a one-verifier (`zip311d1…`) or delegated (`zip311a1…`) receipt, as
/// `zip311r1…` text with empty signatures: for [`inspect`], to know which payment to fetch.
#[wasm_bindgen]
pub fn inner_receipt(text: &str) -> Result<String, JsError> {
    let t = text.trim();
    if t.starts_with(zceipt_core::designated::DESIGNATED_TEXT_PREFIX) {
        return Ok(zceipt_core::designated::DesignatedReceipt::from_text(t).map_err(|e| JsError::new(&e.to_string()))?.receipt.to_text());
    }
    Ok(zceipt_core::delegated::DelegatedReceipt::from_text(t).map_err(|e| JsError::new(&e.to_string()))?.receipt.to_text())
}

/// Verifies an aggregated batch (`zip311b1…` version 2): `txs` is JSON `[{ raw, height }]`, each
/// receipt's mined transaction (raw hex) in batch order. Checks every receipt, then the batch's
/// one proof for all their spends. Returns a JSON list of what [`verify`] returns for each.
#[wasm_bindgen]
pub fn verify_aggregated(batch: &str, txs: &str, regtest: bool) -> Result<String, JsError> {
    console_error_panic_hook::set_once();
    let b = zceipt_core::ReceiptBatch::from_text(batch).map_err(|e| JsError::new(&e.to_string()))?;
    zceipt_core::check_batch(&b).map_err(|e| JsError::new(&e))?;
    let proof = b.aggregate.clone().ok_or_else(|| JsError::new("not an aggregated batch"))?;
    let txs: Vec<SourceTxIn> = serde_json::from_str(txs).map_err(|e| JsError::new(&format!("bad transactions: {e}")))?;
    if txs.len() != b.receipts.len() {
        return Err(JsError::new("one transaction per receipt, in batch order"));
    }
    let mut instances = Vec::new();
    let mut out = Vec::with_capacity(txs.len());
    for (r, t) in b.receipts.into_iter().zip(txs) {
        let raw = hex::decode(t.raw.trim()).map_err(|_| JsError::new("bad transaction hex"))?;
        out.push(serde_json::from_str::<serde_json::Value>(&verify_inner(r, &raw, t.height, regtest, None, Some(&mut instances), Auth::Signed)?)?);
    }
    VK.with(|vk| zceipt_core::verify_aggregate(vk.get_or_init(zceipt_core::verifying_key), &instances, &proof))
        .map_err(|e| JsError::new(&format!("{e}: a receipt in the batch was changed after it was made, or not made by the wallet that paid")))?;
    Ok(serde_json::to_string(&out)?)
}

/// What stands in for a receipt's signatures.
enum Auth<'a> {
    Signed,
    Designated(&'a zceipt_core::designated::DesignatedReceipt),
    Delegated(&'a zceipt_core::delegated::DelegatedReceipt),
}

fn verify_inner(
    r: Receipt,
    raw_tx: &[u8],
    height: u32,
    regtest: bool,
    sources: Option<String>,
    deferred: Option<&mut Vec<orchard::circuit::Instance>>,
    auth: Auth<'_>,
) -> Result<String, JsError> {
    console_error_panic_hook::set_once();
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
            let stx = Transaction::read(&raw[..], BranchId::for_height(&net, BlockHeight::from_u32(s.height)))
                .map_err(|e| JsError::new(&format!("bad source transaction: {e}")))?;
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
        zceipt_core::output_cmx(b, index)
    };
    let v = VK
        .with(|vk| {
            let vk = vk.get_or_init(zceipt_core::verifying_key);
            match (deferred, auth) {
                (_, Auth::Designated(d)) => {
                    zceipt_core::verify_designated_tx_bundles(vk, d, u.coin_type, u.txid, tx.orchard_bundle(), tx.ironwood_bundle(), &lookup)
                }
                (_, Auth::Delegated(d)) => {
                    zceipt_core::verify_delegated_tx_bundles(vk, d, u.coin_type, u.txid, tx.orchard_bundle(), tx.ironwood_bundle(), &lookup)
                        .and_then(|v| zceipt_core::delegated::check_policy(&d.cert, &v, height).map(|_| v))
                }
                (Some(st), Auth::Signed) => zceipt_core::verify_tx_bundles_deferred(vk, &r, u.coin_type, u.txid, tx.orchard_bundle(), tx.ironwood_bundle(), st),
                (None, Auth::Signed) => {
                    zceipt_core::verify_tx_bundles_with_sources(vk, &r, u.coin_type, u.txid, tx.orchard_bundle(), tx.ironwood_bundle(), &lookup)
                }
            }
        })
        .map_err(|e| match e {
            // The signature holds but the spend proof doesn't: whoever signed doesn't hold the
            // spent note's key (an observer's claim, or a receipt changed before signing).
            zceipt_core::Error::BadProof(_) => JsError::new(&format!("not proven by the payer: {e}")),
            e => JsError::new(&e.to_string()),
        })?;
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
            Some(o) if o != u.pool => {
                if u.pool == Pool::Orchard {
                    "Orchard to Ironwood"
                } else {
                    "Ironwood to Orchard"
                }
            }
            _ => pool_name(u.pool),
        },
        txid: display_txid(&u.txid),
        mined_height: height,
        public_demo: zceipt_core::is_public_demo(&u.txid),
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

/// The network a unified address belongs to: "mainnet", "testnet" or "regtest". A receipt's
/// recipient bytes carry no network, so an expected address is checked against the receipt's
/// network with this before its receiver is compared.
#[wasm_bindgen]
pub fn address_network(ua: &str) -> Result<String, JsError> {
    use zcash_protocol::consensus::NetworkType;
    let (nt, _, _) = unified::Address::decode(ua).map_err(|e| JsError::new(&e.to_string()))?;
    Ok(match nt {
        NetworkType::Main => "mainnet",
        NetworkType::Test => "testnet",
        NetworkType::Regtest => "regtest",
    }
    .into())
}

/// Splits a `zip311b1…` batch into its receipts after checking it is complete and consistent.
/// Returns JSON `{ "id": "<batch id>", "receipts": ["zip311r1…", …] }`.
#[wasm_bindgen]
pub fn open_batch(batch: &str) -> Result<String, JsError> {
    console_error_panic_hook::set_once();
    let b = zceipt_core::ReceiptBatch::from_text(batch).map_err(|e| JsError::new(&e.to_string()))?;
    let id = zceipt_core::check_batch(&b).map_err(|e| JsError::new(&e))?;
    let receipts: Vec<String> = b.receipts.iter().map(|r| r.to_text()).collect();
    Ok(serde_json::json!({ "id": id, "receipts": receipts, "aggregated": b.aggregate.is_some() }).to_string())
}

/// If `text` contains a viewing key, spending key or seed phrase, its kind; otherwise "".
#[wasm_bindgen]
pub fn secret_kind(text: &str) -> String {
    zceipt_core::tripwire::secret_kind(text).unwrap_or_default().to_string()
}

/// Checks a `zsig1…` "Sign in with Zcash" proof for `domain` and `nonce`, offline: no chain
/// and no server. Returns JSON `{ "address": "u1…|utest1…", "network", "issued_at" }` or throws.
/// The caller must still make sure the nonce was its own, unexpired and is used only once.
#[wasm_bindgen]
pub fn verify_sign_in(sign_in: &str, domain: &str, nonce: &str) -> Result<String, JsError> {
    console_error_panic_hook::set_once();
    let s = zceipt_core::signin::SignIn::from_text(sign_in).ok_or_else(|| JsError::new("not a zsig1… sign-in"))?;
    let (_, nt, name) = net_of(s.coin_type)?;
    let address = VK
        .with(|vk| {
            let vk = vk.get_or_init(zceipt_core::verifying_key);
            zceipt_core::signin::verify_sign_in(vk, &s, s.coin_type, domain, nonce)
        })
        .map_err(|e| JsError::new(&format!("sign-in does not check out for {domain}: {e}")))?;
    let ua = unified::Address::try_from_items(unified::Revision::R0, vec![unified::Uitem::Data(unified::Receiver::Orchard(address))])
        .map(|a| a.encode(&nt))
        .map_err(|e| JsError::new(&e.to_string()))?;
    Ok(serde_json::json!({ "address": ua, "network": name, "issued_at": s.issued_at }).to_string())
}

/// Checks screened-set proofs (`zip311s1…`, any number in `proofs`) for a receipt already verified
/// against `raw_tx`: each spend the receipt proves was of a note in `set` (the published list, one
/// note commitment in hex per line, `#` comments allowed), which one hidden. The root is computed
/// here from the list. Returns JSON `{ root, size, covered_zatoshis }`.
#[wasm_bindgen]
pub fn verify_screened(receipt: &str, raw_tx: &[u8], height: u32, proofs: &str, set: &str) -> Result<String, JsError> {
    let r = parse(receipt)?;
    let u = &r.unsigned;
    let (net, _, _) = net_of(u.coin_type)?;
    let tx =
        Transaction::read(raw_tx, BranchId::for_height(&net, BlockHeight::from_u32(height))).map_err(|e| JsError::new(&format!("bad transaction: {e}")))?;
    if tx.txid().as_ref() != &u.txid {
        return Err(JsError::new("the transaction does not match the receipt's txid"));
    }
    let set: Vec<[u8; 32]> = set
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(|l| hex::decode(l).ok().and_then(|b| b.try_into().ok()).ok_or_else(|| JsError::new(&format!("not a note commitment: {l}"))))
        .collect::<Result<_, _>>()?;
    let proofs: Vec<_> = proofs
        .split(|c: char| !(c.is_ascii_alphanumeric() || c == '-' || c == '_'))
        .filter(|w| w.starts_with(zceipt_core::screened::SCREENED_TEXT_PREFIX))
        .map(|w| zceipt_core::screened::ScreenedProof::from_text(w).ok_or_else(|| JsError::new("malformed screened-set proof")))
        .collect::<Result<_, _>>()?;
    let bundle = match u.pool {
        Pool::Orchard => tx.orchard_bundle(),
        Pool::Ironwood => tx.ironwood_bundle(),
    }
    .ok_or_else(|| JsError::new("the transaction has no bundle in the receipt's pool"))?;
    let mut covered = 0u64;
    for s in &u.spends {
        let nf = bundle.actions().get(s.index as usize).ok_or_else(|| JsError::new("bad action index"))?.nullifier().to_bytes();
        let p =
            proofs.iter().find(|p| p.index == s.index).ok_or_else(|| JsError::new(&format!("no screened-set proof for the spend in action {}", s.index)))?;
        VK.with(|vk| zceipt_core::screened::verify(vk.get_or_init(zceipt_core::verifying_key), &r, &nf, p, &set)).map_err(|e| JsError::new(&e.to_string()))?;
        covered += p.floor;
    }
    let root = zceipt_core::screened::set_root(&set).map_err(|e| JsError::new(&e.to_string()))?;
    Ok(serde_json::json!({ "root": hex::encode(root), "size": set.len(), "covered_zatoshis": covered }).to_string())
}

/// Checks a key-set proof (`zip311m1…`) for a receipt (`zip311r1…`): it was signed under one of
/// the keys the proof lists, not saying which. Returns how many keys; compare them with the
/// published set ([`key_set_keys`]).
#[wasm_bindgen]
pub fn verify_keyset(proof: &str, receipt: &str) -> Result<usize, JsError> {
    let p = zceipt_core::keyset::KeySetProof::from_text(proof).map_err(|e| JsError::new(&e.to_string()))?;
    zceipt_core::keyset::verify(&p, &parse(receipt)?).map_err(|e| JsError::new(&e.to_string()))
}

/// The keys a key-set proof lists, hex, for comparing with the published set.
#[wasm_bindgen]
pub fn key_set_keys(proof: &str) -> Result<String, JsError> {
    let p = zceipt_core::keyset::KeySetProof::from_text(proof).map_err(|e| JsError::new(&e.to_string()))?;
    Ok(serde_json::to_string(&p.keys.iter().map(hex::encode).collect::<Vec<_>>())?)
}

/// Checks a policy proof (`zip311p1…`) for a receipt: signed under the published t-of-n key.
/// Returns JSON `{ threshold, holders, key }` (`key` hex, to compare with the published one).
#[wasm_bindgen]
pub fn verify_policy(proof: &str, receipt: &str) -> Result<String, JsError> {
    let p = zceipt_core::policy::PolicyProof::from_text(proof).map_err(|e| JsError::new(&e.to_string()))?;
    let (t, n) = zceipt_core::policy::verify(&p, &parse(receipt)?).map_err(|e| JsError::new(&e.to_string()))?;
    Ok(serde_json::json!({ "claimed_threshold": t, "claimed_holders": n, "key": hex::encode(p.commitment[0]), "pinned": false }).to_string())
}

/// Like [`verify_policy`], against the published commitment (JSON array of hex points, `C_0` first)
/// and holder count: only then are the threshold and holders a verified fact.
#[wasm_bindgen]
pub fn verify_policy_pinned(proof: &str, receipt: &str, commitment: &str, holders: u16) -> Result<String, JsError> {
    let p = zceipt_core::policy::PolicyProof::from_text(proof).map_err(|e| JsError::new(&e.to_string()))?;
    let hexes: Vec<String> = serde_json::from_str(commitment).map_err(|_| JsError::new("the commitment is a JSON array of hex points"))?;
    let c: Vec<[u8; 32]> = hexes
        .iter()
        .map(|h| hex::decode(h.trim()).ok().and_then(|b| b.try_into().ok()).ok_or_else(|| JsError::new("bad commitment point")))
        .collect::<Result<_, _>>()?;
    let (t, n) = zceipt_core::policy::verify_pinned(&p, &parse(receipt)?, &c, holders).map_err(|e| JsError::new(&e.to_string()))?;
    Ok(serde_json::json!({ "threshold": t, "holders": n, "key": hex::encode(p.commitment[0]), "pinned": true }).to_string())
}

/// The payments a proof of income counts, JSON `[{ txid, height, pool, index }]`, for fetching.
#[wasm_bindgen]
pub fn inspect_income(proof: &str) -> Result<String, JsError> {
    let p = zceipt_core::income::IncomeProof::from_text(proof).map_err(|e| JsError::new(&e.to_string()))?;
    let (_, _, name) = net_of(p.coin_type)?;
    Ok(serde_json::json!({
        "network": name,
        "message": String::from_utf8_lossy(&p.msg),
        "items": p.items.iter().map(|i| serde_json::json!({ "txid": display_txid(&i.txid), "height": i.height, "pool": pool_name(i.pool), "index": i.index })).collect::<Vec<_>>(),
    })
    .to_string())
}

/// Checks a proof of income against the transactions it counts (`txs`: JSON `[{ raw, height }]`,
/// one per item, in order). Returns JSON `{ at_least_zatoshis, payments, message }`.
#[wasm_bindgen]
pub fn verify_income(proof: &str, txs: &str) -> Result<String, JsError> {
    console_error_panic_hook::set_once();
    let p = zceipt_core::income::IncomeProof::from_text(proof).map_err(|e| JsError::new(&e.to_string()))?;
    let (net, _, _) = net_of(p.coin_type)?;
    let txs: Vec<SourceTxIn> = serde_json::from_str(txs).map_err(|e| JsError::new(&format!("bad transactions: {e}")))?;
    if txs.len() != p.items.len() {
        return Err(JsError::new("one transaction per item, in order"));
    }
    let mut cmxs = std::collections::BTreeMap::new();
    for (it, t) in p.items.iter().zip(txs) {
        let raw = hex::decode(t.raw.trim()).map_err(|_| JsError::new("bad transaction hex"))?;
        let tx = Transaction::read(&raw[..], BranchId::for_height(&net, BlockHeight::from_u32(t.height)))
            .map_err(|e| JsError::new(&format!("bad transaction: {e}")))?;
        if tx.txid().as_ref() != &it.txid || t.height != it.height {
            return Err(JsError::new("a transaction isn't the one the proof counts"));
        }
        let b = match it.pool {
            Pool::Orchard => tx.orchard_bundle(),
            Pool::Ironwood => tx.ironwood_bundle(),
        };
        cmxs.insert((it.txid, it.pool as u8), b.map(|b| b.actions().iter().map(|a| a.cmx().to_bytes()).collect::<Vec<[u8; 32]>>()).unwrap_or_default());
    }
    let lookup = |pool: Pool, txid: &[u8; 32], index: u32| cmxs.get(&(*txid, pool as u8)).and_then(|l| l.get(index as usize)).copied();
    let total = VK.with(|vk| zceipt_core::income::verify(vk.get_or_init(zceipt_core::verifying_key), &p, &lookup)).map_err(|e| JsError::new(&e.to_string()))?;
    let payments = p.items.iter().map(|i| i.txid).collect::<std::collections::BTreeSet<_>>().len();
    Ok(serde_json::json!({ "at_least_zatoshis": total, "payments": payments, "message": String::from_utf8_lossy(&p.msg) }).to_string())
}

/// Checks a same-payer proof (`zip311k1…`) for a batch (`zip311b1…`): every payment in it was
/// signed with one spend key. Returns how many spends it links. Checks only the link; verify the
/// batch's receipts as usual.
#[wasm_bindgen]
pub fn verify_same_payer(link: &str, batch: &str) -> Result<usize, JsError> {
    let b = zceipt_core::ReceiptBatch::from_text(batch).map_err(|e| JsError::new(&e.to_string()))?;
    let id = zceipt_core::check_batch(&b).map_err(|e| JsError::new(&e.to_string()))?;
    let proof = zceipt_core::link::LinkProof::from_text(link).map_err(|e| JsError::new(&e.to_string()))?;
    if proof.msg != format!("batch:{id}").as_bytes() {
        return Err(JsError::new("the same-payer proof is for another batch"));
    }
    zceipt_core::link::verify(&proof, &b.receipts.iter().collect::<Vec<_>>())
        .map_err(|_| JsError::new("the same-payer proof doesn't hold: these payments weren't all signed by one key"))?;
    Ok(proof.links.len() + 1)
}

/// `text` as a QR code, an SVG image (for a payment or request link a phone can scan).
#[wasm_bindgen]
pub fn qr_svg(text: &str) -> Result<String, JsError> {
    let code = qrcode::QrCode::new(text.as_bytes()).map_err(|e| JsError::new(&e.to_string()))?;
    Ok(code.render::<qrcode::render::svg::Color>().min_dimensions(200, 200).quiet_zone(true).build())
}

/// The outputs a receipt claims, opened with their `ock`s and nothing else checked (JSON list of
/// `{ action, recipient, zatoshis, memo }`): what a receipt that failed its spend proof says it
/// paid. Not a verification.
#[wasm_bindgen]
pub fn claimed_outputs(receipt: &str, raw_tx: &[u8], height: u32, regtest: bool) -> Result<String, JsError> {
    let r = parse(receipt)?;
    let u = &r.unsigned;
    let (net, mut nt, _) = net_of(u.coin_type)?;
    if regtest {
        nt = NetworkType::Regtest;
    }
    let tx =
        Transaction::read(raw_tx, BranchId::for_height(&net, BlockHeight::from_u32(height))).map_err(|e| JsError::new(&format!("bad transaction: {e}")))?;
    if tx.txid().as_ref() != &u.txid {
        return Err(JsError::new("the fetched transaction does not match the receipt's txid"));
    }
    let bundle = match u.output_pool.unwrap_or(u.pool) {
        Pool::Orchard => tx.orchard_bundle(),
        Pool::Ironwood => tx.ironwood_bundle(),
    }
    .ok_or_else(|| JsError::new("the transaction has no such bundle"))?;
    let outs: Vec<Output> = zceipt_core::claimed_outputs(&r, bundle)
        .iter()
        .map(|o| Output {
            action: o.index,
            recipient: unified::Address::try_from_items(unified::Revision::R0, vec![unified::Uitem::Data(unified::Receiver::Orchard(o.recipient))])
                .map(|a| a.encode(&nt))
                .unwrap_or_default(),
            zatoshis: o.value,
            memo: memo_text(&o.memo),
            memo_withheld: false,
        })
        .collect();
    Ok(serde_json::to_string(&outs)?)
}

/// Signs a prepared `zip311u1…` receipt for `message` with a 32-byte Orchard spending key (hex),
/// the second half of `zceipt create --unsigned`. It makes no proofs, so it is instant; the key
/// never leaves this call. Returns the `zip311r1…` text.
#[wasm_bindgen]
pub fn sign_prepared_text(prepared: &str, spending_key_hex: &str, message: &str) -> Result<String, JsError> {
    console_error_panic_hook::set_once();
    let p = zceipt_core::PreparedReceipt::from_text(prepared).map_err(|e| JsError::new(&format!("not a prepared receipt: {e}")))?;
    let bytes: [u8; 32] =
        hex::decode(spending_key_hex.trim()).ok().and_then(|b| b.try_into().ok()).ok_or_else(|| JsError::new("the key is 32 bytes of hex"))?;
    let sk = Option::from(orchard::keys::SpendingKey::from_bytes(bytes)).ok_or_else(|| JsError::new("not an Orchard spending key"))?;
    let p = p.with_message(message.as_bytes()).map_err(|e| JsError::new(&e.to_string()))?;
    let asks = vec![orchard::keys::SpendAuthorizingKey::from(&sk); p.unsigned().spends.len()];
    let r = p.sign(&asks, rand::rand_core::UnwrapErr(rand::rngs::SysRng)).map_err(|e| JsError::new(&format!("this key did not make these spends ({e})")))?;
    Ok(r.to_text())
}

/// Lints a ZIP-321 payment URI (see `zceipt_core::preflight`). `network` may be "".
/// Returns JSON `{ ok, payments, total_zatoshis, qr, findings }`.
#[wasm_bindgen]
pub fn check_payment_uri(uri: &str, network: &str) -> String {
    zceipt_core::preflight::check_payment_uri(uri, (!network.is_empty()).then_some(network)).to_string()
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
    let read = |raw: &[u8], h: u32| {
        Transaction::read(raw, BranchId::for_height(&net, BlockHeight::from_u32(h))).map_err(|e| JsError::new(&format!("bad transaction: {e}")))
    };
    let (tx1, tx2) = (read(tx1_raw, tx1_height)?, read(tx2_raw, tx2_height)?);
    let msg = String::from_utf8_lossy(&r.unsigned.msg).into_owned();
    let d = zceipt_core::deposit::check(&r, &msg, nt, &tx1, &tx2).map_err(|e| JsError::new(&e))?;
    Ok(d.to_json().to_string())
}

/// Verifies an incoming receipt (`zrcin1…`: the recipient proves it was paid) against `raw_tx`
/// mined at `height`. Returns JSON `{ valid, kind: "incoming", network, pool, txid, mined_height,
/// message, recipient, outputs: [{ action, recipient, zatoshis, memo }] }` or throws.
#[wasm_bindgen]
pub fn verify_incoming(receipt: &str, raw_tx: &[u8], height: u32, regtest: bool) -> Result<String, JsError> {
    console_error_panic_hook::set_once();
    let r = zceipt_core::incoming::IncomingReceipt::from_text(receipt).ok_or_else(|| JsError::new("not a valid zrcin1… incoming receipt"))?;
    let (net, mut nt, mut name) = net_of(r.coin_type)?;
    if regtest {
        nt = NetworkType::Regtest;
        name = "regtest";
    }
    if height == 0 {
        return Err(JsError::new("the transaction is not mined"));
    }
    let tx =
        Transaction::read(raw_tx, BranchId::for_height(&net, BlockHeight::from_u32(height))).map_err(|e| JsError::new(&format!("bad transaction: {e}")))?;
    if tx.txid().as_ref() != &r.txid {
        return Err(JsError::new("the fetched transaction does not match the receipt's txid"));
    }
    let bundle = match r.pool {
        Pool::Orchard => tx.orchard_bundle(),
        Pool::Ironwood => tx.ironwood_bundle(),
    }
    .ok_or_else(|| JsError::new("the transaction has no bundle in the receipt's pool"))?;
    let v = VK
        .with(|vk| zceipt_core::incoming::verify_incoming(vk.get_or_init(zceipt_core::verifying_key), &r, r.coin_type, r.txid, bundle))
        .map_err(|e| JsError::new(&e.to_string()))?;
    let ua = |raw: [u8; 43]| {
        unified::Address::try_from_items(unified::Revision::R0, vec![unified::Uitem::Data(unified::Receiver::Orchard(raw))])
            .map(|a| a.encode(&nt))
            .unwrap_or_default()
    };
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
    let r = zceipt_core::incoming::IncomingReceipt::from_text(receipt).ok_or_else(|| JsError::new("not a valid zrcin1… incoming receipt"))?;
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
    // NaN or a negative time would become 0 and no request would ever look expired.
    if !now.is_finite() || now < 0.0 {
        return Err(JsError::new("now must be a Unix time in seconds"));
    }
    let r = zceipt_core::payreq::PaymentRequest::from_text(request).ok_or_else(|| JsError::new("not a valid zreq1… signed payment request"))?;
    let (_, nt, name) = net_of(r.coin_type)?;
    let raw = VK
        .with(|vk| zceipt_core::payreq::verify_request(vk.get_or_init(zceipt_core::verifying_key), &r, r.coin_type, now as u64))
        .map_err(|e| JsError::new(&e.to_string()))?;
    let payee = unified::Address::try_from_items(unified::Revision::R0, vec![unified::Uitem::Data(unified::Receiver::Orchard(raw))])
        .map(|a| a.encode(&nt))
        .unwrap_or_default();
    let host = r.domain.split(':').next().unwrap_or(&r.domain);
    let scheme = if matches!(host, "localhost" | "127.0.0.1") { "http" } else { "https" };
    Ok(serde_json::json!({
        "payee": payee, "domain": r.domain, "amount_zatoshis": r.amount, "memo": r.memo, "code": r.code,
        "expires_at": r.expires_at, "network": name,
        "well_known": format!("{scheme}://{}/.well-known/zceipt.json", r.domain),
    })
    .to_string())
}
