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
    outputs: Vec<Output>,
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

/// Verifies `receipt` against `raw_tx` (the transaction bytes) mined at `height`.
/// `regtest` marks a local test chain (receipts there carry the testnet coin type).
/// Returns JSON describing what the receipt proves, or throws why it is invalid.
#[wasm_bindgen]
pub fn verify(receipt: &str, raw_tx: &[u8], height: u32, regtest: bool) -> Result<String, JsError> {
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
    let bundle = match u.pool {
        Pool::Ironwood => tx.ironwood_bundle(),
        Pool::Orchard => tx.orchard_bundle(),
    }
    .ok_or_else(|| JsError::new("the transaction has no bundle in the receipt's pool"))?;
    let v = VK.with(|vk| {
        let vk = vk.get_or_init(receipts_core::verifying_key);
        receipts_core::verify(vk, &r, u.coin_type, u.pool, u.txid, bundle)
    })
    .map_err(|e| JsError::new(&e.to_string()))?;
    Ok(serde_json::to_string(&Verified {
        valid: true,
        network: name,
        pool: pool_name(u.pool),
        txid: display_txid(&u.txid),
        mined_height: height,
        message: String::from_utf8_lossy(&v.msg).into_owned(),
        proven_spend_actions: v.proven_spends,
        outputs: v
            .outputs
            .iter()
            .map(|o| Output {
                action: o.index,
                recipient: unified::Address::try_from_items(vec![unified::Receiver::Orchard(o.recipient)])
                    .map(|a| a.encode(&nt))
                    .unwrap_or_default(),
                zatoshis: o.value,
                memo: memo_text(&o.memo),
            })
            .collect(),
    })?)
}

/// The Orchard receiver of a unified address, hex-encoded, for "is this address paid?" checks.
#[wasm_bindgen]
pub fn orchard_receiver_hex(ua: &str) -> Result<String, JsError> {
    use zcash_address::unified::Container;
    let (_, a) = unified::Address::decode(ua).map_err(|e| JsError::new(&e.to_string()))?;
    a.items()
        .into_iter()
        .find_map(|r| match r {
            unified::Receiver::Orchard(b) => Some(hex::encode(b)),
            _ => None,
        })
        .ok_or_else(|| JsError::new("no Orchard receiver in that address"))
}
