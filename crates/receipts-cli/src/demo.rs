//! `receipts demo`: a real testnet receipt verified, and an edited copy refused, offline, with no
//! wallet, faucet or setup. `receipts demo --shop` goes on to tour the payment API:
//!
//! Starts the API (dashboard and browser verifier included) on a free local port with a
//! throwaway database, then walks through what a shop does: ask for a payment, receive a
//! receipt, see it become final, refund part of it, and give an accountant a signed fact. Every
//! step is a real API call; the payments are sandbox fixtures. Last, it verifies a real testnet
//! receipt offline. The server keeps running so you can open the dashboard and the verifier.

use anyhow::anyhow;
use receipts_client::{Client, CreateRequest};
use serde_json::{json, Value};
use std::sync::{Arc, Mutex};

const PAYEE: &str = "utest14te2vs2rwfe54mal8dwgejft2e9smlyasrku87ay4rq3dxnwcukp0vyck6exmjg60jttxz9y4a94772x0zc7xhj8gg7k00g4rg0zmdfa";
const REAL_RECEIPT: &str = include_str!("../../../examples/testnet/receipt.txt");
const REAL_TX: &str = include_str!("../../../examples/testnet/tx.hex");
const REAL_HEIGHT: u32 = 4_500_997;

fn step(n: u32, title: &str) {
    println!("\n\x1b[1m{n}. {title}\x1b[0m");
}

fn say(s: &str) {
    println!("   {s}");
}

fn zec(z: u64) -> String {
    receipts_chain::chain::zec(z).trim_end_matches('0').trim_end_matches('.').to_string() + " ZEC"
}

/// The real receipt and its edited copy, checked against the transaction's bytes.
fn real_receipt(n: u32) -> anyhow::Result<()> {
    step(n, "A real receipt from the Zcash testnet, checked against the transaction's bytes");
    let receipt = receipts_core::Receipt::from_text(REAL_RECEIPT.trim())?;
    let t0 = std::time::Instant::now();
    let report = receipts_chain::chain::verify_offline(&receipt, REAL_TX, REAL_HEIGHT, None)?;
    let o = &report.outputs[0];
    say(&format!("tx {}… block {}: {} TAZ paid, memo “{}”", &report.txid[..12], report.mined_height, o.zec.trim_end_matches('0'), o.memo.clone().unwrap_or_default()));
    say(&format!("Halo 2 spend proof and signature valid in {} ms; the sender's address, balance and other payments stay private", t0.elapsed().as_millis()));
    let mut edited = receipt.clone();
    if let Some(i) = edited.unsigned.msg.iter().position(|b| *b == b'2') {
        edited.unsigned.msg[i] = b'3';
    }
    let refused = receipts_chain::chain::verify_offline(&edited, REAL_TX, REAL_HEIGHT, None).err().map(|e| e.to_string()).unwrap_or_else(|| "accepted (this is a bug)".into());
    say(&format!("the same receipt with its note changed to “{}”: refused ({refused})", String::from_utf8_lossy(&edited.unsigned.msg)));
    Ok(())
}

pub async fn run(wait: bool, shop: bool) -> anyhow::Result<()> {
    if !shop {
        println!("\x1b[1mReceipts demo\x1b[0m: prove one shielded Zcash payment without handing over a viewing key.");
        real_receipt(1)?;
        step(2, "Next");
        say("against the live testnet:  receipts verify @examples/testnet/receipt-link.txt");
        say("make your own:             receipts create --seed-stdin --network test --birthday <height> --txid <txid>");
        say("the payment API for shops: receipts demo --shop");
        return Ok(());
    }
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let base = format!("http://{addr}");
    let db = std::env::temp_dir().join(format!("receipts-demo-{}.db", std::process::id()));
    let _ = std::fs::remove_file(&db);
    let mut config = receipts_server::Config::new(receipts_chain::net::Net::Test, format!("{base}/verify/"));
    config.public_url = base.clone();
    let (app, keys) = receipts_server::build(db.to_str().unwrap(), config).await?;
    let key = keys.iter().find(|(_, m)| m == "test").map(|(k, _)| k.clone()).ok_or_else(|| anyhow!("no test key"))?;
    tokio::spawn(async move { axum::serve(listener, app).await });

    // A tiny shop backend that receives the webhooks and checks their signatures.
    let hooks: Arc<Mutex<Vec<String>>> = Arc::default();
    let hook_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let hook_url = format!("http://{}/webhooks/receipts", hook_listener.local_addr()?);
    let secret: Arc<Mutex<String>> = Arc::default();
    {
        let (hooks, secret) = (hooks.clone(), secret.clone());
        let app = axum::Router::new().route(
            "/webhooks/receipts",
            axum::routing::post(move |headers: axum::http::HeaderMap, body: String| {
                let (hooks, secret) = (hooks.clone(), secret.clone());
                async move {
                    let sig = headers.get("receipts-signature").and_then(|v| v.to_str().ok()).unwrap_or("");
                    let s = secret.lock().unwrap().clone();
                    match receipts_client::webhooks::construct_event(&body, sig, &s, 300) {
                        Ok(ev) => hooks.lock().unwrap().push(ev["type"].as_str().unwrap_or("?").to_string()),
                        Err(_) => hooks.lock().unwrap().push("BAD SIGNATURE".into()),
                    }
                    "ok"
                }
            }),
        );
        tokio::spawn(async move { axum::serve(hook_listener, app).await });
    }

    let api = Client::new(key.clone()).base_url(base.clone());
    let http = reqwest::Client::new();
    let call = |method: reqwest::Method, path: String, body: Option<Value>| {
        let (http, key, base) = (http.clone(), key.clone(), base.clone());
        async move {
            let mut r = http.request(method, format!("{base}{path}")).bearer_auth(&key);
            if let Some(b) = body {
                r = r.json(&b);
            }
            let v: Value = r.send().await?.json().await?;
            anyhow::Ok(v)
        }
    };
    let wait_for = |want: &'static str| {
        let hooks = hooks.clone();
        async move {
            for _ in 0..50 {
                if hooks.lock().unwrap().iter().any(|h| h == want) {
                    return true;
                }
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            }
            false
        }
    };

    println!("\x1b[1mReceipts demo\x1b[0m: a shop takes a shielded Zcash payment without ever seeing the customer's wallet.");
    println!("API, dashboard and browser verifier on {base} (testnet sandbox; throwaway database).");

    real_receipt(1)?;
    println!("\nThe rest of the tour runs a shop on the payment API with sandbox fixtures (no wallet or faucet needed).");

    let ep = api.create_webhook_endpoint(&hook_url, None).await?;
    *secret.lock().unwrap() = ep["secret"].as_str().unwrap_or_default().to_string();
    let clock = call(reqwest::Method::POST, "/v1/test_clocks".into(), Some(json!({}))).await?;
    let clock_id = clock["id"].as_str().unwrap_or_default().to_string();

    step(2, "[sandbox] The shop asks for 0.01 ZEC");
    let req = api
        .create_request(&CreateRequest { payee: PAYEE.into(), amount_zatoshis: Some(1_000_000), label: Some("Kemi's Coffee, order 42".into()), test_clock: Some(clock_id.clone()), ..Default::default() })
        .await?;
    let id = req["id"].as_str().unwrap_or_default().to_string();
    say(&format!("request {id}; the customer's wallet pays this ZIP-321 link:"));
    let uri = req["payment_uri"].as_str().unwrap_or_default();
    say(&format!("\x1b[2m{}\x1b[0m", if uri.len() > 96 { format!("{}…", &uri[..96]) } else { uri.to_string() }));
    if let Ok(code) = qrcode::QrCode::with_error_correction_level(uri.as_bytes(), qrcode::EcLevel::L) {
        let art = code.render::<qrcode::render::unicode::Dense1x2>().quiet_zone(true).build();
        for l in art.lines() {
            println!("   {l}");
        }
    }
    let check = call(reqwest::Method::POST, "/v1/payment_links/check".into(), Some(json!({ "uri": uri }))).await?;
    say(&format!("link checker: {} (testnet unified address, provable with a receipt)", if check["ok"] == true { "OK to print" } else { "problems" }));

    step(3, "[sandbox] The customer pays and sends a receipt instead of a viewing key");
    say("(sandbox: zip311_test_refund_to stands in for a real zip311r1… receipt, which also signs a refund address)");
    let paid = api.submit_receipt(&id, "zip311_test_refund_to").await?;
    let v = &paid["fulfillment"]["verification"];
    say(&format!("status {}: paid {} to the shop, spend authority {}, challenge {}", paid["status"].as_str().unwrap_or("?"), zec(paid["received_zatoshis"].as_u64().unwrap_or(0)), v["checks"]["spend_authority"]["level"].as_str().unwrap_or("?"), v["checks"]["challenge"].as_str().unwrap_or("?")));
    say(&format!("verdict {} (1 confirmation; final at 10)", v["verdict"].as_str().unwrap_or("?")));
    say(&format!("shop backend got a signed webhook: request.fulfilled {}", if wait_for("request.fulfilled").await { "✓" } else { "(not yet)" }));

    step(4, "[sandbox] Nine blocks later the payment is final");
    let adv = call(reqwest::Method::POST, format!("/v1/test_clocks/{clock_id}/advance"), Some(json!({ "blocks": 9 }))).await?;
    say(&format!("test clock moved to block {}; fired: {}", adv["height"], adv["fired"].as_array().map(|a| a.iter().filter_map(|f| f["type"].as_str()).collect::<Vec<_>>().join(", ")).unwrap_or_default()));
    say(&format!("webhook request.final {}", if wait_for("request.final").await { "✓" } else { "(not yet)" }));

    step(5, "[sandbox] One coffee was cold: refund 0.004 ZEC to the address the customer signed");
    let rf = api.create_refund(&id, Some(400_000), Some("one coffee was cold")).await?;
    say(&format!("refund {} pays {}…", rf["id"].as_str().unwrap_or("?"), &rf["payment_uri"].as_str().unwrap_or("")[..40.min(rf["payment_uri"].as_str().unwrap_or("").len())]));
    let done = api.submit_refund_receipt(rf["id"].as_str().unwrap_or_default(), "zip311_test_valid").await?;
    say(&format!("the shop's own receipt for the refund settles it: {}", done["status"].as_str().unwrap_or("?")));
    say(&format!("webhook refund.succeeded {}", if wait_for("refund.succeeded").await { "✓" } else { "(not yet)" }));

    step(6, "[sandbox] The accountant gets a signed fact, not the transaction");
    let att = api.create_attestation(&id, None, None, &[]).await?;
    let c = &att["claims"];
    say(&format!("states: paid at least {} on or before {} (net of refunds, final: {})", zec(c["paid_at_least_zatoshis"].as_u64().unwrap_or(0)), c["paid_on_or_before"].as_str().unwrap_or("?"), c["final"]));
    let pres = att["presentation"].as_str().unwrap_or_default();
    say(&format!("hidden unless revealed: txid, exact amount, time, request, label ({} chars, Ed25519 SD-JWT)", pres.len()));
    let ok = api.verify_attestation(pres).await?;
    say(&format!("anyone can check it: valid {}", ok["valid"]));


    if wait {
        println!("\n\x1b[1mExplore\x1b[0m (the server keeps running; Ctrl-C to stop and delete the demo database)");
        say(&format!("dashboard   {base}/dashboard   (paste key {key})"));
        say(&format!("API docs    {base}/docs"));
        say("verifier    the link below checks the testnet receipt in your browser (it fetches that block from a public testnet server)");
        println!("\n{base}/verify/#{}&h={REAL_HEIGHT}", REAL_RECEIPT.trim());
        let _ = tokio::signal::ctrl_c().await;
    }
    for suffix in ["", "-wal", "-shm"] {
        let _ = std::fs::remove_file(format!("{}{suffix}", db.display()));
    }
    Ok(())
}
