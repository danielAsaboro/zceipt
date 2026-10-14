//! `receipts`: create and verify Zcash payment receipts (ZIP 311) for Orchard and Ironwood.

mod mcp;
mod wallet;

use receipts_chain::{chain, net};

/// `rand` 0.10 replaced the infallible `OsRng` with the fallible `SysRng`.
#[allow(non_upper_case_globals)]
pub(crate) const OsRng: rand::rand_core::UnwrapErr<rand::rngs::SysRng> = rand::rand_core::UnwrapErr(rand::rngs::SysRng);

use anyhow::{anyhow, bail, Context};
use clap::{Parser, Subcommand};
use receipts_core::{Pool, Receipt};
use std::path::PathBuf;

/// Where `receipts create` points the shareable link. The page verifies everything in the
/// browser; the receipt travels in the URL fragment, which browsers never send to a server.
const DEFAULT_LINK_BASE: &str = "https://zecathon-receipts.vercel.app/";

#[derive(Parser)]
#[command(name = "receipts", version, about = "Prove one shielded Zcash payment, reveal nothing else.")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Create a receipt for a transaction you sent, from a zcash-devtool wallet.
    Create {
        /// Wallet directory (as used by `zcash-devtool wallet -w`).
        #[arg(short, long)]
        wallet: PathBuf,
        /// age identity file that decrypts the wallet's mnemonic.
        #[arg(short, long)]
        identity: PathBuf,
        /// Transaction id (as shown by block explorers). Repeat it to make one batch link that
        /// proves several payments, e.g. a whole payroll or grant round.
        #[arg(long = "txid", required = true)]
        txids: Vec<String>,
        /// Message or challenge to bind into the receipt (for example an invoice number).
        #[arg(short, long, default_value = "")]
        msg: String,
        /// Action indices to disclose. Default: every output you sent to someone else.
        #[arg(long = "output")]
        outputs: Vec<u32>,
        /// Which pool's bundle to disclose. Default: Ironwood if present, else Orchard.
        #[arg(long)]
        pool: Option<String>,
        /// Base URL of the verifier page for the shareable link.
        #[arg(long, default_value = DEFAULT_LINK_BASE)]
        link_base: String,
        /// Write the receipt text to this file as well.
        #[arg(long)]
        out: Option<PathBuf>,
        /// Rebuild Merkle paths from public chain data instead of the wallet's checkpoints.
        /// This happens automatically when the wallet has pruned them.
        #[arg(long)]
        from_chain: bool,
        /// lightwalletd server (host:port) used when rebuilding from chain data.
        #[arg(short, long)]
        server: Option<String>,
        /// Also prove that this wallet controls this public address (e.g. a donation address),
        /// so the verifier sees who paid. Without it, the sender stays anonymous.
        #[arg(long)]
        prove_address: Option<String>,
        /// A proof request link from the verifier page (`…?request=<code>&to=<ua>&min=<zats>`).
        /// The receipt signs the request's challenge, and the CLI checks the payee and amount.
        #[arg(long)]
        request: Option<String>,
    },
    /// Verify a receipt against the chain.
    Verify {
        /// The receipt (`zrcpt1…`), a link containing it, or `@file`.
        receipt: String,
        /// lightwalletd server, host:port. Default: zec.rocks for the receipt's network.
        #[arg(short, long)]
        server: Option<String>,
        /// Fail unless this unified address received a disclosed output.
        #[arg(long)]
        expect_address: Option<String>,
        /// Print the result as JSON.
        #[arg(long)]
        json: bool,
        /// Verify against a local regtest chain with these activation heights (devtool format).
        #[arg(long)]
        regtest: Option<PathBuf>,
        /// Verify offline against this raw transaction (hex file) instead of fetching it.
        #[arg(long, requires = "height")]
        raw_tx: Option<PathBuf>,
        /// Block height of --raw-tx.
        #[arg(long)]
        height: Option<u32>,
    },
    /// Decode a receipt without touching the network.
    Inspect { receipt: String },
    /// Receive webhooks locally: registers a temporary endpoint, prints each event and
    /// forwards it (with its signature) to your app.
    Listen {
        /// Your app's webhook URL, e.g. http://localhost:3000/webhooks/receipts
        #[arg(long)]
        forward_to: Option<String>,
        #[arg(long, env = "RECEIPTS_KEY")]
        api_key: String,
        #[arg(long, env = "RECEIPTS_URL", default_value = "http://127.0.0.1:8723")]
        base_url: String,
        /// Only these event types (default: all).
        #[arg(long = "event")]
        events: Vec<String>,
    },
    /// Model Context Protocol server (stdio) so AI agents can verify receipts and manage
    /// proof requests through the Receipts API.
    Mcp {
        #[arg(long, env = "RECEIPTS_KEY")]
        api_key: String,
        #[arg(long, env = "RECEIPTS_URL", default_value = "http://127.0.0.1:8723")]
        base_url: String,
    },
    /// Fire a real event in test mode, using a sandbox fixture.
    Trigger {
        /// request.fulfilled, request.created or receipt.rejected
        event: String,
        #[arg(long, env = "RECEIPTS_KEY")]
        api_key: String,
        #[arg(long, env = "RECEIPTS_URL", default_value = "http://127.0.0.1:8723")]
        base_url: String,
        /// Payee for the proof request (default: a sandbox testnet address).
        #[arg(long)]
        payee: Option<String>,
    },
    /// Run the Receipts REST API (proof requests, verification, signed webhooks).
    Serve {
        #[arg(long, default_value = "127.0.0.1:8723")]
        listen: String,
        /// SQLite database file (created if missing).
        #[arg(long, default_value = "receipts.db")]
        db: String,
        /// Network for rcpt_test_ keys: "test", or "regtest" with --heights.
        #[arg(long, default_value = "test")]
        test_network: String,
        #[arg(long)]
        heights: Option<PathBuf>,
        /// lightwalletd for test mode (default: testnet.zec.rocks:443, or 127.0.0.1:9067 on regtest).
        #[arg(long)]
        test_lightwalletd: Option<String>,
        /// lightwalletd for live mode (default: zec.rocks:443).
        #[arg(long)]
        live_lightwalletd: Option<String>,
        /// Verifier page used in proof-request links.
        #[arg(long, default_value = DEFAULT_LINK_BASE)]
        verifier_url: String,
    },
    /// Show a mined transaction's shielded bundles (useful before creating a receipt).
    Tx {
        txid: String,
        #[arg(long, default_value = "main")]
        network: String,
        /// Activation heights file, for `--network regtest`.
        #[arg(long)]
        heights: Option<PathBuf>,
        #[arg(short, long)]
        server: Option<String>,
        /// Also print the raw transaction hex (for the web page's offline mode).
        #[arg(long)]
        hex: bool,
    },
}

fn read_arg_text(arg: &str) -> anyhow::Result<String> {
    Ok(if let Some(path) = arg.strip_prefix('@') {
        std::fs::read_to_string(path).with_context(|| format!("reading {path}"))?
    } else {
        arg.to_string()
    })
}

async fn verify_batch(text: &str, server: Option<&str>, regtest: Option<&std::path::Path>, json: bool) -> anyhow::Result<()> {
    let i = text.find(receipts_core::BATCH_TEXT_PREFIX).unwrap();
    let body: String = text[i..].chars().take_while(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_').collect();
    let batch = receipts_core::ReceiptBatch::from_text(&body)?;
    let id = receipts_core::check_batch(&batch).map_err(|e| anyhow!("batch is inconsistent: {e}"))?;
    let mut reports = Vec::new();
    for r in &batch.receipts {
        reports.push(chain::verify_against_chain(r, server, regtest).await?);
    }
    if json {
        println!("{}", serde_json::to_string_pretty(&reports)?);
        return Ok(());
    }
    let mut totals: std::collections::BTreeMap<String, u64> = Default::default();
    println!("VALID batch {id}: {} payments, each proven by its sender", reports.len());
    for rep in &reports {
        for o in &rep.outputs {
            *totals.entry(o.recipient.clone()).or_default() += o.zatoshis;
            println!("  {} ZEC  tx {}…  {}", o.zec, &rep.txid[..12], o.memo.clone().unwrap_or_default());
        }
    }
    let sum: u64 = totals.values().sum();
    println!("  total {} ZEC to {} recipient(s)", chain::zec(sum), totals.len());
    Ok(())
}

fn read_receipt_arg(arg: &str) -> anyhow::Result<Receipt> {
    let text = if let Some(path) = arg.strip_prefix('@') {
        std::fs::read_to_string(path).with_context(|| format!("reading {path}"))?
    } else {
        arg.to_string()
    };
    let text = text.trim();
    let body = match text.find("zrcpt1") {
        Some(i) => &text[i..],
        None => bail!("no zrcpt1… receipt found in the input"),
    };
    let body: String = body.chars().take_while(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_').collect();
    Ok(Receipt::from_text(&body)?)
}

struct Request {
    code: String,
    to: Option<String>,
    min: u64,
}

fn parse_request(link: &str) -> anyhow::Result<Request> {
    let query = link.split('#').next().unwrap_or(link).split_once('?').map(|(_, q)| q).unwrap_or("");
    let mut code = None;
    let mut to = None;
    let mut min = 0;
    for pair in query.split('&') {
        let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
        let v = percent_decode(v);
        match k {
            "request" => code = Some(v),
            "to" => to = Some(v),
            "min" => min = v.parse().map_err(|_| anyhow!("bad min amount in request"))?,
            _ => {}
        }
    }
    let code = code.ok_or_else(|| anyhow!("that link has no request code"))?;
    if !(6..=64).contains(&code.len()) || !code.chars().all(|c| c.is_ascii_hexdigit()) {
        bail!("malformed request code");
    }
    Ok(Request { code, to, min })
}

fn percent_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'+' => out.push(b' '),
            b'%' if i + 2 < b.len() => {
                if let Ok(x) = u8::from_str_radix(&s[i + 1..i + 3], 16) {
                    out.push(x);
                    i += 2;
                } else {
                    out.push(b'%');
                }
            }
            c => out.push(c),
        }
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn parse_txid(s: &str) -> anyhow::Result<[u8; 32]> {
    let mut b: [u8; 32] = hex::decode(s.trim())?
        .try_into()
        .map_err(|_| anyhow!("a txid is 32 bytes of hex"))?;
    b.reverse();
    Ok(b)
}

fn pool_name(p: Pool) -> &'static str {
    match p {
        Pool::Orchard => "Orchard",
        Pool::Ironwood => "Ironwood",
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Create { wallet, identity, txids, msg, outputs, pool, link_base, out, from_chain, server, request, prove_address } => {
            let pool = match pool.as_deref() {
                None => None,
                Some("ironwood") => Some(Pool::Ironwood),
                Some("orchard") => Some(Pool::Orchard),
                Some(other) => bail!("unknown pool {other}"),
            };
            let req = request.as_deref().map(parse_request).transpose()?;
            let msg = match &req {
                Some(r) if msg.is_empty() => format!("challenge:{}", r.code),
                Some(r) => format!("challenge:{}\n{}", r.code, msg),
                None => msg,
            };
            let link_base = match &request {
                Some(link) => link.split('#').next().unwrap_or(link).to_string(),
                None => link_base,
            };
            let source = if from_chain { wallet::WitnessSource::Chain } else { wallet::WitnessSource::Auto };
            if txids.len() > 1 {
                if !outputs.is_empty() {
                    bail!("--output selects actions of one transaction; omit it for a batch");
                }
                let id = format!("{:016x}", rand::random::<u64>());
                let n = txids.len();
                let mut receipts = Vec::with_capacity(n);
                for (i, t) in txids.iter().enumerate() {
                    let m = if msg.is_empty() { format!("batch:{id} {}/{n}", i + 1) } else { format!("batch:{id} {}/{n}\n{msg}", i + 1) };
                    eprintln!("[{}/{n}] {t}", i + 1);
                    receipts.push(wallet::create_receipt(&wallet, &identity, parse_txid(t)?, m.as_bytes(), &[], pool, source, server.as_deref(), prove_address.as_deref()).await?);
                }
                let batch = receipts_core::ReceiptBatch { receipts };
                receipts_core::check_batch(&batch).map_err(|e| anyhow!(e))?;
                let text = batch.to_text();
                if let Some(out) = out {
                    std::fs::write(&out, &text)?;
                    eprintln!("wrote {}", out.display());
                }
                eprintln!("Batch {id}: {n} receipts, {} bytes.\n\nShare this link:", batch.to_bytes().len());
                println!("{}#{}", link_base, text);
                return Ok(());
            }
            let txid = &txids[0];
            let receipt = wallet::create_receipt(&wallet, &identity, parse_txid(&txid)?, msg.as_bytes(), &outputs, pool, source, server.as_deref(), prove_address.as_deref()).await?;
            let text = receipt.to_text();
            if let Some(r) = &req {
                // Check the receipt answers the request before handing it over.
                let report = chain::verify_against_chain(&receipt, server.as_deref(), None).await?;
                let paid: u64 = match &r.to {
                    Some(to) => {
                        let want = chain::orchard_receiver_of(to)?;
                        report.outputs.iter().filter(|o| o.recipient_raw == want).map(|o| o.zatoshis).sum()
                    }
                    None => report.outputs.iter().map(|o| o.zatoshis).sum(),
                };
                if r.to.is_some() && paid == 0 {
                    bail!("this transaction paid nothing to the requested address");
                }
                if paid < r.min {
                    bail!("this transaction paid {} ZEC, less than the requested {}", chain::zec(paid), chain::zec(r.min));
                }
                eprintln!("Answers request {}: paid {} ZEC to the requested address.", r.code, chain::zec(paid));
            }
            if let Some(out) = out {
                std::fs::write(&out, &text)?;
                eprintln!("wrote {}", out.display());
            }
            eprintln!(
                "Receipt for {} ({} pool): {} output(s) disclosed, spend authority proven for {} action(s), {} bytes.",
                receipts_core::display_txid(&receipt.unsigned.txid),
                pool_name(receipt.unsigned.pool),
                receipt.unsigned.outputs.len(),
                receipt.unsigned.spends.len(),
                receipt.to_bytes().len()
            );
            eprintln!("\nShare this link (the receipt stays in the #fragment, never sent to a server):");
            println!("{}#{}", link_base, text);
        }
        Cmd::Verify { receipt, server, expect_address, json, regtest, raw_tx: Some(raw), height: Some(height) } => {
            let receipt = read_receipt_arg(&receipt)?;
            let report = chain::verify_offline(&receipt, &std::fs::read_to_string(&raw)?, height, regtest.as_deref())?;
            if let Some(addr) = &expect_address {
                let want = chain::orchard_receiver_of(addr)?;
                if !report.outputs.iter().any(|o| o.recipient_raw == want) {
                    bail!("no disclosed output pays {addr}");
                }
            }
            let _ = server;
            if json { println!("{}", serde_json::to_string_pretty(&report)?); } else { report.print(); }
        }
        Cmd::Verify { receipt, server, expect_address, json, regtest, .. } => {
            let text = read_arg_text(&receipt)?;
            if text.contains(receipts_core::BATCH_TEXT_PREFIX) {
                return verify_batch(&text, server.as_deref(), regtest.as_deref(), json).await;
            }
            let receipt = read_receipt_arg(&receipt)?;
            let report = chain::verify_against_chain(&receipt, server.as_deref(), regtest.as_deref()).await?;
            if let Some(addr) = &expect_address {
                let want = chain::orchard_receiver_of(addr)?;
                if !report.outputs.iter().any(|o| o.recipient_raw == want) {
                    bail!("no disclosed output pays {addr}");
                }
            }
            if json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                report.print();
            }
        }
        Cmd::Tx { txid, network, heights, server, hex } => {
            let net = match network.as_str() {
                "main" => net::Net::Main,
                "test" => net::Net::Test,
                "regtest" => net::regtest_from_file(heights.as_deref().ok_or_else(|| anyhow!("--heights is required for regtest"))?)?,
                n => bail!("unknown network {n}"),
            };
            let (tx, height) = chain::fetch_mined_tx(net, server.as_deref(), parse_txid(&txid)?).await?;
            println!("mined at height {height}, version {:?}", tx.version());
            if let Some(b) = tx.orchard_bundle() {
                println!("Orchard bundle: {} actions", b.actions().len());
            }
            if let Some(b) = tx.ironwood_bundle() {
                println!("Ironwood bundle: {} actions", b.actions().len());
            }
            if hex {
                let mut raw = Vec::new();
                tx.write(&mut raw)?;
                println!("{}", ::hex::encode(raw));
            }
        }
        Cmd::Serve { listen, db, test_network, heights, test_lightwalletd, live_lightwalletd, verifier_url } => {
            let test_net = match test_network.as_str() {
                "test" => net::Net::Test,
                "regtest" => net::regtest_from_file(heights.as_deref().ok_or_else(|| anyhow!("--heights is required for regtest"))?)?,
                n => bail!("--test-network must be test or regtest, not {n}"),
            };
            let config = receipts_server::Config { test_lightwalletd, live_lightwalletd, public_url: format!("http://{listen}"), ..receipts_server::Config::new(test_net, verifier_url) };
            let (app, keys) = receipts_server::build(&db, config).await?;
            let listener = tokio::net::TcpListener::bind(&listen).await?;
            eprintln!("Receipts API on http://{listen}  (test mode: {}, live mode: mainnet)", test_net.name());
            for (k, mode) in &keys {
                eprintln!("  {mode:<4} key  {k}");
            }
            eprintln!("  docs      http://{listen}/docs   openapi http://{listen}/openapi.yaml");
            axum::serve(listener, app).with_graceful_shutdown(async { let _ = tokio::signal::ctrl_c().await; }).await?;
        }
        Cmd::Mcp { api_key, base_url } => mcp::run(api_key, base_url).await?,
        Cmd::Listen { forward_to, api_key, base_url, events } => listen(forward_to, api_key, base_url, events).await?,
        Cmd::Trigger { event, api_key, base_url, payee } => trigger(event, api_key, base_url, payee).await?,
        Cmd::Inspect { receipt } => {
            let r = read_receipt_arg(&receipt)?;
            let u = &r.unsigned;
            println!("network:  {}", if u.coin_type == receipts_core::COIN_TYPE_MAINNET { "mainnet" } else { "testnet or regtest" });
            println!("pool:     {}", pool_name(u.pool));
            println!("txid:     {}", receipts_core::display_txid(&u.txid));
            println!("message:  {}", String::from_utf8_lossy(&u.msg));
            println!("outputs:  {:?}", u.outputs.iter().map(|o| o.index).collect::<Vec<_>>());
            println!("spends:   {:?}", u.spends.iter().map(|s| s.index).collect::<Vec<_>>());
            println!("size:     {} bytes", r.to_bytes().len());
        }
    }
    Ok(())
}

const SANDBOX_PAYEE: &str = "utest14te2vs2rwfe54mal8dwgejft2e9smlyasrku87ay4rq3dxnwcukp0vyck6exmjg60jttxz9y4a94772x0zc7xhj8gg7k00g4rg0zmdfa";

async fn listen(forward_to: Option<String>, api_key: String, base_url: String, events: Vec<String>) -> anyhow::Result<()> {
    use axum::{body::Bytes, http::HeaderMap, routing::post, Router};
    let client = receipts_client::Client::new(api_key.clone()).base_url(base_url.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let ev: Vec<&str> = events.iter().map(String::as_str).collect();
    let ep = client.create_webhook_endpoint(&format!("http://{addr}/"), if ev.is_empty() { None } else { Some(&ev) }).await?;
    let ep_id = ep["id"].as_str().unwrap_or_default().to_string();
    eprintln!("Ready. Your webhook signing secret is {} (temporary endpoint {ep_id})", ep["secret"].as_str().unwrap_or_default());
    if let Some(f) = &forward_to {
        eprintln!("Forwarding events to {f}");
    }
    eprintln!("Press Ctrl-C to stop.\n");
    let http = reqwest::Client::new();
    let fwd = forward_to.clone();
    let app = Router::new().route(
        "/",
        post(move |headers: HeaderMap, body: Bytes| {
            let http = http.clone();
            let fwd = fwd.clone();
            async move {
                let v: serde_json::Value = serde_json::from_slice(&body).unwrap_or_default();
                let obj = &v["data"]["object"];
                let summary = obj["id"].as_str().or(obj["request"].as_str()).unwrap_or("");
                let mut line = format!("{}  --> {}  [{}]  {summary}", chrono_like_now(), v["type"].as_str().unwrap_or("?"), v["id"].as_str().unwrap_or("?"));
                if let Some(f) = fwd {
                    let mut rb = http.post(&f).header("content-type", "application/json").body(body.to_vec());
                    if let Some(sig) = headers.get("receipts-signature") {
                        rb = rb.header("receipts-signature", sig.clone());
                    }
                    match rb.send().await {
                        Ok(r) => line.push_str(&format!("  <-- [{}] POST {f}", r.status().as_u16())),
                        Err(e) => line.push_str(&format!("  <-- forward failed: {e}")),
                    }
                }
                println!("{line}");
                "ok"
            }
        }),
    );
    axum::serve(listener, app).with_graceful_shutdown(shutdown_signal()).await?;
    // Remove the temporary endpoint on exit (Ctrl-C or SIGTERM).
    let _ = reqwest::Client::new()
        .delete(format!("{}/v1/webhook_endpoints/{ep_id}", base_url.trim_end_matches('/')))
        .bearer_auth(&api_key)
        .send()
        .await;
    eprintln!("Removed temporary endpoint {ep_id}.");
    Ok(())
}

fn chrono_like_now() -> String {
    let s = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
    format!("{:02}:{:02}:{:02}", (s / 3600) % 24, (s / 60) % 60, s % 60)
}

async fn trigger(event: String, api_key: String, base_url: String, payee: Option<String>) -> anyhow::Result<()> {
    if !api_key.starts_with("rcpt_test_") {
        bail!("trigger only works with rcpt_test_ keys");
    }
    const EVENTS: &[&str] = &["request.created", "request.fulfilled", "receipt.rejected", "request.expired", "request.payment_received"];
    if !EVENTS.contains(&event.as_str()) {
        bail!("unknown event {event}; use one of {}", EVENTS.join(", "));
    }
    let client = receipts_client::Client::new(api_key).base_url(base_url);
    let kind = if event == "request.payment_received" { Some("partial".to_string()) } else { None };
    let req = client
        .create_request(&receipts_client::CreateRequest {
            kind,
            expires_in: (event == "request.expired").then_some(1),
            payee: payee.unwrap_or_else(|| SANDBOX_PAYEE.into()),
            amount_zatoshis: Some(1_000_000),
            label: Some(format!("receipts trigger {event}")),
            ..Default::default()
        })
        .await?;
    let id = req["id"].as_str().unwrap_or_default().to_string();
    match event.as_str() {
        "request.created" => {}
        "request.fulfilled" => {
            client.submit_receipt(&id, "zrcpt_test_valid").await?;
        }
        "receipt.rejected" => {
            let _ = client.submit_receipt(&id, "zrcpt_test_wrong_payee").await;
        }
        "request.payment_received" => {
            client.submit_receipt(&id, "zrcpt_test_partial").await?;
        }
        "request.expired" => eprintln!("The request expires in 1 s; request.expired follows shortly."),
        _ => unreachable!(),
    }
    eprintln!("Triggered {event} on {id}");
    Ok(())
}

/// Resolves on Ctrl-C or SIGTERM, so `kill` cleans up as well as Ctrl-C does.
async fn shutdown_signal() {
    #[cfg(unix)]
    {
        let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()).expect("SIGTERM handler");
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = term.recv() => {}
        }
    }
    #[cfg(not(unix))]
    let _ = tokio::signal::ctrl_c().await;
}
