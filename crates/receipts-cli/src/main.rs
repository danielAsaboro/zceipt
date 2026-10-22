//! `receipts`: create and verify Zcash payment receipts (ZIP 311) for Orchard and Ironwood.

mod demo;
mod mcp;
use receipts_wallet as wallet;

use receipts_chain::{chain, net};


use anyhow::{anyhow, bail, Context};
use clap::{Parser, Subcommand};
use receipts_core::{Pool, Receipt};
use std::path::PathBuf;

/// Where `receipts create` points the shareable link. The page verifies everything in the
/// browser; the receipt travels in the URL fragment, which browsers never send to a server.
/// The verifier `receipts serve` (and `receipts demo`) host locally; pass --link-base for another.
const DEFAULT_LINK_BASE: &str = "http://127.0.0.1:8723/verify/";

#[derive(Parser)]
#[command(name = "receipts", version, about = "ZIP 311 payment disclosures for Orchard and Ironwood: prove one shielded payment, reveal nothing else.", after_help = "Start with `receipts demo`. The core is create, verify, inspect, received and reserve; commands marked Shops are the payment API around it.")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
    /// ZIP 32 account of the zcash-devtool wallet to use (default 0).
    #[arg(long, global = true, default_value_t = 0)]
    account: u32,
}

#[derive(Subcommand)]
enum Cmd {
    /// Create a receipt for a payment you sent, from a zcash-devtool wallet.
    ///
    /// Create a receipt for a transaction you sent, from a zcash-devtool wallet.
    #[command(display_order = 1)]
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
        /// Also prove where the money came from: for each spent note, the earlier transaction
        /// output that created it (for example the shielding of an exchange withdrawal). The
        /// verifier learns that link and nothing else; add --reveal-source-value to also show
        /// each spent note's exact value.
        #[arg(long)]
        prove_source: bool,
        /// With --prove-source, reveal the exact value of each spent note.
        #[arg(long, requires = "prove_source")]
        reveal_source_value: bool,
        /// Disclose each output's recipient and amount but not its memo (the memo stays
        /// encrypted; the receipt carries no key that opens it).
        #[arg(long)]
        withhold_memo: bool,
        /// For campaigns: a note you choose to show publicly (signed into the receipt).
        #[arg(long)]
        public_note: Option<String>,
        /// Where the merchant should send a refund, signed into the receipt so only you could
        /// have chosen it. `fresh` uses a new address of this wallet, so receipts with refund
        /// addresses can't be linked to each other; or give an address of yours.
        #[arg(long)]
        refund_to: Option<String>,
        /// Exchange deposit (ZIP 320): the TEX address this transaction (the first of the two
        /// steps) paid. Needs --second-tx. The receipt then proves you made that deposit.
        #[arg(long, requires = "second_tx")]
        tex_deposit: Option<String>,
        /// The second step of the TEX payment: the transaction that paid the TEX address.
        #[arg(long, requires = "tex_deposit")]
        second_tx: Option<String>,
        /// A proof request link from the verifier page (`…?request=<code>&to=<ua>&min=<zats>`).
        /// The receipt signs the request's challenge, and the CLI checks the payee and amount.
        #[arg(long)]
        request: Option<String>,
    },
    /// Verify a receipt against the chain.
    #[command(display_order = 2)]
    Verify {
        /// The receipt (`zip311r1…`), a link containing it, or `@file`.
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
        /// Also ask this second lightwalletd server (host:port) that the transaction is mined in
        /// the same block, so the result doesn't rest on one server's word. It learns the txid.
        #[arg(long)]
        cross_check: Option<String>,
        /// Verify offline against this raw transaction (hex file) instead of fetching it.
        /// Needs --height.
        #[arg(long, requires = "height")]
        raw_tx: Option<PathBuf>,
        /// Block height of --raw-tx.
        #[arg(long)]
        height: Option<u32>,
        /// Offline exchange deposits: the second ZIP 320 step's raw transaction (hex file).
        #[arg(long, requires = "raw_tx")]
        second_raw_tx: Option<PathBuf>,
        /// Block height of --second-raw-tx. Default: --height.
        #[arg(long)]
        second_height: Option<u32>,
        /// Offline source proofs: a source transaction as HEIGHT:FILE (raw hex). Repeat it for
        /// each source the receipt names.
        #[arg(long = "source-raw-tx", requires = "raw_tx")]
        source_raw_txs: Vec<String>,
    },
    /// Decode a receipt without touching the network.
    #[command(display_order = 3)]
    Inspect {
        /// The receipt (`zip311r1…`), a link containing it, or `@file`.
        receipt: String,
    },
    /// Shops: lint a ZIP-321 payment link (`zcash:…`) before printing it.
    ///
    /// Lint a ZIP-321 payment link (`zcash:…`) before printing it or making a QR code: network,
    /// address type, whether a receipt can prove it, amount, memo, unknown params, QR density.
    #[command(display_order = 16)]
    CheckLink {
        /// The payment link, e.g. `zcash:u1…?amount=0.01&memo=…` (quote it in the shell).
        uri: String,
        /// mainnet, testnet or regtest: a different network is an error.
        #[arg(long)]
        network: Option<String>,
        /// Print the full result as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Prove you received a payment (the recipient's side), without a viewing key.
    ///
    /// Prove you RECEIVED a payment (the recipient's side): for an accountant, a tax office or a
    /// lender, without a viewing key. Shows the chosen outputs of one transaction to your
    /// address and proves you control that address; nothing else about your wallet.
    #[command(display_order = 5)]
    Received {
        /// Wallet directory (as used by `zcash-devtool wallet -w`).
        #[arg(short, long)]
        wallet: PathBuf,
        /// age identity file that decrypts the wallet's mnemonic.
        #[arg(short, long)]
        identity: PathBuf,
        /// The transaction that paid you.
        #[arg(long)]
        txid: String,
        /// Message or challenge to bind in (for example the accountant's reference).
        #[arg(short, long, default_value = "")]
        msg: String,
        /// Action indices to disclose. Default: every output this wallet received at one address.
        #[arg(long = "output")]
        outputs: Vec<u32>,
        /// orchard or ironwood. Default: whichever holds your outputs.
        #[arg(long)]
        pool: Option<String>,
        /// lightwalletd server, used only if the wallet kept no copy of the transaction.
        #[arg(short, long)]
        server: Option<String>,
        /// Base URL of the verifier page for the shareable link.
        #[arg(long, default_value = DEFAULT_LINK_BASE)]
        link_base: String,
        /// Write the receipt text to this file as well.
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Proof of funds: prove you hold at least an amount, without a viewing key.
    ///
    /// Proof of funds: prove you hold at least an amount in unspent shielded notes (for a
    /// counterparty, an escrow, a lender or a treasury report), without a viewing key. Reveals
    /// each note's value and nullifier (so the verifier can see when they are spent), nothing else.
    #[command(display_order = 6)]
    Reserve {
        #[arg(short, long)]
        wallet: PathBuf,
        #[arg(short, long)]
        identity: PathBuf,
        /// A challenge or purpose to bind in (e.g. the counterparty's nonce).
        #[arg(short, long, default_value = "")]
        msg: String,
        /// Prove at least this many ZEC, using the fewest (largest) notes. Default: every unspent note.
        #[arg(long)]
        at_least: Option<String>,
        /// orchard or ironwood (default ironwood, where new funds live).
        #[arg(long, default_value = "ironwood")]
        pool: String,
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Shops: sign a payment request (`zreq1…`) so payers can check nothing was changed.
    ///
    /// Shops: sign a payment request (`zreq1…`) with your wallet's key, so payers' wallets can
    /// check nobody changed the address, amount or memo, and that your domain lists the address.
    #[command(display_order = 11)]
    Request {
        #[arg(short, long)]
        wallet: PathBuf,
        #[arg(short, long)]
        identity: PathBuf,
        /// Your shop's domain; publish the address at https://<domain>/.well-known/zcash-receipts.json.
        #[arg(long)]
        domain: String,
        /// Amount in ZEC, e.g. 0.25.
        #[arg(long)]
        amount: String,
        #[arg(long, default_value = "")]
        memo: String,
        /// Request code (hex). Default: random. The payer's receipt signs `challenge:<code>`.
        #[arg(long)]
        code: Option<String>,
        /// Valid for this many seconds.
        #[arg(long, default_value_t = 86_400)]
        expires_in: u64,
        /// The address to be paid (an address of this wallet). Default: its default address.
        #[arg(long)]
        payee: Option<String>,
    },
    /// Sign in with Zcash: prove to a site that you control a shielded address.
    ///
    /// Sign in with Zcash: prove to a site that you control a shielded address, for its
    /// one-time nonce. No transaction, no fee, nothing revealed but the address you choose.
    #[command(display_order = 20)]
    SignIn {
        /// Wallet directory (as used by `zcash-devtool wallet -w`).
        #[arg(short, long)]
        wallet: PathBuf,
        /// age identity file that decrypts the wallet's mnemonic.
        #[arg(short, long)]
        identity: PathBuf,
        /// The site asking (`domain` from its sign-in challenge).
        #[arg(long)]
        domain: String,
        /// The challenge's single-use nonce.
        #[arg(long)]
        nonce: String,
        /// Address to prove. Default: the account's first Orchard address.
        #[arg(long)]
        address: Option<String>,
        /// Send it to this Receipts API (e.g. http://127.0.0.1:8723) and print the result.
        #[arg(long)]
        submit: Option<String>,
        /// API key for --submit.
        #[arg(long, env = "RECEIPTS_KEY")]
        api_key: Option<String>,
    },
    /// Scan files for leaked viewing keys, spending keys and seed phrases.
    ///
    /// Scan files or directories (logs, configs, code) for leaked viewing keys, spending keys
    /// and seed phrases. Prints file:line and the kind, never the secret. Exits 1 if any are found.
    #[command(display_order = 21)]
    PrivacyLint {
        /// Files or directories to scan. Default: the current directory.
        paths: Vec<PathBuf>,
    },
    /// Shops: receive webhooks locally and forward them to your app.
    ///
    /// Receive webhooks locally: registers a temporary endpoint, prints each event and
    /// forwards it (with its signature) to your app.
    #[command(display_order = 13)]
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
    /// Tour: a real testnet receipt verified and an edited copy refused, then the payment API in the sandbox.
    ///
    /// The whole product in one command: starts the API, dashboard and verifier on a free port
    /// and walks through pay, prove, settle, refund and attest in the sandbox. No setup needed.
    #[command(display_order = 4)]
    Demo {
        /// Exit after the walkthrough instead of keeping the server running.
        #[arg(long)]
        no_wait: bool,
    },
    /// Shops: pay a proof request and answer it with a receipt in one step.
    ///
    /// Pay a proof request and answer it in one step: pays from your zcash-devtool wallet,
    /// waits for the block, builds the receipt and hands it back. Takes the shop's hosted pay
    /// link (`…/pay/<id>?secret=…`, submitted automatically) or a receipt link (`…?request=…`).
    #[command(display_order = 10)]
    Pay {
        /// The hosted pay link or receipt link the shop gave you.
        link: String,
        /// Wallet directory (as used by `zcash-devtool wallet -w`).
        #[arg(short, long)]
        wallet: PathBuf,
        /// age identity file that decrypts the wallet's mnemonic.
        #[arg(short, long)]
        identity: PathBuf,
        /// The zcash-devtool binary that sends the payment.
        #[arg(long, default_value = "zcash-devtool")]
        devtool: String,
        /// lightwalletd server (host:port). Default: zec.rocks for the wallet's network.
        #[arg(short, long)]
        server: Option<String>,
        /// Also sign this refund address into the receipt (`fresh`: a new address of this wallet).
        #[arg(long)]
        refund_to: Option<String>,
        /// Show what would be paid, then stop.
        #[arg(long)]
        dry_run: bool,
        /// Already paid: skip sending and answer the request with this transaction.
        #[arg(long)]
        txid: Option<String>,
        /// Pay without asking for confirmation.
        #[arg(long)]
        yes: bool,
    },
    /// Check your setup (servers, API key, clock, wallet) and print what to fix.
    ///
    /// Check your setup: lightwalletd servers, the Receipts API and key, the clock, a wallet,
    /// and how fast this machine builds proofs. Prints what to fix.
    #[command(display_order = 22)]
    Doctor {
        /// Also check this zcash-devtool wallet directory.
        #[arg(short, long)]
        wallet: Option<PathBuf>,
        #[arg(long, env = "RECEIPTS_KEY")]
        api_key: Option<String>,
        #[arg(long, env = "RECEIPTS_URL", default_value = "http://127.0.0.1:8723")]
        base_url: String,
        /// Skip the proof-building timing (about 2 seconds).
        #[arg(long)]
        quick: bool,
    },
    /// Shops: Model Context Protocol server so AI agents can use the Receipts API.
    #[command(display_order = 15)]
    Mcp {
        #[arg(long, env = "RECEIPTS_KEY")]
        api_key: String,
        #[arg(long, env = "RECEIPTS_URL", default_value = "http://127.0.0.1:8723")]
        base_url: String,
    },
    /// Shops: fire a real event in test mode, using a sandbox fixture.
    #[command(display_order = 14)]
    Trigger {
        /// Any event type: request.created, request.payment_received, request.fulfilled,
        /// request.final, request.expired, receipt.rejected, refund.created, refund.succeeded,
        /// request.payment_reorged
        event: String,
        #[arg(long, env = "RECEIPTS_KEY")]
        api_key: String,
        #[arg(long, env = "RECEIPTS_URL", default_value = "http://127.0.0.1:8723")]
        base_url: String,
        /// Payee for the proof request (default: a sandbox testnet address).
        #[arg(long)]
        payee: Option<String>,
    },
    /// Shops: run the Receipts REST API (proof requests, verification, signed webhooks).
    #[command(display_order = 12)]
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
        /// Verifier page used in proof-request links. Default: this server's own /verify/.
        #[arg(long)]
        verifier_url: Option<String>,
        /// Requests allowed per API key per minute.
        #[arg(long, default_value_t = receipts_server::RATE_LIMIT)]
        rate_limit: u32,
    },
    /// Show a mined transaction's shielded bundles (useful before creating a receipt).
    #[command(display_order = 7)]
    Tx {
        /// Transaction id as block explorers show it.
        txid: String,
        /// mainnet, testnet or regtest (also main/test).
        #[arg(long, default_value = "mainnet")]
        network: String,
        /// Activation heights file, for `--network regtest`.
        #[arg(long)]
        heights: Option<PathBuf>,
        /// lightwalletd server, host:port. Default: zec.rocks for the network.
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
    // `h=` block hints, one per receipt: fetch each payment by block, not by txid.
    let hints = chain::height_hints(text).filter(|h| h.len() == batch.receipts.len());
    let mut reports = Vec::new();
    for (i, r) in batch.receipts.iter().enumerate() {
        reports.push(chain::verify_against_chain_hinted(r, server, regtest, hints.as_ref().map(|h| h[i])).await?);
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
            println!("  {} {}  tx {}…  {}", o.zec, chain::unit(rep.network), &rep.txid[..12], o.memo.clone().unwrap_or_default());
        }
    }
    let sum: u64 = totals.values().sum();
    println!("  total {} {} to {} recipient(s) (sum of the outputs the senders disclosed)", chain::zec(sum), chain::unit(reports[0].network), totals.len());
    for line in provenance_lines(&reports) {
        println!("{line}");
    }
    Ok(())
}

/// Multi-hop source of funds: when receipts in a batch prove sources that are other receipts'
/// transactions, print each chain from the last payment back to where it was funded in the clear.
fn provenance_lines(reports: &[chain::Report]) -> Vec<String> {
    let by_txid: std::collections::BTreeMap<&str, &chain::Report> = reports.iter().map(|r| (r.txid.as_str(), r)).collect();
    let used_as_source: std::collections::BTreeSet<&str> = reports.iter().flat_map(|r| r.sources.iter().map(|s| s.source_txid.as_str())).collect();
    let mut out = Vec::new();
    if reports.iter().all(|r| r.sources.is_empty()) {
        return out;
    }
    out.push("  source of funds (proven hop by hop):".into());
    fn walk(txid: &str, depth: usize, by: &std::collections::BTreeMap<&str, &chain::Report>, out: &mut Vec<String>, seen: &mut std::collections::BTreeSet<String>) {
        let pad = "    ".repeat(depth + 1);
        let Some(r) = by.get(txid) else { return };
        if !seen.insert(txid.to_string()) {
            return;
        }
        let unproven = r.proven_spend_actions.len().saturating_sub(r.sources.len());
        for s in &r.sources {
            let v = s.zec.as_ref().map(|z| format!(" ({z} ZEC)")).unwrap_or_default();
            out.push(format!("{pad}tx {}… action {} spent a note{v} from tx {}… output {}", &r.txid[..12], s.spend_action, &s.source_txid[..12], s.source_action));
            if by.contains_key(s.source_txid.as_str()) {
                walk(&s.source_txid, depth + 1, by, out, seen);
            } else if seen.insert(format!("funded:{}", s.source_txid)) {
                let funded: Vec<String> = s.transparent_inputs.iter().filter_map(|t| Some(format!("{} ZEC from {}", chain::zec(t.zatoshis?), t.address.clone()?))).collect();
                if funded.is_empty() {
                    out.push(format!("{pad}    tx {}… was itself funded from shielded notes not shown", &s.source_txid[..12]));
                } else {
                    out.push(format!("{pad}    tx {}… was funded in the clear: {}", &s.source_txid[..12], funded.join(", ")));
                }
            }
        }
        if unproven > 0 {
            out.push(format!("{pad}(plus {unproven} spend(s) of tx {}… whose source isn't shown)", &r.txid[..12]));
        }
    }
    let mut seen = std::collections::BTreeSet::new();
    for r in reports.iter().filter(|r| !used_as_source.contains(r.txid.as_str())) {
        walk(&r.txid, 0, &by_txid, &mut out, &mut seen);
    }
    out
}

/// Parses a ZEC amount ("0.25") into zatoshis, exactly.
fn parse_zec(s: &str) -> anyhow::Result<u64> {
    let (whole, frac) = s.trim().split_once('.').unwrap_or((s.trim(), ""));
    if whole.is_empty() && frac.is_empty() || frac.len() > 8 || !whole.chars().chain(frac.chars()).all(|c| c.is_ascii_digit()) {
        bail!("amount must look like 0.25 (at most 8 decimals)");
    }
    let w: u64 = if whole.is_empty() { 0 } else { whole.parse()? };
    let f: u64 = format!("{frac:0<8}").parse()?;
    w.checked_mul(100_000_000).and_then(|x| x.checked_add(f)).ok_or_else(|| anyhow!("amount too large"))
}

/// Fetches `https://<domain>/.well-known/zcash-receipts.json` (plain http only for localhost)
/// and says whether it lists `payee_raw`.
async fn domain_lists(domain: &str, payee_raw: &[u8; 43]) -> anyhow::Result<bool> {
    let host = domain.split(':').next().unwrap_or(domain);
    let scheme = if matches!(host, "localhost" | "127.0.0.1") { "http" } else { "https" };
    let url = format!("{scheme}://{domain}/.well-known/zcash-receipts.json");
    let client = reqwest::Client::builder().redirect(reqwest::redirect::Policy::none()).timeout(std::time::Duration::from_secs(10)).build()?;
    let doc: serde_json::Value = client.get(&url).send().await?.error_for_status()?.json().await?;
    Ok(receipts_core::payreq::domain_lists_payee(&doc, payee_raw, |ua| chain::orchard_receiver_of(ua).ok()))
}

fn read_incoming_arg(arg: &str) -> anyhow::Result<receipts_core::incoming::IncomingReceipt> {
    let text = read_arg_text(arg)?;
    if let Some(kind) = receipts_core::tripwire::secret_kind(&text) {
        bail!("refusing: the input contains what looks like a {kind}. Never share it.");
    }
    let i = text.find(receipts_core::incoming::INCOMING_TEXT_PREFIX).ok_or_else(|| anyhow!("no zrcin1… receipt found"))?;
    let body: String = text[i..].chars().take_while(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_').collect();
    receipts_core::incoming::IncomingReceipt::from_text(&body).ok_or_else(|| anyhow!("malformed incoming receipt"))
}

fn read_receipt_arg(arg: &str) -> anyhow::Result<Receipt> {
    if let Some(kind) = receipts_core::tripwire::secret_kind(&read_arg_text(arg)?) {
        bail!("refusing: the input contains what looks like a {kind}. Never share it; a zip311r1… receipt is all that's needed.");
    }
    let text = if let Some(path) = arg.strip_prefix('@') {
        std::fs::read_to_string(path).with_context(|| format!("reading {path}"))?
    } else {
        arg.to_string()
    };
    let text = text.trim();
    let body = match text.find("zip311r1") {
        Some(i) => &text[i..],
        // zreceipt (a separate project) writes `zrcpt1` + base64url JSON: say so.
        None if text.contains("zrcpt1eyJ") => bail!("this is a zreceipt link (github.com/Cosmiq2025/zreceipt), a different format that discloses an output without proving who sent it; see docs/RELATED-WORK.md"),
        None => bail!("no zip311r1… receipt found in the input"),
    };
    let body: String = body.chars().take_while(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_').collect();
    Ok(Receipt::from_text(&body)?)
}

use receipts_wallet::RequestLink as Request;

fn parse_request(link: &str) -> anyhow::Result<Request> {
    receipts_wallet::parse_request_link(link)
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
    receipts_wallet::set_account(cli.account)?;
    match cli.cmd {
        Cmd::Create { wallet, identity, txids, msg, outputs, pool, link_base, out, from_chain, server, request, prove_address, prove_source, reveal_source_value, withhold_memo, public_note, refund_to, tex_deposit, second_tx } => {
            let mut lines: Vec<String> = if msg.is_empty() { vec![] } else { vec![msg] };
            if let Some(n) = public_note {
                lines.push(format!("public-note:{n}"));
            }
            if let (Some(tex), Some(t2)) = (&tex_deposit, &second_tx) {
                eprintln!("Warning: {}", receipts_chain::deposit::WARNING);
                lines.push(format!("tex-deposit:{tex}"));
                lines.push(format!("second-tx:{}", t2.trim().to_lowercase()));
            }
            if let Some(a) = refund_to {
                let a = if a == "fresh" { wallet::fresh_address(&wallet, &identity)? } else { a };
                receipts_chain::chain::orchard_receiver_of(&a).map_err(|e| anyhow::anyhow!("--refund-to: {e}"))?;
                lines.push(format!("refund-to:{a}"));
            }
            let msg = lines.join("\n");
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
            let prove_source = match (prove_source, reveal_source_value) {
                (false, _) => None,
                (true, false) => Some(wallet::SourceMode::HideValue),
                (true, true) => Some(wallet::SourceMode::RevealValue),
            };
            if txids.len() > 1 {
                if !outputs.is_empty() {
                    bail!("--output selects actions of one transaction; omit it for a batch");
                }
                let id = format!("{:016x}", rand::random::<u64>());
                let n = txids.len();
                let mut receipts = Vec::with_capacity(n);
                let mut heights = Vec::with_capacity(n);
                for (i, t) in txids.iter().enumerate() {
                    let m = if msg.is_empty() { format!("batch:{id} {}/{n}", i + 1) } else { format!("batch:{id} {}/{n}\n{msg}", i + 1) };
                    eprintln!("[{}/{n}] {t}", i + 1);
                    let (r, h) = wallet::create_receipt(&wallet, &identity, parse_txid(t)?, m.as_bytes(), &[], pool, source, server.as_deref(), prove_address.as_deref(), prove_source, withhold_memo).await?;
                    receipts.push(r);
                    heights.push(h.to_string());
                }
                let batch = receipts_core::ReceiptBatch { receipts };
                receipts_core::check_batch(&batch).map_err(|e| anyhow!(e))?;
                let text = batch.to_text();
                if let Some(out) = out {
                    std::fs::write(&out, &text)?;
                    eprintln!("wrote {}", out.display());
                }
                eprintln!("Batch {id}: {n} receipts, {} bytes.\n\nShare this link (`h=` lists each payment's block, so verifiers fetch each payment among others from its block, not by its id):", batch.to_bytes().len());
                println!("{}#{}&h={}", link_base, text, heights.join(","));
                return Ok(());
            }
            let txid = &txids[0];
            let (receipt, mined_height) = wallet::create_receipt(&wallet, &identity, parse_txid(txid)?, msg.as_bytes(), &outputs, pool, source, server.as_deref(), prove_address.as_deref(), prove_source, withhold_memo).await?;
            let text = receipt.to_text();
            if let Some(r) = &req {
                // Check the receipt answers the request before handing it over.
                let paid = receipts_wallet::check_answers(&receipt, r, server.as_deref(), None).await?;
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
            eprintln!("\nShare this link (the receipt stays in the #fragment, never sent to a server;");
            eprintln!("`h=` lets verifiers fetch it among up to 64 shielded transactions of its block, so the server learns the block, not which one):");
            println!("{}#{}&h={}", link_base, text, mined_height);
        }
        Cmd::Verify { receipt, server, json, regtest, .. } if read_arg_text(&receipt)?.contains(receipts_core::reserve::RESERVE_TEXT_PREFIX) => {
            let text = read_arg_text(&receipt)?;
            let i = text.find(receipts_core::reserve::RESERVE_TEXT_PREFIX).unwrap();
            let body: String = text[i..].chars().take_while(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_').collect();
            let r = receipts_core::reserve::ReserveProof::from_text(&body).ok_or_else(|| anyhow!("malformed proof of funds"))?;
            // Nullifiers already downloaded are cached, so the next check only fetches new blocks.
            let net = net::for_receipt(r.coin_type, regtest.as_deref())?;
            let cache = std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".cache/receipts").join(format!("{}-{}-{}-nullifiers.bin", net.name(), if r.pool == Pool::Orchard { "orchard" } else { "ironwood" }, server.as_deref().unwrap_or("default").replace([':', '/'], "_"))));
            eprintln!("Checking the proofs and scanning the {} pool's nullifiers (cached after the first run)…", if r.pool == Pool::Orchard { "Orchard" } else { "Ironwood" });
            let rep = chain::verify_reserve_against_chain(&r, server.as_deref(), regtest.as_deref(), cache.as_deref()).await?;
            if json { println!("{}", serde_json::to_string_pretty(&rep)?); } else { rep.print(); }
        }
        Cmd::Verify { receipt, json, regtest, raw_tx: Some(raw), height: Some(height), .. } if read_arg_text(&receipt)?.contains(receipts_core::incoming::INCOMING_TEXT_PREFIX) => {
            let r = read_incoming_arg(&receipt)?;
            let rep = chain::verify_incoming_offline(&r, &std::fs::read_to_string(&raw)?, height, regtest.as_deref())?;
            if json { println!("{}", serde_json::to_string_pretty(&rep)?); } else { rep.print(); }
        }
        Cmd::Verify { receipt, server, json, regtest, .. } if read_arg_text(&receipt)?.contains(receipts_core::incoming::INCOMING_TEXT_PREFIX) => {
            let r = read_incoming_arg(&receipt)?;
            let rep = chain::verify_incoming_against_chain(&r, server.as_deref(), regtest.as_deref()).await?;
            if json { println!("{}", serde_json::to_string_pretty(&rep)?); } else { rep.print(); }
        }
        Cmd::Verify { receipt, server, expect_address, json, regtest, raw_tx: Some(raw), height: Some(height), second_raw_tx, second_height, source_raw_txs, .. } => {
            let receipt = read_receipt_arg(&receipt)?;
            let raw1 = std::fs::read_to_string(&raw)?;
            let mut sources = Vec::new();
            for s in &source_raw_txs {
                let (h, f) = s.split_once(':').ok_or_else(|| anyhow!("--source-raw-tx takes HEIGHT:FILE"))?;
                sources.push((std::fs::read_to_string(f)?, h.parse().map_err(|_| anyhow!("bad height in --source-raw-tx {s}"))?));
            }
            let report = chain::verify_offline_with_sources(&receipt, &raw1, height, &sources, regtest.as_deref())?;
            if receipts_chain::deposit::deposit_claim(&report.message).is_some() {
                let second = second_raw_tx.ok_or_else(|| anyhow!("this is an exchange-deposit receipt: pass the second step with --second-raw-tx (and --second-height if it is in another block)"))?;
                let net = net::for_receipt(receipt.unsigned.coin_type, regtest.as_deref())?;
                let read = |hex_text: &str, h: u32| -> anyhow::Result<zcash_primitives::transaction::Transaction> {
                    let bytes = hex::decode(hex_text.trim())?;
                    Ok(zcash_primitives::transaction::Transaction::read(&bytes[..], zcash_protocol::consensus::BranchId::for_height(&net, zcash_protocol::consensus::BlockHeight::from_u32(h)))?)
                };
                let tx1 = read(&raw1, height)?;
                let h2 = second_height.unwrap_or(height);
                if h2 < height {
                    bail!("--second-height {h2} is before the first transaction's block {height}; the second step can't be mined first");
                }
                let tx2 = read(&std::fs::read_to_string(&second)?, h2)?;
                let d = receipts_chain::deposit::check(&receipt, &report.message, receipts_chain::deposit::network_type(net), &tx1, &tx2).map_err(|e| anyhow!(e))?;
                print_deposit(&report, &d, json)?;
                return Ok(());
            }
            if let Some(addr) = &expect_address {
                let want = chain::orchard_receiver_of(addr)?;
                if !report.outputs.iter().any(|o| o.recipient_raw == want) {
                    bail!("no disclosed output pays {addr}");
                }
            }
            let _ = server;
            if json { println!("{}", serde_json::to_string_pretty(&report)?); } else { report.print(); }
        }
        Cmd::Verify { receipt, server, expect_address, json, regtest, cross_check, .. } => {
            let text = read_arg_text(&receipt)?;
            if text.contains(receipts_core::BATCH_TEXT_PREFIX) {
                return verify_batch(&text, server.as_deref(), regtest.as_deref(), json).await;
            }
            let receipt = read_receipt_arg(&receipt)?;
            if receipts_chain::deposit::deposit_claim(&String::from_utf8_lossy(&receipt.unsigned.msg)).is_some() {
                let (report, d) = receipts_chain::deposit::verify_against_chain(&receipt, server.as_deref(), regtest.as_deref()).await?;
                print_deposit(&report, &d, json)?;
                return Ok(());
            }
            // A link's `h=` block hint: fetch the payment among others from its block.
            let hint = chain::height_hint(&text);
            let report = chain::verify_against_chain_hinted(&receipt, server.as_deref(), regtest.as_deref(), hint).await?;
            if !json {
                match hint {
                    Some(h) => eprintln!("(fetched among up to {} shielded transactions of block {h}: the server learned the block, not which transaction)", chain::PRIVATE_FETCH_SET),
                    None => eprintln!("(fetched by txid: the server learned which transaction was checked; links with &h=<block> avoid this)"),
                }
            }
            if let Some(addr) = &expect_address {
                let want = chain::orchard_receiver_of(addr)?;
                if !report.outputs.iter().any(|o| o.recipient_raw == want) {
                    bail!("no disclosed output pays {addr}");
                }
            }
            if let Some(second) = &cross_check {
                let net = net::for_receipt(receipt.unsigned.coin_type, regtest.as_deref())?;
                let conf = chain::cross_check(net, server.as_deref(), second, receipt.unsigned.txid, report.mined_height, hint.is_some()).await?;
                if !json {
                    eprintln!("(cross-checked with {second}: same block, {conf} confirmation{})", if conf == 1 { "" } else { "s" });
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
                "main" | "mainnet" => net::Net::Main,
                "test" | "testnet" => net::Net::Test,
                "regtest" => net::regtest_from_file(heights.as_deref().ok_or_else(|| anyhow!("--heights is required for regtest"))?)?,
                n => bail!("unknown network {n}; use mainnet, testnet or regtest"),
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
        Cmd::Serve { listen, db, test_network, heights, test_lightwalletd, live_lightwalletd, verifier_url, rate_limit } => {
            let test_net = match test_network.as_str() {
                "test" => net::Net::Test,
                "regtest" => net::regtest_from_file(heights.as_deref().ok_or_else(|| anyhow!("--heights is required for regtest"))?)?,
                n => bail!("--test-network must be test or regtest, not {n}"),
            };
            let verifier_url = verifier_url.unwrap_or_else(|| format!("http://{listen}/verify/"));
            let config = receipts_server::Config { test_lightwalletd, live_lightwalletd, rate_limit, public_url: format!("http://{listen}"), ..receipts_server::Config::new(test_net, verifier_url) };
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
        Cmd::PrivacyLint { paths } => {
            let mut found = 0;
            let mut stack: Vec<PathBuf> = if paths.is_empty() { vec![PathBuf::from(".")] } else { paths };
            while let Some(p) = stack.pop() {
                if p.is_dir() {
                    let name = p.file_name().and_then(|n| n.to_str()).unwrap_or("");
                    if [".git", "target", "node_modules"].contains(&name) {
                        continue;
                    }
                    for e in std::fs::read_dir(&p)? {
                        stack.push(e?.path());
                    }
                } else if let Ok(text) = std::fs::read_to_string(&p) {
                    for (i, line) in text.lines().enumerate() {
                        // Test fixtures can opt out with a `privacy-lint: allow` comment.
                        if line.contains("privacy-lint: allow") {
                            continue;
                        }
                        if let Some(kind) = receipts_core::tripwire::secret_kind(line) {
                            println!("{}:{}: {kind} (redacted)", p.display(), i + 1);
                            found += 1;
                        }
                    }
                }
            }
            if found > 0 {
                eprintln!("{found} possible secret(s) found. Rotate any real keys and remove them.");
                std::process::exit(1);
            }
            eprintln!("No viewing keys, spending keys or seed phrases found.");
        }
        Cmd::Demo { no_wait } => demo::run(!no_wait).await?,
        Cmd::Pay { link, wallet, identity, devtool, server, refund_to, dry_run, txid, yes } => pay(link, wallet, identity, devtool, server, refund_to, dry_run, txid, yes).await?,
        Cmd::Doctor { wallet, api_key, base_url, quick } => doctor(wallet, api_key, base_url, quick).await?,
        Cmd::CheckLink { uri, network, json } => {
            let v = receipts_core::preflight::check_payment_uri(&uri, network.as_deref());
            if json {
                println!("{}", serde_json::to_string_pretty(&v)?);
            } else {
                for p in v["payments"].as_array().into_iter().flatten() {
                    println!(
                        "payment {}: {} {} address, {}{}",
                        p["index"],
                        p["network"].as_str().unwrap_or("unknown-network"),
                        p["address_kind"].as_str().unwrap_or_default(),
                        p["amount_zatoshis"].as_u64().map(|z| format!("{} ZEC", receipts_chain::chain::zec(z))).unwrap_or_else(|| "no amount".into()),
                        if p["receipt_provable"] == true { ", provable with a receipt" } else if p["address_kind"] == "tex" { ", provable with a deposit receipt (--tex-deposit)" } else { ", NOT provable with a receipt" },
                    );
                }
                if let Some(q) = v["qr"].as_object() {
                    println!("QR: version {} ({}×{} modules)", q["version"], q["modules"], q["modules"]);
                }
                for f in v["findings"].as_array().into_iter().flatten() {
                    println!("{:7} {}: {}", f["level"].as_str().unwrap_or_default().to_uppercase(), f["code"].as_str().unwrap_or_default(), f["message"].as_str().unwrap_or_default());
                }
                let warned = v["findings"].as_array().is_some_and(|f| f.iter().any(|f| f["level"] == "warning"));
                println!("{}", if v["ok"] != true { "PROBLEMS FOUND" } else if warned { "OK, WITH WARNINGS" } else { "OK" });
            }
            if v["ok"] != true {
                std::process::exit(1);
            }
        }
        Cmd::Reserve { wallet, identity, msg, at_least, pool, out } => {
            let pool = match pool.as_str() {
                "ironwood" => Pool::Ironwood,
                "orchard" => Pool::Orchard,
                p => bail!("unknown pool {p}"),
            };
            let min = at_least.as_deref().map(parse_zec).transpose()?;
            let r = wallet::create_reserve_proof(&wallet, &identity, pool, msg.as_bytes(), min)?;
            let text = r.to_text();
            if let Some(out) = out {
                std::fs::write(&out, &text)?;
                eprintln!("wrote {}", out.display());
            }
            eprintln!("Proof of funds: {} ZEC in {} note(s) at block {}, {} bytes.", chain::zec(r.total()), r.notes.len(), r.height, r.to_bytes().len());
            eprintln!("It reveals each note's value and nullifier (the verifier can see when they are spent), nothing else.");
            println!("{text}");
        }
        Cmd::Request { wallet, identity, domain, amount, memo, code, expires_in, payee } => {
            let zats = parse_zec(&amount)?;
            let code = code.unwrap_or_else(|| format!("{:032x}", rand::random::<u128>()));
            let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_secs();
            let (r, ua) = wallet::sign_payment_request(&wallet, &identity, &domain, zats, &memo, &code, now + expires_in, payee.as_deref())?;
            eprintln!("Signed request {} for {} ZEC to {ua}, valid {}s.", r.code, chain::zec(zats), expires_in);
            eprintln!("Publish this at https://{}/.well-known/zcash-receipts.json so wallets can check it:", r.domain);
            eprintln!("{}", serde_json::json!({ "payees": [ua] }));
            eprintln!("\nGive the payer this (they run `receipts pay '<it>'`):");
            println!("{}", r.to_text());
        }
        Cmd::Received { wallet, identity, txid, msg, outputs, pool, server, link_base, out } => {
            let pool = match pool.as_deref() {
                None => None,
                Some("ironwood") => Some(Pool::Ironwood),
                Some("orchard") => Some(Pool::Orchard),
                Some(other) => bail!("unknown pool {other}"),
            };
            let (r, height) = wallet::create_incoming_receipt(&wallet, &identity, parse_txid(&txid)?, msg.as_bytes(), &outputs, pool, server.as_deref()).await?;
            let text = r.to_text();
            if let Some(out) = out {
                std::fs::write(&out, &text)?;
                eprintln!("wrote {}", out.display());
            }
            eprintln!("Incoming receipt for {}: {} output(s) you received, {} bytes.", receipts_core::display_txid(&r.txid), r.outputs.len(), r.to_bytes().len());
            eprintln!("It shows the receiving address and these payments, and nothing else about your wallet.\n\nShare this link:");
            println!("{}#{}&h={}", link_base, text, height);
        }
        Cmd::SignIn { wallet, identity, domain, nonce, address, submit, api_key } => {
            eprintln!("Proving control of an address for {domain}…");
            let (s, addr) = tokio::task::spawn_blocking(move || wallet::sign_in(&wallet, &identity, &domain, &nonce, address.as_deref())).await??;
            eprintln!("address: {addr}");
            let text = s.to_text();
            match submit {
                None => println!("{text}"),
                Some(base) => {
                    let key = api_key.ok_or_else(|| anyhow::anyhow!("set RECEIPTS_KEY (or --api-key) to submit"))?;
                    let res = reqwest::Client::new()
                        .post(format!("{}/v1/sign_in/verify", base.trim_end_matches('/')))
                        .bearer_auth(key)
                        .json(&serde_json::json!({ "sign_in": text }))
                        .send()
                        .await?;
                    let status = res.status();
                    println!("{}", res.text().await?);
                    if !status.is_success() {
                        std::process::exit(1);
                    }
                }
            }
        }
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

#[allow(clippy::too_many_arguments)]
async fn pay(link: String, wallet_dir: PathBuf, identity: PathBuf, devtool: String, server: Option<String>, refund_to: Option<String>, dry_run: bool, paid_txid: Option<String>, yes: bool) -> anyhow::Result<()> {
    let refund_to = match refund_to.as_deref() {
        Some("fresh") => Some(wallet::fresh_address(&wallet_dir, &identity)?),
        _ => refund_to,
    };
    if let Some(a) = &refund_to {
        receipts_wallet::check_refund_address(a)?;
    }
    // What to pay: from the hosted page's public API, or from a receipt link's parameters.
    let link = link.trim().to_string();
    let parsed = reqwest::Url::parse(&link).ok();
    let hosted = parsed.as_ref().filter(|u| u.path().starts_with("/pay/") && u.path().len() > 5);
    let host = parsed.as_ref().and_then(|u| u.host_str().map(|h| match u.port() { Some(p) => format!("{h}:{p}"), None => h.to_string() })).unwrap_or_else(|| "(no host)".into());
    let signed = link.find(receipts_core::payreq::REQUEST_TEXT_PREFIX).map(|i| link[i..].chars().take_while(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_').collect::<String>());
    let mut memo_to_send: Option<String> = None;
    let mut need_source = false;
    let mut host = host;
    let (payee, amount, code, submit_to, receipt_link) = if let Some(text) = signed {
        let r = receipts_core::payreq::PaymentRequest::from_text(&text).ok_or_else(|| anyhow!("malformed signed request"))?;
        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_secs();
        let wallet_net = wallet::wallet_network(&wallet_dir)?;
        let raw = receipts_core::payreq::verify_request(&receipts_core::verifying_key(), &r, wallet_net.coin_type(), now).map_err(|e| anyhow!("refusing the request: {e}"))?;
        let ua = chain::encode_orchard_receiver(wallet_net, raw);
        match domain_lists(&r.domain, &raw).await {
            Ok(true) => println!("Signed by the payee, and {} lists this address.", r.domain),
            Ok(false) => bail!("refusing: {} does not list {ua} in its /.well-known/zcash-receipts.json; the request may have been tampered with", r.domain),
            Err(e) => bail!("refusing: could not confirm that {} lists the payee ({e})", r.domain),
        }
        host = r.domain.clone();
        memo_to_send = (!r.memo.is_empty()).then(|| r.memo.clone());
        if !r.memo.is_empty() {
            println!("  memo     {}", r.memo);
        }
        (ua, r.amount, r.code.clone(), None, DEFAULT_LINK_BASE.to_string())
    } else if let Some(u) = hosted {
        let base = format!("{}://{}", u.scheme(), host);
        let id = u.path()["/pay/".len()..].trim_end_matches('/').to_string();
        if !id.starts_with("preq_") || !id[5..].chars().all(|c| c.is_ascii_hexdigit()) {
            bail!("that doesn't look like a Receipts pay link");
        }
        let secret = u.query_pairs().find(|(k, _)| k == "secret").map(|(_, v)| v.into_owned()).ok_or_else(|| anyhow!("the pay link has no secret"))?;
        let (base, id, secret) = (base.as_str(), id.as_str(), secret.as_str());
        let info: serde_json::Value = reqwest::get(format!("{base}/v1/public/requests/{id}?secret={secret}")).await?.json().await?;
        if info.get("error").is_some() {
            bail!("the shop's server refused: {}", info["error"]["message"]);
        }
        if info["status"] != "open" {
            bail!("that request is {}, nothing to pay", info["status"]);
        }
        if info["kind"] == "campaign" {
            bail!("that's a campaign: choose your amount, pay it from your wallet, then `receipts create --request '<its receipt link>'`");
        }
        let rl = info["receipt_link"].as_str().unwrap_or_default().to_string();
        let r = parse_request(&rl)?;
        need_source = info["source_of_funds"]["required"] == true;
        let amount = info["remaining_zatoshis"].as_u64().or(info["amount_zatoshis"].as_u64()).ok_or_else(|| anyhow!("the request has no amount; pay it from your wallet and use `receipts create --request`"))?;
        (info["payee"].as_str().unwrap_or_default().to_string(), amount, r.code, Some((base.to_string(), id.to_string(), secret.to_string())), rl)
    } else {
        let r = parse_request(&link)?;
        let payee = r.to.clone().ok_or_else(|| anyhow!("the receipt link has no payee (to=)"))?;
        if r.min == 0 {
            bail!("the receipt link has no amount (min=); pay it from your wallet and use `receipts create --request`");
        }
        (payee, r.min, r.code, None, link.clone())
    };
    let check = receipts_core::preflight::check_payment_uri(&format!("zcash:{payee}?amount={}", chain::zec(amount)), None);
    if check["ok"] != true || check["payments"][0]["receipt_provable"] != true {
        bail!("that payee can't be proven with a receipt (needs an Orchard/Ironwood receiver)");
    }
    let wallet_net = wallet::wallet_network(&wallet_dir)?;
    let payee_net = check["payments"][0]["network"].as_str().unwrap_or("?");
    if !(payee_net == wallet_net.name() || (payee_net == "testnet" && wallet_net.name() == "regtest")) {
        bail!("the payee is a {payee_net} address but this wallet is for {}", wallet_net.name());
    }
    println!("Request {code} from {host}");
    println!("  pay      {} ZEC", chain::zec(amount));
    println!("  to       {payee}");
    if need_source {
        println!("  source   this deposit asks where the money came from: the receipt will prove which earlier");
        println!("           transaction created each note you spend, and nothing else about your wallet");
    }
    if dry_run {
        return Ok(());
    }
    if !yes && paid_txid.is_none() {
        use std::io::Write;
        print!("Send this payment? [y/N] ");
        std::io::stdout().flush()?;
        let mut answer = String::new();
        std::io::stdin().read_line(&mut answer)?;
        if !matches!(answer.trim(), "y" | "Y" | "yes") {
            bail!("not paid");
        }
    }
    let srv = server.clone();
    let devtool_run = |args: Vec<String>| {
        let devtool = devtool.clone();
        let wallet_dir = wallet_dir.clone();
        let srv = srv.clone();
        async move {
            let mut cmd = tokio::process::Command::new(&devtool);
            cmd.arg("wallet").arg("-w").arg(&wallet_dir).args(&args);
            if let Some(s) = &srv {
                cmd.arg("-s").arg(s);
            }
            let out = cmd.output().await.map_err(|e| anyhow!("running {devtool}: {e} (install zcash-devtool or pass --devtool)"))?;
            anyhow::Ok(String::from_utf8_lossy(&out.stdout).into_owned() + &String::from_utf8_lossy(&out.stderr))
        }
    };
    let txid = match paid_txid {
        Some(t) => t,
        None => {
            eprintln!("Syncing the wallet…");
            devtool_run(vec!["sync".into()]).await?;
            eprintln!("Sending…");
            let out = devtool_run(vec!["send".into(), "-i".into(), identity.display().to_string(), "--address".into(), payee.clone(), "--value".into(), amount.to_string(), "--memo".into(), memo_to_send.clone().unwrap_or_else(|| format!("Receipts request {code}"))]).await?;
            let txid = out.split_whitespace().rfind(|w| w.len() == 64 && w.chars().all(|c| c.is_ascii_hexdigit())).ok_or_else(|| anyhow!("the wallet did not send: {}", out.lines().rev().find(|l| !l.trim().is_empty()).unwrap_or("")))?.to_string();
            eprintln!("Sent {txid}.");
            txid
        }
    };
    eprintln!("Waiting for {txid} to be mined…");
    let net = wallet_net;
    let id = parse_txid(&txid)?;
    let mut mined = false;
    for _ in 0..120 {
        if chain::fetch_mined_tx(net, server.as_deref(), id).await.is_ok() {
            mined = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_secs(10)).await;
    }
    if !mined {
        bail!("{txid} is not mined after 20 minutes; run this again later with --txid {txid}");
    }
    let mut msg = format!("challenge:{code}");
    if let Some(a) = &refund_to {
        msg.push_str(&format!("\nrefund-to:{a}"));
    }
    // The wallet learns the block a little after the chain does: sync until it has it.
    let mut attempt = 0;
    let (receipt, height) = loop {
        devtool_run(vec!["sync".into()]).await?;
        match wallet::create_receipt(&wallet_dir, &identity, id, msg.as_bytes(), &[], None, wallet::WitnessSource::Auto, server.as_deref(), None, need_source.then_some(wallet::SourceMode::HideValue), false).await {
            Ok(x) => break x,
            Err(e) if attempt < 12 && e.to_string().contains("not mined") => {
                attempt += 1;
                tokio::time::sleep(std::time::Duration::from_secs(10)).await;
            }
            Err(e) => return Err(e),
        }
    };
    let text = receipt.to_text();
    match submit_to {
        Some((base, rid, secret)) => {
            let res = reqwest::Client::new().post(format!("{base}/v1/public/requests/{rid}/receipts")).json(&serde_json::json!({ "receipt": text, "client_secret": secret })).send().await?;
            let ok = res.status().is_success();
            let body: serde_json::Value = res.json().await.unwrap_or_default();
            if ok {
                match body["status"].as_str() {
                    Some("held_for_review") => println!("Paid and proven: request {rid} is held while the shop reviews where the funds came from."),
                    s => println!("Paid and proven: request {rid} is {}.", s.unwrap_or("updated")),
                }
            } else {
                println!("The shop refused the receipt: {}", body["error"]["message"].as_str().unwrap_or("unknown error"));
                println!("{text}");
                std::process::exit(1);
            }
        }
        None => {
            println!("Paid. Send this receipt link back to the shop:");
            println!("{}#{}&h={height}", receipt_link.split('#').next().unwrap_or(&receipt_link), text);
        }
    }
    Ok(())
}

async fn doctor(wallet: Option<PathBuf>, api_key: Option<String>, base_url: String, quick: bool) -> anyhow::Result<()> {
    let mut problems = 0;
    let mut line = |ok: Option<bool>, what: &str, detail: String| {
        let mark = match ok { Some(true) => "ok  ", Some(false) => "FIX ", None => "--  " };
        if ok == Some(false) {
            problems += 1;
        }
        println!("{mark} {what:<22} {detail}");
    };
    println!("receipts {}", env!("CARGO_PKG_VERSION"));
    for net in [net::Net::Main, net::Net::Test] {
        let t0 = std::time::Instant::now();
        match tokio::time::timeout(std::time::Duration::from_secs(15), chain::chain_tip(net, None)).await {
            Ok(Ok(h)) => line(Some(true), &format!("lightwalletd {}", net.name()), format!("{} at height {h} ({} ms)", net.default_server(), t0.elapsed().as_millis())),
            Ok(Err(e)) => line(Some(false), &format!("lightwalletd {}", net.name()), format!("{}: {e}. Pass -s host:port to use another server", net.default_server())),
            Err(_) => line(Some(false), &format!("lightwalletd {}", net.name()), format!("{} did not answer in 15 s", net.default_server())),
        }
    }
    let http = reqwest::Client::builder().timeout(std::time::Duration::from_secs(10)).build()?;
    match http.get(format!("{}/v1/health", base_url.trim_end_matches('/'))).send().await {
        Ok(res) => {
            let date = res.headers().get("date").and_then(|d| d.to_str().ok()).map(str::to_string);
            let health: serde_json::Value = res.json().await.unwrap_or_default();
            line(Some(health["ok"] == true), "Receipts API", format!("{base_url} (version {}; test keys use {}, live keys {})", health["version"].as_str().unwrap_or("?"), health["test_network"].as_str().unwrap_or("?"), health["live_network"].as_str().unwrap_or("mainnet")));
            if let Some(d) = date.and_then(|d| httpdate_to_unix(&d)) {
                let skew = (std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_secs() as i64 - d).abs();
                line(Some(skew < 120), "clock", if skew < 120 { format!("within {skew} s of the API") } else { format!("{skew} s off the API; webhook signatures allow 300 s, fix your clock") });
            }
            match &api_key {
                None => line(None, "API key", "RECEIPTS_KEY not set (only needed for the API, listen, trigger and mcp)".into()),
                Some(k) => {
                    let r = http.get(format!("{}/v1/requests?limit=1", base_url.trim_end_matches('/'))).bearer_auth(k).send().await;
                    match r {
                        Ok(r) if r.status().is_success() => line(Some(true), "API key", format!("accepted ({} mode)", if k.starts_with("rcpt_live_") { "live" } else { "test" })),
                        Ok(r) => line(Some(false), "API key", format!("refused ({}); use a key `receipts serve` printed", r.status())),
                        Err(e) => line(Some(false), "API key", e.to_string()),
                    }
                }
            }
        }
        // Unreachable is only a problem if you meant to use it (a key is set, or the URL was chosen).
        Err(_) => line(
            (api_key.is_some() || std::env::args().any(|a| a.starts_with("--base-url")) || std::env::var("RECEIPTS_URL").is_ok()).then_some(false),
            "Receipts API",
            format!("nothing at {base_url} (start one with `receipts serve`, or set RECEIPTS_URL)"),
        ),
    }
    if let Some(w) = wallet {
        let keys = w.join("keys.toml");
        match std::fs::read_to_string(&keys) {
            Err(_) => line(Some(false), "wallet", format!("{} not found; -w must be a zcash-devtool wallet directory", keys.display())),
            Ok(t) => {
                let netname = t.lines().find_map(|l| l.trim().strip_prefix("network = ")).map(|s| s.trim_matches('"').to_string()).unwrap_or_else(|| "test".into());
                let db = w.join("data.sqlite");
                let synced: Option<u32> = rusqlite_height(&db);
                let net = match netname.as_str() { "main" => Some(net::Net::Main), "test" => Some(net::Net::Test), _ => None };
                let tip = match net { Some(n) => chain::chain_tip(n, None).await.ok(), None => None };
                let behind = match (synced, tip) { (Some(s), Some(t)) => Some(t.saturating_sub(s)), _ => None };
                let ok = db.exists() && synced.is_some() && behind.is_none_or(|b| b <= 10);
                line(Some(ok), "wallet", match (synced, behind) {
                    (None, _) => format!("{} ({netname}): sync height unknown; run `zcash-devtool wallet sync`", w.display()),
                    (Some(s), Some(b)) if b > 10 => format!("{} ({netname}) is {b} blocks behind (at {s}); run `zcash-devtool wallet sync`", w.display()),
                    (Some(s), _) => format!("{} ({netname}), synced to {s}", w.display()),
                });
                if t.contains("AGE-SECRET-KEY") {
                    line(Some(false), "wallet secrets", "keys.toml contains an age secret key; keep identities in a separate file".into());
                }
            }
        }
    }
    if !quick {
        let t0 = std::time::Instant::now();
        let _ = tokio::task::spawn_blocking(receipts_core::verifying_key).await;
        let vk_ms = t0.elapsed().as_millis();
        let t1 = std::time::Instant::now();
        let _ = tokio::task::spawn_blocking(receipts_core::proving_key).await;
        line(Some(true), "proof keys", format!("verifying key built in {vk_ms} ms, proving key in {} ms on this machine (then one Halo 2 proof per disclosed spend; the testnet receipt in examples/ took 2.4 s end to end)", t1.elapsed().as_millis()));
    }
    println!();
    if problems == 0 {
        println!("All good.");
        Ok(())
    } else {
        println!("{problems} thing(s) to fix above.");
        std::process::exit(1);
    }
}

/// Unix time from an HTTP `Date` header (`Thu, 15 Oct 2026 00:12:34 GMT`).
fn httpdate_to_unix(s: &str) -> Option<i64> {
    let p: Vec<&str> = s.split_whitespace().collect();
    let [_, d, mon, y, hms, _] = p[..] else { return None };
    let m = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"].iter().position(|x| *x == mon)? as i64 + 1;
    let (d, y): (i64, i64) = (d.parse().ok()?, y.parse().ok()?);
    let t: Vec<i64> = hms.split(':').map(|x| x.parse().ok()).collect::<Option<_>>()?;
    let y2 = if m <= 2 { y - 1 } else { y };
    let era = y2.div_euclid(400);
    let yoe = y2 - era * 400;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1;
    let days = era * 146_097 + yoe * 365 + yoe / 4 - yoe / 100 + doy - 719_468;
    Some(days * 86_400 + t[0] * 3600 + t[1] * 60 + t[2])
}

fn rusqlite_height(db: &std::path::Path) -> Option<u32> {
    let c = rusqlite::Connection::open_with_flags(db, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY).ok()?;
    c.query_row("SELECT MAX(height) FROM blocks", [], |r| r.get::<_, Option<u32>>(0)).ok().flatten()
}

fn print_deposit(report: &chain::Report, d: &receipts_chain::deposit::Deposit, json: bool) -> anyhow::Result<()> {
    if json {
        println!("{}", serde_json::to_string_pretty(&serde_json::json!({ "receipt": report, "deposit": d.to_json() }))?);
    } else {
        report.print();
        println!("EXCHANGE DEPOSIT (ZIP 320)");
        println!("  paid      {} ZEC to {}", chain::zec(d.deposit_zatoshis), d.tex_address);
        println!("  via       {} -> {}", d.first_tx, d.second_tx);
        println!("  the sender proved they made this deposit.");
        println!("  warning   {}", d.warning);
    }
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
    const EVENTS: &[&str] = &["request.created", "request.fulfilled", "request.final", "receipt.rejected", "request.expired", "request.payment_received", "refund.created", "refund.succeeded", "request.payment_reorged"];
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
        // Sandbox payments are final at once, so this fires request.fulfilled then request.final.
        "request.fulfilled" | "request.final" => {
            client.submit_receipt(&id, "zrcpt_test_valid").await?;
        }
        "request.payment_reorged" => {
            let clock = client.create_test_clock(None).await?;
            let cid = clock["id"].as_str().unwrap_or_default().to_string();
            eprintln!("(on a new test clock {cid})");
            let req = client
                .create_request(&receipts_client::CreateRequest {
                    payee: SANDBOX_PAYEE.into(),
                    amount_zatoshis: Some(1_000_000),
                    label: Some("receipts trigger request.payment_reorged".into()),
                    test_clock: Some(cid.clone()),
                    ..Default::default()
                })
                .await?;
            let rid = req["id"].as_str().unwrap_or_default().to_string();
            client.submit_receipt(&rid, "zrcpt_test_valid").await?;
            client.reorg_test_clock(&cid, 1).await?;
            eprintln!("Triggered {event} on {rid}");
            return Ok(());
        }
        "refund.created" | "refund.succeeded" => {
            client.submit_receipt(&id, "zrcpt_test_refund_to").await?;
            let rf = client.create_refund(&id, None, Some("receipts trigger")).await?;
            if event == "refund.succeeded" {
                client.submit_refund_receipt(rf["id"].as_str().unwrap_or_default(), "zrcpt_test_valid").await?;
            }
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
