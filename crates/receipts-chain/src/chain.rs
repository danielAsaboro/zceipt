//! Fetching transactions from lightwalletd and verifying receipts against them.

use crate::net::{self, Net};
use anyhow::{anyhow, bail, Context};
use receipts_core::{display_txid, Pool, Receipt};
use serde::Serialize;
use tonic::transport::{Channel, ClientTlsConfig};
use zcash_address::unified::{self, Container, Encoding};
use zcash_client_backend::proto::service::{compact_tx_streamer_client::CompactTxStreamerClient, TxFilter};
use zcash_primitives::transaction::Transaction;
use zcash_protocol::consensus::{BlockHeight, BranchId, Parameters};

pub async fn connect(server: &str) -> anyhow::Result<CompactTxStreamerClient<Channel>> {
    let host = server.split(':').next().unwrap_or(server).to_string();
    let local = matches!(host.as_str(), "localhost" | "127.0.0.1");
    let uri = format!("{}://{}", if local { "http" } else { "https" }, server);
    let mut ch = Channel::from_shared(uri)?;
    if !local {
        ch = ch.tls_config(ClientTlsConfig::new().domain_name(host).assume_http2(true).with_webpki_roots())?;
    }
    Ok(CompactTxStreamerClient::new(ch.connect().await.context("connecting to lightwalletd")?))
}

/// Height of the chain tip, as lightwalletd sees it.
pub async fn chain_tip(net: Net, server: Option<&str>) -> anyhow::Result<u32> {
    let mut client = connect(server.unwrap_or(net.default_server())).await?;
    let b =
        client.get_latest_block(zcash_client_backend::proto::service::ChainSpec {}).await.map_err(|e| anyhow!("latest block: {}", e.message()))?.into_inner();
    Ok(b.height as u32)
}

/// Confirmations after which a receipt is reported `final` (reorgs deeper than this are not expected).
pub const FINALITY_CONFIRMATIONS: u32 = 10;

/// Fetches a mined transaction. Returns the transaction and its block height.
pub async fn fetch_mined_tx(net: Net, server: Option<&str>, txid: [u8; 32]) -> anyhow::Result<(Transaction, u32)> {
    let mut client = connect(server.unwrap_or(net.default_server())).await?;
    fetch_mined_tx_with(&mut client, net, txid).await
}

async fn fetch_mined_tx_with(client: &mut CompactTxStreamerClient<Channel>, net: Net, txid: [u8; 32]) -> anyhow::Result<(Transaction, u32)> {
    let raw = client
        .get_transaction(TxFilter { block: None, index: 0, hash: txid.to_vec() })
        .await
        .map_err(|e| anyhow!("lightwalletd could not find {}: {}", display_txid(&txid), e.message()))?
        .into_inner();
    let height = u32::try_from(raw.height).unwrap_or(0);
    if height == 0 {
        bail!("transaction {} is not mined yet", display_txid(&txid));
    }
    let branch = BranchId::for_height(&net, BlockHeight::from_u32(height));
    let tx = Transaction::read(&raw.data[..], branch)?;
    if tx.txid().as_ref() != &txid {
        bail!("server returned a different transaction");
    }
    Ok((tx, height))
}

/// How many transactions a block-hinted fetch asks for, ours included.
pub const PRIVATE_FETCH_SET: usize = 64;

/// The window of a block's `n` transactions that holds position `pos`: the block is cut into
/// equal windows of at most `max`, so the last one is never a lone transaction (65 → 33 + 32).
/// Returns (start, size).
pub fn window_of(n: usize, pos: usize, max: usize) -> (usize, usize) {
    let size = n.div_ceil(n.div_ceil(max).max(1)).max(1);
    (pos / size * size, size)
}
/// Below this many candidates in the payment's block, the other blocks of its aligned run of 4 are fetched too.
pub const MIN_PRIVATE_SET: usize = 8;

/// Fetches `txid` without telling the server which transaction is wanted: lists the shielded
/// transactions in block `height`, then fetches the run of up to [`PRIVATE_FETCH_SET`] of them
/// that holds `txid` (the same run every time), in random order. Returns the transaction, its height and how many were
/// fetched (the anonymity set; 1 means the block hid nothing). Same scheme as the browser's.
pub async fn fetch_mined_tx_in_block(net: Net, server: Option<&str>, txid: [u8; 32], height: u32) -> anyhow::Result<(Transaction, u32, usize)> {
    use zcash_client_backend::proto::service::BlockId;
    let mut client = connect(server.unwrap_or(net.default_server())).await?;
    // The whole aligned run of 4 blocks holding the payment is listed every time, in random
    // order, so neither which blocks are asked for nor their order points at the payment's.
    let first = height - height % 4;
    let mut run: Vec<u32> = (first..first + 4).collect();
    shuffle(&mut run)?;
    let mut listed = std::collections::HashMap::new();
    for h in run {
        if let Ok(b) = client.get_block(BlockId { height: u64::from(h), hash: vec![] }).await {
            listed.insert(h, b.into_inner());
        }
    }
    let block = listed.remove(&height).ok_or_else(|| anyhow!("block {height}: the server didn't send it"))?;
    let all: Vec<([u8; 32], bool)> = block
        .vtx
        .iter()
        .filter_map(|t| {
            // Only Orchard or Ironwood transactions can carry a receipt (Sapling-only ones can't).
            let shielded = !(t.actions.is_empty() && t.ironwood_actions.is_empty());
            <[u8; 32]>::try_from(t.txid.as_slice()).ok().map(|id| (id, shielded && t.index != 0))
        })
        .collect();
    if !all.iter().any(|(id, _)| *id == txid) {
        bail!("transaction {} is not in block {height}", display_txid(&txid));
    }
    // Only transactions that could carry a receipt are cover: ones with Orchard or Ironwood
    // actions, not the coinbase, transparent-only or Sapling-only ones. (If the server's compact data doesn't show ours as shielded, fall
    // back to every transaction but the coinbase.)
    let mut ids: Vec<[u8; 32]> = all.iter().filter(|(_, s)| *s).map(|(id, _)| *id).collect();
    if !ids.contains(&txid) {
        ids = block.vtx.iter().filter(|t| t.index != 0).filter_map(|t| <[u8; 32]>::try_from(t.txid.as_slice()).ok()).collect();
        if !ids.contains(&txid) {
            ids = all.iter().map(|(id, _)| *id).collect();
        }
    }
    // The set is the block's run of PRIVATE_FETCH_SET transactions that holds ours, fixed by
    // block order, so checking the same receipt twice asks for the same set: random decoys would
    // differ each time and their intersection would point at the target.
    // A txid listed twice counts once.
    let mut seen = std::collections::HashSet::new();
    ids.retain(|t| seen.insert(*t));
    let pos = ids.iter().position(|t| *t == txid).expect("checked above");
    let (start, size) = window_of(ids.len(), pos, PRIVATE_FETCH_SET);
    let mut others: Vec<[u8; 32]> = ids[start..(start + size).min(ids.len())].to_vec();
    let mut block_of: std::collections::HashMap<[u8; 32], u32> = others.iter().map(|t| (*t, height)).collect();
    // A quiet block hides little: then the rest of its aligned run of 4 blocks joins the cover.
    // The run is fixed by the height, not centred on it, so the requests don't point at the
    // payment's block.
    // Quiet is about the whole block, not the window of it that holds the payment.
    if ids.len() < MIN_PRIVATE_SET {
        for (h, b) in &listed {
            let h = *h;
            // Only other quiet blocks: the server can see the cover widened, so it knows the
            // payment's block is quiet, and a busy block's transactions would hide nothing.
            let candidates = b.vtx.iter().filter(|t| t.index != 0 && !(t.actions.is_empty() && t.ironwood_actions.is_empty())).count();
            if candidates >= MIN_PRIVATE_SET {
                continue;
            }
            for t in b.vtx.iter().filter(|t| t.index != 0 && !(t.actions.is_empty() && t.ironwood_actions.is_empty())).take(PRIVATE_FETCH_SET) {
                if let Ok(id) = <[u8; 32]>::try_from(t.txid.as_slice()) {
                    if block_of.insert(id, h).is_none() {
                        others.push(id);
                    }
                }
            }
        }
    }
    shuffle(&mut others)?;
    let mut mine = None;
    let mut real_decoys = 0;
    for t in others {
        // Every transaction is fetched and checked the same way, and every one is fetched even if
        // ours fails, so neither the requests nor where they stop point at ours.
        let fetched = fetch_mined_tx_with(&mut client, net, t).await;
        if t == txid {
            mine = Some(fetched);
        } else if fetched
            .is_ok_and(|(tx, h)| Some(&h) == block_of.get(&t) && tx.txid().as_ref() == &t && (tx.orchard_bundle().is_some() || tx.ironwood_bundle().is_some()))
        {
            // A decoy only counts if the server really has it (its bytes hash to the txid asked
            // for), in this block, with Orchard or Ironwood actions: a hostile server could list
            // made-up txids around ours, or answer them all with one real transaction.
            real_decoys += 1;
        }
    }
    let (tx, h) = mine.expect("txid is in the set")?;
    let set = real_decoys + 1;
    if h != height {
        bail!("the server put transaction {} at block {h}, not {height}", display_txid(&txid));
    }
    Ok((tx, h, set))
}

/// Whether block `height` (on the server's current chain) contains `txid`, from the block's
/// compact form: the server learns which block is being watched, not which transaction.
pub async fn tx_in_block(net: Net, server: Option<&str>, txid: [u8; 32], height: u32) -> anyhow::Result<bool> {
    use zcash_client_backend::proto::service::BlockId;
    let mut client = connect(server.unwrap_or(net.default_server())).await?;
    let block =
        client.get_block(BlockId { height: u64::from(height), hash: vec![] }).await.map_err(|e| anyhow!("block {height}: {}", e.message()))?.into_inner();
    Ok(block.vtx.iter().any(|t| t.txid.as_slice() == txid))
}

/// Fisher-Yates with the OS random number generator.
fn shuffle<T>(v: &mut [T]) -> anyhow::Result<()> {
    for i in (1..v.len()).rev() {
        let mut b = [0u8; 8];
        getrandom::fill(&mut b).map_err(|e| anyhow!("OS RNG: {e}"))?;
        v.swap(i, (u64::from_le_bytes(b) % (i as u64 + 1)) as usize);
    }
    Ok(())
}

/// The block-height hint in a receipt link (`…&h=4500997`), if any. Unsigned: only a fetch hint.
pub fn height_hint(link: &str) -> Option<u32> {
    let i = link.find("&h=").or_else(|| link.find("?h=")).or_else(|| link.find("#h="))?;
    let digits: String = link[i + 3..].chars().take_while(|c| c.is_ascii_digit()).collect();
    (1..=9).contains(&digits.len()).then(|| digits.parse().ok()).flatten()
}

/// A batch link's block hints (`…&h=12,40,41`), one per receipt in order, if any.
pub fn height_hints(link: &str) -> Option<Vec<u32>> {
    let i = link.find("&h=").or_else(|| link.find("?h=")).or_else(|| link.find("#h="))?;
    let list: String = link[i + 3..].chars().take_while(|c| c.is_ascii_digit() || *c == ',').collect();
    list.split(',').map(|d| if (1..=9).contains(&d.len()) { d.parse().ok() } else { None }).collect()
}

#[derive(Serialize)]
pub struct Report {
    pub valid: bool,
    pub network: &'static str,
    pub pool: &'static str,
    pub txid: String,
    pub mined_height: u32,
    /// False for offline verification: the transaction and height were supplied, not fetched from
    /// the chain, so the report shows the receipt matches that transaction, not that it was mined.
    pub chain_checked: bool,
    /// Signed with the public demo wallet's key (`receipts_core::PUBLIC_DEMO_TXIDS`): anyone can.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub public_demo: bool,
    pub message: String,
    pub proven_spend_actions: Vec<u32>,
    /// Public addresses the sender proved they control (empty unless they chose to).
    pub sender_addresses: Vec<String>,
    /// Where spent notes came from, for spends whose source the sender chose to prove.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub sources: Vec<ReportSource>,
    pub outputs: Vec<ReportOutput>,
    /// With a block hint: how many transactions that could carry a receipt were fetched with
    /// this one (the server can't tell which of them was checked).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub anonymity_set: Option<usize>,
    /// The nullifier each proven spend's action published (for screened-set proofs).
    #[serde(skip)]
    pub spend_nullifiers: Vec<(u32, [u8; 32])>,
    /// Set by `check_screened`: the screened list the spent notes were proven to come from.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub screened_set: Option<ScreenedSet>,
}

/// A screened-set check that passed: every proven spend's note is one of the `size` outputs of
/// the list whose tree root is `root`.
#[derive(Serialize, Clone)]
pub struct ScreenedSet {
    pub root: String,
    pub size: usize,
    /// At least this much of the spent notes' value came from the list (zatoshis).
    pub covered_zatoshis: u64,
}

/// Checks screened-set proofs (`zip311s1…`, one per spend) for a receipt `report` came from,
/// against the published `set` of note commitments. Every proven spend needs one.
pub fn check_screened(report: &mut Report, receipt: &Receipt, proofs: &[receipts_core::screened::ScreenedProof], set: &[[u8; 32]]) -> anyhow::Result<()> {
    static VK: std::sync::OnceLock<orchard::circuit::VerifyingKey> = std::sync::OnceLock::new();
    let vk = VK.get_or_init(receipts_core::verifying_key);
    for (index, nf) in &report.spend_nullifiers {
        let p = proofs.iter().find(|p| p.index == *index).ok_or_else(|| anyhow!("no screened-set proof for the spend in action {index}"))?;
        receipts_core::screened::verify(vk, receipt, nf, p, set).map_err(|e| anyhow!("{e}"))?;
    }
    let covered = report.spend_nullifiers.iter().filter_map(|(i, _)| proofs.iter().find(|p| p.index == *i)).map(|p| p.floor).sum();
    report.screened_set = Some(ScreenedSet { root: hex::encode(receipts_core::screened::set_root(set)?), size: set.len(), covered_zatoshis: covered });
    Ok(())
}

/// A proven source: the note spent by `spend_action` was created by `source_action` of
/// `source_txid`, a transaction the verifier fetched (or was given) and read.
#[derive(Serialize)]
pub struct ReportSource {
    pub spend_action: u32,
    pub source_txid: String,
    pub source_action: u32,
    pub source_height: u32,
    /// The note's value, if the sender revealed it.
    pub zatoshis: Option<u64>,
    pub zec: Option<String>,
    /// The source transaction's public transparent inputs: who funded it, if it was funded in
    /// the clear (an exchange withdrawal shielded by the sender, for instance).
    pub transparent_inputs: Vec<FundingInput>,
    /// Net value the source transaction moved from transparent into the shielded pools (public).
    /// Shielded spends inside it, if any, are not visible, and their origin stays hidden unless
    /// the sender proves it with another receipt.
    pub net_into_shielded_zatoshis: i64,
}

#[derive(Serialize, Clone)]
pub struct FundingInput {
    pub prevout_txid: String,
    pub prevout_index: u32,
    /// The address and value the input spent, if the verifier could read the previous output.
    pub address: Option<String>,
    pub zatoshis: Option<u64>,
}

/// A source transaction the verifier has read, with what it learned about its funding.
pub struct SourceTx {
    pub tx: Transaction,
    pub height: u32,
    pub transparent_inputs: Vec<FundingInput>,
}

#[derive(Serialize)]
pub struct ReportOutput {
    pub action: u32,
    pub recipient: String,
    #[serde(skip)]
    pub recipient_raw: [u8; 43],
    pub zatoshis: u64,
    pub zec: String,
    pub memo: Option<String>,
    /// The sender disclosed this output without its memo.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub memo_withheld: bool,
}

/// The currency name for amounts on `network` ("TAZ" on testnet and regtest).
pub fn unit(network: &str) -> &'static str {
    if network == "mainnet" {
        "ZEC"
    } else {
        "TAZ"
    }
}

/// Text a sender chose (messages, memos), made safe to print: control characters and bidi
/// overrides are shown as `\u{..}` escapes, so a memo can't move the cursor, recolour or reorder
/// what the verifier prints, and each line break is followed by `indent`.
pub fn shown(text: &str, indent: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '\n' => {
                out.push('\n');
                out.push_str(indent);
            }
            c if c.is_control() || matches!(c, '\u{200e}' | '\u{200f}' | '\u{061c}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}') => {
                out.push_str(&c.escape_unicode().to_string());
            }
            c => out.push(c),
        }
    }
    out
}

impl Report {
    pub fn print(&self) {
        let u = unit(self.network);
        println!("{}", if self.chain_checked { "VALID receipt" } else { "VALID receipt for the transaction given (not checked on chain)" });
        if self.public_demo {
            println!("  DEMO      signed with the public demo wallet's key: anyone can make these, so it proves nothing about who paid");
        }
        println!("  network   {}", self.network);
        if self.chain_checked {
            println!("  tx        {} (mined at height {})", self.txid, self.mined_height);
        } else {
            println!("  tx        {} (height {} as given; not checked against the chain)", self.txid, self.mined_height);
            println!("  offline   this shows the receipt matches the transaction you supplied, not that it was mined");
        }
        println!("  pool      {}", self.pool);
        if !self.message.is_empty() {
            println!("  message   {}", shown(&self.message, "            "));
        }
        println!("  sender    proved spend authority for action(s) {:?}", self.proven_spend_actions);
        if let Some(set) = &self.screened_set {
            println!("  funds     each spend this receipt proves used a note from the screened list of {} outputs (root {}…), not saying which; at least {} {} of their value came from it", set.size, &set.root[..16], zec(set.covered_zatoshis), unit(self.network));
        }
        for a in &self.sender_addresses {
            println!("  from      {a} (the receipt's signer controls it)");
        }
        for src in &self.sources {
            let value = src.zec.as_ref().map(|z| format!("a {z} {u} note")).unwrap_or_else(|| "the note".into());
            println!(
                "  source    action {} spent {value} created by tx {} action {} (height {})",
                src.spend_action, src.source_txid, src.source_action, src.source_height
            );
            for t in &src.transparent_inputs {
                match (&t.address, t.zatoshis) {
                    (Some(a), Some(z)) => println!("            that tx was funded in the clear: {} {u} from {a}", zec(z)),
                    _ => println!("            that tx spent transparent output {}:{}", t.prevout_txid, t.prevout_index),
                }
            }
            if src.transparent_inputs.is_empty() {
                println!("            that tx had no transparent inputs: its own funding was shielded and is not shown");
            } else if src.net_into_shielded_zatoshis > 0 {
                println!("            it moved {} {u} from transparent into the shielded pool", zec(src.net_into_shielded_zatoshis as u64));
            }
        }
        for o in &self.outputs {
            println!("  paid      {} {u} to {}", o.zec, o.recipient);
            if let Some(m) = &o.memo {
                println!("            memo: {}", shown(m, "                  "));
            } else if o.memo_withheld {
                println!("            memo: withheld by the sender (not in the receipt)");
            }
        }
        if crate::deposit::deposit_claim(&self.message).is_some() {
            // The deposit block that follows says what this does reveal.
        } else if !self.sources.is_empty() {
            println!("  nothing else about the sender's wallet (balance, other transactions) is revealed");
        } else if self.sender_addresses.is_empty() {
            println!("  nothing else about the sender's wallet is revealed");
        } else {
            println!("  nothing else about the sender's wallet (balance, other transactions) is revealed");
        }
    }
}

pub fn encode_orchard_receiver(net: Net, raw: [u8; 43]) -> String {
    let ua = unified::Address::try_from_items(unified::Revision::R0, vec![unified::Uitem::Data(unified::Receiver::Orchard(raw))]).expect("one receiver");
    ua.encode(&net.network_type())
}

pub fn orchard_receiver_of(ua: &str) -> anyhow::Result<[u8; 43]> {
    let (_, _, addr) = unified::Address::decode(ua).map_err(|e| anyhow!("not a unified address: {e}"))?;
    addr.items()
        .into_iter()
        .find_map(|r| match r {
            unified::Receiver::Orchard(b) => Some(b),
            _ => None,
        })
        .ok_or_else(|| anyhow!("that unified address has no Orchard receiver"))
}

/// The Orchard receiver of `ua`, refusing an address of another network than `network`
/// ("mainnet", "testnet" or "regtest", as reports name them): the raw receiver bytes carry no
/// network, so comparing them alone would let a testnet payment satisfy a mainnet payee.
pub fn orchard_receiver_on(network: &str, ua: &str) -> anyhow::Result<[u8; 43]> {
    use zcash_protocol::consensus::NetworkType;
    let (nt, _, _) = unified::Address::decode(ua).map_err(|e| anyhow!("not a unified address: {e}"))?;
    // Testnet and regtest share a coin type, so a receipt can't tell them apart: only mainnet
    // versus the test networks is checked.
    let ok = matches!((network, nt), ("mainnet", NetworkType::Main) | ("testnet" | "regtest", NetworkType::Test | NetworkType::Regtest));
    if !ok {
        bail!(
            "{} is a {} address, but the payment is on {network}",
            short_ua(ua),
            match nt {
                NetworkType::Main => "mainnet",
                NetworkType::Test => "testnet",
                NetworkType::Regtest => "regtest",
            }
        );
    }
    orchard_receiver_of(ua)
}

/// What a verified receipt paid `ua`: the sum of its disclosed outputs to that address's Orchard
/// receiver. The address must be on the receipt's network, and outputs disclosed without their
/// memo don't count (they don't show the payee can receive the note). The CLI's "was I paid"
/// checks and the Rust run of the conformance vectors go through this; the server, npm and page
/// apply the same rule (and the shared expectation vectors check they agree).
pub fn paid_to_address(report: &Report, ua: &str) -> anyhow::Result<u64> {
    let want = orchard_receiver_on(report.network, ua)?;
    Ok(report.outputs.iter().filter(|o| o.recipient_raw == want && !o.memo_withheld).map(|o| o.zatoshis).sum())
}

fn short_ua(ua: &str) -> String {
    if ua.len() > 16 {
        format!("{}…", &ua[..14])
    } else {
        ua.to_string()
    }
}

pub fn memo_text(memo: &[u8; 512]) -> Option<String> {
    if memo[0] > 0xf4 {
        return None; // not a text memo (ZIP 302)
    }
    let end = memo.iter().rposition(|&b| b != 0).map(|i| i + 1).unwrap_or(0);
    if end == 0 {
        return None;
    }
    std::str::from_utf8(&memo[..end]).ok().map(str::to_string)
}

pub fn zec(z: u64) -> String {
    format!("{}.{:08}", z / 100_000_000, z % 100_000_000)
}

/// Verifies a receipt against a raw transaction (hex) at a known height: no network at all.
pub fn verify_offline(receipt: &Receipt, raw_hex: &str, height: u32, regtest: Option<&std::path::Path>) -> anyhow::Result<Report> {
    verify_offline_with_sources(receipt, raw_hex, height, &[], regtest)
}

/// Like `verify_offline`, with the raw source transactions (hex) and their heights for source
/// proofs. Their transparent inputs are listed by outpoint only (no previous outputs offline).
pub fn verify_offline_with_sources(
    receipt: &Receipt,
    raw_hex: &str,
    height: u32,
    sources: &[(String, u32)],
    regtest: Option<&std::path::Path>,
) -> anyhow::Result<Report> {
    let u = &receipt.unsigned;
    let net = net::for_receipt(u.coin_type, regtest)?;
    let tx = read_tx(net, raw_hex, height)?;
    if tx.txid().as_ref() != &u.txid {
        bail!("that transaction is not the one this receipt is for");
    }
    let mut map = std::collections::BTreeMap::new();
    for (hex_text, h) in sources {
        let stx = read_tx(net, hex_text, *h)?;
        let id: [u8; 32] = *stx.txid().as_ref();
        let transparent_inputs = outpoints(&stx)
            .into_iter()
            .map(|(t, n)| FundingInput { prevout_txid: display_txid(&t), prevout_index: n, address: None, zatoshis: None })
            .collect();
        map.insert(id, SourceTx { tx: stx, height: *h, transparent_inputs });
    }
    let mut r = report_for(receipt, net, &tx, height, &map, None, None, None)?;
    r.chain_checked = false;
    Ok(r)
}

fn read_tx(net: Net, raw_hex: &str, height: u32) -> anyhow::Result<Transaction> {
    let raw = hex_decode(raw_hex.trim())?;
    let branch = BranchId::for_height(&net, BlockHeight::from_u32(height));
    Ok(Transaction::read(&raw[..], branch)?)
}

/// The transparent outpoints a transaction spends.
fn outpoints(tx: &Transaction) -> Vec<([u8; 32], u32)> {
    tx.transparent_bundle().map(|b| b.vin.iter().map(|i| (*i.prevout().hash(), i.prevout().n())).collect()).unwrap_or_default()
}

/// Net value a transaction moved from transparent into the shielded pools (negative: out).
pub fn net_into_shielded(tx: &Transaction) -> i64 {
    let o = tx.orchard_bundle().map(|b| i64::from(*b.value_balance())).unwrap_or(0);
    let i = tx.ironwood_bundle().map(|b| i64::from(*b.value_balance())).unwrap_or(0);
    let s = tx.sapling_bundle().map(|b| i64::from(*b.value_balance())).unwrap_or(0);
    -(o + i + s)
}

/// Encodes a transparent output's address, if it is a standard P2PKH or P2SH output.
fn transparent_address(net: Net, out: &zcash_transparent::bundle::TxOut) -> Option<String> {
    use zcash_address::ToAddress;
    use zcash_transparent::address::TransparentAddress;
    let nt = crate::deposit::network_type(net);
    Some(match out.recipient_address()? {
        TransparentAddress::PublicKeyHash(h) => zcash_address::ZcashAddress::from_transparent_p2pkh(nt, h).encode(),
        TransparentAddress::ScriptHash(h) => zcash_address::ZcashAddress::from_transparent_p2sh(nt, h).encode(),
    })
}

/// Fetches the source transactions a receipt's source proofs name, and the previous outputs
/// their transparent inputs spent (at most `MAX_FUNDING_INPUTS` per source).
pub async fn fetch_sources(receipt: &Receipt, net: Net, server: Option<&str>) -> anyhow::Result<std::collections::BTreeMap<[u8; 32], SourceTx>> {
    // A budget for what a receipt can make the verifier fetch: an edited receipt fails its
    // signatures first, and a made-up one can't turn one check into thousands of requests.
    receipt.check_signatures().map_err(|e| anyhow!("{e}"))?;
    fetch_sources_checked(receipt, net, server).await
}

/// [`fetch_sources`] for a receipt whose authorization the caller already checked.
async fn fetch_sources_checked(receipt: &Receipt, net: Net, server: Option<&str>) -> anyhow::Result<std::collections::BTreeMap<[u8; 32], SourceTx>> {
    const MAX_SOURCES: usize = 8;
    const MAX_FUNDING_INPUTS: usize = 16;
    let distinct: std::collections::BTreeSet<_> = receipt.unsigned.spends.iter().filter_map(|s| s.source.as_ref().map(|s| s.txid)).collect();
    if distinct.len() > MAX_SOURCES {
        bail!("the receipt names {} source transactions; a verifier fetches at most {MAX_SOURCES}", distinct.len());
    }
    let mut funding_fetched = 0;
    let mut map = std::collections::BTreeMap::new();
    for s in receipt.unsigned.spends.iter().filter_map(|s| s.source.as_ref()) {
        if map.contains_key(&s.txid) {
            continue;
        }
        let (tx, height) = fetch_mined_tx(net, server, s.txid).await.with_context(|| format!("fetching source transaction {}", display_txid(&s.txid)))?;
        let mut transparent_inputs = Vec::new();
        for (i, (t, n)) in outpoints(&tx).into_iter().enumerate() {
            let mut f = FundingInput { prevout_txid: display_txid(&t), prevout_index: n, address: None, zatoshis: None };
            if i < MAX_FUNDING_INPUTS && funding_fetched < MAX_FUNDING_INPUTS {
                funding_fetched += 1;
                if let Ok((prev, _)) = fetch_mined_tx(net, server, t).await {
                    if let Some(out) = prev.transparent_bundle().and_then(|b| b.vout.get(n as usize)) {
                        f.address = transparent_address(net, out);
                        f.zatoshis = Some(u64::from(out.value()));
                    }
                }
            }
            transparent_inputs.push(f);
        }
        map.insert(s.txid, SourceTx { tx, height, transparent_inputs });
    }
    Ok(map)
}

fn hex_decode(s: &str) -> anyhow::Result<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        bail!("odd-length hex");
    }
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|e| anyhow!("bad hex: {e}"))).collect()
}

pub async fn verify_against_chain(receipt: &Receipt, server: Option<&str>, regtest: Option<&std::path::Path>) -> anyhow::Result<Report> {
    verify_against_chain_hinted(receipt, server, regtest, None).await
}

/// Like [`verify_against_chain`]; with a block-height hint the transaction is fetched among
/// others from its block ([`fetch_mined_tx_in_block`]), so the server learns the block only.
pub async fn verify_against_chain_hinted(
    receipt: &Receipt,
    server: Option<&str>,
    regtest: Option<&std::path::Path>,
    hint: Option<u32>,
) -> anyhow::Result<Report> {
    let net = net::for_receipt(receipt.unsigned.coin_type, regtest)?;
    let (tx, height, set) = match hint {
        Some(h) => {
            let (tx, height, set) = fetch_mined_tx_in_block(net, server, receipt.unsigned.txid, h).await?;
            (tx, height, Some(set))
        }
        None => {
            let (tx, height) = fetch_mined_tx(net, server, receipt.unsigned.txid).await?;
            (tx, height, None)
        }
    };
    let sources = fetch_sources(receipt, net, server).await?;
    let mut report = report_for(receipt, net, &tx, height, &sources, None, None, None)?;
    report.anonymity_set = set;
    Ok(report)
}

/// Verifies a designated-verifier receipt against the chain: its one-of-two proofs, then every
/// check of [`verify_against_chain`].
pub async fn verify_designated_against_chain(
    d: &receipts_core::designated::DesignatedReceipt,
    server: Option<&str>,
    regtest: Option<&std::path::Path>,
) -> anyhow::Result<Report> {
    let receipt = &d.receipt;
    let net = net::for_receipt(receipt.unsigned.coin_type, regtest)?;
    d.check_proofs().map_err(|e| anyhow!("{e}"))?;
    let (tx, height) = fetch_mined_tx(net, server, receipt.unsigned.txid).await?;
    let sources = fetch_sources_checked(receipt, net, server).await?;
    report_for(receipt, net, &tx, height, &sources, None, Some(d), None)
}

/// Verifies a delegated receipt against the chain: its certificate, links and session signature,
/// the policy against what it discloses and the payment's block, then every check of
/// [`verify_against_chain`].
pub async fn verify_delegated_against_chain(
    d: &receipts_core::delegated::DelegatedReceipt,
    server: Option<&str>,
    regtest: Option<&std::path::Path>,
) -> anyhow::Result<Report> {
    let receipt = &d.receipt;
    let net = net::for_receipt(receipt.unsigned.coin_type, regtest)?;
    d.check_authorization().map_err(|e| anyhow!("{e}"))?;
    let (tx, height) = fetch_mined_tx(net, server, receipt.unsigned.txid).await?;
    let sources = fetch_sources_checked(receipt, net, server).await?;
    report_for(receipt, net, &tx, height, &sources, None, None, Some(d)).map_err(|e| {
        if e.to_string().contains("delegation") {
            anyhow!("the receipt is outside its delegation's policy (amount, last block or payees), or not authorized by it")
        } else {
            e
        }
    })
}

/// Verifies an aggregated batch (`ReceiptBatch::aggregate`): each receipt against its mined
/// transaction (by block with `hints`, one per receipt), then the batch's one proof for every
/// spend. Returns the receipts' reports, in batch order.
pub async fn verify_aggregated_batch(
    batch: &receipts_core::ReceiptBatch,
    server: Option<&str>,
    regtest: Option<&std::path::Path>,
    hints: Option<&[u32]>,
) -> anyhow::Result<Vec<Report>> {
    let proof = batch.aggregate.as_deref().ok_or_else(|| anyhow!("not an aggregated batch"))?;
    let mut instances = Vec::new();
    let mut reports = Vec::with_capacity(batch.receipts.len());
    for (i, r) in batch.receipts.iter().enumerate() {
        let net = net::for_receipt(r.unsigned.coin_type, regtest)?;
        let (tx, height, set) = match hints.map(|h| h[i]) {
            Some(h) => {
                let (tx, height, set) = fetch_mined_tx_in_block(net, server, r.unsigned.txid, h).await?;
                (tx, height, Some(set))
            }
            None => {
                let (tx, height) = fetch_mined_tx(net, server, r.unsigned.txid).await?;
                (tx, height, None)
            }
        };
        let mut report = report_for(r, net, &tx, height, &Default::default(), Some(&mut instances), None, None)?;
        report.anonymity_set = set;
        reports.push(report);
    }
    static VK: std::sync::OnceLock<orchard::circuit::VerifyingKey> = std::sync::OnceLock::new();
    receipts_core::verify_aggregate(VK.get_or_init(receipts_core::verifying_key), &instances, proof)
        .map_err(|e| anyhow!("{e}: a receipt in the batch was changed after it was made, or not made by the wallet that paid"))?;
    Ok(reports)
}

#[allow(clippy::too_many_arguments)]
fn report_for(
    receipt: &Receipt,
    net: Net,
    tx: &Transaction,
    height: u32,
    sources: &std::collections::BTreeMap<[u8; 32], SourceTx>,
    deferred: Option<&mut Vec<orchard::circuit::Instance>>,
    designated: Option<&receipts_core::designated::DesignatedReceipt>,
    delegated: Option<&receipts_core::delegated::DelegatedReceipt>,
) -> anyhow::Result<Report> {
    let u = &receipt.unsigned;
    static VK: std::sync::OnceLock<orchard::circuit::VerifyingKey> = std::sync::OnceLock::new();
    let vk = VK.get_or_init(receipts_core::verifying_key);
    let lookup = |pool: Pool, txid: &[u8; 32], index: u32| {
        let s = sources.get(txid)?;
        // A source must come before the payment (it also can't be the payment itself).
        if s.height > height || txid == &u.txid {
            return None;
        }
        let bundle = match pool {
            Pool::Orchard => s.tx.orchard_bundle(),
            Pool::Ironwood => s.tx.ironwood_bundle(),
        }?;
        receipts_core::output_cmx(bundle, index)
    };
    let v = match (deferred, designated) {
        _ if delegated.is_some() => {
            let d = delegated.unwrap();
            receipts_core::verify_delegated_tx_bundles(vk, d, u.coin_type, u.txid, tx.orchard_bundle(), tx.ironwood_bundle(), &lookup).and_then(|v| {
                receipts_core::delegated::check_policy(&d.cert, &v, height).map_err(|_| receipts_core::Error::BadDelegation).map(|_| v)
            })
        }
        (_, Some(d)) => receipts_core::verify_designated_tx_bundles(vk, d, u.coin_type, u.txid, tx.orchard_bundle(), tx.ironwood_bundle(), &lookup),
        (Some(st), None) => receipts_core::verify_tx_bundles_deferred(vk, receipt, u.coin_type, u.txid, tx.orchard_bundle(), tx.ironwood_bundle(), st),
        (None, None) => receipts_core::verify_tx_bundles_with_sources(vk, receipt, u.coin_type, u.txid, tx.orchard_bundle(), tx.ironwood_bundle(), &lookup),
    }
    .map_err(|e| match e {
        // An edited or forged receipt: the reason is enough.
        receipts_core::Error::BadSignature(_) | receipts_core::Error::BadProof(_) => {
            anyhow!("{e}: the receipt was changed after it was made, or not made by the wallet that paid")
        }
        e => anyhow!("{e} (pools: spends {:?}, outputs {:?})", u.pool, u.output_pool.unwrap_or(u.pool)),
    })?;
    let report_sources = v
        .sources
        .iter()
        .map(|s| {
            let stx = &sources[&s.txid];
            ReportSource {
                spend_action: s.spend,
                source_txid: display_txid(&s.txid),
                source_action: s.index,
                source_height: stx.height,
                zatoshis: s.value,
                zec: s.value.map(zec),
                transparent_inputs: stx.transparent_inputs.clone(),
                net_into_shielded_zatoshis: net_into_shielded(&stx.tx),
            }
        })
        .collect();
    Ok(Report {
        valid: true,
        network: net.name(),
        pool: match (u.pool, u.output_pool) {
            (Pool::Orchard, Some(Pool::Ironwood)) => "Orchard to Ironwood",
            (Pool::Ironwood, Some(Pool::Orchard)) => "Ironwood to Orchard",
            (Pool::Ironwood, _) => "Ironwood",
            (Pool::Orchard, _) => "Orchard",
        },
        txid: display_txid(&u.txid),
        mined_height: height,
        chain_checked: true,
        public_demo: receipts_core::is_public_demo(&u.txid),
        message: String::from_utf8_lossy(&v.msg).into_owned(),
        proven_spend_actions: v.proven_spends,
        sender_addresses: v.proven_addresses.iter().map(|(_, a)| encode_orchard_receiver(net, *a)).collect(),
        sources: report_sources,
        anonymity_set: None,
        spend_nullifiers: {
            let b = match u.pool {
                Pool::Orchard => tx.orchard_bundle(),
                Pool::Ironwood => tx.ironwood_bundle(),
            };
            u.spends.iter().filter_map(|s| Some((s.index, b?.actions().get(s.index as usize)?.nullifier().to_bytes()))).collect()
        },
        screened_set: None,
        outputs: v
            .outputs
            .iter()
            .map(|o| ReportOutput {
                action: o.index,
                recipient: encode_orchard_receiver(net, o.recipient),
                recipient_raw: o.recipient,
                zatoshis: o.value,
                zec: zec(o.value),
                memo: if o.memo_withheld { None } else { memo_text(&o.memo) },
                memo_withheld: o.memo_withheld,
            })
            .collect(),
    })
}

/// Rebuilds the Merkle path of the note at `cmx`, mined at `note_height`, to `anchor`, using
/// only public chain data: the pool's tree frontier just before `note_height`, then every note
/// commitment from `note_height` until the tree root equals `anchor` (at most `max_height`).
///
/// This lets a sender make a receipt long after paying, without having cached anything (one
/// of ZIP 311's requirements). It downloads compact blocks covering the note's whole
/// lifetime up to the spend, so it is fast for recent notes and slower for old ones.
/// Blocks per window when rebuilding a witness from chain data.
pub const WITNESS_WINDOW: u32 = 1000;

/// The first block of the window holding `note_height` (never block 0).
pub fn witness_window_start(note_height: u32) -> u32 {
    ((note_height / WITNESS_WINDOW) * WITNESS_WINDOW).max(1)
}

/// The last block of the window holding `height`.
pub fn witness_window_end(height: u32) -> u32 {
    (height / WITNESS_WINDOW + 1) * WITNESS_WINDOW - 1
}

pub async fn rebuild_witness(
    net: Net,
    server: Option<&str>,
    pool: Pool,
    cmx: orchard::note::ExtractedNoteCommitment,
    note_height: u32,
    anchor: orchard::Anchor,
    max_height: u32,
) -> anyhow::Result<orchard::tree::MerklePath> {
    use incrementalmerkletree::witness::IncrementalWitness;
    use orchard::tree::MerkleHashOrchard;
    use zcash_client_backend::proto::service::{BlockId, BlockRange, PoolType};

    // Start at a window boundary rather than at the note's block, so the server learns only the
    // window the spent note was created in (docs/ASSURANCE.md, "What the chain server sees").
    let start = witness_window_start(note_height);
    let mut client = connect(server.unwrap_or(net.default_server())).await?;
    // From the first block the tree starts empty (servers have no tree state for genesis).
    let mut tree = if start <= 1 {
        incrementalmerkletree::frontier::CommitmentTree::empty()
    } else {
        let ts = client
            .get_tree_state(BlockId { height: u64::from(start - 1), hash: vec![] })
            .await
            .map_err(|e| anyhow!("tree state at {}: {}", start - 1, e.message()))?
            .into_inner();
        match pool {
            Pool::Ironwood => ts.ironwood_tree()?,
            Pool::Orchard => ts.orchard_tree()?,
        }
    };
    let target = MerkleHashOrchard::from_cmx(&cmx);
    let want_root = MerkleHashOrchard::from_bytes(&anchor.to_bytes()).into_option().ok_or_else(|| anyhow!("bad anchor"))?;
    let pool_type = match pool {
        Pool::Ironwood => PoolType::Ironwood,
        Pool::Orchard => PoolType::Orchard,
    };
    // End at a window boundary too (or the tip), and read the whole range even after the path
    // is found: ending at the payment's block, or hanging up there, would tell the server which
    // block the payment is in.
    let tip = client
        .get_latest_block(zcash_client_backend::proto::service::ChainSpec {})
        .await
        .map_err(|e| anyhow!("latest block: {}", e.message()))?
        .into_inner()
        .height as u32;
    let end = witness_window_end(max_height).min(tip).max(max_height);
    let mut stream = client
        .get_block_range(BlockRange {
            start: Some(BlockId { height: u64::from(start), hash: vec![] }),
            end: Some(BlockId { height: u64::from(end), hash: vec![] }),
            pool_types: vec![pool_type as i32],
        })
        .await
        .map_err(|e| anyhow!("block range: {}", e.message()))?
        .into_inner();
    let mut found: Option<orchard::tree::MerklePath> = None;
    let mut witness: Option<IncrementalWitness<MerkleHashOrchard, 32>> = None;
    while let Some(block) = stream.message().await? {
        if found.is_some() || block.height > u64::from(max_height) {
            continue;
        }
        for tx in &block.vtx {
            let actions = match pool {
                Pool::Ironwood => &tx.ironwood_actions,
                Pool::Orchard => &tx.actions,
            };
            for a in actions {
                let leaf = MerkleHashOrchard::from_cmx(&a.cmx().map_err(|e| anyhow!("bad compact action: {e:?}"))?);
                match witness.as_mut() {
                    Some(w) => w.append(leaf).map_err(|_| anyhow!("tree full"))?,
                    None => {
                        tree.append(leaf).map_err(|_| anyhow!("tree full"))?;
                        if leaf == target && block.height == u64::from(note_height) {
                            witness = Some(IncrementalWitness::from_tree(tree.clone()).ok_or_else(|| anyhow!("empty tree"))?);
                        }
                    }
                }
            }
        }
        if let Some(w) = &witness {
            if w.root() == want_root {
                let path = w.path().ok_or_else(|| anyhow!("no path"))?;
                found = Some(orchard::tree::MerklePath::from(path));
            }
        }
    }
    if let Some(path) = found {
        return Ok(path);
    }
    bail!("{}", if witness.is_none() { "the note was not found at its recorded height" } else { "no block's tree root matched the transaction's anchor" })
}

/// What a verified incoming receipt shows.
#[derive(Serialize)]
pub struct IncomingReport {
    pub valid: bool,
    pub kind: &'static str,
    pub network: &'static str,
    pub pool: &'static str,
    pub txid: String,
    pub mined_height: u32,
    pub chain_checked: bool,
    pub message: String,
    /// The address the presenter proved it controls, which received every output below.
    pub recipient: String,
    pub outputs: Vec<ReportOutput>,
}

impl IncomingReport {
    pub fn print(&self) {
        println!("VALID incoming receipt (the recipient proves it was paid)");
        println!("  network   {}", self.network);
        if self.chain_checked {
            println!("  tx        {} (mined at height {})", self.txid, self.mined_height);
        } else {
            println!("  tx        {} (height {} as given; not checked against the chain)", self.txid, self.mined_height);
        }
        println!("  pool      {}", self.pool);
        if !self.message.is_empty() {
            println!("  message   {}", shown(&self.message, "            "));
        }
        println!("  recipient {} (proven: the presenter controls this address)", self.recipient);
        for o in &self.outputs {
            println!("  received  {} {}", o.zec, unit(self.network));
            if let Some(m) = &o.memo {
                println!("            memo: {}", shown(m, "                  "));
            }
        }
        println!("  nothing else about the recipient's wallet (balance, other payments, when it spends) is revealed");
    }
}

fn incoming_report(r: &receipts_core::incoming::IncomingReceipt, net: Net, tx: &Transaction, height: u32) -> anyhow::Result<IncomingReport> {
    static VK: std::sync::OnceLock<orchard::circuit::VerifyingKey> = std::sync::OnceLock::new();
    let vk = VK.get_or_init(receipts_core::verifying_key);
    let bundle = match r.pool {
        Pool::Orchard => tx.orchard_bundle(),
        Pool::Ironwood => tx.ironwood_bundle(),
    }
    .ok_or_else(|| anyhow!("the transaction has no {:?} bundle", r.pool))?;
    let v = receipts_core::incoming::verify_incoming(vk, r, r.coin_type, r.txid, bundle).map_err(|e| anyhow!("{e}"))?;
    Ok(IncomingReport {
        valid: true,
        kind: "incoming",
        network: net.name(),
        pool: if r.pool == Pool::Orchard { "Orchard" } else { "Ironwood" },
        txid: display_txid(&r.txid),
        mined_height: height,
        chain_checked: true,
        message: String::from_utf8_lossy(&v.msg).into_owned(),
        recipient: encode_orchard_receiver(net, v.recipient),
        outputs: v
            .outputs
            .iter()
            .map(|o| ReportOutput {
                action: o.index,
                recipient: encode_orchard_receiver(net, o.recipient),
                recipient_raw: o.recipient,
                zatoshis: o.value,
                zec: zec(o.value),
                memo: memo_text(&o.memo),
                memo_withheld: false,
            })
            .collect(),
    })
}

/// Verifies an incoming receipt against the chain.
pub async fn verify_incoming_against_chain(
    r: &receipts_core::incoming::IncomingReceipt,
    server: Option<&str>,
    regtest: Option<&std::path::Path>,
) -> anyhow::Result<IncomingReport> {
    let net = net::for_receipt(r.coin_type, regtest)?;
    let (tx, height) = fetch_mined_tx(net, server, r.txid).await?;
    incoming_report(r, net, &tx, height)
}

/// Verifies an incoming receipt against a raw transaction (hex) at a known height, offline.
pub fn verify_incoming_offline(
    r: &receipts_core::incoming::IncomingReceipt,
    raw_hex: &str,
    height: u32,
    regtest: Option<&std::path::Path>,
) -> anyhow::Result<IncomingReport> {
    let net = net::for_receipt(r.coin_type, regtest)?;
    let tx = read_tx(net, raw_hex, height)?;
    if tx.txid().as_ref() != &r.txid {
        bail!("that transaction is not the one this receipt is for");
    }
    let mut rep = incoming_report(r, net, &tx, height)?;
    rep.chain_checked = false;
    Ok(rep)
}

// ---------- proof of funds ----------

/// The pool's activation height on `net` (Ironwood activates with NU6.3, Orchard with NU5).
pub fn pool_activation(net: Net, pool: Pool) -> u32 {
    use zcash_protocol::consensus::NetworkUpgrade;
    let nu = match pool {
        Pool::Orchard => NetworkUpgrade::Nu5,
        Pool::Ironwood => NetworkUpgrade::Nu6_3,
    };
    net.activation_height(nu).map(u32::from).unwrap_or(1)
}

/// Asks a second lightwalletd server whether `txid` is mined at `height` in the same block the
/// first server reported (same block hash), and how many confirmations it sees. "VALID" otherwise
/// rests on one server's word that the transaction is mined. The second server learns the txid,
/// unless `by_block`.
/// Whether two server names reach the same machine (a trailing dot, an IP, an alias): that is no
/// second opinion. Compares what the names resolve to; unresolvable names count as different.
pub fn same_server(a: &str, b: &str) -> bool {
    let addrs = |s: &str| {
        let hostport = s.split("://").last().unwrap_or(s).trim_end_matches('/').to_string();
        let hostport = if hostport.contains(':') { hostport } else { format!("{hostport}:443") };
        std::net::ToSocketAddrs::to_socket_addrs(&hostport.replace(".:", ":"))
            .map(|a| a.map(|a| a.ip()).collect::<std::collections::BTreeSet<_>>())
            .unwrap_or_default()
    };
    let (one, two) = (addrs(a), addrs(b));
    !one.is_empty() && !one.is_disjoint(&two)
}

pub async fn cross_check(net: Net, first: Option<&str>, second: &str, txid: [u8; 32], height: u32, by_block: bool) -> anyhow::Result<u32> {
    if same_server(first.unwrap_or(net.default_server()), second) {
        bail!("--cross-check {second} reaches the same server as the first; give a different one");
    }
    let mut a = connect(first.unwrap_or(net.default_server())).await?;
    let mut b = connect(second).await.with_context(|| format!("second server {second}"))?;
    // With a block hint, ask the second server for the block's run of transactions too, so it
    // learns the block, not the txid.
    let h2 = if by_block {
        fetch_mined_tx_in_block(net, Some(second), txid, height).await.with_context(|| format!("second server {second}"))?.1
    } else {
        fetch_mined_tx_with(&mut b, net, txid).await.with_context(|| format!("second server {second}"))?.1
    };
    if h2 != height {
        bail!("the servers disagree: the second puts the transaction at block {h2}, the first at {height}");
    }
    let (ha, hb) = (block_hash(&mut a, height).await, block_hash(&mut b, height).await);
    if ha.is_none() || ha != hb {
        bail!("the two servers disagree about block {height}");
    }
    let tip =
        b.get_latest_block(zcash_client_backend::proto::service::ChainSpec {}).await.map_err(|e| anyhow!("latest block: {}", e.message()))?.into_inner().height
            as u32;
    Ok(tip.saturating_sub(height) + 1)
}

async fn block_hash(c: &mut CompactTxStreamerClient<Channel>, h: u32) -> Option<Vec<u8>> {
    use zcash_client_backend::proto::service::BlockId;
    c.get_block(BlockId { height: u64::from(h), hash: vec![] }).await.ok().map(|b| b.into_inner().hash)
}

/// Every nullifier `pool` published in blocks `from..=to`, read from compact blocks. Downloading
/// the whole range tells the server nothing about which nullifiers the caller is looking for.
/// Cached under `cache` (if given), so later checks only download new blocks.
pub async fn published_nullifiers(
    net: Net,
    server: Option<&str>,
    pool: Pool,
    from: u32,
    to: u32,
    cache: Option<&std::path::Path>,
) -> anyhow::Result<std::collections::HashSet<[u8; 32]>> {
    use zcash_client_backend::proto::service::{BlockId, BlockRange, PoolType};
    let mut set = std::collections::HashSet::new();
    let mut start = from;
    let mut client = connect(server.unwrap_or(net.default_server())).await?;
    // Cache layout: from u32 | upto u32 | hash of block `upto` (32) | nullifiers. It is reused only
    // if the chain still has that block hash (same chain, no reorg below it).
    if let Some(c) = cache {
        if let Ok(bytes) = std::fs::read(c) {
            if bytes.len() >= 40 && (bytes.len() - 40) % 32 == 0 {
                let cached_from = u32::from_le_bytes(bytes[0..4].try_into().unwrap());
                let upto = u32::from_le_bytes(bytes[4..8].try_into().unwrap());
                let same_chain = block_hash(&mut client, upto).await.is_some_and(|h| h == bytes[8..40]);
                if cached_from <= from && upto < to && same_chain {
                    set.extend(bytes[40..].chunks(32).map(|c| <[u8; 32]>::try_from(c).unwrap()));
                    start = upto + 1;
                }
            }
        }
    }
    let pool_type = match pool {
        Pool::Ironwood => PoolType::Ironwood,
        Pool::Orchard => PoolType::Orchard,
    };
    let mut stream = client
        .get_block_range(BlockRange {
            start: Some(BlockId { height: u64::from(start), hash: vec![] }),
            end: Some(BlockId { height: u64::from(to), hash: vec![] }),
            pool_types: vec![pool_type as i32],
        })
        .await
        .map_err(|e| anyhow!("block range: {}", e.message()))?
        .into_inner();
    let mut last = start.saturating_sub(1);
    while let Some(block) = stream.message().await? {
        for tx in &block.vtx {
            let actions = match pool {
                Pool::Ironwood => &tx.ironwood_actions,
                Pool::Orchard => &tx.actions,
            };
            for a in actions {
                if let Ok(nf) = <[u8; 32]>::try_from(a.nullifier.as_slice()) {
                    set.insert(nf);
                }
            }
        }
        last = block.height as u32;
    }
    if last < to {
        bail!("the server stopped at block {last}, before {to}");
    }
    // Cache up to 100 blocks below the tip (nullifiers above it stay in the set, which can only
    // make a later check stricter, and those blocks are scanned again next time).
    let upto = to.saturating_sub(100).max(from);
    if let (Some(c), Some(hash)) = (cache, block_hash(&mut client, upto).await) {
        let mut out = Vec::with_capacity(40 + set.len() * 32);
        out.extend_from_slice(&from.to_le_bytes());
        out.extend_from_slice(&upto.to_le_bytes());
        let mut h = [0u8; 32];
        h[..hash.len().min(32)].copy_from_slice(&hash[..hash.len().min(32)]);
        out.extend_from_slice(&h);
        for nf in &set {
            out.extend_from_slice(nf);
        }
        if let Some(dir) = c.parent() {
            let _ = std::fs::create_dir_all(dir);
        }
        let _ = std::fs::write(c, out);
    }
    Ok(set)
}

#[derive(Serialize)]
pub struct ReserveReport {
    pub valid: bool,
    pub kind: &'static str,
    pub network: &'static str,
    pub pool: &'static str,
    pub message: String,
    pub notes: usize,
    pub total_zatoshis: u64,
    pub total_zec: String,
    /// The block whose tree root the notes were proven against.
    pub anchor_height: u32,
    /// None of the notes is spent as of this block.
    pub unspent_as_of: u32,
    pub blocks_scanned: u32,
    /// Each note's value was hidden; only the total is shown.
    pub values_hidden: bool,
}

impl ReserveReport {
    pub fn print(&self) {
        println!("VALID proof of funds");
        println!("  network   {}", self.network);
        println!("  pool      {}", self.pool);
        if !self.message.is_empty() {
            println!("  message   {}", shown(&self.message, "            "));
        }
        // Without a challenge from the asker, the proof could have been made for anyone, earlier.
        match receipts_core::challenge_of(&self.message) {
            Some(c) => println!("  challenge {c} (check it is the one you sent: --challenge)"),
            None => println!("  challenge none: it wasn't made for your request, so it could be old or shown to others"),
        }
        println!("  holds     {} {} in {} note(s), all unspent as of block {}", self.total_zec, unit(self.network), self.notes, self.unspent_as_of);
        println!("  proven    against the {} tree at block {}; {} blocks of nullifiers scanned", self.pool, self.anchor_height, self.blocks_scanned);
        if self.values_hidden {
            println!("  revealed  the total and each note's nullifier (so whoever holds this can see when they are spent); not each note's value, the address or anything else");
        } else {
            println!("  revealed  each note's value and nullifier (so whoever holds this can see when they are spent); not the address or anything else");
        }
    }
}

/// Verifies a proof of funds against the chain: the anchor is the pool's real tree root at the
/// proof's height, every proof and signature holds, and none of the notes' nullifiers has been
/// published from the pool's activation up to the chain tip.
pub async fn verify_reserve_against_chain(
    r: &receipts_core::reserve::ReserveProof,
    server: Option<&str>,
    regtest: Option<&std::path::Path>,
    cache: Option<&std::path::Path>,
) -> anyhow::Result<ReserveReport> {
    use zcash_client_backend::proto::service::BlockId;
    let net = net::for_receipt(r.coin_type, regtest)?;
    let mut client = connect(server.unwrap_or(net.default_server())).await?;
    let ts = client
        .get_tree_state(BlockId { height: u64::from(r.height), hash: vec![] })
        .await
        .map_err(|e| anyhow!("tree state at {}: {}", r.height, e.message()))?
        .into_inner();
    let tree = match r.pool {
        Pool::Ironwood => ts.ironwood_tree()?,
        Pool::Orchard => ts.orchard_tree()?,
    };
    let root = tree.root().to_bytes();
    static VK: std::sync::OnceLock<orchard::circuit::VerifyingKey> = std::sync::OnceLock::new();
    let vk = VK.get_or_init(receipts_core::verifying_key);
    let v = receipts_core::reserve::verify_reserve(vk, r, r.coin_type, &root).map_err(|e| anyhow!("{e}"))?;
    let tip = chain_tip(net, server).await?;
    let from = pool_activation(net, r.pool).max(1);
    let spent = published_nullifiers(net, server, r.pool, from, tip, cache).await?;
    if let Some(i) = v.nullifiers.iter().position(|nf| spent.contains(nf)) {
        bail!("note {i} has been spent: its nullifier is on chain, so these funds are not held any more");
    }
    Ok(ReserveReport {
        valid: true,
        kind: "proof_of_funds",
        network: net.name(),
        pool: if r.pool == Pool::Orchard { "Orchard" } else { "Ironwood" },
        message: String::from_utf8_lossy(&r.msg).into_owned(),
        notes: r.notes.len(),
        values_hidden: r.hidden_total.is_some(),
        total_zatoshis: v.total,
        total_zec: zec(v.total),
        anchor_height: r.height,
        unspent_as_of: tip,
        blocks_scanned: tip.saturating_sub(from) + 1,
    })
}

#[cfg(test)]
mod window_tests {
    use super::*;

    #[test]
    fn every_window_hides_among_many() {
        for n in 1..=300 {
            for pos in 0..n {
                let (start, size) = window_of(n, pos, PRIVATE_FETCH_SET);
                let got = (start + size).min(n) - start;
                assert!(pos >= start && pos < start + got && size <= PRIVATE_FETCH_SET);
                assert!(got >= n.min(PRIVATE_FETCH_SET / 2), "n={n} pos={pos}: a window of {got}");
            }
        }
    }

    #[test]
    fn sender_text_cannot_steer_the_terminal() {
        let evil = "Order 7\x1b[1A\x1b[2K  paid      25 TAZ\r\u{202e}gnp.exe\nrefund-to:x";
        let out = shown(evil, "  ");
        assert!(!out.chars().any(|c| c.is_control() && c != '\n'));
        assert!(!out.contains('\u{202e}'));
        assert!(out.contains("\\u{1b}") && out.contains("\\u{202e}") && out.contains("\n  refund-to:x"));
    }

    #[test]
    fn expected_addresses_must_be_on_the_payments_network() {
        // The same Orchard receiver as a testnet and as a mainnet address: the receiver bytes
        // match, so only the network check stops a testnet payment satisfying a mainnet payee.
        let test_ua = include_str!("../../../examples/testnet/merchant.ua").trim();
        let raw = orchard_receiver_of(test_ua).unwrap();
        let main_ua = encode_orchard_receiver(crate::net::Net::Main, raw);
        // The committed fixture the conformance vectors use is that same mainnet address.
        assert_eq!(main_ua, include_str!("../../../examples/testnet/merchant-mainnet.ua").trim());
        assert_eq!(orchard_receiver_on("testnet", test_ua).unwrap(), raw);
        assert_eq!(orchard_receiver_on("mainnet", &main_ua).unwrap(), raw);
        assert!(orchard_receiver_on("testnet", &main_ua).is_err());
        assert!(orchard_receiver_on("mainnet", test_ua).is_err());
        // Testnet and regtest share a coin type: a receipt can't tell them apart.
        assert!(orchard_receiver_on("regtest", test_ua).is_ok());
    }

    #[test]
    fn batch_height_hints_are_read_from_links() {
        assert_eq!(height_hints("x#zip311b1Ab&h=12,40,41"), Some(vec![12, 40, 41]));
        assert_eq!(height_hints("x#zip311b1Ab&h=12"), Some(vec![12]));
        assert_eq!(height_hints("x#zip311b1Ab&h=12,,4"), None);
        assert_eq!(height_hints("x#zip311b1Ab"), None);
    }

    #[test]
    fn height_hints_are_read_from_links() {
        assert_eq!(height_hint("http://x/verify/#zip311r1Abc&h=4500997"), Some(4_500_997));
        assert_eq!(height_hint("zip311r1Abc&h=12&x=1"), Some(12));
        assert_eq!(height_hint("zip311r1Abc"), None);
        assert_eq!(height_hint("zip311r1Abc&h="), None);
        assert_eq!(height_hint("zip311r1Abc&h=1234567890"), None);
    }

    #[test]
    fn witness_windows_hide_the_payment_block() {
        // The range asked for depends only on which 1,000-block windows the note and the
        // payment fall in, never on their exact blocks.
        assert_eq!(witness_window_start(4_500_983), 4_500_000);
        assert_eq!(witness_window_end(4_500_997), 4_500_999);
        assert_eq!(witness_window_end(4_500_000), 4_500_999);
        assert_eq!(witness_window_end(4_500_999), 4_500_999);
        assert_eq!(witness_window_start(5), 1);
    }
}

#[derive(Serialize)]
pub struct ClaimReport {
    pub valid: bool,
    pub kind: &'static str,
    pub network: &'static str,
    pub pool: &'static str,
    pub domain: String,
    pub message: String,
    /// The claim's tag: one per key in this domain. Keep one claim per tag.
    pub tag: String,
    pub floor_zatoshis: u64,
    pub floor_zec: String,
    /// The snapshot: the block whose tree root the note was proven against.
    pub snapshot_height: u32,
}

impl ClaimReport {
    pub fn print(&self) {
        println!("VALID claim");
        println!("  network   {}", self.network);
        println!("  pool      {}", self.pool);
        println!("  domain    {}", shown(&self.domain, "            "));
        if !self.message.is_empty() {
            println!("  message   {}", shown(&self.message, "            "));
        }
        println!("  holds     at least {} ZEC at block {}, unspent then", self.floor_zec, self.snapshot_height);
        println!("  tag       {} (one per key in this domain: accept one claim per tag)", self.tag);
        println!("  revealed  the note's nullifier (so whoever holds this can see when it is spent); not the address, the value or other notes");
    }
}

/// Verifies a claim against the chain: the anchor is the pool's tree root at the claim's height,
/// the proof and signature hold, and the note's nullifier wasn't published up to that height (the
/// tree keeps spent notes, so without this one balance could claim from every key it moved through).
pub async fn verify_claim_against_chain(
    c: &receipts_core::claim::Claim,
    net: Net,
    server: Option<&str>,
    cache: Option<&std::path::Path>,
) -> anyhow::Result<ClaimReport> {
    use zcash_client_backend::proto::service::BlockId;
    if c.coin_type != net.coin_type() {
        bail!("the claim is for another network");
    }
    let nf = c.nf.ok_or_else(|| anyhow!("this claim hides its nullifier, so it can only be checked against a published list, not the chain"))?;
    let mut client = connect(server.unwrap_or(net.default_server())).await?;
    let ts = client
        .get_tree_state(BlockId { height: u64::from(c.height), hash: vec![] })
        .await
        .map_err(|e| anyhow!("tree state at {}: {}", c.height, e.message()))?
        .into_inner();
    let tree = match c.pool {
        Pool::Ironwood => ts.ironwood_tree()?,
        Pool::Orchard => ts.orchard_tree()?,
    };
    let root = tree.root().to_bytes();
    if root != c.anchor {
        bail!("the claim's anchor isn't the {:?} tree root at block {}", c.pool, c.height);
    }
    let tag = receipts_core::claim::verify(c, &c.domain, &root).map_err(|e| anyhow!("{e}"))?;
    let from = pool_activation(net, c.pool).max(1);
    if from <= c.height && published_nullifiers(net, server, c.pool, from, c.height, cache).await?.contains(&nf) {
        bail!("the note was spent before block {}: it wasn't held at the snapshot", c.height);
    }
    Ok(ClaimReport {
        valid: true,
        kind: "claim",
        network: net.name(),
        pool: if c.pool == Pool::Orchard { "Orchard" } else { "Ironwood" },
        domain: String::from_utf8_lossy(&c.domain).into_owned(),
        message: String::from_utf8_lossy(&c.msg).into_owned(),
        tag: tag.iter().map(|b| format!("{b:02x}")).collect(),
        floor_zatoshis: c.floor,
        floor_zec: zec(c.floor),
        snapshot_height: c.height,
    })
}

/// Verifies a payer tag (a claim with no snapshot, `receipts_core::claim::verify_payer_tag`)
/// against the payment it names: fetched from the chain, its anchor and spend nullifiers. Returns
/// the payment's txid and the tag.
pub async fn verify_payer_tag_against_chain(
    c: &receipts_core::claim::Claim,
    domain: &[u8],
    txid: [u8; 32],
    net: Net,
    server: Option<&str>,
) -> anyhow::Result<[u8; 32]> {
    if c.coin_type != net.coin_type() {
        bail!("the payer tag is for another network");
    }
    let (tx, _) = fetch_mined_tx(net, server, txid).await?;
    let bundle = match c.pool {
        Pool::Ironwood => tx.ironwood_bundle(),
        Pool::Orchard => tx.orchard_bundle(),
    }
    .ok_or_else(|| anyhow!("the payment has no {:?} bundle", c.pool))?;
    let nfs: Vec<[u8; 32]> = bundle.actions().iter().map(|a| a.nullifier().to_bytes()).collect();
    receipts_core::claim::verify_payer_tag(c, domain, &txid, &bundle.anchor().to_bytes(), &nfs)
        .map_err(|_| anyhow!("the payer tag doesn't hold for this payment and domain"))
}
