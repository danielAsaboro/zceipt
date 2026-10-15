//! Fetching transactions from lightwalletd and verifying receipts against them.

use anyhow::{anyhow, bail, Context};
use crate::net::{self, Net};
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
    let b = client
        .get_latest_block(zcash_client_backend::proto::service::ChainSpec {})
        .await
        .map_err(|e| anyhow!("latest block: {}", e.message()))?
        .into_inner();
    Ok(b.height as u32)
}

/// Confirmations after which a receipt is reported `final` (reorgs deeper than this are not expected).
pub const FINALITY_CONFIRMATIONS: u32 = 10;

/// Fetches a mined transaction. Returns the transaction and its block height.
pub async fn fetch_mined_tx(
    net: Net,
    server: Option<&str>,
    txid: [u8; 32],
) -> anyhow::Result<(Transaction, u32)> {
    let mut client = connect(server.unwrap_or(net.default_server())).await?;
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
    pub message: String,
    pub proven_spend_actions: Vec<u32>,
    /// Public addresses the sender proved they control (empty unless they chose to).
    pub sender_addresses: Vec<String>,
    /// Where spent notes came from, for spends whose source the sender chose to prove.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub sources: Vec<ReportSource>,
    pub outputs: Vec<ReportOutput>,
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
}

impl Report {
    pub fn print(&self) {
        println!("VALID receipt");
        println!("  network   {}", self.network);
        if self.chain_checked {
            println!("  tx        {} (mined at height {})", self.txid, self.mined_height);
        } else {
            println!("  tx        {} (height {} as given; not checked against the chain)", self.txid, self.mined_height);
            println!("  offline   this shows the receipt matches the transaction you supplied, not that it was mined");
        }
        println!("  pool      {}", self.pool);
        if !self.message.is_empty() {
            println!("  message   {}", self.message.replace('\n', "\n            "));
        }
        println!("  sender    proved spend authority for action(s) {:?}", self.proven_spend_actions);
        for a in &self.sender_addresses {
            println!("  from      {a} (proven by the sender)");
        }
        for src in &self.sources {
            let value = src.zec.as_ref().map(|z| format!("a {z} ZEC note")).unwrap_or_else(|| "the note".into());
            println!("  source    action {} spent {value} created by tx {} action {} (height {})", src.spend_action, src.source_txid, src.source_action, src.source_height);
            for t in &src.transparent_inputs {
                match (&t.address, t.zatoshis) {
                    (Some(a), Some(z)) => println!("            that tx was funded in the clear: {} ZEC from {a}", zec(z)),
                    _ => println!("            that tx spent transparent output {}:{}", t.prevout_txid, t.prevout_index),
                }
            }
            if src.transparent_inputs.is_empty() {
                println!("            that tx had no transparent inputs: its own funding was shielded and is not shown");
            } else if src.net_into_shielded_zatoshis > 0 {
                println!("            it moved {} ZEC from transparent into the shielded pool", zec(src.net_into_shielded_zatoshis as u64));
            }
        }
        for o in &self.outputs {
            println!("  paid      {} ZEC to {}", o.zec, o.recipient);
            if let Some(m) = &o.memo {
                println!("            memo: {m}");
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
pub fn verify_offline_with_sources(receipt: &Receipt, raw_hex: &str, height: u32, sources: &[(String, u32)], regtest: Option<&std::path::Path>) -> anyhow::Result<Report> {
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
        let transparent_inputs = outpoints(&stx).into_iter().map(|(t, n)| FundingInput { prevout_txid: display_txid(&t), prevout_index: n, address: None, zatoshis: None }).collect();
        map.insert(id, SourceTx { tx: stx, height: *h, transparent_inputs });
    }
    let mut r = report_for(receipt, net, &tx, height, &map)?;
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
    tx.transparent_bundle()
        .map(|b| b.vin.iter().map(|i| (*i.prevout().hash(), i.prevout().n())).collect())
        .unwrap_or_default()
}

/// Net value a transaction moved from transparent into the shielded pools (negative: out).
fn net_into_shielded(tx: &Transaction) -> i64 {
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
    const MAX_FUNDING_INPUTS: usize = 16;
    let mut map = std::collections::BTreeMap::new();
    for s in receipt.unsigned.spends.iter().filter_map(|s| s.source.as_ref()) {
        if map.contains_key(&s.txid) {
            continue;
        }
        let (tx, height) = fetch_mined_tx(net, server, s.txid).await.with_context(|| format!("fetching source transaction {}", display_txid(&s.txid)))?;
        let mut transparent_inputs = Vec::new();
        for (i, (t, n)) in outpoints(&tx).into_iter().enumerate() {
            let mut f = FundingInput { prevout_txid: display_txid(&t), prevout_index: n, address: None, zatoshis: None };
            if i < MAX_FUNDING_INPUTS {
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

pub async fn verify_against_chain(
    receipt: &Receipt,
    server: Option<&str>,
    regtest: Option<&std::path::Path>,
) -> anyhow::Result<Report> {
    let net = net::for_receipt(receipt.unsigned.coin_type, regtest)?;
    let (tx, height) = fetch_mined_tx(net, server, receipt.unsigned.txid).await?;
    let sources = fetch_sources(receipt, net, server).await?;
    report_for(receipt, net, &tx, height, &sources)
}

fn report_for(receipt: &Receipt, net: Net, tx: &Transaction, height: u32, sources: &std::collections::BTreeMap<[u8; 32], SourceTx>) -> anyhow::Result<Report> {
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
    let v = receipts_core::verify_tx_bundles_with_sources(vk, receipt, u.coin_type, u.txid, tx.orchard_bundle(), tx.ironwood_bundle(), &lookup)
        .map_err(|e| anyhow!("{e} (pools: spends {:?}, outputs {:?})", u.pool, u.output_pool.unwrap_or(u.pool)))?;
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
        message: String::from_utf8_lossy(&v.msg).into_owned(),
        proven_spend_actions: v.proven_spends,
        sender_addresses: v.proven_addresses.iter().map(|(_, a)| encode_orchard_receiver(net, *a)).collect(),
        sources: report_sources,
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
    let ts = client
        .get_tree_state(BlockId { height: u64::from(start - 1), hash: vec![] })
        .await
        .map_err(|e| anyhow!("tree state at {}: {}", start - 1, e.message()))?
        .into_inner();
    let mut tree = match pool {
        Pool::Ironwood => ts.ironwood_tree()?,
        Pool::Orchard => ts.orchard_tree()?,
    };
    let target = MerkleHashOrchard::from_cmx(&cmx);
    let want_root = MerkleHashOrchard::from_bytes(&anchor.to_bytes()).into_option().ok_or_else(|| anyhow!("bad anchor"))?;
    let pool_type = match pool {
        Pool::Ironwood => PoolType::Ironwood,
        Pool::Orchard => PoolType::Orchard,
    };
    let mut stream = client
        .get_block_range(BlockRange {
            start: Some(BlockId { height: u64::from(start), hash: vec![] }),
            end: Some(BlockId { height: u64::from(max_height), hash: vec![] }),
            pool_types: vec![pool_type as i32],
        })
        .await
        .map_err(|e| anyhow!("block range: {}", e.message()))?
        .into_inner();
    let mut witness: Option<IncrementalWitness<MerkleHashOrchard, 32>> = None;
    while let Some(block) = stream.message().await? {
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
                return Ok(orchard::tree::MerklePath::from(path));
            }
        }
    }
    bail!(
        "{}",
        if witness.is_none() { "the note was not found at its recorded height" } else { "no block's tree root matched the transaction's anchor" }
    )
}
