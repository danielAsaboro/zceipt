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
    pub message: String,
    pub proven_spend_actions: Vec<u32>,
    /// Public addresses the sender proved they control (empty unless they chose to).
    pub sender_addresses: Vec<String>,
    pub outputs: Vec<ReportOutput>,
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
        println!("  tx        {} (mined at height {})", self.txid, self.mined_height);
        println!("  pool      {}", self.pool);
        if !self.message.is_empty() {
            println!("  message   {}", self.message.replace('\n', "\n            "));
        }
        println!("  sender    proved spend authority for action(s) {:?}", self.proven_spend_actions);
        for a in &self.sender_addresses {
            println!("  from      {a} (proven by the sender)");
        }
        for o in &self.outputs {
            println!("  paid      {} ZEC to {}", o.zec, o.recipient);
            if let Some(m) = &o.memo {
                println!("            memo: {m}");
            }
        }
        if crate::deposit::deposit_claim(&self.message).is_some() {
            // The deposit block that follows says what this does reveal.
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
    let u = &receipt.unsigned;
    let net = net::for_receipt(u.coin_type, regtest)?;
    let raw = hex_decode(raw_hex.trim())?;
    let branch = BranchId::for_height(&net, BlockHeight::from_u32(height));
    let tx = Transaction::read(&raw[..], branch)?;
    if tx.txid().as_ref() != &u.txid {
        bail!("that transaction is not the one this receipt is for");
    }
    report_for(receipt, net, &tx, height)
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
    report_for(receipt, net, &tx, height)
}

fn report_for(receipt: &Receipt, net: Net, tx: &Transaction, height: u32) -> anyhow::Result<Report> {
    let u = &receipt.unsigned;
    static VK: std::sync::OnceLock<orchard::circuit::VerifyingKey> = std::sync::OnceLock::new();
    let vk = VK.get_or_init(receipts_core::verifying_key);
    let v = receipts_core::verify_tx_bundles(vk, receipt, u.coin_type, u.txid, tx.orchard_bundle(), tx.ironwood_bundle())
        .map_err(|e| anyhow!("{e} (pools: spends {:?}, outputs {:?})", u.pool, u.output_pool.unwrap_or(u.pool)))?;
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
        message: String::from_utf8_lossy(&v.msg).into_owned(),
        proven_spend_actions: v.proven_spends,
        sender_addresses: v.proven_addresses.iter().map(|(_, a)| encode_orchard_receiver(net, *a)).collect(),
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

    let mut client = connect(server.unwrap_or(net.default_server())).await?;
    let ts = client
        .get_tree_state(BlockId { height: u64::from(note_height - 1), hash: vec![] })
        .await
        .map_err(|e| anyhow!("tree state at {}: {}", note_height - 1, e.message()))?
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
            start: Some(BlockId { height: u64::from(note_height), hash: vec![] }),
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
