//! Making a receipt in the browser from a unified full viewing key: no install, no terminal.
//!
//! The page (in a worker) fetches public chain data over grpc-web and hands it here: compact
//! blocks to find the wallet's notes and the payment, the payment itself, and a tree state plus
//! blocks to rebuild the spent notes' Merkle paths. The proofs are made here, then the receipt
//! is signed with the seed phrase ([`sign_with_phrase`]), which never leaves this call, or the
//! prepared receipt is handed to another signer.
//!
//! Compact actions arrive packed, 181 bytes each:
//! `pool:u8 (0 Orchard, 1 Ironwood) | txid[32] (internal order) | nf[32] | cmx[32] | epk[32] | ct[52]`.

use crate::net_of;
use incrementalmerkletree::{frontier::CommitmentTree, witness::IncrementalWitness};
use orchard::{
    keys::{FullViewingKey, PreparedIncomingViewingKey, Scope, SpendAuthorizingKey, SpendingKey},
    note::{ExtractedNoteCommitment, Nullifier},
    note_encryption::{CompactAction, IronwoodDomain, OrchardDomain},
    tree::{MerkleHashOrchard, MerklePath},
    Note,
};
use receipts_core::{display_txid, Network as RNet, Pool, PreparedReceipt, ReceiptBuilder, ViewingSpendWitness};
use std::collections::HashMap;
use wasm_bindgen::prelude::*;
use zcash_address::unified::{self, Container, Encoding};
use zcash_note_encryption::{try_compact_note_decryption, try_note_decryption, try_output_recovery_with_ovk, EphemeralKeyBytes};
use zcash_primitives::transaction::Transaction;
use zcash_protocol::consensus::{BlockHeight, BranchId, NetworkType};

const PACKED: usize = 1 + 32 * 4 + 52;

thread_local! {
    static PK: std::cell::OnceCell<orchard::circuit::ProvingKey> = const { std::cell::OnceCell::new() };
}

fn err(e: impl std::fmt::Display) -> JsError {
    JsError::new(&e.to_string())
}

fn pool_of(b: u8) -> Result<Pool, JsError> {
    match b {
        0 => Ok(Pool::Orchard),
        1 => Ok(Pool::Ironwood),
        _ => Err(err("bad pool byte")),
    }
}

struct Found {
    note: Note,
    height: u32,
    cmx: [u8; 32],
}

struct Rebuild {
    pool: Pool,
    nf: [u8; 32],
    target: MerkleHashOrchard,
    note_height: u32,
    want_root: MerkleHashOrchard,
    tree: CommitmentTree<MerkleHashOrchard, 32>,
    witness: Option<IncrementalWitness<MerkleHashOrchard, 32>>,
}

/// One receipt being made from a viewing key. Feed it chain data in order; see the module docs.
#[wasm_bindgen]
pub struct ReceiptMaker {
    fvk: FullViewingKey,
    nt: NetworkType,
    coin_type: u32,
    ivks: [PreparedIncomingViewingKey; 2],
    target: Option<[u8; 32]>,
    notes: HashMap<(Pool, [u8; 32]), Found>,
    tx: Option<(Transaction, u32)>,
    paths: HashMap<(Pool, [u8; 32]), MerklePath>,
    rebuild: Option<Rebuild>,
}

#[wasm_bindgen]
impl ReceiptMaker {
    /// From a unified full viewing key (`uview1…`, `uviewtest1…`) with an Orchard part.
    #[wasm_bindgen(constructor)]
    pub fn new(ufvk: &str) -> Result<ReceiptMaker, JsError> {
        console_error_panic_hook::set_once();
        let (nt, _, ufvk) = unified::Ufvk::decode(ufvk.trim()).map_err(|e| err(format!("that isn't a unified full viewing key ({e})")))?;
        let bytes = ufvk
            .items()
            .into_iter()
            .find_map(|i| match i {
                unified::Fvk::Orchard(b) => Some(b),
                _ => None,
            })
            .ok_or_else(|| err("that viewing key has no Orchard part"))?;
        let fvk = FullViewingKey::from_bytes(&bytes).ok_or_else(|| err("the viewing key's Orchard part is invalid"))?;
        let coin_type = if nt == NetworkType::Main { receipts_core::COIN_TYPE_MAINNET } else { receipts_core::COIN_TYPE_TESTNET };
        let ivks = [PreparedIncomingViewingKey::new(&fvk.to_ivk(Scope::External)), PreparedIncomingViewingKey::new(&fvk.to_ivk(Scope::Internal))];
        Ok(ReceiptMaker { fvk, nt, coin_type, ivks, target: None, notes: HashMap::new(), tx: None, paths: HashMap::new(), rebuild: None })
    }

    /// "mainnet" or "testnet".
    #[wasm_bindgen(getter)]
    pub fn network(&self) -> String {
        if self.nt == NetworkType::Main { "mainnet" } else { "testnet" }.into()
    }

    /// The payment to make the receipt for, as block explorers show its txid.
    pub fn set_target(&mut self, txid: &str) -> Result<(), JsError> {
        let mut b: [u8; 32] = hex::decode(txid.trim()).ok().and_then(|b| b.try_into().ok()).ok_or_else(|| err("a txid is 64 hex digits"))?;
        b.reverse();
        self.target = Some(b);
        Ok(())
    }

    /// Trial-decrypts one compact block's actions with the wallet's keys and keeps the notes
    /// found. Returns true if the payment is in this block.
    pub fn scan_block(&mut self, height: u32, packed: &[u8]) -> Result<bool, JsError> {
        if !packed.len().is_multiple_of(PACKED) {
            return Err(err("bad packed actions"));
        }
        let mut here = false;
        for a in packed.chunks(PACKED) {
            let pool = pool_of(a[0])?;
            let txid: [u8; 32] = a[1..33].try_into().unwrap();
            here |= Some(txid) == self.target;
            let nf = Option::from(Nullifier::from_bytes(&a[33..65].try_into().unwrap())).ok_or_else(|| err("bad nullifier"))?;
            let cmx_bytes: [u8; 32] = a[65..97].try_into().unwrap();
            let Some(cmx) = Option::<ExtractedNoteCommitment>::from(ExtractedNoteCommitment::from_bytes(&cmx_bytes)) else { continue };
            let action = CompactAction::from_parts(nf, cmx, EphemeralKeyBytes(a[97..129].try_into().unwrap()), a[129..181].try_into().unwrap());
            let note = self.ivks.iter().find_map(|ivk| match pool {
                Pool::Orchard => try_compact_note_decryption(&OrchardDomain::for_compact_action(&action), ivk, &action),
                Pool::Ironwood => try_compact_note_decryption(&IronwoodDomain::for_compact_action(&action), ivk, &action),
            });
            if let Some((note, _)) = note {
                self.notes.insert((pool, note.nullifier(&self.fvk).to_bytes()), Found { note, height, cmx: cmx_bytes });
            }
        }
        Ok(here)
    }

    /// How many of the wallet's notes the scan has found so far.
    #[wasm_bindgen(getter)]
    pub fn notes_found(&self) -> usize {
        self.notes.len()
    }

    /// Takes the payment (raw bytes, mined at `height`) and returns the wallet's notes it spent
    /// as JSON `[{ pool: 0|1, nf, note_height }]`. Fails if it spent none of them.
    pub fn spent_notes(&mut self, raw_tx: &[u8], height: u32) -> Result<String, JsError> {
        let (net, _, _) = net_of(self.coin_type)?;
        let tx = Transaction::read(raw_tx, BranchId::for_height(&net, BlockHeight::from_u32(height))).map_err(|e| err(format!("bad transaction: {e}")))?;
        if Some(*tx.txid().as_ref()) != self.target {
            return Err(err("the fetched transaction is not the payment asked for"));
        }
        let mut out = vec![];
        for (pool, b) in [(Pool::Orchard, tx.orchard_bundle()), (Pool::Ironwood, tx.ironwood_bundle())] {
            for a in b.map(|b| b.actions().iter().collect::<Vec<_>>()).unwrap_or_default() {
                let nf = a.nullifier().to_bytes();
                if let Some(f) = self.notes.get(&(pool, nf)).filter(|f| f.height < height) {
                    out.push(serde_json::json!({ "pool": if pool == Pool::Orchard { 0 } else { 1 }, "nf": hex::encode(nf), "note_height": f.height }));
                }
            }
        }
        if out.is_empty() {
            return Err(err("this viewing key's wallet spent none of its notes in that payment (wrong key, or a birthday after the notes arrived?)"));
        }
        self.tx = Some((tx, height));
        Ok(serde_json::to_string(&out)?)
    }

    /// Starts rebuilding one spent note's Merkle path: `tree_hex` is the pool's tree from
    /// GetTreeState at the block before the first block that will be fed (empty for genesis).
    pub fn witness_start(&mut self, pool: u8, nf_hex: &str, tree_hex: &str) -> Result<(), JsError> {
        let pool = pool_of(pool)?;
        let nf: [u8; 32] = hex::decode(nf_hex).ok().and_then(|b| b.try_into().ok()).ok_or_else(|| err("bad nullifier"))?;
        let found = self.notes.get(&(pool, nf)).ok_or_else(|| err("unknown note"))?;
        let (tx, _) = self.tx.as_ref().ok_or_else(|| err("give the payment first"))?;
        let bundle = match pool {
            Pool::Orchard => tx.orchard_bundle(),
            Pool::Ironwood => tx.ironwood_bundle(),
        }
        .ok_or_else(|| err("the payment has no bundle in that pool"))?;
        let want_root = Option::from(MerkleHashOrchard::from_bytes(&bundle.anchor().to_bytes())).ok_or_else(|| err("bad anchor"))?;
        let tree = if tree_hex.is_empty() {
            CommitmentTree::empty()
        } else {
            let bytes = hex::decode(tree_hex).map_err(|_| err("bad tree state"))?;
            zcash_primitives::merkle_tree::read_commitment_tree::<MerkleHashOrchard, _, 32>(&bytes[..]).map_err(|e| err(format!("bad tree state: {e}")))?
        };
        let cmx = Option::from(ExtractedNoteCommitment::from_bytes(&found.cmx)).ok_or_else(|| err("bad cmx"))?;
        self.rebuild = Some(Rebuild { pool, nf, target: MerkleHashOrchard::from_cmx(&cmx), note_height: found.height, want_root, tree, witness: None });
        Ok(())
    }

    /// Feeds one block to the path being rebuilt. Returns true once the path at the payment's
    /// anchor is found (later blocks are then ignored, but keep fetching to the window's end so
    /// the server can't tell where it was found).
    pub fn witness_block(&mut self, height: u32, packed: &[u8]) -> Result<bool, JsError> {
        let r = self.rebuild.as_mut().ok_or_else(|| err("call witness_start first"))?;
        if packed.len() % PACKED != 0 {
            return Err(err("a block's actions are packed 181 bytes each"));
        }
        if self.paths.contains_key(&(r.pool, r.nf)) {
            return Ok(true);
        }
        for a in packed.chunks(PACKED) {
            if pool_of(a[0])? != r.pool {
                continue;
            }
            let cmx = Option::from(ExtractedNoteCommitment::from_bytes(&a[65..97].try_into().unwrap())).ok_or_else(|| err("bad cmx"))?;
            let leaf = MerkleHashOrchard::from_cmx(&cmx);
            match r.witness.as_mut() {
                Some(w) => w.append(leaf).map_err(|_| err("tree full"))?,
                None => {
                    r.tree.append(leaf).map_err(|_| err("tree full"))?;
                    if leaf == r.target && height == r.note_height {
                        r.witness = Some(IncrementalWitness::from_tree(r.tree.clone()).ok_or_else(|| err("empty tree"))?);
                    }
                }
            }
        }
        if let Some(w) = &r.witness {
            if w.root() == r.want_root {
                let path = w.path().ok_or_else(|| err("no path"))?;
                self.paths.insert((r.pool, r.nf), MerklePath::from(path));
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Makes the proofs (several seconds; the proving key is built on first use) and returns the
    /// prepared receipt, `zip311u1…`. Discloses what the wallet sent to others, with memos.
    pub fn prepare(&self, message: &str) -> Result<String, JsError> {
        let (tx, _) = self.tx.as_ref().ok_or_else(|| err("give the payment first"))?;
        let ovk = self.fvk.to_ovk(Scope::External);
        let bundle_of = |p: Pool| match p {
            Pool::Orchard => tx.orchard_bundle(),
            Pool::Ironwood => tx.ironwood_bundle(),
        };
        let spends_in = |p: Pool| self.paths.keys().any(|(q, _)| *q == p);
        let pool = if spends_in(Pool::Ironwood) {
            Pool::Ironwood
        } else if spends_in(Pool::Orchard) {
            Pool::Orchard
        } else {
            return Err(err("no spent note's path was rebuilt"));
        };
        let bundle = bundle_of(pool).ok_or_else(|| err("no bundle"))?;
        let mut spends = vec![];
        for (i, a) in bundle.actions().iter().enumerate() {
            let key = (pool, a.nullifier().to_bytes());
            if let (Some(f), Some(path)) = (self.notes.get(&key), self.paths.get(&key)) {
                spends.push(ViewingSpendWitness {
                    index: i,
                    fvk: self.fvk.clone(),
                    note: f.note,
                    merkle_path: path.clone(),
                    prove_address: None,
                    source: None,
                });
            }
        }
        // Outputs sent to someone else: recoverable with the wallet's OVK, not decryptable by its
        // own incoming keys (so not change). In the spends' pool, else the other (a crossing).
        let sent = |p: Pool| -> Vec<usize> {
            bundle_of(p)
                .map(|b| {
                    b.actions()
                        .iter()
                        .enumerate()
                        .filter(|(_, a)| {
                            let out = &a.encrypted_note().out_ciphertext;
                            let (recover, ours) = match p {
                                Pool::Orchard => (
                                    try_output_recovery_with_ovk(&OrchardDomain::for_action(a), &ovk, *a, a.cv_net(), out).is_some(),
                                    self.ivks.iter().any(|ivk| try_note_decryption(&OrchardDomain::for_action(a), ivk, *a).is_some()),
                                ),
                                Pool::Ironwood => (
                                    try_output_recovery_with_ovk(&IronwoodDomain::for_action(a), &ovk, *a, a.cv_net(), out).is_some(),
                                    self.ivks.iter().any(|ivk| try_note_decryption(&IronwoodDomain::for_action(a), ivk, *a).is_some()),
                                ),
                            };
                            recover && !ours
                        })
                        .map(|(i, _)| i)
                        .collect()
                })
                .unwrap_or_default()
        };
        let other = if pool == Pool::Orchard { Pool::Ironwood } else { Pool::Orchard };
        let same = sent(pool);
        let (output_pool, outs) = if same.is_empty() && !sent(other).is_empty() { (other, sent(other)) } else { (pool, same) };
        let network = if self.nt == NetworkType::Main { RNet::Mainnet } else { RNet::Testnet };
        let mut b = ReceiptBuilder::new(network, tx).spends_in(pool).outputs_in(output_pool).message(message.as_bytes());
        for i in outs {
            b = b.disclose(i, ovk.clone());
        }
        for w in spends {
            b = b.spend(w);
        }
        let prepared = PK.with(|pk| {
            let pk = pk.get_or_init(receipts_core::proving_key);
            b.prepare(pk, rand::rand_core::UnwrapErr(rand::rngs::SysRng))
        });
        Ok(prepared.map_err(err)?.to_text())
    }

    /// The payment's txid as block explorers show it, once given.
    #[wasm_bindgen(getter)]
    pub fn txid(&self) -> Option<String> {
        self.tx.as_ref().map(|(t, _)| display_txid(t.txid().as_ref()))
    }
}

/// Builds the proving key now (it takes several seconds), so `prepare` doesn't wait for it.
#[wasm_bindgen]
pub fn warm_up_prover() {
    PK.with(|pk| {
        pk.get_or_init(receipts_core::proving_key);
    });
}

/// Signs a prepared receipt with the wallet's seed phrase (BIP 39, ZIP 32 `account`), after
/// checking that the phrase's key made its spends. The phrase and the keys derived from it are
/// dropped when this returns; nothing is stored or sent. Returns `zip311r1…`.
#[wasm_bindgen]
pub fn sign_with_phrase(prepared: &str, phrase: &str, account: u32) -> Result<String, JsError> {
    let p = PreparedReceipt::from_text(prepared).map_err(err)?;
    let words = phrase.split_whitespace().collect::<Vec<_>>().join(" ");
    // Never echo the error: it can quote a word of the phrase.
    let m = <bip0039::Mnemonic<bip0039::English>>::from_phrase(words.as_str()).map_err(|_| err("that doesn't decode as a BIP 39 seed phrase"))?;
    let seed = m.to_seed("");
    let account = zip32::AccountId::try_from(account).map_err(|_| err("bad account index"))?;
    let sk = SpendingKey::from_zip32_seed(&seed, p.unsigned().coin_type, account).map_err(|_| err("couldn't derive the spending key"))?;
    let asks = vec![SpendAuthorizingKey::from(&sk); p.unsigned().spends.len()];
    let sigs = receipts_core::sign_prepared(p.unsigned(), p.alphas(), &asks, rand::rand_core::UnwrapErr(rand::rngs::SysRng))
        .map_err(|_| err("this seed phrase's wallet (account above) didn't make these spends"))?;
    Ok(p.apply_signatures(sigs).map_err(err)?.to_text())
}
