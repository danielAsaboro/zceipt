//! Screened-set proofs: the note a receipt spent was created by one of a published list of
//! outputs (for example the shield deposits an exchange has screened), without saying which.
//!
//! The list's commitments are the leaves of an Orchard-shaped tree, and the proof is one more
//! Orchard Action proof with that tree's root as its anchor, the spend's own nullifier and the
//! receipt's `rk`. Same construction as a source proof (lib.rs), with a tree of many leaves in
//! place of a tree of one: the verifier learns that the spent note is in the set, not which one.
//!
//! ```text
//! proof := "ZRCS" | version:u8 = 2 | coin_type:u32le | pool:u8 | txid[32] | index:u32le
//!          | floor:u64le | set_root[32] | cmx[32] | proof_len:u32le | proof
//! text  := "zip311s1" || base64url_nopad(proof)
//! ```
//!
//! `cv_net` is fixed by the verifier to `ValueCommit_0(floor)` (the hidden output carries
//! `v - floor`), so the spent note held at least `floor` (at least 1, so the circuit enforces the
//! anchor), and the proof shows that much came from the set without showing the note's value.
//! (Version 1, with no floor field and a floor of 1, was never released.)

use crate::{note_to_throwaway, pool_note_version, zero_trapdoor, Error, Pool, Receipt, RECEIPT_CIRCUIT};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use incrementalmerkletree::{Hashable, Level};
use orchard::bundle::Flags;
use orchard::{
    builder::SpendInfo,
    circuit::{Circuit, Instance, ProvingKey, VerifyingKey},
    keys::FullViewingKey,
    note::{ExtractedNoteCommitment, Nullifier, Rho},
    primitives::redpallas::{self, SpendAuth},
    tree::{MerkleHashOrchard, MerklePath},
    value::{NoteValue, ValueCommitment},
    Anchor, Note, Proof,
};
use pasta_curves::pallas;
use rand_core::CryptoRng;

pub const SCREENED_TEXT_PREFIX: &str = "zip311s1";
const MAGIC: &[u8; 4] = b"ZRCS";
const VERSION: u8 = 2;
const MAX_PROOF_LEN: usize = 16 * 1024;
/// A list longer than this would not fit the tree a proof is made against in reasonable time.
pub const MAX_SET: usize = 1 << 20;

/// Proof that the note spent at action `index` of the receipt's transaction is in the set
/// whose tree root is `set_root`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScreenedProof {
    pub coin_type: u32,
    pub pool: Pool,
    pub txid: [u8; 32],
    pub index: u32,
    /// The spent note held at least this much (zatoshis, at least 1).
    pub floor: u64,
    pub set_root: [u8; 32],
    pub cmx: [u8; 32],
    pub proof: Vec<u8>,
}

/// The root of the tree whose leaves are `set`, in order (each a note commitment `cmx`).
pub fn set_root(set: &[[u8; 32]]) -> Result<[u8; 32], Error> {
    Ok(tree(set, 0)?.0.to_bytes())
}

/// The root and the authentication path of leaf `pos`.
pub(crate) fn tree(set: &[[u8; 32]], pos: usize) -> Result<(Anchor, MerklePath), Error> {
    if set.is_empty() || set.len() > MAX_SET || pos >= set.len() {
        return Err(Error::NotInSet);
    }
    let mut level: Vec<MerkleHashOrchard> = set
        .iter()
        .map(|c| {
            Option::<ExtractedNoteCommitment>::from(ExtractedNoteCommitment::from_bytes(c)).map(|c| MerkleHashOrchard::from_cmx(&c)).ok_or(Error::NotInSet)
        })
        .collect::<Result<_, _>>()?;
    let mut auth = [MerkleHashOrchard::empty_leaf(); 32];
    let mut idx = pos;
    for (l, slot) in auth.iter_mut().enumerate() {
        let lvl = Level::from(l as u8);
        let empty = MerkleHashOrchard::empty_root(lvl);
        *slot = level.get(idx ^ 1).copied().unwrap_or(empty);
        level = level.chunks(2).map(|p| MerkleHashOrchard::combine(lvl, &p[0], p.get(1).unwrap_or(&empty))).collect();
        idx >>= 1;
    }
    let path = MerklePath::from_parts(pos as u32, auth);
    Ok((Anchor::from(level[0]), path))
}

pub(crate) fn cv_net(floor: u64) -> Option<ValueCommitment> {
    (floor >= 1).then(|| ValueCommitment::derive(NoteValue::from_raw(floor) - NoteValue::ZERO, zero_trapdoor()))
}

/// Proves that `note` (spent at action `index` of `txid` under `rk = ak + [alpha] G`) is in
/// `set` and held at least `floor` (1 to the note's value). Made by the payer along with the
/// receipt, since it needs the spend's `alpha`.
#[allow(clippy::too_many_arguments)]
pub fn prove(
    pk: &ProvingKey,
    coin_type: u32,
    pool: Pool,
    txid: [u8; 32],
    index: u32,
    fvk: &FullViewingKey,
    note: Note,
    set: &[[u8; 32]],
    floor: u64,
    alpha: pallas::Scalar,
    rk: &redpallas::VerificationKey<SpendAuth>,
    rng: &mut impl CryptoRng,
) -> Result<ScreenedProof, Error> {
    let mine: ExtractedNoteCommitment = note.commitment().into();
    let pos = set.iter().position(|c| *c == mine.to_bytes()).ok_or(Error::NotInSet)?;
    let v = note.value().inner();
    if v == 0 {
        return Err(Error::ZeroValueSource);
    }
    if floor == 0 || floor > v {
        return Err(Error::BadScreenedProof(index));
    }
    let (anchor, path) = tree(set, pos)?;
    let nf = note.nullifier(fvk);
    let spend = SpendInfo::new(fvk.clone(), note, path).ok_or(Error::NoteNotOwned)?;
    let out_rho = Option::<Rho>::from(Rho::from_bytes(&nf.to_bytes())).ok_or(Error::Proving)?;
    let out = note_to_throwaway(out_rho, NoteValue::from_raw(v - floor), pool_note_version(pool), rng);
    let cmx: ExtractedNoteCommitment = out.commitment().into();
    let circuit = Circuit::from_action_context(spend, out, alpha, zero_trapdoor(), RECEIPT_CIRCUIT).ok_or(Error::Proving)?;
    let instance = Instance::from_parts(anchor, cv_net(floor).ok_or(Error::Proving)?, nf, rk.clone(), cmx, Flags::ENABLED).ok_or(Error::Proving)?;
    let proof = Proof::create(pk, &[circuit], &[instance], &mut *rng).map_err(|_| Error::Proving)?;
    Ok(ScreenedProof { coin_type, pool, txid, index, floor, set_root: anchor.to_bytes(), cmx: cmx.to_bytes(), proof: proof.as_ref().to_vec() })
}

/// Checks `p` against a receipt that has already been verified against its transaction, and the
/// nullifier action `p.index` of that transaction published. `set` is the published list, from
/// which the root is computed here (never taken from the proof).
pub fn verify(vk: &VerifyingKey, receipt: &Receipt, nf: &[u8; 32], p: &ScreenedProof, set: &[[u8; 32]]) -> Result<(), Error> {
    let bad = || Error::BadScreenedProof(p.index);
    let u = &receipt.unsigned;
    if p.coin_type != u.coin_type || p.pool != u.pool || p.txid != u.txid {
        return Err(bad());
    }
    let spend = u.spends.iter().find(|s| s.index == p.index).ok_or_else(bad)?;
    let root = set_root(set)?;
    if root != p.set_root {
        return Err(Error::NotInSet);
    }
    let anchor = Option::<Anchor>::from(Anchor::from_bytes(root)).ok_or_else(bad)?;
    let rk = redpallas::VerificationKey::<SpendAuth>::try_from(spend.rk).map_err(|_| bad())?;
    let nf = Option::<Nullifier>::from(Nullifier::from_bytes(nf)).ok_or_else(bad)?;
    let cmx = Option::<ExtractedNoteCommitment>::from(ExtractedNoteCommitment::from_bytes(&p.cmx)).ok_or_else(bad)?;
    // Fixed by the verifier from the stated floor, never taken from the prover.
    let instance = Instance::from_parts(anchor, cv_net(p.floor).ok_or_else(bad)?, nf, rk, cmx, Flags::ENABLED).ok_or_else(bad)?;
    Proof::new(p.proof.clone()).verify(vk, &[instance]).map_err(|_| bad())
}

impl ScreenedProof {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(4 + 1 + 4 + 1 + 32 + 4 + 64 + 4 + self.proof.len());
        v.extend_from_slice(MAGIC);
        v.push(VERSION);
        v.extend_from_slice(&self.coin_type.to_le_bytes());
        v.push(match self.pool {
            Pool::Orchard => 0,
            Pool::Ironwood => 1,
        });
        v.extend_from_slice(&self.txid);
        v.extend_from_slice(&self.index.to_le_bytes());
        v.extend_from_slice(&self.floor.to_le_bytes());
        v.extend_from_slice(&self.set_root);
        v.extend_from_slice(&self.cmx);
        v.extend_from_slice(&(self.proof.len() as u32).to_le_bytes());
        v.extend_from_slice(&self.proof);
        v
    }

    pub fn from_bytes(b: &[u8]) -> Option<Self> {
        let take = |r: &mut &[u8], n: usize| -> Option<Vec<u8>> {
            (r.len() >= n).then(|| {
                let (a, rest) = r.split_at(n);
                *r = rest;
                a.to_vec()
            })
        };
        let mut r = b;
        if take(&mut r, 4)? != MAGIC || take(&mut r, 1)? != [VERSION] {
            return None;
        }
        let coin_type = u32::from_le_bytes(take(&mut r, 4)?.try_into().ok()?);
        let pool = match take(&mut r, 1)?[0] {
            0 => Pool::Orchard,
            1 => Pool::Ironwood,
            _ => return None,
        };
        let txid = take(&mut r, 32)?.try_into().ok()?;
        let index = u32::from_le_bytes(take(&mut r, 4)?.try_into().ok()?);
        let floor = u64::from_le_bytes(take(&mut r, 8)?.try_into().ok()?);
        if floor == 0 {
            return None;
        }
        let set_root = take(&mut r, 32)?.try_into().ok()?;
        let cmx = take(&mut r, 32)?.try_into().ok()?;
        let len = u32::from_le_bytes(take(&mut r, 4)?.try_into().ok()?) as usize;
        if len > MAX_PROOF_LEN {
            return None;
        }
        let proof = take(&mut r, len)?;
        r.is_empty().then_some(ScreenedProof { coin_type, pool, txid, index, floor, set_root, cmx, proof })
    }

    pub fn to_text(&self) -> String {
        format!("{SCREENED_TEXT_PREFIX}{}", URL_SAFE_NO_PAD.encode(self.to_bytes()))
    }

    pub fn from_text(s: &str) -> Option<Self> {
        Self::from_bytes(&URL_SAFE_NO_PAD.decode(s.trim().strip_prefix(SCREENED_TEXT_PREFIX)?).ok()?)
    }
}
