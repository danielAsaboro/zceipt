//! Proof of income: a recipient proves it received at least an amount across several payments,
//! without revealing any payment's amount.
//!
//! For each payment output `(txid, index)` the recipient makes an Orchard Action proof that spends
//! its own note there, against the root of a one-leaf tree holding that output's `cmx` (read by
//! the verifier from the chain), with `cv_net` fixed by the verifier to `ValueCommit_0(floor)`;
//! the hidden output carries `v - floor`. The circuit's range checks then give `v >= floor`, and
//! the anchor check (which applies since `v >= 1`) ties the note to that output. Every item uses
//! the same `rk`, and one SpendAuthSig over the whole proof binds the items, the floors and a
//! verifier's challenge. One Halo 2 proof covers every item.
//!
//! What it shows: the holder of one spend authority (the same `rk`) received at least
//! `sum(floor)` in these outputs. What it reveals beyond that: which outputs, each note's
//! nullifier (so the verifier sees if and when it is spent, as with a proof of funds), and the
//! floors, which [`spread`] keeps as even as the notes allow.
//!
//! ```text
//! income := "ZRCI" | version:u8 = 1 | coinType:u32le | msgLen:u16le | msg | rk[32]
//!         | n:u16le | { pool:u8 | txid[32] | index:u32le | height:u32le | floor:u64le | nf[32] | cmx[32] }^n
//!         | proofLen:u32le | proof | spendAuthSig[64]
//! text   := "zip311i1" || base64url_nopad(income)
//! digest := BLAKE2b-256("ZIP311Income" || coinType, income without spendAuthSig)
//! ```

use crate::{note_to_throwaway, pool_note_version, screened, signing_personal, zero_trapdoor, Error, Pool, RECEIPT_CIRCUIT};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use orchard::{
    builder::SpendInfo,
    bundle::Flags,
    circuit::{Circuit, Instance, ProvingKey, VerifyingKey},
    keys::{FullViewingKey, SpendAuthorizingKey, SpendValidatingKey},
    note::{ExtractedNoteCommitment, Nullifier, Rho},
    primitives::redpallas::{self, SpendAuth},
    value::NoteValue,
    Anchor, Note, Proof,
};
use rand_core::CryptoRng;

pub const INCOME_TEXT_PREFIX: &str = "zip311i1";
const MAGIC: &[u8; 4] = b"ZRCI";
const MAX_ITEMS: usize = 256;
const MAX_PROOF: usize = 1 << 20;

/// One payment output counted towards the total.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IncomeItem {
    pub pool: Pool,
    pub txid: [u8; 32],
    /// The output's action index in the transaction's `pool` bundle.
    pub index: u32,
    /// The block the transaction was mined in (where verifiers fetch it).
    pub height: u32,
    /// The note held at least this much (zatoshis, at least 1).
    pub floor: u64,
    pub nf: [u8; 32],
    /// The hidden output of this item's Action statement.
    pub cmx: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IncomeProof {
    pub coin_type: u32,
    pub msg: Vec<u8>,
    pub rk: [u8; 32],
    pub items: Vec<IncomeItem>,
    pub proof: Vec<u8>,
    pub sig: [u8; 64],
}

/// A received note to count: the note, and the output of `txid` that created it.
pub struct IncomeWitness {
    pub pool: Pool,
    pub txid: [u8; 32],
    pub index: u32,
    pub height: u32,
    pub note: Note,
}

/// Floors for notes of `values` that add up to `target`, each at most its note's value and as
/// even as the values allow (so the floors say little about the notes), or `None` if the notes
/// hold less than `target`. Every floor is at least 1.
pub fn spread(values: &[u64], target: u64) -> Option<Vec<u64>> {
    if values.is_empty() || values.contains(&0) || values.iter().map(|v| *v as u128).sum::<u128>() < target as u128 {
        return None;
    }
    let mut order: Vec<usize> = (0..values.len()).collect();
    order.sort_by_key(|&i| values[i]);
    let mut floors = vec![0u64; values.len()];
    let mut left = target;
    for (k, &i) in order.iter().enumerate() {
        let share = left.div_ceil((values.len() - k) as u64);
        floors[i] = values[i].min(share).max(1);
        left -= left.min(floors[i]);
    }
    Some(floors)
}

impl IncomeProof {
    fn body(&self) -> Vec<u8> {
        let mut v = MAGIC.to_vec();
        v.push(1);
        v.extend_from_slice(&self.coin_type.to_le_bytes());
        v.extend_from_slice(&(self.msg.len() as u16).to_le_bytes());
        v.extend_from_slice(&self.msg);
        v.extend_from_slice(&self.rk);
        v.extend_from_slice(&(self.items.len() as u16).to_le_bytes());
        for it in &self.items {
            v.push(it.pool as u8);
            v.extend_from_slice(&it.txid);
            v.extend_from_slice(&it.index.to_le_bytes());
            v.extend_from_slice(&it.height.to_le_bytes());
            v.extend_from_slice(&it.floor.to_le_bytes());
            v.extend_from_slice(&it.nf);
            v.extend_from_slice(&it.cmx);
        }
        v.extend_from_slice(&(self.proof.len() as u32).to_le_bytes());
        v.extend_from_slice(&self.proof);
        v
    }

    /// What the signature covers: everything but itself.
    pub fn digest(&self) -> [u8; 32] {
        let h = blake2b_simd::Params::new().hash_length(32).personal(&signing_personal(b"ZIP311Income", self.coin_type)).hash(&self.body());
        h.as_bytes().try_into().unwrap()
    }

    /// The total the proof shows (the sum of the floors).
    pub fn total(&self) -> u64 {
        self.items.iter().fold(0u64, |a, i| a.saturating_add(i.floor))
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut v = self.body();
        v.extend_from_slice(&self.sig);
        v
    }

    pub fn from_bytes(b: &[u8]) -> Result<Self, Error> {
        let mut p = 0usize;
        let mut take = |n: usize| -> Result<&[u8], Error> {
            let s = b.get(p..p + n).ok_or(Error::BadIncome)?;
            p += n;
            Ok(s)
        };
        let u16_ = |s: &[u8]| u16::from_le_bytes(s.try_into().unwrap()) as usize;
        let u32_ = |s: &[u8]| u32::from_le_bytes(s.try_into().unwrap());
        if take(4)? != MAGIC || take(1)? != [1] {
            return Err(Error::BadIncome);
        }
        let coin_type = u32_(take(4)?);
        let n = u16_(take(2)?);
        let msg = take(n)?.to_vec();
        let rk: [u8; 32] = take(32)?.try_into().unwrap();
        let n = u16_(take(2)?);
        if n == 0 || n > MAX_ITEMS {
            return Err(Error::BadIncome);
        }
        let mut items = Vec::with_capacity(n);
        for _ in 0..n {
            let pool = match take(1)?[0] {
                0 => Pool::Orchard,
                1 => Pool::Ironwood,
                _ => return Err(Error::BadIncome),
            };
            let txid = take(32)?.try_into().unwrap();
            let index = u32_(take(4)?);
            let height = u32_(take(4)?);
            let floor = u64::from_le_bytes(take(8)?.try_into().unwrap());
            let nf = take(32)?.try_into().unwrap();
            let cmx = take(32)?.try_into().unwrap();
            if floor == 0 {
                return Err(Error::BadIncome);
            }
            items.push(IncomeItem { pool, txid, index, height, floor, nf, cmx });
        }
        let len = u32_(take(4)?) as usize;
        if len == 0 || len > MAX_PROOF {
            return Err(Error::BadIncome);
        }
        let proof = take(len)?.to_vec();
        let sig = take(64)?.try_into().unwrap();
        if p != b.len() {
            return Err(Error::BadIncome);
        }
        Ok(IncomeProof { coin_type, msg, rk, items, proof, sig })
    }

    pub fn to_text(&self) -> String {
        format!("{INCOME_TEXT_PREFIX}{}", URL_SAFE_NO_PAD.encode(self.to_bytes()))
    }

    pub fn from_text(s: &str) -> Result<Self, Error> {
        let body = s.trim().strip_prefix(INCOME_TEXT_PREFIX).ok_or(Error::BadIncome)?;
        let bytes = URL_SAFE_NO_PAD.decode(body).map_err(|_| Error::BadIncome)?;
        if URL_SAFE_NO_PAD.encode(&bytes) != body {
            return Err(Error::BadIncome);
        }
        Self::from_bytes(&bytes)
    }
}

fn instance(it: &IncomeItem, source_cmx: &[u8; 32], rk: &redpallas::VerificationKey<SpendAuth>) -> Result<Instance, Error> {
    let anchor = Option::<Anchor>::from(Anchor::from_bytes(screened::set_root(&[*source_cmx]).map_err(|_| Error::BadIncome)?)).ok_or(Error::BadIncome)?;
    let nf = Option::<Nullifier>::from(Nullifier::from_bytes(&it.nf)).ok_or(Error::BadIncome)?;
    let cmx = Option::<ExtractedNoteCommitment>::from(ExtractedNoteCommitment::from_bytes(&it.cmx)).ok_or(Error::BadIncome)?;
    // Fixed by the verifier from the stated floor, never taken from the prover.
    Instance::from_parts(anchor, screened::cv_net(it.floor).ok_or(Error::BadIncome)?, nf, rk.clone(), cmx, Flags::ENABLED).ok_or(Error::BadIncome)
}

/// Proves the notes in `witnesses` (this wallet's, received in those outputs) held at least
/// `floors` (one each, 1 to the note's value), bound to `msg`. Signed with `ask`.
#[allow(clippy::too_many_arguments)]
pub fn prove(
    pk: &ProvingKey,
    coin_type: u32,
    fvk: &FullViewingKey,
    ask: &SpendAuthorizingKey,
    witnesses: &[IncomeWitness],
    floors: &[u64],
    msg: &[u8],
    mut rng: impl CryptoRng,
) -> Result<IncomeProof, Error> {
    if witnesses.is_empty() || witnesses.len() != floors.len() || witnesses.len() > MAX_ITEMS || msg.len() > u16::MAX as usize {
        return Err(Error::BadIncome);
    }
    let alpha = crate::random_scalar(&mut rng);
    let rk = SpendValidatingKey::from(fvk.clone()).randomize(&alpha);
    let (mut circuits, mut items) = (vec![], vec![]);
    let mut instances = vec![];
    for (w, &floor) in witnesses.iter().zip(floors) {
        let v = w.note.value().inner();
        if floor == 0 || floor > v {
            return Err(Error::BadIncome);
        }
        let source: ExtractedNoteCommitment = w.note.commitment().into();
        let (anchor, path) = screened::tree(&[source.to_bytes()], 0).map_err(|_| Error::BadIncome)?;
        let nf = w.note.nullifier(fvk);
        let spend = SpendInfo::new(fvk.clone(), w.note, path).ok_or(Error::NoteNotOwned)?;
        let rho = Option::<Rho>::from(Rho::from_bytes(&nf.to_bytes())).ok_or(Error::Proving)?;
        let out = note_to_throwaway(rho, NoteValue::from_raw(v - floor), pool_note_version(w.pool), &mut rng);
        let cmx: ExtractedNoteCommitment = out.commitment().into();
        let item = IncomeItem { pool: w.pool, txid: w.txid, index: w.index, height: w.height, floor, nf: nf.to_bytes(), cmx: cmx.to_bytes() };
        debug_assert_eq!(anchor.to_bytes(), screened::set_root(&[source.to_bytes()]).unwrap());
        instances.push(instance(&item, &source.to_bytes(), &rk)?);
        circuits.push(Circuit::from_action_context(spend, out, alpha, zero_trapdoor(), RECEIPT_CIRCUIT).ok_or(Error::Proving)?);
        items.push(item);
    }
    let proof = Proof::create(pk, &circuits, &instances, &mut rng).map_err(|_| Error::Proving)?.as_ref().to_vec();
    let mut p = IncomeProof { coin_type, msg: msg.to_vec(), rk: (&rk).into(), items, proof, sig: [0; 64] };
    let sig = ask.randomize(&alpha).sign(&mut rng, &p.digest());
    p.sig = (&sig).into();
    Ok(p)
}

/// Checks a proof of income. `source_cmx(pool, txid, index)` returns the `cmx` of that output as
/// read from the chain (`None` refuses the proof); the caller also checks that each `txid` was
/// mined. Returns the total the proof shows.
pub fn verify(vk: &VerifyingKey, p: &IncomeProof, source_cmx: crate::SourceLookup<'_>) -> Result<u64, Error> {
    crate::check_vk(vk)?;
    let rk = redpallas::VerificationKey::<SpendAuth>::try_from(p.rk).map_err(|_| Error::BadIncome)?;
    if bool::from(group::Group::is_identity(&<pasta_curves::pallas::Point as group::GroupEncoding>::from_bytes(&p.rk).unwrap_or(group::Group::identity()))) {
        return Err(Error::BadIncome);
    }
    rk.verify(&p.digest(), &redpallas::Signature::<SpendAuth>::from(p.sig)).map_err(|_| Error::BadIncome)?;
    // Each output and each note once.
    let mut seen = std::collections::BTreeSet::new();
    let mut nfs = std::collections::BTreeSet::new();
    let mut instances = Vec::with_capacity(p.items.len());
    for it in &p.items {
        if !seen.insert((it.pool as u8, it.txid, it.index)) || !nfs.insert(it.nf) {
            return Err(Error::BadIncome);
        }
        let source = source_cmx(it.pool, &it.txid, it.index).ok_or(Error::BadIncome)?;
        instances.push(instance(it, &source, &rk)?);
    }
    Proof::new(p.proof.clone()).verify(vk, &instances).map_err(|_| Error::BadIncome)?;
    Ok(p.total())
}
