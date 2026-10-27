//! Proof of funds (`zrsv1`): "I hold at least X ZEC in unspent shielded notes", for a treasury
//! report, an OTC counterparty, an escrow or a lender, without a viewing key.
//!
//! For each note the holder makes an Orchard Action proof that spends it against the pool's real
//! commitment-tree root at a recent height `H` (so the note exists, and its nullifier is the one the
//! proof publishes), with the value commitment fixed by the verifier, `ValueCommit_0(v)`, and the
//! proof's zero-value output opened, so the note carries exactly `v` (the source-proof construction
//! with a real anchor). Every note's fresh `rk` signs the whole proof, which binds a verifier's
//! challenge.
//!
//! "Still unspent" is the chain's part: the verifier downloads every nullifier the pool has
//! published (for Ironwood, every block since its activation) and checks none is one of the
//! proof's. Downloading all of them, as a wallet sync does, tells the server nothing about which
//! notes are being checked.
//!
//! What the verifier learns: the total and each note's value, and the notes' nullifiers, so it can
//! see when they are spent later. That is the price of the claim (Monero's reserve proofs pay it
//! too); hold the proof's audience to people who may know that.
//!
//! Version 2 hides each note's value and shows only the total: each proof carries the prover's
//! own value commitment `cv_i = ValueCommit_rcv_i(v_i)` (the opened output still carries 0), and the
//! proof reveals the total `V` and `R = sum rcv_i`; the verifier checks `sum cv_i = ValueCommit_R(V)`.
//! A note of value 0 skips the circuit's anchor check, so it could be made up, but it adds nothing
//! to the total. Each nullifier is still shown (that is how "unspent" is checked).

use crate::{note_to_throwaway, pool_note_version, random_scalar, signing_personal, source_output_cmx, source_proof_cv_net, Error, Pool};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use blake2b_simd::Params;
use ff::PrimeField;
use orchard::{
    builder::SpendInfo,
    bundle::Flags,
    circuit::{Circuit, Instance, ProvingKey, VerifyingKey},
    keys::{FullViewingKey, SpendAuthorizingKey, SpendingKey},
    note::{ExtractedNoteCommitment, Nullifier, Rho},
    primitives::redpallas::{self, SpendAuth},
    tree::MerklePath,
    value::{NoteValue, ValueCommitTrapdoor, ValueCommitment},
    Anchor, Note, Proof,
};
use rand_core::CryptoRng;

pub const RESERVE_TEXT_PREFIX: &str = "zrsv1";
const MAGIC: &[u8; 4] = b"ZRSV";
const MAX_NOTES: usize = 255;

/// One proven note.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReserveNote {
    pub nf: [u8; 32],
    /// The note's value (version 1); 0 when hidden.
    pub value: u64,
    /// Version 2: the prover's value commitment to the note's value, in place of the value.
    pub cv_net: Option<[u8; 32]>,
    pub rk: [u8; 32],
    /// The proof's opened zero-value output (throwaway address, `rho = nf`).
    pub out_address: [u8; 43],
    pub out_rseed: [u8; 32],
    pub proof: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReserveProof {
    pub coin_type: u32,
    pub pool: Pool,
    /// The block height whose tree root every note is proven against.
    pub height: u32,
    pub anchor: [u8; 32],
    /// A verifier's challenge, a date, a purpose.
    pub msg: Vec<u8>,
    pub notes: Vec<ReserveNote>,
    /// Version 2: the total and the sum of the notes' value-commitment trapdoors.
    pub hidden_total: Option<(u64, [u8; 32])>,
    /// One signature per note, each by that note's `rk` over everything above.
    pub sigs: Vec<[u8; 64]>,
}

/// A note the holder will prove: the note, its Merkle path to the anchor at `height`.
pub struct ReserveWitness {
    pub note: Note,
    pub merkle_path: MerklePath,
}

impl ReserveProof {
    fn unsigned_bytes(&self) -> Vec<u8> {
        let mut v = MAGIC.to_vec();
        v.push(if self.hidden_total.is_some() { 2 } else { 1 });
        v.extend_from_slice(&self.coin_type.to_le_bytes());
        v.push(match self.pool {
            Pool::Orchard => 0,
            Pool::Ironwood => 1,
        });
        v.extend_from_slice(&self.height.to_le_bytes());
        v.extend_from_slice(&self.anchor);
        v.extend_from_slice(&(self.msg.len() as u16).to_le_bytes());
        v.extend_from_slice(&self.msg);
        if let Some((total, rcv)) = &self.hidden_total {
            v.extend_from_slice(&total.to_le_bytes());
            v.extend_from_slice(rcv);
        }
        v.push(self.notes.len() as u8);
        for n in &self.notes {
            v.extend_from_slice(&n.nf);
            match (&self.hidden_total, &n.cv_net) {
                (Some(_), Some(cv)) => v.extend_from_slice(cv),
                _ => v.extend_from_slice(&n.value.to_le_bytes()),
            }
            v.extend_from_slice(&n.rk);
            v.extend_from_slice(&n.out_address);
            v.extend_from_slice(&n.out_rseed);
            v.extend_from_slice(&(n.proof.len() as u32).to_le_bytes());
            v.extend_from_slice(&n.proof);
        }
        v
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut v = self.unsigned_bytes();
        for s in &self.sigs {
            v.extend_from_slice(s);
        }
        v
    }

    /// Strict decoding (re-encoding must give the same bytes).
    pub fn from_bytes(b: &[u8]) -> Option<Self> {
        let mut p = 0usize;
        let mut take = |n: usize| -> Option<&[u8]> {
            let s = b.get(p..p + n)?;
            p += n;
            Some(s)
        };
        if take(4)? != MAGIC {
            return None;
        }
        let hidden = match take(1)?[0] {
            1 => false,
            2 => true,
            _ => return None,
        };
        let coin_type = u32::from_le_bytes(take(4)?.try_into().ok()?);
        let pool = match take(1)?[0] {
            0 => Pool::Orchard,
            1 => Pool::Ironwood,
            _ => return None,
        };
        let height = u32::from_le_bytes(take(4)?.try_into().ok()?);
        let anchor = take(32)?.try_into().ok()?;
        let ml = u16::from_le_bytes(take(2)?.try_into().ok()?) as usize;
        let msg = take(ml)?.to_vec();
        let hidden_total = if hidden { Some((u64::from_le_bytes(take(8)?.try_into().ok()?), take(32)?.try_into().ok()?)) } else { None };
        let n = take(1)?[0] as usize;
        let mut notes = Vec::with_capacity(n);
        for _ in 0..n {
            let nf = take(32)?.try_into().ok()?;
            let (value, cv_net) = if hidden { (0, Some(take(32)?.try_into().ok()?)) } else { (u64::from_le_bytes(take(8)?.try_into().ok()?), None) };
            let rk = take(32)?.try_into().ok()?;
            let out_address = take(43)?.try_into().ok()?;
            let out_rseed = take(32)?.try_into().ok()?;
            let pl = u32::from_le_bytes(take(4)?.try_into().ok()?) as usize;
            if pl > 1 << 16 {
                return None;
            }
            notes.push(ReserveNote { nf, value, cv_net, rk, out_address, out_rseed, proof: take(pl)?.to_vec() });
        }
        let mut sigs = Vec::with_capacity(n);
        for _ in 0..n {
            sigs.push(take(64)?.try_into().ok()?);
        }
        if p != b.len() {
            return None;
        }
        let r = ReserveProof { coin_type, pool, height, anchor, msg, notes, hidden_total, sigs };
        (r.to_bytes() == b).then_some(r)
    }

    pub fn to_text(&self) -> String {
        format!("{RESERVE_TEXT_PREFIX}{}", URL_SAFE_NO_PAD.encode(self.to_bytes()))
    }

    pub fn from_text(s: &str) -> Option<Self> {
        Self::from_bytes(&URL_SAFE_NO_PAD.decode(s.trim().strip_prefix(RESERVE_TEXT_PREFIX)?).ok()?)
    }

    /// The total proven, in zatoshis.
    pub fn total(&self) -> u64 {
        match &self.hidden_total {
            Some((total, _)) => *total,
            None => self.notes.iter().map(|n| n.value).sum(),
        }
    }
}

/// `BLAKE2b-256("ZcashReserve" || coinType, everything before the signatures)`.
pub fn signing_digest(r: &ReserveProof) -> [u8; 32] {
    let h = Params::new().hash_length(32).personal(&signing_personal(b"ZcashReserve", r.coin_type)).hash(&r.unsigned_bytes());
    h.as_bytes().try_into().expect("32 bytes")
}

/// Proves the given notes (all owned by `sk`, each with a path to `anchor`, the pool's tree root
/// after block `height`).
#[allow(clippy::too_many_arguments)]
pub fn create_reserve(
    pk: &ProvingKey,
    coin_type: u32,
    pool: Pool,
    height: u32,
    anchor: Anchor,
    msg: &[u8],
    sk: &SpendingKey,
    witnesses: &[ReserveWitness],
    rng: impl CryptoRng,
) -> Result<ReserveProof, Error> {
    create(pk, coin_type, pool, height, anchor, msg, sk, witnesses, false, rng)
}

/// Like [`create_reserve`], showing only the total, not each note's value (version 2).
#[allow(clippy::too_many_arguments)]
pub fn create_reserve_hiding_values(
    pk: &ProvingKey,
    coin_type: u32,
    pool: Pool,
    height: u32,
    anchor: Anchor,
    msg: &[u8],
    sk: &SpendingKey,
    witnesses: &[ReserveWitness],
    rng: impl CryptoRng,
) -> Result<ReserveProof, Error> {
    create(pk, coin_type, pool, height, anchor, msg, sk, witnesses, true, rng)
}

#[allow(clippy::too_many_arguments)]
fn create(
    pk: &ProvingKey,
    coin_type: u32,
    pool: Pool,
    height: u32,
    anchor: Anchor,
    msg: &[u8],
    sk: &SpendingKey,
    witnesses: &[ReserveWitness],
    hide: bool,
    mut rng: impl CryptoRng,
) -> Result<ReserveProof, Error> {
    if witnesses.is_empty() {
        return Err(Error::NoSpends);
    }
    if msg.len() > u16::MAX as usize || witnesses.len() > MAX_NOTES {
        return Err(Error::TooLarge);
    }
    let fvk = FullViewingKey::from(sk);
    let mut notes = Vec::with_capacity(witnesses.len());
    let mut keys = Vec::with_capacity(witnesses.len());
    let mut seen = std::collections::BTreeSet::new();
    let mut rcv_sum = pasta_curves::pallas::Scalar::zero();
    for (i, w) in witnesses.iter().enumerate() {
        let i = i as u32;
        let v = w.note.value().inner();
        if v == 0 {
            return Err(Error::ZeroValueSource);
        }
        if w.merkle_path.root(w.note.commitment().into()) != anchor {
            return Err(Error::WrongAnchor);
        }
        if w.note.version() != pool_note_version(pool) {
            return Err(Error::PoolMismatch);
        }
        let nf = w.note.nullifier(&fvk);
        if !seen.insert(nf.to_bytes()) {
            return Err(Error::DuplicateIndex(i));
        }
        let alpha = random_scalar(&mut rng);
        let rsk = SpendAuthorizingKey::from(sk).randomize(&alpha);
        let rk = redpallas::VerificationKey::<SpendAuth>::from(&rsk);
        let spend = SpendInfo::new(fvk.clone(), w.note, w.merkle_path.clone()).ok_or(Error::NoteNotOwned)?;
        let out_rho = Option::<Rho>::from(Rho::from_bytes(&nf.to_bytes())).ok_or(Error::Proving)?;
        let out = note_to_throwaway(out_rho, orchard::value::NoteValue::ZERO, pool_note_version(pool), &mut rng);
        // Hidden: the prover's own trapdoor; shown: the zero trapdoor, so the verifier can fix `cv`.
        let rcv_scalar = if hide { random_scalar(&mut rng) } else { pasta_curves::pallas::Scalar::zero() };
        rcv_sum += rcv_scalar;
        let rcv = Option::<ValueCommitTrapdoor>::from(ValueCommitTrapdoor::from_bytes(rcv_scalar.to_repr())).ok_or(Error::Proving)?;
        let cv_net = if hide {
            ValueCommitment::derive(NoteValue::from_raw(v) - NoteValue::ZERO, rcv.clone())
        } else {
            source_proof_cv_net(Some(v)).ok_or(Error::ZeroValueSource)?
        };
        let cv_bytes = cv_net.to_bytes();
        let cmx: ExtractedNoteCommitment = out.commitment().into();
        let circuit = Circuit::from_action_context(spend, out, alpha, rcv, crate::RECEIPT_CIRCUIT).ok_or(Error::Proving)?;
        let instance = Instance::from_parts(anchor, cv_net, nf, rk.clone(), cmx, Flags::ENABLED).ok_or(Error::Proving)?;
        let proof = Proof::create(pk, &[circuit], &[instance], &mut rng).map_err(|_| Error::Proving)?;
        notes.push(ReserveNote {
            nf: nf.to_bytes(),
            value: if hide { 0 } else { v },
            cv_net: hide.then_some(cv_bytes),
            rk: (&rk).into(),
            out_address: out.recipient().to_raw_address_bytes(),
            out_rseed: *out.rseed().as_bytes(),
            proof: proof.as_ref().to_vec(),
        });
        keys.push(rsk);
    }
    let total = witnesses.iter().map(|w| w.note.value().inner()).sum();
    let hidden_total = hide.then(|| (total, rcv_sum.to_repr()));
    let mut r = ReserveProof { coin_type, pool, height, anchor: anchor.to_bytes(), msg: msg.to_vec(), notes, hidden_total, sigs: vec![] };
    r.sigs = sign_all(&r, &keys, &mut rng);
    LAST_KEYS_FOR_TESTS.with(|k| *k.borrow_mut() = keys);
    Ok(r)
}

fn sign_all(r: &ReserveProof, keys: &[redpallas::SigningKey<SpendAuth>], rng: &mut impl CryptoRng) -> Vec<[u8; 64]> {
    let d = signing_digest(r);
    keys.iter().map(|k| (&k.sign(&mut *rng, &d)).into()).collect()
}

thread_local! {
    static LAST_KEYS_FOR_TESTS: std::cell::RefCell<Vec<redpallas::SigningKey<SpendAuth>>> = const { std::cell::RefCell::new(Vec::new()) };
}

/// Re-signs `r` with the keys of the last proof `create_reserve` made on this thread, so tests can
/// check that the proofs (not only the signatures) refuse an edit. Not part of the API.
#[doc(hidden)]
pub fn __resign_for_tests(r: &mut ReserveProof, rng: &mut impl CryptoRng) {
    let keys = LAST_KEYS_FOR_TESTS.with(|k| k.borrow().clone());
    r.sigs = sign_all(r, &keys, rng);
}

/// What a valid reserve proof shows, before the chain checks that the notes are unspent.
#[derive(Clone, Debug)]
pub struct VerifiedReserve {
    pub total: u64,
    /// Each note's value; empty when the proof hides them (version 2).
    pub values: Vec<u64>,
    pub nullifiers: Vec<[u8; 32]>,
}

/// Checks every proof and signature against `chain_anchor`, the pool's tree root after block
/// `r.height` as the verifier read it from the chain. The caller then checks that none of the
/// returned nullifiers has been published.
pub fn verify_reserve(vk: &VerifyingKey, r: &ReserveProof, expected_coin_type: u32, chain_anchor: &[u8; 32]) -> Result<VerifiedReserve, Error> {
    crate::check_vk(vk)?;
    if r.coin_type != expected_coin_type {
        return Err(Error::CoinTypeMismatch(r.coin_type, expected_coin_type));
    }
    if &r.anchor != chain_anchor {
        return Err(Error::WrongAnchor);
    }
    if r.notes.is_empty() {
        return Err(Error::NoSpends);
    }
    if r.sigs.len() != r.notes.len() {
        return Err(Error::SignatureCount);
    }
    let anchor = Option::<Anchor>::from(Anchor::from_bytes(r.anchor)).ok_or(Error::WrongAnchor)?;
    let digest = signing_digest(r);
    let mut seen = std::collections::BTreeSet::new();
    let mut cv_sum: Option<ValueCommitment> = None;
    for (i, (n, sig)) in r.notes.iter().zip(&r.sigs).enumerate() {
        let i = i as u32;
        if !seen.insert(n.nf) {
            return Err(Error::DuplicateIndex(i));
        }
        let rk = redpallas::VerificationKey::<SpendAuth>::try_from(n.rk).map_err(|_| Error::Malformed(i))?;
        rk.verify(&digest, &redpallas::Signature::<SpendAuth>::from(*sig)).map_err(|_| Error::BadSignature(i))?;
        let nf = Option::<Nullifier>::from(Nullifier::from_bytes(&n.nf)).ok_or(Error::Malformed(i))?;
        // Shown values: fixed by the verifier, non-zero, so the circuit enforces the anchor, and
        // exact, because the opened output carries 0. Hidden: the prover's, checked in sum below.
        let cv_net = match (&r.hidden_total, &n.cv_net) {
            (None, None) => source_proof_cv_net(Some(n.value)).ok_or(Error::BadProof(i))?,
            (Some(_), Some(cv)) => Option::<ValueCommitment>::from(ValueCommitment::from_bytes(cv)).ok_or(Error::Malformed(i))?,
            _ => return Err(Error::Malformed(i)),
        };
        cv_sum = Some(match cv_sum {
            None => cv_net.clone(),
            Some(acc) => acc + &cv_net,
        });
        let cmx = source_output_cmx(r.pool, &nf, &n.out_address, &n.out_rseed).ok_or(Error::BadProof(i))?;
        let instance = Instance::from_parts(anchor, cv_net, nf, rk, cmx, Flags::ENABLED).ok_or(Error::Malformed(i))?;
        Proof::new(n.proof.clone()).verify(vk, &[instance]).map_err(|_| Error::BadProof(i))?;
    }
    // Hidden values: the notes' commitments must add up to a commitment to the stated total.
    if let Some((total, rcv)) = &r.hidden_total {
        let rcv = Option::<ValueCommitTrapdoor>::from(ValueCommitTrapdoor::from_bytes(*rcv)).ok_or(Error::BadProof(0))?;
        let want = ValueCommitment::derive(NoteValue::from_raw(*total) - NoteValue::ZERO, rcv);
        if cv_sum.map(|c| c.to_bytes()) != Some(want.to_bytes()) {
            return Err(Error::BadTotal);
        }
        return Ok(VerifiedReserve { total: *total, values: vec![], nullifiers: r.notes.iter().map(|n| n.nf).collect() });
    }
    Ok(VerifiedReserve { total: r.total(), values: r.notes.iter().map(|n| n.value).collect(), nullifiers: r.notes.iter().map(|n| n.nf).collect() })
}
