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

use crate::{note_to_throwaway, pool_note_version, random_scalar, signing_personal, source_output_cmx, source_proof_cv_net, zero_trapdoor, Error, Pool};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use blake2b_simd::Params;
use orchard::{
    builder::SpendInfo,
    bundle::Flags,
    circuit::{Circuit, Instance, ProvingKey, VerifyingKey},
    keys::{FullViewingKey, SpendAuthorizingKey, SpendingKey},
    note::{ExtractedNoteCommitment, Nullifier, Rho},
    primitives::redpallas::{self, SpendAuth},
    tree::MerklePath,
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
    pub value: u64,
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
        v.push(1);
        v.extend_from_slice(&self.coin_type.to_le_bytes());
        v.push(match self.pool {
            Pool::Orchard => 0,
            Pool::Ironwood => 1,
        });
        v.extend_from_slice(&self.height.to_le_bytes());
        v.extend_from_slice(&self.anchor);
        v.extend_from_slice(&(self.msg.len() as u16).to_le_bytes());
        v.extend_from_slice(&self.msg);
        v.push(self.notes.len() as u8);
        for n in &self.notes {
            v.extend_from_slice(&n.nf);
            v.extend_from_slice(&n.value.to_le_bytes());
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
        if take(4)? != MAGIC || take(1)? != [1] {
            return None;
        }
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
        let n = take(1)?[0] as usize;
        let mut notes = Vec::with_capacity(n);
        for _ in 0..n {
            let nf = take(32)?.try_into().ok()?;
            let value = u64::from_le_bytes(take(8)?.try_into().ok()?);
            let rk = take(32)?.try_into().ok()?;
            let out_address = take(43)?.try_into().ok()?;
            let out_rseed = take(32)?.try_into().ok()?;
            let pl = u32::from_le_bytes(take(4)?.try_into().ok()?) as usize;
            if pl > 1 << 16 {
                return None;
            }
            notes.push(ReserveNote { nf, value, rk, out_address, out_rseed, proof: take(pl)?.to_vec() });
        }
        let mut sigs = Vec::with_capacity(n);
        for _ in 0..n {
            sigs.push(take(64)?.try_into().ok()?);
        }
        if p != b.len() {
            return None;
        }
        let r = ReserveProof { coin_type, pool, height, anchor, msg, notes, sigs };
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
        self.notes.iter().map(|n| n.value).sum()
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
        let cv_net = source_proof_cv_net(Some(v)).ok_or(Error::ZeroValueSource)?;
        let cmx: ExtractedNoteCommitment = out.commitment().into();
        let circuit = Circuit::from_action_context(spend, out, alpha, zero_trapdoor(), crate::RECEIPT_CIRCUIT).ok_or(Error::Proving)?;
        let instance = Instance::from_parts(anchor, cv_net, nf, rk.clone(), cmx, Flags::ENABLED).ok_or(Error::Proving)?;
        let proof = Proof::create(pk, &[circuit], &[instance], &mut rng).map_err(|_| Error::Proving)?;
        notes.push(ReserveNote {
            nf: nf.to_bytes(),
            value: v,
            rk: (&rk).into(),
            out_address: out.recipient().to_raw_address_bytes(),
            out_rseed: *out.rseed().as_bytes(),
            proof: proof.as_ref().to_vec(),
        });
        keys.push(rsk);
    }
    let mut r = ReserveProof { coin_type, pool, height, anchor: anchor.to_bytes(), msg: msg.to_vec(), notes, sigs: vec![] };
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
    pub values: Vec<u64>,
    pub nullifiers: Vec<[u8; 32]>,
}

/// Checks every proof and signature against `chain_anchor`, the pool's tree root after block
/// `r.height` as the verifier read it from the chain. The caller then checks that none of the
/// returned nullifiers has been published.
pub fn verify_reserve(vk: &VerifyingKey, r: &ReserveProof, expected_coin_type: u32, chain_anchor: &[u8; 32]) -> Result<VerifiedReserve, Error> {
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
    for (i, (n, sig)) in r.notes.iter().zip(&r.sigs).enumerate() {
        let i = i as u32;
        if !seen.insert(n.nf) {
            return Err(Error::DuplicateIndex(i));
        }
        let rk = redpallas::VerificationKey::<SpendAuth>::try_from(n.rk).map_err(|_| Error::Malformed(i))?;
        rk.verify(&digest, &redpallas::Signature::<SpendAuth>::from(*sig)).map_err(|_| Error::BadSignature(i))?;
        let nf = Option::<Nullifier>::from(Nullifier::from_bytes(&n.nf)).ok_or(Error::Malformed(i))?;
        // Fixed by the verifier: non-zero, so the circuit enforces the anchor, and exact, because
        // the opened output carries 0.
        let cv_net = source_proof_cv_net(Some(n.value)).ok_or(Error::BadProof(i))?;
        let cmx = source_output_cmx(r.pool, &nf, &n.out_address, &n.out_rseed).ok_or(Error::BadProof(i))?;
        let instance = Instance::from_parts(anchor, cv_net, nf, rk, cmx, Flags::ENABLED).ok_or(Error::Malformed(i))?;
        Proof::new(n.proof.clone()).verify(vk, &[instance]).map_err(|_| Error::BadProof(i))?;
    }
    Ok(VerifiedReserve { total: r.total(), values: r.notes.iter().map(|n| n.value).collect(), nullifiers: r.notes.iter().map(|n| n.nf).collect() })
}
