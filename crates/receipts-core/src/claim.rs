//! Claims: one per key per domain (an airdrop, a grant round, a vote), with a minimum holding,
//! and nothing else about the wallet.
//!
//! A claim is the Orchard Action statement extended with `tag = Poseidon(nk, domain)` and with
//! the nullifier kept private (`orchard::circuit::claim`, a local circuit): the claimant owns a
//! note in the tree at `anchor` (the verifier's snapshot root) holding at least `floor` (fixed by
//! the verifier as `cv_net = ValueCommit_0(floor)`), and the tag depends only on the key that
//! owns it and the domain. Two claims from one key in one domain carry the same tag, whichever
//! notes they prove, so a verifier keeps one claim per tag; tags in different domains don't link,
//! and the note's nullifier isn't revealed, so a claim doesn't mark the note's later spend.
//!
//! Against a chain snapshot (the pool's tree root at a height), the claim also reveals the note's
//! nullifier, so the verifier checks the note was unspent at that height: the tree keeps spent
//! notes, and without the check one balance could claim again from each key it moved through.
//! Against a published list of notes the verifier knows were held (its own deposits, say), the
//! nullifier can stay private, and a claim then doesn't mark the note's later spend.
//!
//! What it stops: one key claiming twice, and one balance claiming from many keys. What it
//! doesn't: holders splitting funds across keys; each claim then needs `floor` of its own.
//!
//! ```text
//! height is the snapshot's block height (0 for a published list).
//! claim  := "ZRCL" | version:u8 = 1 | coinType:u32le | pool:u8 | domainLen:u16le | domain
//!         | msgLen:u16le | msg | height:u32le | anchor[32] | floor:u64le | rk[32] | cmx[32] | tag[32]
//!         | hasNf:u8 | (nf[32] if hasNf = 1)
//!         | proofLen:u32le | proof | spendAuthSig[64]
//! text   := "zip311t1" || base64url_nopad(claim)
//! digest := BLAKE2b-256("ZIP311Claim\0" || coinType, claim without spendAuthSig)
//! domainField := ToBase(BLAKE2b-512("ZIP311ClaimDom", domain))
//! ```

use crate::{note_to_throwaway, pool_note_version, screened, signing_personal, zero_trapdoor, Error, Pool};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use group::ff::{FromUniformBytes, PrimeField};
use orchard::{
    builder::SpendInfo,
    bundle::Flags,
    circuit::{
        claim::{claim_tag, ClaimCircuit, ClaimInstance, ClaimKeys},
        Circuit, Instance,
    },
    keys::{FullViewingKey, SpendAuthorizingKey, SpendValidatingKey},
    note::{ExtractedNoteCommitment, Nullifier, Rho},
    primitives::redpallas::{self, SpendAuth},
    tree::MerklePath,
    value::NoteValue,
    Anchor, Note, Proof,
};
use pasta_curves::pallas;
use rand_core::CryptoRng;

pub const CLAIM_TEXT_PREFIX: &str = "zip311t1";
const MAGIC: &[u8; 4] = b"ZRCL";

/// The claim circuit's keys (nullifier public or private), each built once (a few seconds).
pub fn keys(expose_nf: bool) -> &'static ClaimKeys {
    static PUBLIC: std::sync::OnceLock<ClaimKeys> = std::sync::OnceLock::new();
    static PRIVATE: std::sync::OnceLock<ClaimKeys> = std::sync::OnceLock::new();
    if expose_nf { &PUBLIC } else { &PRIVATE }.get_or_init(|| ClaimKeys::build(expose_nf))
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Claim {
    pub coin_type: u32,
    pub pool: Pool,
    pub domain: Vec<u8>,
    pub msg: Vec<u8>,
    /// The snapshot's block height (0 for a published list).
    pub height: u32,
    pub anchor: [u8; 32],
    pub floor: u64,
    pub rk: [u8; 32],
    pub cmx: [u8; 32],
    pub tag: [u8; 32],
    /// The note's nullifier, when revealed (for a chain snapshot).
    pub nf: Option<[u8; 32]>,
    pub proof: Vec<u8>,
    pub sig: [u8; 64],
}

/// The domain as the field element the circuit hashes.
pub fn domain_field(domain: &[u8]) -> pallas::Base {
    let h = blake2b_simd::Params::new().hash_length(64).personal(b"ZIP311ClaimDom\0\0").hash(domain);
    pallas::Base::from_uniform_bytes(h.as_array())
}

impl Claim {
    fn body(&self) -> Vec<u8> {
        let mut v = MAGIC.to_vec();
        v.push(1);
        v.extend_from_slice(&self.coin_type.to_le_bytes());
        v.push(self.pool as u8);
        v.extend_from_slice(&(self.domain.len() as u16).to_le_bytes());
        v.extend_from_slice(&self.domain);
        v.extend_from_slice(&(self.msg.len() as u16).to_le_bytes());
        v.extend_from_slice(&self.msg);
        v.extend_from_slice(&self.height.to_le_bytes());
        v.extend_from_slice(&self.anchor);
        v.extend_from_slice(&self.floor.to_le_bytes());
        v.extend_from_slice(&self.rk);
        v.extend_from_slice(&self.cmx);
        v.extend_from_slice(&self.tag);
        match &self.nf {
            Some(nf) => {
                v.push(1);
                v.extend_from_slice(nf);
            }
            None => v.push(0),
        }
        v.extend_from_slice(&(self.proof.len() as u32).to_le_bytes());
        v.extend_from_slice(&self.proof);
        v
    }

    /// What the signature covers: everything but itself.
    pub fn digest(&self) -> [u8; 32] {
        let h = blake2b_simd::Params::new().hash_length(32).personal(&signing_personal(b"ZIP311Claim\0", self.coin_type)).hash(&self.body());
        h.as_bytes().try_into().unwrap()
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut v = self.body();
        v.extend_from_slice(&self.sig);
        v
    }

    pub fn from_bytes(b: &[u8]) -> Result<Self, Error> {
        let mut p = 0usize;
        let mut take = |n: usize| -> Result<&[u8], Error> {
            let s = b.get(p..p + n).ok_or(Error::BadClaim)?;
            p += n;
            Ok(s)
        };
        if take(4)? != MAGIC || take(1)? != [1] {
            return Err(Error::BadClaim);
        }
        let coin_type = u32::from_le_bytes(take(4)?.try_into().unwrap());
        let pool = match take(1)?[0] {
            0 => Pool::Orchard,
            1 => Pool::Ironwood,
            _ => return Err(Error::BadClaim),
        };
        let n = u16::from_le_bytes(take(2)?.try_into().unwrap()) as usize;
        let domain = take(n)?.to_vec();
        let n = u16::from_le_bytes(take(2)?.try_into().unwrap()) as usize;
        let msg = take(n)?.to_vec();
        let height = u32::from_le_bytes(take(4)?.try_into().unwrap());
        let anchor = take(32)?.try_into().unwrap();
        let floor = u64::from_le_bytes(take(8)?.try_into().unwrap());
        let rk = take(32)?.try_into().unwrap();
        let cmx = take(32)?.try_into().unwrap();
        let tag = take(32)?.try_into().unwrap();
        let nf = match take(1)?[0] {
            0 => None,
            1 => Some(take(32)?.try_into().unwrap()),
            _ => return Err(Error::BadClaim),
        };
        let len = u32::from_le_bytes(take(4)?.try_into().unwrap()) as usize;
        if len == 0 || len > 1 << 16 || floor == 0 {
            return Err(Error::BadClaim);
        }
        let proof = take(len)?.to_vec();
        let sig = take(64)?.try_into().unwrap();
        if p != b.len() {
            return Err(Error::BadClaim);
        }
        Ok(Claim { coin_type, pool, domain, msg, height, anchor, floor, rk, cmx, tag, nf, proof, sig })
    }

    pub fn to_text(&self) -> String {
        format!("{CLAIM_TEXT_PREFIX}{}", URL_SAFE_NO_PAD.encode(self.to_bytes()))
    }

    pub fn from_text(s: &str) -> Result<Self, Error> {
        let body = s.trim().strip_prefix(CLAIM_TEXT_PREFIX).ok_or(Error::BadClaim)?;
        let bytes = URL_SAFE_NO_PAD.decode(body).map_err(|_| Error::BadClaim)?;
        if URL_SAFE_NO_PAD.encode(&bytes) != body {
            return Err(Error::BadClaim);
        }
        Self::from_bytes(&bytes)
    }

    fn instance(&self) -> Result<ClaimInstance, Error> {
        let bad = || Error::BadClaim;
        let anchor = Option::<Anchor>::from(Anchor::from_bytes(self.anchor)).ok_or_else(bad)?;
        let rk = redpallas::VerificationKey::<SpendAuth>::try_from(self.rk).map_err(|_| bad())?;
        let cmx = Option::<ExtractedNoteCommitment>::from(ExtractedNoteCommitment::from_bytes(&self.cmx)).ok_or_else(bad)?;
        // A private nullifier: any value stands in (that circuit doesn't expose it).
        let nf = Option::<Nullifier>::from(Nullifier::from_bytes(&self.nf.unwrap_or([0; 32]))).ok_or_else(bad)?;
        let action = Instance::from_parts(anchor, screened::cv_net(self.floor).ok_or_else(bad)?, nf, rk, cmx, Flags::ENABLED).ok_or_else(bad)?;
        let tag = Option::<pallas::Base>::from(pallas::Base::from_repr(self.tag)).ok_or_else(bad)?;
        Ok(ClaimInstance { action, domain: domain_field(&self.domain), tag })
    }
}

/// The message of a payer tag: the payment's txid (in display order).
pub fn payer_tag_msg(txid: &[u8; 32]) -> Vec<u8> {
    format!("payer-tag:{}", crate::display_txid(txid)).into_bytes()
}

/// A payer tag: a claim, with no snapshot, on a note a payment spent (its nullifier is one of the
/// payment's, its anchor the payment's anchor, its message [`payer_tag_msg`]). Payments whose tags
/// in one domain differ were paid by different keys; equal tags, by one key. Checks it against
/// the payment's `txid`, `anchor` and spend `nullifiers`; returns the tag.
pub fn verify_payer_tag(claim: &Claim, domain: &[u8], txid: &[u8; 32], anchor: &[u8; 32], nullifiers: &[[u8; 32]]) -> Result<[u8; 32], Error> {
    let nf = claim.nf.ok_or(Error::BadClaim)?;
    if claim.height != 0 || claim.msg != payer_tag_msg(txid) || !nullifiers.contains(&nf) {
        return Err(Error::BadClaim);
    }
    verify(claim, domain, anchor)
}

/// The snapshot a verifier publishes is a list of note commitments (`cmx`, in order); its root
/// is the claim's anchor. Returns the path of `cmx` in it.
pub fn snapshot_path(set: &[[u8; 32]], cmx: &[u8; 32]) -> Result<MerklePath, Error> {
    let pos = set.iter().position(|c| c == cmx).ok_or(Error::NotInSet)?;
    Ok(screened::tree(set, pos)?.1)
}

/// Claims in `domain` with `note` (this wallet's, at `path` under the snapshot root), showing it
/// holds at least `floor`, bound to `msg` and the snapshot's `height` (0 for a list), revealing the note's nullifier if `reveal_nf` (for a
/// chain snapshot). Signed with `ask`.
#[allow(clippy::too_many_arguments)]
pub fn prove(
    coin_type: u32,
    pool: Pool,
    fvk: &FullViewingKey,
    ask: &SpendAuthorizingKey,
    note: Note,
    path: MerklePath,
    floor: u64,
    domain: &[u8],
    msg: &[u8],
    height: u32,
    reveal_nf: bool,
    rng: impl CryptoRng,
) -> Result<Claim, Error> {
    let v = note.value().inner();
    if floor == 0 || floor > v || domain.len() > u16::MAX as usize || msg.len() > u16::MAX as usize {
        return Err(Error::BadClaim);
    }
    prove_inner(coin_type, pool, fvk, ask, note, path, floor, v - floor, None, domain, msg, height, reveal_nf, rng)
}

/// A dishonest prover, for tests: claims `floor` with the hidden output holding `out_value`
/// (honestly `v - floor`), and the tag `tag` (honestly the key's). Signed with the real key, so
/// only the proof can catch it.
#[doc(hidden)]
#[allow(clippy::too_many_arguments)]
pub fn __prove_dishonest_for_tests(
    fvk: &FullViewingKey,
    ask: &SpendAuthorizingKey,
    note: Note,
    path: MerklePath,
    floor: u64,
    out_value: u64,
    tag: Option<pallas::Base>,
    domain: &[u8],
    rng: impl CryptoRng,
) -> Result<Claim, Error> {
    prove_inner(crate::COIN_TYPE_TESTNET, Pool::Ironwood, fvk, ask, note, path, floor, out_value, tag, domain, b"", 0, false, rng)
}

#[allow(clippy::too_many_arguments)]
fn prove_inner(
    coin_type: u32,
    pool: Pool,
    fvk: &FullViewingKey,
    ask: &SpendAuthorizingKey,
    note: Note,
    path: MerklePath,
    floor: u64,
    out_value: u64,
    tag: Option<pallas::Base>,
    domain: &[u8],
    msg: &[u8],
    height: u32,
    reveal_nf: bool,
    mut rng: impl CryptoRng,
) -> Result<Claim, Error> {
    let cm: ExtractedNoteCommitment = note.commitment().into();
    let anchor = path.root(cm);
    let alpha = crate::random_scalar(&mut rng);
    let rk = SpendValidatingKey::from(fvk.clone()).randomize(&alpha);
    let nf = note.nullifier(fvk);
    let spend = SpendInfo::new(fvk.clone(), note, path).ok_or(Error::NoteNotOwned)?;
    let rho = Option::<Rho>::from(Rho::from_bytes(&nf.to_bytes())).ok_or(Error::Proving)?;
    let out = note_to_throwaway(rho, NoteValue::from_raw(out_value), pool_note_version(pool), &mut rng);
    let cmx: ExtractedNoteCommitment = out.commitment().into();
    let d = domain_field(domain);
    let mut claim = Claim {
        coin_type,
        pool,
        domain: domain.to_vec(),
        msg: msg.to_vec(),
        height,
        anchor: anchor.to_bytes(),
        floor,
        rk: (&rk).into(),
        cmx: cmx.to_bytes(),
        tag: tag.unwrap_or_else(|| claim_tag(fvk, d)).to_repr(),
        nf: reveal_nf.then(|| nf.to_bytes()),
        proof: vec![],
        sig: [0; 64],
    };
    let circuit = Circuit::from_action_context(spend, out, alpha, zero_trapdoor(), crate::RECEIPT_CIRCUIT).ok_or(Error::Proving)?;
    let circuit = ClaimCircuit::new(circuit, d, reveal_nf).ok_or(Error::Proving)?;
    let proof: Proof = keys(reveal_nf).create(&[circuit], &[claim.instance()?], &mut rng).map_err(|_| Error::Proving)?;
    claim.proof = proof.as_ref().to_vec();
    claim.sig = (&ask.randomize(&alpha).sign(&mut rng, &claim.digest())).into();
    Ok(claim)
}

/// Checks a claim for `domain` against the verifier's snapshot `anchor`, holding at least the
/// claim's floor. Returns the tag the verifier keeps (one claim per tag). Against a chain
/// snapshot, also check the claim's `nf` is revealed and wasn't published up to the snapshot.
pub fn verify(claim: &Claim, domain: &[u8], anchor: &[u8; 32]) -> Result<[u8; 32], Error> {
    if claim.domain != domain || &claim.anchor != anchor {
        return Err(Error::BadClaim);
    }
    let rk = redpallas::VerificationKey::<SpendAuth>::try_from(claim.rk).map_err(|_| Error::BadClaim)?;
    rk.verify(&claim.digest(), &redpallas::Signature::<SpendAuth>::from(claim.sig)).map_err(|_| Error::BadClaim)?;
    keys(claim.nf.is_some()).verify(&Proof::new(claim.proof.clone()), &[claim.instance()?]).map_err(|_| Error::BadClaim)?;
    Ok(claim.tag)
}
