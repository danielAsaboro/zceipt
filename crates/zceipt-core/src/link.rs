//! Same-payer proofs: that several receipts were signed with one spend authorizing key, without
//! revealing the key, its validating key `ak`, or any other payment of the wallet.
//!
//! Every spend in a receipt carries `rk = ak + [alpha]G` (G the Orchard SpendAuthSig base) with a
//! fresh `alpha`, which is why receipts from one wallet look unrelated. For two spends of one
//! key, `rk_i - rk_0 = [alpha_i - alpha_0]G`, a point whose discrete log the prover knows. The
//! proof is a Schnorr proof of knowledge of each `delta_i = alpha_i - alpha_0` for `rk_i - rk_0`,
//! made non-interactive by hashing a transcript that binds the receipts (by signing digest), the
//! `rk`s, a verifier's challenge in `msg`, and the commitments.
//!
//! What it proves: whoever made it knows how every listed `rk` relates to the first. For keys of
//! different holders nobody knows that relation (it is the difference of their secret keys), so
//! the receipts share one key, or keys whose holders pooled them. It reveals the link between
//! these receipts only, and needs each spend's `alpha`: make it when signing, while the prepared
//! receipts are still at hand (`zceipt sign --link`).
//!
//! ```text
//! link    := "ZRCK" | version:u8 = 1 | coinType:u32le | msgLen:u16le | msg
//!          | nReceipts:u8 | { digest[32] }^nReceipts | nLinks:u16le | { R[32] | s[32] }^nLinks
//! text    := "zip311k1" || base64url_nopad(link)
//! c       := ToScalar(BLAKE2b-512("ZIP311Linked" || coinType, link without the s values
//!                                 || { rk }^all spends, in receipt then spend order))
//! check   := [s_i]G == R_i + [c](rk_i - rk_0) for i = 1..nLinks, nLinks = (all spends) - 1
//! ```

use crate::{signing_digest, signing_personal, Error, PreparedReceipt, Receipt, UnsignedReceipt};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use group::{ff::FromUniformBytes, Group, GroupEncoding};
use pasta_curves::{arithmetic::CurveExt, pallas};
use rand_core::CryptoRng;

/// Prefix of the text encoding of a same-payer proof.
pub const LINK_TEXT_PREFIX: &str = "zip311k1";
const MAGIC: &[u8; 4] = b"ZRCK";
const MAX_RECEIPTS: usize = 64;

/// A same-payer proof over receipts listed by their signing digests, in order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LinkProof {
    pub coin_type: u32,
    /// Signed context, usually a verifier's `challenge:<hex>`.
    pub msg: Vec<u8>,
    /// The receipts' signing digests ([`signing_digest`]), in the order the `rk`s are taken.
    pub receipts: Vec<[u8; 32]>,
    /// One `(R, s)` per spend after the first.
    pub links: Vec<([u8; 32], [u8; 32])>,
}

/// The Orchard SpendAuthSig base, `GroupHash("z.cash:Orchard", "G")` (protocol §5.4.7.1).
pub fn spend_auth_base() -> pallas::Point {
    pallas::Point::hash_to_curve("z.cash:Orchard")(b"G")
}

pub(crate) fn point(b: &[u8; 32]) -> Result<pallas::Point, Error> {
    Option::from(pallas::Point::from_bytes(b)).ok_or(Error::BadLink)
}

/// A point that is not the identity. The identity's encoding is 32 zero bytes and decodes like any
/// point; as a verifier's or session key it would have a known discrete log (0), so anyone could
/// make the "I know the log of V" half of a proof.
pub(crate) fn nonidentity_point(b: &[u8; 32]) -> Result<pallas::Point, Error> {
    let p = point(b)?;
    if bool::from(group::Group::is_identity(&p)) {
        return Err(Error::BadLink);
    }
    Ok(p)
}

pub(crate) fn scalar(b: &[u8; 32]) -> Result<pallas::Scalar, Error> {
    Option::from(<pallas::Scalar as group::ff::PrimeField>::from_repr(*b)).ok_or(Error::BadLink)
}

impl LinkProof {
    fn head(&self) -> Vec<u8> {
        let mut v = MAGIC.to_vec();
        v.push(1);
        v.extend_from_slice(&self.coin_type.to_le_bytes());
        v.extend_from_slice(&(self.msg.len() as u16).to_le_bytes());
        v.extend_from_slice(&self.msg);
        v.push(self.receipts.len() as u8);
        for d in &self.receipts {
            v.extend_from_slice(d);
        }
        v.extend_from_slice(&(self.links.len() as u16).to_le_bytes());
        v
    }

    fn challenge(&self, rks: &[[u8; 32]]) -> pallas::Scalar {
        let mut h = blake2b_simd::Params::new().hash_length(64).personal(&signing_personal(b"ZIP311Linked", self.coin_type)).to_state();
        h.update(&self.head());
        for (r, _) in &self.links {
            h.update(r);
        }
        for rk in rks {
            h.update(rk);
        }
        pallas::Scalar::from_uniform_bytes(h.finalize().as_array())
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut v = self.head();
        for (r, s) in &self.links {
            v.extend_from_slice(r);
            v.extend_from_slice(s);
        }
        v
    }

    pub fn from_bytes(b: &[u8]) -> Result<Self, Error> {
        let mut p = 0usize;
        let mut take = |n: usize| -> Result<&[u8], Error> {
            let s = b.get(p..p + n).ok_or(Error::BadLink)?;
            p += n;
            Ok(s)
        };
        if take(4)? != MAGIC || take(1)?[0] != 1 {
            return Err(Error::BadLink);
        }
        let coin_type = u32::from_le_bytes(take(4)?.try_into().unwrap());
        let n = u16::from_le_bytes(take(2)?.try_into().unwrap()) as usize;
        let msg = take(n)?.to_vec();
        let nr = take(1)?[0] as usize;
        if nr == 0 || nr > MAX_RECEIPTS {
            return Err(Error::BadLink);
        }
        let receipts = (0..nr).map(|_| Ok(take(32)?.try_into().unwrap())).collect::<Result<Vec<[u8; 32]>, Error>>()?;
        let nl = u16::from_le_bytes(take(2)?.try_into().unwrap()) as usize;
        let mut links = Vec::with_capacity(nl.min(1024));
        for _ in 0..nl {
            links.push((take(32)?.try_into().unwrap(), take(32)?.try_into().unwrap()));
        }
        if p != b.len() {
            return Err(Error::BadLink);
        }
        let proof = LinkProof { coin_type, msg, receipts, links };
        // One encoding only: every scalar canonical.
        for (_, s) in &proof.links {
            scalar(s)?;
        }
        Ok(proof)
    }

    pub fn to_text(&self) -> String {
        format!("{LINK_TEXT_PREFIX}{}", URL_SAFE_NO_PAD.encode(self.to_bytes()))
    }

    pub fn from_text(s: &str) -> Result<Self, Error> {
        let body = s.trim().strip_prefix(LINK_TEXT_PREFIX).ok_or(Error::BadLink)?;
        let bytes = URL_SAFE_NO_PAD.decode(body).map_err(|_| Error::BadLink)?;
        if URL_SAFE_NO_PAD.encode(&bytes) != body {
            return Err(Error::BadLink);
        }
        Self::from_bytes(&bytes)
    }
}

fn rks_of<'a>(unsigned: impl Iterator<Item = &'a UnsignedReceipt>) -> Vec<[u8; 32]> {
    unsigned.flat_map(|u| u.spends.iter().map(|s| s.rk)).collect()
}

/// Proves that `prepared` (proofs made, `alpha`s known) were all made for one spend key, bound to
/// `msg`. Prove it before the `alpha`s are discarded, with the receipts' final messages.
pub fn prove(prepared: &[&PreparedReceipt], msg: &[u8], mut rng: impl CryptoRng) -> Result<LinkProof, Error> {
    if prepared.is_empty() || prepared.len() > MAX_RECEIPTS || msg.len() > u16::MAX as usize {
        return Err(Error::BadLink);
    }
    let coin_type = prepared[0].unsigned().coin_type;
    if prepared.iter().any(|p| p.unsigned().coin_type != coin_type) {
        return Err(Error::BadLink);
    }
    let alphas: Vec<pallas::Scalar> = prepared.iter().flat_map(|p| p.alphas().iter().copied()).collect();
    let rks = rks_of(prepared.iter().map(|p| p.unsigned()));
    let g = spend_auth_base();
    // Each rk must be ak + [alpha]G for one ak: refuse to prove what isn't so.
    let ak = point(&rks[0])? - g * alphas[0];
    for (rk, a) in rks.iter().zip(&alphas) {
        if point(rk)? != ak + g * a {
            return Err(Error::BadLink);
        }
    }
    let nonces: Vec<pallas::Scalar> = (1..rks.len()).map(|_| crate::random_scalar(&mut rng)).collect();
    let mut proof = LinkProof {
        coin_type,
        msg: msg.to_vec(),
        receipts: prepared.iter().map(|p| signing_digest(p.unsigned())).collect(),
        links: nonces.iter().map(|k| ((g * k).to_bytes(), [0; 32])).collect(),
    };
    let c = proof.challenge(&rks);
    for (i, k) in nonces.iter().enumerate() {
        let delta = alphas[i + 1] - alphas[0];
        proof.links[i].1 = group::ff::PrimeField::to_repr(&(*k + c * delta));
    }
    Ok(proof)
}

/// Checks a same-payer proof against the receipts it names, given in the same order. It checks
/// only the link: verify each receipt itself (against the chain) as usual.
pub fn verify(proof: &LinkProof, receipts: &[&Receipt]) -> Result<(), Error> {
    if receipts.len() != proof.receipts.len() || receipts.iter().any(|r| r.unsigned.coin_type != proof.coin_type) {
        return Err(Error::BadLink);
    }
    for (r, d) in receipts.iter().zip(&proof.receipts) {
        if signing_digest(&r.unsigned) != *d {
            return Err(Error::BadLink);
        }
    }
    let rks = rks_of(receipts.iter().map(|r| &r.unsigned));
    if proof.links.len() + 1 != rks.len() {
        return Err(Error::BadLink);
    }
    let c = proof.challenge(&rks);
    let g = spend_auth_base();
    let rk0 = point(&rks[0])?;
    for ((r, s), rk) in proof.links.iter().zip(&rks[1..]) {
        let (big_r, s) = (point(r)?, scalar(s)?);
        if bool::from(big_r.is_identity()) || g * s != big_r + (point(rk)? - rk0) * c {
            return Err(Error::BadLink);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_identity_is_not_a_key() {
        // The all-zero encoding decodes as the identity; keys a verifier or delegator is given must not be it.
        assert!(point(&[0; 32]).is_ok());
        assert!(nonidentity_point(&[0; 32]).is_err());
        assert!(nonidentity_point(&spend_auth_base().to_bytes()).is_ok());
    }
}
