//! Key-set proofs: a receipt was signed by one of a published set of spend keys (a department's,
//! a program's signers), without saying which.
//!
//! Each spend carries `rk = ak + [alpha]G`. For a published set `K_1..K_n` of `ak`s, the prover
//! shows it knows `alpha` with `rk - K_j = [alpha]G` for one `j`, by a one-of-many Schnorr proof
//! (Cramer-Damgård-Schoenmakers): for every `j` a pair `(c_j, s_j)`, with
//! `R_j = [s_j]G - [c_j](rk - K_j)`, and the `c_j` adding up to the hash of the statement and all
//! the `R_j`. The prover can answer for `j` only where it knows the discrete log, and the
//! verifier can't tell which `j` that was.
//!
//! What it shows: whoever made it knows how `rk` relates to one listed key: it holds that key, or
//! knows its relation to it (as for any key-relation proof here). Which key, and every other
//! payment, stay hidden. A set of one key is a proof that the receipt was signed under that key.
//!
//! ```text
//! keyset := "ZRCM" | version:u8 = 1 | coinType:u32le | msgLen:u16le | msg | digest[32]
//!         | n:u16le | { K_j[32] }^n | nSpends:u8 | { { c_j[32] | s_j[32] }^n }^nSpends
//! text   := "zip311m1" || base64url_nopad(keyset)
//! c      := ToScalar(BLAKE2b-512("ZIP311KeySet" || coinType, keyset without the (c, s) pairs
//!                    || every rk || every R_j, spend by spend))
//! check  := for each spend, sum_j c_j == c
//! ```

use crate::link::{point, scalar, spend_auth_base};
use crate::{signing_digest, signing_personal, Error, PreparedReceipt, Receipt};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use group::{ff::Field, ff::FromUniformBytes, ff::PrimeField, GroupEncoding};
use pasta_curves::pallas;
use rand_core::CryptoRng;

pub const KEYSET_TEXT_PREFIX: &str = "zip311m1";
const MAGIC: &[u8; 4] = b"ZRCM";
const MAX_KEYS: usize = 1024;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeySetProof {
    pub coin_type: u32,
    pub msg: Vec<u8>,
    /// The receipt's signing digest.
    pub receipt: [u8; 32],
    /// The published keys (`ak`s).
    pub keys: Vec<[u8; 32]>,
    /// Per spend, one `(c_j, s_j)` per key.
    pub spends: Vec<Vec<([u8; 32], [u8; 32])>>,
}

impl KeySetProof {
    fn head(&self, n_spends: usize) -> Vec<u8> {
        let mut v = MAGIC.to_vec();
        v.push(1);
        v.extend_from_slice(&self.coin_type.to_le_bytes());
        v.extend_from_slice(&(self.msg.len() as u16).to_le_bytes());
        v.extend_from_slice(&self.msg);
        v.extend_from_slice(&self.receipt);
        v.extend_from_slice(&(self.keys.len() as u16).to_le_bytes());
        for k in &self.keys {
            v.extend_from_slice(k);
        }
        v.push(n_spends as u8);
        v
    }

    fn challenge(&self, rks: &[[u8; 32]], commitments: &[Vec<pallas::Point>]) -> pallas::Scalar {
        let mut h = blake2b_simd::Params::new().hash_length(64).personal(&signing_personal(b"ZIP311KeySet", self.coin_type)).to_state();
        h.update(&self.head(rks.len()));
        for (rk, rs) in rks.iter().zip(commitments) {
            h.update(rk);
            for r in rs {
                h.update(&r.to_bytes());
            }
        }
        pallas::Scalar::from_uniform_bytes(h.finalize().as_array())
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut v = self.head(self.spends.len());
        for s in &self.spends {
            for (c, z) in s {
                v.extend_from_slice(c);
                v.extend_from_slice(z);
            }
        }
        v
    }

    pub fn from_bytes(b: &[u8]) -> Result<Self, Error> {
        let mut p = 0usize;
        let mut take = |n: usize| -> Result<&[u8], Error> {
            let s = b.get(p..p + n).ok_or(Error::BadKeySet)?;
            p += n;
            Ok(s)
        };
        if take(4)? != MAGIC || take(1)? != [1] {
            return Err(Error::BadKeySet);
        }
        let coin_type = u32::from_le_bytes(take(4)?.try_into().unwrap());
        let n = u16::from_le_bytes(take(2)?.try_into().unwrap()) as usize;
        let msg = take(n)?.to_vec();
        let receipt = take(32)?.try_into().unwrap();
        let n = u16::from_le_bytes(take(2)?.try_into().unwrap()) as usize;
        if n == 0 || n > MAX_KEYS {
            return Err(Error::BadKeySet);
        }
        let keys = (0..n).map(|_| Ok(take(32)?.try_into().unwrap())).collect::<Result<Vec<[u8; 32]>, Error>>()?;
        let ns = take(1)?[0] as usize;
        let mut spends = Vec::with_capacity(ns);
        for _ in 0..ns {
            spends.push((0..n).map(|_| Ok((take(32)?.try_into().unwrap(), take(32)?.try_into().unwrap()))).collect::<Result<Vec<_>, Error>>()?);
        }
        if p != b.len() || ns == 0 {
            return Err(Error::BadKeySet);
        }
        for (c, s) in spends.iter().flatten() {
            scalar(c)?;
            scalar(s)?;
        }
        Ok(KeySetProof { coin_type, msg, receipt, keys, spends })
    }

    pub fn to_text(&self) -> String {
        format!("{KEYSET_TEXT_PREFIX}{}", URL_SAFE_NO_PAD.encode(self.to_bytes()))
    }

    pub fn from_text(s: &str) -> Result<Self, Error> {
        let body = s.trim().strip_prefix(KEYSET_TEXT_PREFIX).ok_or(Error::BadKeySet)?;
        let bytes = URL_SAFE_NO_PAD.decode(body).map_err(|_| Error::BadKeySet)?;
        if URL_SAFE_NO_PAD.encode(&bytes) != body {
            return Err(Error::BadKeySet);
        }
        Self::from_bytes(&bytes)
    }
}

/// Proves every spend of `prepared` is under one of `keys` (the prover finds which from the
/// `alpha`s), bound to `msg`.
pub fn prove(prepared: &PreparedReceipt, keys: Vec<[u8; 32]>, msg: &[u8], mut rng: impl CryptoRng) -> Result<KeySetProof, Error> {
    let u = prepared.unsigned();
    if keys.is_empty() || keys.len() > MAX_KEYS || msg.len() > u16::MAX as usize || u.spends.len() > u8::MAX as usize {
        return Err(Error::BadKeySet);
    }
    let g = spend_auth_base();
    let ks = keys.iter().map(point).collect::<Result<Vec<_>, _>>()?;
    let rks: Vec<[u8; 32]> = u.spends.iter().map(|s| s.rk).collect();
    let mut proof = KeySetProof { coin_type: u.coin_type, msg: msg.to_vec(), receipt: signing_digest(u), keys, spends: vec![] };
    // Per spend: the real index, its nonce, and the simulated (c_j, s_j) for the others.
    let mut plans = Vec::with_capacity(rks.len());
    let mut commitments = Vec::with_capacity(rks.len());
    for (rk, alpha) in rks.iter().zip(prepared.alphas()) {
        let rk = point(rk)?;
        let real = ks.iter().position(|k| rk == *k + g * alpha).ok_or(Error::BadKeySet)?;
        let k = crate::random_scalar(&mut rng);
        let mut cs = vec![pallas::Scalar::ZERO; ks.len()];
        let mut ss = vec![pallas::Scalar::ZERO; ks.len()];
        let mut rs = Vec::with_capacity(ks.len());
        for (j, key) in ks.iter().enumerate() {
            if j == real {
                rs.push(g * k);
            } else {
                cs[j] = crate::random_scalar(&mut rng);
                ss[j] = crate::random_scalar(&mut rng);
                rs.push(g * ss[j] - (rk - key) * cs[j]);
            }
        }
        plans.push((real, k, *alpha, cs, ss));
        commitments.push(rs);
    }
    let c = proof.challenge(&rks, &commitments);
    for (real, k, alpha, mut cs, mut ss) in plans {
        let others: pallas::Scalar = cs.iter().enumerate().filter(|(j, _)| *j != real).map(|(_, c)| *c).sum();
        cs[real] = c - others;
        ss[real] = k + cs[real] * alpha;
        proof.spends.push(cs.iter().zip(&ss).map(|(c, s)| (c.to_repr(), s.to_repr())).collect());
    }
    Ok(proof)
}

/// Checks a key-set proof for `receipt` (verify the receipt itself as usual). Returns how many
/// keys the set holds.
pub fn verify(p: &KeySetProof, receipt: &Receipt) -> Result<usize, Error> {
    let u = &receipt.unsigned;
    if u.coin_type != p.coin_type || signing_digest(u) != p.receipt || p.spends.len() != u.spends.len() {
        return Err(Error::BadKeySet);
    }
    let g = spend_auth_base();
    let ks = p.keys.iter().map(point).collect::<Result<Vec<_>, _>>()?;
    let rks: Vec<[u8; 32]> = u.spends.iter().map(|s| s.rk).collect();
    let mut commitments = Vec::with_capacity(rks.len());
    let mut sums = Vec::with_capacity(rks.len());
    for (rk, pairs) in rks.iter().zip(&p.spends) {
        if pairs.len() != ks.len() {
            return Err(Error::BadKeySet);
        }
        let rk = point(rk)?;
        let mut rs = Vec::with_capacity(ks.len());
        let mut sum = pallas::Scalar::ZERO;
        for ((c, s), key) in pairs.iter().zip(&ks) {
            let (c, s) = (scalar(c)?, scalar(s)?);
            rs.push(g * s - (rk - key) * c);
            sum += c;
        }
        commitments.push(rs);
        sums.push(sum);
    }
    let c = p.challenge(&rks, &commitments);
    if sums.iter().any(|s| *s != c) {
        return Err(Error::BadKeySet);
    }
    Ok(ks.len())
}
