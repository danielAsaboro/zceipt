//! Policy proofs: a receipt was signed by a published threshold key (a treasury whose spend key is
//! split t-of-n with FROST), without showing which holders signed.
//!
//! A threshold key's holders publish its verifiable-secret-sharing commitment `C_0..C_{t-1}`
//! (the commitments to the sharing polynomial's coefficients; `C_0` is the key's `ak`) and how many
//! holders `n` there are. A receipt signed by any `t` of them carries `rk = C_0 + [alpha]G` for
//! each spend. The proof is a Schnorr proof of knowledge of each spend's `alpha` for `rk - C_0`,
//! bound to the receipt's signing digest, the commitment and a verifier's challenge, so the
//! verifier learns "this payment was authorized under that t-of-n key". The FROST signature
//! itself is an ordinary SpendAuthSig, so nothing shows which `t` signed.
//!
//! What the commitment shows: the key is shared with a polynomial of degree `t - 1`, so any `t`
//! of the `n` share holders, and no fewer, can sign (each holder checks its own share against
//! it). It doesn't show that whoever dealt the shares (with a trusted dealer) discarded the
//! whole key; distributed key generation avoids having one.
//!
//! ```text
//! policy := "ZRCP" | version:u8 = 1 | coinType:u32le | msgLen:u16le | msg | digest[32]
//!         | n:u16le | t:u8 | { C_j[32] }^t | nSpends:u8 | { R[32] | s[32] }^nSpends
//! text   := "zip311p1" || base64url_nopad(policy)
//! c      := ToScalar(BLAKE2b-512("ZIP311Policy" || coinType, policy without the s values || every rk))
//! check  := [s_i]G == R_i + [c](rk_i - C_0)
//! ```

use crate::link::{point, scalar, spend_auth_base};
use crate::{signing_digest, signing_personal, Error, PreparedReceipt, Receipt};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use group::{ff::FromUniformBytes, Group, GroupEncoding};
use pasta_curves::pallas;
use rand_core::CryptoRng;

pub const POLICY_TEXT_PREFIX: &str = "zip311p1";
const MAGIC: &[u8; 4] = b"ZRCP";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PolicyProof {
    pub coin_type: u32,
    pub msg: Vec<u8>,
    /// The receipt's signing digest.
    pub receipt: [u8; 32],
    /// How many holders share the key.
    pub holders: u16,
    /// The sharing commitment `C_0..C_{t-1}`; `C_0` is the key's `ak`, and `t` its threshold.
    pub commitment: Vec<[u8; 32]>,
    /// One `(R, s)` per spend of the receipt.
    pub links: Vec<([u8; 32], [u8; 32])>,
}

impl PolicyProof {
    /// The threshold: how many of the holders must sign.
    pub fn threshold(&self) -> usize {
        self.commitment.len()
    }

    fn head(&self) -> Vec<u8> {
        let mut v = MAGIC.to_vec();
        v.push(1);
        v.extend_from_slice(&self.coin_type.to_le_bytes());
        v.extend_from_slice(&(self.msg.len() as u16).to_le_bytes());
        v.extend_from_slice(&self.msg);
        v.extend_from_slice(&self.receipt);
        v.extend_from_slice(&self.holders.to_le_bytes());
        v.push(self.commitment.len() as u8);
        for c in &self.commitment {
            v.extend_from_slice(c);
        }
        v.push(self.links.len() as u8);
        v
    }

    fn challenge(&self, rks: &[[u8; 32]]) -> pallas::Scalar {
        let mut h = blake2b_simd::Params::new().hash_length(64).personal(&signing_personal(b"ZIP311Policy", self.coin_type)).to_state();
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
            let s = b.get(p..p + n).ok_or(Error::BadPolicy)?;
            p += n;
            Ok(s)
        };
        if take(4)? != MAGIC || take(1)? != [1] {
            return Err(Error::BadPolicy);
        }
        let coin_type = u32::from_le_bytes(take(4)?.try_into().unwrap());
        let n = u16::from_le_bytes(take(2)?.try_into().unwrap()) as usize;
        let msg = take(n)?.to_vec();
        let receipt = take(32)?.try_into().unwrap();
        let holders = u16::from_le_bytes(take(2)?.try_into().unwrap());
        let t = take(1)?[0] as usize;
        let commitment = (0..t).map(|_| Ok(take(32)?.try_into().unwrap())).collect::<Result<Vec<[u8; 32]>, Error>>()?;
        let ns = take(1)?[0] as usize;
        let links = (0..ns).map(|_| Ok((take(32)?.try_into().unwrap(), take(32)?.try_into().unwrap()))).collect::<Result<Vec<_>, Error>>()?;
        if p != b.len() || t == 0 || holders < t as u16 || ns == 0 {
            return Err(Error::BadPolicy);
        }
        for (_, s) in &links {
            scalar(s)?;
        }
        Ok(PolicyProof { coin_type, msg, receipt, holders, commitment, links })
    }

    pub fn to_text(&self) -> String {
        format!("{POLICY_TEXT_PREFIX}{}", URL_SAFE_NO_PAD.encode(self.to_bytes()))
    }

    pub fn from_text(s: &str) -> Result<Self, Error> {
        let body = s.trim().strip_prefix(POLICY_TEXT_PREFIX).ok_or(Error::BadPolicy)?;
        let bytes = URL_SAFE_NO_PAD.decode(body).map_err(|_| Error::BadPolicy)?;
        if URL_SAFE_NO_PAD.encode(&bytes) != body {
            return Err(Error::BadPolicy);
        }
        Self::from_bytes(&bytes)
    }
}

/// Proves `prepared`'s spends are under the threshold key with sharing `commitment` (`C_0` its
/// `ak`) held by `holders`, bound to `msg`. Made by the coordinator, who holds the `alpha`s.
pub fn prove(prepared: &PreparedReceipt, commitment: Vec<[u8; 32]>, holders: u16, msg: &[u8], mut rng: impl CryptoRng) -> Result<PolicyProof, Error> {
    let u = prepared.unsigned();
    if commitment.is_empty() || commitment.len() > u8::MAX as usize || holders < commitment.len() as u16 || msg.len() > u16::MAX as usize {
        return Err(Error::BadPolicy);
    }
    let g = spend_auth_base();
    let ak = point(&commitment[0])?;
    for (s, a) in u.spends.iter().zip(prepared.alphas()) {
        if point(&s.rk)? != ak + g * a {
            return Err(Error::BadPolicy);
        }
    }
    let rks: Vec<[u8; 32]> = u.spends.iter().map(|s| s.rk).collect();
    let nonces: Vec<pallas::Scalar> = rks.iter().map(|_| crate::random_scalar(&mut rng)).collect();
    let mut p = PolicyProof {
        coin_type: u.coin_type,
        msg: msg.to_vec(),
        receipt: signing_digest(u),
        holders,
        commitment,
        links: nonces.iter().map(|k| ((g * k).to_bytes(), [0; 32])).collect(),
    };
    let c = p.challenge(&rks);
    for (i, (k, a)) in nonces.iter().zip(prepared.alphas()).enumerate() {
        p.links[i].1 = group::ff::PrimeField::to_repr(&(*k + c * a));
    }
    Ok(p)
}

/// Checks a policy proof for `receipt` (verify the receipt itself as usual). Returns `(t, n)` **as the
/// prover stated them**: only `C_0` is tied to the receipt. Use [`verify_pinned`] to mean "t-of-n".
pub fn verify(p: &PolicyProof, receipt: &Receipt) -> Result<(usize, u16), Error> {
    let u = &receipt.unsigned;
    if u.coin_type != p.coin_type || signing_digest(u) != p.receipt || p.links.len() != u.spends.len() {
        return Err(Error::BadPolicy);
    }
    for c in &p.commitment {
        if bool::from(point(c)?.is_identity()) {
            return Err(Error::BadPolicy);
        }
    }
    let rks: Vec<[u8; 32]> = u.spends.iter().map(|s| s.rk).collect();
    let c = p.challenge(&rks);
    let g = spend_auth_base();
    let ak = point(&p.commitment[0])?;
    for ((r, s), rk) in p.links.iter().zip(&rks) {
        let big_r = point(r)?;
        if bool::from(big_r.is_identity()) || g * scalar(s)? != big_r + (point(rk)? - ak) * c {
            return Err(Error::BadPolicy);
        }
    }
    Ok((p.threshold(), p.holders))
}

/// Like [`verify`], and the proof's commitment and holder count must be exactly the published ones.
/// Only this makes `(t, n)` mean anything: [`verify`] alone returns numbers the prover chose.
pub fn verify_pinned(p: &PolicyProof, receipt: &Receipt, commitment: &[[u8; 32]], holders: u16) -> Result<(usize, u16), Error> {
    if p.commitment != commitment || p.holders != holders {
        return Err(Error::BadPolicy);
    }
    verify(p, receipt)
}

/// Each holder's verifying share under the commitment, for holders `1..=n` (FROST's default
/// identifiers): `Y_i = sum_j [i^j] C_j`. A holder checks its share's public key against this.
pub fn verifying_shares(commitment: &[[u8; 32]], n: u16) -> Result<Vec<[u8; 32]>, Error> {
    let cs = commitment.iter().map(point).collect::<Result<Vec<_>, _>>()?;
    Ok((1..=n as u64)
        .map(|i| {
            let x = pallas::Scalar::from(i);
            let mut pow = pallas::Scalar::from(1);
            let mut y = pallas::Point::identity();
            for c in &cs {
                y += *c * pow;
                pow *= x;
            }
            y.to_bytes()
        })
        .collect())
}
