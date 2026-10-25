//! Delegated receipts: the spend key authorizes a session key, under a policy, to issue receipts
//! for its payments, so an agent or a back office can answer for payments without the spend key.
//!
//! The spend key signs a certificate under `rk_c = ak + [alpha_c]G`: the session key `S`, a most
//! a receipt may show paid, the last block a payment may be in, and optionally the only addresses
//! it may show paid. The delegate holds the viewing key (to make the Action proofs), the session
//! secret `s` and `alpha_c`. For each spend of a payment, it proves `rk_i - rk_c = [alpha_i -
//! alpha_c]G` (the same `ak`: a Schnorr proof, as in same-payer proofs) and signs the receipt with
//! `S`. The verifier checks the certificate, the links, the session signature and the policy
//! against what the receipt discloses, then the receipt's proofs as usual.
//!
//! What it proves: the spend key's holder authorized `S` under this policy, the payment's spends
//! are under that spend key, and `S` vouched for this receipt within the policy. It doesn't stop
//! the delegate from not answering; it can't spend. Every receipt under one certificate carries
//! it, so they are linkable to each other (not to the wallet's other payments).
//!
//! ```text
//! cert      := "ZRCG" | version:u8 = 1 | coinType:u32le | S[32] | maxZats:u64le | untilHeight:u32le
//!            | nPayees:u8 | { address[43] }^nPayees | rk_c[32] | sig_c[64]
//! certSig   := RedPallas SpendAuthSig by rk_c over BLAKE2b-256("ZIP311Deleg\0" || coinType, cert without sig_c)
//! delegated := "ZRCA" | version:u8 = 1 | certLen:u16le | cert | n:u8 | { R[32] | z[32] }^n
//!            | sessionSig[64] | receipt (zip311r1 bytes, every signature 64 zero bytes)
//! c         := ToScalar(BLAKE2b-512("ZIP311DLink\0" || coinType, digest || rk_c || every rk || every R))
//! link      := [z_i]G == R_i + [c](rk_i - rk_c)
//! sessionSig:= Schnorr by S over BLAKE2b-512("ZIP311DSess\0" || coinType, digest || cert || links)
//! text      := "zip311a1" || base64url_nopad(delegated)
//! ```

use crate::link::{point, scalar, spend_auth_base};
use crate::{random_scalar, signing_digest, signing_personal, Error, PreparedReceipt, Receipt, VerifiedReceipt};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use group::{ff::FromUniformBytes, ff::PrimeField, GroupEncoding};
use orchard::{
    keys::SpendAuthorizingKey,
    primitives::redpallas::{self, SpendAuth},
};
use pasta_curves::pallas;
use rand_core::CryptoRng;

pub const DELEGATED_TEXT_PREFIX: &str = "zip311a1";
pub const CERT_TEXT_PREFIX: &str = "zip311g1";
const CERT_MAGIC: &[u8; 4] = b"ZRCG";
const MAGIC: &[u8; 4] = b"ZRCA";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Certificate {
    pub coin_type: u32,
    /// The session key `S = [s]G`.
    pub session: [u8; 32],
    /// The most a receipt may show paid to others (zatoshis).
    pub max_zats: u64,
    /// The last block a payment may be mined in.
    pub until_height: u32,
    /// If not empty, the only recipients a receipt may show paid (raw Orchard addresses).
    pub payees: Vec<[u8; 43]>,
    pub rk: [u8; 32],
    pub sig: [u8; 64],
}

impl Certificate {
    fn body(&self) -> Vec<u8> {
        let mut v = CERT_MAGIC.to_vec();
        v.push(1);
        v.extend_from_slice(&self.coin_type.to_le_bytes());
        v.extend_from_slice(&self.session);
        v.extend_from_slice(&self.max_zats.to_le_bytes());
        v.extend_from_slice(&self.until_height.to_le_bytes());
        v.push(self.payees.len() as u8);
        for p in &self.payees {
            v.extend_from_slice(p);
        }
        v.extend_from_slice(&self.rk);
        v
    }

    fn digest(&self) -> [u8; 32] {
        blake2b_simd::Params::new().hash_length(32).personal(&signing_personal(b"ZIP311Deleg\0", self.coin_type)).hash(&self.body()).as_bytes().try_into().unwrap()
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut v = self.body();
        v.extend_from_slice(&self.sig);
        v
    }

    pub fn from_bytes(b: &[u8]) -> Result<Self, Error> {
        let bad = || Error::BadDelegation;
        let mut p = 0usize;
        let mut take = |n: usize| -> Result<&[u8], Error> {
            let s = b.get(p..p + n).ok_or(Error::BadDelegation)?;
            p += n;
            Ok(s)
        };
        if take(4)? != CERT_MAGIC || take(1)? != [1] {
            return Err(bad());
        }
        let coin_type = u32::from_le_bytes(take(4)?.try_into().unwrap());
        let session = take(32)?.try_into().unwrap();
        let max_zats = u64::from_le_bytes(take(8)?.try_into().unwrap());
        let until_height = u32::from_le_bytes(take(4)?.try_into().unwrap());
        let n = take(1)?[0] as usize;
        let payees = (0..n).map(|_| Ok(take(43)?.try_into().unwrap())).collect::<Result<Vec<[u8; 43]>, Error>>()?;
        let rk = take(32)?.try_into().unwrap();
        let sig = take(64)?.try_into().unwrap();
        if p != b.len() {
            return Err(bad());
        }
        Ok(Certificate { coin_type, session, max_zats, until_height, payees, rk, sig })
    }

    pub fn to_text(&self) -> String {
        format!("{CERT_TEXT_PREFIX}{}", URL_SAFE_NO_PAD.encode(self.to_bytes()))
    }

    pub fn from_text(s: &str) -> Result<Self, Error> {
        let body = s.trim().strip_prefix(CERT_TEXT_PREFIX).ok_or(Error::BadDelegation)?;
        let bytes = URL_SAFE_NO_PAD.decode(body).map_err(|_| Error::BadDelegation)?;
        if URL_SAFE_NO_PAD.encode(&bytes) != body {
            return Err(Error::BadDelegation);
        }
        Self::from_bytes(&bytes)
    }

    /// Checks the spend key's signature on the certificate.
    pub fn check(&self) -> Result<(), Error> {
        let rk = redpallas::VerificationKey::<SpendAuth>::try_from(self.rk).map_err(|_| Error::BadDelegation)?;
        rk.verify(&self.digest(), &redpallas::Signature::<SpendAuth>::from(self.sig)).map_err(|_| Error::BadDelegation)?;
        crate::link::nonidentity_point(&self.session).map_err(|_| Error::BadDelegation)?;
        Ok(())
    }
}

/// What the spend key gives the delegate: the session secret, `alpha_c`, and the certificate.
#[derive(Clone, Debug)]
pub struct Session {
    pub secret: [u8; 32],
    pub alpha: [u8; 32],
    pub cert: Certificate,
}

impl Session {
    pub fn to_text(&self) -> String {
        let hex = |b: &[u8]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
        format!("session {}\nalpha {}\n{}\n", hex(&self.secret), hex(&self.alpha), self.cert.to_text())
    }

    pub fn from_text(s: &str) -> Result<Self, Error> {
        let bad = || Error::BadDelegation;
        let field = |name: &str| -> Result<[u8; 32], Error> {
            let h = s.lines().find_map(|l| l.strip_prefix(name)).ok_or_else(bad)?.trim();
            let v: Vec<u8> = (0..h.len()).step_by(2).map(|i| h.get(i..i + 2).and_then(|x| u8::from_str_radix(x, 16).ok()).ok_or_else(bad)).collect::<Result<_, _>>()?;
            v.try_into().map_err(|_| bad())
        };
        let cert = Certificate::from_text(s.lines().find(|l| l.starts_with(CERT_TEXT_PREFIX)).ok_or_else(bad)?)?;
        Ok(Session { secret: field("session ")?, alpha: field("alpha ")?, cert })
    }
}

/// The spend key authorizes a fresh session key under the policy. Give the delegate the session.
pub fn delegate(coin_type: u32, ask: &SpendAuthorizingKey, max_zats: u64, until_height: u32, payees: Vec<[u8; 43]>, mut rng: impl CryptoRng) -> Result<Session, Error> {
    if payees.len() > u8::MAX as usize {
        return Err(Error::BadDelegation);
    }
    let g = spend_auth_base();
    let s = random_scalar(&mut rng);
    let alpha = random_scalar(&mut rng);
    let rsk = ask.randomize(&alpha);
    let rk: [u8; 32] = (&redpallas::VerificationKey::<SpendAuth>::from(&rsk)).into();
    let mut cert = Certificate { coin_type, session: (g * s).to_bytes(), max_zats, until_height, payees, rk, sig: [0; 64] };
    cert.sig = (&rsk.sign(&mut rng, &cert.digest())).into();
    Ok(Session { secret: s.to_repr(), alpha: alpha.to_repr(), cert })
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DelegatedReceipt {
    pub cert: Certificate,
    /// Per spend, `(R, z)` linking its `rk` to the certificate's.
    pub links: Vec<([u8; 32], [u8; 32])>,
    /// The session key's Schnorr signature `(R, z)`.
    pub session_sig: [u8; 64],
    /// The receipt, its signatures zeroed.
    pub receipt: Receipt,
}

fn link_challenge(d: &DelegatedReceipt, digest: &[u8; 32], rs: &[[u8; 32]]) -> pallas::Scalar {
    let mut h = blake2b_simd::Params::new().hash_length(64).personal(&signing_personal(b"ZIP311DLink\0", d.cert.coin_type)).to_state();
    h.update(digest).update(&d.cert.rk);
    for s in &d.receipt.unsigned.spends {
        h.update(&s.rk);
    }
    for r in rs {
        h.update(r);
    }
    pallas::Scalar::from_uniform_bytes(h.finalize().as_array())
}

fn session_challenge(d: &DelegatedReceipt, digest: &[u8; 32], r: &[u8; 32]) -> pallas::Scalar {
    let mut h = blake2b_simd::Params::new().hash_length(64).personal(&signing_personal(b"ZIP311DSess\0", d.cert.coin_type)).to_state();
    h.update(digest).update(&d.cert.to_bytes());
    for (r, z) in &d.links {
        h.update(r).update(z);
    }
    h.update(&d.cert.session).update(r);
    pallas::Scalar::from_uniform_bytes(h.finalize().as_array())
}

/// The delegate answers for `prepared` (made with the viewing key) under `session`.
pub fn issue(prepared: PreparedReceipt, session: &Session, mut rng: impl CryptoRng) -> Result<DelegatedReceipt, Error> {
    let u = prepared.unsigned();
    if u.spends.is_empty() || u.spends.len() > u8::MAX as usize || u.coin_type != session.cert.coin_type {
        return Err(Error::BadDelegation);
    }
    let g = spend_auth_base();
    let (s, alpha_c) = (scalar(&session.secret).map_err(|_| Error::BadDelegation)?, scalar(&session.alpha).map_err(|_| Error::BadDelegation)?);
    let rk_c = point(&session.cert.rk).map_err(|_| Error::BadDelegation)?;
    let digest = signing_digest(u);
    let mut d = DelegatedReceipt { cert: session.cert.clone(), links: vec![], session_sig: [0; 64], receipt: Receipt { unsigned: u.clone(), spend_auth_sigs: vec![[0; 64]; u.spends.len()] } };
    let mut nonces = Vec::new();
    let mut rs = Vec::new();
    for (sp, alpha) in u.spends.iter().zip(prepared.alphas()) {
        // This spend must be under the certificate's key.
        if point(&sp.rk).map_err(|_| Error::BadDelegation)? - rk_c != g * (alpha - alpha_c) {
            return Err(Error::BadDelegation);
        }
        let k = random_scalar(&mut rng);
        nonces.push((k, alpha - alpha_c));
        rs.push((g * k).to_bytes());
    }
    let c = link_challenge(&d, &digest, &rs);
    d.links = rs.iter().zip(&nonces).map(|(r, (k, delta))| (*r, (k + c * delta).to_repr())).collect();
    let k = random_scalar(&mut rng);
    let r = (g * k).to_bytes();
    let e = session_challenge(&d, &digest, &r);
    let mut sig = [0u8; 64];
    sig[..32].copy_from_slice(&r);
    sig[32..].copy_from_slice(&(k + e * s).to_repr());
    d.session_sig = sig;
    Ok(d)
}

impl DelegatedReceipt {
    /// Checks the certificate, the links and the session signature (not the policy, which needs
    /// the verified receipt: [`check_policy`]).
    pub fn check_authorization(&self) -> Result<(), Error> {
        let bad = || Error::BadDelegation;
        self.cert.check()?;
        let u = &self.receipt.unsigned;
        if self.links.len() != u.spends.len() || u.spends.is_empty() || u.coin_type != self.cert.coin_type {
            return Err(bad());
        }
        let g = spend_auth_base();
        let digest = signing_digest(u);
        let rk_c = point(&self.cert.rk).map_err(|_| bad())?;
        let rs: Vec<[u8; 32]> = self.links.iter().map(|(r, _)| *r).collect();
        let c = link_challenge(self, &digest, &rs);
        for (sp, (r, z)) in u.spends.iter().zip(&self.links) {
            let rk = point(&sp.rk).map_err(|_| bad())?;
            if g * scalar(z).map_err(|_| bad())? != point(r).map_err(|_| bad())? + (rk - rk_c) * c {
                return Err(bad());
            }
        }
        let r: [u8; 32] = self.session_sig[..32].try_into().unwrap();
        let z = scalar(&self.session_sig[32..].try_into().unwrap()).map_err(|_| bad())?;
        let e = session_challenge(self, &digest, &r);
        if g * z != point(&r).map_err(|_| bad())? + point(&self.cert.session).map_err(|_| bad())? * e {
            return Err(bad());
        }
        Ok(())
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut v = MAGIC.to_vec();
        v.push(1);
        let cert = self.cert.to_bytes();
        v.extend_from_slice(&(cert.len() as u16).to_le_bytes());
        v.extend_from_slice(&cert);
        v.push(self.links.len() as u8);
        for (r, z) in &self.links {
            v.extend_from_slice(r);
            v.extend_from_slice(z);
        }
        v.extend_from_slice(&self.session_sig);
        v.extend_from_slice(&self.receipt.to_bytes());
        v
    }

    pub fn from_bytes(b: &[u8]) -> Result<Self, Error> {
        let bad = || Error::BadDelegation;
        if b.len() < 7 || &b[..4] != MAGIC || b[4] != 1 {
            return Err(bad());
        }
        let n = u16::from_le_bytes([b[5], b[6]]) as usize;
        let cert = Certificate::from_bytes(b.get(7..7 + n).ok_or_else(bad)?)?;
        let mut p = 7 + n;
        let nl = *b.get(p).ok_or_else(bad)? as usize;
        p += 1;
        let links = (0..nl)
            .map(|i| {
                let s = b.get(p + i * 64..p + i * 64 + 64).ok_or_else(bad)?;
                Ok((s[..32].try_into().unwrap(), s[32..].try_into().unwrap()))
            })
            .collect::<Result<Vec<_>, Error>>()?;
        p += nl * 64;
        let session_sig = b.get(p..p + 64).ok_or_else(bad)?.try_into().unwrap();
        let receipt = Receipt::from_bytes(&b[p + 64..]).map_err(|_| bad())?;
        if receipt.spend_auth_sigs.iter().any(|s| *s != [0; 64]) || receipt.unsigned.spends.len() != nl {
            return Err(bad());
        }
        Ok(DelegatedReceipt { cert, links, session_sig, receipt })
    }

    pub fn to_text(&self) -> String {
        format!("{DELEGATED_TEXT_PREFIX}{}", URL_SAFE_NO_PAD.encode(self.to_bytes()))
    }

    pub fn from_text(s: &str) -> Result<Self, Error> {
        let body = s.trim().strip_prefix(DELEGATED_TEXT_PREFIX).ok_or(Error::BadDelegation)?;
        let bytes = URL_SAFE_NO_PAD.decode(body).map_err(|_| Error::BadDelegation)?;
        if URL_SAFE_NO_PAD.encode(&bytes) != body {
            return Err(Error::BadDelegation);
        }
        Self::from_bytes(&bytes)
    }
}

/// Checks the certificate's policy against what the verified receipt shows and the block the
/// payment was mined in: within the most, by the last block, and only to listed payees.
pub fn check_policy(cert: &Certificate, v: &VerifiedReceipt, mined_height: u32) -> Result<(), Error> {
    let total: u64 = v.outputs.iter().map(|o| o.value).sum();
    if total > cert.max_zats || mined_height > cert.until_height {
        return Err(Error::BadDelegation);
    }
    if !cert.payees.is_empty() && v.outputs.iter().any(|o| !cert.payees.contains(&o.recipient)) {
        return Err(Error::BadDelegation);
    }
    Ok(())
}
