//! "Sign in with Zcash": prove you control a shielded address, with no transaction.
//!
//! The same construction as a receipt's address proof (see `AddressProof`): a Halo 2 action
//! proof that spends a fresh 1-zatoshi note addressed to `A` under a fresh randomized key `rk`,
//! plus a spend-authorization signature by `rk` over the sign-in message
//! `(coin type, domain, nonce, issued_at, A)`. The verifier recomputes the note commitment from
//! the revealed note, uses the one-leaf tree root as the anchor, and checks proof and
//! signature. Binding the domain and a single-use nonce stops replay to another site or later.

use crate::{
    address_proof, random_scalar, signing_personal, verify_address_proof, AddressProof, Error, Pool,
};
use blake2b_simd::Params;
use orchard::{
    circuit::{ProvingKey, VerifyingKey},
    keys::{FullViewingKey, SpendAuthorizingKey, SpendingKey},
    primitives::redpallas::{self, SpendAuth},
    Address,
};
use rand_core::CryptoRng;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignIn {
    pub coin_type: u32,
    pub domain: String,
    pub nonce: String,
    pub issued_at: u64,
    pub rk: [u8; 32],
    pub address: AddressProof,
    pub sig: [u8; 64],
}

fn digest(coin_type: u32, domain: &str, nonce: &str, issued_at: u64, rk: &[u8; 32], a: &AddressProof) -> [u8; 32] {
    let mut m = Vec::new();
    m.extend_from_slice(b"Receipts sign-in v1");
    for part in [domain.as_bytes(), nonce.as_bytes()] {
        m.extend_from_slice(&(part.len() as u32).to_le_bytes());
        m.extend_from_slice(part);
    }
    m.extend_from_slice(&issued_at.to_le_bytes());
    m.extend_from_slice(rk);
    m.extend_from_slice(&a.address);
    m.extend_from_slice(&a.rho);
    m.extend_from_slice(&a.rseed);
    m.extend_from_slice(&a.nf);
    m.extend_from_slice(&a.cv_net);
    m.extend_from_slice(&a.cmx);
    m.extend_from_slice(&a.proof);
    let h = Params::new().hash_length(32).personal(&signing_personal(b"ZcashSignIn\0", coin_type)).hash(&m);
    h.as_bytes().try_into().unwrap()
}

/// Proves control of `address` (which must belong to `sk`) for `domain` and `nonce`.
#[allow(clippy::too_many_arguments)]
pub fn sign_in(
    pk: &ProvingKey,
    coin_type: u32,
    domain: &str,
    nonce: &str,
    issued_at: u64,
    sk: &SpendingKey,
    address: Address,
    mut rng: impl CryptoRng,
) -> Result<SignIn, Error> {
    let fvk = FullViewingKey::from(sk);
    let alpha = random_scalar(&mut rng);
    let rsk = SpendAuthorizingKey::from(sk).randomize(&alpha);
    let rk = redpallas::VerificationKey::<SpendAuth>::from(&rsk);
    let a = address_proof(pk, Pool::Ironwood, &fvk, address, alpha, &rk, &mut rng)?;
    let rk_bytes: [u8; 32] = (&rk).into();
    let d = digest(coin_type, domain, nonce, issued_at, &rk_bytes, &a);
    let sig: [u8; 64] = (&rsk.sign(&mut rng, &d)).into();
    Ok(SignIn { coin_type, domain: domain.into(), nonce: nonce.into(), issued_at, rk: rk_bytes, address: a, sig })
}

/// Checks a sign-in for `expected_domain` / `expected_nonce`; returns the proven address.
pub fn verify_sign_in(vk: &VerifyingKey, s: &SignIn, expected_coin_type: u32, expected_domain: &str, expected_nonce: &str) -> Result<[u8; 43], Error> {
    if s.coin_type != expected_coin_type {
        return Err(Error::CoinTypeMismatch(s.coin_type, expected_coin_type));
    }
    if s.domain != expected_domain || s.nonce != expected_nonce {
        return Err(Error::BadSignature(0));
    }
    let rk = redpallas::VerificationKey::<SpendAuth>::try_from(s.rk).map_err(|_| Error::Malformed(0))?;
    let d = digest(s.coin_type, &s.domain, &s.nonce, s.issued_at, &s.rk, &s.address);
    rk.verify(&d, &redpallas::Signature::<SpendAuth>::from(s.sig)).map_err(|_| Error::BadSignature(0))?;
    verify_address_proof(vk, Pool::Ironwood, 0, &rk, &s.address)?;
    Ok(s.address.address)
}

// ---------- encoding: "zsig1" + base64url ----------

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};

impl SignIn {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut v = b"ZSIG".to_vec();
        v.push(1);
        v.extend_from_slice(&self.coin_type.to_le_bytes());
        for s in [self.domain.as_bytes(), self.nonce.as_bytes()] {
            v.extend_from_slice(&(s.len() as u16).to_le_bytes());
            v.extend_from_slice(s);
        }
        v.extend_from_slice(&self.issued_at.to_le_bytes());
        v.extend_from_slice(&self.rk);
        let a = &self.address;
        v.extend_from_slice(&a.address);
        v.extend_from_slice(&a.rho);
        v.extend_from_slice(&a.rseed);
        v.extend_from_slice(&a.nf);
        v.extend_from_slice(&a.cv_net);
        v.extend_from_slice(&a.cmx);
        v.extend_from_slice(&(a.proof.len() as u32).to_le_bytes());
        v.extend_from_slice(&a.proof);
        v.extend_from_slice(&self.sig);
        v
    }

    pub fn from_bytes(b: &[u8]) -> Option<Self> {
        let mut p = 0usize;
        let mut take = |n: usize| -> Option<&[u8]> {
            let s = b.get(p..p + n)?;
            p += n;
            Some(s)
        };
        if take(4)? != b"ZSIG" || take(1)? != [1] {
            return None;
        }
        let coin_type = u32::from_le_bytes(take(4)?.try_into().ok()?);
        let dl = u16::from_le_bytes(take(2)?.try_into().ok()?) as usize;
        let domain = String::from_utf8(take(dl)?.to_vec()).ok()?;
        let nl = u16::from_le_bytes(take(2)?.try_into().ok()?) as usize;
        let nonce = String::from_utf8(take(nl)?.to_vec()).ok()?;
        let issued_at = u64::from_le_bytes(take(8)?.try_into().ok()?);
        let rk = take(32)?.try_into().ok()?;
        let address = take(43)?.try_into().ok()?;
        let rho = take(32)?.try_into().ok()?;
        let rseed = take(32)?.try_into().ok()?;
        let nf = take(32)?.try_into().ok()?;
        let cv_net = take(32)?.try_into().ok()?;
        let cmx = take(32)?.try_into().ok()?;
        let pl = u32::from_le_bytes(take(4)?.try_into().ok()?) as usize;
        if pl > 1 << 16 {
            return None;
        }
        let proof = take(pl)?.to_vec();
        let sig = take(64)?.try_into().ok()?;
        if p != b.len() {
            return None;
        }
        Some(SignIn { coin_type, domain, nonce, issued_at, rk, address: AddressProof { address, rho, rseed, nf, cv_net, cmx, proof }, sig })
    }

    pub fn to_text(&self) -> String {
        format!("zsig1{}", URL_SAFE_NO_PAD.encode(self.to_bytes()))
    }

    pub fn from_text(s: &str) -> Option<Self> {
        Self::from_bytes(&URL_SAFE_NO_PAD.decode(s.trim().strip_prefix("zsig1")?).ok()?)
    }
}
