//! Signed payment requests (`zreq1`): what to pay, signed by the payee address's own key.
//!
//! ZIP 321 payment links say what to pay but not who is asking (zcash/zips#611, #977). Anyone who
//! can change a link in transit (clipboard malware, a compromised chat, an edited invoice) can
//! swap the address or the amount, and the wallet can't tell. A signed request carries the payee
//! address, amount, memo, a request code, an expiry and the shop's domain, signed under a fresh
//! `rk` whose spend authority is proven to control the payee address (the address proof of
//! receipts and Sign in with Zcash). So:
//!
//! - nobody without the payee's spending key can change any field;
//! - an attacker who swaps in their own address must sign with their own key, and then the
//!   request names an address the shop's domain doesn't list: wallets check
//!   `https://<domain>/.well-known/zcash-receipts.json` (`{"payees": ["u1…"]}`) over TLS.
//!
//! The payer's receipt then signs `challenge:<code>`, closing the loop: request, payment, proof.

use crate::{address_proof, random_scalar, signing_personal, verify_address_proof, AddressProof, Error, Pool};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use blake2b_simd::Params;
use orchard::{
    circuit::{ProvingKey, VerifyingKey},
    keys::{FullViewingKey, SpendAuthorizingKey, SpendingKey},
    primitives::redpallas::{self, SpendAuth},
    Address,
};
use rand_core::CryptoRng;

pub const REQUEST_TEXT_PREFIX: &str = "zreq1";
const MAGIC: &[u8; 4] = b"ZREQ";
/// The longest memo a payment can carry (ZIP 302).
pub const MAX_MEMO: usize = 512;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PaymentRequest {
    pub coin_type: u32,
    /// The shop's domain (lowercase host name), which must list the payee address.
    pub domain: String,
    pub amount: u64,
    /// UTF-8 memo for the payment (at most 512 bytes).
    pub memo: String,
    /// Request code (hex, 6 to 64 characters); the payer's receipt signs `challenge:<code>`.
    pub code: String,
    /// Unix time after which wallets refuse to pay it.
    pub expires_at: u64,
    pub rk: [u8; 32],
    /// The payee address (`address.address`) and the proof that `rk`'s key controls it.
    pub address: AddressProof,
    pub sig: [u8; 64],
}

fn valid_fields(domain: &str, memo: &str, code: &str, amount: u64) -> bool {
    let domain_ok = !domain.is_empty()
        && domain.len() <= 253
        && domain.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '.' || c == '-' || c == ':');
    domain_ok && memo.len() <= MAX_MEMO && (6..=64).contains(&code.len()) && code.chars().all(|c| c.is_ascii_hexdigit()) && amount > 0
}

impl PaymentRequest {
    fn unsigned_bytes(&self) -> Vec<u8> {
        let mut v = MAGIC.to_vec();
        v.push(1);
        v.extend_from_slice(&self.coin_type.to_le_bytes());
        for s in [self.domain.as_bytes(), self.memo.as_bytes(), self.code.as_bytes()] {
            v.extend_from_slice(&(s.len() as u16).to_le_bytes());
            v.extend_from_slice(s);
        }
        v.extend_from_slice(&self.amount.to_le_bytes());
        v.extend_from_slice(&self.expires_at.to_le_bytes());
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
        v
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut v = self.unsigned_bytes();
        v.extend_from_slice(&self.sig);
        v
    }

    /// Strict decoding: fields must be well formed and re-encode to the same bytes.
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
        let mut strs = Vec::with_capacity(3);
        for _ in 0..3 {
            let l = u16::from_le_bytes(take(2)?.try_into().ok()?) as usize;
            strs.push(String::from_utf8(take(l)?.to_vec()).ok()?);
        }
        let amount = u64::from_le_bytes(take(8)?.try_into().ok()?);
        let expires_at = u64::from_le_bytes(take(8)?.try_into().ok()?);
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
        let [domain, memo, code]: [String; 3] = strs.try_into().ok()?;
        if !valid_fields(&domain, &memo, &code, amount) {
            return None;
        }
        Some(PaymentRequest { coin_type, domain, amount, memo, code, expires_at, rk, address: AddressProof { address, rho, rseed, nf, cv_net, cmx, proof }, sig })
    }

    pub fn to_text(&self) -> String {
        format!("{REQUEST_TEXT_PREFIX}{}", URL_SAFE_NO_PAD.encode(self.to_bytes()))
    }

    pub fn from_text(s: &str) -> Option<Self> {
        Self::from_bytes(&URL_SAFE_NO_PAD.decode(s.trim().strip_prefix(REQUEST_TEXT_PREFIX)?).ok()?)
    }
}

/// `BLAKE2b-256("ZIP321Signed" || coinType, everything before the signature)`.
pub fn signing_digest(r: &PaymentRequest) -> [u8; 32] {
    let h = Params::new().hash_length(32).personal(&signing_personal(b"ZIP321Signed", r.coin_type)).hash(&r.unsigned_bytes());
    h.as_bytes().try_into().expect("32 bytes")
}

/// Signs a payment request for `payee`, an address of `sk`.
#[allow(clippy::too_many_arguments)]
pub fn sign_request(
    pk: &ProvingKey,
    coin_type: u32,
    domain: &str,
    amount: u64,
    memo: &str,
    code: &str,
    expires_at: u64,
    sk: &SpendingKey,
    payee: Address,
    mut rng: impl CryptoRng,
) -> Result<PaymentRequest, Error> {
    let domain = domain.trim().to_ascii_lowercase();
    if !valid_fields(&domain, memo, code, amount) {
        return Err(Error::Malformed(0));
    }
    let fvk = FullViewingKey::from(sk);
    let alpha = random_scalar(&mut rng);
    let rsk = SpendAuthorizingKey::from(sk).randomize(&alpha);
    let rk = redpallas::VerificationKey::<SpendAuth>::from(&rsk);
    let a = address_proof(pk, Pool::Ironwood, &fvk, payee, alpha, &rk, &mut rng)?;
    let mut r = PaymentRequest { coin_type, domain, amount, memo: memo.into(), code: code.to_ascii_lowercase(), expires_at, rk: (&rk).into(), address: a, sig: [0; 64] };
    r.sig = (&rsk.sign(&mut rng, &signing_digest(&r))).into();
    Ok(r)
}

/// Why a request can't be paid as is.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum RequestError {
    #[error("the request is for another network")]
    Network,
    #[error("the request expired")]
    Expired,
    #[error("the signature or the payee's address proof does not check out: {0}")]
    Invalid(Error),
}

/// Checks a request's signature and that its signer controls the payee address, the network and
/// the expiry (`now`, Unix seconds). Returns the payee's raw Orchard address. The caller still
/// checks that `r.domain` lists that address (see the module docs).
pub fn verify_request(vk: &VerifyingKey, r: &PaymentRequest, expected_coin_type: u32, now: u64) -> Result<[u8; 43], RequestError> {
    if r.coin_type != expected_coin_type {
        return Err(RequestError::Network);
    }
    let rk = redpallas::VerificationKey::<SpendAuth>::try_from(r.rk).map_err(|_| RequestError::Invalid(Error::Malformed(0)))?;
    rk.verify(&signing_digest(r), &redpallas::Signature::<SpendAuth>::from(r.sig)).map_err(|_| RequestError::Invalid(Error::BadSignature(0)))?;
    verify_address_proof(vk, Pool::Ironwood, 0, &rk, &r.address).map_err(RequestError::Invalid)?;
    if now > r.expires_at {
        return Err(RequestError::Expired);
    }
    Ok(r.address.address)
}

/// Whether a `/.well-known/zcash-receipts.json` document (`{"payees": ["u1…", …]}`) lists the
/// payee: any listed unified address with that Orchard receiver counts.
pub fn domain_lists_payee(well_known: &serde_json::Value, payee_raw: &[u8; 43], orchard_receiver_of: impl Fn(&str) -> Option<[u8; 43]>) -> bool {
    well_known["payees"].as_array().is_some_and(|a| a.iter().filter_map(|v| v.as_str()).any(|ua| orchard_receiver_of(ua).as_ref() == Some(payee_raw)))
}
