//! Designated-verifier receipts: convincing to one verifier (a shop), not to anyone it shows.
//!
//! A receipt's SpendAuthSig convinces whoever sees it that the payer's spend key authorized it.
//! Here each spend's signature is replaced by a one-of-two Schnorr proof over the same digest:
//! "I know `x` with `rk = [x]G`, or I know `y` with `V = [y]G`", where `V` is the verifier's
//! published key. The verifier knows it didn't use `y`, so it is convinced the spend key signed;
//! anyone it forwards the receipt to sees a proof the verifier could have made itself. The
//! Action proofs are unchanged, so a third party still sees that someone holding the payer's
//! viewing key built it (the payer, or anyone the payer gave that key), not that the spend key
//! authorized it.
//!
//! ```text
//! designated := "ZRCD" | version:u8 = 1 | V[32] | n:u8 | { c1[32] | s1[32] | c2[32] | s2[32] }^n
//!             | receipt (the zip311r1 bytes, every signature 64 zero bytes)
//! text       := "zip311d1" || base64url_nopad(designated)
//! c          := ToScalar(BLAKE2b-512("ZIP311Desig\0" || coinType, digest || V || rk || R1 || R2))
//! check      := R1 = [s1]G - [c1]rk, R2 = [s2]G - [c2]V, c1 + c2 == c
//! ```

use crate::link::{nonidentity_point, point, scalar, spend_auth_base};
use crate::{random_scalar, sign_prepared, signing_digest, signing_personal, Error, PreparedReceipt, Receipt};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use group::{ff::FromUniformBytes, ff::PrimeField, GroupEncoding};
use orchard::keys::{SpendAuthorizingKey, SpendingKey};
use pasta_curves::pallas;
use rand_core::CryptoRng;

pub const DESIGNATED_TEXT_PREFIX: &str = "zip311d1";
const MAGIC: &[u8; 4] = b"ZRCD";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DesignatedReceipt {
    /// The receipt, its signatures zeroed.
    pub receipt: Receipt,
    /// The verifier's key `V`.
    pub verifier: [u8; 32],
    /// Per spend, `(c1, s1, c2, s2)`.
    pub proofs: Vec<[[u8; 32]; 4]>,
}

/// A verifier's key pair: `y` (keep it) and `V = [y]G` (publish it).
pub fn verifier_key(mut rng: impl CryptoRng) -> ([u8; 32], [u8; 32]) {
    let y = random_scalar(&mut rng);
    (y.to_repr(), (spend_auth_base() * y).to_bytes())
}

/// `V = [y]G` for a secret half `y`.
pub fn public_key(y: &[u8; 32]) -> Result<[u8; 32], Error> {
    Ok((spend_auth_base() * scalar(y).map_err(|_| Error::BadDesignated)?).to_bytes())
}

fn challenge(coin_type: u32, digest: &[u8; 32], v: &[u8; 32], rk: &[u8; 32], r1: &pallas::Point, r2: &pallas::Point) -> pallas::Scalar {
    let mut h = blake2b_simd::Params::new().hash_length(64).personal(&signing_personal(b"ZIP311Desig\0", coin_type)).to_state();
    h.update(digest).update(v).update(rk).update(&r1.to_bytes()).update(&r2.to_bytes());
    pallas::Scalar::from_uniform_bytes(h.finalize().as_array())
}

/// `ask` as a scalar (ZIP 32: ToScalar(PRF^expand(sk, [0x06])), negated if needed so `ak` has
/// ỹ = 0), which orchard keeps inside its signing key.
fn ask_scalar(sk: &SpendingKey) -> pallas::Scalar {
    let h = blake2b_simd::Params::new().hash_length(64).personal(b"Zcash_ExpandSeed").to_state().update(sk.to_bytes()).update(&[0x06]).finalize();
    let ask = pallas::Scalar::from_uniform_bytes(h.as_array());
    let ak = (spend_auth_base() * ask).to_bytes();
    if ak[31] >> 7 == 1 {
        -ask
    } else {
        ask
    }
}

/// Authorizes `prepared` for the verifier with key `verifier` only, with the spending keys (one
/// per spend, in spend order).
pub fn prove(prepared: PreparedReceipt, sks: &[SpendingKey], verifier: [u8; 32], mut rng: impl CryptoRng) -> Result<DesignatedReceipt, Error> {
    let u = prepared.unsigned();
    if sks.len() != u.spends.len() || u.spends.len() > u8::MAX as usize {
        return Err(Error::SignatureCount);
    }
    // Checks each key against its rk, as signing would.
    let asks: Vec<SpendAuthorizingKey> = sks.iter().map(SpendAuthorizingKey::from).collect();
    sign_prepared(u, prepared.alphas(), &asks, &mut rng)?;
    let g = spend_auth_base();
    let v = nonidentity_point(&verifier).map_err(|_| Error::BadDesignated)?;
    let digest = signing_digest(u);
    let mut proofs = Vec::with_capacity(u.spends.len());
    for ((s, sk), alpha) in u.spends.iter().zip(sks).zip(prepared.alphas()) {
        let x = ask_scalar(sk) + alpha;
        if (g * x).to_bytes() != s.rk {
            return Err(Error::BadDesignated);
        }
        let k = random_scalar(&mut rng);
        let (c2, s2) = (random_scalar(&mut rng), random_scalar(&mut rng));
        let r1 = g * k;
        let r2 = g * s2 - v * c2;
        let c1 = challenge(u.coin_type, &digest, &verifier, &s.rk, &r1, &r2) - c2;
        let s1 = k + c1 * x;
        proofs.push([c1.to_repr(), s1.to_repr(), c2.to_repr(), s2.to_repr()]);
    }
    let n = u.spends.len();
    let receipt = Receipt { unsigned: u.clone(), spend_auth_sigs: vec![[0; 64]; n] };
    Ok(DesignatedReceipt { receipt, verifier, proofs })
}

/// What only the verifier holding `y` can do: make the same proof without any spend key. This is
/// why a designated receipt convinces no one else.
pub fn simulate(receipt: Receipt, y: &[u8; 32], mut rng: impl CryptoRng) -> Result<DesignatedReceipt, Error> {
    let g = spend_auth_base();
    let y = scalar(y).map_err(|_| Error::BadDesignated)?;
    if bool::from(group::ff::Field::is_zero(&y)) {
        return Err(Error::BadDesignated);
    }
    let verifier = (g * y).to_bytes();
    let u = &receipt.unsigned;
    let digest = signing_digest(u);
    let mut proofs = Vec::new();
    for s in &u.spends {
        let rk = point(&s.rk).map_err(|_| Error::BadDesignated)?;
        let k = random_scalar(&mut rng);
        let (c1, s1) = (random_scalar(&mut rng), random_scalar(&mut rng));
        let r1 = g * s1 - rk * c1;
        let r2 = g * k;
        let c2 = challenge(u.coin_type, &digest, &verifier, &s.rk, &r1, &r2) - c1;
        let s2 = k + c2 * y;
        proofs.push([c1.to_repr(), s1.to_repr(), c2.to_repr(), s2.to_repr()]);
    }
    let n = u.spends.len();
    Ok(DesignatedReceipt { receipt: Receipt { unsigned: u.clone(), spend_auth_sigs: vec![[0; 64]; n] }, verifier, proofs })
}

impl DesignatedReceipt {
    /// Checks the one-of-two proofs (verify the receipt's proofs against the chain as usual, with
    /// [`crate::verify_designated_tx_bundles`]).
    pub fn check_proofs(&self) -> Result<(), Error> {
        let u = &self.receipt.unsigned;
        if self.proofs.len() != u.spends.len() || u.spends.is_empty() {
            return Err(Error::BadDesignated);
        }
        let g = spend_auth_base();
        let v = nonidentity_point(&self.verifier).map_err(|_| Error::BadDesignated)?;
        let digest = signing_digest(u);
        for (s, p) in u.spends.iter().zip(&self.proofs) {
            let rk = point(&s.rk).map_err(|_| Error::BadDesignated)?;
            let [c1, s1, c2, s2] = p.map(|b| scalar(&b).map_err(|_| Error::BadDesignated)).into_iter().collect::<Result<Vec<_>, _>>()?.try_into().unwrap();
            let r1 = g * s1 - rk * c1;
            let r2 = g * s2 - v * c2;
            if c1 + c2 != challenge(u.coin_type, &digest, &self.verifier, &s.rk, &r1, &r2) {
                return Err(Error::BadDesignated);
            }
        }
        Ok(())
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut v = MAGIC.to_vec();
        v.push(1);
        v.extend_from_slice(&self.verifier);
        v.push(self.proofs.len() as u8);
        for p in &self.proofs {
            for b in p {
                v.extend_from_slice(b);
            }
        }
        v.extend_from_slice(&self.receipt.to_bytes());
        v
    }

    pub fn from_bytes(b: &[u8]) -> Result<Self, Error> {
        if b.len() < 38 || &b[..4] != MAGIC || b[4] != 1 {
            return Err(Error::BadDesignated);
        }
        let verifier: [u8; 32] = b[5..37].try_into().unwrap();
        let n = b[37] as usize;
        let rest = &b[38..];
        if rest.len() < n * 128 {
            return Err(Error::BadDesignated);
        }
        let proofs = rest[..n * 128].chunks(128).map(|c| [0, 1, 2, 3].map(|i| c[i * 32..i * 32 + 32].try_into().unwrap())).collect();
        let receipt = Receipt::from_bytes(&rest[n * 128..]).map_err(|_| Error::BadDesignated)?;
        if receipt.spend_auth_sigs.iter().any(|s| *s != [0; 64]) || receipt.unsigned.spends.len() != n {
            return Err(Error::BadDesignated);
        }
        Ok(DesignatedReceipt { receipt, verifier, proofs })
    }

    pub fn to_text(&self) -> String {
        format!("{DESIGNATED_TEXT_PREFIX}{}", URL_SAFE_NO_PAD.encode(self.to_bytes()))
    }

    pub fn from_text(s: &str) -> Result<Self, Error> {
        let body = s.trim().strip_prefix(DESIGNATED_TEXT_PREFIX).ok_or(Error::BadDesignated)?;
        let bytes = URL_SAFE_NO_PAD.decode(body).map_err(|_| Error::BadDesignated)?;
        if URL_SAFE_NO_PAD.encode(&bytes) != body {
            return Err(Error::BadDesignated);
        }
        Self::from_bytes(&bytes)
    }
}
