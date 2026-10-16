//! Incoming receipts: the *recipient* proves it received a payment, without a viewing key.
//!
//! A sender's receipt (ZIP 311) proves "I paid". A merchant, freelancer or charity often needs the
//! other half for an accountant, a tax office or a lender: "I was paid this, at this address". With
//! Zcash today that means handing over an incoming viewing key, which shows every payment to the
//! wallet. An incoming receipt shows chosen outputs of one transaction, and that whoever made it
//! controls the address they paid:
//!
//! - for each disclosed output, its ephemeral secret key `esk`. With the recipient's `pk_d` it opens
//!   exactly that output (§4.20.3 recovery: the verifier checks `epk = [esk] g_d`, decrypts with
//!   `KDF([esk] pk_d, epk)`, re-derives `esk` from the plaintext's `rseed` and checks `cmx`), so the
//!   recipient, value and memo are those committed on chain. `esk` opens nothing else;
//! - an address proof (as in sender receipts and Sign in with Zcash) that the signer's spend
//!   authority controls the recipient address, under a fresh `rk`;
//! - a RedPallas signature by `rk` over everything, so a sender (who also knows `esk`, through its
//!   outgoing viewing key) can't make one: it doesn't control the address.
//!
//! No nullifier is revealed, so the verifier can't tell when the received notes are spent.

use crate::{address_proof, random_scalar, signing_personal, verify_address_proof, AddressProof, Error, Pool, VerifiedOutput};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use blake2b_simd::Params;
use orchard::{
    bundle::Authorization,
    circuit::{ProvingKey, VerifyingKey},
    keys::{EphemeralSecretKey, FullViewingKey, PreparedIncomingViewingKey, Scope, SpendAuthorizingKey, SpendingKey},
    note_encryption::{IronwoodDomain, OrchardDomain},
    primitives::redpallas::{self, SpendAuth},
    Address, Bundle,
};
use rand_core::CryptoRng;
use zcash_note_encryption::{try_note_decryption, try_output_recovery_with_pkd_esk};

/// Prefix of the text encoding.
pub const INCOMING_TEXT_PREFIX: &str = "zrcin1";
const MAGIC: &[u8; 4] = b"ZRCI";

/// One disclosed output: its action index and ephemeral secret key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IncomingOutput {
    pub index: u32,
    pub esk: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IncomingReceipt {
    pub coin_type: u32,
    pub pool: Pool,
    pub txid: [u8; 32],
    pub msg: Vec<u8>,
    pub outputs: Vec<IncomingOutput>,
    pub rk: [u8; 32],
    /// Proves that `rk`'s spend authority controls `address.address`, the recipient of every output.
    pub address: AddressProof,
    pub sig: [u8; 64],
}

/// What a verifier learns from a valid incoming receipt.
#[derive(Clone, Debug)]
pub struct VerifiedIncoming {
    pub coin_type: u32,
    pub pool: Pool,
    pub txid: [u8; 32],
    pub msg: Vec<u8>,
    /// The address the signer proved it controls, which received every output.
    pub recipient: [u8; 43],
    pub outputs: Vec<VerifiedOutput>,
}

impl IncomingReceipt {
    /// The canonical encoding of everything but the signature.
    fn unsigned_bytes(&self) -> Vec<u8> {
        let mut v = MAGIC.to_vec();
        v.push(1);
        v.extend_from_slice(&self.coin_type.to_le_bytes());
        v.push(match self.pool {
            Pool::Orchard => 0,
            Pool::Ironwood => 1,
        });
        v.extend_from_slice(&self.txid);
        v.extend_from_slice(&(self.msg.len() as u16).to_le_bytes());
        v.extend_from_slice(&self.msg);
        v.push(self.outputs.len() as u8);
        for o in &self.outputs {
            v.extend_from_slice(&o.index.to_le_bytes());
            v.extend_from_slice(&o.esk);
        }
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

    /// Strict decoding: the bytes must re-encode exactly (one encoding per receipt).
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
        let txid = take(32)?.try_into().ok()?;
        let ml = u16::from_le_bytes(take(2)?.try_into().ok()?) as usize;
        let msg = take(ml)?.to_vec();
        let n = take(1)?[0] as usize;
        let mut outputs = Vec::with_capacity(n);
        for _ in 0..n {
            let index = u32::from_le_bytes(take(4)?.try_into().ok()?);
            outputs.push(IncomingOutput { index, esk: take(32)?.try_into().ok()? });
        }
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
        let r = IncomingReceipt { coin_type, pool, txid, msg, outputs, rk, address: AddressProof { address, rho, rseed, nf, cv_net, cmx, proof }, sig };
        (r.to_bytes() == b).then_some(r)
    }

    pub fn to_text(&self) -> String {
        format!("{INCOMING_TEXT_PREFIX}{}", URL_SAFE_NO_PAD.encode(self.to_bytes()))
    }

    pub fn from_text(s: &str) -> Option<Self> {
        Self::from_bytes(&URL_SAFE_NO_PAD.decode(s.trim().strip_prefix(INCOMING_TEXT_PREFIX)?).ok()?)
    }
}

/// The digest the signature covers: `BLAKE2b-256("ZIP311Incomg" || coinType, unsigned bytes)`.
pub fn signing_digest(r: &IncomingReceipt) -> [u8; 32] {
    let h = Params::new().hash_length(32).personal(&signing_personal(b"ZIP311Incomg", r.coin_type)).hash(&r.unsigned_bytes());
    h.as_bytes().try_into().expect("32 bytes")
}

/// Finds the notes at `indices` of `bundle` that `sk`'s wallet received, all at one address, and
/// proves receipt of them. With no indices, every output this wallet received at the address of
/// the first one found.
#[allow(clippy::too_many_arguments)]
pub fn create_incoming<A: Authorization, V>(
    pk: &ProvingKey,
    coin_type: u32,
    pool: Pool,
    txid: [u8; 32],
    bundle: &Bundle<A, V>,
    msg: &[u8],
    sk: &SpendingKey,
    indices: &[usize],
    mut rng: impl CryptoRng,
) -> Result<IncomingReceipt, Error> {
    if msg.len() > u16::MAX as usize || indices.len() > u8::MAX as usize {
        return Err(Error::TooLarge);
    }
    let fvk = FullViewingKey::from(sk);
    let ivks = [PreparedIncomingViewingKey::new(&fvk.to_ivk(Scope::External)), PreparedIncomingViewingKey::new(&fvk.to_ivk(Scope::Internal))];
    let actions = bundle.actions();
    let decrypt = |i: usize| -> Option<(orchard::Note, Address)> {
        let a = actions.get(i)?;
        ivks.iter().find_map(|ivk| match pool {
            Pool::Orchard => try_note_decryption(&OrchardDomain::for_action(a), ivk, a).map(|(n, addr, _)| (n, addr)),
            Pool::Ironwood => try_note_decryption(&IronwoodDomain::for_action(a), ivk, a).map(|(n, addr, _)| (n, addr)),
        })
    };
    let chosen: Vec<usize> = if indices.is_empty() { (0..actions.len()).filter(|&i| decrypt(i).is_some()).collect() } else { indices.to_vec() };
    let mut outputs = Vec::new();
    let mut recipient: Option<Address> = None;
    for i in chosen {
        let (note, addr) = decrypt(i).ok_or(Error::WrongOvk(i as u32))?;
        match &recipient {
            None => recipient = Some(addr),
            Some(r) if r.to_raw_address_bytes() == addr.to_raw_address_bytes() => {}
            // One receipt proves one address; with indices given, a mismatch is an error.
            Some(_) if indices.is_empty() => continue,
            Some(_) => return Err(Error::AddressNotOwned),
        }
        outputs.push(IncomingOutput { index: i as u32, esk: note.esk_bytes() });
    }
    let recipient = recipient.ok_or(Error::WrongOvk(0))?;
    let mut seen = std::collections::BTreeSet::new();
    if !outputs.iter().all(|o| seen.insert(o.index)) {
        return Err(Error::DuplicateIndex(outputs[0].index));
    }
    let alpha = random_scalar(&mut rng);
    let rsk = SpendAuthorizingKey::from(sk).randomize(&alpha);
    let rk = redpallas::VerificationKey::<SpendAuth>::from(&rsk);
    let address = address_proof(pk, pool, &fvk, recipient, alpha, &rk, &mut rng)?;
    let mut r = IncomingReceipt { coin_type, pool, txid, msg: msg.to_vec(), outputs, rk: (&rk).into(), address, sig: [0; 64] };
    r.sig = (&rsk.sign(&mut rng, &signing_digest(&r))).into();
    Ok(r)
}

/// Signs arbitrary `outputs` for `recipient` (an address of `sk`), without checking them: for
/// tests that need a validly signed receipt with wrong contents. Not part of the API.
#[doc(hidden)]
#[allow(clippy::too_many_arguments)]
pub fn __sign_unchecked_for_tests(pk: &ProvingKey, coin_type: u32, pool: Pool, txid: [u8; 32], msg: &[u8], sk: &SpendingKey, recipient: Address, outputs: Vec<IncomingOutput>, mut rng: impl CryptoRng) -> Result<IncomingReceipt, Error> {
    let fvk = FullViewingKey::from(sk);
    let alpha = random_scalar(&mut rng);
    let rsk = SpendAuthorizingKey::from(sk).randomize(&alpha);
    let rk = redpallas::VerificationKey::<SpendAuth>::from(&rsk);
    let address = address_proof(pk, pool, &fvk, recipient, alpha, &rk, &mut rng)?;
    let mut r = IncomingReceipt { coin_type, pool, txid, msg: msg.to_vec(), outputs, rk: (&rk).into(), address, sig: [0; 64] };
    r.sig = (&rsk.sign(&mut rng, &signing_digest(&r))).into();
    Ok(r)
}

/// Verifies an incoming receipt against the bundle of `r.pool` in transaction `txid`. The caller
/// checks that the transaction was mined.
pub fn verify_incoming<A: Authorization, V>(vk: &VerifyingKey, r: &IncomingReceipt, expected_coin_type: u32, txid: [u8; 32], bundle: &Bundle<A, V>) -> Result<VerifiedIncoming, Error> {
    if r.coin_type != expected_coin_type {
        return Err(Error::CoinTypeMismatch(r.coin_type, expected_coin_type));
    }
    if r.txid != txid {
        return Err(Error::TxidMismatch(crate::display_txid(&r.txid)));
    }
    if r.outputs.is_empty() {
        return Err(Error::WrongOvk(0));
    }
    let rk = redpallas::VerificationKey::<SpendAuth>::try_from(r.rk).map_err(|_| Error::Malformed(0))?;
    rk.verify(&signing_digest(r), &redpallas::Signature::<SpendAuth>::from(r.sig)).map_err(|_| Error::BadSignature(0))?;
    verify_address_proof(vk, r.pool, 0, &rk, &r.address)?;
    let recipient = Option::<Address>::from(Address::from_raw_address_bytes(&r.address.address)).ok_or(Error::BadAddressProof(0))?;
    let actions = bundle.actions();
    let mut seen = std::collections::BTreeSet::new();
    let mut outputs = Vec::with_capacity(r.outputs.len());
    for o in &r.outputs {
        let a = actions.get(o.index as usize).ok_or(Error::IndexOutOfRange(o.index))?;
        if !seen.insert(o.index) {
            return Err(Error::DuplicateIndex(o.index));
        }
        let esk = Option::<EphemeralSecretKey>::from(EphemeralSecretKey::from_bytes(&o.esk)).ok_or(Error::BadOutputKey(o.index))?;
        let pk_d = *recipient.pk_d();
        let found = match r.pool {
            Pool::Orchard => try_output_recovery_with_pkd_esk(&OrchardDomain::for_action(a), pk_d, esk, a),
            Pool::Ironwood => try_output_recovery_with_pkd_esk(&IronwoodDomain::for_action(a), pk_d, esk, a),
        };
        let (note, to, memo) = found.ok_or(Error::BadOutputKey(o.index))?;
        // Recovery rebuilds the note for the pk_d it was given and checks its commitment, so the
        // note is to the proven address; checked again here explicitly.
        if to.to_raw_address_bytes() != r.address.address {
            return Err(Error::BadOutputKey(o.index));
        }
        outputs.push(VerifiedOutput { index: o.index, recipient: r.address.address, value: note.value().inner(), memo, memo_withheld: false });
    }
    Ok(VerifiedIncoming { coin_type: r.coin_type, pool: r.pool, txid: r.txid, msg: r.msg.clone(), recipient: r.address.address, outputs })
}
