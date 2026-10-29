//! Sapling receipts: ZIP 311 as the draft specifies it for Sapling.
//!
//! - **Outputs**: `(index, ock)`. The verifier recovers the note and memo from the output's
//!   `outCiphertext` and `encCiphertext` with `ock` (protocol §4.20.3); recovery recomputes
//!   `cmu`, so the opened note is the one on chain.
//! - **Spends**: `(index, cv, rk, zkproof)`, a fresh Sapling Spend proof for the note spent by
//!   spend `index` of the transaction, against the transaction's own anchor and nullifier, with
//!   a fresh `alpha` (so `rk` is unlinkable to the transaction's) and a fresh `rcv` (so `cv`
//!   hides the value). Every spend signs the receipt digest with `rsk = ask + alpha`.
//!
//! The verifier takes `anchor` and `nf` from the transaction, never from the receipt. A valid
//! proof means `rk` randomizes the `ak` that owns the note with nullifier `nf` in the tree at
//! `anchor`; a valid signature under `rk` means the signer knows `ask`.
//!
//! Wire format (pool byte 2, otherwise laid out like the Orchard receipt):
//!
//! ```text
//! unsigned := "ZRCT" | version:u8 = 1 | coin_type:u32le | pool:u8 = 2 | txid[32]
//!             | msg_len:u16le | msg | n_out:u8 | (index:u32le | ock[32])*
//!             | n_spend:u8 | (index:u32le | cv[32] | rk[32] | zkproof[192])*
//! receipt  := unsigned | spendAuthSig[64] * n_spend
//! digest   := BLAKE2b-256("ZIP311Signed" || I2LEOSP_32(coinType), unsigned)
//! ```

use bellman::gadgets::multipack;
use bls12_381::Bls12;
use ff::Field;
use groth16::{PreparedVerifyingKey, Proof};
use group::Curve;
use rand_core::CryptoRng;
use redjubjub::SpendAuth;
use sapling_crypto::{
    bundle::{Authorization, GrothProofBytes, OutputDescription},
    circuit::SpendParameters,
    keys::{OutgoingViewingKey, ProofGenerationKey, SpendAuthorizingKey},
    note_encryption::{prf_ock, Zip212Enforcement},
    prover::SpendProver,
    value::{ValueCommitTrapdoor, ValueCommitment},
    Bundle, MerklePath, Note, PaymentAddress,
};
use zcash_note_encryption::{OutgoingCipherKey, ShieldedOutput};

/// Pool byte of a Sapling receipt (0 is Orchard, 1 Ironwood).
pub const POOL_SAPLING: u8 = 2;
const MAGIC: &[u8; 4] = b"ZRCT";
const VERSION: u8 = 1;

/// One disclosed Sapling output: its index in the bundle and its outgoing cipher key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SaplingOutputDisclosure {
    pub index: u32,
    pub ock: [u8; 32],
}

/// One disclosed Sapling spend: a fresh Spend proof for the note spent at `index`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SaplingSpendDisclosure {
    pub index: u32,
    pub cv: [u8; 32],
    pub rk: [u8; 32],
    pub zkproof: GrothProofBytes,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SaplingUnsignedReceipt {
    pub coin_type: u32,
    pub txid: [u8; 32],
    pub msg: Vec<u8>,
    pub outputs: Vec<SaplingOutputDisclosure>,
    pub spends: Vec<SaplingSpendDisclosure>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SaplingReceipt {
    pub unsigned: SaplingUnsignedReceipt,
    pub sigs: Vec<[u8; 64]>,
}

/// What the payer's wallet knows about one spent note.
#[derive(Clone)]
pub struct SaplingSpendWitness {
    /// Index of the spend in the transaction's Sapling bundle.
    pub index: u32,
    pub ask: SpendAuthorizingKey,
    pub proof_generation_key: ProofGenerationKey,
    pub note: Note,
    pub diversifier: sapling_crypto::Diversifier,
    /// The note's path to the transaction's anchor.
    pub merkle_path: MerklePath,
}

/// A disclosed output as the verifier recovered it from the chain.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedSaplingOutput {
    pub index: u32,
    pub recipient: PaymentAddress,
    pub value: u64,
    pub memo: [u8; 512],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedSaplingReceipt {
    pub txid: [u8; 32],
    pub coin_type: u32,
    pub msg: Vec<u8>,
    pub outputs: Vec<VerifiedSaplingOutput>,
    /// Spend indices whose authority the payer proved.
    pub spends: Vec<u32>,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum SaplingError {
    #[error("the transaction has no Sapling bundle")]
    NoBundle,
    #[error("the receipt is for a different transaction")]
    WrongTxid,
    #[error("the receipt is for a different network")]
    WrongNetwork,
    #[error("a receipt must prove at least one spend, so only a payer can make it")]
    NoSpend,
    #[error("index {0} is not in the transaction's Sapling bundle")]
    BadIndex(u32),
    #[error("an index appears twice")]
    DuplicateIndex,
    #[error("the note does not belong to the proof generation key and diversifier")]
    BadWitness,
    #[error("the witness note is not the one spent at index {0}")]
    WrongNote(u32),
    #[error("output {0} does not open with its ock")]
    OutputNotRecovered(u32),
    #[error("spend {0}: the proof or signature does not verify")]
    SpendInvalid(u32),
    #[error("wrong number of signatures")]
    SignatureCount,
    #[error("malformed receipt: {0}")]
    Malformed(&'static str),
}

/// The Sapling outgoing cipher key of output `index`, as the payer's wallet derives it.
pub fn output_ock<A: Authorization, V>(bundle: &Bundle<A, V>, index: u32, ovk: &OutgoingViewingKey) -> Option<[u8; 32]> {
    let o = bundle.shielded_outputs().get(index as usize)?;
    Some(prf_ock(ovk, o.cv(), &o.cmu().to_bytes(), o.ephemeral_key()).0)
}

/// The digest every spend signs.
pub fn signing_digest(u: &SaplingUnsignedReceipt) -> [u8; 32] {
    let personal = crate::signing_personal(b"ZIP311Signed", u.coin_type);
    let h = blake2b_simd::Params::new().hash_length(32).personal(&personal).hash(&encode_unsigned(u));
    h.as_bytes().try_into().expect("32 bytes")
}

/// Makes a Sapling receipt: discloses `outputs` (by index and `ovk`) and proves spend authority
/// for every witness. `params` are the Sapling Spend parameters (`sapling-spend.params`).
#[allow(clippy::too_many_arguments)]
pub fn create<A: Authorization, V>(
    params: &SpendParameters,
    coin_type: u32,
    txid: [u8; 32],
    bundle: &Bundle<A, V>,
    outputs: &[(u32, OutgoingViewingKey)],
    spends: &[SaplingSpendWitness],
    msg: &[u8],
    mut rng: impl CryptoRng,
) -> Result<SaplingReceipt, SaplingError> {
    if spends.is_empty() {
        return Err(SaplingError::NoSpend);
    }
    // The encoding counts each in one byte.
    if spends.len() > usize::from(u8::MAX) {
        return Err(SaplingError::Malformed("more than 255 spends"));
    }
    if outputs.len() > usize::from(u8::MAX) {
        return Err(SaplingError::Malformed("more than 255 outputs"));
    }
    if msg.len() > u16::MAX as usize {
        return Err(SaplingError::Malformed("message too long"));
    }
    let mut out = Vec::with_capacity(outputs.len());
    for (index, ovk) in outputs {
        let ock = output_ock(bundle, *index, ovk).ok_or(SaplingError::BadIndex(*index))?;
        out.push(SaplingOutputDisclosure { index: *index, ock });
    }
    let mut disclosures = Vec::with_capacity(spends.len());
    let mut alphas = Vec::with_capacity(spends.len());
    for w in spends {
        let spend = bundle.shielded_spends().get(w.index as usize).ok_or(SaplingError::BadIndex(w.index))?;
        let vk = w.proof_generation_key.to_viewing_key();
        let addr = vk.to_payment_address(w.diversifier).ok_or(SaplingError::BadWitness)?;
        if addr != w.note.recipient() {
            return Err(SaplingError::BadWitness);
        }
        let position: u64 = w.merkle_path.position().into();
        if w.note.nf(vk.nk(), position).0 != spend.nullifier().0 {
            return Err(SaplingError::WrongNote(w.index));
        }
        let anchor = *spend.anchor();
        let alpha = jubjub::Fr::random(&mut rng);
        let rcv = ValueCommitTrapdoor::random(&mut rng);
        let cv = ValueCommitment::derive(w.note.value(), rcv.clone());
        let circuit = SpendParameters::prepare_circuit(
            w.proof_generation_key.clone(),
            w.diversifier,
            *w.note.rseed(),
            w.note.value(),
            alpha,
            rcv,
            anchor,
            w.merkle_path.clone(),
        )
        .ok_or(SaplingError::BadWitness)?;
        let proof = params.create_proof(circuit, &mut rng);
        let rk = vk.rk(alpha);
        disclosures.push(SaplingSpendDisclosure { index: w.index, cv: cv.to_bytes(), rk: <[u8; 32]>::from(rk), zkproof: SpendParameters::encode_proof(proof) });
        alphas.push(alpha);
    }
    let unsigned = SaplingUnsignedReceipt { coin_type, txid, msg: msg.to_vec(), outputs: out, spends: disclosures };
    check_indices(&unsigned)?;
    let digest = signing_digest(&unsigned);
    let sigs = spends.iter().zip(&alphas).map(|(w, alpha)| <[u8; 64]>::from(w.ask.randomize(alpha).sign(&mut rng, &digest))).collect();
    Ok(SaplingReceipt { unsigned, sigs })
}

fn check_indices(u: &SaplingUnsignedReceipt) -> Result<(), SaplingError> {
    let mut o: Vec<u32> = u.outputs.iter().map(|d| d.index).collect();
    let mut s: Vec<u32> = u.spends.iter().map(|d| d.index).collect();
    o.sort_unstable();
    s.sort_unstable();
    if o.windows(2).any(|w| w[0] == w[1]) || s.windows(2).any(|w| w[0] == w[1]) {
        return Err(SaplingError::DuplicateIndex);
    }
    Ok(())
}

/// Verifies a Sapling receipt against the transaction it names. `txid` and `bundle` come from
/// the chain, `expected_coin_type` from the verifier's own network. `pvk` is the Sapling Spend
/// verifying key ([`spend_verifying_key`] for the Zcash one).
pub fn verify<A, V>(
    pvk: &PreparedVerifyingKey<Bls12>,
    receipt: &SaplingReceipt,
    expected_coin_type: u32,
    txid: &[u8; 32],
    bundle: Option<&Bundle<A, V>>,
) -> Result<VerifiedSaplingReceipt, SaplingError>
where
    A: Authorization,
    OutputDescription<A::OutputProof>: ShieldedOutput<sapling_crypto::note_encryption::SaplingDomain>,
{
    let u = &receipt.unsigned;
    if &u.txid != txid {
        return Err(SaplingError::WrongTxid);
    }
    if u.coin_type != expected_coin_type {
        return Err(SaplingError::WrongNetwork);
    }
    if u.spends.is_empty() {
        return Err(SaplingError::NoSpend);
    }
    if receipt.sigs.len() != u.spends.len() {
        return Err(SaplingError::SignatureCount);
    }
    check_indices(u)?;
    let bundle = bundle.ok_or(SaplingError::NoBundle)?;
    let digest = signing_digest(u);

    let mut spends = Vec::with_capacity(u.spends.len());
    for (d, sig) in u.spends.iter().zip(&receipt.sigs) {
        let tx_spend = bundle.shielded_spends().get(d.index as usize).ok_or(SaplingError::BadIndex(d.index))?;
        let bad = || SaplingError::SpendInvalid(d.index);
        let cv = Option::from(ValueCommitment::from_bytes_not_small_order(&d.cv)).ok_or_else(bad)?;
        let rk = redjubjub::VerificationKey::<SpendAuth>::try_from(d.rk).map_err(|_| bad())?;
        let proof = Proof::<Bls12>::read(&d.zkproof[..]).map_err(|_| bad())?;
        let sig = redjubjub::Signature::<SpendAuth>::from(*sig);
        if !check_spend(pvk, &cv, *tx_spend.anchor(), &tx_spend.nullifier().0, &rk, &digest, &sig, &proof) {
            return Err(bad());
        }
        spends.push(d.index);
    }

    let mut outputs = Vec::with_capacity(u.outputs.len());
    for d in &u.outputs {
        let o = bundle.shielded_outputs().get(d.index as usize).ok_or(SaplingError::BadIndex(d.index))?;
        let (note, recipient, memo) = recover(o, &d.ock).ok_or(SaplingError::OutputNotRecovered(d.index))?;
        outputs.push(VerifiedSaplingOutput { index: d.index, recipient, value: note.value().inner(), memo });
    }
    Ok(VerifiedSaplingReceipt { txid: u.txid, coin_type: u.coin_type, msg: u.msg.clone(), outputs, spends })
}

fn recover<P>(o: &OutputDescription<P>, ock: &[u8; 32]) -> Option<(Note, PaymentAddress, [u8; 512])>
where
    OutputDescription<P>: ShieldedOutput<sapling_crypto::note_encryption::SaplingDomain>,
{
    let domain = sapling_crypto::note_encryption::SaplingDomain::new(Zip212Enforcement::On);
    zcash_note_encryption::try_output_recovery_with_ock(&domain, &OutgoingCipherKey(*ock), o, o.out_ciphertext())
}

/// The Sapling consensus spend check minus the binding signature, which a receipt has no use
/// for: `rk` not small order, `spendAuthSig` under `rk` over the receipt digest, and the
/// Groth16 proof against `(rk, cv, anchor, nf)` (protocol §4.17.2, the public inputs as
/// sapling-crypto's verifier lays them out).
#[allow(clippy::too_many_arguments)]
fn check_spend(
    pvk: &PreparedVerifyingKey<Bls12>,
    cv: &ValueCommitment,
    anchor: bls12_381::Scalar,
    nf: &[u8; 32],
    rk: &redjubjub::VerificationKey<SpendAuth>,
    digest: &[u8; 32],
    sig: &redjubjub::Signature<SpendAuth>,
    proof: &Proof<Bls12>,
) -> bool {
    let Some(rk_point) = Option::<jubjub::AffinePoint>::from(jubjub::AffinePoint::from_bytes((*rk).into())) else { return false };
    if bool::from(rk_point.is_small_order()) || rk.verify(digest, sig).is_err() {
        return false;
    }
    let cv_point = cv.as_inner().to_affine();
    let nf_bits = multipack::bytes_to_bits_le(nf);
    let nf_packed = multipack::compute_multipacking::<bls12_381::Scalar>(&nf_bits);
    let mut inputs = vec![rk_point.get_u(), rk_point.get_v(), cv_point.get_u(), cv_point.get_v(), anchor];
    inputs.extend(nf_packed);
    groth16::verify_proof(pvk, proof, &inputs).is_ok()
}

/// SHA-256 of the Zcash `sapling-spend.params` (the Sapling MPC result, as zcashd and
/// zcash_proofs pin it).
pub const SAPLING_SPEND_PARAMS_SHA256: &str = "8e48ffd23abb3a5fd9c5589204f32d9c31285a04b78096ba40a79b75677efc13";

/// Where Zcash wallets keep the parameters: `$ZCASH_PARAMS`, else the platform default
/// (`~/Library/Application Support/ZcashParams` on macOS, `~/.zcash-params` elsewhere).
pub fn default_params_dir() -> Option<std::path::PathBuf> {
    if let Some(d) = std::env::var_os("ZCASH_PARAMS") {
        return Some(d.into());
    }
    let home = std::path::PathBuf::from(std::env::var_os("HOME")?);
    let mac = home.join("Library/Application Support/ZcashParams");
    Some(if mac.exists() { mac } else { home.join(".zcash-params") })
}

/// The Sapling Spend verifying key, read from the front of `sapling-spend.params` (a Groth16
/// parameter file starts with its verifying key). The whole file is hashed first, so a
/// tampered key is refused.
pub fn spend_verifying_key_from(path: &std::path::Path) -> std::io::Result<PreparedVerifyingKey<Bls12>> {
    use sha2::Digest;
    let bytes = std::fs::read(path)?;
    let hash: String = sha2::Sha256::digest(&bytes).iter().map(|b| format!("{b:02x}")).collect();
    if hash != SAPLING_SPEND_PARAMS_SHA256 {
        return Err(std::io::Error::other(format!("{} is not the Zcash sapling-spend.params (SHA-256 {hash})", path.display())));
    }
    Ok(groth16::prepare_verifying_key(&groth16::VerifyingKey::<Bls12>::read(&bytes[..])?))
}

/// The Zcash Sapling Spend parameters for making receipts, checked against their hash.
pub fn spend_parameters_from(path: &std::path::Path) -> std::io::Result<SpendParameters> {
    use sha2::Digest;
    let bytes = std::fs::read(path)?;
    let hash: String = sha2::Sha256::digest(&bytes).iter().map(|b| format!("{b:02x}")).collect();
    if hash != SAPLING_SPEND_PARAMS_SHA256 {
        return Err(std::io::Error::other(format!("{} is not the Zcash sapling-spend.params", path.display())));
    }
    SpendParameters::read(&bytes[..], false)
}

/// The Sapling Spend verifying key of the Zcash parameters, embedded (cut out of the
/// hash-checked `sapling-spend.params` by `examples/extract_sapling_vk.rs`), so a verifier,
/// including the browser one, needs no parameter file.
pub fn spend_verifying_key() -> &'static PreparedVerifyingKey<Bls12> {
    static K: std::sync::OnceLock<PreparedVerifyingKey<Bls12>> = std::sync::OnceLock::new();
    K.get_or_init(|| {
        let vk = groth16::VerifyingKey::<Bls12>::read(&include_bytes!("sapling-spend-vk.bin")[..]).expect("embedded key parses");
        groth16::prepare_verifying_key(&vk)
    })
}

/// Text form: `zip311z1` and the receipt bytes in unpadded URL-safe base64.
pub const SAPLING_TEXT_PREFIX: &str = "zip311z1";

pub fn to_text(r: &SaplingReceipt) -> String {
    use base64::Engine;
    format!("{SAPLING_TEXT_PREFIX}{}", base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(encode(r)))
}

pub fn from_text(s: &str) -> Result<SaplingReceipt, SaplingError> {
    use base64::Engine;
    let body = s.trim().strip_prefix(SAPLING_TEXT_PREFIX).ok_or(SaplingError::Malformed("not a Sapling receipt"))?;
    decode(&base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(body).map_err(|_| SaplingError::Malformed("bad base64"))?)
}

// ---- encoding ----

pub fn encode_unsigned(u: &SaplingUnsignedReceipt) -> Vec<u8> {
    let mut b = Vec::with_capacity(64 + u.msg.len() + 36 * u.outputs.len() + 260 * u.spends.len());
    b.extend_from_slice(MAGIC);
    b.push(VERSION);
    b.extend_from_slice(&u.coin_type.to_le_bytes());
    b.push(POOL_SAPLING);
    b.extend_from_slice(&u.txid);
    b.extend_from_slice(&(u.msg.len() as u16).to_le_bytes());
    b.extend_from_slice(&u.msg);
    b.push(u.outputs.len() as u8);
    for o in &u.outputs {
        b.extend_from_slice(&o.index.to_le_bytes());
        b.extend_from_slice(&o.ock);
    }
    b.push(u.spends.len() as u8);
    for s in &u.spends {
        b.extend_from_slice(&s.index.to_le_bytes());
        b.extend_from_slice(&s.cv);
        b.extend_from_slice(&s.rk);
        b.extend_from_slice(&s.zkproof);
    }
    b
}

pub fn encode(r: &SaplingReceipt) -> Vec<u8> {
    let mut b = encode_unsigned(&r.unsigned);
    for s in &r.sigs {
        b.extend_from_slice(s);
    }
    b
}

struct Reader<'a>(&'a [u8]);
impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], SaplingError> {
        if self.0.len() < n {
            return Err(SaplingError::Malformed("truncated"));
        }
        let (a, b) = self.0.split_at(n);
        self.0 = b;
        Ok(a)
    }
    fn arr<const N: usize>(&mut self) -> Result<[u8; N], SaplingError> {
        Ok(self.take(N)?.try_into().expect("length checked"))
    }
    fn u8(&mut self) -> Result<u8, SaplingError> {
        Ok(self.take(1)?[0])
    }
    fn u32(&mut self) -> Result<u32, SaplingError> {
        Ok(u32::from_le_bytes(self.arr()?))
    }
}

/// Is this a Sapling receipt (pool byte 2)? Lets a caller route bytes before decoding.
pub fn is_sapling(bytes: &[u8]) -> bool {
    bytes.len() > 9 && &bytes[..4] == MAGIC && bytes[4] == VERSION && bytes[9] == POOL_SAPLING
}

pub fn decode(bytes: &[u8]) -> Result<SaplingReceipt, SaplingError> {
    let mut r = Reader(bytes);
    if r.take(4)? != MAGIC {
        return Err(SaplingError::Malformed("not a receipt"));
    }
    if r.u8()? != VERSION {
        return Err(SaplingError::Malformed("unknown version"));
    }
    let coin_type = r.u32()?;
    if r.u8()? != POOL_SAPLING {
        return Err(SaplingError::Malformed("not a Sapling receipt"));
    }
    let txid = r.arr()?;
    let msg_len = u16::from_le_bytes(r.arr()?) as usize;
    let msg = r.take(msg_len)?.to_vec();
    let n_out = r.u8()?;
    let mut outputs = Vec::with_capacity(n_out as usize);
    for _ in 0..n_out {
        outputs.push(SaplingOutputDisclosure { index: r.u32()?, ock: r.arr()? });
    }
    let n_spend = r.u8()?;
    let mut spends = Vec::with_capacity(n_spend as usize);
    for _ in 0..n_spend {
        spends.push(SaplingSpendDisclosure { index: r.u32()?, cv: r.arr()?, rk: r.arr()?, zkproof: r.arr()? });
    }
    let mut sigs = Vec::with_capacity(n_spend as usize);
    for _ in 0..n_spend {
        sigs.push(r.arr()?);
    }
    if !r.0.is_empty() {
        return Err(SaplingError::Malformed("trailing bytes"));
    }
    Ok(SaplingReceipt { unsigned: SaplingUnsignedReceipt { coin_type, txid, msg, outputs, spends }, sigs })
}
