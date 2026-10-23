//! Receipts: ZIP 311 payment disclosures for Zcash Orchard and Ironwood.
//!
//! A receipt lets the sender of a shielded transaction prove, to anyone they choose:
//!
//! - **what was paid**: for each disclosed output, the recipient address, value and memo,
//!   recovered from the on-chain ciphertext with that output's outgoing cipher key (`ock`);
//! - **who paid it**: for each disclosed spend, a fresh Halo 2 proof that the prover knows
//!   the note spent in that action (same anchor, same nullifier), under a freshly
//!   randomized key `rk`, plus a spend-authorization signature by `rk` over the whole
//!   receipt.
//!
//! Nothing else about the sender's wallet is revealed: no viewing key, no address, no other
//! transaction. The `msg` field binds a verifier's challenge into the signature, so a
//! receipt can be made interactive.
//!
//! ZIP 311 (Draft) specifies this for Sapling and leaves Orchard as a TODO. This crate is a
//! proposed Orchard/Ironwood instantiation: the Sapling "spend proof" becomes an Orchard
//! action proof that spends the disclosed note and creates a zero-value dummy output, and
//! the Sapling `ock` becomes the Orchard `ock`. See `docs/SPEC.md` in the repository.

use blake2b_simd::Params;
use ff::{Field, PrimeField};
use orchard::{
    builder::SpendInfo,
    bundle::{Authorization, Flags},
    circuit::{Circuit, Instance, OrchardCircuitVersion, ProvingKey, VerifyingKey},
    keys::{FullViewingKey, OutgoingViewingKey, SpendAuthorizingKey, SpendValidatingKey, SpendingKey},
    note::{ExtractedNoteCommitment, Note, RandomSeed, Rho},
    note_encryption::{IronwoodDomain, OrchardDomain},
    primitives::redpallas::{self, SpendAuth},
    tree::MerklePath,
    value::{NoteValue, ValueCommitTrapdoor, ValueCommitment},
    Action, Address, Bundle, Proof,
};
use pasta_curves::pallas;
use rand_core::CryptoRng;
use zcash_note_encryption::{try_output_recovery_with_ock, Domain, EphemeralKeyBytes, OutgoingCipherKey};

pub mod builder;
#[cfg(feature = "extensions")]
pub mod deposit;
mod encoding;
#[cfg(feature = "orchard-ext")]
pub mod incoming;
#[cfg(feature = "extensions")]
pub mod payreq;
#[cfg(feature = "extensions")]
pub mod preflight;
#[cfg(feature = "extensions")]
pub mod reserve;
#[cfg(feature = "extensions")]
pub mod screened;
#[cfg(feature = "extensions")]
pub mod signin;
#[cfg(feature = "extensions")]
pub mod tripwire;
pub use builder::{Network, ReceiptBuilder};
pub use encoding::{batch_position, check_batch, DecodeError, ReceiptBatch, BATCH_TEXT_PREFIX, PREPARED_TEXT_PREFIX, TEXT_PREFIX};

/// SLIP-44 coin type for Zcash mainnet (index form).
pub const COIN_TYPE_MAINNET: u32 = 133;
/// SLIP-44 coin type for Zcash testnet and regtest (index form).
pub const COIN_TYPE_TESTNET: u32 = 1;

/// The circuit used for every spend-authority proof in a receipt. It is the current
/// network circuit, so receipts never rely on the insecure pre-NU6.2 circuit.
pub const RECEIPT_CIRCUIT: OrchardCircuitVersion = OrchardCircuitVersion::PostNu6_3;

/// Which shielded pool the disclosed bundle belongs to.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Pool {
    Orchard,
    Ironwood,
}

impl Pool {
    fn to_byte(self) -> u8 {
        match self {
            Pool::Orchard => 0,
            Pool::Ironwood => 1,
        }
    }
    fn from_byte(b: u8) -> Option<Self> {
        match b {
            0 => Some(Pool::Orchard),
            1 => Some(Pool::Ironwood),
            _ => None,
        }
    }
}

/// A disclosed output: the action index and the outgoing cipher key that opens it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OutputDisclosure {
    pub index: u32,
    pub ock: [u8; 32],
}

/// An output disclosed by its note-commitment opening, without the memo (ZIP 311's per-field
/// disclosure, zcash/zcash#2631). An `ock` would let the verifier decrypt the whole note,
/// memo included; `(ψ, rcm)` instead of `rseed` binds the recipient and value to the on-chain
/// `cmx` but gives no key to the ciphertext (`esk` derives from `rseed`, which stays secret).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OpenedOutput {
    pub index: u32,
    /// Raw Orchard address of the recipient.
    pub address: [u8; 43],
    pub value: u64,
    pub psi: [u8; 32],
    pub rcm: [u8; 32],
}

/// A proof of spend authority over one action's spent note.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SpendDisclosure {
    pub index: u32,
    /// Value commitment of the disclosure statement (fresh trapdoor; hides the value).
    pub cv_net: [u8; 32],
    /// Freshly randomized spend validating key.
    pub rk: [u8; 32],
    /// Commitment to the zero-value dummy output of the disclosure statement.
    pub cmx: [u8; 32],
    /// Halo 2 proof of the Orchard action statement.
    pub proof: Vec<u8>,
    /// Optional proof that the same spend authority controls a named payment address.
    pub address: Option<AddressProof>,
    /// Optional proof of where the spent note came from (format v4).
    pub source: Option<SourceProof>,
}

/// Proof that the note spent in a disclosed action is the note created by output `index` of an
/// earlier transaction `txid` (the receipt's spend pool): where the money came from.
///
/// It is a third action proof, under the *same* randomized key `rk`, that spends the very same
/// note (same nullifier, so the same note) against the root of a one-leaf tree holding the source
/// action's `cmx`, which the verifier reads from the source transaction itself. Orchard nullifiers
/// do not depend on the note's tree position, so the one-leaf tree is as good as the real one.
///
/// As for address proofs, the circuit only checks the anchor when the spent value is non-zero,
/// so `cv_net` is fixed with a zero trapdoor and never taken from the prover:
/// - value hidden: `cv_net = ValueCommit_0(1)` and the proof's output carries `v - 1`;
/// - value revealed: `cv_net = ValueCommit_0(v)` and the proof's output (to a throwaway address)
///   is opened, so the verifier sees it carries 0 and the spent note carries exactly `v`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SourceProof {
    /// The transaction whose output created the spent note.
    pub txid: [u8; 32],
    /// The action index of that output in the source transaction's bundle of the receipt's pool.
    pub index: u32,
    pub value: SourceValue,
    pub proof: Vec<u8>,
}

/// Whether a source proof reveals the spent note's value, and the proof's own output.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SourceValue {
    /// Value hidden: only the commitment to the proof's output (which carries `v - 1`).
    Hidden { cmx: [u8; 32] },
    /// Value `v` (at least 1) revealed: the proof's zero-value output, opened.
    Revealed { value: u64, address: [u8; 43], rseed: [u8; 32] },
}

impl SourceProof {
    /// The revealed value of the spent note, if any.
    pub fn revealed_value(&self) -> Option<u64> {
        match self.value {
            SourceValue::Hidden { .. } => None,
            SourceValue::Revealed { value, .. } => Some(value),
        }
    }
}

/// Where a spent note came from, for `create`. The wallet knows this from its own records.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SourceWitness {
    pub txid: [u8; 32],
    pub index: u32,
    /// The `cmx` of that action, read from the source transaction (checked against the note).
    pub cmx: [u8; 32],
    /// Reveal the note's value to the verifier.
    pub reveal_value: bool,
}

/// Proof that the spend authority behind a disclosed spend also controls `address`
/// (the Orchard analogue of ZIP 311's optional ZIP 304 address proof).
///
/// It is a second action proof, under the *same* randomized key `rk`, that spends a fresh
/// 1-zatoshi note addressed to `address`. The note is revealed (`rho`, `rseed`), so the verifier
/// recomputes its commitment and the root of a one-leaf tree, and the circuit's anchor check
/// binds the proof to that address.
///
/// The circuit only enforces the anchor when the spent value is non-zero, so the verifier must
/// know that the witnessed value is 1. As in ZIP 304, the value commitment uses a zero trapdoor:
/// `cv_net` must equal `ValueCommit_0(1)`, which the verifier checks. (A version of this code that
/// took `cv_net` from the prover let anyone claim any address by witnessing a zero-value note to
/// their own address; see `tests/roundtrip.rs::claiming_someone_elses_sender_address_is_refused`.)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AddressProof {
    pub address: [u8; 43],
    pub rho: [u8; 32],
    pub rseed: [u8; 32],
    pub nf: [u8; 32],
    pub cv_net: [u8; 32],
    pub cmx: [u8; 32],
    pub proof: Vec<u8>,
}

/// The part of a receipt covered by the signatures.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UnsignedReceipt {
    pub coin_type: u32,
    /// The pool of the spends (and of the outputs, unless `output_pool` says otherwise).
    pub pool: Pool,
    /// The pool of the disclosed outputs, when it differs from the spends' (format v3).
    pub output_pool: Option<Pool>,
    pub txid: [u8; 32],
    pub msg: Vec<u8>,
    pub outputs: Vec<OutputDisclosure>,
    /// Outputs disclosed with their memo withheld (format v5): recipient and value only.
    pub opened: Vec<OpenedOutput>,
    pub spends: Vec<SpendDisclosure>,
}

/// A complete receipt: the unsigned part plus one spend-authorization signature per spend.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Receipt {
    pub unsigned: UnsignedReceipt,
    pub spend_auth_sigs: Vec<[u8; 64]>,
}

/// Everything needed to prove authority over the note spent in one action.
pub struct SpendWitness {
    /// Index of the action in the bundle that spent `note`.
    pub index: usize,
    /// Spending key that owns `note`.
    pub sk: SpendingKey,
    /// The spent note.
    pub note: Note,
    /// Merkle path of `note` to the bundle's anchor.
    pub merkle_path: MerklePath,
    /// Also prove that this spend authority controls this address (it must belong to `sk`).
    pub prove_address: Option<Address>,
    /// Also prove which earlier transaction output created `note`.
    pub source: Option<SourceWitness>,
}

/// Like [`SpendWitness`], with the full viewing key instead of the spending key: everything
/// [`prepare`] needs to make the proofs. The spend authorizing key is only needed to sign
/// ([`PreparedReceipt::sign`]), which can happen on another device, such as a hardware wallet.
#[derive(Clone)]
pub struct ViewingSpendWitness {
    pub index: usize,
    pub fvk: FullViewingKey,
    pub note: Note,
    pub merkle_path: MerklePath,
    pub prove_address: Option<Address>,
    pub source: Option<SourceWitness>,
}

impl From<&SpendWitness> for ViewingSpendWitness {
    fn from(w: &SpendWitness) -> Self {
        ViewingSpendWitness {
            index: w.index,
            fvk: FullViewingKey::from(&w.sk),
            note: w.note,
            merkle_path: w.merkle_path.clone(),
            prove_address: w.prove_address,
            source: w.source.clone(),
        }
    }
}

/// A receipt with every proof made but not yet signed. A separate signer (a hardware wallet) is
/// given the unsigned receipt and the randomizers ([`Self::unsigned`], [`Self::alphas`]) and signs
/// with [`sign_prepared`], which computes the digest itself and checks each `rk`: a signer that
/// signed whatever digest the host handed it, with the same `ask`, could be made to authorize a
/// transaction. The randomizers link the receipt to its spends, so treat them as secret.
#[derive(Clone)]
pub struct PreparedReceipt {
    unsigned: UnsignedReceipt,
    alphas: Vec<pallas::Scalar>,
}

impl PreparedReceipt {
    pub(crate) fn from_parts(unsigned: UnsignedReceipt, alphas: Vec<pallas::Scalar>) -> Self {
        PreparedReceipt { unsigned, alphas }
    }

    /// The unsigned receipt, to show the user and give the signer.
    pub fn unsigned(&self) -> &UnsignedReceipt {
        &self.unsigned
    }

    /// One randomizer per spend, in spend order, for the signer.
    pub fn alphas(&self) -> &[pallas::Scalar] {
        &self.alphas
    }

    /// The same proofs under another signed message. The proofs don't cover the message (the
    /// signatures do), so one prepared receipt can be signed for several messages; the receipts
    /// share their `rk`s, so whoever sees two of them can tell they are for the same spends.
    pub fn with_message(mut self, msg: &[u8]) -> Result<Self, Error> {
        if msg.len() > u16::MAX as usize {
            return Err(Error::TooLarge);
        }
        self.unsigned.msg = msg.to_vec();
        Ok(self)
    }

    /// Signs here with the spend authorizing keys, one per spend, in spend order.
    pub fn sign(self, asks: &[SpendAuthorizingKey], rng: impl CryptoRng) -> Result<Receipt, Error> {
        let sigs = sign_prepared(&self.unsigned, &self.alphas, asks, rng)?;
        self.apply_signatures(sigs)
    }

    /// Attaches signatures made elsewhere (a hardware wallet), checking each under its spend's
    /// `rk`, so a wrong key or a wrong digest is caught here rather than by the verifier.
    pub fn apply_signatures(self, sigs: Vec<[u8; 64]>) -> Result<Receipt, Error> {
        if sigs.len() != self.unsigned.spends.len() {
            return Err(Error::SignatureCount);
        }
        let digest = signing_digest(&self.unsigned);
        for (s, sig) in self.unsigned.spends.iter().zip(&sigs) {
            let rk = redpallas::VerificationKey::<SpendAuth>::try_from(s.rk).map_err(|_| Error::Malformed(s.index))?;
            rk.verify(&digest, &redpallas::Signature::<SpendAuth>::from(*sig)).map_err(|_| Error::BadSignature(s.index))?;
        }
        Ok(Receipt { unsigned: self.unsigned, spend_auth_sigs: sigs })
    }
}

impl Receipt {
    /// Checks only the spend-authorization signatures, under the `rk`s the receipt carries. It
    /// needs no chain data and proves nothing on its own (anyone can sign under a key they made
    /// up), but an edited receipt fails here, before a verifier asks a server for anything.
    pub fn check_signatures(&self) -> Result<(), Error> {
        if self.spend_auth_sigs.len() != self.unsigned.spends.len() {
            return Err(Error::SignatureCount);
        }
        let digest = signing_digest(&self.unsigned);
        for (s, sig) in self.unsigned.spends.iter().zip(&self.spend_auth_sigs) {
            let rk = redpallas::VerificationKey::<SpendAuth>::try_from(s.rk).map_err(|_| Error::Malformed(s.index))?;
            rk.verify(&digest, &redpallas::Signature::<SpendAuth>::from(*sig)).map_err(|_| Error::BadSignature(s.index))?;
        }
        Ok(())
    }
}

/// The verifier's challenge a receipt's message carries: the rest of the first line starting
/// `challenge:` (lines end at LF; a trailing CR is ignored), if that is 6 to 64 lowercase hex
/// digits; otherwise none. A request's challenge matches only if equal.
pub fn challenge_of(msg: &str) -> Option<String> {
    msg.split('\n')
        .map(|l| l.strip_suffix('\r').unwrap_or(l))
        .find_map(|l| l.strip_prefix("challenge:"))
        .filter(|c| (6..=64).contains(&c.len()) && c.bytes().all(|x| matches!(x, b'0'..=b'9' | b'a'..=b'f')))
        .map(str::to_string)
}

/// The reference signer for a prepared receipt: computes the receipt digest itself from
/// `unsigned` (never takes a digest from the caller), checks that every spend's `rk` is
/// `ak` randomized by its `alpha` (so it only signs for keys it holds, as the receipt says), and
/// signs. A hardware wallet should do the same, after showing the txid, outputs and message.
pub fn sign_prepared(
    unsigned: &UnsignedReceipt,
    alphas: &[pallas::Scalar],
    asks: &[SpendAuthorizingKey],
    mut rng: impl CryptoRng,
) -> Result<Vec<[u8; 64]>, Error> {
    if asks.len() != unsigned.spends.len() || alphas.len() != unsigned.spends.len() {
        return Err(Error::SignatureCount);
    }
    let digest = signing_digest(unsigned);
    let mut sigs = Vec::with_capacity(asks.len());
    for ((s, ask), alpha) in unsigned.spends.iter().zip(asks).zip(alphas) {
        let rsk = ask.randomize(alpha);
        let rk: [u8; 32] = (&redpallas::VerificationKey::<SpendAuth>::from(&rsk)).into();
        if rk != s.rk {
            return Err(Error::BadSignature(s.index));
        }
        sigs.push((&rsk.sign(&mut rng, &digest)).into());
    }
    Ok(sigs)
}

/// What a verifier learns from a valid receipt.
#[derive(Clone, Debug)]
pub struct VerifiedReceipt {
    pub coin_type: u32,
    pub pool: Pool,
    /// Where the disclosed outputs are, if not in `pool`.
    pub output_pool: Option<Pool>,
    pub txid: [u8; 32],
    pub msg: Vec<u8>,
    /// Actions whose spend authority was proven by the receipt's signer.
    pub proven_spends: Vec<u32>,
    /// Addresses proven to be controlled by the spend authority of the given action.
    pub proven_addresses: Vec<(u32, [u8; 43])>,
    /// Where the note spent by the given action came from, proven against the source transaction.
    pub sources: Vec<VerifiedSource>,
    pub outputs: Vec<VerifiedOutput>,
}

/// A proven link: the note spent by action `spend` was created by output `index` of `txid`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedSource {
    pub spend: u32,
    pub txid: [u8; 32],
    pub index: u32,
    /// The note's value, if the payer revealed it.
    pub value: Option<u64>,
}

#[derive(Clone, Debug)]
pub struct VerifiedOutput {
    pub index: u32,
    /// Raw Orchard address (43 bytes) of the recipient.
    pub recipient: [u8; 43],
    pub value: u64,
    /// All zero when `memo_withheld`.
    pub memo: [u8; 512],
    /// The sender disclosed this output without its memo.
    pub memo_withheld: bool,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum Error {
    #[error("the receipt must prove spend authority for at least one action")]
    NoSpends,
    #[error("the transaction has no {0:?} bundle")]
    NoBundle(Pool),
    #[error("action index {0} is out of range for this bundle")]
    IndexOutOfRange(u32),
    #[error("action index {0} is disclosed more than once")]
    DuplicateIndex(u32),
    #[error("the note does not belong to the spending key")]
    NoteNotOwned,
    #[error("action {0} does not spend the given note")]
    WrongNullifier(u32),
    #[error("the Merkle path does not lead to the bundle's anchor")]
    WrongAnchor,
    #[error("the outgoing viewing key does not open output {0}")]
    WrongOvk(u32),
    #[error("proving failed")]
    Proving,
    #[error("receipt is for transaction {0}, not this one")]
    TxidMismatch(String),
    #[error("receipt is for coin type {0}, expected {1}")]
    CoinTypeMismatch(u32, u32),
    #[error("receipt pool does not match the bundle")]
    PoolMismatch,
    #[error("the spend proof for action {0} is invalid")]
    BadProof(u32),
    #[error("the signature for action {0} is invalid")]
    BadSignature(u32),
    #[error("malformed field in the disclosure for action {0}")]
    Malformed(u32),
    #[error("output {0} could not be recovered with the disclosed key")]
    BadOutputKey(u32),
    #[error("the number of signatures does not match the number of spends")]
    SignatureCount,
    #[error("the address to prove does not belong to the spending key")]
    AddressNotOwned,
    #[error("the address proof for action {0} is invalid")]
    BadAddressProof(u32),
    #[error("too large to encode: at most 65,535 message bytes, 255 outputs and 255 spends")]
    TooLarge,
    #[error("the source proof for action {0} is invalid")]
    BadSourceProof(u32),
    #[error("the source transaction output for action {0} is not available to the verifier")]
    SourceUnavailable(u32),
    #[error("the source given for action {0} did not create the spent note")]
    WrongSource(u32),
    #[error("a note of value zero has no provable source")]
    ZeroValueSource,
    #[error("the spent note is not in the screened set (or the set's list doesn't give the proof's root)")]
    NotInSet,
    #[error("the screened-set proof for action {0} is invalid")]
    BadScreenedProof(u32),
    #[error("the notes' value commitments don't add up to the stated total")]
    BadTotal,
    #[error("the opening for output {0} does not match its note commitment")]
    BadOpening(u32),
    #[error("{0} need receipts-core's `orchard-ext` feature (the orchard patch in vendor/)")]
    NeedsOrchardExt(&'static str),
}

/// The digest every spend-authorization signature covers:
/// `BLAKE2b-256("ZIP311Signed" || coinType_LE32, unsignedReceipt)`.
pub(crate) fn signing_personal(tag: &[u8; 12], coin_type: u32) -> [u8; 16] {
    let mut personal = [0u8; 16];
    personal[..12].copy_from_slice(tag);
    personal[12..].copy_from_slice(&coin_type.to_le_bytes());
    personal
}

pub fn signing_digest(unsigned: &UnsignedReceipt) -> [u8; 32] {
    let personal = signing_personal(b"ZIP311Signed", unsigned.coin_type);
    let h = Params::new().hash_length(32).personal(&personal).hash(&unsigned.encode());
    h.as_bytes().try_into().expect("32 bytes")
}

pub(crate) fn random_scalar(rng: &mut impl CryptoRng) -> pallas::Scalar {
    pallas::Scalar::random(rng)
}

fn random_scalar_base_bytes(rng: &mut impl CryptoRng) -> [u8; 32] {
    pallas::Base::random(rng).to_repr()
}

fn random_bytes(rng: &mut impl CryptoRng) -> [u8; 32] {
    let mut b = [0u8; 32];
    rng.fill_bytes(&mut b);
    b
}

fn check_indices<'a>(n_actions: usize, indices: impl Iterator<Item = &'a u32>) -> Result<(), Error> {
    let mut seen = std::collections::BTreeSet::new();
    for &i in indices {
        if i as usize >= n_actions {
            return Err(Error::IndexOutOfRange(i));
        }
        if !seen.insert(i) {
            return Err(Error::DuplicateIndex(i));
        }
    }
    Ok(())
}

fn derive_ock<A>(pool: Pool, ovk: &OutgoingViewingKey, action: &Action<A>) -> OutgoingCipherKey {
    let epk = EphemeralKeyBytes(action.encrypted_note().epk_bytes);
    let cmx = action.cmx().to_bytes();
    match pool {
        Pool::Orchard => OrchardDomain::derive_ock(ovk, action.cv_net(), &cmx, &epk),
        Pool::Ironwood => IronwoodDomain::derive_ock(ovk, action.cv_net(), &cmx, &epk),
    }
}

fn recover_with_ock<A>(pool: Pool, ock: &OutgoingCipherKey, action: &Action<A>) -> Option<(Note, Address, [u8; 512])> {
    let out = &action.encrypted_note().out_ciphertext;
    match pool {
        Pool::Orchard => try_output_recovery_with_ock(&OrchardDomain::for_action(action), ock, action, out),
        Pool::Ironwood => try_output_recovery_with_ock(&IronwoodDomain::for_action(action), ock, action, out),
    }
}

/// The note version used for address proofs in `pool`.
pub(crate) fn pool_note_version(pool: Pool) -> orchard::note::NoteVersion {
    match pool {
        Pool::Orchard => orchard::note::NoteVersion::V2,
        Pool::Ironwood => orchard::note::NoteVersion::V3,
    }
}

/// Merkle path of position 0 in a tree that holds a single leaf.
fn single_leaf_path() -> MerklePath {
    use incrementalmerkletree::{Hashable, Level};
    use orchard::tree::MerkleHashOrchard;
    let auth: [MerkleHashOrchard; 32] = core::array::from_fn(|i| MerkleHashOrchard::empty_root(Level::from(i as u8)));
    MerklePath::from_parts(0, auth)
}

/// A zero-value note to a throwaway address with the given `rho`, like Orchard dummy outputs.
fn dummy_output(rho: Rho, version: orchard::note::NoteVersion, rng: &mut impl CryptoRng) -> Note {
    note_to_throwaway(rho, NoteValue::ZERO, version, rng)
}

/// A note of `value` to a throwaway address with the given `rho`.
pub(crate) fn note_to_throwaway(rho: Rho, value: NoteValue, version: orchard::note::NoteVersion, rng: &mut impl CryptoRng) -> Note {
    let addr = loop {
        if let Some(sk) = Option::<SpendingKey>::from(SpendingKey::from_bytes(random_bytes(rng))) {
            break FullViewingKey::from(&sk).address_at(0u32, orchard::keys::Scope::External);
        }
    };
    loop {
        if let Some(rseed) = Option::<RandomSeed>::from(RandomSeed::from_bytes(random_bytes(rng), &rho)) {
            if let Some(n) = Option::<Note>::from(Note::from_parts(addr, value, rho, rseed, version)) {
                return n;
            }
        }
    }
}

pub(crate) fn zero_trapdoor() -> ValueCommitTrapdoor {
    Option::from(ValueCommitTrapdoor::from_bytes([0; 32])).expect("zero is a canonical scalar")
}

/// `ValueCommit_0(1 - 0)`: the value commitment every address proof must carry (ZIP 304's `cv`).
pub fn address_proof_cv_net() -> ValueCommitment {
    ValueCommitment::derive(NoteValue::from_raw(1) - NoteValue::ZERO, zero_trapdoor())
}

pub(crate) fn address_proof(
    pk: &ProvingKey,
    pool: Pool,
    fvk: &FullViewingKey,
    address: Address,
    alpha: pallas::Scalar,
    rk: &redpallas::VerificationKey<SpendAuth>,
    rng: &mut impl CryptoRng,
) -> Result<AddressProof, Error> {
    fvk.scope_for_address(&address).ok_or(Error::AddressNotOwned)?;
    let version = pool_note_version(pool);
    let (rho, rseed, note) = loop {
        let Some(rho) = Option::<Rho>::from(Rho::from_bytes(&random_scalar_base_bytes(rng))) else { continue };
        let Some(rseed) = Option::<RandomSeed>::from(RandomSeed::from_bytes(random_bytes(rng), &rho)) else { continue };
        if let Some(n) = Option::<Note>::from(Note::from_parts(address, NoteValue::from_raw(1), rho, rseed, version)) {
            break (rho, rseed, n);
        }
    };
    let path = single_leaf_path();
    let cmx_note: ExtractedNoteCommitment = note.commitment().into();
    let anchor = path.root(cmx_note);
    let nf = note.nullifier(fvk);
    let spend = SpendInfo::new(fvk.clone(), note, path).ok_or(Error::AddressNotOwned)?;
    let out_rho = Option::<Rho>::from(Rho::from_bytes(&nf.to_bytes())).ok_or(Error::Proving)?;
    let dummy = dummy_output(out_rho, version, rng);
    let rcv = zero_trapdoor();
    let cv_net = address_proof_cv_net();
    let cmx: ExtractedNoteCommitment = dummy.commitment().into();
    let circuit = Circuit::from_action_context(spend, dummy, alpha, rcv, RECEIPT_CIRCUIT).ok_or(Error::Proving)?;
    let instance = Instance::from_parts(anchor, cv_net.clone(), nf, rk.clone(), cmx, Flags::ENABLED).ok_or(Error::Proving)?;
    let proof = Proof::create(pk, &[circuit], &[instance], &mut *rng).map_err(|_| Error::Proving)?;
    Ok(AddressProof {
        address: address.to_raw_address_bytes(),
        rho: rho.to_bytes(),
        rseed: *rseed.as_bytes(),
        nf: nf.to_bytes(),
        cv_net: cv_net.to_bytes(),
        cmx: cmx.to_bytes(),
        proof: proof.as_ref().to_vec(),
    })
}

/// The anchor an address proof is verified against: the root of the one-leaf tree holding the
/// revealed 1-zatoshi note to the claimed address (`None` if the fields don't form a note).
pub fn address_proof_anchor(pool: Pool, a: &AddressProof) -> Option<[u8; 32]> {
    let address = Option::<Address>::from(Address::from_raw_address_bytes(&a.address))?;
    let rho = Option::<Rho>::from(Rho::from_bytes(&a.rho))?;
    let rseed = Option::<RandomSeed>::from(RandomSeed::from_bytes(a.rseed, &rho))?;
    let note = Option::<Note>::from(Note::from_parts(address, NoteValue::from_raw(1), rho, rseed, pool_note_version(pool)))?;
    Some(single_leaf_path().root(note.commitment().into()).to_bytes())
}

pub(crate) fn verify_address_proof(
    vk: &VerifyingKey,
    pool: Pool,
    index: u32,
    rk: &redpallas::VerificationKey<SpendAuth>,
    a: &AddressProof,
) -> Result<(), Error> {
    let bad = || Error::BadAddressProof(index);
    let address = Option::<Address>::from(Address::from_raw_address_bytes(&a.address)).ok_or_else(bad)?;
    let rho = Option::<Rho>::from(Rho::from_bytes(&a.rho)).ok_or_else(bad)?;
    let rseed = Option::<RandomSeed>::from(RandomSeed::from_bytes(a.rseed, &rho)).ok_or_else(bad)?;
    let note = Option::<Note>::from(Note::from_parts(address, NoteValue::from_raw(1), rho, rseed, pool_note_version(pool))).ok_or_else(bad)?;
    let anchor = single_leaf_path().root(note.commitment().into());
    let nf = Option::<orchard::note::Nullifier>::from(orchard::note::Nullifier::from_bytes(&a.nf)).ok_or_else(bad)?;
    // The value must be 1 for the circuit to enforce the anchor: `cv_net` is fixed, not the prover's.
    let cv_net = address_proof_cv_net();
    if a.cv_net != cv_net.to_bytes() {
        return Err(bad());
    }
    let cmx = Option::<ExtractedNoteCommitment>::from(ExtractedNoteCommitment::from_bytes(&a.cmx)).ok_or_else(bad)?;
    let instance = Instance::from_parts(anchor, cv_net, nf, rk.clone(), cmx, Flags::ENABLED).ok_or_else(bad)?;
    Proof::new(a.proof.clone()).verify(vk, &[instance]).map_err(|_| bad())
}

/// The value commitment a source proof must carry: `ValueCommit_0(1)` when the value is hidden,
/// `ValueCommit_0(v)` when it is revealed. `None` for a revealed value of zero, which would let
/// the circuit skip its anchor check.
pub fn source_proof_cv_net(value: Option<u64>) -> Option<ValueCommitment> {
    let v = value.unwrap_or(1);
    (v >= 1).then(|| ValueCommitment::derive(NoteValue::from_raw(v) - NoteValue::ZERO, zero_trapdoor()))
}

/// The anchor a source proof is verified against: the root of the one-leaf tree holding the
/// source output's `cmx` (`None` if `cmx` is not a valid commitment).
pub fn source_proof_anchor(source_cmx: &[u8; 32]) -> Option<orchard::Anchor> {
    let cmx = Option::<ExtractedNoteCommitment>::from(ExtractedNoteCommitment::from_bytes(source_cmx))?;
    Some(single_leaf_path().root(cmx))
}

/// The `cmx` public input of a source proof for the spend whose nullifier is `nf`: the hidden
/// output's commitment, or the commitment of the opened zero-value output.
pub fn source_proof_cmx(pool: Pool, nf: &[u8; 32], s: &SourceProof) -> Option<[u8; 32]> {
    match &s.value {
        SourceValue::Hidden { cmx } => Some(*cmx),
        SourceValue::Revealed { address, rseed, .. } => {
            let nf = Option::<orchard::note::Nullifier>::from(orchard::note::Nullifier::from_bytes(nf))?;
            source_output_cmx(pool, &nf, address, rseed).map(|c| c.to_bytes())
        }
    }
}

/// The commitment of a revealed source proof's output: zero value to `address`, `rho = nf`.
pub(crate) fn source_output_cmx(pool: Pool, nf: &orchard::note::Nullifier, address: &[u8; 43], rseed: &[u8; 32]) -> Option<ExtractedNoteCommitment> {
    let address = Option::<Address>::from(Address::from_raw_address_bytes(address))?;
    let rho = Option::<Rho>::from(Rho::from_bytes(&nf.to_bytes()))?;
    let rseed = Option::<RandomSeed>::from(RandomSeed::from_bytes(*rseed, &rho))?;
    let note = Option::<Note>::from(Note::from_parts(address, NoteValue::ZERO, rho, rseed, pool_note_version(pool)))?;
    Some(note.commitment().into())
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn source_proof(
    pk: &ProvingKey,
    pool: Pool,
    index: u32,
    fvk: &FullViewingKey,
    note: Note,
    src: &SourceWitness,
    alpha: pallas::Scalar,
    rk: &redpallas::VerificationKey<SpendAuth>,
    rng: &mut impl CryptoRng,
) -> Result<SourceProof, Error> {
    let cmx_src: ExtractedNoteCommitment = note.commitment().into();
    if cmx_src.to_bytes() != src.cmx {
        return Err(Error::WrongSource(index));
    }
    let v = note.value().inner();
    if v == 0 {
        return Err(Error::ZeroValueSource);
    }
    let path = single_leaf_path();
    let anchor = path.root(cmx_src);
    let nf = note.nullifier(fvk);
    let spend = SpendInfo::new(fvk.clone(), note, path).ok_or(Error::NoteNotOwned)?;
    let out_rho = Option::<Rho>::from(Rho::from_bytes(&nf.to_bytes())).ok_or(Error::Proving)?;
    let out_value = if src.reveal_value { 0 } else { v - 1 };
    let out = note_to_throwaway(out_rho, NoteValue::from_raw(out_value), pool_note_version(pool), rng);
    let cv_net = source_proof_cv_net(src.reveal_value.then_some(v)).ok_or(Error::ZeroValueSource)?;
    let cmx: ExtractedNoteCommitment = out.commitment().into();
    let circuit = Circuit::from_action_context(spend, out, alpha, zero_trapdoor(), RECEIPT_CIRCUIT).ok_or(Error::Proving)?;
    let instance = Instance::from_parts(anchor, cv_net, nf, rk.clone(), cmx, Flags::ENABLED).ok_or(Error::Proving)?;
    let proof = Proof::create(pk, &[circuit], &[instance], &mut *rng).map_err(|_| Error::Proving)?;
    let value = if src.reveal_value {
        SourceValue::Revealed { value: v, address: out.recipient().to_raw_address_bytes(), rseed: *out.rseed().as_bytes() }
    } else {
        SourceValue::Hidden { cmx: cmx.to_bytes() }
    };
    Ok(SourceProof { txid: src.txid, index: src.index, value, proof: proof.as_ref().to_vec() })
}

/// `source_proof`, exposed for tests that build receipts by hand. Not part of the API.
#[doc(hidden)]
#[allow(clippy::too_many_arguments)]
pub fn __source_proof_for_tests(
    pk: &ProvingKey,
    pool: Pool,
    index: u32,
    fvk: &FullViewingKey,
    note: Note,
    src: &SourceWitness,
    alpha: pallas::Scalar,
    rk: &redpallas::VerificationKey<SpendAuth>,
    rng: &mut impl CryptoRng,
) -> Result<SourceProof, Error> {
    source_proof(pk, pool, index, fvk, note, src, alpha, rk, rng)
}

/// Checks a source proof for the spend at action `index` (nullifier `nf`, key `rk`), given the
/// `cmx` of the source output as read from the source transaction.
pub(crate) fn verify_source_proof(
    vk: &VerifyingKey,
    pool: Pool,
    index: u32,
    rk: &redpallas::VerificationKey<SpendAuth>,
    nf: &orchard::note::Nullifier,
    s: &SourceProof,
    source_cmx: &[u8; 32],
) -> Result<(), Error> {
    let bad = || Error::BadSourceProof(index);
    let anchor = source_proof_anchor(source_cmx).ok_or_else(bad)?;
    // Fixed by the verifier, never taken from the prover: this is what forces a non-zero value.
    let cv_net = source_proof_cv_net(s.revealed_value()).ok_or_else(bad)?;
    // Revealed: the opened output carries 0, so the spent note carries exactly the revealed value.
    let cmx = source_proof_cmx(pool, &nf.to_bytes(), s).ok_or_else(bad)?;
    let cmx = Option::<ExtractedNoteCommitment>::from(ExtractedNoteCommitment::from_bytes(&cmx)).ok_or_else(bad)?;
    let instance = Instance::from_parts(anchor, cv_net, *nf, rk.clone(), cmx, Flags::ENABLED).ok_or_else(bad)?;
    Proof::new(s.proof.clone()).verify(vk, &[instance]).map_err(|_| bad())
}

/// Looks up the `cmx` of output `index` in the `pool` bundle of transaction `txid`, for source
/// proofs. Return `None` if the transaction or output is unknown (the receipt is then refused).
pub type SourceLookup<'a> = &'a dyn Fn(Pool, &[u8; 32], u32) -> Option<[u8; 32]>;

/// Reads the source output's `cmx` from a source transaction's bundle (for `SourceLookup`s).
pub fn output_cmx<A: Authorization, V>(bundle: &Bundle<A, V>, index: u32) -> Option<[u8; 32]> {
    bundle.actions().get(index as usize).map(|a| a.cmx().to_bytes())
}

/// Creates a receipt for `bundle`, which was mined in transaction `txid`.
///
/// `outputs` lists the actions to disclose together with the outgoing viewing key used
/// when they were created. `spends` must contain at least one spend witness.
#[allow(clippy::too_many_arguments)]
pub fn create<A: Authorization, V>(
    pk: &ProvingKey,
    coin_type: u32,
    pool: Pool,
    txid: [u8; 32],
    bundle: &Bundle<A, V>,
    msg: &[u8],
    outputs: &[(usize, OutgoingViewingKey)],
    spends: &[SpendWitness],
    rng: impl CryptoRng,
) -> Result<Receipt, Error> {
    create_cross(pk, coin_type, pool, bundle, pool, bundle, txid, msg, outputs, spends, rng)
}

/// Like `create`, for a transaction whose spends are in one pool's bundle and whose disclosed
/// outputs are in another's (Orchard notes spent into Ironwood outputs after NU6.3).
#[allow(clippy::too_many_arguments)]
pub fn create_cross<A: Authorization, V>(
    pk: &ProvingKey,
    coin_type: u32,
    pool: Pool,
    bundle: &Bundle<A, V>,
    output_pool: Pool,
    output_bundle: &Bundle<A, V>,
    txid: [u8; 32],
    msg: &[u8],
    outputs: &[(usize, OutgoingViewingKey)],
    spends: &[SpendWitness],
    rng: impl CryptoRng,
) -> Result<Receipt, Error> {
    create_cross_ext(pk, coin_type, pool, bundle, output_pool, output_bundle, txid, msg, outputs, &[], spends, rng)
}

/// Like `create_cross`, also disclosing the outputs in `withheld_memo` without their memos
/// (recipient and value only, format v5).
#[allow(clippy::too_many_arguments)]
pub fn create_cross_ext<A: Authorization, V>(
    pk: &ProvingKey,
    coin_type: u32,
    pool: Pool,
    bundle: &Bundle<A, V>,
    output_pool: Pool,
    output_bundle: &Bundle<A, V>,
    txid: [u8; 32],
    msg: &[u8],
    outputs: &[(usize, OutgoingViewingKey)],
    withheld_memo: &[(usize, OutgoingViewingKey)],
    spends: &[SpendWitness],
    mut rng: impl CryptoRng,
) -> Result<Receipt, Error> {
    let viewing: Vec<ViewingSpendWitness> = spends.iter().map(ViewingSpendWitness::from).collect();
    let prepared = prepare(pk, coin_type, pool, bundle, output_pool, output_bundle, txid, msg, outputs, withheld_memo, &viewing, &mut rng)?;
    let asks: Vec<SpendAuthorizingKey> = spends.iter().map(|w| SpendAuthorizingKey::from(&w.sk)).collect();
    prepared.sign(&asks, rng)
}

/// Makes every proof of a receipt from viewing keys alone, leaving the signatures to
/// [`PreparedReceipt::sign`] or an external signer ([`PreparedReceipt::apply_signatures`]).
#[allow(clippy::too_many_arguments)]
pub fn prepare<A: Authorization, V>(
    pk: &ProvingKey,
    coin_type: u32,
    pool: Pool,
    bundle: &Bundle<A, V>,
    output_pool: Pool,
    output_bundle: &Bundle<A, V>,
    txid: [u8; 32],
    msg: &[u8],
    outputs: &[(usize, OutgoingViewingKey)],
    withheld_memo: &[(usize, OutgoingViewingKey)],
    spends: &[ViewingSpendWitness],
    mut rng: impl CryptoRng,
) -> Result<PreparedReceipt, Error> {
    if spends.is_empty() {
        return Err(Error::NoSpends);
    }
    // The encoding's length fields are u16 (message) and u8 (outputs, spends).
    if msg.len() > u16::MAX as usize || outputs.len() > u8::MAX as usize || withheld_memo.len() > u8::MAX as usize || spends.len() > u8::MAX as usize {
        return Err(Error::TooLarge);
    }
    let actions = bundle.actions();
    let out_actions = output_bundle.actions();
    let out_idx: Vec<u32> = outputs.iter().chain(withheld_memo).map(|(i, _)| *i as u32).collect();
    let spend_idx: Vec<u32> = spends.iter().map(|s| s.index as u32).collect();
    check_indices(out_actions.len(), out_idx.iter())?;
    check_indices(actions.len(), spend_idx.iter())?;

    // Outputs: derive the ock and check it actually opens the output.
    let mut out_disclosures = Vec::with_capacity(outputs.len());
    for (i, ovk) in outputs {
        let action = &out_actions[*i];
        let ock = derive_ock(output_pool, ovk, action);
        recover_with_ock(output_pool, &ock, action).ok_or(Error::WrongOvk(*i as u32))?;
        out_disclosures.push(OutputDisclosure { index: *i as u32, ock: ock.0 });
    }
    #[cfg_attr(not(feature = "orchard-ext"), allow(unused_mut))]
    let mut opened = Vec::with_capacity(withheld_memo.len());
    #[cfg(not(feature = "orchard-ext"))]
    if !withheld_memo.is_empty() {
        return Err(Error::NeedsOrchardExt("outputs with the memo withheld"));
    }
    #[cfg(feature = "orchard-ext")]
    for (i, ovk) in withheld_memo {
        let action = &out_actions[*i];
        let ock = derive_ock(output_pool, ovk, action);
        let (note, addr, _memo) = recover_with_ock(output_pool, &ock, action).ok_or(Error::WrongOvk(*i as u32))?;
        let (psi, rcm) = note.commitment_opening();
        opened.push(OpenedOutput { index: *i as u32, address: addr.to_raw_address_bytes(), value: note.value().inner(), psi, rcm });
    }

    // Spends: re-prove each spent note against the bundle's own anchor.
    let mut spend_disclosures = Vec::with_capacity(spends.len());
    let mut alphas = Vec::with_capacity(spends.len());
    for w in spends {
        let action = &actions[w.index];
        let fvk = w.fvk.clone();
        let nf_old = w.note.nullifier(&fvk);
        if &nf_old != action.nullifier() {
            return Err(Error::WrongNullifier(w.index as u32));
        }
        let cmx_old: ExtractedNoteCommitment = w.note.commitment().into();
        if w.merkle_path.root(cmx_old) != *bundle.anchor() {
            return Err(Error::WrongAnchor);
        }
        let spend = SpendInfo::new(fvk.clone(), w.note, w.merkle_path.clone()).ok_or(Error::NoteNotOwned)?;

        // Zero-value dummy output to a throwaway address, as Orchard dummy notes do.
        let rho: Rho = action.rho(); // = Rho::from_nf_old(action.nullifier), which equals nf_old
        let dummy_addr = loop {
            if let Some(sk) = Option::<SpendingKey>::from(SpendingKey::from_bytes(random_bytes(&mut rng))) {
                break FullViewingKey::from(&sk).address_at(0u32, orchard::keys::Scope::External);
            }
        };
        let dummy = loop {
            let rseed = Option::<RandomSeed>::from(RandomSeed::from_bytes(random_bytes(&mut rng), &rho));
            if let Some(rseed) = rseed {
                if let Some(n) = Option::<Note>::from(Note::from_parts(dummy_addr, NoteValue::ZERO, rho, rseed, w.note.version())) {
                    break n;
                }
            }
        };

        let alpha = random_scalar(&mut rng);
        let rcv = loop {
            let r = random_scalar(&mut rng);
            if let Some(t) = Option::<ValueCommitTrapdoor>::from(ValueCommitTrapdoor::from_bytes(r.to_repr())) {
                break t;
            }
        };
        let cv_net = ValueCommitment::derive(w.note.value() - NoteValue::ZERO, rcv.clone());
        let rk = SpendValidatingKey::from(fvk.clone()).randomize(&alpha);
        let cmx: ExtractedNoteCommitment = dummy.commitment().into();

        let circuit = Circuit::from_action_context(spend, dummy, alpha, rcv, RECEIPT_CIRCUIT).ok_or(Error::Proving)?;
        let instance = Instance::from_parts(*bundle.anchor(), cv_net.clone(), nf_old, rk.clone(), cmx, Flags::ENABLED).ok_or(Error::Proving)?;
        let proof = Proof::create(pk, &[circuit], &[instance], &mut rng).map_err(|_| Error::Proving)?;

        let address = match w.prove_address {
            Some(addr) => Some(address_proof(pk, pool, &fvk, addr, alpha, &rk, &mut rng)?),
            None => None,
        };
        let source = match &w.source {
            Some(src) => Some(source_proof(pk, pool, w.index as u32, &fvk, w.note, src, alpha, &rk, &mut rng)?),
            None => None,
        };
        spend_disclosures.push(SpendDisclosure {
            index: w.index as u32,
            cv_net: cv_net.to_bytes(),
            rk: (&rk).into(),
            cmx: cmx.to_bytes(),
            proof: proof.as_ref().to_vec(),
            address,
            source,
        });
        alphas.push(alpha);
    }

    let unsigned = UnsignedReceipt {
        coin_type,
        pool,
        output_pool: (output_pool != pool).then_some(output_pool),
        txid,
        msg: msg.to_vec(),
        outputs: out_disclosures,
        opened,
        spends: spend_disclosures,
    };
    Ok(PreparedReceipt { unsigned, alphas })
}

/// Verifies `receipt` against `bundle`, the Orchard or Ironwood bundle of transaction
/// `txid`. The caller is responsible for checking that `txid` was mined.
pub fn verify<A: Authorization, V>(
    vk: &VerifyingKey,
    receipt: &Receipt,
    expected_coin_type: u32,
    pool: Pool,
    txid: [u8; 32],
    bundle: &Bundle<A, V>,
) -> Result<VerifiedReceipt, Error> {
    if receipt.unsigned.output_pool.is_some() {
        return Err(Error::PoolMismatch); // needs both bundles: use verify_tx_bundles
    }
    verify_cross(vk, receipt, expected_coin_type, pool, txid, bundle, bundle, &no_sources)
}

/// A `SourceLookup` that knows no transactions: receipts with source proofs are refused.
fn no_sources(_: Pool, _: &[u8; 32], _: u32) -> Option<[u8; 32]> {
    None
}

/// Like `verify`, also checking source proofs against the outputs `sources` returns.
pub fn verify_with_sources<A: Authorization, V>(
    vk: &VerifyingKey,
    receipt: &Receipt,
    expected_coin_type: u32,
    pool: Pool,
    txid: [u8; 32],
    bundle: &Bundle<A, V>,
    sources: SourceLookup<'_>,
) -> Result<VerifiedReceipt, Error> {
    if receipt.unsigned.output_pool.is_some() {
        return Err(Error::PoolMismatch);
    }
    verify_cross(vk, receipt, expected_coin_type, pool, txid, bundle, bundle, sources)
}

/// Verifies a receipt against a whole transaction, computing its txid here: the entry point for
/// callers holding a parsed transaction. (The bundle-level functions below trust the caller to
/// pass the bundles of the transaction the receipt names.) Source proofs need
/// [`verify_tx_bundles_with_sources`].
pub fn verify_transaction(
    vk: &VerifyingKey,
    receipt: &Receipt,
    expected_coin_type: u32,
    tx: &zcash_primitives::transaction::Transaction,
) -> Result<VerifiedReceipt, Error> {
    let txid: [u8; 32] = *tx.txid().as_ref();
    if txid != receipt.unsigned.txid {
        return Err(Error::TxidMismatch(display_txid(&receipt.unsigned.txid)));
    }
    verify_tx_bundles(vk, receipt, expected_coin_type, txid, tx.orchard_bundle(), tx.ironwood_bundle())
}

/// Verifies a receipt against a transaction's Orchard and Ironwood bundles, whichever pools
/// the receipt's spends and outputs are in. The caller must pass the bundles of the transaction
/// whose txid is `txid` (prefer [`verify_transaction`]).
pub fn verify_tx_bundles<A: Authorization, V>(
    vk: &VerifyingKey,
    receipt: &Receipt,
    expected_coin_type: u32,
    txid: [u8; 32],
    orchard: Option<&Bundle<A, V>>,
    ironwood: Option<&Bundle<A, V>>,
) -> Result<VerifiedReceipt, Error> {
    verify_tx_bundles_with_sources(vk, receipt, expected_coin_type, txid, orchard, ironwood, &no_sources)
}

/// Like `verify_tx_bundles`, also checking source proofs against the outputs `sources` returns.
/// A receipt with a source proof whose output `sources` does not know is refused.
pub fn verify_tx_bundles_with_sources<A: Authorization, V>(
    vk: &VerifyingKey,
    receipt: &Receipt,
    expected_coin_type: u32,
    txid: [u8; 32],
    orchard: Option<&Bundle<A, V>>,
    ironwood: Option<&Bundle<A, V>>,
    sources: SourceLookup<'_>,
) -> Result<VerifiedReceipt, Error> {
    let u = &receipt.unsigned;
    let pick = |p: Pool| match p {
        Pool::Orchard => orchard,
        Pool::Ironwood => ironwood,
    };
    let spends = pick(u.pool).ok_or(Error::PoolMismatch)?;
    let outs = match u.output_pool {
        None => spends,
        Some(p) => pick(p).ok_or(Error::PoolMismatch)?,
    };
    verify_cross(vk, receipt, expected_coin_type, u.pool, txid, spends, outs, sources)
}

#[allow(clippy::too_many_arguments)]
fn verify_cross<A: Authorization, V>(
    vk: &VerifyingKey,
    receipt: &Receipt,
    expected_coin_type: u32,
    pool: Pool,
    txid: [u8; 32],
    bundle: &Bundle<A, V>,
    output_bundle: &Bundle<A, V>,
    sources: SourceLookup<'_>,
) -> Result<VerifiedReceipt, Error> {
    let u = &receipt.unsigned;
    let output_pool = u.output_pool.unwrap_or(u.pool);
    if u.txid != txid {
        return Err(Error::TxidMismatch(display_txid(&u.txid)));
    }
    if u.coin_type != expected_coin_type {
        return Err(Error::CoinTypeMismatch(u.coin_type, expected_coin_type));
    }
    if u.pool != pool {
        return Err(Error::PoolMismatch);
    }
    if u.spends.is_empty() {
        return Err(Error::NoSpends);
    }
    if receipt.spend_auth_sigs.len() != u.spends.len() {
        return Err(Error::SignatureCount);
    }
    let actions = bundle.actions();
    let out_actions = output_bundle.actions();
    check_indices(out_actions.len(), u.outputs.iter().map(|o| &o.index).chain(u.opened.iter().map(|o| &o.index)))?;
    check_indices(actions.len(), u.spends.iter().map(|s| &s.index))?;

    let digest = signing_digest(u);
    let mut proven_addresses = Vec::new();
    let mut proven_sources = Vec::new();
    for (s, sig) in u.spends.iter().zip(&receipt.spend_auth_sigs) {
        let action = &actions[s.index as usize];
        let rk = redpallas::VerificationKey::<SpendAuth>::try_from(s.rk).map_err(|_| Error::Malformed(s.index))?;
        let sig = redpallas::Signature::<SpendAuth>::from(*sig);
        rk.verify(&digest, &sig).map_err(|_| Error::BadSignature(s.index))?;

        let cv_net = Option::<ValueCommitment>::from(ValueCommitment::from_bytes(&s.cv_net)).ok_or(Error::Malformed(s.index))?;
        let cmx = Option::<ExtractedNoteCommitment>::from(ExtractedNoteCommitment::from_bytes(&s.cmx)).ok_or(Error::Malformed(s.index))?;
        let instance = Instance::from_parts(*bundle.anchor(), cv_net, *action.nullifier(), rk, cmx, Flags::ENABLED).ok_or(Error::Malformed(s.index))?;
        Proof::new(s.proof.clone()).verify(vk, &[instance]).map_err(|_| Error::BadProof(s.index))?;
        if let Some(a) = &s.address {
            let rk = redpallas::VerificationKey::<SpendAuth>::try_from(s.rk).map_err(|_| Error::Malformed(s.index))?;
            verify_address_proof(vk, pool, s.index, &rk, a)?;
            proven_addresses.push((s.index, a.address));
        }
        if let Some(src) = &s.source {
            let rk = redpallas::VerificationKey::<SpendAuth>::try_from(s.rk).map_err(|_| Error::Malformed(s.index))?;
            let source_cmx = sources(pool, &src.txid, src.index).ok_or(Error::SourceUnavailable(s.index))?;
            verify_source_proof(vk, pool, s.index, &rk, action.nullifier(), src, &source_cmx)?;
            proven_sources.push(VerifiedSource { spend: s.index, txid: src.txid, index: src.index, value: src.revealed_value() });
        }
    }

    let mut outputs = Vec::with_capacity(u.outputs.len());
    for o in &u.outputs {
        let action = &out_actions[o.index as usize];
        let (note, addr, memo) = recover_with_ock(output_pool, &OutgoingCipherKey(o.ock), action).ok_or(Error::BadOutputKey(o.index))?;
        outputs.push(VerifiedOutput { index: o.index, recipient: addr.to_raw_address_bytes(), value: note.value().inner(), memo, memo_withheld: false });
    }
    #[cfg(not(feature = "orchard-ext"))]
    if !u.opened.is_empty() {
        return Err(Error::NeedsOrchardExt("outputs with the memo withheld"));
    }
    #[cfg(feature = "orchard-ext")]
    for o in &u.opened {
        let action = &out_actions[o.index as usize];
        let bad = || Error::BadOpening(o.index);
        let addr = Option::<Address>::from(Address::from_raw_address_bytes(&o.address)).ok_or_else(bad)?;
        // rho of an Orchard output is the nullifier of its action's spend.
        let cmx = orchard::note::extracted_commitment_from_opening(&addr, NoteValue::from_raw(o.value), &action.rho(), &o.psi, &o.rcm).ok_or_else(bad)?;
        if cmx.to_bytes() != action.cmx().to_bytes() {
            return Err(bad());
        }
        outputs.push(VerifiedOutput { index: o.index, recipient: o.address, value: o.value, memo: [0; 512], memo_withheld: true });
    }
    outputs.sort_by_key(|o| o.index);

    Ok(VerifiedReceipt {
        coin_type: u.coin_type,
        pool: u.pool,
        output_pool: u.output_pool,
        txid: u.txid,
        msg: u.msg.clone(),
        proven_spends: u.spends.iter().map(|s| s.index).collect(),
        proven_addresses,
        sources: proven_sources,
        outputs,
    })
}

/// Displays a txid the way block explorers do (byte-reversed hex).
pub fn display_txid(txid: &[u8; 32]) -> String {
    let mut r = *txid;
    r.reverse();
    r.iter().map(|b| format!("{b:02x}")).collect()
}

/// Proving key for receipts. Building it takes a few seconds; cache it.
pub fn proving_key() -> ProvingKey {
    ProvingKey::build(RECEIPT_CIRCUIT)
}

/// The Orchard circuit's commitment parameters (k = 11), precomputed. They are deterministic
/// (derived by hashing to the curve), and `params_match_derivation` checks these bytes against a
/// fresh derivation, so shipping them changes nothing but speed.
#[cfg(feature = "orchard-ext")]
const ORCHARD_PARAMS_K11: &[u8] = include_bytes!("orchard-params-k11.bin");

/// Verifying key for receipts. Uses the precomputed parameters (about 2.7x faster); cache it.
#[cfg(feature = "orchard-ext")]
pub fn verifying_key() -> VerifyingKey {
    VerifyingKey::build_with_params(ORCHARD_PARAMS_K11, RECEIPT_CIRCUIT).unwrap_or_else(|_| VerifyingKey::build(RECEIPT_CIRCUIT))
}

/// Verifying key for receipts (stock orchard: every parameter is derived). Cache it.
#[cfg(not(feature = "orchard-ext"))]
pub fn verifying_key() -> VerifyingKey {
    VerifyingKey::build(RECEIPT_CIRCUIT)
}

/// The verifying key built the slow way, deriving every parameter (for checking the cache).
pub fn verifying_key_slow() -> VerifyingKey {
    VerifyingKey::build(RECEIPT_CIRCUIT)
}
