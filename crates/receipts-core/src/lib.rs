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
    keys::{FullViewingKey, OutgoingViewingKey, SpendAuthorizingKey, SpendingKey},
    note::{ExtractedNoteCommitment, Note, RandomSeed, Rho},
    note_encryption::{IronwoodDomain, OrchardDomain},
    primitives::redpallas::{self, SpendAuth},
    tree::MerklePath,
    value::{NoteValue, ValueCommitTrapdoor, ValueCommitment},
    Action, Address, Bundle, Proof,
};
use pasta_curves::pallas;
use rand_core::{CryptoRng, Rng};
use zcash_note_encryption::{try_output_recovery_with_ock, Domain, EphemeralKeyBytes, OutgoingCipherKey};

mod encoding;
pub mod tripwire;
pub use encoding::{batch_position, check_batch, DecodeError, ReceiptBatch, BATCH_TEXT_PREFIX};

/// SLIP-44 coin type for Zcash mainnet (index form).
pub const COIN_TYPE_MAINNET: u32 = 133;
/// SLIP-44 coin type for Zcash testnet and regtest (index form).
pub const COIN_TYPE_TESTNET: u32 = 1;

/// The circuit used for every spend-authority proof in a receipt. It is the current
/// network circuit, so receipts never rely on the insecure pre-NU6.2 circuit.
pub const RECEIPT_CIRCUIT: OrchardCircuitVersion = OrchardCircuitVersion::PostNu6_3;

/// Which shielded pool the disclosed bundle belongs to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
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
}

/// Proof that the spend authority behind a disclosed spend also controls `address`
/// (the Orchard analogue of ZIP 311's optional ZIP 304 address proof).
///
/// It is a second action proof, under the *same* randomized key `rk`, that spends a fresh
/// 1-zatoshi note addressed to `address`. The note is revealed (`rho`, `rseed`), so the verifier
/// recomputes its commitment and the root of a one-leaf tree, and the circuit's anchor check
/// (enforced because the value is non-zero) binds the proof to that address.
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
    pub pool: Pool,
    pub txid: [u8; 32],
    pub msg: Vec<u8>,
    pub outputs: Vec<OutputDisclosure>,
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
}

/// What a verifier learns from a valid receipt.
#[derive(Clone, Debug)]
pub struct VerifiedReceipt {
    pub coin_type: u32,
    pub pool: Pool,
    pub txid: [u8; 32],
    pub msg: Vec<u8>,
    /// Actions whose spend authority was proven by the receipt's signer.
    pub proven_spends: Vec<u32>,
    /// Addresses proven to be controlled by the spend authority of the given action.
    pub proven_addresses: Vec<(u32, [u8; 43])>,
    pub outputs: Vec<VerifiedOutput>,
}

#[derive(Clone, Debug)]
pub struct VerifiedOutput {
    pub index: u32,
    /// Raw Orchard address (43 bytes) of the recipient.
    pub recipient: [u8; 43],
    pub value: u64,
    pub memo: [u8; 512],
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum Error {
    #[error("the receipt must prove spend authority for at least one action")]
    NoSpends,
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
}

/// The digest every spend-authorization signature covers:
/// `BLAKE2b-256("ZIP311Signed" || coinType_LE32, unsignedReceipt)`.
pub fn signing_digest(unsigned: &UnsignedReceipt) -> [u8; 32] {
    let mut personal = [0u8; 16];
    personal[..12].copy_from_slice(b"ZIP311Signed");
    personal[12..].copy_from_slice(&unsigned.coin_type.to_le_bytes());
    let h = Params::new()
        .hash_length(32)
        .personal(&personal)
        .hash(&unsigned.encode());
    h.as_bytes().try_into().expect("32 bytes")
}

fn random_scalar(rng: &mut (impl Rng + CryptoRng)) -> pallas::Scalar {
    pallas::Scalar::random(rng)
}

fn random_scalar_base_bytes(rng: &mut (impl Rng + CryptoRng)) -> [u8; 32] {
    pallas::Base::random(rng).to_repr()
}

fn random_bytes(rng: &mut (impl Rng + CryptoRng)) -> [u8; 32] {
    let mut b = [0u8; 32];
    rng.fill_bytes(&mut b);
    b
}

fn check_indices<'a>(
    n_actions: usize,
    indices: impl Iterator<Item = &'a u32>,
) -> Result<(), Error> {
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

fn recover_with_ock<A>(
    pool: Pool,
    ock: &OutgoingCipherKey,
    action: &Action<A>,
) -> Option<(Note, Address, [u8; 512])> {
    let out = &action.encrypted_note().out_ciphertext;
    match pool {
        Pool::Orchard => {
            try_output_recovery_with_ock(&OrchardDomain::for_action(action), ock, action, out)
        }
        Pool::Ironwood => {
            try_output_recovery_with_ock(&IronwoodDomain::for_action(action), ock, action, out)
        }
    }
}

/// The note version used for address proofs in `pool`.
fn pool_note_version(pool: Pool) -> orchard::note::NoteVersion {
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
fn dummy_output(rho: Rho, version: orchard::note::NoteVersion, rng: &mut (impl Rng + CryptoRng)) -> Note {
    let addr = loop {
        if let Some(sk) = Option::<SpendingKey>::from(SpendingKey::from_bytes(random_bytes(rng))) {
            break FullViewingKey::from(&sk).address_at(0u32, orchard::keys::Scope::External);
        }
    };
    loop {
        if let Some(rseed) = Option::<RandomSeed>::from(RandomSeed::from_bytes(random_bytes(rng), &rho)) {
            if let Some(n) = Option::<Note>::from(Note::from_parts(addr, NoteValue::ZERO, rho, rseed, version)) {
                return n;
            }
        }
    }
}

fn random_trapdoor(rng: &mut (impl Rng + CryptoRng)) -> ValueCommitTrapdoor {
    loop {
        let r = random_scalar(rng);
        if let Some(t) = Option::<ValueCommitTrapdoor>::from(ValueCommitTrapdoor::from_bytes(r.to_repr())) {
            return t;
        }
    }
}

fn address_proof(
    pk: &ProvingKey,
    pool: Pool,
    fvk: &FullViewingKey,
    address: Address,
    alpha: pallas::Scalar,
    rk: &redpallas::VerificationKey<SpendAuth>,
    rng: &mut (impl Rng + CryptoRng),
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
    let rcv = random_trapdoor(rng);
    let cv_net = ValueCommitment::derive(NoteValue::from_raw(1) - NoteValue::ZERO, rcv.clone());
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

fn verify_address_proof(
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
    let cv_net = Option::<ValueCommitment>::from(ValueCommitment::from_bytes(&a.cv_net)).ok_or_else(bad)?;
    let cmx = Option::<ExtractedNoteCommitment>::from(ExtractedNoteCommitment::from_bytes(&a.cmx)).ok_or_else(bad)?;
    let instance = Instance::from_parts(anchor, cv_net, nf, rk.clone(), cmx, Flags::ENABLED).ok_or_else(bad)?;
    Proof::new(a.proof.clone()).verify(vk, &[instance]).map_err(|_| bad())
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
    mut rng: impl Rng + CryptoRng,
) -> Result<Receipt, Error> {
    if spends.is_empty() {
        return Err(Error::NoSpends);
    }
    let actions = bundle.actions();
    let out_idx: Vec<u32> = outputs.iter().map(|(i, _)| *i as u32).collect();
    let spend_idx: Vec<u32> = spends.iter().map(|s| s.index as u32).collect();
    check_indices(actions.len(), out_idx.iter())?;
    check_indices(actions.len(), spend_idx.iter())?;

    // Outputs: derive the ock and check it actually opens the output.
    let mut out_disclosures = Vec::with_capacity(outputs.len());
    for (i, ovk) in outputs {
        let action = &actions[*i];
        let ock = derive_ock(pool, ovk, action);
        recover_with_ock(pool, &ock, action).ok_or(Error::WrongOvk(*i as u32))?;
        out_disclosures.push(OutputDisclosure {
            index: *i as u32,
            ock: ock.0,
        });
    }

    // Spends: re-prove each spent note against the bundle's own anchor.
    let mut spend_disclosures = Vec::with_capacity(spends.len());
    let mut signing_keys = Vec::with_capacity(spends.len());
    for w in spends {
        let action = &actions[w.index];
        let fvk = FullViewingKey::from(&w.sk);
        let nf_old = w.note.nullifier(&fvk);
        if &nf_old != action.nullifier() {
            return Err(Error::WrongNullifier(w.index as u32));
        }
        let cmx_old: ExtractedNoteCommitment = w.note.commitment().into();
        if w.merkle_path.root(cmx_old) != *bundle.anchor() {
            return Err(Error::WrongAnchor);
        }
        let spend = SpendInfo::new(fvk.clone(), w.note, w.merkle_path.clone())
            .ok_or(Error::NoteNotOwned)?;

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
                if let Some(n) = Option::<Note>::from(Note::from_parts(
                    dummy_addr,
                    NoteValue::ZERO,
                    rho,
                    rseed,
                    w.note.version(),
                )) {
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
        let ask = SpendAuthorizingKey::from(&w.sk);
        let rsk = ask.randomize(&alpha);
        let rk = redpallas::VerificationKey::<SpendAuth>::from(&rsk);
        let cmx: ExtractedNoteCommitment = dummy.commitment().into();

        let circuit = Circuit::from_action_context(spend, dummy, alpha, rcv, RECEIPT_CIRCUIT)
            .ok_or(Error::Proving)?;
        let instance = Instance::from_parts(*bundle.anchor(), cv_net.clone(), nf_old, rk.clone(), cmx, Flags::ENABLED)
            .ok_or(Error::Proving)?;
        let proof = Proof::create(pk, &[circuit], &[instance], &mut rng).map_err(|_| Error::Proving)?;

        let address = match w.prove_address {
            Some(addr) => Some(address_proof(pk, pool, &fvk, addr, alpha, &rk, &mut rng)?),
            None => None,
        };
        spend_disclosures.push(SpendDisclosure {
            index: w.index as u32,
            cv_net: cv_net.to_bytes(),
            rk: (&rk).into(),
            cmx: cmx.to_bytes(),
            proof: proof.as_ref().to_vec(),
            address,
        });
        signing_keys.push(rsk);
    }

    let unsigned = UnsignedReceipt {
        coin_type,
        pool,
        txid,
        msg: msg.to_vec(),
        outputs: out_disclosures,
        spends: spend_disclosures,
    };
    let digest = signing_digest(&unsigned);
    let spend_auth_sigs = signing_keys
        .iter()
        .map(|rsk| (&rsk.sign(&mut rng, &digest)).into())
        .collect();
    Ok(Receipt {
        unsigned,
        spend_auth_sigs,
    })
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
    let u = &receipt.unsigned;
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
    check_indices(actions.len(), u.outputs.iter().map(|o| &o.index))?;
    check_indices(actions.len(), u.spends.iter().map(|s| &s.index))?;

    let digest = signing_digest(u);
    let mut proven_addresses = Vec::new();
    for (s, sig) in u.spends.iter().zip(&receipt.spend_auth_sigs) {
        let action = &actions[s.index as usize];
        let rk = redpallas::VerificationKey::<SpendAuth>::try_from(s.rk)
            .map_err(|_| Error::Malformed(s.index))?;
        let sig = redpallas::Signature::<SpendAuth>::from(*sig);
        rk.verify(&digest, &sig).map_err(|_| Error::BadSignature(s.index))?;

        let cv_net = Option::<ValueCommitment>::from(ValueCommitment::from_bytes(&s.cv_net))
            .ok_or(Error::Malformed(s.index))?;
        let cmx = Option::<ExtractedNoteCommitment>::from(ExtractedNoteCommitment::from_bytes(&s.cmx))
            .ok_or(Error::Malformed(s.index))?;
        let instance = Instance::from_parts(*bundle.anchor(), cv_net, *action.nullifier(), rk, cmx, Flags::ENABLED)
            .ok_or(Error::Malformed(s.index))?;
        Proof::new(s.proof.clone())
            .verify(vk, &[instance])
            .map_err(|_| Error::BadProof(s.index))?;
        if let Some(a) = &s.address {
            let rk = redpallas::VerificationKey::<SpendAuth>::try_from(s.rk).map_err(|_| Error::Malformed(s.index))?;
            verify_address_proof(vk, pool, s.index, &rk, a)?;
            proven_addresses.push((s.index, a.address));
        }
    }

    let mut outputs = Vec::with_capacity(u.outputs.len());
    for o in &u.outputs {
        let action = &actions[o.index as usize];
        let (note, addr, memo) = recover_with_ock(pool, &OutgoingCipherKey(o.ock), action)
            .ok_or(Error::BadOutputKey(o.index))?;
        outputs.push(VerifiedOutput {
            index: o.index,
            recipient: addr.to_raw_address_bytes(),
            value: note.value().inner(),
            memo,
        });
    }

    Ok(VerifiedReceipt {
        coin_type: u.coin_type,
        pool: u.pool,
        txid: u.txid,
        msg: u.msg.clone(),
        proven_spends: u.spends.iter().map(|s| s.index).collect(),
        proven_addresses,
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

/// Verifying key for receipts. Building it takes a few seconds; cache it.
pub fn verifying_key() -> VerifyingKey {
    VerifyingKey::build(RECEIPT_CIRCUIT)
}
