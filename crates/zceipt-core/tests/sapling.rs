//! Sapling receipts end to end: a real Sapling bundle (spend + outputs, Groth16 proofs,
//! spend-auth and binding signatures) built with sapling-crypto, then a receipt for it.
//!
//! The Groth16 parameters are generated here (a local setup, not the Zcash ceremony), so the
//! test needs no download. Real receipts use `sapling-spend.params`.

use std::sync::OnceLock;

use rand::{rand_core::UnwrapErr, rngs::SysRng};

#[allow(non_upper_case_globals)]
const OsRng: UnwrapErr<SysRng> = UnwrapErr(SysRng);
use sapling_crypto::{
    builder::{BundleType, Builder},
    circuit::{Output, OutputParameters, Spend, SpendParameters},
    bundle::Authorized,
    note_encryption::Zip212Enforcement,
    value::NoteValue,
    zip32::ExtendedSpendingKey,
    Bundle, CommitmentTree, IncrementalWitness, Node, Note, Rseed,
};
use zceipt_core::sapling::{self, SaplingError, SaplingSpendWitness};
use zcash_protocol::value::ZatBalance;

struct Params {
    spend: SpendParameters,
    output: OutputParameters,
    pvk: groth16::PreparedVerifyingKey<bls12_381::Bls12>,
}

fn params() -> &'static Params {
    static P: OnceLock<Params> = OnceLock::new();
    P.get_or_init(|| {
        let mut rng = OsRng;
        let spend = Spend {
            value_commitment_opening: None,
            proof_generation_key: None,
            payment_address: None,
            commitment_randomness: None,
            ar: None,
            auth_path: vec![None; 32],
            anchor: None,
        };
        let output = Output { value_commitment_opening: None, payment_address: None, commitment_randomness: None, esk: None };
        let sp = groth16::generate_random_parameters::<bls12_381::Bls12, _, _>(spend, &mut rng).unwrap();
        let op = groth16::generate_random_parameters::<bls12_381::Bls12, _, _>(output, &mut rng).unwrap();
        let (mut sb, mut ob) = (vec![], vec![]);
        sp.write(&mut sb).unwrap();
        op.write(&mut ob).unwrap();
        let spend = SpendParameters::read(&sb[..], false).unwrap();
        let output = OutputParameters::read(&ob[..], false).unwrap();
        let pvk = groth16::prepare_verifying_key(&sp.vk);
        Params { spend, output, pvk }
    })
}

struct Paid {
    bundle: Bundle<Authorized, ZatBalance>,
    txid: [u8; 32],
    payer: ExtendedSpendingKey,
    witness: SaplingSpendWitness,
    output_index: u32,
}

const MEMO: &[u8] = b"invoice 42";

/// The payer holds one 50_000 zat note and pays 30_000 to a merchant.
fn pay(seed: u8) -> Paid {
    let p = params();
    let mut rng = OsRng;
    let payer = ExtendedSpendingKey::master(&[seed; 32]).unwrap();
    let merchant = ExtendedSpendingKey::master(&[seed.wrapping_add(100); 32]).unwrap();
    let dfvk = payer.to_diversifiable_full_viewing_key();
    let (_, addr) = dfvk.default_address();
    let note = Note::from_parts(addr, NoteValue::from_raw(50_000), Rseed::AfterZip212([seed; 32]));

    let mut tree = CommitmentTree::empty();
    tree.append(Node::from_cmu(&note.cmu())).unwrap();
    let wit = IncrementalWitness::from_tree(tree).unwrap();
    let anchor = wit.root().into();
    let path = wit.path().unwrap();

    let mut b = Builder::new(Zip212Enforcement::On, BundleType::DEFAULT, anchor);
    b.add_spend(dfvk.fvk().clone(), note.clone(), path.clone()).unwrap();
    let mut memo = [0u8; 512];
    memo[..MEMO.len()].copy_from_slice(MEMO);
    let (_, to) = merchant.to_diversifiable_full_viewing_key().default_address();
    b.add_output(Some(dfvk.fvk().ovk), to, NoteValue::from_raw(30_000), memo).unwrap();
    let (unauth, meta) = b.build::<SpendParameters, OutputParameters, _, ZatBalance>(&[payer.clone()], &mut rng).unwrap().unwrap();
    let sighash = [seed; 32];
    let bundle = unauth
        .create_proofs(&p.spend, &p.output, &mut rng, ())
        .apply_signatures(&mut rng, sighash, &[payer.expsk().ask().clone()])
        .unwrap();
    let witness = SaplingSpendWitness {
        index: meta.spend_index(0).unwrap() as u32,
        ask: payer.expsk().ask().clone(),
        proof_generation_key: payer.expsk().proof_generation_key(),
        note,
        diversifier: *addr.diversifier(),
        merkle_path: path,
    };
    Paid { bundle, txid: [seed ^ 0x5a; 32], payer, witness, output_index: meta.output_index(0).unwrap() as u32 }
}

fn ovk(k: &ExtendedSpendingKey) -> sapling_crypto::keys::OutgoingViewingKey {
    k.to_diversifiable_full_viewing_key().fvk().ovk
}

fn make(t: &Paid, msg: &[u8]) -> sapling::SaplingReceipt {
    sapling::create(
        &params().spend,
        1,
        t.txid,
        &t.bundle,
        &[(t.output_index, ovk(&t.payer))],
        std::slice::from_ref(&t.witness),
        msg,
        OsRng,
    )
    .unwrap()
}

#[test]
fn sapling_receipt_round_trips_and_opens_the_payment() {
    let t = pay(1);
    let r = make(&t, b"challenge-7");
    let bytes = sapling::encode(&r);
    assert!(sapling::is_sapling(&bytes));
    let back = sapling::decode(&bytes).unwrap();
    assert_eq!(back, r);
    let v = sapling::verify(&params().pvk, &back, 1, &t.txid, Some(&t.bundle)).unwrap();
    assert_eq!(v.spends, vec![t.witness.index]);
    assert_eq!(v.outputs.len(), 1);
    assert_eq!(v.outputs[0].value, 30_000);
    assert_eq!(&v.outputs[0].memo[..MEMO.len()], MEMO);
    assert_eq!(v.msg, b"challenge-7");
}

#[test]
fn the_receipt_rk_is_not_the_transaction_rk() {
    let t = pay(2);
    let r = make(&t, b"");
    let tx_rk: [u8; 32] = (*t.bundle.shielded_spends()[t.witness.index as usize].rk()).into();
    assert_ne!(r.unsigned.spends[0].rk, tx_rk);
}

#[test]
fn someone_who_only_saw_the_payment_cannot_claim_it() {
    // The merchant knows the output (it can decrypt it) but not the payer's spend key.
    let t = pay(3);
    let thief = ExtendedSpendingKey::master(&[0xee; 32]).unwrap();
    let mut w = SaplingSpendWitness {
        index: t.witness.index,
        ask: thief.expsk().ask().clone(),
        proof_generation_key: thief.expsk().proof_generation_key(),
        note: t.witness.note.clone(),
        diversifier: t.witness.diversifier,
        merkle_path: t.witness.merkle_path.clone(),
    };
    let e = sapling::create(&params().spend, 1, t.txid, &t.bundle, &[], std::slice::from_ref(&w), b"", OsRng).unwrap_err();
    assert_eq!(e, SaplingError::BadWitness);

    // Signing with the wrong key over an honest proof fails verification.
    w.proof_generation_key = t.witness.proof_generation_key.clone();
    let r = sapling::create(&params().spend, 1, t.txid, &t.bundle, &[], std::slice::from_ref(&w), b"", OsRng).unwrap();
    let e = sapling::verify(&params().pvk, &r, 1, &t.txid, Some(&t.bundle)).unwrap_err();
    assert_eq!(e, SaplingError::SpendInvalid(t.witness.index));
}

#[test]
fn a_receipt_does_not_move_to_another_transaction_or_network() {
    let a = pay(4);
    let b = pay(5);
    let r = make(&a, b"");
    assert_eq!(sapling::verify(&params().pvk, &r, 1, &b.txid, Some(&b.bundle)).unwrap_err(), SaplingError::WrongTxid);
    assert_eq!(sapling::verify(&params().pvk, &r, 133, &a.txid, Some(&a.bundle)).unwrap_err(), SaplingError::WrongNetwork);
    // Same txid claimed for another bundle: the proof is against the wrong anchor and nullifier.
    assert!(sapling::verify(&params().pvk, &r, 1, &a.txid, Some(&b.bundle)).is_err());
}

#[test]
fn every_byte_is_signed() {
    let t = pay(6);
    let r = make(&t, b"m");
    let mut edited = r.clone();
    edited.unsigned.msg = b"n".to_vec();
    assert!(matches!(sapling::verify(&params().pvk, &edited, 1, &t.txid, Some(&t.bundle)), Err(SaplingError::SpendInvalid(_))));
    let mut edited = r.clone();
    edited.unsigned.outputs.clear();
    assert!(matches!(sapling::verify(&params().pvk, &edited, 1, &t.txid, Some(&t.bundle)), Err(SaplingError::SpendInvalid(_))));
    let mut edited = r.clone();
    edited.unsigned.outputs[0].ock[0] ^= 1;
    assert!(sapling::verify(&params().pvk, &edited, 1, &t.txid, Some(&t.bundle)).is_err());
    let mut edited = r.clone();
    edited.unsigned.spends[0].zkproof[10] ^= 1;
    assert!(sapling::verify(&params().pvk, &edited, 1, &t.txid, Some(&t.bundle)).is_err());
    let mut bytes = sapling::encode(&r);
    bytes.push(0);
    assert!(sapling::decode(&bytes).is_err());
}

#[test]
fn a_receipt_without_a_spend_is_refused() {
    let t = pay(7);
    let mut r = make(&t, b"");
    r.unsigned.spends.clear();
    r.sigs.clear();
    assert_eq!(sapling::verify(&params().pvk, &r, 1, &t.txid, Some(&t.bundle)).unwrap_err(), SaplingError::NoSpend);
}

/// With the real Zcash Sapling parameters (`$ZCASH_PARAMS` or the default directory): the
/// bundle and the receipt are proved with the ceremony keys, and verified with the verifying
/// key read from `sapling-spend.params` after its SHA-256 check. Skipped when they're absent.
#[test]
fn sapling_receipt_with_the_zcash_parameters() {
    let Some(dir) = sapling::default_params_dir().filter(|d| d.join("sapling-spend.params").exists()) else {
        eprintln!("no Zcash Sapling parameters; skipped");
        return;
    };
    let spend = sapling::spend_parameters_from(&dir.join("sapling-spend.params")).unwrap();
    let output = OutputParameters::read(&std::fs::read(dir.join("sapling-output.params")).unwrap()[..], false).unwrap();
    let pvk = sapling::spend_verifying_key_from(&dir.join("sapling-spend.params")).unwrap();
    let mut rng = OsRng;
    let payer = ExtendedSpendingKey::master(&[9; 32]).unwrap();
    let dfvk = payer.to_diversifiable_full_viewing_key();
    let (_, addr) = dfvk.default_address();
    let note = Note::from_parts(addr, NoteValue::from_raw(70_000), Rseed::AfterZip212([9; 32]));
    let mut tree = CommitmentTree::empty();
    tree.append(Node::from_cmu(&note.cmu())).unwrap();
    let wit = IncrementalWitness::from_tree(tree).unwrap();
    let path = wit.path().unwrap();
    let mut b = Builder::new(Zip212Enforcement::On, BundleType::DEFAULT, wit.root().into());
    b.add_spend(dfvk.fvk().clone(), note.clone(), path.clone()).unwrap();
    let (_, to) = ExtendedSpendingKey::master(&[8; 32]).unwrap().to_diversifiable_full_viewing_key().default_address();
    b.add_output(Some(dfvk.fvk().ovk), to, NoteValue::from_raw(60_000), [0; 512]).unwrap();
    let (unauth, meta) = b.build::<SpendParameters, OutputParameters, _, ZatBalance>(&[payer.clone()], &mut rng).unwrap().unwrap();
    let bundle = unauth.create_proofs(&spend, &output, &mut rng, ()).apply_signatures(&mut rng, [9; 32], &[payer.expsk().ask().clone()]).unwrap();
    let w = SaplingSpendWitness {
        index: meta.spend_index(0).unwrap() as u32,
        ask: payer.expsk().ask().clone(),
        proof_generation_key: payer.expsk().proof_generation_key(),
        note,
        diversifier: *addr.diversifier(),
        merkle_path: path,
    };
    let oi = meta.output_index(0).unwrap() as u32;
    let r = sapling::create(&spend, 1, [7; 32], &bundle, &[(oi, dfvk.fvk().ovk)], &[w], b"", OsRng).unwrap();
    let r = sapling::from_text(&sapling::to_text(&r)).unwrap();
    let v = sapling::verify(&pvk, &r, 1, &[7; 32], Some(&bundle)).unwrap();
    assert_eq!(v.outputs[0].value, 60_000);
    // The embedded key is the same key.
    assert!(sapling::verify(sapling::spend_verifying_key(), &r, 1, &[7; 32], Some(&bundle)).is_ok());
}
