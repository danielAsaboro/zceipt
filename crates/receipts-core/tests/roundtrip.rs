//! End-to-end receipts over real Orchard/Ironwood bundles built in memory.

use incrementalmerkletree::{Hashable, Marking, Retention};
use orchard::{
    builder::{Builder, BundleType},
    bundle::{Authorized, BundleVersion, Flags, TxVersion},
    circuit::{OrchardCircuitVersion, ProvingKey},
    keys::{FullViewingKey, PreparedIncomingViewingKey, Scope, SpendAuthorizingKey, SpendingKey},
    note::ExtractedNoteCommitment,
    note_encryption::{IronwoodDomain, OrchardDomain},
    tree::{MerkleHashOrchard, MerklePath},
    value::NoteValue,
    Bundle, Note,
};
use rand::{rand_core::UnwrapErr, rngs::SysRng};

#[allow(non_upper_case_globals)]
const OsRng: UnwrapErr<SysRng> = UnwrapErr(SysRng);
use receipts_core::{
    create, verify, Error, Pool, Receipt, SpendWitness, COIN_TYPE_MAINNET, COIN_TYPE_TESTNET,
};
use shardtree::{store::memory::MemoryShardStore, ShardTree};
use std::sync::OnceLock;
use zcash_note_encryption::try_note_decryption;


fn keys() -> &'static (ProvingKey, orchard::circuit::VerifyingKey) {
    static K: OnceLock<(ProvingKey, orchard::circuit::VerifyingKey)> = OnceLock::new();
    K.get_or_init(|| (receipts_core::proving_key(), receipts_core::verifying_key()))
}

/// Proving key the network uses for bundles of `version`.
fn network_pk(version: BundleVersion) -> &'static ProvingKey {
    static POST_NU6_3: OnceLock<ProvingKey> = OnceLock::new();
    static FIXED: OnceLock<ProvingKey> = OnceLock::new();
    match version.circuit_version() {
        OrchardCircuitVersion::PostNu6_3 => POST_NU6_3.get_or_init(|| ProvingKey::build(OrchardCircuitVersion::PostNu6_3)),
        v => FIXED.get_or_init(|| ProvingKey::build(v)),
    }
}

fn single_leaf_witness(cmx: &ExtractedNoteCommitment) -> (MerkleHashOrchard, MerklePath) {
    let leaf = MerkleHashOrchard::from_cmx(cmx);
    let mut tree: ShardTree<MemoryShardStore<MerkleHashOrchard, u32>, 32, 16> =
        ShardTree::new(MemoryShardStore::empty(), 100);
    tree.append(leaf, Retention::Checkpoint { id: 0, marking: Marking::Marked })
        .unwrap();
    let root = tree.root_at_checkpoint_id(&0).unwrap().unwrap();
    let position = tree.max_leaf_position(None).unwrap().unwrap();
    let path = tree.witness_at_checkpoint_id(position, &0).unwrap().unwrap();
    (root, path.into())
}

struct Scenario {
    sender_sk: SpendingKey,
    /// The transaction that created the sender's note (the payment's source).
    funding: Bundle<Authorized, i64>,
    funding_index: usize,
    payment: Bundle<Authorized, i64>,
    funding_note: Note,
    funding_path: MerklePath,
    spend_index: usize,
    merchant_index: usize,
    merchant_value: u64,
}

fn decrypt(version: BundleVersion, bundle: &Bundle<Authorized, i64>, fvk: &FullViewingKey) -> Note {
    let ivk = PreparedIncomingViewingKey::new(&fvk.to_ivk(Scope::External));
    bundle
        .actions()
        .iter()
        .find_map(|a| {
            if version == BundleVersion::ironwood_v3() {
                try_note_decryption(&IronwoodDomain::for_action(a), &ivk, a).map(|r| r.0)
            } else {
                try_note_decryption(&OrchardDomain::for_action(a), &ivk, a).map(|r| r.0)
            }
        })
        .expect("funding note decrypts")
}

/// Sender is funded with 100_000 zats, then pays a merchant 42_000 zats with a memo.
fn scenario(version: BundleVersion) -> Scenario {
    scenario_valued(version, 100_000, 42_000)
}

/// Sender is funded with `fund` zats, then pays a merchant `pay` zats with a memo.
fn scenario_valued(version: BundleVersion, fund: u64, pay: u64) -> Scenario {
    let mut rng = OsRng;
    let pk = network_pk(version);
    let sender_sk = SpendingKey::from_bytes([7; 32]).unwrap();
    let sender_fvk = FullViewingKey::from(&sender_sk);
    let sender_addr = sender_fvk.address_at(0u32, Scope::External);
    let merchant_sk = SpendingKey::from_bytes([9; 32]).unwrap();
    let merchant_addr = FullViewingKey::from(&merchant_sk).address_at(3u32, Scope::External);

    let empty: orchard::Anchor = MerkleHashOrchard::empty_root(32.into()).into();
    let mut b = Builder::new(BundleType::DEFAULT, version, Flags::SPENDS_DISABLED, empty).unwrap();
    b.add_output(None, sender_addr, NoteValue::from_raw(fund), [0u8; 512]).unwrap();
    let (unauth, _) = b.build::<i64>(&mut rng).unwrap().unwrap();
    let sighash: [u8; 32] = unauth.commitment(TxVersion::V6).unwrap().into();
    let funding = unauth.create_proof(pk, &mut rng).unwrap().apply_signatures(rng, sighash, &[]).unwrap();

    let funding_note = decrypt(version, &funding, &sender_fvk);
    let cmx: ExtractedNoteCommitment = funding_note.commitment().into();
    let funding_index = funding.actions().iter().position(|a| *a.cmx() == cmx).unwrap();
    let (root, funding_path) = single_leaf_witness(&cmx);

    let mut memo = [0u8; 512];
    memo[..10].copy_from_slice(b"Invoice 42");
    let ovk = sender_fvk.to_ovk(Scope::External);
    let mut b = Builder::new(BundleType::DEFAULT, version, version.default_flags(), root.into()).unwrap();
    b.add_spend(sender_fvk.clone(), funding_note, funding_path.clone()).unwrap();
    b.add_output(Some(ovk.clone()), merchant_addr, NoteValue::from_raw(pay), memo).unwrap();
    b.add_output(Some(ovk), sender_addr, NoteValue::from_raw(fund - pay), [0u8; 512]).unwrap();
    let (unauth, meta) = b.build::<i64>(&mut rng).unwrap().unwrap();
    let sighash: [u8; 32] = unauth.commitment(TxVersion::V6).unwrap().into();
    let payment = unauth
        .create_proof(pk, &mut rng)
        .unwrap()
        .apply_signatures(rng, sighash, &[SpendAuthorizingKey::from(&sender_sk)])
        .unwrap();

    Scenario {
        sender_sk,
        spend_index: meta.spend_action_index(0).unwrap(),
        merchant_index: meta.output_action_index(0).unwrap(),
        funding,
        funding_index,
        payment,
        funding_note,
        funding_path,
        merchant_value: pay,
    }
}

const TXID: [u8; 32] = [0xab; 32];

fn make_receipt(s: &Scenario, pool: Pool, msg: &[u8]) -> Receipt {
    let fvk = FullViewingKey::from(&s.sender_sk);
    create(
        &keys().0,
        COIN_TYPE_TESTNET,
        pool,
        TXID,
        &s.payment,
        msg,
        &[(s.merchant_index, fvk.to_ovk(Scope::External))],
        &[SpendWitness {
            index: s.spend_index,
            sk: s.sender_sk.clone(),
            note: s.funding_note,
            merkle_path: s.funding_path.clone(),
            prove_address: None,
            source: None,
        }],
        OsRng,
    )
    .unwrap()
}

fn roundtrip(version: BundleVersion, pool: Pool) {
    let s = scenario(version);
    let receipt = make_receipt(&s, pool, b"challenge: order 42");

    // Text round trip.
    let text = receipt.to_text();
    assert!(text.starts_with("zrcpt1"));
    let parsed = Receipt::from_text(&text).unwrap();
    assert_eq!(parsed, receipt);

    let v = verify(&keys().1, &parsed, COIN_TYPE_TESTNET, pool, TXID, &s.payment).unwrap();
    assert_eq!(v.proven_spends, vec![s.spend_index as u32]);
    assert_eq!(v.outputs.len(), 1);
    assert_eq!(v.outputs[0].value, s.merchant_value);
    assert_eq!(&v.outputs[0].memo[..10], b"Invoice 42");
    let merchant = FullViewingKey::from(&SpendingKey::from_bytes([9; 32]).unwrap())
        .address_at(3u32, Scope::External);
    assert_eq!(v.outputs[0].recipient, merchant.to_raw_address_bytes());
    assert_eq!(v.msg, b"challenge: order 42");
    println!("{pool:?} receipt: {} bytes, {} chars as text", receipt.to_bytes().len(), text.len());
    if let Ok(dir) = std::env::var("RECEIPT_FIXTURE_DIR") {
        std::fs::write(format!("{dir}/{pool:?}.receipt"), &text).unwrap();
    }
}

#[test]
fn ironwood_receipt_roundtrip() {
    roundtrip(BundleVersion::ironwood_v3(), Pool::Ironwood);
}

#[test]
fn orchard_receipt_roundtrip() {
    // Orchard pool transactions from before NU6.3 (the pool is closed to new value since).
    roundtrip(BundleVersion::orchard_v2(), Pool::Orchard);
}

#[test]
fn tampering_is_rejected() {
    let s = scenario(BundleVersion::ironwood_v3());
    let good = make_receipt(&s, Pool::Ironwood, b"hello");
    let vk = &keys().1;
    let check = |r: &Receipt| verify(vk, r, COIN_TYPE_TESTNET, Pool::Ironwood, TXID, &s.payment);
    assert!(check(&good).is_ok());

    // Changed message: signature no longer matches.
    let mut r = good.clone();
    r.unsigned.msg = b"hellp".to_vec();
    assert_eq!(check(&r).unwrap_err(), Error::BadSignature(s.spend_index as u32));

    // Flipped proof byte.
    let mut r = good.clone();
    r.unsigned.spends[0].proof[100] ^= 1;
    assert!(matches!(check(&r).unwrap_err(), Error::BadSignature(_) | Error::BadProof(_)));

    // Stripped spends: not allowed.
    let mut r = good.clone();
    r.unsigned.spends.clear();
    r.spend_auth_sigs.clear();
    assert_eq!(check(&r).unwrap_err(), Error::NoSpends);

    // Wrong ock (and re-signing is impossible without the key).
    let mut r = good.clone();
    r.unsigned.outputs[0].ock[0] ^= 1;
    assert!(check(&r).is_err());

    // Pointing the spend proof at another action's nullifier.
    let mut r = good.clone();
    r.unsigned.spends[0].index = s.merchant_index as u32;
    if s.merchant_index != s.spend_index {
        assert!(check(&r).is_err());
    }

    // Wrong transaction / network.
    assert!(matches!(
        verify(vk, &good, COIN_TYPE_TESTNET, Pool::Ironwood, [0; 32], &s.payment).unwrap_err(),
        Error::TxidMismatch(_)
    ));
    assert!(matches!(
        verify(vk, &good, COIN_TYPE_MAINNET, Pool::Ironwood, TXID, &s.payment).unwrap_err(),
        Error::CoinTypeMismatch(_, _)
    ));
}

#[test]
fn only_the_spender_can_create() {
    let s = scenario(BundleVersion::ironwood_v3());
    let thief = SpendingKey::from_bytes([3; 32]).unwrap();
    let err = create(
        &keys().0,
        COIN_TYPE_TESTNET,
        Pool::Ironwood,
        TXID,
        &s.payment,
        b"",
        &[],
        &[SpendWitness {
            index: s.spend_index,
            sk: thief,
            note: s.funding_note,
            merkle_path: s.funding_path.clone(),
            prove_address: None,
            source: None,
        }],
        OsRng,
    )
    .unwrap_err();
    assert_eq!(err, Error::WrongNullifier(s.spend_index as u32));
}

#[test]
fn batch_roundtrip_and_checks() {
    use receipts_core::{check_batch, ReceiptBatch};
    let s = scenario(BundleVersion::ironwood_v3());
    let mk = |i: u16, n: u16| make_receipt(&s, Pool::Ironwood, format!("batch:ab12cd34 {i}/{n}\nGrant round 3").as_bytes());
    let batch = ReceiptBatch { receipts: vec![mk(1, 2), mk(2, 2)] };
    let text = batch.to_text();
    assert!(text.starts_with("zrcptb1"));
    let parsed = ReceiptBatch::from_text(&text).unwrap();
    assert_eq!(parsed, batch);
    assert_eq!(check_batch(&parsed).unwrap(), "ab12cd34");

    // Dropping one receipt is detected.
    let short = ReceiptBatch { receipts: vec![batch.receipts[0].clone()] };
    assert!(check_batch(&short).is_err());
    // Duplicating a position is detected.
    let dup = ReceiptBatch { receipts: vec![mk(1, 2), mk(1, 2)] };
    assert!(check_batch(&dup).is_err());
}

#[test]
fn address_proof_roundtrip_and_rejections() {
    let s = scenario(BundleVersion::ironwood_v3());
    let fvk = FullViewingKey::from(&s.sender_sk);
    let public_addr = fvk.address_at(5u32, Scope::External);
    let mk = |addr| {
        create(
            &keys().0,
            COIN_TYPE_TESTNET,
            Pool::Ironwood,
            TXID,
            &s.payment,
            b"donation drive",
            &[(s.merchant_index, fvk.to_ovk(Scope::External))],
            &[SpendWitness {
                index: s.spend_index,
                sk: s.sender_sk.clone(),
                note: s.funding_note,
                merkle_path: s.funding_path.clone(),
                prove_address: Some(addr),
                source: None,
            }],
            OsRng,
        )
    };
    let r = mk(public_addr).unwrap();
    let text = r.to_text();
    let parsed = Receipt::from_text(&text).unwrap();
    assert_eq!(parsed, r);
    let v = verify(&keys().1, &parsed, COIN_TYPE_TESTNET, Pool::Ironwood, TXID, &s.payment).unwrap();
    assert_eq!(v.proven_addresses, vec![(s.spend_index as u32, public_addr.to_raw_address_bytes())]);

    // Someone else's address can't be claimed.
    let merchant = FullViewingKey::from(&SpendingKey::from_bytes([9; 32]).unwrap()).address_at(3u32, Scope::External);
    assert_eq!(mk(merchant).unwrap_err(), Error::AddressNotOwned);

    // The anchor the verifier uses is the root of a one-leaf tree holding the revealed note.
    let a = r.unsigned.spends[0].address.as_ref().unwrap();
    let rho = orchard::note::Rho::from_bytes(&a.rho).unwrap();
    let rseed = orchard::note::RandomSeed::from_bytes(a.rseed, &rho).unwrap();
    let note = Note::from_parts(public_addr, NoteValue::from_raw(1), rho, rseed, orchard::note::NoteVersion::V3).unwrap();
    let (root, _) = single_leaf_witness(&note.commitment().into());
    assert_eq!(receipts_core::address_proof_anchor(Pool::Ironwood, a), Some(root.to_bytes()));
    assert_eq!(a.cv_net, receipts_core::address_proof_cv_net().to_bytes());

    // Two proofs for the same address share nothing a verifier could link them by.
    let r2 = mk(public_addr).unwrap();
    let a2 = r2.unsigned.spends[0].address.as_ref().unwrap();
    assert_ne!(a.rho, a2.rho);
    assert_ne!(a.nf, a2.nf);
    assert_ne!(a.cmx, a2.cmx);
    assert_ne!(r.unsigned.spends[0].rk, r2.unsigned.spends[0].rk);

    // Swapping the claimed address after signing breaks the signature.
    let mut bad = r.clone();
    bad.unsigned.spends[0].address.as_mut().unwrap().address = merchant.to_raw_address_bytes();
    assert!(verify(&keys().1, &bad, COIN_TYPE_TESTNET, Pool::Ironwood, TXID, &s.payment).is_err());
}

/// Flipping any single byte of a receipt (header, txid, message, ock, cv_net, rk, cmx, proof
/// or signature) must make it fail to decode or fail to verify. Never a different valid result.
#[test]
fn every_byte_matters() {
    let s = scenario(BundleVersion::ironwood_v3());
    let good = make_receipt(&s, Pool::Ironwood, b"order 42");
    let bytes = good.to_bytes();
    let vk = &keys().1;
    // Every byte of the structured fields, plus a sample across the proof.
    let proof_start = bytes.len() - 64 - good.unsigned.spends[0].proof.len();
    let mut positions: Vec<usize> = (0..proof_start).collect();
    positions.extend((proof_start..bytes.len() - 64).step_by(97));
    positions.extend(bytes.len() - 64..bytes.len());
    let mut checked = 0;
    for &i in &positions {
        let mut b = bytes.clone();
        b[i] ^= 0x01;
        if let Ok(r) = Receipt::from_bytes(&b) {
            let res = verify(vk, &r, COIN_TYPE_TESTNET, Pool::Ironwood, TXID, &s.payment);
            assert!(res.is_err(), "flipping byte {i} still verified");
        }
        checked += 1;
    }
    assert!(checked > 300, "checked {checked} positions");
}

#[test]
fn sign_in_roundtrip_and_replay() {
    use receipts_core::signin::{sign_in, verify_sign_in, SignIn};
    let (pk, vk) = keys();
    let sk = SpendingKey::from_bytes([7; 32]).unwrap();
    let addr = FullViewingKey::from(&sk).address_at(0u32, Scope::External);
    let s = sign_in(pk, 1, "shop.example", "n0nce-1", 1_760_000_000, &sk, addr, OsRng).unwrap();
    let text = s.to_text();
    assert!(text.starts_with("zsig1"));
    let back = SignIn::from_text(&text).unwrap();
    assert_eq!(back, s);
    assert_eq!(verify_sign_in(vk, &back, 1, "shop.example", "n0nce-1").unwrap(), addr.to_raw_address_bytes());
    // Another site, another nonce, another network: all refused.
    assert!(verify_sign_in(vk, &back, 1, "evil.example", "n0nce-1").is_err());
    assert!(verify_sign_in(vk, &back, 1, "shop.example", "n0nce-2").is_err());
    assert!(verify_sign_in(vk, &back, 133, "shop.example", "n0nce-1").is_err());
    // Rewriting the signed fields breaks the signature.
    let mut forged = back.clone();
    forged.domain = "evil.example".into();
    assert!(verify_sign_in(vk, &forged, 1, "evil.example", "n0nce-1").is_err());
    let mut forged = back.clone();
    forged.address.address = FullViewingKey::from(&SpendingKey::from_bytes([9; 32]).unwrap()).address_at(0u32, Scope::External).to_raw_address_bytes();
    assert!(verify_sign_in(vk, &forged, 1, "shop.example", "n0nce-1").is_err());
    // Only the key holder can sign in as the address.
    let thief = SpendingKey::from_bytes([3; 32]).unwrap();
    assert!(sign_in(pk, 1, "shop.example", "n", 0, &thief, addr, OsRng).is_err());
    assert!(SignIn::from_text(&text[..text.len() - 4]).is_none());
}

#[test]
fn params_match_derivation() {
    // The shipped parameters are exactly what deriving them gives.
    let derived = receipts_core::verifying_key_slow().params_bytes();
    assert_eq!(derived, receipts_core::verifying_key().params_bytes());
    assert_eq!(derived.as_slice(), &include_bytes!("../src/orchard-params-k11.bin")[..]);
}

#[test]
fn encodings_are_canonical() {
    // The real testnet receipt (v1) relabelled as v2 with an "absent" flag byte decodes to the
    // same receipt; strict decoding refuses it, so one receipt has exactly one encoding.
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    let text = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/../../examples/testnet/receipt.txt")).unwrap();
    let mut b = URL_SAFE_NO_PAD.decode(text.trim().strip_prefix("zrcpt1").unwrap()).unwrap();
    assert!(Receipt::from_bytes(&b).is_ok());
    b[4] = 2;
    assert!(Receipt::from_bytes(&b).is_err(), "v1 bytes labelled v2 must not decode");
    let x = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/../../examples/regtest-crosspool/receipt.txt")).unwrap();
    let r = Receipt::from_text(x.trim()).unwrap();
    assert_eq!(Receipt::from_bytes(&r.to_bytes()).unwrap(), r);
}

#[test]
fn disclosures_are_unlinkable_to_the_action_and_to_each_other() {
    // The spend disclosure re-randomizes everything that could identify the spender: its rk and
    // cv_net differ from the on-chain action's, and two receipts for the same spend share none.
    let s = scenario(BundleVersion::ironwood_v3());
    let a = make_receipt(&s, Pool::Ironwood, b"one");
    let b = make_receipt(&s, Pool::Ironwood, b"one");
    let action = &s.payment.actions()[s.spend_index];
    let onchain_rk: [u8; 32] = action.rk().into();
    let onchain_cv = action.cv_net().to_bytes();
    for r in [&a, &b] {
        let sp = &r.unsigned.spends[0];
        assert_ne!(sp.rk, onchain_rk);
        assert_ne!(sp.cv_net, onchain_cv);
        // No output disclosure reveals a key beyond that one output's ock.
        assert_eq!(r.unsigned.outputs.len(), 1);
    }
    assert_ne!(a.unsigned.spends[0].rk, b.unsigned.spends[0].rk);
    assert_ne!(a.unsigned.spends[0].cv_net, b.unsigned.spends[0].cv_net);
    assert_ne!(a.unsigned.spends[0].cmx, b.unsigned.spends[0].cmx);
}

// ---------- forged address proofs (zero-value witness note) ----------
//
// The Action circuit only checks the Merkle path when the spent note's value is non-zero
// (`v_old * (root - anchor) = 0`). An address proof is meant to spend a 1-zatoshi note to the
// claimed address under a one-leaf tree, but if the verifier takes `cv_net` from the prover it
// cannot tell whether the witness note really had value 1. A prover can then witness a
// zero-value note to an address of their own, skip the anchor check, and claim any address.
// ZIP 304 avoids this by fixing `cv = ValueCommit_0(1)` on the verifier's side.

/// An address proof for `victim`, made by the holder of `attacker_sk` (who does not own it).
fn forge_address_proof(
    attacker_sk: &SpendingKey,
    alpha: pasta_curves::pallas::Scalar,
    victim: orchard::Address,
    version: orchard::note::NoteVersion,
) -> receipts_core::AddressProof {
    use ff::{Field, PrimeField};
    use orchard::{
        builder::SpendInfo,
        circuit::{Circuit, Instance, OrchardCircuitVersion},
        note::{RandomSeed, Rho},
        primitives::redpallas::{SpendAuth, VerificationKey},
        value::{ValueCommitTrapdoor, ValueCommitment},
        Proof,
    };
    let mut rng = OsRng;
    let rand32 = |rng: &mut UnwrapErr<SysRng>| {
        let mut b = [0u8; 32];
        rand::rand_core::Rng::fill_bytes(rng, &mut b);
        b
    };
    let fvk = FullViewingKey::from(attacker_sk);
    let own = fvk.address_at(0u32, Scope::External);
    let note_for = |addr, value, rng: &mut UnwrapErr<SysRng>| loop {
        let Some(rho) = Option::<Rho>::from(Rho::from_bytes(&pasta_curves::pallas::Base::random(&mut *rng).to_repr())) else { continue };
        let Some(rseed) = Option::<RandomSeed>::from(RandomSeed::from_bytes(rand32(rng), &rho)) else { continue };
        if let Some(n) = Option::<Note>::from(Note::from_parts(addr, NoteValue::from_raw(value), rho, rseed, version)) {
            break (rho, rseed, n);
        }
    };
    // The note the verifier will rebuild: 1 zatoshi to the victim.
    let (rho_v, rseed_v, victim_note) = note_for(victim, 1, &mut rng);
    let (_, victim_path) = single_leaf_witness(&victim_note.commitment().into());
    let anchor = victim_path.root(victim_note.commitment().into());
    // The note actually witnessed: zero value, to the attacker's own address.
    let (_, _, own_note) = note_for(own, 0, &mut rng);
    let nf = own_note.nullifier(&fvk);
    let spend = SpendInfo::new(fvk.clone(), own_note, victim_path).unwrap();
    let (_, _, dummy) = loop {
        let rho = Rho::from_bytes(&nf.to_bytes()).unwrap();
        let Some(rseed) = Option::<RandomSeed>::from(RandomSeed::from_bytes(rand32(&mut rng), &rho)) else { continue };
        if let Some(n) = Option::<Note>::from(Note::from_parts(own, NoteValue::ZERO, rho, rseed, version)) {
            break (rho, rseed, n);
        }
    };
    let rcv = ValueCommitTrapdoor::from_bytes(pasta_curves::pallas::Scalar::random(&mut rng).to_repr()).unwrap();
    let cv_net = ValueCommitment::derive(NoteValue::from_raw(0) - NoteValue::ZERO, rcv.clone());
    let rk = VerificationKey::<SpendAuth>::from(&SpendAuthorizingKey::from(attacker_sk).randomize(&alpha));
    let cmx: ExtractedNoteCommitment = dummy.commitment().into();
    let circuit = Circuit::from_action_context(spend, dummy, alpha, rcv, OrchardCircuitVersion::PostNu6_3).unwrap();
    let instance = Instance::from_parts(anchor, cv_net.clone(), nf, rk, cmx, Flags::ENABLED).unwrap();
    let proof = Proof::create(&keys().0, &[circuit], &[instance], &mut rng).unwrap();
    receipts_core::AddressProof {
        address: victim.to_raw_address_bytes(),
        rho: rho_v.to_bytes(),
        rseed: *rseed_v.as_bytes(),
        nf: nf.to_bytes(),
        cv_net: cv_net.to_bytes(),
        cmx: cmx.to_bytes(),
        proof: proof.as_ref().to_vec(),
    }
}

/// A receipt that wouldn't fit its encoding's length fields is refused when created, rather than
/// encoded with a wrapped length.
#[test]
fn oversized_receipts_are_refused_at_creation() {
    let s = scenario(BundleVersion::ironwood_v3());
    let fvk = FullViewingKey::from(&s.sender_sk);
    let w = || SpendWitness { index: s.spend_index, sk: s.sender_sk.clone(), note: s.funding_note, merkle_path: s.funding_path.clone(), prove_address: None, source: None };
    let long = vec![b'x'; 65_536];
    assert_eq!(create(&keys().0, COIN_TYPE_TESTNET, Pool::Ironwood, TXID, &s.payment, &long, &[], &[w()], OsRng).unwrap_err(), Error::TooLarge);
    let outs = vec![(s.merchant_index, fvk.to_ovk(Scope::External)); 256];
    assert_eq!(create(&keys().0, COIN_TYPE_TESTNET, Pool::Ironwood, TXID, &s.payment, b"", &outs, &[w()], OsRng).unwrap_err(), Error::TooLarge);
    let spends: Vec<_> = (0..256).map(|_| w()).collect();
    assert_eq!(create(&keys().0, COIN_TYPE_TESTNET, Pool::Ironwood, TXID, &s.payment, b"", &[], &spends, OsRng).unwrap_err(), Error::TooLarge);
    // At the limits themselves the size check passes (these then fail on the repeated index).
    assert_eq!(create(&keys().0, COIN_TYPE_TESTNET, Pool::Ironwood, TXID, &s.payment, b"", &outs[..255], &[w()], OsRng).unwrap_err(), Error::DuplicateIndex(s.merchant_index as u32));
    assert_eq!(create(&keys().0, COIN_TYPE_TESTNET, Pool::Ironwood, TXID, &s.payment, b"", &[], &spends[..255], OsRng).unwrap_err(), Error::DuplicateIndex(s.spend_index as u32));
    assert!(create(&keys().0, COIN_TYPE_TESTNET, Pool::Ironwood, TXID, &s.payment, &long[..65_535], &[], &[w()], OsRng).is_ok());
}

#[test]
fn sign_in_as_someone_elses_address_is_refused() {
    use receipts_core::signin::{verify_sign_in, SignIn};
    use ff::Field;
    let vk = &keys().1;
    let thief = SpendingKey::from_bytes([3; 32]).unwrap();
    let victim = FullViewingKey::from(&SpendingKey::from_bytes([7; 32]).unwrap()).address_at(0u32, Scope::External);
    let mut rng = OsRng;
    let alpha = pasta_curves::pallas::Scalar::random(&mut rng);
    let rsk = SpendAuthorizingKey::from(&thief).randomize(&alpha);
    let rk: [u8; 32] = (&orchard::primitives::redpallas::VerificationKey::from(&rsk)).into();
    let address = forge_address_proof(&thief, alpha, victim, orchard::note::NoteVersion::V3);
    // As made, and with `cv_net` replaced by the value the verifier expects.
    for cv_net in [address.cv_net, receipts_core::address_proof_cv_net().to_bytes()] {
        let address = receipts_core::AddressProof { cv_net, ..address.clone() };
        let mut forged = SignIn { coin_type: 1, domain: "shop.example".into(), nonce: "n0nce-1".into(), issued_at: 1_760_000_000, rk, address, sig: [0; 64] };
        let digest = receipts_core::signin::signing_digest(&forged);
        forged.sig = (&rsk.sign(OsRng, &digest)).into();
        let res = verify_sign_in(vk, &forged, 1, "shop.example", "n0nce-1");
        assert!(res.is_err(), "a thief signed in as the victim's address: {res:?}");
    }
}

#[test]
fn claiming_someone_elses_sender_address_is_refused() {
    use ff::Field;
    use orchard::{
        builder::SpendInfo,
        circuit::{Circuit, Instance, OrchardCircuitVersion},
        note::RandomSeed,
        primitives::redpallas::{SpendAuth, VerificationKey},
        value::{ValueCommitTrapdoor, ValueCommitment},
        Proof,
    };
    use ff::PrimeField;
    let s = scenario(BundleVersion::ironwood_v3());
    let mut rng = OsRng;
    let fvk = FullViewingKey::from(&s.sender_sk);
    let victim = FullViewingKey::from(&SpendingKey::from_bytes([9; 32]).unwrap()).address_at(3u32, Scope::External);
    // An honest spend disclosure with a known alpha (as `create` makes it)...
    let action = &s.payment.actions()[s.spend_index];
    let alpha = pasta_curves::pallas::Scalar::random(&mut rng);
    let rsk = SpendAuthorizingKey::from(&s.sender_sk).randomize(&alpha);
    let rk = VerificationKey::<SpendAuth>::from(&rsk);
    let rho = action.rho();
    let dummy_addr = FullViewingKey::from(&SpendingKey::from_bytes([5; 32]).unwrap()).address_at(0u32, Scope::External);
    let dummy = loop {
        let mut b = [0u8; 32];
        rand::rand_core::Rng::fill_bytes(&mut rng, &mut b);
        if let Some(rs) = Option::<RandomSeed>::from(RandomSeed::from_bytes(b, &rho)) {
            if let Some(n) = Option::<Note>::from(Note::from_parts(dummy_addr, NoteValue::ZERO, rho, rs, s.funding_note.version())) {
                break n;
            }
        }
    };
    let rcv = ValueCommitTrapdoor::from_bytes(pasta_curves::pallas::Scalar::random(&mut rng).to_repr()).unwrap();
    let cv_net = ValueCommitment::derive(s.funding_note.value() - NoteValue::ZERO, rcv.clone());
    let cmx: ExtractedNoteCommitment = dummy.commitment().into();
    let spend = SpendInfo::new(fvk.clone(), s.funding_note, s.funding_path.clone()).unwrap();
    let circuit = Circuit::from_action_context(spend, dummy, alpha, rcv, OrchardCircuitVersion::PostNu6_3).unwrap();
    let instance = Instance::from_parts(*s.payment.anchor(), cv_net.clone(), *action.nullifier(), rk.clone(), cmx, Flags::ENABLED).unwrap();
    let proof = Proof::create(&keys().0, &[circuit], &[instance], &mut rng).unwrap();
    // ...plus an address proof for the merchant's address, which the sender does not own.
    let forged_address = forge_address_proof(&s.sender_sk, alpha, victim, s.funding_note.version());
    for cv in [forged_address.cv_net, receipts_core::address_proof_cv_net().to_bytes()] {
    let address = receipts_core::AddressProof { cv_net: cv, ..forged_address.clone() };
    let unsigned = receipts_core::UnsignedReceipt {
        coin_type: COIN_TYPE_TESTNET,
        pool: Pool::Ironwood,
        output_pool: None,
        txid: TXID,
        msg: b"I am the merchant".to_vec(),
        outputs: vec![],
        opened: vec![],
        spends: vec![receipts_core::SpendDisclosure {
            index: s.spend_index as u32,
            cv_net: cv_net.to_bytes(),
            rk: (&rk).into(),
            cmx: cmx.to_bytes(),
            proof: proof.as_ref().to_vec(),
            address: Some(address),
            source: None,
        }],
    };
    let digest = receipts_core::signing_digest(&unsigned);
    let forged = Receipt { spend_auth_sigs: vec![(&rsk.sign(OsRng, &digest)).into()], unsigned };
    let forged = Receipt::from_bytes(&forged.to_bytes()).unwrap();
    let res = verify(&keys().1, &forged, COIN_TYPE_TESTNET, Pool::Ironwood, TXID, &s.payment);
    assert!(res.is_err(), "a sender proved control of the merchant's address: {:?}", res.map(|v| v.proven_addresses));
    }
}

// ---------- differential corpus for the independent Python verifier ----------

/// An honest spend disclosure for the scenario's spent note, with a chosen alpha (as `create`
/// makes it), so tests can re-sign receipts they alter.
fn honest_spend(s: &Scenario, bundle: &Bundle<Authorized, i64>, alpha: pasta_curves::pallas::Scalar) -> receipts_core::SpendDisclosure {
    use ff::{Field, PrimeField};
    use orchard::{
        builder::SpendInfo,
        circuit::{Circuit, Instance, OrchardCircuitVersion},
        note::RandomSeed,
        primitives::redpallas::{SpendAuth, VerificationKey},
        value::{ValueCommitTrapdoor, ValueCommitment},
        Proof,
    };
    let mut rng = OsRng;
    let fvk = FullViewingKey::from(&s.sender_sk);
    let action = &bundle.actions()[s.spend_index];
    let rk = VerificationKey::<SpendAuth>::from(&SpendAuthorizingKey::from(&s.sender_sk).randomize(&alpha));
    let rho = action.rho();
    let dummy_addr = FullViewingKey::from(&SpendingKey::from_bytes([5; 32]).unwrap()).address_at(0u32, Scope::External);
    let dummy = loop {
        let mut b = [0u8; 32];
        rand::rand_core::Rng::fill_bytes(&mut rng, &mut b);
        if let Some(rs) = Option::<RandomSeed>::from(RandomSeed::from_bytes(b, &rho)) {
            if let Some(n) = Option::<Note>::from(Note::from_parts(dummy_addr, NoteValue::ZERO, rho, rs, s.funding_note.version())) {
                break n;
            }
        }
    };
    let rcv = ValueCommitTrapdoor::from_bytes(pasta_curves::pallas::Scalar::random(&mut rng).to_repr()).unwrap();
    let cv_net = ValueCommitment::derive(s.funding_note.value() - NoteValue::ZERO, rcv.clone());
    let cmx: ExtractedNoteCommitment = dummy.commitment().into();
    let spend = SpendInfo::new(fvk, s.funding_note, s.funding_path.clone()).unwrap();
    let circuit = Circuit::from_action_context(spend, dummy, alpha, rcv, OrchardCircuitVersion::PostNu6_3).unwrap();
    let instance = Instance::from_parts(*bundle.anchor(), cv_net.clone(), *action.nullifier(), rk.clone(), cmx, Flags::ENABLED).unwrap();
    let proof = Proof::create(&keys().0, &[circuit], &[instance], &mut rng).unwrap();
    receipts_core::SpendDisclosure { index: s.spend_index as u32, cv_net: cv_net.to_bytes(), rk: (&rk).into(), cmx: cmx.to_bytes(), proof: proof.as_ref().to_vec(), address: None, source: None }
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn bundle_json(b: &Bundle<Authorized, i64>) -> serde_json::Value {
    let actions: Vec<_> = b
        .actions()
        .iter()
        .map(|a| {
            let rk: [u8; 32] = a.rk().into();
            serde_json::json!({
                "cv": hex(&a.cv_net().to_bytes()), "nf": hex(&a.nullifier().to_bytes()), "rk": hex(&rk),
                "cmx": hex(&a.cmx().to_bytes()), "epk": hex(&a.encrypted_note().epk_bytes),
                "enc": hex(&a.encrypted_note().enc_ciphertext.0), "out": hex(&a.encrypted_note().out_ciphertext),
            })
        })
        .collect();
    serde_json::json!({ "anchor": hex(&b.anchor().to_bytes()), "actions": actions })
}

/// What the Rust verifier says, plus the public inputs it uses for every proof (whatever the verdict).
fn rust_view(r: &Receipt, pool: Pool, b: &Bundle<Authorized, i64>, coin: u32, source: Option<&Bundle<Authorized, i64>>) -> serde_json::Value {
    let lookup = |_p: Pool, t: &[u8; 32], i: u32| if t == &FUNDING_TXID { source.and_then(|sb| receipts_core::output_cmx(sb, i)) } else { None };
    let res = receipts_core::verify_with_sources(&keys().1, r, coin, pool, TXID, b, &lookup);
    let pis: Vec<_> = r
        .unsigned
        .spends
        .iter()
        .map(|s| {
            let nf = b.actions().get(s.index as usize).map(|a| hex(&a.nullifier().to_bytes()));
            serde_json::json!({
                "anchor": hex(&b.anchor().to_bytes()), "cv_net": hex(&s.cv_net), "nf": nf, "rk": hex(&s.rk), "cmx": hex(&s.cmx),
                "address_anchor": s.address.as_ref().and_then(|a| receipts_core::address_proof_anchor(pool, a)).map(|x| hex(&x)),
                "source": s.source.as_ref().map(|src| serde_json::json!({
                    "anchor": source.and_then(|sb| receipts_core::output_cmx(sb, src.index)).and_then(|c| receipts_core::source_proof_anchor(&c)).map(|a| hex(&a.to_bytes())),
                    "cv_net": receipts_core::source_proof_cv_net(src.revealed_value()).map(|c| hex(&c.to_bytes())),
                    "cmx": b.actions().get(s.index as usize).and_then(|a| receipts_core::source_proof_cmx(pool, &a.nullifier().to_bytes(), src)).map(|c| hex(&c)),
                })),
            })
        })
        .collect();
    match res {
        Ok(v) => serde_json::json!({
            "ok": true, "public_inputs": pis,
            "outputs": v.outputs.iter().map(|o| serde_json::json!({"index": o.index, "recipient": hex(&o.recipient), "value": o.value, "memo": (!o.memo_withheld).then(|| hex(&o.memo))})).collect::<Vec<_>>(),
            "proven_addresses": v.proven_addresses.iter().map(|(_, a)| hex(a)).collect::<Vec<_>>(),
            "sources": v.sources.iter().map(|x| serde_json::json!({"spend": x.spend, "index": x.index, "value": x.value})).collect::<Vec<_>>(),
        }),
        Err(e) => serde_json::json!({ "ok": false, "error": format!("{e:?}"), "public_inputs": pis }),
    }
}

/// Writes signed adversarial receipts (each re-signed after the change, so only the check under
/// test can catch it) with the Rust verdicts, for `spec-verifier/tests/test_differential.py`.
/// Set DIFF_CORPUS=path to write the file.
#[test]
fn differential_corpus() {
    use ff::Field;
    use orchard::primitives::redpallas::{SigningKey, SpendAuth, VerificationKey};
    let Ok(path) = std::env::var("DIFF_CORPUS") else { return };
    let mut rng = OsRng;
    let s = scenario(BundleVersion::ironwood_v3());
    let so = scenario(BundleVersion::orchard_v2());
    let mut cases = Vec::new();
    let mut add = |name: &str, pool: Pool, b: &Bundle<Authorized, i64>, r: &Receipt, coin: u32| {
        // Source proofs are checked against each scenario's own funding transaction.
        let source = if pool == Pool::Orchard { &so.funding } else { &s.funding };
        cases.push(serde_json::json!({
            "name": name, "pool": if pool == Pool::Orchard { "orchard" } else { "ironwood" }, "coin_type": coin,
            "receipt": hex(&r.to_bytes()), "rust": rust_view(r, pool, b, coin, Some(source)),
        }));
    };
    let sign = |u: receipts_core::UnsignedReceipt, rsks: &[&SigningKey<SpendAuth>]| {
        let d = receipts_core::signing_digest(&u);
        Receipt { spend_auth_sigs: rsks.iter().map(|k| (&k.sign(OsRng, &d)).into()).collect(), unsigned: u }
    };

    let a = make_receipt(&s, Pool::Ironwood, b"order 42");
    add("honest/ironwood", Pool::Ironwood, &s.payment, &a, COIN_TYPE_TESTNET);
    add("honest/orchard", Pool::Orchard, &so.payment, &make_receipt(&so, Pool::Orchard, b"order 7"), COIN_TYPE_TESTNET);
    let fvk = FullViewingKey::from(&s.sender_sk);
    let with_addr = create(&keys().0, COIN_TYPE_TESTNET, Pool::Ironwood, TXID, &s.payment, b"from my public address",
        &[(s.merchant_index, fvk.to_ovk(Scope::External))],
        &[SpendWitness { index: s.spend_index, sk: s.sender_sk.clone(), note: s.funding_note, merkle_path: s.funding_path.clone(), prove_address: Some(fvk.address_at(5u32, Scope::External)), source: None }],
        OsRng).unwrap();
    add("honest/with-address", Pool::Ironwood, &s.payment, &with_addr, COIN_TYPE_TESTNET);

    let alpha = pasta_curves::pallas::Scalar::random(&mut rng);
    let rsk = SpendAuthorizingKey::from(&s.sender_sk).randomize(&alpha);
    let spend = honest_spend(&s, &s.payment, alpha);
    let base = receipts_core::UnsignedReceipt {
        coin_type: COIN_TYPE_TESTNET, pool: Pool::Ironwood, output_pool: None, txid: TXID, msg: b"manual".to_vec(),
        outputs: a.unsigned.outputs.clone(), opened: vec![], spends: vec![spend.clone()],
    };
    add("manual/valid", Pool::Ironwood, &s.payment, &sign(base.clone(), &[&rsk]), COIN_TYPE_TESTNET);
    add("resigned/new-message", Pool::Ironwood, &s.payment, &sign(receipts_core::UnsignedReceipt { msg: b"challenge:00ff".to_vec(), ..base.clone() }, &[&rsk]), COIN_TYPE_TESTNET);
    add("resigned/no-outputs", Pool::Ironwood, &s.payment, &sign(receipts_core::UnsignedReceipt { outputs: vec![], ..base.clone() }, &[&rsk]), COIN_TYPE_TESTNET);
    let victim = FullViewingKey::from(&SpendingKey::from_bytes([9; 32]).unwrap()).address_at(3u32, Scope::External);
    let forged = forge_address_proof(&s.sender_sk, alpha, victim, s.funding_note.version());
    let with = |a: receipts_core::AddressProof| receipts_core::UnsignedReceipt { spends: vec![receipts_core::SpendDisclosure { address: Some(a), ..spend.clone() }], ..base.clone() };
    add("forged-address/prover-cv", Pool::Ironwood, &s.payment, &sign(with(forged.clone()), &[&rsk]), COIN_TYPE_TESTNET);
    add("forged-address/fixed-cv", Pool::Ironwood, &s.payment, &sign(with(receipts_core::AddressProof { cv_net: receipts_core::address_proof_cv_net().to_bytes(), ..forged.clone() }), &[&rsk]), COIN_TYPE_TESTNET);
    let mut o = base.clone();
    o.outputs[0].index = s.payment.actions().len() as u32;
    add("resigned/output-index-out-of-range", Pool::Ironwood, &s.payment, &sign(o, &[&rsk]), COIN_TYPE_TESTNET);
    let mut o = base.clone();
    o.outputs.push(o.outputs[0].clone());
    add("resigned/duplicate-output", Pool::Ironwood, &s.payment, &sign(o, &[&rsk]), COIN_TYPE_TESTNET);
    let mut o = base.clone();
    o.outputs[0].ock[0] ^= 1;
    add("resigned/wrong-ock", Pool::Ironwood, &s.payment, &sign(o, &[&rsk]), COIN_TYPE_TESTNET);
    add("resigned/ock-for-another-output", Pool::Ironwood, &s.payment, &sign(receipts_core::UnsignedReceipt { outputs: vec![receipts_core::OutputDisclosure { index: (s.merchant_index as u32 + 1) % s.payment.actions().len() as u32, ock: base.outputs[0].ock }], ..base.clone() }, &[&rsk]), COIN_TYPE_TESTNET);
    let zero = SigningKey::<SpendAuth>::try_from([0u8; 32]).unwrap();
    let zero_rk: [u8; 32] = (&VerificationKey::from(&zero)).into();
    add("resigned/rk-identity", Pool::Ironwood, &s.payment, &sign(receipts_core::UnsignedReceipt { spends: vec![receipts_core::SpendDisclosure { rk: zero_rk, ..spend.clone() }], ..base.clone() }, &[&zero]), COIN_TYPE_TESTNET);
    add("resigned/non-canonical-cmx", Pool::Ironwood, &s.payment, &sign(receipts_core::UnsignedReceipt { spends: vec![receipts_core::SpendDisclosure { cmx: [0xff; 32], ..spend.clone() }], ..base.clone() }, &[&rsk]), COIN_TYPE_TESTNET);
    add("resigned/cv-not-a-point", Pool::Ironwood, &s.payment, &sign(receipts_core::UnsignedReceipt { spends: vec![receipts_core::SpendDisclosure { cv_net: [0xff; 32], ..spend.clone() }], ..base.clone() }, &[&rsk]), COIN_TYPE_TESTNET);
    add("resigned/proof-from-another-receipt", Pool::Ironwood, &s.payment, &sign(receipts_core::UnsignedReceipt { spends: vec![receipts_core::SpendDisclosure { proof: a.unsigned.spends[0].proof.clone(), ..spend.clone() }], ..base.clone() }, &[&rsk]), COIN_TYPE_TESTNET);
    add("resigned/cv-from-another-receipt", Pool::Ironwood, &s.payment, &sign(receipts_core::UnsignedReceipt { spends: vec![receipts_core::SpendDisclosure { cv_net: a.unsigned.spends[0].cv_net, ..spend.clone() }], ..base.clone() }, &[&rsk]), COIN_TYPE_TESTNET);
    add("resigned/spend-index-of-another-action", Pool::Ironwood, &s.payment, &sign(receipts_core::UnsignedReceipt { spends: vec![receipts_core::SpendDisclosure { index: (s.spend_index as u32 + 1) % s.payment.actions().len() as u32, ..spend.clone() }], ..base.clone() }, &[&rsk]), COIN_TYPE_TESTNET);
    add("resigned/mainnet-receipt-on-testnet", Pool::Ironwood, &s.payment, &sign(receipts_core::UnsignedReceipt { coin_type: COIN_TYPE_MAINNET, ..base.clone() }, &[&rsk]), COIN_TYPE_TESTNET);
    add("resigned/wrong-pool-bundle", Pool::Orchard, &so.payment, &sign(receipts_core::UnsignedReceipt { pool: Pool::Orchard, ..base.clone() }, &[&rsk]), COIN_TYPE_TESTNET);
    let other = SpendAuthorizingKey::from(&SpendingKey::from_bytes([3; 32]).unwrap()).randomize(&alpha);
    add("signed-by-someone-else", Pool::Ironwood, &s.payment, &sign(base.clone(), &[&other]), COIN_TYPE_TESTNET);
    // Source proofs.
    add("honest/source-hidden", Pool::Ironwood, &s.payment, &receipt_with_source(&s, Pool::Ironwood, false), COIN_TYPE_TESTNET);
    let revealed = receipt_with_source(&s, Pool::Ironwood, true);
    add("honest/source-revealed", Pool::Ironwood, &s.payment, &revealed, COIN_TYPE_TESTNET);
    add("honest/source-orchard", Pool::Orchard, &so.payment, &receipt_with_source(&so, Pool::Orchard, true), COIN_TYPE_TESTNET);
    let honest_src = receipts_core::__source_proof_for_tests(&keys().0, Pool::Ironwood, s.spend_index as u32, &fvk, s.funding_note, &source_witness(&s, true), alpha, &orchard::primitives::redpallas::VerificationKey::from(&rsk), &mut { OsRng }).unwrap();
    let with_src = |p: receipts_core::SourceProof| receipts_core::UnsignedReceipt { spends: vec![receipts_core::SpendDisclosure { source: Some(p), ..spend.clone() }], ..base.clone() };
    add("manual/source-valid", Pool::Ironwood, &s.payment, &sign(with_src(honest_src.clone()), &[&rsk]), COIN_TYPE_TESTNET);
    let lie = |v: u64| {
        let mut p = honest_src.clone();
        if let receipts_core::SourceValue::Revealed { value, .. } = &mut p.value {
            *value = v;
        }
        p
    };
    add("resigned/source-value-lower", Pool::Ironwood, &s.payment, &sign(with_src(lie(99_999)), &[&rsk]), COIN_TYPE_TESTNET);
    add("resigned/source-value-higher", Pool::Ironwood, &s.payment, &sign(with_src(lie(100_001)), &[&rsk]), COIN_TYPE_TESTNET);
    let other_out = ((s.funding_index + 1) % s.funding.actions().len()) as u32;
    add("resigned/source-other-output", Pool::Ironwood, &s.payment, &sign(with_src(receipts_core::SourceProof { index: other_out, ..honest_src.clone() }), &[&rsk]), COIN_TYPE_TESTNET);
    add("resigned/source-unknown-tx", Pool::Ironwood, &s.payment, &sign(with_src(receipts_core::SourceProof { txid: [0x11; 32], ..honest_src.clone() }), &[&rsk]), COIN_TYPE_TESTNET);
    add("resigned/source-is-the-payment", Pool::Ironwood, &s.payment, &sign(with_src(receipts_core::SourceProof { txid: TXID, ..honest_src.clone() }), &[&rsk]), COIN_TYPE_TESTNET);
    add("resigned/source-proof-from-another-receipt", Pool::Ironwood, &s.payment, &sign(with_src(revealed.unsigned.spends[0].source.clone().unwrap()), &[&rsk]), COIN_TYPE_TESTNET);
    let hidden_as_revealed = receipts_core::__source_proof_for_tests(&keys().0, Pool::Ironwood, s.spend_index as u32, &fvk, s.funding_note, &source_witness(&s, false), alpha, &orchard::primitives::redpallas::VerificationKey::from(&rsk), &mut { OsRng }).unwrap();
    add("resigned/source-hidden-relabelled-as-1", Pool::Ironwood, &s.payment, &sign(with_src(receipts_core::SourceProof { value: receipts_core::SourceValue::Revealed { value: 1, address: s.funding_note.recipient().to_raw_address_bytes(), rseed: *s.funding_note.rseed().as_bytes() }, ..hidden_as_revealed }), &[&rsk]), COIN_TYPE_TESTNET);
    // Outputs disclosed without their memo.
    let mw = receipt_memo_withheld(&s, Pool::Ironwood);
    add("honest/memo-withheld", Pool::Ironwood, &s.payment, &mw, COIN_TYPE_TESTNET);
    add("honest/memo-withheld-orchard", Pool::Orchard, &so.payment, &receipt_memo_withheld(&so, Pool::Orchard), COIN_TYPE_TESTNET);
    let op = mw.unsigned.opened[0].clone();
    let with_opened = |o: receipts_core::OpenedOutput| receipts_core::UnsignedReceipt { outputs: vec![], opened: vec![o], ..base.clone() };
    add("manual/opened-valid", Pool::Ironwood, &s.payment, &sign(with_opened(op.clone()), &[&rsk]), COIN_TYPE_TESTNET);
    add("resigned/opened-value-higher", Pool::Ironwood, &s.payment, &sign(with_opened(receipts_core::OpenedOutput { value: op.value + 1, ..op.clone() }), &[&rsk]), COIN_TYPE_TESTNET);
    add("resigned/opened-other-recipient", Pool::Ironwood, &s.payment, &sign(with_opened(receipts_core::OpenedOutput { address: fvk.address_at(0u32, Scope::External).to_raw_address_bytes(), ..op.clone() }), &[&rsk]), COIN_TYPE_TESTNET);
    add("resigned/opened-other-psi", Pool::Ironwood, &s.payment, &sign(with_opened(receipts_core::OpenedOutput { psi: [2; 32], ..op.clone() }), &[&rsk]), COIN_TYPE_TESTNET);
    add("resigned/opened-noncanonical-rcm", Pool::Ironwood, &s.payment, &sign(with_opened(receipts_core::OpenedOutput { rcm: [0xff; 32], ..op.clone() }), &[&rsk]), COIN_TYPE_TESTNET);
    add("resigned/opened-and-ock-same-output", Pool::Ironwood, &s.payment, &sign(receipts_core::UnsignedReceipt { opened: vec![op.clone()], ..base.clone() }, &[&rsk]), COIN_TYPE_TESTNET);
    // Single-byte flips of an honest receipt, not re-signed.
    let bytes = a.to_bytes();
    for i in (0..bytes.len()).step_by(41).chain(bytes.len() - 64..bytes.len()).step_by(1) {
        let mut b = bytes.clone();
        b[i] ^= 0x10;
        if let Ok(r) = Receipt::from_bytes(&b) {
            add(&format!("flip/{i}"), Pool::Ironwood, &s.payment, &r, COIN_TYPE_TESTNET);
        }
    }
    let out = serde_json::json!({
        "bundles": { "ironwood": bundle_json(&s.payment), "orchard": bundle_json(&so.payment) },
        // The funding transaction of each scenario, at FUNDING_TXID, for source proofs.
        "source_txid": hex(&FUNDING_TXID),
        "source_bundles": { "ironwood": bundle_json(&s.funding), "orchard": bundle_json(&so.funding) },
        "cases": cases,
    });
    std::fs::write(path, serde_json::to_string_pretty(&out).unwrap()).unwrap();
}

// ---------- source proofs: where the spent money came from ----------

const FUNDING_TXID: [u8; 32] = [0xcd; 32];

fn funding_lookup(s: &Scenario) -> impl Fn(Pool, &[u8; 32], u32) -> Option<[u8; 32]> + '_ {
    move |_pool, txid, index| (txid == &FUNDING_TXID).then(|| receipts_core::output_cmx(&s.funding, index)).flatten()
}

fn source_witness(s: &Scenario, reveal_value: bool) -> receipts_core::SourceWitness {
    receipts_core::SourceWitness {
        txid: FUNDING_TXID,
        index: s.funding_index as u32,
        cmx: s.funding.actions()[s.funding_index].cmx().to_bytes(),
        reveal_value,
    }
}

fn receipt_with_source(s: &Scenario, pool: Pool, reveal_value: bool) -> Receipt {
    let fvk = FullViewingKey::from(&s.sender_sk);
    create(
        &keys().0,
        COIN_TYPE_TESTNET,
        pool,
        TXID,
        &s.payment,
        b"deposit to exchange B",
        &[(s.merchant_index, fvk.to_ovk(Scope::External))],
        &[SpendWitness {
            index: s.spend_index,
            sk: s.sender_sk.clone(),
            note: s.funding_note,
            merkle_path: s.funding_path.clone(),
            prove_address: None,
            source: Some(source_witness(s, reveal_value)),
        }],
        OsRng,
    )
    .unwrap()
}

fn source_roundtrip(version: BundleVersion, pool: Pool) {
    let s = scenario(version);
    for reveal in [false, true] {
        let receipt = receipt_with_source(&s, pool, reveal);
        assert_eq!(receipt.to_bytes()[4], 4, "a receipt with a source proof is format v4");
        let parsed = Receipt::from_text(&receipt.to_text()).unwrap();
        assert_eq!(parsed, receipt);
        let lookup = funding_lookup(&s);
        let v = receipts_core::verify_with_sources(&keys().1, &parsed, COIN_TYPE_TESTNET, pool, TXID, &s.payment, &lookup).unwrap();
        assert_eq!(
            v.sources,
            vec![receipts_core::VerifiedSource {
                spend: s.spend_index as u32,
                txid: FUNDING_TXID,
                index: s.funding_index as u32,
                value: reveal.then_some(100_000),
            }]
        );
        assert_eq!(v.outputs[0].value, s.merchant_value);
        // A verifier that can't see the source transaction refuses rather than ignoring the claim.
        assert_eq!(verify(&keys().1, &parsed, COIN_TYPE_TESTNET, pool, TXID, &s.payment).unwrap_err(), Error::SourceUnavailable(s.spend_index as u32));
        println!("{pool:?} receipt with source (reveal={reveal}): {} bytes", receipt.to_bytes().len());
        if let Ok(dir) = std::env::var("RECEIPT_FIXTURE_DIR") {
            std::fs::write(format!("{dir}/{pool:?}-source-{reveal}.receipt"), receipt.to_text()).unwrap();
        }
    }
}

#[test]
fn ironwood_source_roundtrip() {
    source_roundtrip(BundleVersion::ironwood_v3(), Pool::Ironwood);
}

#[test]
fn orchard_source_roundtrip() {
    source_roundtrip(BundleVersion::orchard_v2(), Pool::Orchard);
}

#[test]
fn a_source_must_be_the_output_that_created_the_note() {
    let s = scenario(BundleVersion::ironwood_v3());
    let receipt = receipt_with_source(&s, Pool::Ironwood, false);
    let i = s.spend_index as u32;
    // The claimed index points at another output of the source transaction (its dummy action).
    let other = (s.funding_index + 1) % s.funding.actions().len();
    let wrong_output = |_p: Pool, _t: &[u8; 32], _i: u32| receipts_core::output_cmx(&s.funding, other as u32);
    assert_eq!(receipts_core::verify_with_sources(&keys().1, &receipt, COIN_TYPE_TESTNET, Pool::Ironwood, TXID, &s.payment, &wrong_output).unwrap_err(), Error::BadSourceProof(i));
    // ...or at an output of an unrelated transaction (here: the merchant's output of the payment).
    let unrelated = |_p: Pool, _t: &[u8; 32], _i: u32| receipts_core::output_cmx(&s.payment, s.merchant_index as u32);
    assert_eq!(receipts_core::verify_with_sources(&keys().1, &receipt, COIN_TYPE_TESTNET, Pool::Ironwood, TXID, &s.payment, &unrelated).unwrap_err(), Error::BadSourceProof(i));
    // `create` refuses a source whose cmx isn't the note's.
    let fvk = FullViewingKey::from(&s.sender_sk);
    let mut bad = source_witness(&s, false);
    bad.cmx = s.funding.actions()[other].cmx().to_bytes();
    let w = SpendWitness { index: s.spend_index, sk: s.sender_sk.clone(), note: s.funding_note, merkle_path: s.funding_path.clone(), prove_address: None, source: Some(bad) };
    assert_eq!(create(&keys().0, COIN_TYPE_TESTNET, Pool::Ironwood, TXID, &s.payment, b"", &[(s.merchant_index, fvk.to_ovk(Scope::External))], &[w], OsRng).unwrap_err(), Error::WrongSource(i));
}

#[test]
fn source_claims_are_bound_by_the_signature_and_the_proof() {
    use receipts_core::{SourceProof, SourceValue};
    let s = scenario(BundleVersion::ironwood_v3());
    let lookup = funding_lookup(&s);
    let check = |r: &Receipt| receipts_core::verify_with_sources(&keys().1, r, COIN_TYPE_TESTNET, Pool::Ironwood, TXID, &s.payment, &lookup);
    let hidden = receipt_with_source(&s, Pool::Ironwood, false);
    let revealed = receipt_with_source(&s, Pool::Ironwood, true);
    let edit = |r: &Receipt, f: &dyn Fn(&mut SourceProof)| {
        let mut r = r.clone();
        f(r.unsigned.spends[0].source.as_mut().unwrap());
        r
    };
    let set_value = |p: &mut SourceProof, v: u64| {
        if let SourceValue::Revealed { value, .. } = &mut p.value {
            *value = v;
        }
    };
    // Edits without re-signing break the signature.
    assert_eq!(check(&edit(&revealed, &|p| set_value(p, 1_000_000))).unwrap_err(), Error::BadSignature(s.spend_index as u32));
    assert!(check(&edit(&hidden, &|p| p.index += 1)).is_err());
    // Dropping the source proof breaks the signature too (the claim can't be silently removed).
    let mut dropped = hidden.clone();
    dropped.unsigned.spends[0].source = None;
    assert!(check(&dropped).is_err());

    // The signer themself can't lie about the value either: re-sign with a known alpha.
    use ff::Field;
    let mut rng = OsRng;
    let alpha = pasta_curves::pallas::Scalar::random(&mut rng);
    let rsk = SpendAuthorizingKey::from(&s.sender_sk).randomize(&alpha);
    let rk = orchard::primitives::redpallas::VerificationKey::from(&rsk);
    let fvk = FullViewingKey::from(&s.sender_sk);
    let mut spend = honest_spend(&s, &s.payment, alpha);
    let honest_source = |reveal: bool| {
        receipts_core::__source_proof_for_tests(&keys().0, Pool::Ironwood, s.spend_index as u32, &fvk, s.funding_note, &source_witness(&s, reveal), alpha, &rk, &mut { OsRng }).unwrap()
    };
    let resign = |spend: receipts_core::SpendDisclosure| {
        let unsigned = receipts_core::UnsignedReceipt { coin_type: COIN_TYPE_TESTNET, pool: Pool::Ironwood, output_pool: None, txid: TXID, msg: vec![], outputs: vec![], opened: vec![], spends: vec![spend] };
        let digest = receipts_core::signing_digest(&unsigned);
        Receipt { spend_auth_sigs: vec![(&rsk.sign(OsRng, &digest)).into()], unsigned }
    };
    let bad = Error::BadSourceProof(s.spend_index as u32);
    let opened = honest_source(true);
    spend.source = Some(opened.clone());
    assert_eq!(check(&resign(spend.clone())).unwrap().sources[0].value, Some(100_000));
    spend.source = Some(honest_source(false));
    assert_eq!(check(&resign(spend.clone())).unwrap().sources[0].value, None);
    // Revealing any other value than the note's fails, smaller or larger.
    for lie in [1, 99_999, 100_001, 1_000_000] {
        let mut p = opened.clone();
        set_value(&mut p, lie);
        spend.source = Some(p);
        assert_eq!(check(&resign(spend.clone())).unwrap_err(), bad, "value {lie} accepted");
    }
    // A hidden-value proof can't be relabelled as revealing 1 zatoshi (its output isn't 0), and
    // a revealed one can't be relabelled as hidden with a made-up output.
    let SourceValue::Hidden { cmx } = honest_source(false).value else { unreachable!() };
    let hidden_proof = honest_source(false);
    for addr_seed in [([0u8; 43], [0u8; 32]), (s.funding_note.recipient().to_raw_address_bytes(), *s.funding_note.rseed().as_bytes())] {
        spend.source = Some(SourceProof { value: SourceValue::Revealed { value: 1, address: addr_seed.0, rseed: addr_seed.1 }, ..hidden_proof.clone() });
        assert_eq!(check(&resign(spend.clone())).unwrap_err(), bad);
    }
    spend.source = Some(SourceProof { value: SourceValue::Hidden { cmx }, ..opened.clone() });
    assert_eq!(check(&resign(spend.clone())).unwrap_err(), bad);
    // A source proof made under another receipt's key doesn't transfer.
    spend.source = hidden.unsigned.spends[0].source.clone();
    assert_eq!(check(&resign(spend.clone())).unwrap_err(), bad);
}

/// The forgery that fixing `cv_net` prevents. The circuit only checks the anchor when the spent
/// value is non-zero, so the owner of a *zero-value* note could otherwise "prove" it came from any
/// output at all, for instance a withdrawal from a regulated exchange they never received.
#[test]
fn a_zero_value_note_cannot_claim_any_source() {
    use ff::Field;
    use orchard::{
        builder::SpendInfo,
        circuit::{Circuit, Instance, OrchardCircuitVersion},
        note::{RandomSeed, Rho},
        primitives::redpallas::{SpendAuth, VerificationKey},
        value::{ValueCommitTrapdoor, ValueCommitment},
        Proof,
    };
    let s = scenario_valued(BundleVersion::ironwood_v3(), 0, 0);
    assert_eq!(s.funding_note.value().inner(), 0);
    let victim = scenario(BundleVersion::ironwood_v3());
    let claimed: ExtractedNoteCommitment = *victim.funding.actions()[victim.funding_index].cmx();
    let mut rng = OsRng;
    let fvk = FullViewingKey::from(&s.sender_sk);
    let alpha = pasta_curves::pallas::Scalar::random(&mut rng);
    let rsk = SpendAuthorizingKey::from(&s.sender_sk).randomize(&alpha);
    let rk = VerificationKey::<SpendAuth>::from(&rsk);
    // `create` refuses outright.
    let w = SpendWitness { index: s.spend_index, sk: s.sender_sk.clone(), note: s.funding_note, merkle_path: s.funding_path.clone(), prove_address: None, source: Some(source_witness(&s, false)) };
    assert_eq!(create(&keys().0, COIN_TYPE_TESTNET, Pool::Ironwood, TXID, &s.payment, b"", &[], &[w], OsRng).unwrap_err(), Error::ZeroValueSource);
    // A hand-made proof: the real (zero-value) note, witnessed against the claimed output's tree.
    let (_, claimed_path) = single_leaf_witness(&claimed);
    let anchor = claimed_path.root(claimed);
    let nf = s.funding_note.nullifier(&fvk);
    let spend = SpendInfo::new(fvk.clone(), s.funding_note, claimed_path).unwrap();
    let rho = Rho::from_bytes(&nf.to_bytes()).unwrap();
    let out = loop {
        let mut b = [0u8; 32];
        rand::rand_core::Rng::fill_bytes(&mut rng, &mut b);
        if let Some(rs) = Option::<RandomSeed>::from(RandomSeed::from_bytes(b, &rho)) {
            if let Some(n) = Option::<Note>::from(Note::from_parts(fvk.address_at(0u32, Scope::External), NoteValue::ZERO, rho, rs, s.funding_note.version())) {
                break n;
            }
        }
    };
    let zero = ValueCommitTrapdoor::from_bytes([0; 32]).unwrap();
    let cv_own = ValueCommitment::derive(NoteValue::from_raw(0) - NoteValue::ZERO, zero.clone());
    let cmx: ExtractedNoteCommitment = out.commitment().into();
    let circuit = Circuit::from_action_context(spend, out, alpha, zero, OrchardCircuitVersion::PostNu6_3).unwrap();
    let instance = Instance::from_parts(anchor, cv_own.clone(), nf, rk.clone(), cmx, Flags::ENABLED).unwrap();
    let proof = Proof::create(&keys().0, &[circuit], std::slice::from_ref(&instance), &mut rng).unwrap();
    // The proof is valid for the prover's own value commitment: this is a real forgery...
    assert!(proof.verify(&keys().1, &[instance]).is_ok(), "the forgery should satisfy the circuit");
    // ...which the verifier refuses because it fixes the value commitment itself.
    let mut honest = honest_spend(&s, &s.payment, alpha);
    let lookup = |_p: Pool, _t: &[u8; 32], _i: u32| Some(claimed.to_bytes());
    for claimed_value in [None, Some(1u64), Some(100_000)] {
        let value = match claimed_value {
            None => receipts_core::SourceValue::Hidden { cmx: cmx.to_bytes() },
            Some(v) => receipts_core::SourceValue::Revealed { value: v, address: out.recipient().to_raw_address_bytes(), rseed: *out.rseed().as_bytes() },
        };
        honest.source = Some(receipts_core::SourceProof { txid: FUNDING_TXID, index: 0, value, proof: proof.as_ref().to_vec() });
        let unsigned = receipts_core::UnsignedReceipt { coin_type: COIN_TYPE_TESTNET, pool: Pool::Ironwood, output_pool: None, txid: TXID, msg: vec![], outputs: vec![], opened: vec![], spends: vec![honest.clone()] };
        let digest = receipts_core::signing_digest(&unsigned);
        let forged = Receipt::from_bytes(&Receipt { spend_auth_sigs: vec![(&rsk.sign(OsRng, &digest)).into()], unsigned }.to_bytes()).unwrap();
        let res = receipts_core::verify_with_sources(&keys().1, &forged, COIN_TYPE_TESTNET, Pool::Ironwood, TXID, &s.payment, &lookup);
        assert_eq!(res.unwrap_err(), Error::BadSourceProof(s.spend_index as u32), "a zero-value note claimed a source (value {claimed_value:?})");
    }
}

/// Source proofs reveal the link the payer chose to reveal, and nothing that links this receipt
/// to the transaction's own `rk` or to another receipt for the same spend.
#[test]
fn source_proofs_stay_unlinkable() {
    let s = scenario(BundleVersion::ironwood_v3());
    let a = receipt_with_source(&s, Pool::Ironwood, false);
    let b = receipt_with_source(&s, Pool::Ironwood, false);
    let (sa, sb) = (&a.unsigned.spends[0], &b.unsigned.spends[0]);
    assert_ne!(sa.rk, sb.rk);
    assert_ne!(sa.source, sb.source);
    let tx_rk: [u8; 32] = s.payment.actions()[s.spend_index].rk().into();
    assert_ne!(sa.rk, tx_rk);
    // Hidden value: the encoding carries no value and no value commitment.
    assert_eq!(sa.source.as_ref().unwrap().revealed_value(), None);
}

// ---------- outputs disclosed without their memo (per-field disclosure) ----------

fn receipt_memo_withheld(s: &Scenario, pool: Pool) -> Receipt {
    let fvk = FullViewingKey::from(&s.sender_sk);
    receipts_core::create_cross_ext(
        &keys().0,
        COIN_TYPE_TESTNET,
        pool,
        &s.payment,
        pool,
        &s.payment,
        TXID,
        b"paid, memo withheld",
        &[],
        &[(s.merchant_index, fvk.to_ovk(Scope::External))],
        &[SpendWitness { index: s.spend_index, sk: s.sender_sk.clone(), note: s.funding_note, merkle_path: s.funding_path.clone(), prove_address: None, source: None }],
        OsRng,
    )
    .unwrap()
}

fn memo_withheld_roundtrip(version: BundleVersion, pool: Pool) {
    let s = scenario(version);
    let r = receipt_memo_withheld(&s, pool);
    assert_eq!(r.to_bytes()[4], 5, "a receipt with a memo-withheld output is format v5");
    let parsed = Receipt::from_text(&r.to_text()).unwrap();
    assert_eq!(parsed, r);
    let v = verify(&keys().1, &parsed, COIN_TYPE_TESTNET, pool, TXID, &s.payment).unwrap();
    assert_eq!(v.outputs.len(), 1);
    let o = &v.outputs[0];
    assert!(o.memo_withheld);
    assert_eq!(o.value, s.merchant_value);
    assert_eq!(o.memo, [0; 512]);
    let merchant = FullViewingKey::from(&SpendingKey::from_bytes([9; 32]).unwrap()).address_at(3u32, Scope::External);
    assert_eq!(o.recipient, merchant.to_raw_address_bytes());
    // The receipt carries nothing that opens the memo: no ock and not the note's rseed (from
    // which esk, and so the memo key, derive).
    let fvk = FullViewingKey::from(&s.sender_sk);
    let action = &s.payment.actions()[s.merchant_index];
    let ovk = fvk.to_ovk(Scope::External);
    let note = s.payment.recover_output_with_ovk(s.merchant_index, &ovk).map(|(n, _, _)| n).or_else(|| {
        // Ironwood bundles need the Ironwood domain.
        zcash_note_encryption::try_output_recovery_with_ovk(&IronwoodDomain::for_action(action), &ovk, action, action.cv_net(), &action.encrypted_note().out_ciphertext).map(|(n, _, _)| n)
    });
    let note = note.expect("sender recovers its own output");
    let bytes = r.to_bytes();
    assert!(!bytes.windows(32).any(|w| w == note.rseed().as_bytes()), "rseed must not be in the receipt");
    assert!(r.unsigned.outputs.is_empty(), "no ock for the withheld output");
    println!("{pool:?} memo-withheld receipt: {} bytes", bytes.len());
    if let Ok(dir) = std::env::var("RECEIPT_FIXTURE_DIR") {
        std::fs::write(format!("{dir}/{pool:?}-memo-withheld.receipt"), r.to_text()).unwrap();
    }
}

#[test]
fn ironwood_memo_withheld_roundtrip() {
    memo_withheld_roundtrip(BundleVersion::ironwood_v3(), Pool::Ironwood);
}

#[test]
fn orchard_memo_withheld_roundtrip() {
    memo_withheld_roundtrip(BundleVersion::orchard_v2(), Pool::Orchard);
}

/// The signer can't change what an opened output says: a different value, recipient, or a
/// different opening of the same commitment is refused, and an index can't be disclosed twice.
#[test]
fn opened_outputs_must_open_the_commitment() {
    use ff::Field;
    let s = scenario(BundleVersion::ironwood_v3());
    let good = receipt_memo_withheld(&s, Pool::Ironwood);
    let o = good.unsigned.opened[0].clone();
    let mut rng = OsRng;
    let alpha = pasta_curves::pallas::Scalar::random(&mut rng);
    let rsk = SpendAuthorizingKey::from(&s.sender_sk).randomize(&alpha);
    let spend = honest_spend(&s, &s.payment, alpha);
    let sign = |opened: Vec<receipts_core::OpenedOutput>, outputs: Vec<receipts_core::OutputDisclosure>| {
        let u = receipts_core::UnsignedReceipt { coin_type: COIN_TYPE_TESTNET, pool: Pool::Ironwood, output_pool: None, txid: TXID, msg: vec![], outputs, opened, spends: vec![spend.clone()] };
        let d = receipts_core::signing_digest(&u);
        Receipt { spend_auth_sigs: vec![(&rsk.sign(OsRng, &d)).into()], unsigned: u }
    };
    let check = |r: &Receipt| verify(&keys().1, r, COIN_TYPE_TESTNET, Pool::Ironwood, TXID, &s.payment);
    let i = o.index;
    assert!(check(&sign(vec![o.clone()], vec![])).is_ok());
    for (what, bad) in [
        ("value + 1", receipts_core::OpenedOutput { value: o.value + 1, ..o.clone() }),
        ("value - 1", receipts_core::OpenedOutput { value: o.value - 1, ..o.clone() }),
        ("another recipient", receipts_core::OpenedOutput { address: FullViewingKey::from(&s.sender_sk).address_at(0u32, Scope::External).to_raw_address_bytes(), ..o.clone() }),
        ("another psi", receipts_core::OpenedOutput { psi: [1; 32], ..o.clone() }),
        ("another rcm", receipts_core::OpenedOutput { rcm: [1; 32], ..o.clone() }),
        ("non-canonical psi", receipts_core::OpenedOutput { psi: [0xff; 32], ..o.clone() }),
        ("another output", receipts_core::OpenedOutput { index: (i + 1) % s.payment.actions().len() as u32, ..o.clone() }),
    ] {
        assert!(check(&sign(vec![bad], vec![])).is_err(), "{what} accepted");
    }
    // Disclosing the same output both ways, or twice opened, is refused.
    let fvk = FullViewingKey::from(&s.sender_sk);
    let full = make_receipt(&s, Pool::Ironwood, b"x");
    assert_eq!(check(&sign(vec![o.clone()], full.unsigned.outputs.clone())).unwrap_err(), Error::DuplicateIndex(i));
    assert_eq!(check(&sign(vec![o.clone(), o.clone()], vec![])).unwrap_err(), Error::DuplicateIndex(i));
    let both = receipts_core::create_cross_ext(&keys().0, COIN_TYPE_TESTNET, Pool::Ironwood, &s.payment, Pool::Ironwood, &s.payment, TXID, b"", &[(s.merchant_index, fvk.to_ovk(Scope::External))], &[(s.merchant_index, fvk.to_ovk(Scope::External))], &[SpendWitness { index: s.spend_index, sk: s.sender_sk.clone(), note: s.funding_note, merkle_path: s.funding_path.clone(), prove_address: None, source: None }], OsRng);
    assert_eq!(both.unwrap_err(), Error::DuplicateIndex(i));
    // Editing the opening without re-signing breaks the signature.
    let mut edited = good.clone();
    edited.unsigned.opened[0].value += 1;
    assert!(check(&edited).is_err());
}

// ---------- incoming receipts: the recipient proves it was paid ----------

fn incoming(s: &Scenario, pool: Pool) -> receipts_core::incoming::IncomingReceipt {
    let merchant_sk = SpendingKey::from_bytes([9; 32]).unwrap();
    receipts_core::incoming::create_incoming(&keys().0, COIN_TYPE_TESTNET, pool, TXID, &s.payment, b"challenge:ab12cd", &merchant_sk, &[s.merchant_index], OsRng).unwrap()
}

fn incoming_roundtrip(version: BundleVersion, pool: Pool) {
    use receipts_core::incoming::{verify_incoming, IncomingReceipt};
    let s = scenario(version);
    let r = incoming(&s, pool);
    let text = r.to_text();
    assert!(text.starts_with("zrcin1"));
    let parsed = IncomingReceipt::from_text(&text).unwrap();
    assert_eq!(parsed, r);
    let v = verify_incoming(&keys().1, &parsed, COIN_TYPE_TESTNET, TXID, &s.payment).unwrap();
    let merchant = FullViewingKey::from(&SpendingKey::from_bytes([9; 32]).unwrap()).address_at(3u32, Scope::External);
    assert_eq!(v.recipient, merchant.to_raw_address_bytes());
    assert_eq!(v.outputs.len(), 1);
    assert_eq!(v.outputs[0].value, s.merchant_value);
    assert_eq!(&v.outputs[0].memo[..10], b"Invoice 42");
    assert_eq!(v.msg, b"challenge:ab12cd");
    // With no indices, the wallet finds its own outputs.
    let merchant_sk = SpendingKey::from_bytes([9; 32]).unwrap();
    let auto = receipts_core::incoming::create_incoming(&keys().0, COIN_TYPE_TESTNET, pool, TXID, &s.payment, b"", &merchant_sk, &[], OsRng).unwrap();
    assert_eq!(auto.outputs.iter().map(|o| o.index).collect::<Vec<_>>(), vec![s.merchant_index as u32]);
    // No nullifier of the received note appears (its later spend stays unlinkable).
    let n = decrypt(version, &s.payment, &FullViewingKey::from(&merchant_sk));
    let nf = n.nullifier(&FullViewingKey::from(&merchant_sk)).to_bytes();
    assert!(!r.to_bytes().windows(32).any(|w| w == nf), "the received note's nullifier is in the receipt");
    println!("{pool:?} incoming receipt: {} bytes", r.to_bytes().len());
}

#[test]
fn ironwood_incoming_roundtrip() {
    incoming_roundtrip(BundleVersion::ironwood_v3(), Pool::Ironwood);
}

#[test]
fn orchard_incoming_roundtrip() {
    incoming_roundtrip(BundleVersion::orchard_v2(), Pool::Orchard);
}

/// Only the recipient can make one. The sender knows `esk` (its outgoing viewing key recovers
/// it) but not the recipient's keys, so it can't prove the address; with its own address the
/// output doesn't open. Edits, other outputs, other transactions and networks are refused.
#[test]
fn only_the_recipient_can_prove_receipt() {
    use receipts_core::incoming::{create_incoming, verify_incoming, IncomingOutput, IncomingReceipt};
    let s = scenario(BundleVersion::ironwood_v3());
    let good = incoming(&s, Pool::Ironwood);
    let check = |r: &IncomingReceipt| verify_incoming(&keys().1, r, COIN_TYPE_TESTNET, TXID, &s.payment);
    assert!(check(&good).is_ok());
    // The sender's wallet can't find the output as received.
    assert!(create_incoming(&keys().0, COIN_TYPE_TESTNET, Pool::Ironwood, TXID, &s.payment, b"", &s.sender_sk, &[s.merchant_index], OsRng).is_err());
    // The sender, with the right esk, signing for its own address, is refused: the output
    // doesn't open to that address.
    use receipts_core::incoming::__sign_unchecked_for_tests as sign_for;
    let sender_addr = FullViewingKey::from(&s.sender_sk).address_at(0u32, Scope::External);
    let claim = sign_for(&keys().0, COIN_TYPE_TESTNET, Pool::Ironwood, TXID, b"", &s.sender_sk, sender_addr, good.outputs.clone(), OsRng).unwrap();
    assert_eq!(check(&claim).unwrap_err(), Error::BadOutputKey(s.merchant_index as u32), "the sender proved receipt of the merchant's payment");
    // The recipient itself, validly signing wrong contents, is refused too.
    let merchant_sk = SpendingKey::from_bytes([9; 32]).unwrap();
    let merchant = FullViewingKey::from(&merchant_sk).address_at(3u32, Scope::External);
    let resign = |outputs: Vec<IncomingOutput>| sign_for(&keys().0, COIN_TYPE_TESTNET, Pool::Ironwood, TXID, b"", &merchant_sk, merchant, outputs, OsRng).unwrap();
    let i = s.merchant_index as u32;
    let e = good.outputs[0].esk;
    assert!(check(&resign(vec![IncomingOutput { index: i, esk: e }])).is_ok());
    let other = ((s.merchant_index + 1) % s.payment.actions().len()) as u32;
    assert_eq!(check(&resign(vec![IncomingOutput { index: other, esk: e }])).unwrap_err(), Error::BadOutputKey(other));
    let mut e2 = e;
    e2[0] ^= 1;
    assert_eq!(check(&resign(vec![IncomingOutput { index: i, esk: e2 }])).unwrap_err(), Error::BadOutputKey(i));
    assert_eq!(check(&resign(vec![IncomingOutput { index: i, esk: e }; 2])).unwrap_err(), Error::DuplicateIndex(i));
    assert_eq!(check(&resign(vec![IncomingOutput { index: 99, esk: e }])).unwrap_err(), Error::IndexOutOfRange(99));
    assert!(check(&resign(vec![])).is_err(), "an empty incoming receipt proves nothing");
    // Edits without the key break the signature.
    let mut edited = good.clone();
    edited.msg = b"challenge:000000".to_vec();
    assert_eq!(check(&edited).unwrap_err(), Error::BadSignature(0));
    assert!(verify_incoming(&keys().1, &good, COIN_TYPE_MAINNET, TXID, &s.payment).is_err());
    assert!(verify_incoming(&keys().1, &good, COIN_TYPE_TESTNET, [0x11; 32], &s.payment).is_err());
    // Canonical decoding: trailing bytes or a truncation don't decode.
    let mut b = good.to_bytes();
    b.push(0);
    assert!(IncomingReceipt::from_bytes(&b).is_none());
    assert!(IncomingReceipt::from_bytes(&good.to_bytes()[..100]).is_none());
}
