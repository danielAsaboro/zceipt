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
    let mut rng = OsRng;
    let pk = network_pk(version);
    let sender_sk = SpendingKey::from_bytes([7; 32]).unwrap();
    let sender_fvk = FullViewingKey::from(&sender_sk);
    let sender_addr = sender_fvk.address_at(0u32, Scope::External);
    let merchant_sk = SpendingKey::from_bytes([9; 32]).unwrap();
    let merchant_addr = FullViewingKey::from(&merchant_sk).address_at(3u32, Scope::External);

    let empty: orchard::Anchor = MerkleHashOrchard::empty_root(32.into()).into();
    let mut b = Builder::new(BundleType::DEFAULT, version, Flags::SPENDS_DISABLED, empty).unwrap();
    b.add_output(None, sender_addr, NoteValue::from_raw(100_000), [0u8; 512]).unwrap();
    let (unauth, _) = b.build::<i64>(&mut rng).unwrap().unwrap();
    let sighash: [u8; 32] = unauth.commitment(TxVersion::V6).unwrap().into();
    let funding = unauth.create_proof(pk, &mut rng).unwrap().apply_signatures(rng, sighash, &[]).unwrap();

    let funding_note = decrypt(version, &funding, &sender_fvk);
    let cmx: ExtractedNoteCommitment = funding_note.commitment().into();
    let (root, funding_path) = single_leaf_witness(&cmx);

    let mut memo = [0u8; 512];
    memo[..10].copy_from_slice(b"Invoice 42");
    let ovk = sender_fvk.to_ovk(Scope::External);
    let mut b = Builder::new(BundleType::DEFAULT, version, version.default_flags(), root.into()).unwrap();
    b.add_spend(sender_fvk.clone(), funding_note, funding_path.clone()).unwrap();
    b.add_output(Some(ovk.clone()), merchant_addr, NoteValue::from_raw(42_000), memo).unwrap();
    b.add_output(Some(ovk), sender_addr, NoteValue::from_raw(58_000), [0u8; 512]).unwrap();
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
        payment,
        funding_note,
        funding_path,
        merchant_value: 42_000,
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
