//! A receipt for a treasury whose spend key is split 2-of-3 with FROST (the Zcash Foundation's
//! re-randomized FROST over Pallas): any two signers make the receipt's signature with the
//! receipt's own randomizer, and it verifies like any other; nothing shows which two signed.

use incrementalmerkletree::{Hashable, Marking, Retention};
use orchard::{
    builder::{Builder, BundleType},
    bundle::{BundleVersion, Flags, TxVersion},
    keys::{FullViewingKey, PreparedIncomingViewingKey, Scope, SpendingKey},
    note::ExtractedNoteCommitment,
    note_encryption::IronwoodDomain,
    tree::{MerkleHashOrchard, MerklePath},
    value::NoteValue,
};
use rand::{rand_core::UnwrapErr, rngs::SysRng};
use receipts_core::{prepare, signing_digest, verify, Pool, ViewingSpendWitness, COIN_TYPE_TESTNET};
use reddsa05::frost::redpallas::{self as frost, keys::EvenY, rerandomized};
use shardtree::{store::memory::MemoryShardStore, ShardTree};
use std::collections::BTreeMap;

#[allow(non_upper_case_globals)]
const OsRng: UnwrapErr<SysRng> = UnwrapErr(SysRng);
const TXID: [u8; 32] = [0xab; 32];

#[test]
#[allow(deprecated)] // frost_rerandomized::sign takes the randomizer directly; the receipt fixes it.
fn a_frost_treasury_signs_a_receipt_with_any_two_of_three() {
    let mut rng = OsRng;
    let rng06 = rand_core06::OsRng;
    let version = BundleVersion::ironwood_v3();
    let pk = receipts_core::proving_key();
    let vk = receipts_core::verifying_key();

    // A 2-of-3 key: the group's verifying key is the treasury's `ak` (even y, as Orchard requires).
    let (shares, pubkeys) = frost::keys::generate_with_dealer(3, 2, frost::keys::IdentifierList::Default, rng06).unwrap();
    let pubkeys = pubkeys.into_even_y(None);
    let shares: BTreeMap<_, _> = shares.into_iter().map(|(id, s)| (id, s.into_even_y(None))).collect();
    let ak: [u8; 32] = pubkeys.verifying_key().serialize().unwrap().try_into().unwrap();
    // The treasury's full viewing key: the group ak with its own nk and rivk.
    let other = FullViewingKey::from(&SpendingKey::from_bytes([5; 32]).unwrap()).to_bytes();
    let mut fvk_bytes = [0u8; 96];
    fvk_bytes[..32].copy_from_slice(&ak);
    fvk_bytes[32..].copy_from_slice(&other[32..]);
    let fvk = FullViewingKey::from_bytes(&fvk_bytes).expect("an even-y group key is a valid ak");
    let treasury = fvk.address_at(0u32, Scope::External);
    let payee = FullViewingKey::from(&SpendingKey::from_bytes([9; 32]).unwrap()).address_at(0u32, Scope::External);

    // Funded, then paying a grantee. The payment's own signature isn't what a receipt checks, so
    // the test leaves it unsigned (the treasury would sign it with FROST too).
    let empty: orchard::Anchor = MerkleHashOrchard::empty_root(32.into()).into();
    let mut b = Builder::new(BundleType::DEFAULT, version, Flags::SPENDS_DISABLED, empty).unwrap();
    b.add_output(None, treasury, NoteValue::from_raw(500_000), [0u8; 512]).unwrap();
    let (unauth, _) = b.build::<i64>(&mut rng).unwrap().unwrap();
    let sighash: [u8; 32] = unauth.commitment(TxVersion::V6).unwrap().into();
    let funding = unauth.create_proof(&pk, &mut rng).unwrap().apply_signatures(rng, sighash, &[]).unwrap();
    let ivk = PreparedIncomingViewingKey::new(&fvk.to_ivk(Scope::External));
    let note = funding.actions().iter().find_map(|a| zcash_note_encryption::try_note_decryption(&IronwoodDomain::for_action(a), &ivk, a)).unwrap().0;
    let cmx: ExtractedNoteCommitment = note.commitment().into();
    let leaf = MerkleHashOrchard::from_cmx(&cmx);
    let mut tree: ShardTree<MemoryShardStore<MerkleHashOrchard, u32>, 32, 16> = ShardTree::new(MemoryShardStore::empty(), 100);
    tree.append(leaf, Retention::Checkpoint { id: 0, marking: Marking::Marked }).unwrap();
    let root = tree.root_at_checkpoint_id(&0).unwrap().unwrap();
    let path: MerklePath = tree.witness_at_checkpoint_id(0.into(), &0).unwrap().unwrap().into();

    let ovk = fvk.to_ovk(Scope::External);
    let mut b = Builder::new(BundleType::DEFAULT, version, version.default_flags(), root.into()).unwrap();
    b.add_spend(fvk.clone(), note, path.clone()).unwrap();
    let mut memo = [0u8; 512];
    memo[..21].copy_from_slice(b"Grant 7: wallet audit");
    b.add_output(Some(ovk.clone()), payee, NoteValue::from_raw(200_000), memo).unwrap();
    let (unauth, meta) = b.build::<i64>(&mut rng).unwrap().unwrap();
    let payment = unauth.create_proof(&pk, &mut rng).unwrap();

    // The receipt's proofs, from the treasury's viewing key alone.
    let w = ViewingSpendWitness { index: meta.spend_action_index(0).unwrap(), fvk: fvk.clone(), note, merkle_path: path, prove_address: None, source: None };
    let prepared = prepare(
        &pk,
        COIN_TYPE_TESTNET,
        Pool::Ironwood,
        &payment,
        Pool::Ironwood,
        &payment,
        TXID,
        b"Grant 7 paid",
        &[(meta.output_action_index(0).unwrap(), ovk)],
        &[],
        &[w],
        OsRng,
    )
    .unwrap();

    // FROST: two of the three sign the receipt's digest, re-randomized by the receipt's alpha.
    let digest = signing_digest(prepared.unsigned());
    let alpha = group::ff::PrimeField::to_repr(&prepared.alphas()[0]);
    let sign_with = |who: &[u16]| -> [u8; 64] {
        let randomizer = rerandomized::Randomizer::deserialize(&alpha).unwrap();
        let mut nonces = BTreeMap::new();
        let mut commitments = BTreeMap::new();
        for &i in who {
            let id = frost::Identifier::try_from(i).unwrap();
            let kp = frost::keys::KeyPackage::try_from(shares[&id].clone()).unwrap();
            let (n, c) = frost::round1::commit(kp.signing_share(), &mut rand_core06::OsRng);
            nonces.insert(id, (n, kp));
            commitments.insert(id, c);
        }
        let package = frost::SigningPackage::new(commitments, &digest);
        let mut sig_shares = BTreeMap::new();
        for (id, (n, kp)) in &nonces {
            sig_shares.insert(*id, frost_rerandomized::sign(&package, n, kp, randomizer).unwrap());
        }
        let params = rerandomized::RandomizedParams::from_randomizer(pubkeys.verifying_key(), randomizer);
        let sig = rerandomized::aggregate(&package, &sig_shares, &pubkeys, &params).unwrap();
        sig.serialize().unwrap().try_into().unwrap()
    };
    let receipt = prepared.clone().apply_signatures(vec![sign_with(&[1, 3])]).unwrap();
    let shown = verify(&vk, &receipt, COIN_TYPE_TESTNET, Pool::Ironwood, TXID, &payment).unwrap();
    assert_eq!(shown.msg, b"Grant 7 paid");
    assert_eq!(shown.outputs[0].value, 200_000);
    // Any other pair works the same way.
    let again = prepared.clone().apply_signatures(vec![sign_with(&[2, 3])]).unwrap();
    verify(&vk, &again, COIN_TYPE_TESTNET, Pool::Ironwood, TXID, &payment).unwrap();
    // One signer alone can't: a single share isn't the key.
    assert!(std::panic::catch_unwind(|| sign_with(&[2])).is_err());
}
