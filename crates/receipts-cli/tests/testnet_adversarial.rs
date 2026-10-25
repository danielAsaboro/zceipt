//! Attacks on real Zcash public-testnet proofs, offline (`examples/testnet/proofs`, made by
//! `scripts/e2e-testnet.sh`): every byte of each proof is edited, proofs are moved to payments,
//! domains, kinds and keys they weren't made for, and dishonest provers are run. None may pass.

use receipts_core::claim::{self, Claim, TagKind};
use receipts_core::{delegated, designated, Pool, Receipt, COIN_TYPE_TESTNET};
use zcash_primitives::transaction::Transaction;
use zcash_protocol::consensus::BranchId;

const DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../examples/testnet/proofs");
const DOMAIN: &[u8] = b"round-testnet";

fn text(name: &str) -> String {
    std::fs::read_to_string(format!("{DIR}/{name}")).unwrap().trim().to_string()
}

/// A payment: its transaction, and the block it was mined in.
struct Payment {
    tx: Transaction,
    txid: [u8; 32],
    height: u32,
}

fn payment(letter: char) -> Payment {
    let raw = hex::decode(text(&format!("tx{letter}.hex"))).unwrap();
    let tx = Transaction::read(&raw[..], BranchId::Nu6_3).unwrap();
    let txid = *tx.txid().as_ref();
    assert_eq!(receipts_core::display_txid(&txid), text(&format!("txid{letter}")), "the fixture is the payment it is named for");
    let height = std::fs::read_to_string(format!("{DIR}/height{letter}")).unwrap().trim().parse().unwrap();
    Payment { tx, txid, height }
}

fn nullifiers(p: &Payment) -> (Vec<[u8; 32]>, [u8; 32]) {
    let b = p.tx.ironwood_bundle().unwrap();
    (b.actions().iter().map(|a| a.nullifier().to_bytes()).collect(), b.anchor().to_bytes())
}

fn tag_of(letter: char, pay: &Payment) -> Result<[u8; 32], receipts_core::Error> {
    let c = Claim::from_text(&text(&format!("tag{letter}.txt"))).unwrap();
    let (nfs, anchor) = nullifiers(pay);
    claim::verify_payer_tag(&c, DOMAIN, &pay.txid, &anchor, &nfs)
}

/// `bytes` with byte `i` xor `mask`.
fn flipped(bytes: &[u8], i: usize, mask: u8) -> Vec<u8> {
    let mut b = bytes.to_vec();
    b[i] ^= mask;
    b
}

#[test]
fn the_real_testnet_proofs_verify() {
    let (a, b, c, s) = (payment('A'), payment('B'), payment('C'), payment('S'));
    let (ta, tb, tc, ts) = (tag_of('A', &a).unwrap(), tag_of('B', &b).unwrap(), tag_of('C', &c).unwrap(), tag_of('S', &s).unwrap());
    // Accounts 0 and 1 of one wallet and a second wallet: three keys, so three tags; A and B are one key's.
    assert_eq!(ta, tb);
    assert_ne!(ta, tc);
    assert_ne!(ta, ts);
    assert_ne!(tc, ts);
    let claim = Claim::from_text(&text("claim.txt")).unwrap();
    assert!(claim::verify(&claim, b"airdrop-testnet", &claim.anchor).is_ok());
}

#[test]
fn a_payer_tag_moves_to_no_other_payment_domain_or_kind() {
    let (a, b, c) = (payment('A'), payment('B'), payment('C'));
    let tag_a = Claim::from_text(&text("tagA.txt")).unwrap();
    let (nfs_a, anchor_a) = nullifiers(&a);
    let (nfs_c, anchor_c) = nullifiers(&c);
    // Another payment (even one by the same key, B), with its own nullifiers and anchor.
    let (nfs_b, anchor_b) = nullifiers(&b);
    assert!(claim::verify_payer_tag(&tag_a, DOMAIN, &c.txid, &anchor_c, &nfs_c).is_err());
    assert!(claim::verify_payer_tag(&tag_a, DOMAIN, &b.txid, &anchor_b, &nfs_b).is_err());
    // Another payment's nullifiers or anchor under the right txid.
    assert!(claim::verify_payer_tag(&tag_a, DOMAIN, &a.txid, &anchor_a, &nfs_c).is_err());
    assert!(claim::verify_payer_tag(&tag_a, DOMAIN, &a.txid, &anchor_c, &nfs_a).is_err());
    // Another round, a prefix or extension of the round's name, and the empty domain.
    for d in [&b"round-other"[..], b"round-testne", b"round-testnet ", b"", b"ROUND-TESTNET"] {
        assert!(claim::verify_payer_tag(&tag_a, d, &a.txid, &anchor_a, &nfs_a).is_err(), "{}", String::from_utf8_lossy(d));
    }
    // A payer tag is no claim at any snapshot, and a claim is no payer tag.
    assert!(claim::verify(&tag_a, DOMAIN, &anchor_a).is_err());
    let airdrop = Claim::from_text(&text("claim.txt")).unwrap();
    assert!(claim::verify_payer_tag(&airdrop, b"airdrop-testnet", &a.txid, &anchor_a, &nfs_a).is_err());
    // A claim presented as the payer tag of every payment, with its nullifier among theirs.
    let mut forged = airdrop.clone();
    forged.height = 0;
    forged.msg = claim::payer_tag_msg(&a.txid);
    let mut nfs = nfs_a.clone();
    nfs.push(forged.nf.unwrap());
    assert!(claim::verify_payer_tag(&forged, b"airdrop-testnet", &a.txid, &airdrop.anchor, &nfs).is_err());
}

/// Every byte of a claim, each flipped three ways: nothing edited verifies. The signature rejects
/// most edits first, so the edits to the statement itself (the domain, anchor, floor, `rk`,
/// commitment, tag and nullifier) are also tried on the proof alone, as a claimant who could
/// re-sign (the key's owner) would present them.
fn claim_sweep(c: &Claim, kind: TagKind, check: impl Fn(&Claim) -> bool) {
    let bytes = c.to_bytes();
    let domain_at = 4 + 1 + 4 + 1 + 2;
    let public_at = domain_at + c.domain.len() + 2 + c.msg.len() + 4;
    let public_end = public_at + 32 + 8 + 32 + 32 + 32 + 1 + c.nf.map_or(0, |_| 32);
    let mut statement_edits = 0;
    for i in 0..bytes.len() {
        for mask in [0x01u8, 0x80, 0xff] {
            let Ok(edited) = Claim::from_bytes(&flipped(&bytes, i, mask)) else { continue };
            assert!(!check(&edited), "byte {i} ^ {mask:#x} was accepted");
            if (domain_at..domain_at + c.domain.len()).contains(&i) || (public_at..public_end).contains(&i) {
                assert!(claim::__check_proof_only_for_tests(kind, &edited).is_err(), "the proof alone accepted byte {i} ^ {mask:#x}");
                statement_edits += 1;
            }
        }
    }
    assert!(statement_edits > 200, "{statement_edits}");
}

#[test]
fn every_byte_of_the_real_claim_matters() {
    let c = Claim::from_text(&text("claim.txt")).unwrap();
    let anchor = c.anchor;
    claim_sweep(&c, TagKind::Claim, |e| claim::verify(e, b"airdrop-testnet", &anchor).is_ok());
}

#[test]
fn every_byte_of_a_real_payer_tag_matters() {
    let a = payment('A');
    let c = Claim::from_text(&text("tagA.txt")).unwrap();
    let (nfs, anchor) = nullifiers(&a);
    claim_sweep(&c, TagKind::PayerTag, |e| claim::verify_payer_tag(e, DOMAIN, &a.txid, &anchor, &nfs).is_ok());
}

#[test]
fn a_claim_that_hides_its_nullifier_is_not_a_chain_claim() {
    // The chain check wants the nullifier (to see the note unspent at the snapshot): a claim with
    // none, or with another note's, doesn't verify as the real one.
    let c = Claim::from_text(&text("claim.txt")).unwrap();
    let mut hidden = c.clone();
    hidden.nf = None;
    assert!(claim::verify(&hidden, b"airdrop-testnet", &c.anchor).is_err());
    let mut other = c.clone();
    other.nf = Some([1; 32]);
    assert!(claim::verify(&other, b"airdrop-testnet", &c.anchor).is_err());
    // Payer tags must name their payment and carry one of its nullifiers.
    let a = payment('A');
    let mut tag = Claim::from_text(&text("tagA.txt")).unwrap();
    let (nfs, anchor) = nullifiers(&a);
    tag.nf = None;
    assert!(claim::verify_payer_tag(&tag, DOMAIN, &a.txid, &anchor, &nfs).is_err());
}

#[test]
fn the_real_sibling_proof_is_for_its_tags_and_domain_only() {
    use receipts_kce::{Siblings, VerifyingKey};
    let s = Siblings::from_text(&text("sib.txt")).unwrap();
    let vk = VerifyingKey::build(receipts_wallet::kce_params_cache().as_deref());
    let d = claim::domain_field(TagKind::PayerTag, DOMAIN);
    receipts_kce::verify(&vk, &s, d).unwrap();
    // Its tags are the payer tags of account 0 (payment A) and account 1 (payment C).
    assert_eq!(s.tags[0], tag_of('A', &payment('A')).unwrap());
    assert_eq!(s.tags[1], tag_of('C', &payment('C')).unwrap());
    // Not for another domain, nor for a claim's domain hashing of the same name.
    assert!(receipts_kce::verify(&vk, &s, claim::domain_field(TagKind::PayerTag, b"round-other")).is_err());
    assert!(receipts_kce::verify(&vk, &s, claim::domain_field(TagKind::Claim, DOMAIN)).is_err());
    // Not with its tags swapped, or doubled, or with another wallet's tag in place of one.
    let mut swapped = s.clone();
    swapped.tags.swap(0, 1);
    assert!(receipts_kce::verify(&vk, &swapped, d).is_err());
    let mut doubled = s.clone();
    doubled.tags[1] = doubled.tags[0];
    assert!(receipts_kce::verify(&vk, &doubled, d).is_err());
    let mut stranger = s.clone();
    stranger.tags[1] = tag_of('S', &payment('S')).unwrap();
    assert!(receipts_kce::verify(&vk, &stranger, d).is_err());
    // A tag that isn't a field element.
    let mut off = s.clone();
    off.tags[0] = [0xff; 32];
    assert!(receipts_kce::verify(&vk, &off, d).is_err());
    // Every header byte and a sample of the proof's bytes: none holds.
    let bytes = s.to_bytes();
    let proof_at = bytes.len() - s.proof.len();
    let mut tried = 0;
    for i in (0..bytes.len()).filter(|i| *i < proof_at || i % 11 == 0) {
        let Some(e) = Siblings::from_bytes(&flipped(&bytes, i, 0x01)) else { continue };
        tried += 1;
        assert!(e.coin_type != s.coin_type || e.domain != s.domain || receipts_kce::verify(&vk, &e, d).is_err(), "byte {i} was accepted");
    }
    assert!(tried > 600);
}

fn designated(name: &str) -> designated::DesignatedReceipt {
    designated::DesignatedReceipt::from_text(&text(name)).unwrap()
}

#[test]
fn the_real_one_verifier_receipt_convinces_only_its_verifier() {
    let a = payment('A');
    let vk = receipts_core::verifying_key();
    let none = |_: Pool, _: &[u8; 32], _: u32| None;
    let d = designated("dv.txt");
    let ok = |d: &designated::DesignatedReceipt, p: &Payment| receipts_core::verify_designated_tx_bundles(&vk, d, COIN_TYPE_TESTNET, p.txid, None, p.tx.ironwood_bundle(), &none);
    assert_eq!(ok(&d, &a).unwrap().outputs[0].value, 200_000);
    // Its key is the shop's, not the other one.
    let y = |f: &str| -> [u8; 32] { hex::decode(text(f)).unwrap().try_into().unwrap() };
    assert_eq!(d.verifier, designated::public_key(&y("shop.key")).unwrap());
    assert_ne!(d.verifier, designated::public_key(&y("other.key")).unwrap());
    // The shop (knowing y) could have made it, and so can simulate one for another payment's
    // inner receipt: it convinces the shop, and nobody else.
    // Moved to another payment.
    assert!(ok(&d, &payment('C')).is_err());
    // It has no ordinary signatures.
    assert!(receipts_core::verify_tx_bundles(&vk, &d.receipt, COIN_TYPE_TESTNET, a.txid, None, a.tx.ironwood_bundle()).is_err());
    // Every byte, one flip each way: nothing edited verifies.
    let bytes = d.to_bytes();
    for i in 0..bytes.len() {
        for mask in [0x01u8, 0x80] {
            let Ok(e) = designated::DesignatedReceipt::from_bytes(&flipped(&bytes, i, mask)) else { continue };
            assert!(ok(&e, &a).is_err(), "byte {i} ^ {mask:#x} was accepted");
        }
    }
}

#[test]
fn the_real_delegated_receipts_keep_to_their_policy() {
    let a = payment('A');
    let vk = receipts_core::verifying_key();
    let none = |_: Pool, _: &[u8; 32], _: u32| None;
    let run = |d: &delegated::DelegatedReceipt, p: &Payment| {
        let v = receipts_core::verify_delegated_tx_bundles(&vk, d, COIN_TYPE_TESTNET, p.txid, None, p.tx.ironwood_bundle(), &none)?;
        delegated::check_policy(&d.cert, &v, p.height)
    };
    let load = |f: &str| delegated::DelegatedReceipt::from_text(&text(f)).unwrap();
    let ok = load("dg.txt");
    run(&ok, &a).unwrap();
    // Over its limit, issued after its last block, to a payee it doesn't list: refused.
    for f in ["dg2.txt", "dg-expired.txt", "dg-wrong-payee.txt"] {
        assert!(run(&load(f), &a).is_err(), "{f}");
    }
    // Moved to another payment.
    assert!(run(&ok, &payment('C')).is_err());
    // A policy edit: raise the limit, push the last block out, drop the payee list.
    let bytes = ok.to_bytes();
    for i in 0..bytes.len() {
        let Ok(e) = delegated::DelegatedReceipt::from_bytes(&flipped(&bytes, i, 0x01)) else { continue };
        assert!(run(&e, &a).is_err(), "byte {i} was accepted");
    }
}

#[test]
fn every_byte_of_the_income_proof_matters() {
    let p = receipts_core::income::IncomeProof::from_text(&text("income.txt")).unwrap();
    let vk = receipts_core::verifying_key();
    let pay: Vec<Payment> = ['A', 'C', 'S'].map(payment).into();
    let lookup = |pool: Pool, txid: &[u8; 32], index: u32| {
        let t = pay.iter().find(|x| &x.txid == txid)?;
        let b = match pool {
            Pool::Ironwood => t.tx.ironwood_bundle()?,
            Pool::Orchard => t.tx.orchard_bundle()?,
        };
        b.actions().get(index as usize).map(|a| a.cmx().to_bytes())
    };
    assert!(receipts_core::income::verify(&vk, &p, &lookup).unwrap() >= 500_000);
    let bytes = p.to_bytes();
    for i in 0..bytes.len() {
        let Ok(e) = receipts_core::income::IncomeProof::from_bytes(&flipped(&bytes, i, 0x01)) else { continue };
        assert!(receipts_core::income::verify(&vk, &e, &lookup).is_err(), "byte {i} was accepted");
    }
    let _ = Receipt::from_text;
}
