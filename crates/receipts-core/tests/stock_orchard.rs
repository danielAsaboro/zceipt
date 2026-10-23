//! Real testnet receipts verified through the public API only, so this file also runs against
//! stock `orchard` without the `orchard-ext` feature (`scripts/check-stock-orchard.sh`): the
//! receipt verifies, the edited copy is refused, and the receipt whose spend proof was altered
//! before signing is refused by the Halo 2 check.

use receipts_core::{verify_transaction, Error, Receipt, COIN_TYPE_TESTNET};
use zcash_primitives::transaction::Transaction;
use zcash_protocol::consensus::{BlockHeight, BranchId, TEST_NETWORK};

fn example(path: &str) -> String {
    std::fs::read_to_string(format!("{}/../../examples/testnet/{path}", env!("CARGO_MANIFEST_DIR"))).unwrap()
}

fn check(receipt: &str) -> Result<(), Error> {
    let raw = (0..example("tx.hex").trim().len()).step_by(2).map(|i| u8::from_str_radix(&example("tx.hex").trim()[i..i + 2], 16).unwrap()).collect::<Vec<u8>>();
    let height = BlockHeight::from_u32(4_500_997);
    let tx = Transaction::read(&raw[..], BranchId::for_height(&TEST_NETWORK, height)).unwrap();
    let text = receipt.trim();
    let r = Receipt::from_text(&text[text.find("zip311r1").unwrap()..]).unwrap();
    verify_transaction(&receipts_core::verifying_key(), &r, COIN_TYPE_TESTNET, &tx).map(|_| ())
}

#[test]
fn real_testnet_receipts_on_the_public_api() {
    check(&example("receipt.txt")).unwrap();
    assert!(matches!(check(&example("receipt-edited.txt")), Err(Error::BadSignature(_))));
    assert!(matches!(check(&example("proof-only/receipt.txt")), Err(Error::BadProof(_))));
    // A receipt for another transaction, against this one: refused by the txid, computed here.
    assert!(matches!(check(&example("receipt-with-sender-address.txt")), Err(Error::TxidMismatch(_))));
}

/// Someone who saw the payment (a viewing-key holder, the merchant) can open its outputs, but
/// can't claim to have made it: put in their own key and sign, and the spend proof, made for the
/// payer's key, no longer holds. `RECEIPTS_WRITE_FIXTURES=1` writes the claim the verifier page
/// offers as a sample.
#[test]
fn someone_who_only_saw_the_payment_cannot_claim_it() {
    use orchard::keys::{SpendAuthorizingKey, SpendingKey};
    use orchard::primitives::redpallas::{self, SpendAuth};
    let text = example("receipt.txt");
    let mut claim = Receipt::from_text(&text.trim()[text.trim().find("zip311r1").unwrap()..]).unwrap();
    claim.unsigned.msg = b"Order #42 at Kemi's Coffee (paid by me, the observer)".to_vec();
    let sk = SpendingKey::from_bytes([42; 32]).unwrap();
    let rsk = SpendAuthorizingKey::from(&sk).randomize(&pasta_curves::pallas::Scalar::from(7u64));
    claim.unsigned.spends[0].rk = (&redpallas::VerificationKey::<SpendAuth>::from(&rsk)).into();
    let digest = receipts_core::signing_digest(&claim.unsigned);
    claim.spend_auth_sigs = vec![(&rsk.sign(rand::rand_core::UnwrapErr(rand::rngs::SysRng), &digest)).into()];
    let text = claim.to_text();
    assert!(matches!(check(&text), Err(Error::BadProof(_))), "the observer's claim must fail only on the proof");
    if std::env::var_os("RECEIPTS_WRITE_FIXTURES").is_some() {
        std::fs::write(format!("{}/../../examples/testnet/claimed-by-observer.txt", env!("CARGO_MANIFEST_DIR")), format!("{text}\n")).unwrap();
    }
}
