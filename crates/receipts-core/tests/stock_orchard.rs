//! Real testnet receipts verified through the public API only, so this file also runs against
//! stock `orchard` without the `orchard-ext` feature (`scripts/check-stock-orchard.sh`): the
//! receipt verifies, the edited copy is refused, and the receipt whose spend proof was altered
//! before signing is refused by the Halo 2 check.

use receipts_core::{verify_tx_bundles, Error, Receipt, COIN_TYPE_TESTNET};
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
    let txid: [u8; 32] = *tx.txid().as_ref();
    verify_tx_bundles(&receipts_core::verifying_key(), &r, COIN_TYPE_TESTNET, txid, tx.orchard_bundle(), tx.ironwood_bundle()).map(|_| ())
}

#[test]
fn real_testnet_receipts_on_the_public_api() {
    check(&example("receipt.txt")).unwrap();
    assert!(matches!(check(&example("receipt-edited.txt")), Err(Error::BadSignature(_))));
    assert!(matches!(check(&example("proof-only/receipt.txt")), Err(Error::BadProof(_))));
}
