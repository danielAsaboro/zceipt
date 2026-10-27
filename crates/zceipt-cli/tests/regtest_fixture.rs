//! Verifies the committed receipt for a real regtest Ironwood transaction, offline.

use zceipt_core::{Pool, Receipt, COIN_TYPE_TESTNET};
use zcash_address::unified::{self, Container, Encoding};
use zcash_primitives::transaction::Transaction;
use zcash_protocol::consensus::BranchId;

const DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../examples/regtest");

fn load() -> (Receipt, Transaction) {
    let receipt = Receipt::from_text(&std::fs::read_to_string(format!("{DIR}/receipt.txt")).unwrap()).unwrap();
    let raw = hex::decode(std::fs::read_to_string(format!("{DIR}/tx.hex")).unwrap().trim()).unwrap();
    // v6 transactions carry their consensus branch id in the header.
    let tx = Transaction::read(&raw[..], BranchId::Nu6_3).unwrap();
    (receipt, tx)
}

#[test]
fn committed_regtest_receipt_verifies() {
    let (receipt, tx) = load();
    let txid: [u8; 32] = *tx.txid().as_ref();
    let vk = zceipt_core::verifying_key();
    let v = zceipt_core::verify(&vk, &receipt, COIN_TYPE_TESTNET, Pool::Ironwood, txid, tx.ironwood_bundle().unwrap()).unwrap();
    assert_eq!(v.outputs.len(), 1);
    assert_eq!(v.outputs[0].value, 42_000_000);
    assert!(v.outputs[0].memo.starts_with(b"Invoice 42: two coffees"));
    assert_eq!(v.msg, b"Order #42 at Kemi's Coffee");

    let ua = std::fs::read_to_string(format!("{DIR}/merchant.ua")).unwrap();
    let (_, _, addr) = unified::Address::decode(ua.trim()).unwrap();
    let orchard = addr.items().into_iter().find_map(|r| match r {
        unified::Receiver::Orchard(b) => Some(b),
        _ => None,
    });
    assert_eq!(orchard, Some(v.outputs[0].recipient));
}

#[test]
fn committed_regtest_receipt_rejects_edits() {
    let (mut receipt, tx) = load();
    let txid: [u8; 32] = *tx.txid().as_ref();
    receipt.unsigned.msg = b"Order #43 at Kemi's Coffee".to_vec();
    let vk = zceipt_core::verifying_key();
    assert!(zceipt_core::verify(&vk, &receipt, COIN_TYPE_TESTNET, Pool::Ironwood, txid, tx.ironwood_bundle().unwrap()).is_err());
}
