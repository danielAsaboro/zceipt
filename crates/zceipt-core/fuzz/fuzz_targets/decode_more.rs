//! Arbitrary bytes through every binary decoder the text fuzzer reaches only after base64: each
//! either fails or re-encodes to the same bytes (no second encoding of one value), and the
//! checks that read a decoded value never panic.
#![no_main]
use libfuzzer_sys::fuzz_target;
use zceipt_core::{claim::Claim, delegated, designated, income::IncomeProof, keyset::KeySetProof, link::LinkProof, policy, reserve::ReserveProof, Receipt, ReceiptBatch};

fuzz_target!(|b: &[u8]| {
    if let Some(x) = zceipt_kce::Siblings::from_bytes(b) {
        assert_eq!(x.to_bytes(), b);
    }
    if let Ok(x) = Receipt::from_bytes(b) {
        assert_eq!(x.to_bytes(), b);
    }
    if let Ok(x) = ReceiptBatch::from_bytes(b) {
        assert_eq!(x.to_bytes(), b);
    }
    if let Ok(x) = Claim::from_bytes(b) {
        assert_eq!(x.to_bytes(), b);
        let _ = zceipt_core::claim::verify(&x, &x.domain.clone(), &x.anchor);
    }
    if let Ok(x) = designated::DesignatedReceipt::from_bytes(b) {
        assert_eq!(x.to_bytes(), b);
        let _ = x.check_proofs();
    }
    if let Ok(x) = delegated::DelegatedReceipt::from_bytes(b) {
        assert_eq!(x.to_bytes(), b);
        let _ = x.check_authorization();
    }
    if let Ok(x) = delegated::Certificate::from_bytes(b) {
        assert_eq!(x.to_bytes(), b);
        let _ = x.check();
    }
    if let Ok(x) = policy::PolicyProof::from_bytes(b) {
        assert_eq!(x.to_bytes(), b);
        let _ = policy::verifying_shares(&x.commitment, x.holders.min(64));
    }
    if let Ok(x) = KeySetProof::from_bytes(b) {
        assert_eq!(x.to_bytes(), b);
    }
    if let Ok(x) = IncomeProof::from_bytes(b) {
        assert_eq!(x.to_bytes(), b);
    }
    if let Ok(x) = LinkProof::from_bytes(b) {
        assert_eq!(x.to_bytes(), b);
    }
    if let Some(x) = ReserveProof::from_bytes(b) {
        assert_eq!(x.to_bytes(), b);
    }
});
