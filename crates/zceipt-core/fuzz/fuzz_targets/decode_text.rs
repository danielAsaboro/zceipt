//! Any string through every text decoder (zip311r1, zip311b1, zip311u1, zip311k1, zip311i1, zip311m1,
//! zip311t1, zip311d1, zsig1): never panics; a decoded
//! receipt re-encodes to the same text, up to surrounding whitespace.
#![no_main]
use libfuzzer_sys::fuzz_target;
use zceipt_core::{signin::SignIn, PreparedReceipt, Receipt, ReceiptBatch};

fuzz_target!(|s: &str| {
    if let Ok(r) = Receipt::from_text(s) {
        assert_eq!(r.to_text(), s.trim());
    }
    if let Ok(b) = ReceiptBatch::from_text(s) {
        assert_eq!(b.to_text(), s.trim());
    }
    if let Ok(p) = PreparedReceipt::from_text(s) {
        assert_eq!(p.to_text(), s.trim());
    }
    if let Ok(l) = zceipt_core::link::LinkProof::from_text(s) {
        assert_eq!(l.to_text(), s.trim());
    }
    if let Ok(p) = zceipt_core::income::IncomeProof::from_text(s) {
        assert_eq!(p.to_text(), s.trim());
    }
    if let Ok(p) = zceipt_core::keyset::KeySetProof::from_text(s) {
        assert_eq!(p.to_text(), s.trim());
    }
    if let Ok(c) = zceipt_core::claim::Claim::from_text(s) {
        assert_eq!(c.to_text(), s.trim());
    }
    if let Ok(d) = zceipt_core::designated::DesignatedReceipt::from_text(s) {
        assert_eq!(d.to_text(), s.trim());
        let _ = d.check_proofs();
    }
    if let Some(si) = SignIn::from_text(s) {
        assert_eq!(si.to_text(), s.trim());
    }
});
