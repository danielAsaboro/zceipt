//! Any string through every text decoder (zip311r1, zip311b1, zsig1): never panics; a decoded
//! receipt re-encodes to the same text, up to surrounding whitespace.
#![no_main]
use libfuzzer_sys::fuzz_target;
use receipts_core::{signin::SignIn, Receipt, ReceiptBatch};

fuzz_target!(|s: &str| {
    if let Ok(r) = Receipt::from_text(s) {
        assert_eq!(r.to_text(), s.trim());
    }
    if let Ok(b) = ReceiptBatch::from_text(s) {
        assert_eq!(b.to_text(), s.trim());
    }
    if let Some(si) = SignIn::from_text(s) {
        assert_eq!(si.to_text(), s.trim());
    }
});
