//! Any bytes: decoding never panics, and whatever decodes is its own canonical encoding
//! (so one receipt has exactly one encoding, which is what the signatures cover).
#![no_main]
use libfuzzer_sys::fuzz_target;
use receipts_core::Receipt;

fuzz_target!(|data: &[u8]| {
    if let Ok(r) = Receipt::from_bytes(data) {
        assert_eq!(r.to_bytes(), data, "decoded a non-canonical encoding");
        assert!(!r.unsigned.spends.is_empty() || r.spend_auth_sigs.is_empty());
        assert_eq!(Receipt::from_text(&r.to_text()).as_ref(), Ok(&r));
        let _ = receipts_core::signing_digest(&r.unsigned);
        let _ = receipts_core::batch_position(&r.unsigned.msg);
    }
});
