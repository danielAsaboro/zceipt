//! Any bytes through the binary decoders of claims (ZRCT) and one-verifier receipts (ZRCD): never
//! panics, and only canonical encodings decode.
#![no_main]
use libfuzzer_sys::fuzz_target;
use receipts_core::{claim::Claim, designated::DesignatedReceipt};

fuzz_target!(|data: &[u8]| {
    if let Ok(c) = Claim::from_bytes(data) {
        assert_eq!(c.to_bytes(), data, "decoded a non-canonical claim");
    }
    if let Ok(d) = DesignatedReceipt::from_bytes(data) {
        assert_eq!(d.to_bytes(), data, "decoded a non-canonical designated receipt");
        let _ = d.check_proofs();
    }
});
