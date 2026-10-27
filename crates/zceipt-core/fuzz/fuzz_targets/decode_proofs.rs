//! Any bytes through the binary decoders of claims (ZRCL), one-verifier receipts (ZRCD),
//! delegation certificates (ZRCG) and delegated receipts (ZRCA): never
//! panics, and only canonical encodings decode.
#![no_main]
use libfuzzer_sys::fuzz_target;
use zceipt_core::{claim::Claim, delegated::{Certificate, DelegatedReceipt}, designated::DesignatedReceipt};

fuzz_target!(|data: &[u8]| {
    if let Ok(c) = Claim::from_bytes(data) {
        assert_eq!(c.to_bytes(), data, "decoded a non-canonical claim");
    }
    if let Ok(d) = DesignatedReceipt::from_bytes(data) {
        assert_eq!(d.to_bytes(), data, "decoded a non-canonical designated receipt");
        let _ = d.check_proofs();
    }
    if let Ok(c) = Certificate::from_bytes(data) {
        assert_eq!(c.to_bytes(), data, "decoded a non-canonical certificate");
        let _ = c.check();
    }
    if let Ok(d) = DelegatedReceipt::from_bytes(data) {
        assert_eq!(d.to_bytes(), data, "decoded a non-canonical delegated receipt");
        let _ = d.check_authorization();
    }
});
