#![no_main]
use libfuzzer_sys::fuzz_target;
use zceipt_core::{check_batch, ReceiptBatch};

fuzz_target!(|data: &[u8]| {
    if let Ok(b) = ReceiptBatch::from_bytes(data) {
        assert_eq!(b.to_bytes(), data, "decoded a non-canonical batch");
        let _ = check_batch(&b);
    }
});
