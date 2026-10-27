#![no_main]
use libfuzzer_sys::fuzz_target;
use zceipt_core::signin::SignIn;

fuzz_target!(|data: &[u8]| {
    if let Some(s) = SignIn::from_bytes(data) {
        assert_eq!(s.to_bytes(), data, "decoded a non-canonical sign-in");
        let _ = zceipt_core::signin::signing_digest(&s);
    }
});
