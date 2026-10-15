//! Decoding and encoding the real testnet receipts, batch and sign-in, small enough to run
//! under Miri (no proofs): `cargo +nightly miri test -p receipts-core --test encoding_ub`.
//! Also runs in the normal test suite.

use receipts_core::{check_batch, signin::SignIn, signing_digest, Receipt, ReceiptBatch};

const RECEIPTS: &[&str] = &[
    include_str!("../../../examples/testnet/receipt.txt"),
    include_str!("../../../examples/testnet/receipt-with-sender-address.txt"),
    include_str!("../../../examples/testnet/refund-receipt.txt"),
];

fn body(t: &str, prefix: &str) -> String {
    let i = t.find(prefix).expect("prefix");
    t[i..].chars().take_while(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_').collect()
}

#[test]
fn receipts_round_trip() {
    for t in RECEIPTS {
        let text = body(t, "zrcpt1");
        let r = Receipt::from_text(&text).unwrap();
        assert_eq!(r.to_text(), text);
        let bytes = r.to_bytes();
        assert_eq!(Receipt::from_bytes(&bytes).unwrap(), r);
        let _ = signing_digest(&r.unsigned);
        // Every truncation is refused, without reading out of bounds.
        for cut in (0..bytes.len()).step_by(97) {
            assert!(Receipt::from_bytes(&bytes[..cut]).is_err());
        }
    }
}

#[test]
fn batch_and_sign_in_round_trip() {
    let b = ReceiptBatch::from_text(&body(include_str!("../../../examples/testnet/batch.txt"), "zrcptb1")).unwrap();
    assert!(check_batch(&b).is_ok());
    assert_eq!(ReceiptBatch::from_bytes(&b.to_bytes()).unwrap(), b);
    let s = SignIn::from_text(&body(include_str!("../../../examples/testnet/sign-in.txt"), "zsig1")).unwrap();
    assert_eq!(SignIn::from_bytes(&s.to_bytes()).unwrap(), s);
    let _ = receipts_core::signin::signing_digest(&s);
}

#[test]
fn spend_auth_signatures_verify() {
    use orchard::primitives::redpallas::{Signature, SpendAuth, VerificationKey};
    let r = Receipt::from_text(&body(RECEIPTS[0], "zrcpt1")).unwrap();
    let digest = signing_digest(&r.unsigned);
    for (s, sig) in r.unsigned.spends.iter().zip(&r.spend_auth_sigs) {
        let rk = VerificationKey::<SpendAuth>::try_from(s.rk).unwrap();
        assert!(rk.verify(&digest, &Signature::<SpendAuth>::from(*sig)).is_ok());
        let mut bad = *sig;
        bad[40] ^= 1;
        assert!(rk.verify(&digest, &Signature::<SpendAuth>::from(bad)).is_err());
    }
}

#[test]
fn txids_display_as_explorers_show_them() {
    let r = Receipt::from_text(&body(RECEIPTS[0], "zrcpt1")).unwrap();
    assert_eq!(receipts_core::display_txid(&r.unsigned.txid), "571de6e4cc96b64c0d849cc172905449011b195e521532d78fe9c29a149e0e73");
}

/// Length limits at their exact boundaries: proofs up to 65,536 bytes decode, one more is
/// `TooLarge`; batches hold 1..=256 receipts.
#[test]
fn length_limits_are_exact() {
    use receipts_core::{AddressProof, DecodeError};
    let base = Receipt::from_text(&body(RECEIPTS[0], "zrcpt1")).unwrap();
    let with_proof = |n: usize, in_address: bool| {
        let mut r = base.clone();
        if in_address {
            let s = &mut r.unsigned.spends[0];
            s.address = Some(AddressProof { address: [0; 43], rho: [0; 32], rseed: [0; 32], nf: [0; 32], cv_net: [0; 32], cmx: [0; 32], proof: vec![7; n] });
        } else {
            r.unsigned.spends[0].proof = vec![7; n];
        }
        Receipt::from_bytes(&r.to_bytes())
    };
    for in_address in [false, true] {
        assert!(with_proof(1 << 16, in_address).is_ok());
        assert_eq!(with_proof((1 << 16) + 1, in_address).unwrap_err(), DecodeError::TooLarge);
    }
    let batch = |n: usize| {
        let mut v = b"ZRCB\x01".to_vec();
        v.extend_from_slice(&(n as u16).to_le_bytes());
        for _ in 0..n {
            let b = base.to_bytes();
            v.extend_from_slice(&(b.len() as u32).to_le_bytes());
            v.extend_from_slice(&b);
        }
        ReceiptBatch::from_bytes(&v).map(|b| b.receipts.len())
    };
    assert_eq!(batch(0).unwrap_err(), DecodeError::TooLarge);
    assert_eq!(batch(1).unwrap(), 1);
    assert_eq!(batch(256).unwrap(), 256);
    assert_eq!(batch(257).unwrap_err(), DecodeError::TooLarge);
}

/// Batch positions must be 1..=n, each once, with one id and the right count.
#[test]
fn batch_positions_are_checked() {
    let base = Receipt::from_text(&body(RECEIPTS[0], "zrcpt1")).unwrap();
    let batch = |msgs: &[&str]| {
        let receipts = msgs
            .iter()
            .map(|m| {
                let mut r = base.clone();
                r.unsigned.msg = m.as_bytes().to_vec();
                r
            })
            .collect();
        check_batch(&ReceiptBatch { receipts })
    };
    assert_eq!(batch(&["batch:ab 1/2", "batch:ab 2/2"]).unwrap(), "ab");
    assert!(batch(&["batch:ab 0/2", "batch:ab 2/2"]).is_err());
    assert!(batch(&["batch:ab 1/2", "batch:ab 3/2"]).is_err());
    assert!(batch(&["batch:ab 1/2", "batch:ab 1/2"]).is_err());
    assert!(batch(&["batch:ab 1/2", "batch:cd 2/2"]).is_err());
    assert!(batch(&["batch:ab 1/3", "batch:ab 2/3"]).is_err());
    assert!(batch(&["batch:ab 1/2", "no position"]).is_err());
    assert!(batch(&["batch:ab 2/2", "batch:cd 1/2"]).is_err());
}

/// The sign-in's public digest is the one its signature verifies under; its proof-length cap is exact.
#[test]
fn sign_in_digest_and_limits() {
    use orchard::primitives::redpallas::{Signature, SpendAuth, VerificationKey};
    let s = SignIn::from_text(&body(include_str!("../../../examples/testnet/sign-in.txt"), "zsig1")).unwrap();
    let rk = VerificationKey::<SpendAuth>::try_from(s.rk).unwrap();
    assert!(rk.verify(&receipts_core::signin::signing_digest(&s), &Signature::<SpendAuth>::from(s.sig)).is_ok());
    let with_proof = |n: usize| {
        let mut t = s.clone();
        t.address.proof = vec![7; n];
        SignIn::from_bytes(&t.to_bytes())
    };
    assert!(with_proof(1 << 16).is_some());
    assert!(with_proof((1 << 16) + 1).is_none());
}
