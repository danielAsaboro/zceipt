//! Soundness fuzzing on the real testnet proofs: up to four byte edits to a claim, a payer tag, a
//! one-verifier receipt, a delegated receipt or a FROST policy proof. The edited proof must be
//! refused (or fail to decode) unless the edits cancel out; one accepted is a forgery.
#![no_main]
use libfuzzer_sys::fuzz_target;
use zceipt_core::{claim, delegated, designated, policy, Receipt};

const CLAIM: &str = include_str!("../../../../examples/testnet/proofs/claim.txt");
const TAG: &str = include_str!("../../../../examples/testnet/proofs/tagA.txt");
const DV: &str = include_str!("../../../../examples/testnet/proofs/dv.txt");
const DG: &str = include_str!("../../../../examples/testnet/proofs/dg.txt");
const FROST: &str = include_str!("../../../../examples/testnet/proofs/frost/receipt.txt");

fn bytes_of(text: &str, prefix: &str) -> Vec<u8> {
    use base64::Engine;
    let body = text.trim().split('\n').find_map(|l| l.trim().strip_prefix(prefix)).unwrap();
    base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(body).unwrap()
}

/// Applies the edits in `data` (pairs of position and xor mask) to `bytes`; whether anything changed.
fn edit(bytes: &mut [u8], data: &[u8]) -> bool {
    let before = bytes.to_vec();
    for e in data.chunks_exact(3).take(4) {
        let pos = u16::from_le_bytes([e[0], e[1]]) as usize % bytes.len();
        bytes[pos] ^= e[2];
    }
    bytes != &before[..]
}

fuzz_target!(|data: &[u8]| {
    let Some((&kind, rest)) = data.split_first() else { return };
    match kind % 5 {
        0 => {
            let mut b = bytes_of(CLAIM, claim::CLAIM_TEXT_PREFIX);
            let anchor = claim::Claim::from_bytes(&b).unwrap().anchor;
            if edit(&mut b, rest) {
                if let Ok(c) = claim::Claim::from_bytes(&b) {
                    assert!(claim::verify(&c, b"airdrop-testnet", &anchor).is_err(), "an edited claim verified");
                }
            }
        }
        1 => {
            let mut b = bytes_of(TAG, claim::CLAIM_TEXT_PREFIX);
            let c0 = claim::Claim::from_bytes(&b).unwrap();
            if edit(&mut b, rest) {
                if let Ok(c) = claim::Claim::from_bytes(&b) {
                    // The statement alone, as a claimant who can re-sign would present it.
                    assert!(claim::verify(&c, b"round-testnet", &c0.anchor).is_err(), "an edited payer tag verified");
                }
            }
        }
        2 => {
            let mut b = bytes_of(DV, designated::DESIGNATED_TEXT_PREFIX);
            if edit(&mut b, rest) {
                if let Ok(d) = designated::DesignatedReceipt::from_bytes(&b) {
                    let orig = designated::DesignatedReceipt::from_bytes(&bytes_of(DV, designated::DESIGNATED_TEXT_PREFIX)).unwrap();
                    // An edit that leaves the proofs valid must leave what they authorize unchanged.
                    if d.check_proofs().is_ok() {
                        assert_eq!(zceipt_core::signing_digest(&d.receipt.unsigned), zceipt_core::signing_digest(&orig.receipt.unsigned), "an edited receipt keeps valid proofs");
                    }
                }
            }
        }
        3 => {
            let mut b = bytes_of(DG, delegated::DELEGATED_TEXT_PREFIX);
            let orig = delegated::DelegatedReceipt::from_bytes(&b).unwrap();
            if edit(&mut b, rest) {
                if let Ok(d) = delegated::DelegatedReceipt::from_bytes(&b) {
                    if d.check_authorization().is_ok() {
                        assert_eq!(zceipt_core::signing_digest(&d.receipt.unsigned), zceipt_core::signing_digest(&orig.receipt.unsigned));
                        assert_eq!(d.cert, orig.cert, "an edited policy kept a valid authorization");
                    }
                }
            }
        }
        _ => {
            let mut pb = bytes_of(FROST, policy::POLICY_TEXT_PREFIX);
            let receipt = Receipt::from_text(FROST.lines().next().unwrap()).unwrap();
            let orig = policy::PolicyProof::from_bytes(&pb).unwrap();
            if edit(&mut pb, rest) {
                if let Ok(p) = policy::PolicyProof::from_bytes(&pb) {
                    if policy::verify(&p, &receipt).is_ok() {
                        assert_eq!(p, orig, "an edited policy proof verified");
                    }
                }
            }
        }
    }
});
