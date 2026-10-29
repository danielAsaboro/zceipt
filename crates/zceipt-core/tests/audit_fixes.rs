//! Regressions for the findings of docs/AUDIT-HOSTILE.md.

use group::{ff::PrimeField, GroupEncoding};
use zceipt_core::delegated::{check_policy, Certificate};
use zceipt_core::link::spend_auth_base;
use zceipt_core::{Pool, VerifiedOutput, VerifiedReceipt};

fn forged_identity_cert() -> Certificate {
    let g = spend_auth_base();
    let s = pasta_curves::pallas::Scalar::from(12345u64);
    let mut sig = [0u8; 64];
    sig[..32].copy_from_slice(&(g * s).to_bytes());
    sig[32..].copy_from_slice(&s.to_repr());
    let session = (g * pasta_curves::pallas::Scalar::from(777u64)).to_bytes();
    Certificate { coin_type: 1, session, max_zats: u64::MAX, until_height: u32::MAX, payees: vec![], rk: [0; 32], sig }
}

#[test]
fn a_certificate_under_the_identity_key_is_refused() {
    assert!(forged_identity_cert().check().is_err());
}

fn receipt_paying(values: &[u64]) -> VerifiedReceipt {
    VerifiedReceipt {
        coin_type: 1,
        pool: Pool::Ironwood,
        output_pool: None,
        txid: [0; 32],
        msg: vec![],
        proven_spends: vec![0],
        proven_addresses: vec![],
        sources: vec![],
        outputs: values.iter().map(|v| VerifiedOutput { index: 0, recipient: [1; 43], value: *v, memo: [0; 512], memo_withheld: false }).collect(),
    }
}

#[test]
fn delegation_limits_hold_at_their_exact_boundaries() {
    let mut cert = forged_identity_cert();
    cert.max_zats = 100;
    cert.until_height = 50;
    assert!(check_policy(&cert, &receipt_paying(&[60, 40]), 50).is_ok());
    assert!(check_policy(&cert, &receipt_paying(&[60, 41]), 50).is_err());
    assert!(check_policy(&cert, &receipt_paying(&[100]), 51).is_err());
    assert!(check_policy(&cert, &receipt_paying(&[u64::MAX, 1]), 50).is_err(), "a sum that wraps is refused");
}

#[test]
fn a_verifying_key_of_another_circuit_is_refused() {
    let vk = orchard::circuit::VerifyingKey::build(orchard::circuit::OrchardCircuitVersion::FixedPostNu6_2);
    assert_eq!(zceipt_core::verify_aggregate(&vk, &[], &[]), Err(zceipt_core::Error::WrongCircuit));
}
