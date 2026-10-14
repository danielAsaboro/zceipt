//! Test-mode fixtures, like Stripe's test card numbers: receipts that always produce a known
//! outcome without a wallet, a faucet or the chain. Only `rcpt_test_` keys accept them.
//!
//! | receipt                          | outcome                                   |
//! |----------------------------------|-------------------------------------------|
//! | `zrcpt_test_valid`               | valid; pays the expected payee and amount |
//! | `zrcpt_test_wrong_payee`         | `wrong_payee`                             |
//! | `zrcpt_test_insufficient_amount` | `insufficient_amount`                     |
//! | `zrcpt_test_challenge_mismatch`  | `challenge_mismatch`                      |
//! | `zrcpt_test_invalid`             | `receipt_invalid`                         |
//! | `zrcpt_test_not_mined`           | `transaction_not_mined`                   |
//! | `zrcpt_test_not_found`           | `transaction_not_found`                   |
//! | `zrcpt_test_chain_unavailable`   | `chain_unavailable` (502, retryable)      |
//! | `zrcpt_test_partial`             | valid; pays half of what is still owed    |
//! | `zrcpt_test_public_note`         | valid; the contributor opted in to a public campaign note |
//! | `zrcpt_test_same_payment`        | valid; always the same transaction, to see `payment_already_used` |

use crate::{error::ApiError, verify::{Output, Verification}};

pub const PREFIX: &str = "zrcpt_test_";

/// A stand-in testnet recipient when the caller gave none.
const DEFAULT_RECIPIENT: &str = "utest14te2vs2rwfe54mal8dwgejft2e9smlyasrku87ay4rq3dxnwcukp0vyck6exmjg60jttxz9y4a94772x0zc7xhj8gg7k00g4rg0zmdfa";

pub fn is_fixture(text: &str) -> bool {
    text.trim().starts_with(PREFIX)
}

pub const FIXTURES: &[&str] = &[
    "zrcpt_test_valid",
    "zrcpt_test_wrong_payee",
    "zrcpt_test_insufficient_amount",
    "zrcpt_test_challenge_mismatch",
    "zrcpt_test_invalid",
    "zrcpt_test_not_mined",
    "zrcpt_test_not_found",
    "zrcpt_test_chain_unavailable",
    "zrcpt_test_partial",
    "zrcpt_test_same_payment",
    "zrcpt_test_public_note",
];

/// Resolves a fixture. `payee`, `amount` and `challenge` are what the caller expects, so the
/// valid fixture satisfies them and the failing ones fail exactly one check.
pub fn resolve(text: &str, payee: Option<&str>, amount: Option<u64>, challenge: Option<&str>) -> Result<Verification, ApiError> {
    let name = text.trim();
    let recipient = payee.unwrap_or(DEFAULT_RECIPIENT).to_string();
    let raw = receipts_chain::chain::orchard_receiver_of(&recipient).unwrap_or([0u8; 43]);
    let amount = amount.unwrap_or(1_000_000);
    let mut v = Verification {
        object: "verification",
        valid: true,
        livemode: false,
        network: "testnet",
        pool: "ironwood",
        // A fresh fake txid per call, so sandbox payments never collide with each other.
        txid: {
            let mut b = [0u8; 28];
            getrandom::fill(&mut b).expect("OS RNG");
            format!("5a4db0c5{}", hex::encode(b))
        },
        mined_height: 4_500_000,
        message: challenge.map(|c| format!("challenge:{c}")).unwrap_or_default(),
        challenge: challenge.map(str::to_string),
        batch: None,
        sender_addresses: vec![],
        outputs: vec![Output { action: 0, recipient, recipient_raw: raw, zatoshis: amount, memo: Some("sandbox fixture".into()) }],
        verdict: "valid",
        checks: serde_json::Value::Null,
    };
    let (verdict, checks) = crate::verify::levels(4_500_000, Some(4_500_019), 1, 1, challenge, None, 0);
    v.verdict = verdict;
    v.checks = checks;
    match name {
        "zrcpt_test_valid" => Ok(v),
        "zrcpt_test_partial" => {
            v.outputs[0].zatoshis = amount.div_ceil(2).max(1);
            Ok(v)
        }
        "zrcpt_test_public_note" => {
            v.message.push_str("\npublic-note:Good luck with the library!");
            Ok(v)
        }
        "zrcpt_test_same_payment" => {
            v.txid = "5a4db0c5000000000000000000000000000000000000000000000000000000aa".into();
            Ok(v)
        }
        "zrcpt_test_wrong_payee" => {
            v.outputs[0].recipient = DEFAULT_RECIPIENT.into();
            v.outputs[0].recipient_raw = [1u8; 43];
            Ok(v)
        }
        "zrcpt_test_insufficient_amount" => {
            v.outputs[0].zatoshis = amount.saturating_sub(1).max(0);
            if amount == 0 {
                v.outputs.clear();
            }
            Ok(v)
        }
        "zrcpt_test_challenge_mismatch" => {
            v.challenge = Some("0000000000000000".into());
            v.message = "challenge:0000000000000000".into();
            Ok(v)
        }
        "zrcpt_test_invalid" => Err(ApiError::verification("receipt_invalid", "sandbox: the spend proof for action 0 is invalid")),
        "zrcpt_test_not_mined" => Err(ApiError::verification("transaction_not_mined", "sandbox: transaction is not mined yet")),
        "zrcpt_test_not_found" => Err(ApiError::verification("transaction_not_found", "sandbox: lightwalletd could not find the transaction")),
        "zrcpt_test_chain_unavailable" => Err(ApiError::chain("sandbox: lightwalletd unreachable")),
        _ => Err(ApiError::invalid("receipt_malformed", format!("unknown sandbox fixture; use one of {FIXTURES:?}")).param("receipt")),
    }
}
