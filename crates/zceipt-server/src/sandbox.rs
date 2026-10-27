//! Test-mode fixtures, like Stripe's test card numbers: receipts that always produce a known
//! outcome without a wallet, a faucet or the chain. Only `rcpt_test_` keys accept them.
//!
//! | receipt                          | outcome                                   |
//! |----------------------------------|-------------------------------------------|
//! | `zip311_test_valid`               | valid; pays the expected payee and amount |
//! | `zip311_test_wrong_payee`         | `wrong_payee`                             |
//! | `zip311_test_insufficient_amount` | `insufficient_amount`                     |
//! | `zip311_test_challenge_mismatch`  | `challenge_mismatch`                      |
//! | `zip311_test_invalid`             | `receipt_invalid`                         |
//! | `zip311_test_not_mined`           | `transaction_not_mined`                   |
//! | `zip311_test_not_found`           | `transaction_not_found`                   |
//! | `zip311_test_chain_unavailable`   | `chain_unavailable` (502, retryable)      |
//! | `zip311_test_partial`             | valid; pays half of what is still owed    |
//! | `zip311_test_public_note`         | valid; the contributor opted in to a public campaign note |
//! | `zip311_test_refund_to`           | valid; the payer signed a refund address  |
//! | `zip311_test_same_payment`        | valid; always the same transaction, to see `payment_already_used` |

use crate::{
    error::ApiError,
    verify::{Output, Verification},
};

pub const PREFIX: &str = "zip311_test_";

/// A stand-in testnet recipient when the caller gave none.
const DEFAULT_RECIPIENT: &str = "utest14te2vs2rwfe54mal8dwgejft2e9smlyasrku87ay4rq3dxnwcukp0vyck6exmjg60jttxz9y4a94772x0zc7xhj8gg7k00g4rg0zmdfa";

pub fn is_fixture(text: &str) -> bool {
    text.trim().starts_with(PREFIX)
}

pub const FIXTURES: &[&str] = &[
    "zip311_test_valid",
    "zip311_test_wrong_payee",
    "zip311_test_insufficient_amount",
    "zip311_test_challenge_mismatch",
    "zip311_test_invalid",
    "zip311_test_not_mined",
    "zip311_test_not_found",
    "zip311_test_chain_unavailable",
    "zip311_test_partial",
    "zip311_test_same_payment",
    "zip311_test_public_note",
    "zip311_test_refund_to",
    "zip311_test_memo_withheld",
];

/// The refund address `zip311_test_refund_to` signs (a testnet address).
pub const SANDBOX_REFUND_ADDRESS: &str = "utest1vuxevmthp07lftrlqy86a3us3nsl5ssq8ejwp5t5mqly2zrqa79v06qsm89983eqqllwwchnqkl0z2gh2nragk474pgexmf508m2qtz3r7w7nv25jaktzm4nxselfl5de9z9f8a9sv23r7v8fsr7nzcfz4vwsd80h2jtq0h0qpj5h3znrdf09hns22nmeh99a8mk8znd75cfzgs5nqu";

/// Resolves a fixture. `payee`, `amount` and `challenge` are what the caller expects, so the
/// valid fixture satisfies them and the failing ones fail exactly one check.
pub fn resolve(text: &str, payee: Option<&str>, amount: Option<u64>, challenge: Option<&str>) -> Result<Verification, ApiError> {
    let name = text.trim();
    let recipient = payee.unwrap_or(DEFAULT_RECIPIENT).to_string();
    let raw = zceipt_chain::chain::orchard_receiver_of(&recipient).unwrap_or([0u8; 43]);
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
        public_demo: false,
        message: challenge.map(|c| format!("challenge:{c}")).unwrap_or_default(),
        challenge: challenge.map(str::to_string),
        batch: None,
        sender_addresses: vec![],
        sources: vec![],
        outputs: vec![Output { action: 0, recipient, recipient_raw: raw, zatoshis: amount, memo: Some("sandbox fixture".into()), memo_withheld: false }],
        verdict: "valid",
        checks: serde_json::Value::Null,
        deposit: None,
    };
    let (verdict, checks) = crate::verify::levels(4_500_000, Some(4_500_019), 1, 1, challenge, None, 0);
    v.verdict = verdict;
    v.checks = checks;
    match name {
        "zip311_test_valid" => Ok(v),
        "zip311_test_partial" => {
            v.outputs[0].zatoshis = amount.div_ceil(2).max(1);
            Ok(v)
        }
        "zip311_test_public_note" => {
            v.message.push_str("\npublic-note:Good luck with the library!");
            Ok(v)
        }
        "zip311_test_refund_to" => {
            v.message.push_str(&format!("\nrefund-to:{SANDBOX_REFUND_ADDRESS}"));
            Ok(v)
        }
        "zip311_test_same_payment" => {
            v.txid = "5a4db0c5000000000000000000000000000000000000000000000000000000aa".into();
            Ok(v)
        }
        "zip311_test_memo_withheld" => {
            v.outputs[0].memo = None;
            v.outputs[0].memo_withheld = true;
            Ok(v)
        }
        "zip311_test_wrong_payee" => {
            v.outputs[0].recipient = DEFAULT_RECIPIENT.into();
            v.outputs[0].recipient_raw = [1u8; 43];
            Ok(v)
        }
        "zip311_test_insufficient_amount" => {
            v.outputs[0].zatoshis = amount.saturating_sub(1);
            if amount == 0 {
                v.outputs.clear();
            }
            Ok(v)
        }
        "zip311_test_challenge_mismatch" => {
            v.challenge = Some("0000000000000000".into());
            v.message = "challenge:0000000000000000".into();
            Ok(v)
        }
        "zip311_test_invalid" => Err(ApiError::verification("receipt_invalid", "sandbox: the spend proof for action 0 is invalid")),
        "zip311_test_not_mined" => Err(ApiError::verification("transaction_not_mined", "sandbox: transaction is not mined yet")),
        "zip311_test_not_found" => Err(ApiError::verification("transaction_not_found", "sandbox: lightwalletd could not find the transaction")),
        "zip311_test_chain_unavailable" => Err(ApiError::chain("sandbox: lightwalletd unreachable")),
        _ => Err(ApiError::invalid("receipt_malformed", format!("unknown sandbox fixture; use one of {FIXTURES:?}")).param("receipt")),
    }
}
