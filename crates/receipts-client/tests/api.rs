//! Run with RECEIPTS_URL and RECEIPTS_KEY pointing at `receipts serve` (testnet).
use receipts_client::{webhooks, Client, CreateRequest, Error, VerifyParams};

fn env() -> Option<(String, String)> {
    Some((std::env::var("RECEIPTS_URL").ok()?, std::env::var("RECEIPTS_KEY").ok()?))
}
const EX: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../examples/testnet");

#[test]
fn webhook_signatures() {
    let body = r#"{"id":"evt_1","type":"request.fulfilled"}"#;
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64;
    let h = webhooks::sign(body, "whsec_x", now);
    assert_eq!(webhooks::construct_event(body, &h, "whsec_x", 300).unwrap()["id"], "evt_1");
    assert_eq!(webhooks::construct_event("{}", &h, "whsec_x", 300).unwrap_err(), webhooks::SignatureError::Mismatch);
    assert_eq!(webhooks::construct_event(body, &webhooks::sign(body, "whsec_x", now - 3600), "whsec_x", 300).unwrap_err(), webhooks::SignatureError::Stale);
}

#[tokio::test]
async fn api_roundtrip() {
    let Some((url, key)) = env() else { return };
    let c = Client::new(key).base_url(url);
    let payee = std::fs::read_to_string(format!("{EX}/merchant.ua")).unwrap().trim().to_string();
    let req = CreateRequest { payee, amount_zatoshis: Some(1_000_000), label: Some("rust".into()), ..Default::default() };
    let a = c.create_request_idempotent(&req, "rust-1").await.unwrap();
    let b = c.create_request_idempotent(&req, "rust-1").await.unwrap();
    assert_eq!(a["id"], b["id"]);
    let receipt = std::fs::read_to_string(format!("{EX}/receipt.txt")).unwrap();
    let v = c.verify(&VerifyParams { receipt: receipt.clone(), ..Default::default() }).await.unwrap();
    assert_eq!(v["mined_height"], 4500997);
    let err = c.verify(&VerifyParams { receipt, challenge: Some("00112233aabbccdd".into()), ..Default::default() }).await.unwrap_err();
    assert!(matches!(err, Error::Verification { .. }));
    assert_eq!(err.code(), Some("challenge_mismatch"));
}

/// Calls every API operation through this SDK (sandbox) and checks the list against
/// conformance/sdk-parity.json.
#[tokio::test]
async fn every_operation() {
    let Some((url, key)) = env() else { return };
    let c = Client::new(key).base_url(url);
    let payee = "utest14te2vs2rwfe54mal8dwgejft2e9smlyasrku87ay4rq3dxnwcukp0vyck6exmjg60jttxz9y4a94772x0zc7xhj8gg7k00g4rg0zmdfa".to_string();
    let mut done = std::collections::BTreeSet::new();
    macro_rules! op {
        ($name:literal, $e:expr) => {{
            done.insert($name);
            $e.await.expect($name)
        }};
    }
    op!("health", c.health());
    op!("listErrors", c.list_errors());
    op!("listSandboxFixtures", c.sandbox_fixtures());
    op!("verify", c.verify(&VerifyParams { receipt: "zip311_test_valid".into(), ..Default::default() }));
    op!("checkPaymentLink", c.check_payment_link(&format!("zcash:{payee}?amount=0.01"), None));
    let clock = op!("createTestClock", c.create_test_clock(None));
    let cid = clock["id"].as_str().unwrap().to_string();
    op!("getTestClock", c.get_test_clock(&cid));
    let req = op!(
        "createRequest",
        c.create_request(&CreateRequest { payee: payee.clone(), amount_zatoshis: Some(1_000_000), test_clock: Some(cid.clone()), ..Default::default() })
    );
    let (id, secret) = (req["id"].as_str().unwrap().to_string(), req["client_secret"].as_str().unwrap().to_string());
    op!("getRequest", c.get_request(&id));
    op!("listRequests", c.list_requests(None, Some(2)));
    assert!(op!("requestQr", c.request_qr(&id)).contains("<svg"));
    op!("publicGetRequest", c.public_get_request(&id, &secret));
    op!("publicSubmitReceipt", c.public_submit_receipt(&id, "zip311_test_refund_to", Some(&secret)));
    op!("advanceTestClock", c.advance_test_clock(&cid, None, Some(9)));
    op!("reorgTestClock", c.reorg_test_clock(&cid, 1));
    let rf = op!("createRefund", c.create_refund(&id, Some(1000), None));
    let rid = rf["id"].as_str().unwrap().to_string();
    op!("getRefund", c.get_refund(&rid));
    op!("submitRefundReceipt", c.submit_refund_receipt(&rid, "zip311_test_valid"));
    let other = c.create_request(&CreateRequest { payee: payee.clone(), amount_zatoshis: Some(1_000_000), ..Default::default() }).await.unwrap();
    let oid = other["id"].as_str().unwrap().to_string();
    op!("submitReceipt", c.submit_receipt(&oid, "zip311_test_valid"));
    done.insert("reviewDeposit");
    assert_eq!(c.review_deposit(&oid, "accept", None).await.unwrap_err().code(), Some("not_held_for_review"));
    let att = op!("createAttestation", c.create_attestation(&oid, None, None, &[]));
    op!("verifyAttestation", c.verify_attestation(att["presentation"].as_str().unwrap()));
    op!("jwks", c.jwks());
    let camp = c.create_request(&CreateRequest { payee: payee.clone(), kind: Some("campaign".into()), ..Default::default() }).await.unwrap();
    op!("publicCampaign", c.public_campaign(camp["id"].as_str().unwrap()));
    op!("createSignInChallenge", c.create_sign_in_challenge(Some("parity.test")));
    done.insert("verifySignIn");
    assert_eq!(c.verify_sign_in("zsig1AAAA").await.unwrap_err().code(), Some("sign_in_malformed"));
    done.insert("verifyClaim");
    assert_eq!(c.verify_claim("zip311t1AAAA", "round", None).await.unwrap_err().code(), Some("claim_malformed"));
    let ep = op!("createWebhookEndpoint", c.create_webhook_endpoint("http://127.0.0.1:9/parity", None));
    op!("listWebhookEndpoints", c.list_webhook_endpoints());
    op!("deleteWebhookEndpoint", c.delete_webhook_endpoint(ep["id"].as_str().unwrap()));
    let ev = op!("listEvents", c.list_events(Some(1)));
    op!("resendEvent", c.resend_event(ev["data"][0]["id"].as_str().unwrap()));
    op!("listDeliveries", c.list_deliveries(Some(1)));
    let table: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/../../conformance/sdk-parity.json")).unwrap()).unwrap();
    let want: std::collections::BTreeSet<&str> = table.as_object().unwrap().keys().filter(|k| !k.starts_with('_')).map(String::as_str).collect();
    assert_eq!(want.difference(&done).collect::<Vec<_>>(), Vec::<&&str>::new());
}
