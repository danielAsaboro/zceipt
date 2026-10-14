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
