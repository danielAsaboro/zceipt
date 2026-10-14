//! In-process API tests using sandbox fixtures (no network, no chain).

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use receipts_chain::Net;
use serde_json::{json, Value};
use tower::ServiceExt;

const PAYEE: &str = "utest14te2vs2rwfe54mal8dwgejft2e9smlyasrku87ay4rq3dxnwcukp0vyck6exmjg60jttxz9y4a94772x0zc7xhj8gg7k00g4rg0zmdfa";

async fn app() -> (axum::Router, String, String) {
    let db = std::env::temp_dir().join(format!("receipts-test-{}.db", std::process::id() as u64 * 1000 + rand_suffix()));
    let config = receipts_server::Config { test_net: Net::Test, test_lightwalletd: None, live_lightwalletd: None, verifier_url: "http://verifier.test/".into() };
    let (router, keys) = receipts_server::build(db.to_str().unwrap(), config).await.unwrap();
    let test = keys.iter().find(|(_, m)| m == "test").unwrap().0.clone();
    let live = keys.iter().find(|(_, m)| m == "live").unwrap().0.clone();
    (router, test, live)
}

fn rand_suffix() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().subsec_nanos() as u64
}

async fn call(app: &axum::Router, method: &str, path: &str, key: Option<&str>, body: Option<Value>, idem: Option<&str>) -> (StatusCode, Value, axum::http::HeaderMap) {
    let mut b = Request::builder().method(method).uri(path);
    if let Some(k) = key {
        b = b.header("authorization", format!("Bearer {k}"));
    }
    if let Some(i) = idem {
        b = b.header("idempotency-key", i);
    }
    let req = match body {
        Some(v) => b.header("content-type", "application/json").body(Body::from(v.to_string())).unwrap(),
        None => b.body(Body::empty()).unwrap(),
    };
    let res = app.clone().oneshot(req).await.unwrap();
    let status = res.status();
    let headers = res.headers().clone();
    let bytes = res.into_body().collect().await.unwrap().to_bytes();
    (status, serde_json::from_slice(&bytes).unwrap_or(Value::Null), headers)
}

#[tokio::test]
async fn auth_and_validation_errors() {
    let (app, test, _) = app().await;
    let (s, v, _) = call(&app, "GET", "/v1/requests", None, None, None).await;
    assert_eq!((s, v["error"]["code"].as_str()), (StatusCode::UNAUTHORIZED, Some("missing_api_key")));
    let (s, v, _) = call(&app, "GET", "/v1/requests", Some("rcpt_test_nope"), None, None).await;
    assert_eq!((s, v["error"]["code"].as_str()), (StatusCode::UNAUTHORIZED, Some("invalid_api_key")));
    let (s, v, _) = call(&app, "POST", "/v1/requests", Some(&test), Some(json!({})), None).await;
    assert_eq!((s, v["error"]["param"].as_str()), (StatusCode::BAD_REQUEST, Some("payee")));
    let (s, v, _) = call(&app, "POST", "/v1/requests", Some(&test), Some(json!({ "payee": "u1qqqq" })), None).await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{v}");
}

#[tokio::test]
async fn proof_request_lifecycle_with_fixtures() {
    let (app, test, live) = app().await;
    let (s, req, h) = call(&app, "POST", "/v1/requests", Some(&test), Some(json!({ "payee": PAYEE, "amount_zatoshis": 500000, "label": "t" })), Some("k1")).await;
    assert_eq!(s, StatusCode::CREATED);
    assert_eq!(h.get("receipts-version").unwrap(), receipts_server::API_VERSION);
    assert!(req["payment_uri"].as_str().unwrap().starts_with(&format!("zcash:{PAYEE}?amount=0.005")));
    let id = req["id"].as_str().unwrap().to_string();

    // Idempotent replay returns the same object; a different body with the same key is refused.
    let (_, again, h) = call(&app, "POST", "/v1/requests", Some(&test), Some(json!({ "payee": PAYEE, "amount_zatoshis": 500000, "label": "t" })), Some("k1")).await;
    assert_eq!(again["id"], req["id"]);
    assert_eq!(h.get("idempotent-replayed").unwrap(), "true");
    let (s, v, _) = call(&app, "POST", "/v1/requests", Some(&test), Some(json!({ "payee": PAYEE })), Some("k1")).await;
    assert_eq!((s, v["error"]["code"].as_str()), (StatusCode::CONFLICT, Some("idempotency_key_reused")));

    // Live keys can't see test objects.
    let (s, _, _) = call(&app, "GET", &format!("/v1/requests/{id}"), Some(&live), None, None).await;
    assert_eq!(s, StatusCode::NOT_FOUND);

    // Every failing fixture leaves the request open with the right code.
    for (fixture, code) in [
        ("zrcpt_test_wrong_payee", "wrong_payee"),
        ("zrcpt_test_insufficient_amount", "insufficient_amount"),
        ("zrcpt_test_challenge_mismatch", "challenge_mismatch"),
        ("zrcpt_test_not_mined", "transaction_not_mined"),
    ] {
        let (s, v, _) = call(&app, "POST", &format!("/v1/requests/{id}/receipts"), Some(&test), Some(json!({ "receipt": fixture })), None).await;
        assert_eq!((s, v["error"]["code"].as_str()), (StatusCode::UNPROCESSABLE_ENTITY, Some(code)), "{fixture}");
    }
    let (s, v, _) = call(&app, "POST", &format!("/v1/requests/{id}/receipts"), Some(&test), Some(json!({ "receipt": "zrcpt_test_valid" })), None).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["status"], "fulfilled");
    assert_eq!(v["fulfillment"]["paid_zatoshis"], 500000);
    let (s, v, _) = call(&app, "POST", &format!("/v1/requests/{id}/receipts"), Some(&test), Some(json!({ "receipt": "zrcpt_test_valid" })), None).await;
    assert_eq!((s, v["error"]["code"].as_str()), (StatusCode::CONFLICT, Some("request_already_fulfilled")));

    // Events were recorded: created, 4 rejections, fulfilled.
    let (_, ev, _) = call(&app, "GET", "/v1/events?limit=100", Some(&test), None, None).await;
    let types: Vec<&str> = ev["data"].as_array().unwrap().iter().map(|e| e["type"].as_str().unwrap()).collect();
    assert_eq!(types.iter().filter(|t| **t == "receipt.rejected").count(), 4);
    assert!(types.contains(&"request.fulfilled") && types.contains(&"request.created"));

    // Fixtures are refused with live keys.
    let (s, v, _) = call(&app, "POST", "/v1/verify", Some(&live), Some(json!({ "receipt": "zrcpt_test_valid" })), None).await;
    assert_eq!((s, v["error"]["code"].as_str()), (StatusCode::BAD_REQUEST, Some("receipt_network_mismatch")));
}

#[tokio::test]
async fn webhook_signature_helper_roundtrip() {
    let body = r#"{"id":"evt_1"}"#;
    let t = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64;
    let h = receipts_server::webhooks::sign("whsec_x", t, body);
    assert!(receipts_server::webhooks::verify_signature("whsec_x", &h, body, 300));
    assert!(!receipts_server::webhooks::verify_signature("whsec_y", &h, body, 300));
}

#[tokio::test]
async fn unsupported_version_is_refused() {
    let (app, test, _) = app().await;
    let req = Request::builder().uri("/v1/requests").header("authorization", format!("Bearer {test}")).header("receipts-version", "2001-01-01").body(Body::empty()).unwrap();
    let res = app.oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
}
