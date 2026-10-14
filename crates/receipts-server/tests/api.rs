//! In-process API tests using sandbox fixtures (no network, no chain).

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use receipts_chain::Net;
use serde_json::{json, Value};
use tower::ServiceExt;

const PAYEE: &str = "utest14te2vs2rwfe54mal8dwgejft2e9smlyasrku87ay4rq3dxnwcukp0vyck6exmjg60jttxz9y4a94772x0zc7xhj8gg7k00g4rg0zmdfa";

async fn app() -> (axum::Router, String, String) {
    app_with(receipts_server::Config::new(Net::Test, "http://verifier.test/")).await
}

async fn app_with(config: receipts_server::Config) -> (axum::Router, String, String) {
    // One fresh database per app, so parallel tests never share endpoints or events.
    static N: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let n = N.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    let db = std::env::temp_dir().join(format!("receipts-test-{}-{}-{n}.db", std::process::id(), rand_suffix()));
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

/// A local webhook receiver: answers `status`, records (signature header, body).
async fn receiver(status: u16) -> (String, std::sync::Arc<std::sync::Mutex<Vec<(String, String)>>>) {
    use axum::{http::HeaderMap, routing::post};
    let seen = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let s2 = seen.clone();
    let app = axum::Router::new().route(
        "/",
        post(move |h: HeaderMap, body: String| {
            let s2 = s2.clone();
            async move {
                s2.lock().unwrap().push((h.get("receipts-signature").map(|v| v.to_str().unwrap().to_string()).unwrap_or_default(), body));
                StatusCode::from_u16(status).unwrap()
            }
        }),
    );
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}/", l.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(l, app).await.unwrap() });
    (url, seen)
}

async fn wait_for(mut f: impl FnMut() -> bool) {
    for _ in 0..100 {
        if f() {
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    panic!("condition not met in time");
}

#[tokio::test]
async fn webhooks_are_signed_and_delivered() {
    let (app, test, _) = app().await;
    let (url, seen) = receiver(200).await;
    let (_, ep, _) = call(&app, "POST", "/v1/webhook_endpoints", Some(&test), Some(json!({ "url": url, "events": ["request.fulfilled"] })), None).await;
    let secret = ep["secret"].as_str().unwrap().to_string();
    let (_, req, _) = call(&app, "POST", "/v1/requests", Some(&test), Some(json!({ "payee": PAYEE })), None).await;
    call(&app, "POST", &format!("/v1/requests/{}/receipts", req["id"].as_str().unwrap()), Some(&test), Some(json!({ "receipt": "zrcpt_test_valid" })), None).await;
    wait_for(|| !seen.lock().unwrap().is_empty()).await;
    let (sig, body) = seen.lock().unwrap()[0].clone();
    assert!(receipts_server::webhooks::verify_signature(&secret, &sig, &body, 300), "signature must verify with the endpoint secret");
    let ev: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(ev["type"], "request.fulfilled", "only subscribed events are delivered");
    assert_eq!(ev["data"]["object"]["status"], "fulfilled");
}

#[tokio::test]
async fn failing_webhooks_retry_then_fail() {
    let mut cfg = receipts_server::Config::new(Net::Test, "http://verifier.test/");
    cfg.webhook_backoff_secs = 0;
    cfg.webhook_max_attempts = 3;
    let (app, test, _) = app_with(cfg).await;
    let (url, seen) = receiver(500).await;
    call(&app, "POST", "/v1/webhook_endpoints", Some(&test), Some(json!({ "url": url })), None).await;
    call(&app, "POST", "/v1/requests", Some(&test), Some(json!({ "payee": PAYEE })), None).await;
    wait_for(|| seen.lock().unwrap().len() >= 3).await;
    tokio::time::sleep(std::time::Duration::from_millis(1500)).await;
    let (_, d, _) = call(&app, "GET", "/v1/deliveries", Some(&test), None, None).await;
    assert_eq!(seen.lock().unwrap().len(), 3, "no attempts after the maximum");
    let d = &d["data"][0];
    assert_eq!(d["status"], "failed");
    assert_eq!(d["attempts"], 3);
    assert_eq!(d["last_http_status"], 500);
}

#[tokio::test]
async fn expired_requests_refuse_receipts() {
    let (app, test, _) = app().await;
    let (_, req, _) = call(&app, "POST", "/v1/requests", Some(&test), Some(json!({ "payee": PAYEE, "expires_in": 1 })), None).await;
    let id = req["id"].as_str().unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(2100)).await;
    let (_, r, _) = call(&app, "GET", &format!("/v1/requests/{id}"), Some(&test), None, None).await;
    assert_eq!(r["status"], "expired");
    let (s, v, _) = call(&app, "POST", &format!("/v1/requests/{id}/receipts"), Some(&test), Some(json!({ "receipt": "zrcpt_test_valid" })), None).await;
    assert_eq!((s, v["error"]["code"].as_str()), (StatusCode::CONFLICT, Some("request_expired")));
    let (_, l, _) = call(&app, "GET", "/v1/requests?status=expired", Some(&test), None, None).await;
    assert!(l["data"].as_array().unwrap().iter().any(|x| x["id"] == id));
}

/// Replaying a real receipt (made for no request, or another one) against a new request is
/// refused. Needs the public testnet: RECEIPTS_NETWORK_TESTS=1.
#[tokio::test]
async fn real_receipt_replay_is_refused() {
    if std::env::var("RECEIPTS_NETWORK_TESTS").is_err() {
        return;
    }
    let (app, test, _) = app().await;
    let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/../../examples/testnet");
    let payee = std::fs::read_to_string(format!("{dir}/merchant.ua")).unwrap();
    let answered = std::fs::read_to_string(format!("{dir}/request-answer-link.txt")).unwrap();
    let (_, req, _) = call(&app, "POST", "/v1/requests", Some(&test), Some(json!({ "payee": payee.trim(), "amount_zatoshis": 1000000 })), None).await;
    let (s, v, _) = call(&app, "POST", &format!("/v1/requests/{}/receipts", req["id"].as_str().unwrap()), Some(&test), Some(json!({ "receipt": answered })), None).await;
    assert_eq!((s, v["error"]["code"].as_str()), (StatusCode::UNPROCESSABLE_ENTITY, Some("challenge_mismatch")), "a receipt answering another request must not satisfy this one");
    // The same receipt still verifies on its own.
    let (s, v, _) = call(&app, "POST", "/v1/verify", Some(&test), Some(json!({ "receipt": answered })), None).await;
    assert_eq!(s, StatusCode::OK, "{v}");
}

#[tokio::test]
async fn one_payment_settles_one_request() {
    let (app, test, _) = app().await;
    let (_, a, _) = call(&app, "POST", "/v1/requests", Some(&test), Some(json!({ "payee": PAYEE })), None).await;
    let (_, b, _) = call(&app, "POST", "/v1/requests", Some(&test), Some(json!({ "payee": PAYEE })), None).await;
    let (s, _, _) = call(&app, "POST", &format!("/v1/requests/{}/receipts", a["id"].as_str().unwrap()), Some(&test), Some(json!({ "receipt": "zrcpt_test_same_payment" })), None).await;
    assert_eq!(s, StatusCode::OK);
    let (s, v, _) = call(&app, "POST", &format!("/v1/requests/{}/receipts", b["id"].as_str().unwrap()), Some(&test), Some(json!({ "receipt": "zrcpt_test_same_payment" })), None).await;
    assert_eq!((s, v["error"]["code"].as_str()), (StatusCode::CONFLICT, Some("payment_already_used")));
}

#[tokio::test]
async fn partial_payments_add_up() {
    let (app, test, _) = app().await;
    let (_, r, _) = call(&app, "POST", "/v1/requests", Some(&test), Some(json!({ "payee": PAYEE, "amount_zatoshis": 1000, "kind": "partial" })), None).await;
    let id = r["id"].as_str().unwrap();
    let (_, v, _) = call(&app, "POST", &format!("/v1/requests/{id}/receipts"), Some(&test), Some(json!({ "receipt": "zrcpt_test_partial" })), None).await;
    assert_eq!((v["status"].as_str(), v["received_zatoshis"].as_i64(), v["remaining_zatoshis"].as_i64()), (Some("open"), Some(500), Some(500)));
    assert!(v["payment_uri"].as_str().unwrap().contains("amount=0.000005"), "the payment URI asks only for what is still owed");
    let (_, v, _) = call(&app, "POST", &format!("/v1/requests/{id}/receipts"), Some(&test), Some(json!({ "receipt": "zrcpt_test_partial" })), None).await;
    assert_eq!(v["received_zatoshis"], 750);
    let (_, v, _) = call(&app, "POST", &format!("/v1/requests/{id}/receipts"), Some(&test), Some(json!({ "receipt": "zrcpt_test_valid" })), None).await;
    assert_eq!(v["status"], "fulfilled");
    assert_eq!(v["payments"].as_array().unwrap().len(), 3);
    let (_, ev, _) = call(&app, "GET", "/v1/events?limit=50", Some(&test), None, None).await;
    let n = ev["data"].as_array().unwrap().iter().filter(|e| e["type"] == "request.payment_received").count();
    assert_eq!(n, 3);
}

#[tokio::test]
async fn hosted_pay_page_needs_the_client_secret() {
    let (app, test, _) = app().await;
    let (_, r, _) = call(&app, "POST", "/v1/requests", Some(&test), Some(json!({ "payee": PAYEE, "amount_zatoshis": 1000, "metadata": { "order_id": "42" } })), None).await;
    let id = r["id"].as_str().unwrap();
    let secret = r["client_secret"].as_str().unwrap();
    assert!(r["hosted_url"].as_str().unwrap().contains(&format!("/pay/{id}?secret={secret}")));
    let (s, _, _) = call(&app, "GET", &format!("/v1/public/requests/{id}?secret=wrong"), None, None, None).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    let (s, v, _) = call(&app, "GET", &format!("/v1/public/requests/{id}?secret={secret}"), None, None, None).await;
    assert_eq!(s, StatusCode::OK);
    assert!(v.get("metadata").is_none() && v.get("client_secret").is_none(), "payers never see merchant metadata");
    let (s, _, _) = call(&app, "POST", &format!("/v1/public/requests/{id}/receipts"), None, Some(json!({ "client_secret": "nope", "receipt": "zrcpt_test_valid" })), None).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    let (s, v, _) = call(&app, "POST", &format!("/v1/public/requests/{id}/receipts"), None, Some(json!({ "client_secret": secret, "receipt": "zrcpt_test_valid" })), None).await;
    assert_eq!((s, v["status"].as_str()), (StatusCode::OK, Some("fulfilled")));
}

#[tokio::test]
async fn campaigns_publish_aggregates_only() {
    let mut cfg = receipts_server::Config::new(Net::Test, "http://verifier.test/");
    cfg.campaign_snapshot_secs = 0; // refresh on every read in this test
    let (app, test, _) = app_with(cfg).await;
    let (_, r, _) = call(&app, "POST", "/v1/requests", Some(&test), Some(json!({ "payee": PAYEE, "amount_zatoshis": 5_000_000, "kind": "campaign", "label": "Library fund", "metadata": { "internal": "x" } })), None).await;
    let id = r["id"].as_str().unwrap();
    let pay = |fixture: &'static str| {
        let app = app.clone();
        let id = id.to_string();
        async move { call(&app, "POST", &format!("/v1/public/requests/{id}/receipts"), None, Some(json!({ "receipt": fixture })), None).await.0 }
    };
    assert_eq!(pay("zrcpt_test_partial").await, StatusCode::OK);
    assert_eq!(pay("zrcpt_test_public_note").await, StatusCode::OK);
    // Below k = 3: nothing is published.
    let (_, c, _) = call(&app, "GET", &format!("/v1/public/campaigns/{id}"), None, None, None).await;
    assert_eq!(c["tally"]["visible"], false);
    assert!(c["tally"]["received_zatoshis_rounded"].is_null() && c["tally"]["contributions"].is_null());
    assert_eq!(pay("zrcpt_test_partial").await, StatusCode::OK);
    let (_, c, _) = call(&app, "GET", &format!("/v1/public/campaigns/{id}"), None, None, None).await;
    let t = &c["tally"];
    assert_eq!(t["visible"], true);
    assert_eq!(t["contributions"], 3);
    assert_eq!(t["received_zatoshis_rounded"].as_i64().unwrap() % 100_000, 0, "totals are rounded");
    assert_eq!(t["public_notes"], json!(["Good luck with the library!"]), "only opted-in notes");
    let text = c.to_string();
    for leak in ["txid", "mined_height", "sandbox fixture", "metadata", "internal", "\"zatoshis\":"] {
        assert!(!text.contains(leak), "public campaign JSON must not contain {leak}: {text}");
    }
    // The owner still sees everything through the API.
    let (_, full, _) = call(&app, "GET", &format!("/v1/requests/{id}"), Some(&test), None, None).await;
    assert_eq!(full["payments"].as_array().unwrap().len(), 3);
    assert_eq!(full["status"], "open", "campaigns never close by themselves");
}

#[tokio::test]
async fn campaign_numbers_update_in_batches() {
    let (app, test, _) = app().await; // default: refresh every 600 s
    let (_, r, _) = call(&app, "POST", "/v1/requests", Some(&test), Some(json!({ "payee": PAYEE, "kind": "campaign", "public_min_contributions": 1 })), None).await;
    let id = r["id"].as_str().unwrap();
    call(&app, "POST", &format!("/v1/public/requests/{id}/receipts"), None, Some(json!({ "receipt": "zrcpt_test_valid" })), None).await;
    let (_, a, _) = call(&app, "GET", &format!("/v1/public/campaigns/{id}"), None, None, None).await;
    call(&app, "POST", &format!("/v1/public/requests/{id}/receipts"), None, Some(json!({ "receipt": "zrcpt_test_valid" })), None).await;
    let (_, b, _) = call(&app, "GET", &format!("/v1/public/campaigns/{id}"), None, None, None).await;
    assert_eq!(a["tally"]["contributions"], 1);
    assert_eq!(b["tally"]["contributions"], 1, "a new contribution doesn't show until the next batch");
}

#[tokio::test]
async fn expiry_emits_an_event() {
    let (app, test, _) = app().await;
    call(&app, "POST", "/v1/requests", Some(&test), Some(json!({ "payee": PAYEE, "expires_in": 1 })), None).await;
    let mut seen = false;
    for _ in 0..40 {
        let (_, ev, _) = call(&app, "GET", "/v1/events", Some(&test), None, None).await;
        if ev["data"].as_array().unwrap().iter().any(|e| e["type"] == "request.expired") {
            seen = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    assert!(seen, "request.expired was emitted");
}

#[tokio::test]
async fn pasted_viewing_keys_are_refused_and_never_echoed() {
    let (app, test, _) = app().await;
    let ufvk = format!("uviewtest1{}", "q8w".repeat(40));
    let (s, v, _) = call(&app, "POST", "/v1/verify", Some(&test), Some(json!({ "receipt": ufvk })), None).await;
    assert_eq!((s, v["error"]["code"].as_str()), (StatusCode::BAD_REQUEST, Some("secret_detected")));
    assert!(!v.to_string().contains("q8wq8w"), "the error must not echo the key");
    let seed = "abandon ability able about above absent absorb abstract absurd abuse access accident"; // privacy-lint: allow (test fixture)
    let (s, _, _) = call(&app, "POST", "/v1/requests", Some(&test), Some(json!({ "payee": PAYEE, "label": seed })), None).await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    let (_, ev, _) = call(&app, "GET", "/v1/events", Some(&test), None, None).await;
    assert!(!ev.to_string().contains("abandon"), "nothing was stored");
}

#[tokio::test]
async fn sign_in_with_zcash() {
    use orchard::keys::{FullViewingKey, Scope, SpendingKey};
    use rand::{rand_core::UnwrapErr, rngs::SysRng};
    let (app, test, live) = app().await;
    let (s, ch, _) = call(&app, "POST", "/v1/sign_in/challenges", Some(&test), Some(json!({ "domain": "shop.example" })), None).await;
    assert_eq!(s, StatusCode::OK, "{ch}");
    assert_eq!((ch["status"].as_str(), ch["coin_type"].as_u64()), (Some("pending"), Some(1)));
    let nonce = ch["nonce"].as_str().unwrap().to_string();

    let sk = SpendingKey::from_bytes([7; 32]).unwrap();
    let addr = FullViewingKey::from(&sk).address_at(0u32, Scope::External);
    let sign = |domain: &'static str, nonce: String| {
        let sk = sk.clone();
        tokio::task::spawn_blocking(move || {
            receipts_core::signin::sign_in(&receipts_core::proving_key(), 1, domain, &nonce, 0, &sk, addr, UnwrapErr(SysRng)).unwrap().to_text()
        })
    };
    // Signed for another site: refused, and the challenge stays usable.
    let phished = sign("evil.example", nonce.clone()).await.unwrap();
    let (s, v, _) = call(&app, "POST", "/v1/sign_in/verify", Some(&test), Some(json!({ "sign_in": phished })), None).await;
    assert_eq!((s, v["error"]["code"].as_str()), (StatusCode::UNPROCESSABLE_ENTITY, Some("sign_in_invalid")), "{v}");

    let good = sign("shop.example", nonce.clone()).await.unwrap();
    // A live key can't use a test challenge.
    let (s, v, _) = call(&app, "POST", "/v1/sign_in/verify", Some(&live), Some(json!({ "sign_in": good }))
        , None).await;
    assert_eq!((s, v["error"]["code"].as_str()), (StatusCode::NOT_FOUND, Some("sign_in_challenge_not_found")));
    let (s, v, _) = call(&app, "POST", "/v1/sign_in/verify", Some(&test), Some(json!({ "sign_in": good }))
        , None).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!((v["verified"].as_bool(), v["domain"].as_str()), (Some(true), Some("shop.example")));
    assert!(v["address"].as_str().unwrap().starts_with("utest1"));
    // Replay is refused.
    let (s, v, _) = call(&app, "POST", "/v1/sign_in/verify", Some(&test), Some(json!({ "sign_in": good })), None).await;
    assert_eq!((s, v["error"]["code"].as_str()), (StatusCode::CONFLICT, Some("sign_in_challenge_used")));
    let (s, v, _) = call(&app, "POST", "/v1/sign_in/verify", Some(&test), Some(json!({ "sign_in": "zsig1AAAA" })), None).await;
    assert_eq!((s, v["error"]["code"].as_str()), (StatusCode::BAD_REQUEST, Some("sign_in_malformed")));
}

#[tokio::test]
async fn refunds_go_to_the_signed_address_and_need_proof() {
    let (app, test, _) = app().await;
    let refund_to = receipts_server::sandbox::SANDBOX_REFUND_ADDRESS;
    // A payment without a signed refund address cannot be refunded through the API.
    let (_, r1, _) = call(&app, "POST", "/v1/requests", Some(&test), Some(json!({ "payee": PAYEE, "amount_zatoshis": 300000 })), None).await;
    let id1 = r1["id"].as_str().unwrap();
    let (s, v, _) = call(&app, "POST", &format!("/v1/requests/{id1}/refunds"), Some(&test), Some(json!({})), None).await;
    assert_eq!((s, v["error"]["code"].as_str()), (StatusCode::CONFLICT, Some("refund_not_possible")));
    call(&app, "POST", &format!("/v1/requests/{id1}/receipts"), Some(&test), Some(json!({ "receipt": "zrcpt_test_valid" })), None).await;
    let (s, v, _) = call(&app, "POST", &format!("/v1/requests/{id1}/refunds"), Some(&test), Some(json!({})), None).await;
    assert_eq!((s, v["error"]["code"].as_str()), (StatusCode::CONFLICT, Some("refund_address_missing")));

    // The payer signed refund-to: the merchant can refund part, then the rest, never more.
    let (_, r2, _) = call(&app, "POST", "/v1/requests", Some(&test), Some(json!({ "payee": PAYEE, "amount_zatoshis": 300000 })), None).await;
    let id2 = r2["id"].as_str().unwrap();
    let (s, paid, _) = call(&app, "POST", &format!("/v1/requests/{id2}/receipts"), Some(&test), Some(json!({ "receipt": "zrcpt_test_refund_to" })), None).await;
    assert_eq!(s, StatusCode::OK, "{paid}");
    assert_eq!(paid["payments"][0]["refund_address"].as_str(), Some(refund_to));
    let (s, rf, _) = call(&app, "POST", &format!("/v1/requests/{id2}/refunds"), Some(&test), Some(json!({ "amount_zatoshis": 100000, "reason": "one coffee was cold" })), Some("rf1")).await;
    assert_eq!(s, StatusCode::CREATED, "{rf}");
    assert_eq!((rf["status"].as_str(), rf["address"].as_str()), (Some("pending"), Some(refund_to)));
    assert!(rf["payment_uri"].as_str().unwrap().starts_with(&format!("zcash:{refund_to}?amount=0.001&")));
    let (s, v, _) = call(&app, "POST", &format!("/v1/requests/{id2}/refunds"), Some(&test), Some(json!({ "amount_zatoshis": 200001 })), None).await;
    assert_eq!((s, v["error"]["code"].as_str()), (StatusCode::BAD_REQUEST, Some("refund_amount_invalid")));

    // Settling needs a receipt that signs the refund's challenge and pays the refund address.
    let rid = rf["id"].as_str().unwrap();
    let (s, v, _) = call(&app, "POST", &format!("/v1/refunds/{rid}/receipts"), Some(&test), Some(json!({ "receipt": "zrcpt_test_challenge_mismatch" })), None).await;
    assert_eq!((s, v["error"]["code"].as_str()), (StatusCode::UNPROCESSABLE_ENTITY, Some("challenge_mismatch")));
    let (s, v, _) = call(&app, "POST", &format!("/v1/refunds/{rid}/receipts"), Some(&test), Some(json!({ "receipt": "zrcpt_test_insufficient_amount" })), None).await;
    assert_eq!((s, v["error"]["code"].as_str()), (StatusCode::UNPROCESSABLE_ENTITY, Some("insufficient_amount")));
    let (s, done, _) = call(&app, "POST", &format!("/v1/refunds/{rid}/receipts"), Some(&test), Some(json!({ "receipt": "zrcpt_test_valid" })), None).await;
    assert_eq!((s, done["status"].as_str()), (StatusCode::OK, Some("succeeded")), "{done}");
    let (s, v, _) = call(&app, "POST", &format!("/v1/refunds/{rid}/receipts"), Some(&test), Some(json!({ "receipt": "zrcpt_test_valid" })), None).await;
    assert_eq!((s, v["error"]["code"].as_str()), (StatusCode::CONFLICT, Some("refund_already_succeeded")));

    // The rest of the payment is still refundable; the request lists both refunds.
    let (s, rest, _) = call(&app, "POST", &format!("/v1/requests/{id2}/refunds"), Some(&test), Some(json!({})), None).await;
    assert_eq!((s, rest["amount_zatoshis"].as_i64()), (StatusCode::CREATED, Some(200000)));
    let (_, req, _) = call(&app, "GET", &format!("/v1/requests/{id2}"), Some(&test), None, None).await;
    assert_eq!(req["refunds"].as_array().unwrap().len(), 2);
    let (_, ev, _) = call(&app, "GET", "/v1/events?limit=50", Some(&test), None, None).await;
    let types: Vec<&str> = ev["data"].as_array().unwrap().iter().filter_map(|e| e["type"].as_str()).collect();
    assert!(types.contains(&"refund.created") && types.contains(&"refund.succeeded"), "{types:?}");
}

#[tokio::test]
async fn test_clocks_drive_expiry_and_finality() {
    let (app, test, live) = app().await;
    let (s, v, _) = call(&app, "POST", "/v1/test_clocks", Some(&live), Some(json!({})), None).await;
    assert_eq!((s, v["error"]["code"].as_str()), (StatusCode::BAD_REQUEST, Some("livemode_not_allowed")));
    let (s, clock, _) = call(&app, "POST", "/v1/test_clocks", Some(&test), Some(json!({ "frozen_time": 1_800_000_000, "height": 100 })), None).await;
    assert_eq!(s, StatusCode::CREATED, "{clock}");
    let cid = clock["id"].as_str().unwrap();

    // One request will expire; the other gets paid and then waits for finality.
    let (_, a, _) = call(&app, "POST", "/v1/requests", Some(&test), Some(json!({ "payee": PAYEE, "expires_in": 3600, "test_clock": cid })), None).await;
    let (_, b, _) = call(&app, "POST", "/v1/requests", Some(&test), Some(json!({ "payee": PAYEE, "amount_zatoshis": 1000, "test_clock": cid })), None).await;
    assert_eq!(a["created"], 1_800_000_000);
    let (a_id, b_id) = (a["id"].as_str().unwrap(), b["id"].as_str().unwrap());
    let (_, paid, _) = call(&app, "POST", &format!("/v1/requests/{b_id}/receipts"), Some(&test), Some(json!({ "receipt": "zrcpt_test_valid" })), None).await;
    assert_eq!((paid["status"].as_str(), paid["final"].as_bool()), (Some("fulfilled"), Some(false)), "{paid}");
    assert_eq!(paid["payments"][0]["mined_height"], 100);

    // 5 blocks: nothing due yet.
    let (_, adv, _) = call(&app, "POST", &format!("/v1/test_clocks/{cid}/advance"), Some(&test), Some(json!({ "blocks": 5 })), None).await;
    assert_eq!(adv["fired"].as_array().unwrap().len(), 0, "{adv}");
    // 5 more blocks (10 confirmations) and past the hour: final + expired.
    let (_, adv, _) = call(&app, "POST", &format!("/v1/test_clocks/{cid}/advance"), Some(&test), Some(json!({ "blocks": 4, "seconds": 3600 })), None).await;
    let fired: Vec<(String, String)> = adv["fired"].as_array().unwrap().iter().map(|f| (f["type"].as_str().unwrap().into(), f["request"].as_str().unwrap().into())).collect();
    assert!(fired.contains(&("request.expired".into(), a_id.into())), "{fired:?}");
    assert!(fired.contains(&("request.final".into(), b_id.into())), "{fired:?}");
    assert_eq!(adv["height"], 109);
    let (_, b2, _) = call(&app, "GET", &format!("/v1/requests/{b_id}"), Some(&test), None, None).await;
    assert_eq!(b2["final"].as_bool(), Some(true));
    // Advancing again fires nothing twice.
    let (_, adv, _) = call(&app, "POST", &format!("/v1/test_clocks/{cid}/advance"), Some(&test), Some(json!({ "blocks": 1 })), None).await;
    assert_eq!(adv["fired"].as_array().unwrap().len(), 0);
    let (s, v, _) = call(&app, "POST", "/v1/requests", Some(&test), Some(json!({ "payee": PAYEE, "test_clock": "clock_nope" })), None).await;
    assert_eq!((s, v["error"]["code"].as_str()), (StatusCode::NOT_FOUND, Some("test_clock_not_found")));
}
