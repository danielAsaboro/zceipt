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

async fn call(
    app: &axum::Router,
    method: &str,
    path: &str,
    key: Option<&str>,
    body: Option<Value>,
    idem: Option<&str>,
) -> (StatusCode, Value, axum::http::HeaderMap) {
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
    let (s, req, h) =
        call(&app, "POST", "/v1/requests", Some(&test), Some(json!({ "payee": PAYEE, "amount_zatoshis": 500000, "label": "t" })), Some("k1")).await;
    assert_eq!(s, StatusCode::CREATED);
    assert_eq!(h.get("receipts-version").unwrap(), receipts_server::API_VERSION);
    assert!(req["payment_uri"].as_str().unwrap().starts_with(&format!("zcash:{PAYEE}?amount=0.005")));
    let id = req["id"].as_str().unwrap().to_string();

    // Idempotent replay returns the same object; a different body with the same key is refused.
    let (_, again, h) =
        call(&app, "POST", "/v1/requests", Some(&test), Some(json!({ "payee": PAYEE, "amount_zatoshis": 500000, "label": "t" })), Some("k1")).await;
    assert_eq!(again["id"], req["id"]);
    assert_eq!(h.get("idempotent-replayed").unwrap(), "true");
    let (s, v, _) = call(&app, "POST", "/v1/requests", Some(&test), Some(json!({ "payee": PAYEE })), Some("k1")).await;
    assert_eq!((s, v["error"]["code"].as_str()), (StatusCode::CONFLICT, Some("idempotency_key_reused")));

    // Live keys can't see test objects.
    let (s, _, _) = call(&app, "GET", &format!("/v1/requests/{id}"), Some(&live), None, None).await;
    assert_eq!(s, StatusCode::NOT_FOUND);

    // Every failing fixture leaves the request open with the right code.
    for (fixture, code) in [
        ("zip311_test_wrong_payee", "wrong_payee"),
        ("zip311_test_memo_withheld", "delivery_unproven"),
        ("zip311_test_insufficient_amount", "insufficient_amount"),
        ("zip311_test_challenge_mismatch", "challenge_mismatch"),
        ("zip311_test_not_mined", "transaction_not_mined"),
    ] {
        let (s, v, _) = call(&app, "POST", &format!("/v1/requests/{id}/receipts"), Some(&test), Some(json!({ "receipt": fixture })), None).await;
        assert_eq!((s, v["error"]["code"].as_str()), (StatusCode::UNPROCESSABLE_ENTITY, Some(code)), "{fixture}");
    }
    let (s, v, _) = call(&app, "POST", &format!("/v1/requests/{id}/receipts"), Some(&test), Some(json!({ "receipt": "zip311_test_valid" })), None).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["status"], "fulfilled");
    assert_eq!(v["fulfillment"]["paid_zatoshis"], 500000);
    let (s, v, _) = call(&app, "POST", &format!("/v1/requests/{id}/receipts"), Some(&test), Some(json!({ "receipt": "zip311_test_valid" })), None).await;
    assert_eq!((s, v["error"]["code"].as_str()), (StatusCode::CONFLICT, Some("request_already_fulfilled")));

    // Events were recorded: created, 5 rejections, fulfilled.
    let (_, ev, _) = call(&app, "GET", "/v1/events?limit=100", Some(&test), None, None).await;
    let types: Vec<&str> = ev["data"].as_array().unwrap().iter().map(|e| e["type"].as_str().unwrap()).collect();
    assert_eq!(types.iter().filter(|t| **t == "receipt.rejected").count(), 5);
    assert!(types.contains(&"request.fulfilled") && types.contains(&"request.created"));

    // Fixtures are refused with live keys.
    let (s, v, _) = call(&app, "POST", "/v1/verify", Some(&live), Some(json!({ "receipt": "zip311_test_valid" })), None).await;
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
    let req = Request::builder()
        .uri("/v1/requests")
        .header("authorization", format!("Bearer {test}"))
        .header("receipts-version", "2001-01-01")
        .body(Body::empty())
        .unwrap();
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
    call(&app, "POST", &format!("/v1/requests/{}/receipts", req["id"].as_str().unwrap()), Some(&test), Some(json!({ "receipt": "zip311_test_valid" })), None)
        .await;
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
    let (s, v, _) = call(&app, "POST", &format!("/v1/requests/{id}/receipts"), Some(&test), Some(json!({ "receipt": "zip311_test_valid" })), None).await;
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
    let (s, v, _) =
        call(&app, "POST", &format!("/v1/requests/{}/receipts", req["id"].as_str().unwrap()), Some(&test), Some(json!({ "receipt": answered })), None).await;
    assert_eq!(
        (s, v["error"]["code"].as_str()),
        (StatusCode::UNPROCESSABLE_ENTITY, Some("challenge_mismatch")),
        "a receipt answering another request must not satisfy this one"
    );
    // The same receipt still verifies on its own.
    let (s, v, _) = call(&app, "POST", "/v1/verify", Some(&test), Some(json!({ "receipt": answered })), None).await;
    assert_eq!(s, StatusCode::OK, "{v}");
}

#[tokio::test]
async fn one_payment_settles_one_request() {
    let (app, test, _) = app().await;
    let (_, a, _) = call(&app, "POST", "/v1/requests", Some(&test), Some(json!({ "payee": PAYEE })), None).await;
    let (_, b, _) = call(&app, "POST", "/v1/requests", Some(&test), Some(json!({ "payee": PAYEE })), None).await;
    let (s, _, _) = call(
        &app,
        "POST",
        &format!("/v1/requests/{}/receipts", a["id"].as_str().unwrap()),
        Some(&test),
        Some(json!({ "receipt": "zip311_test_same_payment" })),
        None,
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    let (s, v, _) = call(
        &app,
        "POST",
        &format!("/v1/requests/{}/receipts", b["id"].as_str().unwrap()),
        Some(&test),
        Some(json!({ "receipt": "zip311_test_same_payment" })),
        None,
    )
    .await;
    assert_eq!((s, v["error"]["code"].as_str()), (StatusCode::CONFLICT, Some("payment_already_used")));
}

#[tokio::test]
async fn partial_payments_add_up() {
    let (app, test, _) = app().await;
    let (_, r, _) = call(&app, "POST", "/v1/requests", Some(&test), Some(json!({ "payee": PAYEE, "amount_zatoshis": 1000, "kind": "partial" })), None).await;
    let id = r["id"].as_str().unwrap();
    let (_, v, _) = call(&app, "POST", &format!("/v1/requests/{id}/receipts"), Some(&test), Some(json!({ "receipt": "zip311_test_partial" })), None).await;
    assert_eq!((v["status"].as_str(), v["received_zatoshis"].as_i64(), v["remaining_zatoshis"].as_i64()), (Some("open"), Some(500), Some(500)));
    assert!(v["payment_uri"].as_str().unwrap().contains("amount=0.000005"), "the payment URI asks only for what is still owed");
    let (_, v, _) = call(&app, "POST", &format!("/v1/requests/{id}/receipts"), Some(&test), Some(json!({ "receipt": "zip311_test_partial" })), None).await;
    assert_eq!(v["received_zatoshis"], 750);
    let (_, v, _) = call(&app, "POST", &format!("/v1/requests/{id}/receipts"), Some(&test), Some(json!({ "receipt": "zip311_test_valid" })), None).await;
    assert_eq!(v["status"], "fulfilled");
    assert_eq!(v["payments"].as_array().unwrap().len(), 3);
    let (_, ev, _) = call(&app, "GET", "/v1/events?limit=50", Some(&test), None, None).await;
    let n = ev["data"].as_array().unwrap().iter().filter(|e| e["type"] == "request.payment_received").count();
    assert_eq!(n, 3);
}

#[tokio::test]
async fn hosted_pay_page_needs_the_client_secret() {
    let (app, test, _) = app().await;
    let (_, r, _) =
        call(&app, "POST", "/v1/requests", Some(&test), Some(json!({ "payee": PAYEE, "amount_zatoshis": 1000, "metadata": { "order_id": "42" } })), None).await;
    let id = r["id"].as_str().unwrap();
    let secret = r["client_secret"].as_str().unwrap();
    assert!(r["hosted_url"].as_str().unwrap().contains(&format!("/pay/{id}#secret={secret}")));
    let (s, _, _) = call(&app, "GET", &format!("/v1/public/requests/{id}?secret=wrong"), None, None, None).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    let (s, v, _) = call(&app, "GET", &format!("/v1/public/requests/{id}?secret={secret}"), None, None, None).await;
    assert_eq!(s, StatusCode::OK);
    assert!(v.get("metadata").is_none() && v.get("client_secret").is_none(), "payers never see merchant metadata");
    let (s, _, _) =
        call(&app, "POST", &format!("/v1/public/requests/{id}/receipts"), None, Some(json!({ "client_secret": "nope", "receipt": "zip311_test_valid" })), None)
            .await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    let (s, v, _) =
        call(&app, "POST", &format!("/v1/public/requests/{id}/receipts"), None, Some(json!({ "client_secret": secret, "receipt": "zip311_test_valid" })), None)
            .await;
    assert_eq!((s, v["status"].as_str()), (StatusCode::OK, Some("fulfilled")));
}

#[tokio::test]
async fn campaigns_publish_aggregates_only() {
    let mut cfg = receipts_server::Config::new(Net::Test, "http://verifier.test/");
    cfg.campaign_snapshot_secs = 0; // refresh on every read in this test
    let (app, test, _) = app_with(cfg).await;
    let (_, r, _) = call(
        &app,
        "POST",
        "/v1/requests",
        Some(&test),
        Some(json!({ "payee": PAYEE, "amount_zatoshis": 5_000_000, "kind": "campaign", "label": "Library fund", "metadata": { "internal": "x" } })),
        None,
    )
    .await;
    let id = r["id"].as_str().unwrap();
    let pay = |fixture: &'static str| {
        let app = app.clone();
        let id = id.to_string();
        async move { call(&app, "POST", &format!("/v1/public/requests/{id}/receipts"), None, Some(json!({ "receipt": fixture })), None).await.0 }
    };
    assert_eq!(pay("zip311_test_partial").await, StatusCode::OK);
    assert_eq!(pay("zip311_test_public_note").await, StatusCode::OK);
    // Below k = 3: nothing is published.
    let (_, c, _) = call(&app, "GET", &format!("/v1/public/campaigns/{id}"), None, None, None).await;
    assert_eq!(c["tally"]["visible"], false);
    assert!(c["tally"]["received_zatoshis_rounded"].is_null() && c["tally"]["contributions"].is_null());
    assert_eq!(pay("zip311_test_partial").await, StatusCode::OK);
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
    let (_, r, _) =
        call(&app, "POST", "/v1/requests", Some(&test), Some(json!({ "payee": PAYEE, "kind": "campaign", "public_min_contributions": 1 })), None).await;
    let id = r["id"].as_str().unwrap();
    call(&app, "POST", &format!("/v1/public/requests/{id}/receipts"), None, Some(json!({ "receipt": "zip311_test_valid" })), None).await;
    let (_, a, _) = call(&app, "GET", &format!("/v1/public/campaigns/{id}"), None, None, None).await;
    call(&app, "POST", &format!("/v1/public/requests/{id}/receipts"), None, Some(json!({ "receipt": "zip311_test_valid" })), None).await;
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
    let (s, v, _) = call(&app, "POST", "/v1/sign_in/verify", Some(&live), Some(json!({ "sign_in": good })), None).await;
    assert_eq!((s, v["error"]["code"].as_str()), (StatusCode::NOT_FOUND, Some("sign_in_challenge_not_found")));
    let (s, v, _) = call(&app, "POST", "/v1/sign_in/verify", Some(&test), Some(json!({ "sign_in": good })), None).await;
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
    call(&app, "POST", &format!("/v1/requests/{id1}/receipts"), Some(&test), Some(json!({ "receipt": "zip311_test_valid" })), None).await;
    let (s, v, _) = call(&app, "POST", &format!("/v1/requests/{id1}/refunds"), Some(&test), Some(json!({})), None).await;
    assert_eq!((s, v["error"]["code"].as_str()), (StatusCode::CONFLICT, Some("refund_address_missing")));

    // The payer signed refund-to: the merchant can refund part, then the rest, never more.
    let (_, r2, _) = call(&app, "POST", "/v1/requests", Some(&test), Some(json!({ "payee": PAYEE, "amount_zatoshis": 300000 })), None).await;
    let id2 = r2["id"].as_str().unwrap();
    let (s, paid, _) =
        call(&app, "POST", &format!("/v1/requests/{id2}/receipts"), Some(&test), Some(json!({ "receipt": "zip311_test_refund_to" })), None).await;
    assert_eq!(s, StatusCode::OK, "{paid}");
    assert_eq!(paid["payments"][0]["refund_address"].as_str(), Some(refund_to));
    let (s, rf, _) = call(
        &app,
        "POST",
        &format!("/v1/requests/{id2}/refunds"),
        Some(&test),
        Some(json!({ "amount_zatoshis": 100000, "reason": "one coffee was cold" })),
        Some("rf1"),
    )
    .await;
    assert_eq!(s, StatusCode::CREATED, "{rf}");
    assert_eq!((rf["status"].as_str(), rf["address"].as_str()), (Some("pending"), Some(refund_to)));
    assert!(rf["payment_uri"].as_str().unwrap().starts_with(&format!("zcash:{refund_to}?amount=0.001&")));
    let (s, v, _) = call(&app, "POST", &format!("/v1/requests/{id2}/refunds"), Some(&test), Some(json!({ "amount_zatoshis": 200001 })), None).await;
    assert_eq!((s, v["error"]["code"].as_str()), (StatusCode::BAD_REQUEST, Some("refund_amount_invalid")));

    // Settling needs a receipt that signs the refund's challenge and pays the refund address.
    let rid = rf["id"].as_str().unwrap();
    let (s, v, _) =
        call(&app, "POST", &format!("/v1/refunds/{rid}/receipts"), Some(&test), Some(json!({ "receipt": "zip311_test_challenge_mismatch" })), None).await;
    assert_eq!((s, v["error"]["code"].as_str()), (StatusCode::UNPROCESSABLE_ENTITY, Some("challenge_mismatch")));
    let (s, v, _) =
        call(&app, "POST", &format!("/v1/refunds/{rid}/receipts"), Some(&test), Some(json!({ "receipt": "zip311_test_insufficient_amount" })), None).await;
    assert_eq!((s, v["error"]["code"].as_str()), (StatusCode::UNPROCESSABLE_ENTITY, Some("insufficient_amount")));
    let (s, done, _) = call(&app, "POST", &format!("/v1/refunds/{rid}/receipts"), Some(&test), Some(json!({ "receipt": "zip311_test_valid" })), None).await;
    assert_eq!((s, done["status"].as_str()), (StatusCode::OK, Some("succeeded")), "{done}");
    let (s, v, _) = call(&app, "POST", &format!("/v1/refunds/{rid}/receipts"), Some(&test), Some(json!({ "receipt": "zip311_test_valid" })), None).await;
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
    let (_, paid, _) = call(&app, "POST", &format!("/v1/requests/{b_id}/receipts"), Some(&test), Some(json!({ "receipt": "zip311_test_valid" })), None).await;
    assert_eq!((paid["status"].as_str(), paid["final"].as_bool()), (Some("fulfilled"), Some(false)), "{paid}");
    assert_eq!(paid["payments"][0]["mined_height"], 100);

    // 5 blocks: nothing due yet.
    let (_, adv, _) = call(&app, "POST", &format!("/v1/test_clocks/{cid}/advance"), Some(&test), Some(json!({ "blocks": 5 })), None).await;
    assert_eq!(adv["fired"].as_array().unwrap().len(), 0, "{adv}");
    // 5 more blocks (10 confirmations) and past the hour: final + expired.
    let (_, adv, _) = call(&app, "POST", &format!("/v1/test_clocks/{cid}/advance"), Some(&test), Some(json!({ "blocks": 4, "seconds": 3600 })), None).await;
    let fired: Vec<(String, String)> =
        adv["fired"].as_array().unwrap().iter().map(|f| (f["type"].as_str().unwrap().into(), f["request"].as_str().unwrap().into())).collect();
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

#[tokio::test]
async fn payment_links_are_checked_and_our_own_pass() {
    let (app, test, _) = app().await;
    let (_, r, _) =
        call(&app, "POST", "/v1/requests", Some(&test), Some(json!({ "payee": PAYEE, "amount_zatoshis": 1234500, "label": "Kemi's Coffee" })), None).await;
    let (s, v, _) = call(&app, "POST", "/v1/payment_links/check", Some(&test), Some(json!({ "uri": r["payment_uri"] })), None).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(v["ok"], true, "{v}");
    assert!(v["findings"].as_array().unwrap().is_empty(), "our own links must be clean: {v}");
    assert_eq!(v["payments"][0]["amount_zatoshis"], 1234500);
    // Checking against the wrong network is an error.
    let (_, v, _) =
        call(&app, "POST", "/v1/payment_links/check", Some(&test), Some(json!({ "uri": format!("zcash:{PAYEE}?amount=1"), "network": "mainnet" })), None).await;
    assert_eq!(v["ok"], false);
    let (s, v, _) = call(&app, "POST", "/v1/payment_links/check", Some(&test), Some(json!({})), None).await;
    assert_eq!((s, v["error"]["param"].as_str()), (StatusCode::BAD_REQUEST, Some("uri")));
}

#[tokio::test]
async fn attestations_state_minimal_facts_and_disclose_selectively() {
    let (app, test, live) = app().await;
    let (_, r, _) =
        call(&app, "POST", "/v1/requests", Some(&test), Some(json!({ "payee": PAYEE, "amount_zatoshis": 1234567, "label": "Grant round 3" })), None).await;
    let id = r["id"].as_str().unwrap();
    let (s, v, _) = call(&app, "POST", &format!("/v1/requests/{id}/attestations"), Some(&test), Some(json!({})), None).await;
    assert_eq!((s, v["error"]["code"].as_str()), (StatusCode::CONFLICT, Some("request_not_fulfilled")));
    call(&app, "POST", &format!("/v1/requests/{id}/receipts"), Some(&test), Some(json!({ "receipt": "zip311_test_valid" })), None).await;

    let (s, a, _) = call(&app, "POST", &format!("/v1/requests/{id}/attestations"), Some(&test), Some(json!({ "at_least_zatoshis": 1000000 })), None).await;
    assert_eq!(s, StatusCode::OK, "{a}");
    let pres = a["presentation"].as_str().unwrap();
    // The default presentation carries no txid, exact amount, exact time, request id or label.
    let payload =
        String::from_utf8(base64::Engine::decode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, pres.split('.').nth(1).unwrap()).unwrap()).unwrap();
    for hidden in ["5a4db0c5", "1234567", id, "Grant round 3", "paid_at\""] {
        assert!(!payload.contains(hidden) && !pres.contains(hidden), "{hidden} leaked: {payload}");
    }
    let (s, ok, _) = call(&app, "POST", "/v1/attestations/verify", Some(&test), Some(json!({ "attestation": pres })), None).await;
    assert_eq!(s, StatusCode::OK, "{ok}");
    assert_eq!(ok["claims"]["paid_at_least_zatoshis"], 1000000);
    assert_eq!(ok["claims"]["revealed"], json!({}));

    // Reveal the label later: the signature still checks.
    let with_label = format!("{pres}{}~", a["disclosures"]["label"].as_str().unwrap());
    let (_, ok, _) = call(&app, "POST", "/v1/attestations/verify", Some(&test), Some(json!({ "attestation": with_label })), None).await;
    assert_eq!(ok["claims"]["revealed"]["label"], "Grant round 3", "{ok}");
    // Changing a stated fact, or adding a foreign disclosure, breaks it.
    let forged = pres.replacen('.', ".x", 1);
    let (s, v, _) = call(&app, "POST", "/v1/attestations/verify", Some(&test), Some(json!({ "attestation": forged })), None).await;
    assert_eq!((s, v["error"]["code"].as_str()), (StatusCode::UNPROCESSABLE_ENTITY, Some("attestation_invalid")));
    // A live key refuses a test-mode (sandbox-paid) attestation signed by the same key.
    let (s, v, _) = call(&app, "POST", "/v1/attestations/verify", Some(&live), Some(json!({ "attestation": pres })), None).await;
    assert_eq!((s, v["error"]["code"].as_str()), (StatusCode::UNPROCESSABLE_ENTITY, Some("attestation_invalid")));
    let (_, other, _) = call(&app, "POST", &format!("/v1/requests/{id}/attestations"), Some(&test), Some(json!({})), None).await;
    let mixed = format!("{pres}{}~", other["disclosures"]["txid"].as_str().unwrap());
    let (s, _, _) = call(&app, "POST", "/v1/attestations/verify", Some(&test), Some(json!({ "attestation": mixed })), None).await;
    assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY);
    // No overclaiming.
    let (s, v, _) = call(&app, "POST", &format!("/v1/requests/{id}/attestations"), Some(&test), Some(json!({ "at_least_zatoshis": 9_999_999 })), None).await;
    assert_eq!((s, v["error"]["code"].as_str()), (StatusCode::BAD_REQUEST, Some("attestation_overclaims")));
    let (s, v, _) = call(&app, "POST", &format!("/v1/requests/{id}/attestations"), Some(&test), Some(json!({ "before": "2020-01-01" })), None).await;
    assert_eq!((s, v["error"]["code"].as_str()), (StatusCode::BAD_REQUEST, Some("attestation_overclaims")));
    let (_, jwks, _) = call(&app, "GET", "/.well-known/jwks.json", None, None, None).await;
    assert_eq!(jwks["keys"][0]["crv"], "Ed25519");
}

#[tokio::test]
async fn attestations_subtract_refunds() {
    let (app, test, _) = app().await;
    let (_, r, _) = call(&app, "POST", "/v1/requests", Some(&test), Some(json!({ "payee": PAYEE, "amount_zatoshis": 2000000 })), None).await;
    let id = r["id"].as_str().unwrap();
    call(&app, "POST", &format!("/v1/requests/{id}/receipts"), Some(&test), Some(json!({ "receipt": "zip311_test_refund_to" })), None).await;
    let (_, rf, _) = call(&app, "POST", &format!("/v1/requests/{id}/refunds"), Some(&test), Some(json!({ "amount_zatoshis": 500000 })), None).await;
    call(&app, "POST", &format!("/v1/refunds/{}/receipts", rf["id"].as_str().unwrap()), Some(&test), Some(json!({ "receipt": "zip311_test_valid" })), None)
        .await;
    let (_, a, _) = call(&app, "POST", &format!("/v1/requests/{id}/attestations"), Some(&test), Some(json!({})), None).await;
    assert_eq!(a["claims"]["paid_at_least_zatoshis"], 1000000, "default floor: net 0.015 ZEC rounded down to 0.01: {a}");
    let (s, a, _) = call(&app, "POST", &format!("/v1/requests/{id}/attestations"), Some(&test), Some(json!({ "at_least_zatoshis": 1500000 })), None).await;
    assert_eq!((s, a["claims"]["paid_at_least_zatoshis"].as_i64()), (StatusCode::OK, Some(1500000)));
    let (s, v, _) = call(&app, "POST", &format!("/v1/requests/{id}/attestations"), Some(&test), Some(json!({ "at_least_zatoshis": 2000000 })), None).await;
    assert_eq!((s, v["error"]["code"].as_str()), (StatusCode::BAD_REQUEST, Some("attestation_overclaims")));
}

#[tokio::test]
async fn pagination_never_repeats_requests_created_in_the_same_second() {
    let (app, test, _) = app().await;
    for i in 0..13 {
        call(&app, "POST", "/v1/requests", Some(&test), Some(json!({ "payee": PAYEE, "label": format!("r{i}") })), None).await;
    }
    let mut seen = std::collections::HashSet::new();
    let mut after: Option<String> = None;
    for _ in 0..10 {
        let path = match &after {
            Some(a) => format!("/v1/requests?limit=5&starting_after={a}"),
            None => "/v1/requests?limit=5".into(),
        };
        let (_, page, _) = call(&app, "GET", &path, Some(&test), None, None).await;
        for r in page["data"].as_array().unwrap() {
            assert!(seen.insert(r["id"].as_str().unwrap().to_string()), "repeated {}", r["id"]);
        }
        if page["has_more"] != true {
            break;
        }
        after = page["data"].as_array().unwrap().last().map(|r| r["id"].as_str().unwrap().to_string());
    }
    assert_eq!(seen.len(), 13);
    let (s, v, _) = call(&app, "POST", "/v1/verify", Some(&test), Some(json!({ "receipt": "zip311_test_valid", "min_zatoshis": 5 })), None).await;
    assert_eq!((s, v["error"]["param"].as_str()), (StatusCode::BAD_REQUEST, Some("expect_address")));
}

#[tokio::test]
async fn hardening_public_limits_headers_and_live_webhook_hosts() {
    let (app, test, live) = app().await;
    let (_, r, _) = call(&app, "POST", "/v1/requests", Some(&test), Some(json!({ "payee": PAYEE })), None).await;
    let id = r["id"].as_str().unwrap();
    let secret = r["client_secret"].as_str().unwrap();
    let mut last = StatusCode::OK;
    for _ in 0..(receipts_server::PUBLIC_SUBMIT_LIMIT + 1) {
        let (s, _, _) =
            call(&app, "POST", &format!("/v1/public/requests/{id}/receipts"), None, Some(json!({ "client_secret": secret, "receipt": "zip311r1AAAA" })), None)
                .await;
        last = s;
    }
    assert_eq!(last, StatusCode::TOO_MANY_REQUESTS);
    // Hosted pages never leak their secret-bearing URL as a referrer.
    let (_, _, h) = call(&app, "GET", &format!("/pay/{id}?secret={secret}"), None, None, None).await;
    assert_eq!(h.get("referrer-policy").unwrap(), "no-referrer");
    assert_eq!(h.get("x-content-type-options").unwrap(), "nosniff");
    assert!(h.get("content-security-policy").unwrap().to_str().unwrap().contains("frame-ancestors"));
    // Live webhooks: https and public hosts only. Test mode may use localhost.
    for bad in [
        "http://example.com/h",
        "https://localhost/h",
        "https://127.0.0.1/h",
        "https://10.0.0.5/h",
        "https://169.254.169.254/latest",
        "https://[::1]/h",
        "https://db.internal/h",
    ] {
        let (s, v, _) = call(&app, "POST", "/v1/webhook_endpoints", Some(&live), Some(json!({ "url": bad })), None).await;
        assert_eq!((s, v["error"]["code"].as_str()), (StatusCode::BAD_REQUEST, Some("webhook_url_not_allowed")), "{bad}");
    }
    let (s, _, _) = call(&app, "POST", "/v1/webhook_endpoints", Some(&live), Some(json!({ "url": "https://shop.example.com/hooks" })), None).await;
    assert_eq!(s, StatusCode::CREATED);
    let (s, _, _) = call(&app, "POST", "/v1/webhook_endpoints", Some(&test), Some(json!({ "url": "http://127.0.0.1:3000/hooks" })), None).await;
    assert_eq!(s, StatusCode::CREATED);
    // A sandbox key can't aim the server at link-local or cloud metadata addresses either.
    for bad in ["http://169.254.169.254/latest", "http://[fe80::1]/h", "http://[::ffff:169.254.169.254]/", "http://100.100.100.200/", "http://0.0.0.0:80/", "http://metadata.google.internal/"] {
        let (s, v, _) = call(&app, "POST", "/v1/webhook_endpoints", Some(&test), Some(json!({ "url": bad })), None).await;
        assert_eq!((s, v["error"]["code"].as_str()), (StatusCode::BAD_REQUEST, Some("webhook_url_not_allowed")), "{bad}");
    }
}

#[tokio::test]
async fn test_clock_reorg_unconfirms_then_remines() {
    let (app, test, _) = app().await;
    let (_, clock, _) = call(&app, "POST", "/v1/test_clocks", Some(&test), Some(json!({ "height": 500 })), None).await;
    let cid = clock["id"].as_str().unwrap();
    let (_, r, _) = call(&app, "POST", "/v1/requests", Some(&test), Some(json!({ "payee": PAYEE, "test_clock": cid })), None).await;
    let id = r["id"].as_str().unwrap();
    call(&app, "POST", &format!("/v1/requests/{id}/receipts"), Some(&test), Some(json!({ "receipt": "zip311_test_valid" })), None).await;
    call(&app, "POST", &format!("/v1/test_clocks/{cid}/advance"), Some(&test), Some(json!({ "blocks": 3 })), None).await;
    // Roll back past the payment's block.
    let (s, v, _) = call(&app, "POST", &format!("/v1/test_clocks/{cid}/reorg"), Some(&test), Some(json!({ "depth": 4 })), None).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["fired"][0]["type"], "request.payment_reorged");
    let (_, req, _) = call(&app, "GET", &format!("/v1/requests/{id}"), Some(&test), None, None).await;
    assert!(req["payments"][0]["mined_height"].is_null());
    // Unconfirmed payments never become final, however far the clock moves without a block…
    let (_, v, _) = call(&app, "POST", &format!("/v1/test_clocks/{cid}/advance"), Some(&test), Some(json!({ "seconds": 99999 })), None).await;
    assert!(v["fired"].as_array().unwrap().is_empty());
    // …and once re-mined, they need 10 fresh confirmations.
    call(&app, "POST", &format!("/v1/test_clocks/{cid}/advance"), Some(&test), Some(json!({ "blocks": 1 })), None).await;
    let (_, v, _) = call(&app, "POST", &format!("/v1/test_clocks/{cid}/advance"), Some(&test), Some(json!({ "blocks": 8 })), None).await;
    assert!(v["fired"].as_array().unwrap().is_empty(), "{v}");
    let (_, v, _) = call(&app, "POST", &format!("/v1/test_clocks/{cid}/advance"), Some(&test), Some(json!({ "blocks": 1 })), None).await;
    assert_eq!(v["fired"][0]["type"], "request.final", "{v}");
    // A final payment is not affected by a reorg.
    let (_, v, _) = call(&app, "POST", &format!("/v1/test_clocks/{cid}/reorg"), Some(&test), Some(json!({ "depth": 20 })), None).await;
    assert!(v["fired"].as_array().unwrap().is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn concurrent_submissions_settle_once() {
    let (app, test, _) = app().await;
    let (_, r, _) = call(&app, "POST", "/v1/requests", Some(&test), Some(json!({ "payee": PAYEE, "amount_zatoshis": 1000000 })), None).await;
    let id = r["id"].as_str().unwrap().to_string();
    let mut tasks = Vec::new();
    for _ in 0..8 {
        let (app, test, id) = (app.clone(), test.clone(), id.clone());
        tasks.push(tokio::spawn(async move {
            call(&app, "POST", &format!("/v1/requests/{id}/receipts"), Some(&test), Some(json!({ "receipt": "zip311_test_valid" })), None).await.0
        }));
    }
    let mut ok = 0;
    for t in tasks {
        if t.await.unwrap() == StatusCode::OK {
            ok += 1;
        }
    }
    assert_eq!(ok, 1, "exactly one submission may settle a single request");
    let (_, req, _) = call(&app, "GET", &format!("/v1/requests/{id}"), Some(&test), None, None).await;
    assert_eq!(req["payments"].as_array().unwrap().len(), 1);

    // Partial: every recorded payment counts.
    let (_, p, _) = call(&app, "POST", "/v1/requests", Some(&test), Some(json!({ "payee": PAYEE, "amount_zatoshis": 1000000, "kind": "partial" })), None).await;
    let pid = p["id"].as_str().unwrap().to_string();
    let mut tasks = Vec::new();
    for _ in 0..8 {
        let (app, test, pid) = (app.clone(), test.clone(), pid.clone());
        tasks.push(tokio::spawn(async move {
            call(&app, "POST", &format!("/v1/requests/{pid}/receipts"), Some(&test), Some(json!({ "receipt": "zip311_test_partial" })), None).await
        }));
    }
    for t in tasks {
        t.await.unwrap();
    }
    let (_, p, _) = call(&app, "GET", &format!("/v1/requests/{pid}"), Some(&test), None, None).await;
    let sum: i64 = p["payments"].as_array().unwrap().iter().map(|x| x["zatoshis"].as_i64().unwrap()).sum();
    assert_eq!(p["received_zatoshis"].as_i64().unwrap(), sum, "{p}");
}

#[tokio::test]
async fn second_qa_pass_regressions() {
    let (app, test, live) = app().await;
    // Made-up auth headers don't open fresh public buckets.
    let (_, r, _) = call(&app, "POST", "/v1/requests", Some(&test), Some(json!({ "payee": PAYEE, "kind": "campaign" })), None).await;
    let id = r["id"].as_str().unwrap();
    let mut last = StatusCode::OK;
    for i in 0..(receipts_server::PUBLIC_SUBMIT_LIMIT + 2) {
        let path = if i % 2 == 0 { format!("/v1/public/requests/{id}/receipts") } else { format!("/v1/public/requests/%70{}/receipts", &id[1..]) };
        let req = Request::builder()
            .method("POST")
            .uri(path)
            .header("x-api-key", format!("junk{i}"))
            .header("content-type", "application/json")
            .body(Body::from(json!({ "receipt": "zip311r1AAAA" }).to_string()))
            .unwrap();
        last = app.clone().oneshot(req).await.unwrap().status();
    }
    assert_eq!(last, StatusCode::TOO_MANY_REQUESTS);
    // More webhook guard cases.
    for bad in [
        "https://localhost./h",
        "https://foo.localhost./h",
        "https://metadata.google.internal./x",
        "https://[::127.0.0.1]/",
        "https://[64:ff9b::7f00:1]/",
        "https://[2002:7f00:1::]/",
        "https://[fec0::1]/",
        "https://0.1.2.3/",
        "https://224.0.0.1/",
        "https://198.18.0.1/",
    ] {
        let (s, v, _) = call(&app, "POST", "/v1/webhook_endpoints", Some(&live), Some(json!({ "url": bad })), None).await;
        assert_eq!((s, v["error"]["code"].as_str()), (StatusCode::BAD_REQUEST, Some("webhook_url_not_allowed")), "{bad}");
    }
    // Input caps.
    for body in [
        json!({ "payee": PAYEE, "amount_zatoshis": u64::MAX }),
        json!({ "payee": PAYEE, "expires_in": i64::MAX }),
        json!({ "payee": PAYEE, "metadata": (0..60).map(|i| (format!("k{i}"), json!(i))).collect::<serde_json::Map<_, _>>() }),
    ] {
        let (s, _, _) = call(&app, "POST", "/v1/requests", Some(&test), Some(body.clone()), None).await;
        assert_eq!(s, StatusCode::BAD_REQUEST, "{body}");
    }
    // Attestations: sandbox-marked, deduplicated disclosures.
    let (_, r, _) = call(&app, "POST", "/v1/requests", Some(&test), Some(json!({ "payee": PAYEE, "amount_zatoshis": 1234567 })), None).await;
    let rid = r["id"].as_str().unwrap();
    call(&app, "POST", &format!("/v1/requests/{rid}/receipts"), Some(&test), Some(json!({ "receipt": "zip311_test_valid" })), None).await;
    let (_, a, _) = call(&app, "POST", &format!("/v1/requests/{rid}/attestations"), Some(&test), Some(json!({ "disclose": ["txid", "txid"] })), None).await;
    assert_eq!(a["claims"]["sandbox"], true);
    assert_eq!(a["claims"]["paid_at_least_zatoshis"], 1000000, "default floor is rounded down");
    let (s, _, _) = call(&app, "POST", "/v1/attestations/verify", Some(&test), Some(json!({ "attestation": a["presentation"] })), None).await;
    assert_eq!(s, StatusCode::OK);
    // Secrets hidden behind JSON escapes are still refused.
    let escaped = format!("{{\"payee\":\"{PAYEE}\",\"label\":\"\\u0075view1{}\"}}", "q".repeat(60));
    let req = Request::builder().method("POST").uri("/v1/requests").header("authorization", format!("Bearer {test}")).body(Body::from(escaped)).unwrap();
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    // Events page with a cursor.
    let (_, page1, _) = call(&app, "GET", "/v1/events?limit=2", Some(&test), None, None).await;
    let last_id = page1["data"][1]["id"].as_str().unwrap();
    let (_, page2, _) = call(&app, "GET", &format!("/v1/events?limit=2&starting_after={last_id}"), Some(&test), None, None).await;
    assert_ne!(page2["data"][0]["id"], page1["data"][0]["id"]);
    assert_ne!(page2["data"][0]["id"], page1["data"][1]["id"]);
    // Sign-in domains must look like host names.
    for d in [":::", "-", "a..b", "-x.com"] {
        let (s, _, _) = call(&app, "POST", "/v1/sign_in/challenges", Some(&test), Some(json!({ "domain": d })), None).await;
        assert_eq!(s, StatusCode::BAD_REQUEST, "{d}");
    }
}

#[tokio::test]
async fn built_in_verifier_and_landing_page() {
    let (app, _, _) = app().await;
    let get = |path: &'static str| {
        let app = app.clone();
        async move {
            let res = app.oneshot(Request::builder().uri(path).body(Body::empty()).unwrap()).await.unwrap();
            let ct = res.headers().get("content-type").map(|v| v.to_str().unwrap().to_string()).unwrap_or_default();
            let status = res.status();
            let bytes = res.into_body().collect().await.unwrap().to_bytes();
            (status, ct, bytes.len(), String::from_utf8_lossy(&bytes[..bytes.len().min(8000)]).into_owned())
        }
    };
    let (s, ct, _, body) = get("/").await;
    assert!(s == StatusCode::OK && ct.starts_with("text/html") && body.contains("Prove one Zcash payment"), "{body}");
    assert_eq!(get("/verify").await.0, StatusCode::PERMANENT_REDIRECT);
    let (s, ct, _, _) = get("/verify/").await;
    assert!(s == StatusCode::OK && ct.starts_with("text/html"));
    let (s, ct, n, _) = get("/verify/zcash-receipts/pkg/receipts_wasm_bg.wasm").await;
    assert!(s == StatusCode::OK && ct == "application/wasm" && n > 1_000_000);
    assert_eq!(get("/verify/app.js").await.1, "text/javascript");
    for bad in ["/verify/../Cargo.toml", "/verify/%2e%2e/x", "/verify/nope.js"] {
        assert_eq!(get(bad).await.0, StatusCode::NOT_FOUND, "{bad}");
    }
    for doc in ["/docs/THREAT-MODEL.md", "/docs/COMPARISON.md", "/docs/ZIP311-TODOS.md", "/docs/guides/http-402.md"] {
        assert_eq!(get(doc).await.0, StatusCode::OK, "{doc}");
    }
}

/// Deposit desks: policy validation, a receipt without source proofs refused with a clear code,
/// review only for held deposits, and the public view says what's required (not the list).
#[tokio::test]
async fn deposit_desk_policy() {
    let (app, test, _) = app().await;
    let mk = |sof: Value, kind: &str| json!({ "payee": PAYEE, "amount_zatoshis": 10_000, "kind": kind, "source_of_funds": sof });
    let (s, v, _) =
        call(&app, "POST", "/v1/requests", Some(&test), Some(mk(json!({ "required": true, "blocked_addresses": ["not-an-address"] }), "single")), None).await;
    assert_eq!((s, v["error"]["param"].as_str()), (StatusCode::BAD_REQUEST, Some("source_of_funds")), "{v}");
    let (s, _, _) = call(
        &app,
        "POST",
        "/v1/requests",
        Some(&test),
        Some(mk(json!({ "required": true, "blocked_addresses": ["t1Hsc1LR8yKnbbe3twRp88p6vFfC5t7DLbs"] }), "single")),
        None,
    )
    .await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "a mainnet address on a testnet key");
    let (s, _, _) = call(&app, "POST", "/v1/requests", Some(&test), Some(mk(json!({ "required": true }), "campaign")), None).await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "campaigns can't require a source");
    let (s, _, _) = call(&app, "POST", "/v1/requests", Some(&test), Some(mk(json!({ "required": false }), "single")), None).await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    let (s, r, _) = call(
        &app,
        "POST",
        "/v1/requests",
        Some(&test),
        Some(mk(json!({ "required": true, "blocked_addresses": ["tmGys6dBuEGjch5LFnhdo5gpSa7jiNRWse6"] }), "single")),
        None,
    )
    .await;
    assert_eq!(s, StatusCode::CREATED, "{r}");
    assert_eq!(r["source_of_funds"], json!({ "required": true, "screened_addresses": 1 }));
    assert!(r["cli_command"].as_str().unwrap().contains("--prove-source"));
    let id = r["id"].as_str().unwrap();
    let secret = r["client_secret"].as_str().unwrap();
    let (_, p, _) = call(&app, "GET", &format!("/v1/public/requests/{id}?secret={secret}"), None, None, None).await;
    assert_eq!(p["source_of_funds"]["required"], true);
    assert!(!p.to_string().contains("tmGys6"), "the public view must not show the screening list");
    // A sandbox receipt proves no source: refused, and the request stays open.
    let (s, e, _) = call(&app, "POST", &format!("/v1/requests/{id}/receipts"), Some(&test), Some(json!({ "receipt": "zip311_test_valid" })), None).await;
    assert_eq!((s, e["error"]["code"].as_str()), (StatusCode::UNPROCESSABLE_ENTITY, Some("source_of_funds_required")), "{e}");
    let (_, r2, _) = call(&app, "GET", &format!("/v1/requests/{id}"), Some(&test), None, None).await;
    assert_eq!(r2["status"], "open");
    // Review is only for held deposits.
    let (s, e, _) = call(&app, "POST", &format!("/v1/requests/{id}/review"), Some(&test), Some(json!({ "decision": "accept" })), None).await;
    assert_eq!((s, e["error"]["code"].as_str()), (StatusCode::CONFLICT, Some("not_held_for_review")));
    let (s, _, _) = call(&app, "POST", &format!("/v1/requests/{id}/review"), Some(&test), Some(json!({ "decision": "maybe" })), None).await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
}
