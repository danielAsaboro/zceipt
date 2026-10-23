//! Rust client for the Receipts API.
//!
//! ```no_run
//! # async fn run() -> Result<(), receipts_client::Error> {
//! use receipts_client::{Client, CreateRequest};
//! let client = Client::new("rcpt_test_…").base_url("http://127.0.0.1:8723");
//! let req = client.create_request(&CreateRequest { payee: "utest1…".into(), amount_zatoshis: Some(1_000_000), ..Default::default() }).await?;
//! println!("{}", req["receipt_link"]);
//! # Ok(()) }
//! ```
//!
//! Responses are `serde_json::Value`s shaped as in the OpenAPI document. Errors carry the
//! API's stable `code`. Network errors, 429 and 5xx are retried, and every POST carries an
//! Idempotency-Key.

use serde::Serialize;
use serde_json::{json, Value};
use std::time::Duration;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// 401: missing or unknown key.
    #[error("authentication error ({code}): {message}")]
    Authentication { code: String, message: String },
    /// 400/404/409.
    #[error("invalid request ({code}): {message}")]
    InvalidRequest { status: u16, code: String, message: String, param: Option<String> },
    /// 422: the receipt does not prove what is required.
    #[error("verification failed ({code}): {message}")]
    Verification { code: String, message: String },
    /// 5xx.
    #[error("api error ({code}): {message}")]
    Api { status: u16, code: String, message: String },
    #[error("connection failed: {0}")]
    Connection(#[from] reqwest::Error),
}

impl Error {
    /// The API's machine-readable error code, if any.
    pub fn code(&self) -> Option<&str> {
        match self {
            Error::Authentication { code, .. } | Error::InvalidRequest { code, .. } | Error::Verification { code, .. } | Error::Api { code, .. } => Some(code),
            Error::Connection(_) => None,
        }
    }
}

#[derive(Serialize, Default, Clone)]
pub struct CreateRequest {
    pub payee: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub amount_zatoshis: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_in: Option<i64>,
    /// "single" (default), "partial" or "campaign".
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    /// Sandbox: run the request on this test clock.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub test_clock: Option<String>,
    /// Deposit desks: `{"required": true, "blocked_addresses": [...]}`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_of_funds: Option<Value>,
}

#[derive(Serialize, Default, Clone)]
pub struct VerifyParams {
    pub receipt: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expect_address: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub min_zatoshis: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub challenge: Option<String>,
}

#[derive(Clone)]
pub struct Client {
    key: String,
    base: String,
    http: reqwest::Client,
    max_retries: u32,
}

fn random_key() -> String {
    let mut b = [0u8; 16];
    getrandom::fill(&mut b).expect("OS RNG");
    hex::encode(b)
}

impl Client {
    pub fn new(api_key: impl Into<String>) -> Self {
        Self {
            key: api_key.into(),
            base: "http://127.0.0.1:8723".into(),
            http: reqwest::Client::builder().timeout(Duration::from_secs(60)).build().expect("client"),
            max_retries: 2,
        }
    }
    pub fn base_url(mut self, url: impl Into<String>) -> Self {
        self.base = url.into().trim_end_matches('/').to_string();
        self
    }
    pub fn max_retries(mut self, n: u32) -> Self {
        self.max_retries = n;
        self
    }

    async fn call(&self, method: reqwest::Method, path: &str, body: Option<Value>, idem: Option<&str>) -> Result<Value, Error> {
        let idem = match (&method, idem) {
            (&reqwest::Method::POST, Some(k)) => Some(k.to_string()),
            (&reqwest::Method::POST, None) => Some(random_key()),
            _ => None,
        };
        let mut attempt = 0;
        loop {
            let mut rb =
                self.http.request(method.clone(), format!("{}{path}", self.base)).bearer_auth(&self.key).header("user-agent", "zcash-receipts-rust/0.1");
            if let Some(k) = &idem {
                rb = rb.header("idempotency-key", k);
            }
            if let Some(b) = &body {
                rb = rb.json(b);
            }
            let res = match rb.send().await {
                Ok(r) => r,
                Err(e) if attempt < self.max_retries => {
                    let _ = e;
                    tokio::time::sleep(Duration::from_millis(500 << attempt)).await;
                    attempt += 1;
                    continue;
                }
                Err(e) => return Err(Error::Connection(e)),
            };
            let status = res.status().as_u16();
            let v: Value = res.json().await.unwrap_or(json!({}));
            if (200..300).contains(&status) {
                return Ok(v);
            }
            if (status == 429 || status >= 500) && attempt < self.max_retries {
                tokio::time::sleep(Duration::from_millis(500 << attempt)).await;
                attempt += 1;
                continue;
            }
            let e = &v["error"];
            let code = e["code"].as_str().unwrap_or("unknown").to_string();
            let message = e["message"].as_str().unwrap_or("").to_string();
            return Err(match status {
                401 => Error::Authentication { code, message },
                422 => Error::Verification { code, message },
                s if s >= 500 => Error::Api { status: s, code, message },
                s => Error::InvalidRequest { status: s, code, message, param: e["param"].as_str().map(str::to_string) },
            });
        }
    }

    pub async fn verify(&self, p: &VerifyParams) -> Result<Value, Error> {
        self.call(reqwest::Method::POST, "/v1/verify", Some(serde_json::to_value(p).unwrap()), None).await
    }
    pub async fn create_request(&self, p: &CreateRequest) -> Result<Value, Error> {
        self.call(reqwest::Method::POST, "/v1/requests", Some(serde_json::to_value(p).unwrap()), None).await
    }
    pub async fn create_request_idempotent(&self, p: &CreateRequest, idempotency_key: &str) -> Result<Value, Error> {
        self.call(reqwest::Method::POST, "/v1/requests", Some(serde_json::to_value(p).unwrap()), Some(idempotency_key)).await
    }
    pub async fn get_request(&self, id: &str) -> Result<Value, Error> {
        self.call(reqwest::Method::GET, &format!("/v1/requests/{id}"), None, None).await
    }
    pub async fn list_requests(&self, status: Option<&str>, limit: Option<u32>) -> Result<Value, Error> {
        let mut q = vec![];
        if let Some(s) = status {
            q.push(format!("status={s}"));
        }
        if let Some(l) = limit {
            q.push(format!("limit={l}"));
        }
        let qs = if q.is_empty() { String::new() } else { format!("?{}", q.join("&")) };
        self.call(reqwest::Method::GET, &format!("/v1/requests{qs}"), None, None).await
    }
    pub async fn submit_receipt(&self, id: &str, receipt: &str) -> Result<Value, Error> {
        self.call(reqwest::Method::POST, &format!("/v1/requests/{id}/receipts"), Some(json!({ "receipt": receipt })), None).await
    }
    /// Deposit desks: accept or reject a deposit held for review (`decision`: "accept" or "reject").
    pub async fn review_deposit(&self, id: &str, decision: &str, note: Option<&str>) -> Result<Value, Error> {
        let mut b = json!({ "decision": decision });
        if let Some(n) = note {
            b["note"] = n.into();
        }
        self.call(reqwest::Method::POST, &format!("/v1/requests/{id}/review"), Some(b), None).await
    }
    /// Refund a payment to the address the payer signed into their receipt (`--refund-to`).
    /// `amount_zatoshis: None` refunds what is left of the latest such payment.
    pub async fn create_refund(&self, request_id: &str, amount_zatoshis: Option<u64>, reason: Option<&str>) -> Result<Value, Error> {
        let mut b = json!({});
        if let Some(a) = amount_zatoshis {
            b["amount_zatoshis"] = a.into();
        }
        if let Some(r) = reason {
            b["reason"] = r.into();
        }
        self.call(reqwest::Method::POST, &format!("/v1/requests/{request_id}/refunds"), Some(b), None).await
    }
    pub async fn get_refund(&self, id: &str) -> Result<Value, Error> {
        self.call(reqwest::Method::GET, &format!("/v1/refunds/{id}"), None, None).await
    }
    /// Settle a refund with the receipt for the refund payment (signing the refund's challenge).
    pub async fn submit_refund_receipt(&self, id: &str, receipt: &str) -> Result<Value, Error> {
        self.call(reqwest::Method::POST, &format!("/v1/refunds/{id}/receipts"), Some(json!({ "receipt": receipt })), None).await
    }
    /// A signed, minimal statement about a fulfilled request (SD-JWT); see the attestations guide.
    pub async fn create_attestation(&self, request_id: &str, at_least_zatoshis: Option<u64>, before: Option<&str>, disclose: &[&str]) -> Result<Value, Error> {
        let mut b = json!({ "disclose": disclose });
        if let Some(a) = at_least_zatoshis {
            b["at_least_zatoshis"] = a.into();
        }
        if let Some(d) = before {
            b["before"] = d.into();
        }
        self.call(reqwest::Method::POST, &format!("/v1/requests/{request_id}/attestations"), Some(b), None).await
    }
    pub async fn verify_attestation(&self, attestation: &str) -> Result<Value, Error> {
        self.call(reqwest::Method::POST, "/v1/attestations/verify", Some(json!({ "attestation": attestation })), None).await
    }
    /// Sandbox: a test clock (frozen time and block height) that requests can run on.
    pub async fn create_test_clock(&self, height: Option<u64>) -> Result<Value, Error> {
        let b = height.map(|h| json!({ "height": h })).unwrap_or(json!({}));
        self.call(reqwest::Method::POST, "/v1/test_clocks", Some(b), None).await
    }
    /// Moves a test clock; the response lists the events that fired.
    pub async fn advance_test_clock(&self, id: &str, seconds: Option<u64>, blocks: Option<u64>) -> Result<Value, Error> {
        let mut b = json!({});
        if let Some(s) = seconds {
            b["seconds"] = s.into();
        }
        if let Some(n) = blocks {
            b["blocks"] = n.into();
        }
        self.call(reqwest::Method::POST, &format!("/v1/test_clocks/{id}/advance"), Some(b), None).await
    }
    /// Rolls a test clock's chain back `depth` blocks; unconfirmed payments fire `request.payment_reorged`.
    pub async fn reorg_test_clock(&self, id: &str, depth: u32) -> Result<Value, Error> {
        self.call(reqwest::Method::POST, &format!("/v1/test_clocks/{id}/reorg"), Some(json!({ "depth": depth })), None).await
    }
    /// Sign in with Zcash: a single-use nonce for `domain` (default: the API's host).
    pub async fn create_sign_in_challenge(&self, domain: Option<&str>) -> Result<Value, Error> {
        let b = domain.map(|d| json!({ "domain": d })).unwrap_or(json!({}));
        self.call(reqwest::Method::POST, "/v1/sign_in/challenges", Some(b), None).await
    }
    /// Checks a `zsig1…` sign-in once and returns the proven address.
    pub async fn verify_sign_in(&self, sign_in: &str) -> Result<Value, Error> {
        self.call(reqwest::Method::POST, "/v1/sign_in/verify", Some(json!({ "sign_in": sign_in })), None).await
    }
    pub async fn create_webhook_endpoint(&self, url: &str, events: Option<&[&str]>) -> Result<Value, Error> {
        let mut b = json!({ "url": url });
        if let Some(e) = events {
            b["events"] = json!(e);
        }
        self.call(reqwest::Method::POST, "/v1/webhook_endpoints", Some(b), None).await
    }
    pub async fn list_webhook_endpoints(&self) -> Result<Value, Error> {
        self.call(reqwest::Method::GET, "/v1/webhook_endpoints", None, None).await
    }
    pub async fn delete_webhook_endpoint(&self, id: &str) -> Result<Value, Error> {
        self.call(reqwest::Method::DELETE, &format!("/v1/webhook_endpoints/{id}"), None, None).await
    }
    pub async fn resend_event(&self, id: &str) -> Result<Value, Error> {
        self.call(reqwest::Method::POST, &format!("/v1/events/{id}/resend"), Some(json!({})), None).await
    }
    pub async fn list_deliveries(&self, limit: Option<u32>) -> Result<Value, Error> {
        let qs = limit.map(|l| format!("?limit={l}")).unwrap_or_default();
        self.call(reqwest::Method::GET, &format!("/v1/deliveries{qs}"), None, None).await
    }
    pub async fn get_test_clock(&self, id: &str) -> Result<Value, Error> {
        self.call(reqwest::Method::GET, &format!("/v1/test_clocks/{id}"), None, None).await
    }
    /// Lints a ZIP-321 payment link (`network`: mainnet, testnet or regtest).
    pub async fn check_payment_link(&self, uri: &str, network: Option<&str>) -> Result<Value, Error> {
        let mut b = json!({ "uri": uri });
        if let Some(n) = network {
            b["network"] = n.into();
        }
        self.call(reqwest::Method::POST, "/v1/payment_links/check", Some(b), None).await
    }
    pub async fn jwks(&self) -> Result<Value, Error> {
        self.call(reqwest::Method::GET, "/.well-known/jwks.json", None, None).await
    }
    pub async fn sandbox_fixtures(&self) -> Result<Value, Error> {
        self.call(reqwest::Method::GET, "/v1/sandbox/fixtures", None, None).await
    }
    pub async fn list_errors(&self) -> Result<Value, Error> {
        self.call(reqwest::Method::GET, "/v1/errors", None, None).await
    }
    pub async fn health(&self) -> Result<Value, Error> {
        self.call(reqwest::Method::GET, "/v1/health", None, None).await
    }
    /// The request's ZIP-321 payment URI as an SVG QR code.
    pub async fn request_qr(&self, id: &str) -> Result<String, Error> {
        let res = self.http.get(format!("{}/v1/requests/{id}/qr.svg", self.base)).bearer_auth(&self.key).send().await.map_err(Error::Connection)?;
        let status = res.status().as_u16();
        let text = res.text().await.map_err(Error::Connection)?;
        if (200..300).contains(&status) {
            Ok(text)
        } else {
            Err(Error::InvalidRequest { status, code: "request_not_found".into(), message: text, param: None })
        }
    }
    /// Hosted pages' endpoints (no API key needed; a per-request client secret).
    pub async fn public_get_request(&self, id: &str, secret: &str) -> Result<Value, Error> {
        self.call(reqwest::Method::GET, &format!("/v1/public/requests/{id}?secret={secret}"), None, None).await
    }
    pub async fn public_submit_receipt(&self, id: &str, receipt: &str, client_secret: Option<&str>) -> Result<Value, Error> {
        let mut b = json!({ "receipt": receipt });
        if let Some(s) = client_secret {
            b["client_secret"] = s.into();
        }
        self.call(reqwest::Method::POST, &format!("/v1/public/requests/{id}/receipts"), Some(b), None).await
    }
    pub async fn public_campaign(&self, id: &str) -> Result<Value, Error> {
        self.call(reqwest::Method::GET, &format!("/v1/public/campaigns/{id}"), None, None).await
    }
    pub async fn list_events(&self, limit: Option<u32>) -> Result<Value, Error> {
        let qs = limit.map(|l| format!("?limit={l}")).unwrap_or_default();
        self.call(reqwest::Method::GET, &format!("/v1/events{qs}"), None, None).await
    }
}

/// Webhook signature verification.
pub mod webhooks {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;

    #[derive(Debug, thiserror::Error, PartialEq, Eq)]
    pub enum SignatureError {
        #[error("missing or malformed Receipts-Signature header")]
        Malformed,
        #[error("timestamp outside the tolerance window")]
        Stale,
        #[error("signature does not match")]
        Mismatch,
        #[error("body is not JSON")]
        BadBody,
    }

    pub fn sign(raw_body: &str, secret: &str, t: i64) -> String {
        let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).unwrap();
        mac.update(format!("{t}.{raw_body}").as_bytes());
        format!("t={t},v1={}", hex::encode(mac.finalize().into_bytes()))
    }

    /// Verifies a delivery and returns the parsed event. Pass the raw body.
    pub fn construct_event(raw_body: &str, header: &str, secret: &str, tolerance_secs: i64) -> Result<serde_json::Value, SignatureError> {
        let mut t = None;
        let mut v1 = None;
        for p in header.split(',') {
            match p.split_once('=') {
                Some(("t", x)) => t = x.parse::<i64>().ok(),
                Some(("v1", x)) => v1 = hex::decode(x).ok(),
                _ => {}
            }
        }
        let (t, v1) = (t.ok_or(SignatureError::Malformed)?, v1.ok_or(SignatureError::Malformed)?);
        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64;
        if (now - t).abs() > tolerance_secs {
            return Err(SignatureError::Stale);
        }
        let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).unwrap();
        mac.update(format!("{t}.{raw_body}").as_bytes());
        mac.verify_slice(&v1).map_err(|_| SignatureError::Mismatch)?;
        serde_json::from_str(raw_body).map_err(|_| SignatureError::BadBody)
    }
}
