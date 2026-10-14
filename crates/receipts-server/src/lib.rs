//! Receipts API: a self-hostable REST service for Zcash payment receipts.
//!
//! - `POST /v1/verify`: verify a receipt or a batch, optionally against a payee, an amount
//!   and a challenge.
//! - `POST /v1/requests`: ask someone to prove a payment. Returns a ZIP-321 payment URI,
//!   a verifier link and the CLI command to answer it.
//! - `POST /v1/requests/{id}/receipts`: submit the receipt that answers a request. On success
//!   the request becomes `fulfilled` and a signed `request.fulfilled` webhook is sent.
//! - `GET /v1/requests`, `GET /v1/requests/{id}`, `/v1/webhook_endpoints`, `/v1/events`.
//!
//! Keys work like Stripe's: `rcpt_test_…` serves testnet (or a local regtest chain) and
//! `rcpt_live_…` serves mainnet. The two modes never see each other's objects. Every
//! creating `POST` accepts an `Idempotency-Key` header.

pub mod db;
pub mod error;
pub mod sandbox;
pub mod verify;
pub mod webhooks;

use axum::{
    extract::{FromRequestParts, Path, Query, State},
    http::{request::Parts, HeaderMap, StatusCode},
    response::{Html, IntoResponse, Response},
    routing::{delete, get, post},
    Json, Router,
};
use db::{new_id, now, Db};
use error::ApiError;
use receipts_chain::{chain, Net};
use rusqlite::{params, OptionalExtension};
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use zcash_address::unified::{self, Encoding};
use zcash_protocol::consensus::{NetworkType, Parameters};

#[derive(Clone)]
pub struct Config {
    /// Network for `rcpt_test_` keys: testnet, or a local regtest chain.
    pub test_net: Net,
    pub test_lightwalletd: Option<String>,
    pub live_lightwalletd: Option<String>,
    /// Base URL of the verifier page, for the links in proof requests.
    pub verifier_url: String,
    /// Webhook retry schedule: first retry after this many seconds, doubling, capped at 1 h.
    pub webhook_backoff_secs: i64,
    /// Attempts before a delivery is marked `failed`.
    pub webhook_max_attempts: i64,
}

impl Config {
    /// Defaults: testnet for test keys, public lightwalletd servers, 10 s → 1 h backoff, 8 attempts.
    pub fn new(test_net: Net, verifier_url: impl Into<String>) -> Self {
        Config {
            test_net,
            test_lightwalletd: None,
            live_lightwalletd: None,
            verifier_url: verifier_url.into(),
            webhook_backoff_secs: 10,
            webhook_max_attempts: webhooks::MAX_ATTEMPTS,
        }
    }
}

pub struct AppState {
    pub db: Db,
    pub config: Config,
    pub http: reqwest::Client,
    /// Fixed-window request counters per API key: (window start, count).
    pub rate: std::sync::Mutex<std::collections::HashMap<String, (i64, u32)>>,
}

/// The API version this server speaks. Clients may pin it with a `Receipts-Version` header.
pub const API_VERSION: &str = "2026-10-14";
/// Requests allowed per key per minute.
pub const RATE_LIMIT: u32 = 300;

async fn api_middleware(State(st): State<Shared>, req: axum::extract::Request, next: axum::middleware::Next) -> Response {
    if let Some(v) = req.headers().get("receipts-version").and_then(|v| v.to_str().ok()) {
        if v != API_VERSION {
            return ApiError::invalid("api_version_unsupported", format!("this server speaks Receipts-Version {API_VERSION}, not {v}")).into_response();
        }
    }
    let key = req
        .headers()
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .map(str::to_string)
        .or_else(|| req.headers().get("x-api-key").and_then(|v| v.to_str().ok()).map(str::to_string));
    let mut remaining = None;
    if let Some(k) = key {
        let t = now();
        let window = t - t % 60;
        let mut m = st.rate.lock().unwrap();
        let e = m.entry(k).or_insert((window, 0));
        if e.0 != window {
            *e = (window, 0);
        }
        e.1 += 1;
        if e.1 > RATE_LIMIT {
            let mut res = ApiError::new_rate_limited().into_response();
            res.headers_mut().insert("retry-after", (window + 60 - t).to_string().parse().unwrap());
            return res;
        }
        remaining = Some(RATE_LIMIT - e.1);
    }
    let mut res = next.run(req).await;
    let h = res.headers_mut();
    h.insert("receipts-version", API_VERSION.parse().unwrap());
    if let Some(r) = remaining {
        h.insert("ratelimit-limit", RATE_LIMIT.to_string().parse().unwrap());
        h.insert("ratelimit-remaining", r.to_string().parse().unwrap());
    }
    res
}

pub type Shared = Arc<AppState>;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Mode {
    Test,
    Live,
}

impl Mode {
    fn as_str(self) -> &'static str {
        match self {
            Mode::Test => "test",
            Mode::Live => "live",
        }
    }
    fn net(self, c: &Config) -> Net {
        match self {
            Mode::Test => c.test_net,
            Mode::Live => Net::Main,
        }
    }
    fn server(self, c: &Config) -> Option<String> {
        match self {
            Mode::Test => c.test_lightwalletd.clone(),
            Mode::Live => c.live_lightwalletd.clone(),
        }
    }
}

/// The authenticated caller: their key and its mode.
pub struct Auth {
    pub key: String,
    pub mode: Mode,
}

impl FromRequestParts<Shared> for Auth {
    type Rejection = ApiError;
    async fn from_request_parts(parts: &mut Parts, state: &Shared) -> Result<Self, ApiError> {
        let h = &parts.headers;
        let key = h
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .or_else(|| h.get("x-api-key").and_then(|v| v.to_str().ok()))
            .map(|s| s.trim().to_string())
            .ok_or_else(|| ApiError::auth("missing_api_key", "send `Authorization: Bearer rcpt_test_…`"))?;
        let mode = match state.db.mode_for_key(&key)?.as_deref() {
            Some("test") => Mode::Test,
            Some("live") => Mode::Live,
            _ => return Err(ApiError::auth("invalid_api_key", "unknown or revoked API key")),
        };
        Ok(Auth { key, mode })
    }
}

/// JSON body extractor whose rejections use the API's error shape.
pub struct Body<T>(pub T, pub String);

impl<T: serde::de::DeserializeOwned> axum::extract::FromRequest<Shared> for Body<T> {
    type Rejection = ApiError;
    async fn from_request(req: axum::extract::Request, _: &Shared) -> Result<Self, ApiError> {
        let bytes = axum::body::to_bytes(req.into_body(), 1 << 20)
            .await
            .map_err(|_| ApiError::invalid("invalid_json", "body too large or unreadable"))?;
        let raw = String::from_utf8_lossy(&bytes).into_owned();
        let v = serde_json::from_slice(if bytes.is_empty() { b"{}" } else { &bytes })
            .map_err(|e| ApiError::invalid("invalid_json", e.to_string()))?;
        Ok(Body(v, raw))
    }
}

// ---------- idempotency ----------

fn body_hash(s: &str) -> String {
    hex::encode(Sha256::digest(s.as_bytes()))
}

/// Returns a stored response for a replayed `Idempotency-Key`, or an error if the key was
/// used with a different body.
fn idem_lookup(st: &AppState, auth: &Auth, headers: &HeaderMap, route: &str, raw: &str) -> Result<Option<Response>, ApiError> {
    let Some(k) = headers.get("idempotency-key").and_then(|v| v.to_str().ok()) else { return Ok(None) };
    let c = st.db.0.lock().unwrap();
    let row: Option<(String, String, i64, String)> = c
        .query_row(
            "SELECT route, body_hash, status, response FROM idempotency WHERE api_key = ?1 AND idem_key = ?2",
            params![auth.key, k],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
        )
        .optional()?;
    match row {
        None => Ok(None),
        Some((r, h, status, resp)) if r == route && h == body_hash(raw) => {
            let v: Value = serde_json::from_str(&resp).unwrap_or(Value::Null);
            let mut res = (StatusCode::from_u16(status as u16).unwrap_or(StatusCode::OK), Json(v)).into_response();
            res.headers_mut().insert("idempotent-replayed", "true".parse().unwrap());
            Ok(Some(res))
        }
        Some(_) => Err(ApiError::conflict("idempotency_key_reused", "this Idempotency-Key was used with a different request")),
    }
}

fn idem_store(st: &AppState, auth: &Auth, headers: &HeaderMap, route: &str, raw: &str, status: StatusCode, body: &Value) {
    if let Some(k) = headers.get("idempotency-key").and_then(|v| v.to_str().ok()) {
        let c = st.db.0.lock().unwrap();
        let _ = c.execute(
            "INSERT OR IGNORE INTO idempotency (api_key, idem_key, route, body_hash, status, response, created) VALUES (?1,?2,?3,?4,?5,?6,?7)",
            params![auth.key, k, route, body_hash(raw), status.as_u16(), body.to_string(), now()],
        );
    }
}

/// Runs `f` once per Idempotency-Key, storing and replaying its result (successes and
/// verification failures alike, so a retry never changes the answer).
async fn idempotent<F, Fut>(st: &Shared, auth: &Auth, headers: &HeaderMap, route: &str, raw: &str, f: F) -> Response
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = Result<(StatusCode, Value), ApiError>>,
{
    match idem_lookup(st, auth, headers, route, raw) {
        Ok(Some(res)) => return res,
        Err(e) => return e.into_response(),
        Ok(None) => {}
    }
    let (status, body) = match f().await {
        Ok(ok) => ok,
        // Transient failures are not stored, so a retry can succeed.
        Err(e) if e.status.is_server_error() => return e.into_response(),
        Err(e) => (e.status, e.body()),
    };
    idem_store(st, auth, headers, route, raw, status, &body);
    (status, Json(body)).into_response()
}

// ---------- helpers ----------

fn zec(z: u64) -> String {
    let s = format!("{}.{:08}", z / 100_000_000, z % 100_000_000);
    s.trim_end_matches('0').trim_end_matches('.').to_string()
}

fn urlenc(s: &str) -> String {
    s.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => (b as char).to_string(),
            _ => format!("%{b:02X}"),
        })
        .collect()
}

fn check_payee(net: Net, payee: &str) -> Result<(), ApiError> {
    let (nt, _, _) = unified::Address::decode(payee)
        .map_err(|e| ApiError::invalid("parameter_invalid", format!("payee is not a unified address: {e}")).param("payee"))?;
    let want = net.network_type();
    let ok = nt == want || (want == NetworkType::Regtest && nt == NetworkType::Test) || (want == NetworkType::Test && nt == NetworkType::Regtest);
    if !ok {
        return Err(ApiError::invalid("address_network_mismatch", format!("payee is a {nt:?} address but this key serves {}", net.name())).param("payee"));
    }
    chain::orchard_receiver_of(payee).map_err(|e| ApiError::invalid("parameter_invalid", e.to_string()).param("payee"))?;
    Ok(())
}

type RequestRow = (String, String, String, String, Option<i64>, Option<String>, String, String, i64, Option<i64>, Option<i64>, Option<String>, Option<i64>, Option<String>);

const REQUEST_COLS: &str = "id, mode, challenge, payee, amount_zatoshis, label, metadata, status, created, expires_at, fulfilled_at, txid, paid_zatoshis, verification";

fn load_request(st: &AppState, mode: Mode, id: &str) -> Result<RequestRow, ApiError> {
    let c = st.db.0.lock().unwrap();
    c.query_row(&format!("SELECT {REQUEST_COLS} FROM requests WHERE id = ?1 AND mode = ?2"), params![id, mode.as_str()], row_to_request)
        .optional()?
        .ok_or_else(|| ApiError::not_found("request_not_found", format!("no proof request {id}")))
}

fn row_to_request(r: &rusqlite::Row) -> rusqlite::Result<RequestRow> {
    Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?, r.get(6)?, r.get(7)?, r.get(8)?, r.get(9)?, r.get(10)?, r.get(11)?, r.get(12)?, r.get(13)?))
}

fn request_json(st: &AppState, r: &RequestRow) -> Value {
    let (id, mode, challenge, payee, amount, label, metadata, status, created, expires_at, fulfilled_at, txid, paid, verification) = r;
    let status = if status == "open" && expires_at.is_some_and(|e| e <= now()) { "expired" } else { status.as_str() };
    let memo = format!("Receipts request {id}");
    let mut uri = format!("zcash:{payee}?");
    if let Some(a) = amount {
        uri.push_str(&format!("amount={}&", zec(*a as u64)));
    }
    uri.push_str(&format!("memo={}", base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, memo.as_bytes())));
    if let Some(l) = label {
        uri.push_str(&format!("&message={}", urlenc(l)));
    }
    let mut link = format!("{}?request={challenge}&to={}", st.config.verifier_url, urlenc(payee));
    if let Some(a) = amount {
        link.push_str(&format!("&min={a}"));
    }
    if let Some(l) = label {
        link.push_str(&format!("&label={}", urlenc(l)));
    }
    json!({
        "id": id,
        "object": "proof_request",
        "livemode": mode == "live",
        "status": status,
        "challenge": challenge,
        "payee": payee,
        "amount_zatoshis": amount,
        "label": label,
        "metadata": serde_json::from_str::<Value>(metadata).unwrap_or(json!({})),
        "created": created,
        "expires_at": expires_at,
        "payment_uri": uri,
        "receipt_link": link,
        "cli_command": format!("receipts create -w <wallet> -i <key.age> --txid <txid> --request '{link}'"),
        "fulfillment": fulfilled_at.map(|t| json!({
            "fulfilled_at": t,
            "txid": txid,
            "paid_zatoshis": paid,
            "verification": verification.as_deref().and_then(|v| serde_json::from_str::<Value>(v).ok()),
        })),
    })
}

/// Records an event and queues a delivery to every enabled endpoint subscribed to it.
pub fn emit(st: &AppState, mode: Mode, kind: &str, object: Value) -> Result<Value, ApiError> {
    let id = new_id("evt_");
    let ev = json!({ "id": id, "object": "event", "type": kind, "created": now(), "livemode": mode == Mode::Live, "data": { "object": object } });
    let c = st.db.0.lock().unwrap();
    c.execute("INSERT INTO events (id, mode, type, created, body) VALUES (?1,?2,?3,?4,?5)", params![id, mode.as_str(), kind, now(), ev.to_string()])?;
    let endpoints: Vec<(String, String)> = c
        .prepare("SELECT id, events FROM webhook_endpoints WHERE mode = ?1 AND disabled = 0")?
        .query_map([mode.as_str()], |r| Ok((r.get(0)?, r.get(1)?)))?
        .collect::<Result<_, _>>()?;
    for (eid, events) in endpoints {
        let subs: Vec<String> = serde_json::from_str(&events).unwrap_or_default();
        if subs.iter().any(|s| s == "*" || s == kind) {
            c.execute("INSERT INTO deliveries (event_id, endpoint_id, next_attempt_at) VALUES (?1,?2,?3)", params![id, eid, now()])?;
        }
    }
    Ok(ev)
}

// ---------- handlers ----------

#[derive(Deserialize)]
struct VerifyReq {
    receipt: Option<String>,
    expect_address: Option<String>,
    min_zatoshis: Option<u64>,
    challenge: Option<String>,
}

async fn verify_handler(State(st): State<Shared>, auth: Auth, Body(req, _): Body<VerifyReq>) -> Result<Json<Value>, ApiError> {
    let text = req.receipt.ok_or_else(|| ApiError::missing("receipt"))?;
    let net = auth.mode.net(&st.config);
    let server = auth.mode.server(&st.config);
    let v = if sandbox::is_fixture(&text) {
        if auth.mode != Mode::Test {
            return Err(ApiError::invalid("receipt_network_mismatch", "sandbox fixtures only work with rcpt_test_ keys").param("receipt"));
        }
        sandbox::resolve(&text, req.expect_address.as_deref(), req.min_zatoshis, req.challenge.as_deref())?
    } else if text.contains("zrcptb1") {
        return Ok(Json(verify::verify_batch(net, server.as_deref(), &text).await?));
    } else {
        verify::verify_receipt(net, server.as_deref(), &text).await?
    };
    if let Some(c) = &req.challenge {
        if v.challenge.as_deref() != Some(c.as_str()) {
            return Err(ApiError::verification("challenge_mismatch", "the receipt does not sign this challenge"));
        }
    }
    let mut body = serde_json::to_value(&v).unwrap();
    if let Some(addr) = &req.expect_address {
        let paid = verify::paid_to(&v, addr)?;
        if paid == 0 {
            return Err(ApiError::verification("wrong_payee", "no disclosed output paid expect_address"));
        }
        if req.min_zatoshis.is_some_and(|m| paid < m) {
            return Err(ApiError::verification("insufficient_amount", format!("paid {paid} zatoshis, less than {}", req.min_zatoshis.unwrap())));
        }
        body["paid_to_expected"] = paid.into();
    }
    Ok(Json(body))
}

#[derive(Deserialize)]
struct CreateRequest {
    payee: Option<String>,
    amount_zatoshis: Option<u64>,
    label: Option<String>,
    metadata: Option<serde_json::Map<String, Value>>,
    expires_in: Option<i64>,
}

async fn create_request(State(st): State<Shared>, auth: Auth, headers: HeaderMap, Body(req, raw): Body<CreateRequest>) -> Response {
    let st2 = st.clone();
    let mode = auth.mode;
    idempotent(&st, &auth, &headers, "POST /v1/requests", &raw, || async move {
        let payee = req.payee.ok_or_else(|| ApiError::missing("payee"))?;
        check_payee(mode.net(&st2.config), &payee)?;
        if req.label.as_ref().is_some_and(|l| l.len() > 200) {
            return Err(ApiError::invalid("parameter_invalid", "label is longer than 200 characters").param("label"));
        }
        if req.expires_in.is_some_and(|e| e <= 0) {
            return Err(ApiError::invalid("parameter_invalid", "expires_in must be positive (seconds)").param("expires_in"));
        }
        let id = new_id("preq_");
        let mut ch = [0u8; 8];
        getrandom::fill(&mut ch).expect("OS RNG");
        let challenge = hex::encode(ch);
        let created = now();
        let row = {
            let c = st2.db.0.lock().unwrap();
            c.execute(
                "INSERT INTO requests (id, mode, challenge, payee, amount_zatoshis, label, metadata, status, created, expires_at) VALUES (?1,?2,?3,?4,?5,?6,?7,'open',?8,?9)",
                params![id, mode.as_str(), challenge, payee, req.amount_zatoshis.map(|a| a as i64), req.label, Value::Object(req.metadata.unwrap_or_default()).to_string(), created, req.expires_in.map(|e| created + e)],
            )?;
            c.query_row(&format!("SELECT {REQUEST_COLS} FROM requests WHERE id = ?1"), [&id], row_to_request)?
        };
        let obj = request_json(&st2, &row);
        emit(&st2, mode, "request.created", obj.clone())?;
        Ok((StatusCode::CREATED, obj))
    })
    .await
}

#[derive(Deserialize)]
struct ListQuery {
    status: Option<String>,
    limit: Option<u32>,
    starting_after: Option<String>,
}

async fn list_requests(State(st): State<Shared>, auth: Auth, Query(q): Query<ListQuery>) -> Result<Json<Value>, ApiError> {
    let limit = q.limit.unwrap_or(20).clamp(1, 100);
    let rows: Vec<RequestRow> = {
        let c = st.db.0.lock().unwrap();
        let after = match &q.starting_after {
            Some(id) => c.query_row("SELECT created FROM requests WHERE id = ?1", [id], |r| r.get::<_, i64>(0)).optional()?.unwrap_or(i64::MAX),
            None => i64::MAX,
        };
        let mut stmt = c.prepare(&format!("SELECT {REQUEST_COLS} FROM requests WHERE mode = ?1 AND created <= ?2 AND (?3 IS NULL OR id != ?3) ORDER BY created DESC, id DESC LIMIT ?4"))?;
        let rows = stmt.query_map(params![auth.mode.as_str(), after, q.starting_after, limit + 1], row_to_request)?.collect::<Result<Vec<_>, _>>()?;
        rows
    };
    let mut data: Vec<Value> = rows.iter().map(|r| request_json(&st, r)).collect();
    if let Some(s) = &q.status {
        data.retain(|r| r["status"] == s.as_str());
    }
    let has_more = data.len() > limit as usize;
    data.truncate(limit as usize);
    Ok(Json(json!({ "object": "list", "data": data, "has_more": has_more })))
}

async fn get_request(State(st): State<Shared>, auth: Auth, Path(id): Path<String>) -> Result<Json<Value>, ApiError> {
    let row = load_request(&st, auth.mode, &id)?;
    Ok(Json(request_json(&st, &row)))
}

#[derive(Deserialize)]
struct SubmitReceipt {
    receipt: Option<String>,
}

async fn submit_receipt(State(st): State<Shared>, auth: Auth, headers: HeaderMap, Path(id): Path<String>, Body(req, raw): Body<SubmitReceipt>) -> Response {
    let st2 = st.clone();
    let mode = auth.mode;
    let route = format!("POST /v1/requests/{id}/receipts");
    idempotent(&st, &auth, &headers, &route, &raw, || async move {
        let text = req.receipt.ok_or_else(|| ApiError::missing("receipt"))?;
        let row = load_request(&st2, mode, &id)?;
        let obj = request_json(&st2, &row);
        match obj["status"].as_str() {
            Some("fulfilled") => return Err(ApiError::conflict("request_already_fulfilled", format!("{id} was already fulfilled"))),
            Some("expired") => return Err(ApiError::conflict("request_expired", format!("{id} expired"))),
            _ => {}
        }
        let (challenge, payee, amount) = (&row.2, &row.3, row.4);
        let net = mode.net(&st2.config);
        let result = async {
            let v = if sandbox::is_fixture(&text) {
                if mode != Mode::Test {
                    return Err(ApiError::invalid("receipt_network_mismatch", "sandbox fixtures only work with rcpt_test_ keys").param("receipt"));
                }
                sandbox::resolve(&text, Some(payee), amount.map(|a| a as u64), Some(challenge))?
            } else {
                verify::verify_receipt(net, mode.server(&st2.config).as_deref(), &text).await?
            };
            if v.challenge.as_deref() != Some(challenge.as_str()) {
                return Err(ApiError::verification("challenge_mismatch", "the receipt does not sign this request's challenge; create it with `--request <receipt_link>`"));
            }
            let paid = verify::paid_to(&v, payee)?;
            if paid == 0 {
                return Err(ApiError::verification("wrong_payee", "no disclosed output paid the request's payee"));
            }
            if amount.is_some_and(|a| paid < a as u64) {
                return Err(ApiError::verification("insufficient_amount", format!("paid {paid} zatoshis, the request asks for {}", amount.unwrap())));
            }
            Ok((v, paid))
        }
        .await;
        let (v, paid) = match result {
            Ok(x) => x,
            Err(e) => {
                if e.kind == "verification_error" {
                    let _ = emit(&st2, mode, "receipt.rejected", json!({ "object": "receipt_rejection", "request": id, "error": e.body()["error"] }));
                }
                return Err(e);
            }
        };
        let row = {
            let c = st2.db.0.lock().unwrap();
            let n = c.execute(
                "UPDATE requests SET status = 'fulfilled', fulfilled_at = ?1, txid = ?2, paid_zatoshis = ?3, receipt = ?4, verification = ?5 WHERE id = ?6 AND status = 'open'",
                params![now(), v.txid, paid as i64, text, serde_json::to_string(&v).unwrap(), id],
            )?;
            if n == 0 {
                return Err(ApiError::conflict("request_already_fulfilled", format!("{id} was already fulfilled")));
            }
            c.query_row(&format!("SELECT {REQUEST_COLS} FROM requests WHERE id = ?1"), [&id], row_to_request)?
        };
        let obj = request_json(&st2, &row);
        emit(&st2, mode, "request.fulfilled", obj.clone())?;
        Ok((StatusCode::OK, obj))
    })
    .await
}

#[derive(Deserialize)]
struct CreateEndpoint {
    url: Option<String>,
    events: Option<Vec<String>>,
}

const EVENT_TYPES: &[&str] = &["request.created", "request.fulfilled", "receipt.rejected"];

async fn create_endpoint(State(st): State<Shared>, auth: Auth, Body(req, _): Body<CreateEndpoint>) -> Result<(StatusCode, Json<Value>), ApiError> {
    let url = req.url.ok_or_else(|| ApiError::missing("url"))?;
    if !(url.starts_with("https://") || url.starts_with("http://")) {
        return Err(ApiError::invalid("parameter_invalid", "url must be http(s)").param("url"));
    }
    let events = req.events.unwrap_or_else(|| vec!["*".into()]);
    if let Some(bad) = events.iter().find(|e| *e != "*" && !EVENT_TYPES.contains(&e.as_str())) {
        return Err(ApiError::invalid("parameter_invalid", format!("unknown event type {bad}; one of {EVENT_TYPES:?} or *")).param("events"));
    }
    let id = new_id("we_");
    let mut s = [0u8; 24];
    getrandom::fill(&mut s).expect("OS RNG");
    let secret = format!("whsec_{}", hex::encode(s));
    let c = st.db.0.lock().unwrap();
    c.execute(
        "INSERT INTO webhook_endpoints (id, mode, url, secret, events, created) VALUES (?1,?2,?3,?4,?5,?6)",
        params![id, auth.mode.as_str(), url, secret, serde_json::to_string(&events).unwrap(), now()],
    )?;
    Ok((StatusCode::CREATED, Json(json!({ "id": id, "object": "webhook_endpoint", "url": url, "events": events, "secret": secret, "livemode": auth.mode == Mode::Live }))))
}

async fn list_endpoints(State(st): State<Shared>, auth: Auth) -> Result<Json<Value>, ApiError> {
    let c = st.db.0.lock().unwrap();
    let data: Vec<Value> = c
        .prepare("SELECT id, url, events, created FROM webhook_endpoints WHERE mode = ?1 AND disabled = 0 ORDER BY created DESC")?
        .query_map([auth.mode.as_str()], |r| {
            Ok(json!({ "id": r.get::<_, String>(0)?, "object": "webhook_endpoint", "url": r.get::<_, String>(1)?,
                       "events": serde_json::from_str::<Value>(&r.get::<_, String>(2)?).unwrap_or(json!([])), "created": r.get::<_, i64>(3)? }))
        })?
        .collect::<Result<_, _>>()?;
    Ok(Json(json!({ "object": "list", "data": data, "has_more": false })))
}

async fn delete_endpoint(State(st): State<Shared>, auth: Auth, Path(id): Path<String>) -> Result<Json<Value>, ApiError> {
    let c = st.db.0.lock().unwrap();
    let n = c.execute("UPDATE webhook_endpoints SET disabled = 1 WHERE id = ?1 AND mode = ?2", params![id, auth.mode.as_str()])?;
    if n == 0 {
        return Err(ApiError::not_found("webhook_endpoint_not_found", format!("no webhook endpoint {id}")));
    }
    Ok(Json(json!({ "id": id, "object": "webhook_endpoint", "deleted": true })))
}

async fn list_events(State(st): State<Shared>, auth: Auth, Query(q): Query<ListQuery>) -> Result<Json<Value>, ApiError> {
    let limit = q.limit.unwrap_or(20).clamp(1, 100);
    let c = st.db.0.lock().unwrap();
    let mut data: Vec<Value> = c
        .prepare("SELECT body FROM events WHERE mode = ?1 ORDER BY created DESC, rowid DESC LIMIT ?2")?
        .query_map(params![auth.mode.as_str(), limit + 1], |r| r.get::<_, String>(0))?
        .filter_map(|b| b.ok().and_then(|b| serde_json::from_str(&b).ok()))
        .collect();
    let has_more = data.len() > limit as usize;
    data.truncate(limit as usize);
    Ok(Json(json!({ "object": "list", "data": data, "has_more": has_more })))
}

/// Re-sends an event to every subscribed endpoint (like `stripe events resend`).
async fn resend_event(State(st): State<Shared>, auth: Auth, Path(id): Path<String>) -> Result<Json<Value>, ApiError> {
    let c = st.db.0.lock().unwrap();
    let (kind, body): (String, String) = c
        .query_row("SELECT type, body FROM events WHERE id = ?1 AND mode = ?2", params![id, auth.mode.as_str()], |r| Ok((r.get(0)?, r.get(1)?)))
        .optional()?
        .ok_or_else(|| ApiError::not_found("event_not_found", format!("no event {id}")))?;
    let endpoints: Vec<(String, String)> = c
        .prepare("SELECT id, events FROM webhook_endpoints WHERE mode = ?1 AND disabled = 0")?
        .query_map([auth.mode.as_str()], |r| Ok((r.get(0)?, r.get(1)?)))?
        .collect::<Result<_, _>>()?;
    let mut queued = 0;
    for (eid, events) in endpoints {
        let subs: Vec<String> = serde_json::from_str(&events).unwrap_or_default();
        if subs.iter().any(|s| s == "*" || *s == kind) {
            c.execute("INSERT INTO deliveries (event_id, endpoint_id, next_attempt_at) VALUES (?1,?2,?3)", params![id, eid, now()])?;
            queued += 1;
        }
    }
    let mut ev: Value = serde_json::from_str(&body).unwrap_or(Value::Null);
    ev["resent_to"] = queued.into();
    Ok(Json(ev))
}

#[derive(Deserialize)]
struct DeliveriesQuery {
    event: Option<String>,
    limit: Option<u32>,
}

/// Delivery attempts, newest first: which endpoint, how many attempts, last HTTP status.
async fn list_deliveries(State(st): State<Shared>, auth: Auth, Query(q): Query<DeliveriesQuery>) -> Result<Json<Value>, ApiError> {
    let limit = q.limit.unwrap_or(50).clamp(1, 200);
    let c = st.db.0.lock().unwrap();
    let mut stmt = c.prepare(
        "SELECT d.id, d.event_id, e.type, d.endpoint_id, w.url, d.attempts, d.status, d.last_status, d.last_error, d.next_attempt_at, d.delivered_at
         FROM deliveries d JOIN events e ON e.id = d.event_id JOIN webhook_endpoints w ON w.id = d.endpoint_id
         WHERE e.mode = ?1 AND (?2 IS NULL OR d.event_id = ?2) ORDER BY d.id DESC LIMIT ?3",
    )?;
    let data: Vec<Value> = stmt
        .query_map(params![auth.mode.as_str(), q.event, limit], |r| {
            Ok(json!({
                "id": r.get::<_, i64>(0)?, "object": "webhook_delivery", "event": r.get::<_, String>(1)?, "event_type": r.get::<_, String>(2)?,
                "endpoint": r.get::<_, String>(3)?, "url": r.get::<_, String>(4)?, "attempts": r.get::<_, i64>(5)?, "status": r.get::<_, String>(6)?,
                "last_http_status": r.get::<_, Option<i64>>(7)?, "last_error": r.get::<_, Option<String>>(8)?,
                "next_attempt_at": r.get::<_, i64>(9)?, "delivered_at": r.get::<_, Option<i64>>(10)?,
            }))
        })?
        .collect::<Result<_, _>>()?;
    Ok(Json(json!({ "object": "list", "data": data, "has_more": false })))
}

/// The request's ZIP-321 payment URI as an SVG QR code.
async fn request_qr(State(st): State<Shared>, auth: Auth, Path(id): Path<String>) -> Result<Response, ApiError> {
    let row = load_request(&st, auth.mode, &id)?;
    let uri = request_json(&st, &row)["payment_uri"].as_str().unwrap_or_default().to_string();
    let code = qrcode::QrCode::with_error_correction_level(uri.as_bytes(), qrcode::EcLevel::M).map_err(|e| ApiError::internal(e.to_string()))?;
    let svg = code.render::<qrcode::render::svg::Color>().min_dimensions(240, 240).quiet_zone(true).build();
    Ok(([("content-type", "image/svg+xml")], svg).into_response())
}

async fn errors_handler() -> Json<Value> {
    Json(json!({
        "object": "list",
        "data": error::ERROR_CODES.iter().map(|(code, status, what)| json!({ "code": code, "http_status": status, "description": what })).collect::<Vec<_>>()
    }))
}

async fn fixtures_handler() -> Json<Value> {
    Json(json!({ "object": "list", "data": sandbox::FIXTURES }))
}

async fn health(State(st): State<Shared>) -> Json<Value> {
    Json(json!({ "ok": true, "version": env!("CARGO_PKG_VERSION"), "test_network": st.config.test_net.name(), "live_network": "mainnet" }))
}

const OPENAPI: &str = include_str!("../../../docs/openapi.yaml");

async fn openapi() -> impl IntoResponse {
    ([("content-type", "application/yaml")], OPENAPI)
}

async fn dashboard_page() -> Html<&'static str> {
    Html(include_str!("../../../docs/dashboard.html"))
}

async fn docs_page() -> Html<&'static str> {
    Html(include_str!("../../../docs/api.html"))
}

/// Docs served as Markdown, so people and AI agents read the same text (`/docs/<name>.md`).
const DOCS: &[(&str, &str)] = &[
    ("QUICKSTART.md", include_str!("../../../docs/QUICKSTART.md")),
    ("ERRORS.md", include_str!("../../../docs/ERRORS.md")),
    ("WEBHOOKS.md", include_str!("../../../docs/WEBHOOKS.md")),
    ("SANDBOX.md", include_str!("../../../docs/SANDBOX.md")),
    ("SDKS.md", include_str!("../../../docs/SDKS.md")),
    ("SPEC.md", include_str!("../../../docs/SPEC.md")),
    ("guides/merchant-checkout.md", include_str!("../../../docs/guides/merchant-checkout.md")),
    ("guides/exchange-deposit.md", include_str!("../../../docs/guides/exchange-deposit.md")),
    ("guides/grant-payouts.md", include_str!("../../../docs/guides/grant-payouts.md")),
];

async fn doc_md(Path(name): Path<String>) -> Response {
    match DOCS.iter().find(|(n, _)| *n == name) {
        Some((_, body)) => ([("content-type", "text/markdown; charset=utf-8")], *body).into_response(),
        None => ApiError::not_found("doc_not_found", format!("no doc {name}")).into_response(),
    }
}

async fn llms_txt() -> impl IntoResponse {
    ([("content-type", "text/plain; charset=utf-8")], include_str!("../../../docs/llms.txt"))
}

async fn llms_full() -> impl IntoResponse {
    let mut s = String::from(include_str!("../../../docs/llms.txt"));
    for (name, body) in DOCS {
        s.push_str(&format!("\n\n---\n<!-- /docs/{name} -->\n\n{body}"));
    }
    ([("content-type", "text/plain; charset=utf-8")], s)
}

pub fn router(state: Shared) -> Router {
    Router::new()
        .route("/v1/health", get(health))
        .route("/v1/errors", get(errors_handler))
        .route("/v1/sandbox/fixtures", get(fixtures_handler))
        .route("/v1/verify", post(verify_handler))
        .route("/v1/requests", post(create_request).get(list_requests))
        .route("/v1/requests/{id}", get(get_request))
        .route("/v1/requests/{id}/receipts", post(submit_receipt))
        .route("/v1/requests/{id}/qr.svg", get(request_qr))
        .route("/v1/deliveries", get(list_deliveries))
        .route("/v1/webhook_endpoints", post(create_endpoint).get(list_endpoints))
        .route("/v1/webhook_endpoints/{id}", delete(delete_endpoint))
        .route("/v1/events", get(list_events))
        .route("/v1/events/{id}/resend", post(resend_event))
        .route("/openapi.yaml", get(openapi))
        .route("/docs", get(docs_page))
        .route("/docs/{*name}", get(doc_md))
        .route("/llms.txt", get(llms_txt))
        .route("/llms-full.txt", get(llms_full))
        .route("/dashboard", get(dashboard_page))
        .layer(axum::middleware::from_fn_with_state(state.clone(), api_middleware))
        .layer(tower_http::cors::CorsLayer::permissive().expose_headers([
            axum::http::HeaderName::from_static("receipts-version"),
            axum::http::HeaderName::from_static("ratelimit-remaining"),
            axum::http::HeaderName::from_static("idempotent-replayed"),
        ]))
        .with_state(state)
}

/// Opens the database, ensures one test and one live key exist, starts the webhook worker
/// and warms the verifier. Returns the router and the keys.
pub async fn build(db_path: &str, config: Config) -> anyhow::Result<(Router, Vec<(String, String)>)> {
    let db = Db::open(db_path)?;
    let keys = db.ensure_keys()?;
    let state = Arc::new(AppState {
        db,
        config,
        http: reqwest::Client::builder().timeout(std::time::Duration::from_secs(10)).build()?,
        rate: Default::default(),
    });
    tokio::spawn(webhooks::worker(state.clone()));
    tokio::spawn(verify::warm_up());
    Ok((router(state), keys))
}
