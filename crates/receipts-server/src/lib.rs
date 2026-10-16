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

pub mod attestations;
pub mod clocks;
pub mod db;
pub mod error;
pub mod refunds;
pub mod requests;
pub mod sandbox;
pub mod signin;
pub mod verifier;
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
use requests::{create_request, get_request, list_requests, request_qr, submit_receipt};
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
    /// Public base URL of this API, for hosted pay pages and campaign pages.
    pub public_url: String,
    /// Campaign pages refresh their public numbers at most this often (batched updates make
    /// it harder to match a contribution to an on-chain transaction by timing).
    pub campaign_snapshot_secs: i64,
    /// Requests allowed per API key per minute (default RATE_LIMIT).
    pub rate_limit: u32,
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
            public_url: "http://127.0.0.1:8723".into(),
            campaign_snapshot_secs: 600,
            rate_limit: RATE_LIMIT,
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
/// Unauthenticated receipt submissions allowed per request (hosted pay and campaign pages) per minute.
pub const PUBLIC_SUBMIT_LIMIT: u32 = 20;

async fn api_middleware(State(st): State<Shared>, req: axum::extract::Request, next: axum::middleware::Next) -> Response {
    if let Some(v) = req.headers().get("receipts-version").and_then(|v| v.to_str().ok()) {
        if v != API_VERSION {
            return ApiError::invalid("api_version_unsupported", format!("this server speaks Receipts-Version {API_VERSION}, not {v}")).into_response();
        }
    }
    // Rate-limit buckets: a valid API key (however it was sent), or, for the hosted pages'
    // unauthenticated receipt submissions, the request id. Anything else is not counted here
    // and is refused by authentication, so made-up headers can't open fresh buckets.
    let raw_key = req
        .headers()
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .map(|v| v.strip_prefix("Bearer ").unwrap_or(v).trim().to_string())
        .or_else(|| req.headers().get("x-api-key").and_then(|v| v.to_str().ok()).map(|v| v.trim().to_string()));
    let valid_key = raw_key.filter(|k| matches!(st.db.mode_for_key(k), Ok(Some(_))));
    let path = req.uri().path().to_string();
    let key = valid_key.or_else(|| {
        (req.method() == axum::http::Method::POST && path.starts_with("/v1/public/")).then(|| {
            let decoded = percent_decode(&path);
            let id = decoded.split('/').nth(4).unwrap_or("").to_string();
            format!("public:{id}")
        })
    });
    let mut remaining = None;
    if let Some(k) = key {
        let limit = if k.starts_with("public:") { PUBLIC_SUBMIT_LIMIT } else { st.config.rate_limit };
        let t = now();
        let window = t - t % 60;
        let mut m = st.rate.lock().unwrap();
        if m.len() > 10_000 {
            m.retain(|_, (w, _)| *w == window);
        }
        let e = m.entry(k).or_insert((window, 0));
        if e.0 != window {
            *e = (window, 0);
        }
        e.1 += 1;
        if e.1 > limit {
            let mut res = ApiError::new_rate_limited().into_response();
            res.headers_mut().insert("retry-after", (window + 60 - t).to_string().parse().unwrap());
            return res;
        }
        remaining = Some((limit, limit - e.1));
    }
    let mut res = next.run(req).await;
    let h = res.headers_mut();
    h.insert("receipts-version", API_VERSION.parse().unwrap());
    if let Some((limit, r)) = remaining {
        h.insert("ratelimit-limit", limit.to_string().parse().unwrap());
        h.insert("ratelimit-remaining", r.to_string().parse().unwrap());
    }
    // Hosted pages carry a client secret in their URL: never leak it in a Referer.
    h.insert("referrer-policy", "no-referrer".parse().unwrap());
    h.insert("x-content-type-options", "nosniff".parse().unwrap());
    if h.get("content-type").and_then(|v| v.to_str().ok()).is_some_and(|c| c.starts_with("text/html")) {
        h.insert("content-security-policy", "frame-ancestors 'self'".parse().unwrap());
    }
    res
}

pub type Shared = Arc<AppState>;

/// Constant-time equality for secrets (client secrets, signatures): the time taken doesn't
/// depend on where the first difference is. Lengths are not secret.
pub(crate) fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

fn percent_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            if let Ok(v) = u8::from_str_radix(&s[i + 1..i + 3], 16) {
                out.push(v);
                i += 3;
                continue;
            }
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Mode {
    Test,
    Live,
}

impl Mode {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Mode::Test => "test",
            Mode::Live => "live",
        }
    }
    pub(crate) fn net(self, c: &Config) -> Net {
        match self {
            Mode::Test => c.test_net,
            Mode::Live => Net::Main,
        }
    }
    pub(crate) fn server(self, c: &Config) -> Option<String> {
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
        // Refuse keys and seed phrases outright, and never store or echo them.
        if let Some(kind) = receipts_core::tripwire::secret_kind(&raw) {
            return Err(ApiError::invalid("secret_detected", format!("this request contains what looks like a {kind}. Receipts never needs one; it was not stored. Send only the zrcpt1… receipt.")));
        }
        let value: Value = serde_json::from_slice(if bytes.is_empty() { b"{}" } else { &bytes })
            .map_err(|e| ApiError::invalid("invalid_json", e.to_string()))?;
        // Again on the decoded strings, so JSON escapes (\u0075view…) can't hide a key.
        fn strings<'a>(v: &'a Value, out: &mut Vec<&'a str>) {
            match v {
                Value::String(s) => out.push(s),
                Value::Array(a) => a.iter().for_each(|x| strings(x, out)),
                Value::Object(o) => o.iter().for_each(|(k, x)| {
                    out.push(k);
                    strings(x, out)
                }),
                _ => {}
            }
        }
        let mut all = Vec::new();
        strings(&value, &mut all);
        if let Some(kind) = all.iter().find_map(|s| receipts_core::tripwire::secret_kind(s)) {
            return Err(ApiError::invalid("secret_detected", format!("this request contains what looks like a {kind}. Receipts never needs one; it was not stored. Send only the zrcpt1… receipt.")));
        }
        let v = serde_json::from_value(value).map_err(|e| ApiError::invalid("invalid_json", e.to_string()))?;
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
pub(crate) async fn idempotent<F, Fut>(st: &Shared, auth: &Auth, headers: &HeaderMap, route: &str, raw: &str, f: F) -> Response
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

pub(crate) fn zec(z: u64) -> String {
    let s = format!("{}.{:08}", z / 100_000_000, z % 100_000_000);
    s.trim_end_matches('0').trim_end_matches('.').to_string()
}

pub(crate) fn urlenc(s: &str) -> String {
    s.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => (b as char).to_string(),
            _ => format!("%{b:02X}"),
        })
        .collect()
}

pub(crate) fn check_payee(net: Net, payee: &str) -> Result<(), ApiError> {
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
    if req.min_zatoshis.is_some() && req.expect_address.is_none() {
        return Err(ApiError::invalid("parameter_missing", "min_zatoshis needs expect_address: the minimum is checked against what that address received").param("expect_address"));
    }
    let net = auth.mode.net(&st.config);
    let server = auth.mode.server(&st.config);
    let v = if sandbox::is_fixture(&text) {
        if auth.mode != Mode::Test {
            return Err(ApiError::invalid("receipt_network_mismatch", "sandbox fixtures only work with rcpt_test_ keys").param("receipt"));
        }
        sandbox::resolve(&text, req.expect_address.as_deref(), req.min_zatoshis, req.challenge.as_deref())?
    } else if text.contains("zrcptb1") {
        return Ok(Json(verify::verify_batch(net, server.as_deref(), &text).await?));
    } else if text.contains(receipts_core::incoming::INCOMING_TEXT_PREFIX) {
        return Ok(Json(verify::verify_incoming(net, server.as_deref(), &text, req.expect_address.as_deref(), req.challenge.as_deref()).await?));
    } else {
        verify::verify_receipt(net, server.as_deref(), &text).await?
    };
    if let Some(c) = &req.challenge {
        if v.challenge.as_deref() != Some(c.as_str()) {
            return Err(ApiError::verification("challenge_mismatch", "the receipt does not sign this challenge"));
        }
    }
    let mut body = serde_json::to_value(&v).unwrap();
    if req.challenge.is_some() {
        body["checks"]["challenge"] = "matched".into();
    }
    if let Some(addr) = &req.expect_address {
        let paid = verify::paid_to(&v, addr, "expect_address")?;
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
struct CheckLink {
    uri: Option<String>,
    /// Default: the network of the key's mode.
    network: Option<String>,
}

/// Lints a ZIP-321 payment URI before it is printed or turned into a QR code.
async fn check_link_handler(State(st): State<Shared>, auth: Auth, Body(req, _): Body<CheckLink>) -> Result<Json<Value>, ApiError> {
    let uri = req.uri.ok_or_else(|| ApiError::missing("uri"))?;
    let net = req.network.unwrap_or_else(|| auth.mode.net(&st.config).name().to_string());
    let mut v = receipts_core::preflight::check_payment_uri(&uri, Some(&net));
    v["object"] = "payment_link_check".into();
    Ok(Json(v))
}

#[derive(Deserialize)]
struct CreateEndpoint {
    url: Option<String>,
    events: Option<Vec<String>>,
}

const EVENT_TYPES: &[&str] = &["request.created", "request.payment_received", "request.fulfilled", "request.final", "request.payment_reorged", "request.expired", "receipt.rejected", "refund.created", "refund.succeeded"];

/// Whether `ip` is a public unicast address (not loopback, private, link-local, CGNAT,
/// benchmarking, multicast, reserved, or an IPv6 form that embeds such an IPv4 address).
pub(crate) fn is_public_ip(ip: std::net::IpAddr) -> bool {
    use std::net::IpAddr;
    match ip {
        IpAddr::V4(v) => {
            let o = v.octets();
            !(v.is_private() || v.is_loopback() || v.is_link_local() || v.is_unspecified() || v.is_broadcast() || v.is_multicast() || v.is_documentation()
                || o[0] == 0
                || (o[0] == 100 && (o[1] & 0xc0) == 64)
                || (o[0] == 198 && (o[1] & 0xfe) == 18)
                || o[0] >= 240
                || (o[0] == 192 && o[1] == 0 && o[2] == 0))
        }
        IpAddr::V6(v) => {
            let s = v.segments();
            if let Some(v4) = v.to_ipv4_mapped() {
                return is_public_ip(IpAddr::V4(v4));
            }
            // IPv4-compatible (::a.b.c.d), NAT64 (64:ff9b::/96), 6to4 (2002::/16): check the embedded IPv4.
            let embedded = |a: u16, b: u16| IpAddr::V4(std::net::Ipv4Addr::new((a >> 8) as u8, a as u8, (b >> 8) as u8, b as u8));
            if s[..6] == [0, 0, 0, 0, 0, 0] {
                return !v.is_unspecified() && !v.is_loopback() && is_public_ip(embedded(s[6], s[7]));
            }
            if s[0] == 0x64 && s[1] == 0xff9b {
                return is_public_ip(embedded(s[6], s[7]));
            }
            if s[0] == 0x2002 {
                return is_public_ip(embedded(s[1], s[2]));
            }
            !(v.is_loopback() || v.is_unspecified() || v.is_multicast()
                || (s[0] & 0xfe00) == 0xfc00   // unique local
                || (s[0] & 0xffc0) == 0xfe80   // link-local
                || (s[0] & 0xffc0) == 0xfec0   // site-local (deprecated)
                || s[0] == 0x2001 && s[1] == 0x0db8) // documentation
        }
    }
}

/// Live webhooks must go to a public HTTPS host: no localhost, private or link-local
/// addresses (so a leaked live key can't make the server probe its own network). Checked
/// when the endpoint is created and again, after DNS, before every delivery.
pub(crate) fn check_live_webhook_url(url: &str) -> Result<(), ApiError> {
    let bad = |m: &str| Err(ApiError::invalid("webhook_url_not_allowed", m.to_string()).param("url"));
    let Ok(u) = reqwest::Url::parse(url) else { return bad("not a valid URL") };
    if u.scheme() != "https" {
        return bad("live webhooks must use https");
    }
    match u.host() {
        None => bad("the URL has no host"),
        Some(url::Host::Domain(d)) => {
            let d = d.trim_end_matches('.').to_ascii_lowercase();
            let internal = ["localhost", "local", "internal", "localdomain", "home.arpa", "lan", "intranet", "corp"];
            if d.is_empty() || internal.iter().any(|s| d == *s || d.ends_with(&format!(".{s}"))) {
                bad("live webhooks must go to a public host")
            } else {
                Ok(())
            }
        }
        Some(url::Host::Ipv4(ip)) => if is_public_ip(ip.into()) { Ok(()) } else { bad("live webhooks must go to a public address") },
        Some(url::Host::Ipv6(ip)) => if is_public_ip(ip.into()) { Ok(()) } else { bad("live webhooks must go to a public address") },
    }
}

async fn create_endpoint(State(st): State<Shared>, auth: Auth, Body(req, _): Body<CreateEndpoint>) -> Result<(StatusCode, Json<Value>), ApiError> {
    let url = req.url.ok_or_else(|| ApiError::missing("url"))?;
    if !(url.starts_with("https://") || url.starts_with("http://")) {
        return Err(ApiError::invalid("parameter_invalid", "url must be http(s)").param("url"));
    }
    if auth.mode == Mode::Live {
        check_live_webhook_url(&url)?;
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

#[derive(Deserialize)]
pub struct ListQuery {
    pub(crate) status: Option<String>,
    pub(crate) limit: Option<u32>,
    pub(crate) starting_after: Option<String>,
}

async fn list_events(State(st): State<Shared>, auth: Auth, Query(q): Query<ListQuery>) -> Result<Json<Value>, ApiError> {
    let limit = q.limit.unwrap_or(20).clamp(1, 100);
    let c = st.db.0.lock().unwrap();
    // Cursor: the rowid of `starting_after` (events are append-only, so rowid is their order).
    let after: Option<i64> = match &q.starting_after {
        Some(id) => Some(
            c.query_row("SELECT rowid FROM events WHERE id = ?1 AND mode = ?2", params![id, auth.mode.as_str()], |r| r.get(0))
                .optional()?
                .ok_or_else(|| ApiError::invalid("parameter_invalid", "starting_after is not an event of this mode").param("starting_after"))?,
        ),
        None => None,
    };
    let mut data: Vec<Value> = c
        .prepare("SELECT body FROM events WHERE mode = ?1 AND (?3 IS NULL OR rowid < ?3) ORDER BY rowid DESC LIMIT ?2")?
        .query_map(params![auth.mode.as_str(), limit + 1, after], |r| r.get::<_, String>(0))?
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

/// `GET /`: what Receipts is, in plain words, and where to go next.
async fn root_page(State(st): State<Shared>) -> Html<String> {
    let port = st.config.public_url.rsplit(':').next().unwrap_or("8723").trim_end_matches('/').to_string();
    Html(include_str!("../../../docs/landing.html").replace("{net}", st.config.test_net.name()).replace("{port}", &port))
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
    ("REGTEST.md", include_str!("../../../docs/REGTEST.md")),
    ("THREAT-MODEL.md", include_str!("../../../docs/THREAT-MODEL.md")),
    ("ZIP311-TODOS.md", include_str!("../../../docs/ZIP311-TODOS.md")),
    ("COMPARISON.md", include_str!("../../../docs/COMPARISON.md")),
    ("CRYPTO-REVIEW.md", include_str!("../../../docs/CRYPTO-REVIEW.md")),
    ("guides/merchant-checkout.md", include_str!("../../../docs/guides/merchant-checkout.md")),
    ("guides/exchange-deposit.md", include_str!("../../../docs/guides/exchange-deposit.md")),
    ("guides/grant-payouts.md", include_str!("../../../docs/guides/grant-payouts.md")),
    ("guides/refunds.md", include_str!("../../../docs/guides/refunds.md")),
    ("guides/attestations.md", include_str!("../../../docs/guides/attestations.md")),
    ("guides/http-402.md", include_str!("../../../docs/guides/http-402.md")),
    ("guides/sign-in.md", include_str!("../../../docs/guides/sign-in.md")),
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
        .route("/v1/payment_links/check", post(check_link_handler))
        .route("/v1/sign_in/challenges", post(signin::create_challenge))
        .route("/v1/sign_in/verify", post(signin::verify))
        .route("/v1/requests", post(create_request).get(list_requests))
        .route("/v1/requests/{id}", get(get_request))
        .route("/v1/requests/{id}/receipts", post(submit_receipt))
        .route("/v1/requests/{id}/qr.svg", get(request_qr))
        .route("/v1/requests/{id}/refunds", post(refunds::create))
        .route("/v1/requests/{id}/attestations", post(attestations::create))
        .route("/v1/attestations/verify", post(attestations::verify))
        .route("/.well-known/jwks.json", get(attestations::jwks))
        .route("/v1/refunds/{id}", get(refunds::get))
        .route("/v1/refunds/{id}/receipts", post(refunds::submit))
        .route("/v1/deliveries", get(list_deliveries))
        .route("/v1/test_clocks", post(clocks::create))
        .route("/v1/test_clocks/{id}", get(clocks::get))
        .route("/v1/test_clocks/{id}/advance", post(clocks::advance))
        .route("/v1/test_clocks/{id}/reorg", post(clocks::reorg))
        .route("/v1/public/requests/{id}", get(requests::public_get))
        .route("/v1/public/requests/{id}/qr.svg", get(requests::public_qr))
        .route("/v1/public/requests/{id}/receipts", post(requests::public_submit))
        .route("/v1/public/campaigns/{id}", get(requests::campaign_json))
        .route("/pay/{id}", get(requests::pay_page))
        .route("/c/{id}", get(requests::campaign_page))
        .route("/v1/webhook_endpoints", post(create_endpoint).get(list_endpoints))
        .route("/v1/webhook_endpoints/{id}", delete(delete_endpoint))
        .route("/v1/events", get(list_events))
        .route("/v1/events/{id}/resend", post(resend_event))
        .route("/openapi.yaml", get(openapi))
        .route("/", get(root_page))
        .route("/verify", get(verifier::root))
        .route("/verify/", get(verifier::index))
        .route("/verify/{*path}", get(verifier::file))
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
        // Webhooks never follow redirects: a 3xx could otherwise point a delivery anywhere.
        http: reqwest::Client::builder().timeout(std::time::Duration::from_secs(10)).redirect(reqwest::redirect::Policy::none()).build()?,
        rate: Default::default(),
    });
    tokio::spawn(webhooks::worker(state.clone()));
    tokio::spawn(requests::expiry_sweeper(state.clone()));
    tokio::spawn(clocks::finality_sweeper(state.clone()));
    tokio::spawn(verify::warm_up());
    Ok((router(state), keys))
}
