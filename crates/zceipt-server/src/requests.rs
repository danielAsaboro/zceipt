//! Proof requests: create, list, retrieve, accept receipts; hosted pay pages and campaigns.
//!
//! Kinds:
//! - `single` (default): one receipt must pay at least `amount_zatoshis`.
//! - `partial`: several receipts add up; the request is fulfilled once they reach the amount.
//! - `campaign`: open-ended; every valid receipt is counted and the request never closes.
//!   The public page at `/c/{id}` is aggregate-only: a rounded total and a contributor count,
//!   shown only after `public_min_contributions` (k, default 3) contributions, refreshed in
//!   delayed batches, with no amounts, txids or on-chain memos. A contributor can opt in to a
//!   public note by signing `public-note:<text>` into their receipt.
//!
//! A payment (transaction + output) can count towards only one request, ever. Otherwise one
//! payment could be proven again for a second request with a fresh challenge.

use crate::{
    check_payee,
    db::{new_id, now},
    emit,
    error::ApiError,
    idempotent, sandbox, urlenc, verify, zec, AppState, Auth, Body, ListQuery, Mode, Shared,
};
use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{Html, IntoResponse, Response},
    Json,
};
use rusqlite::{params, OptionalExtension};
use serde::Deserialize;
use serde_json::{json, Value};

pub struct RequestRec {
    pub id: String,
    pub mode: String,
    pub kind: String,
    pub challenge: String,
    pub payee: String,
    pub amount: Option<i64>,
    pub label: Option<String>,
    pub metadata: String,
    pub status: String,
    pub created: i64,
    pub expires_at: Option<i64>,
    pub fulfilled_at: Option<i64>,
    pub txid: Option<String>,
    pub paid: Option<i64>,
    pub verification: Option<String>,
    pub received: i64,
    pub client_secret: Option<String>,
    /// Sandbox: the test clock this request runs on, and that clock's time.
    pub test_clock: Option<String>,
    pub clock_time: Option<i64>,
    /// When the payment reached FINALITY_CONFIRMATIONS.
    pub final_at: Option<i64>,
    /// Deposit desks: the source-of-funds policy (JSON) and the checked provenance (JSON).
    pub source_policy: Option<String>,
    pub provenance: Option<String>,
    /// The chain tip when the request was made, once known: a payment must be mined after it.
    pub created_height: Option<i64>,
}

const COLS: &str = "id, mode, kind, challenge, payee, amount_zatoshis, label, metadata, status, created, expires_at, fulfilled_at, txid, paid_zatoshis, verification, received_zatoshis, client_secret, test_clock, (SELECT frozen_time FROM test_clocks WHERE test_clocks.id = requests.test_clock), final_at, source_policy, provenance, created_height";

fn from_row(r: &rusqlite::Row) -> rusqlite::Result<RequestRec> {
    Ok(RequestRec {
        id: r.get(0)?,
        mode: r.get(1)?,
        kind: r.get(2)?,
        challenge: r.get(3)?,
        payee: r.get(4)?,
        amount: r.get(5)?,
        label: r.get(6)?,
        metadata: r.get(7)?,
        status: r.get(8)?,
        created: r.get(9)?,
        expires_at: r.get(10)?,
        fulfilled_at: r.get(11)?,
        txid: r.get(12)?,
        paid: r.get(13)?,
        verification: r.get(14)?,
        received: r.get(15)?,
        client_secret: r.get(16)?,
        test_clock: r.get(17)?,
        clock_time: r.get(18)?,
        final_at: r.get(19)?,
        source_policy: r.get(20)?,
        provenance: r.get(21)?,
        created_height: r.get(22)?,
    })
}

impl RequestRec {
    pub fn effective_status(&self) -> &str {
        if self.status == "open" && self.expires_at.is_some_and(|e| e <= self.clock_time.unwrap_or_else(now)) {
            "expired"
        } else {
            &self.status
        }
    }
}

pub fn load(st: &AppState, mode: Option<Mode>, id: &str) -> Result<RequestRec, ApiError> {
    let c = st.db.0.lock().unwrap();
    let rec = match mode {
        Some(m) => c.query_row(&format!("SELECT {COLS} FROM requests WHERE id = ?1 AND mode = ?2"), params![id, m.as_str()], from_row),
        None => c.query_row(&format!("SELECT {COLS} FROM requests WHERE id = ?1"), params![id], from_row),
    }
    .optional()?;
    rec.ok_or_else(|| ApiError::not_found("request_not_found", format!("no proof request {id}")))
}

fn payments(st: &AppState, id: &str) -> Result<Vec<Value>, ApiError> {
    let c = st.db.0.lock().unwrap();
    let mut stmt = c.prepare(
        "SELECT txid, zatoshis, mined_height, memo, sender_addresses, created, refund_address FROM request_payments WHERE request_id = ?1 ORDER BY id",
    )?;
    let rows = stmt
        .query_map([id], |r| {
            Ok(json!({
                "txid": r.get::<_, String>(0)?, "zatoshis": r.get::<_, i64>(1)?, "mined_height": r.get::<_, Option<i64>>(2)?,
                "memo": r.get::<_, Option<String>>(3)?, "sender_addresses": serde_json::from_str::<Value>(&r.get::<_, String>(4)?).unwrap_or(json!([])),
                "created": r.get::<_, i64>(5)?, "refund_address": r.get::<_, Option<String>>(6)?,
            }))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(rows)
}

/// Public base URL of this API for hosted pages (falls back to a relative path).
fn hosted(st: &AppState, path: &str) -> String {
    format!("{}{path}", st.config.public_url.trim_end_matches('/'))
}

pub fn to_json(st: &AppState, r: &RequestRec) -> Value {
    let memo = format!("Zceipt request {}", r.id);
    let mut uri = format!("zcash:{}?", r.payee);
    let remaining = r.amount.map(|a| (a - r.received).max(0));
    if let Some(a) = remaining.filter(|a| *a > 0) {
        uri.push_str(&format!("amount={}&", zec(a as u64)));
    }
    uri.push_str(&format!("memo={}", base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, memo.as_bytes())));
    if let Some(l) = &r.label {
        uri.push_str(&format!("&message={}", urlenc(l)));
    }
    // Parameters in the #fragment, which browsers never send: the page's host doesn't learn them.
    let mut link = format!("{}#request={}&to={}", st.config.verifier_url, r.challenge, urlenc(&r.payee));
    if r.kind == "single" {
        if let Some(a) = r.amount {
            link.push_str(&format!("&min={a}"));
        }
    }
    if let Some(l) = &r.label {
        link.push_str(&format!("&label={}", urlenc(l)));
    }
    let secret = r.client_secret.clone().unwrap_or_default();
    json!({
        "id": r.id,
        "object": "proof_request",
        "livemode": r.mode == "live",
        "kind": r.kind,
        "status": r.effective_status(),
        "challenge": r.challenge,
        "payee": r.payee,
        "amount_zatoshis": r.amount,
        "received_zatoshis": r.received,
        "remaining_zatoshis": remaining,
        "label": r.label,
        "metadata": serde_json::from_str::<Value>(&r.metadata).unwrap_or(json!({})),
        "created": r.created,
        "expires_at": r.expires_at,
        "payment_uri": uri,
        "receipt_link": link,
        // Proofs from the wallet's viewing key, then the signature where the seed is (asked for,
        // never shown); the link is shell-quoted.
        "cli_command": format!(
            "zceipt create --ufvk @viewing-key.txt --birthday <wallet birthday> --txid <txid>{} --request '{}' --unsigned r.txt && zceipt sign r.txt --seed-stdin",
            if r.source_policy.is_some() { " --prove-source" } else { "" },
            link.replace('\'', "'\\''")
        ),
        "source_of_funds": crate::deposits::policy_summary(r.source_policy.as_deref()),
        "provenance": r.provenance.as_deref().and_then(|p| serde_json::from_str::<Value>(p).ok()),
        "client_secret": r.client_secret,
        "hosted_url": hosted(st, &format!("/pay/{}#secret={secret}", r.id)),
        "public_url": (r.kind == "campaign").then(|| hosted(st, &format!("/c/{}", r.id))),
        "final": r.final_at.is_some(),
        "final_at": r.final_at,
        "test_clock": r.test_clock,
        "payments": payments(st, &r.id).unwrap_or_default(),
        "refunds": crate::refunds::refunds_of(st, &r.id),
        "fulfillment": r.fulfilled_at.map(|t| json!({
            "fulfilled_at": t,
            "txid": r.txid,
            "paid_zatoshis": r.paid,
            "verification": r.verification.as_deref().and_then(|v| serde_json::from_str::<Value>(v).ok()),
        })),
    })
}

// A misspelt field (`amount` for `amount_zatoshis`) must fail, not make a request with no minimum.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateRequest {
    payee: Option<String>,
    amount_zatoshis: Option<u64>,
    label: Option<String>,
    metadata: Option<serde_json::Map<String, Value>>,
    expires_in: Option<i64>,
    kind: Option<String>,
    /// Campaigns: contributions needed before the public page shows anything (default 3).
    public_min_contributions: Option<i64>,
    /// Sandbox only: run this request on a test clock (`POST /v1/test_clocks`).
    test_clock: Option<String>,
    /// Deposit desks: require the payer to prove where the money came from, and screen it.
    source_of_funds: Option<crate::deposits::SourcePolicy>,
}

pub async fn create_request(State(st): State<Shared>, auth: Auth, headers: HeaderMap, Body(req, raw): Body<CreateRequest>) -> Response {
    let st2 = st.clone();
    let mode = auth.mode;
    let api_key = auth.key.clone();
    idempotent(&st, &auth, &headers, "POST /v1/requests", &raw, || async move {
        let payee = req.payee.ok_or_else(|| ApiError::missing("payee"))?;
        check_payee(mode.net(&st2.config), &payee)?;
        if req.label.as_ref().is_some_and(|l| l.len() > 200) {
            return Err(ApiError::invalid("parameter_invalid", "label is longer than 200 characters").param("label"));
        }
        if req.expires_in.is_some_and(|e| e <= 0 || e > 10 * 366 * 86_400) {
            return Err(ApiError::invalid("parameter_invalid", "expires_in must be 1 second to 10 years").param("expires_in"));
        }
        // 21 million ZEC, the supply cap.
        if req.amount_zatoshis.is_some_and(|a| a == 0 || a > 21_000_000 * 100_000_000) {
            return Err(ApiError::invalid("parameter_invalid", "amount_zatoshis must be 1 to 2,100,000,000,000,000").param("amount_zatoshis"));
        }
        if let Some(m) = &req.metadata {
            if m.len() > 50 || Value::Object(m.clone()).to_string().len() > 8_192 || m.keys().any(|k| k.len() > 40) {
                return Err(ApiError::invalid("parameter_invalid", "metadata: at most 50 keys of up to 40 characters, 8 KB in all").param("metadata"));
            }
        }
        let kind = req.kind.unwrap_or_else(|| "single".into());
        if !["single", "partial", "campaign"].contains(&kind.as_str()) {
            return Err(ApiError::invalid("parameter_invalid", "kind must be single, partial or campaign").param("kind"));
        }
        if req.public_min_contributions.is_some_and(|k| !(1..=1000).contains(&k)) {
            return Err(ApiError::invalid("parameter_invalid", "public_min_contributions must be 1..=1000").param("public_min_contributions"));
        }
        if kind == "partial" && req.amount_zatoshis.is_none() {
            return Err(ApiError::invalid("parameter_missing", "a partial request needs amount_zatoshis").param("amount_zatoshis"));
        }
        let policy_json = match &req.source_of_funds {
            None => None,
            Some(p) => {
                if kind != "single" {
                    return Err(ApiError::invalid("parameter_invalid", "source_of_funds works with single requests (one deposit, one proof)").param("source_of_funds"));
                }
                Some(crate::deposits::validate(mode.net(&st2.config), p)?)
            }
        };
        let clock_time = match &req.test_clock {
            None => None,
            Some(cid) => {
                if mode != Mode::Test {
                    return Err(ApiError::invalid("parameter_invalid", "test clocks only work with rcpt_test_ keys").param("test_clock"));
                }
                Some(crate::clocks::load_owned(&st2, cid, &api_key)?.frozen_time)
            }
        };
        let id = new_id("preq_");
        let mut ch = [0u8; 8];
        getrandom::fill(&mut ch).expect("OS RNG");
        let challenge = hex::encode(ch);
        let client_secret = new_id(&format!("{id}_secret_"));
        let created = clock_time.unwrap_or_else(now);
        {
            let c = st2.db.0.lock().unwrap();
            c.execute(
                "INSERT INTO requests (id, mode, kind, challenge, payee, amount_zatoshis, label, metadata, status, created, expires_at, client_secret, public_k, test_clock, source_policy) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,'open',?9,?10,?11,?12,?13,?14)",
                params![id, mode.as_str(), kind, challenge, payee, req.amount_zatoshis.map(|a| a as i64), req.label, Value::Object(req.metadata.unwrap_or_default()).to_string(), created, req.expires_in.map(|e| created + e), client_secret, req.public_min_contributions.unwrap_or(3), req.test_clock, policy_json],
            )?;
        }
        // The tip now, fetched in the background: a payment mined at or before it can't answer
        // this request (an old payment shown again). Until it is known, the challenge and the
        // used-payment check still apply.
        if req.test_clock.is_none() {
            let (st3, id3) = (st2.clone(), id.clone());
            tokio::spawn(async move {
                let net = mode.net(&st3.config);
                let server = mode.server(&st3.config);
                if let Ok(Ok(tip)) = tokio::time::timeout(std::time::Duration::from_secs(20), zceipt_chain::chain::chain_tip(net, server.as_deref())).await {
                    let c = st3.db.0.lock().unwrap();
                    let _ = c.execute("UPDATE requests SET created_height = ?1 WHERE id = ?2 AND created_height IS NULL", params![tip as i64, id3]);
                }
            });
        }
        let obj = to_json(&st2, &load(&st2, Some(mode), &id)?);
        emit(&st2, mode, "request.created", obj.clone())?;
        Ok((StatusCode::CREATED, obj))
    })
    .await
}

pub async fn list_requests(State(st): State<Shared>, auth: Auth, Query(q): Query<ListQuery>) -> Result<Json<Value>, ApiError> {
    let limit = q.limit.unwrap_or(20).clamp(1, 100);
    // Pages of 500 are read until enough requests match the status filter (the status is computed
    // per request, so it can't be part of the query): a match older than the newest 500 is found too.
    let mut cursor = q.starting_after.clone();
    let mut data: Vec<Value> = Vec::new();
    for _ in 0..40 {
        let rows: Vec<RequestRec> = {
            let c = st.db.0.lock().unwrap();
            let after = match &cursor {
                Some(id) => c.query_row("SELECT created FROM requests WHERE id = ?1", [id], |r| r.get::<_, i64>(0)).optional()?.unwrap_or(i64::MAX),
                None => i64::MAX,
            };
            let mut stmt = c.prepare(&format!("SELECT {COLS} FROM requests WHERE mode = ?1 AND (?3 IS NULL OR created < ?2 OR (created = ?2 AND id < ?3)) ORDER BY created DESC, id DESC LIMIT ?4"))?;
            let rows = stmt.query_map(params![auth.mode.as_str(), after, cursor, 500], from_row)?.collect::<Result<Vec<_>, _>>()?;
            rows
        };
        let full_page = rows.len() == 500;
        let last = rows.last().map(|r| r.id.clone());
        data.extend(rows.iter().filter(|r| q.status.as_deref().is_none_or(|s| r.effective_status() == s)).map(|r| to_json(&st, r)));
        if data.len() > limit as usize || !full_page {
            break;
        }
        cursor = last;
    }
    let has_more = data.len() > limit as usize;
    data.truncate(limit as usize);
    Ok(Json(json!({ "object": "list", "data": data, "has_more": has_more })))
}

pub async fn get_request(State(st): State<Shared>, auth: Auth, Path(id): Path<String>) -> Result<Json<Value>, ApiError> {
    Ok(Json(to_json(&st, &load(&st, Some(auth.mode), &id)?)))
}

/// Verifies `text` against request `r` and records it. Shared by the API and the hosted page.
pub async fn accept_receipt(st: &Shared, mode: Mode, r: &RequestRec, text: &str) -> Result<Value, ApiError> {
    match r.effective_status() {
        "fulfilled" | "held_for_review" | "rejected" => {
            return Err(ApiError::conflict("request_already_fulfilled", format!("{} was already {}", r.id, r.status)))
        }
        "expired" => return Err(ApiError::conflict("request_expired", format!("{} expired", r.id))),
        _ => {}
    }
    let net = mode.net(&st.config);
    let checked = async {
        let v = if sandbox::is_fixture(text) {
            if mode != Mode::Test {
                return Err(ApiError::invalid("receipt_network_mismatch", "sandbox fixtures only work with rcpt_test_ keys").param("receipt"));
            }
            let want = if r.kind == "single" { r.amount.map(|a| a as u64) } else { r.amount.map(|a| (a - r.received).max(1) as u64) };
            let mut v = sandbox::resolve(text, Some(&r.payee), want, Some(&r.challenge))?;
            if let Some(cid) = &r.test_clock {
                // On a test clock the payment is mined "now", with no confirmations yet.
                let clock = crate::clocks::load(st, cid)?;
                v.mined_height = clock.height as u32;
                let (verdict, checks) = verify::levels(v.mined_height, Some(v.mined_height), v.outputs.len(), 1, v.challenge.as_deref(), None, 0);
                v.verdict = verdict;
                v.checks = checks;
            }
            v
        } else {
            verify::verify_receipt(net, mode.server(&st.config).as_deref(), text).await?
        };
        if v.challenge.as_deref() != Some(r.challenge.as_str()) {
            return Err(ApiError::verification(
                "challenge_mismatch",
                "this receipt was made for another order: make it again with this page's command, which signs this order's code",
            ));
        }
        let mut v = v;
        v.checks["challenge"] = "matched".into();
        // The block height at creation is fetched in the background; until it is known, an old payment
        // could be shown again, so a real receipt waits for it (fixtures and test clocks have none).
        if !sandbox::is_fixture(text) && r.test_clock.is_none() && r.created_height.is_none() {
            return Err(ApiError::conflict("request_not_ready", "this request's creation height isn't recorded yet (the chain server was slow); retry in a few seconds"));
        }
        if !sandbox::is_fixture(text) && r.created_height.is_some_and(|h| i64::from(v.mined_height) <= h) {
            return Err(ApiError::verification(
                "paid_before_request",
                format!("the payment was mined at block {}, before this request was made (block {})", v.mined_height, r.created_height.unwrap()),
            ));
        }
        if v.public_demo {
            return Err(ApiError::verification(
                "public_demo_key",
                "this receipt is from the public demo wallet, whose key anyone has; it proves nothing about who paid",
            ));
        }
        let want = zceipt_chain::chain::orchard_receiver_of(&r.payee).map_err(|e| ApiError::internal(e.to_string()))?;
        // Outputs disclosed with the memo withheld (format v5) prove the recipient and amount but
        // not that the recipient's wallet can decrypt and spend the note, so they don't settle.
        let outs: Vec<&verify::Output> = v.outputs.iter().filter(|o| o.recipient_raw == want && !o.memo_withheld).collect();
        let paid: u64 = outs.iter().map(|o| o.zatoshis).sum();
        if paid == 0 && v.outputs.iter().any(|o| o.recipient_raw == want && o.memo_withheld) {
            return Err(ApiError::verification(
                "delivery_unproven",
                "the output to the payee was disclosed with its memo withheld, which doesn't show the note can be received; disclose it with its memo",
            ));
        }
        if paid == 0 {
            return Err(ApiError::verification("wrong_payee", "no disclosed output paid the request's payee"));
        }
        if r.kind == "single" && r.amount.is_some_and(|a| paid < a as u64) {
            return Err(ApiError::verification("insufficient_amount", format!("paid {paid} zatoshis, the request asks for {}", r.amount.unwrap())));
        }
        let actions: Vec<(u32, u64)> = outs.iter().map(|o| (o.action, o.zatoshis)).collect();
        // Deposit desks: the receipt must prove where every spent note came from; then screen it.
        let provenance = match r.source_policy.as_deref() {
            None => None,
            Some(p) => {
                // What earlier credited deposits already claimed from each source transaction.
                let prior = {
                    let c = st.db.0.lock().unwrap();
                    crate::deposits::prior_claims(&c, &r.id)
                };
                Some(crate::deposits::evaluate(p, &v, paid, &prior)?)
            }
        };
        Ok((v, paid, actions, provenance))
    }
    .await;
    let (v, paid, actions, provenance) = match checked {
        Ok(x) => x,
        Err(e) => {
            if e.kind == "verification_error" {
                let _ = emit(st, mode, "receipt.rejected", json!({ "object": "receipt_rejection", "request": r.id, "error": e.body()["error"] }));
            }
            return Err(e);
        }
    };

    // Record the payment atomically: each (txid, output) counts for one request only.
    let (received, fulfilled) = {
        let mut c = st.db.0.lock().unwrap();
        let tx = c.transaction()?;
        // Re-read the request inside the transaction: another submission may have settled it
        // (or added to it) while this one was being verified.
        let (status_now, received_now): (String, i64) =
            tx.query_row("SELECT status, received_zatoshis FROM requests WHERE id = ?1", [&r.id], |x| Ok((x.get(0)?, x.get(1)?)))?;
        if status_now != "open" {
            drop(tx);
            drop(c);
            return Err(ApiError::conflict("request_already_fulfilled", format!("{} was already {status_now}", r.id)));
        }
        // The source-of-funds coverage was computed before this transaction; a deposit credited
        // meanwhile from the same source transaction would make both clear. Recount under the
        // transaction (writers are serialized) and refuse if the funding no longer covers this one.
        // `evaluate` reports a coverage failure as `Ok` with status "review", not as an error, so the
        // recount's own result decides whether the deposit is held (the earlier one is stale).
        let provenance = match r.source_policy.as_deref() {
            Some(p) => {
                let prior = crate::deposits::prior_claims(&tx, &r.id);
                match crate::deposits::evaluate(p, &v, paid, &prior) {
                    Ok(now) => Some(now),
                    Err(e) => {
                        drop(tx);
                        drop(c);
                        return Err(e);
                    }
                }
            }
            None => provenance.clone(),
        };
        for (action, _) in &actions {
            let used: Option<String> = tx
                .query_row("SELECT request_id FROM payments_used WHERE mode = ?1 AND txid = ?2 AND action = ?3", params![mode.as_str(), v.txid, action], |x| {
                    x.get(0)
                })
                .optional()?;
            if let Some(other) = used {
                let msg = if other == r.id {
                    "this payment was already counted for this request".to_string()
                } else {
                    "this payment was already used to settle another request".to_string()
                };
                drop(tx);
                drop(c);
                let e = ApiError::conflict("payment_already_used", msg).param("receipt");
                let _ = emit(st, mode, "receipt.rejected", json!({ "object": "receipt_rejection", "request": r.id, "error": e.body()["error"] }));
                return Err(e);
            }
        }
        for (action, z) in &actions {
            tx.execute(
                "INSERT INTO payments_used (mode, txid, action, request_id, zatoshis, created) VALUES (?1,?2,?3,?4,?5,?6)",
                params![mode.as_str(), v.txid, action, r.id, *z as i64, now()],
            )?;
        }
        let memo =
            v.outputs.iter().find(|o| o.recipient_raw == zceipt_chain::chain::orchard_receiver_of(&r.payee).unwrap_or([0; 43])).and_then(|o| o.memo.clone());
        // A public note only if the contributor signed one into the receipt.
        let public_note = v.message.lines().find_map(|l| l.strip_prefix("public-note:")).map(|s| s.trim().chars().take(140).collect::<String>());
        // A refund address only if the payer signed one into the receipt.
        let refund_address = crate::refunds::checked_refund_address(st, mode, &v.message);
        tx.execute(
            "INSERT INTO request_payments (request_id, txid, zatoshis, mined_height, memo, sender_addresses, created, public_note, refund_address) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9)",
            params![r.id, v.txid, paid as i64, v.mined_height, memo, serde_json::to_string(&v.sender_addresses).unwrap(), now(), public_note, refund_address],
        )?;
        let received = received_now + paid as i64;
        let fulfilled = match r.kind.as_str() {
            "campaign" => false,
            "partial" => r.amount.is_some_and(|a| received >= a),
            _ => true,
        };
        // A deposit whose funding failed screening is held for the desk's review, not credited.
        let held = provenance.as_ref().is_some_and(|p| p["status"] != "cleared");
        if fulfilled {
            tx.execute(
                "UPDATE requests SET status = ?7, fulfilled_at = ?1, txid = ?2, paid_zatoshis = ?3, received_zatoshis = ?3, receipt = ?4, verification = ?5, provenance = ?8 WHERE id = ?6",
                params![r.clock_time.unwrap_or_else(now), v.txid, received, text, serde_json::to_string(&v).unwrap(), r.id, if held { "held_for_review" } else { "fulfilled" }, provenance.as_ref().map(|p| p.to_string())],
            )?;
        } else {
            tx.execute("UPDATE requests SET received_zatoshis = ?1 WHERE id = ?2", params![received, r.id])?;
        }
        tx.commit()?;
        (received, fulfilled)
    };
    let obj = to_json(st, &load(st, Some(mode), &r.id)?);
    if r.kind != "single" {
        emit(
            st,
            mode,
            "request.payment_received",
            json!({ "object": "payment", "request": r.id, "txid": v.txid, "zatoshis": paid, "received_zatoshis": received }),
        )?;
    }
    if fulfilled && obj["status"] == "held_for_review" {
        emit(st, mode, "request.held_for_review", obj.clone())?;
        return Ok(obj);
    }
    if fulfilled {
        emit(st, mode, "request.fulfilled", obj.clone())?;
        // Sandbox payments off a test clock are final at once; real ones wait for the sweeper.
        if sandbox::is_fixture(text) && r.test_clock.is_none() {
            crate::clocks::mark_final(st, mode, &r.id)?;
            return Ok(to_json(st, &load(st, Some(mode), &r.id)?));
        }
    }
    Ok(obj)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SubmitReceipt {
    receipt: Option<String>,
    #[serde(alias = "secret")]
    client_secret: Option<String>,
}

pub async fn submit_receipt(State(st): State<Shared>, auth: Auth, headers: HeaderMap, Path(id): Path<String>, Body(req, raw): Body<SubmitReceipt>) -> Response {
    let st2 = st.clone();
    let mode = auth.mode;
    let route = format!("POST /v1/requests/{id}/receipts");
    idempotent(&st, &auth, &headers, &route, &raw, || async move {
        let text = req.receipt.ok_or_else(|| ApiError::missing("receipt"))?;
        let r = load(&st2, Some(mode), &id)?;
        Ok((StatusCode::OK, accept_receipt(&st2, mode, &r, &text).await?))
    })
    .await
}

/// The request's ZIP-321 payment URI as an SVG QR code.
pub async fn request_qr(State(st): State<Shared>, auth: Auth, Path(id): Path<String>) -> Result<Response, ApiError> {
    qr_for(&st, &load(&st, Some(auth.mode), &id)?)
}

fn qr_for(st: &AppState, r: &RequestRec) -> Result<Response, ApiError> {
    let uri = to_json(st, r)["payment_uri"].as_str().unwrap_or_default().to_string();
    let code = qrcode::QrCode::with_error_correction_level(uri.as_bytes(), qrcode::EcLevel::M).map_err(|e| ApiError::internal(e.to_string()))?;
    let svg = code.render::<qrcode::render::svg::Color>().min_dimensions(240, 240).quiet_zone(true).build();
    Ok(([("content-type", "image/svg+xml")], svg).into_response())
}

// ---------- hosted pages (no API key; a per-request client secret) ----------

fn mode_of(r: &RequestRec) -> Mode {
    if r.mode == "live" {
        Mode::Live
    } else {
        Mode::Test
    }
}

fn check_secret(r: &RequestRec, secret: Option<&str>) -> Result<(), ApiError> {
    match (&r.client_secret, secret) {
        (Some(s), Some(given)) if crate::ct_eq(s.as_bytes(), given.as_bytes()) => Ok(()),
        _ => Err(ApiError::not_found("request_not_found", "unknown request or wrong client secret")),
    }
}

#[derive(Deserialize)]
pub struct SecretQuery {
    secret: Option<String>,
}

/// What a payer may see: never metadata or other payers' details.
fn public_view(st: &AppState, r: &RequestRec) -> Value {
    let full = to_json(st, r);
    json!({
        "id": r.id, "kind": r.kind, "status": full["status"], "label": r.label, "payee": r.payee,
        "amount_zatoshis": r.amount, "received_zatoshis": r.received, "remaining_zatoshis": full["remaining_zatoshis"],
        "payment_uri": full["payment_uri"], "receipt_link": full["receipt_link"], "cli_command": full["cli_command"],
        "livemode": r.mode == "live", "expires_at": r.expires_at,
        "source_of_funds": crate::deposits::policy_summary(r.source_policy.as_deref()),
    })
}

/// The client secret from the `Zceipt-Client-Secret` header (the hosted page sends it there,
/// so it stays out of access logs), else from `?secret=` (older clients and the SDKs).
fn secret_of<'a>(headers: &'a axum::http::HeaderMap, q: &'a SecretQuery) -> Option<&'a str> {
    headers.get("zceipt-client-secret").and_then(|v| v.to_str().ok()).or(q.secret.as_deref())
}

pub async fn public_get(
    State(st): State<Shared>,
    Path(id): Path<String>,
    headers: axum::http::HeaderMap,
    Query(q): Query<SecretQuery>,
) -> Result<Json<Value>, ApiError> {
    let r = load(&st, None, &id)?;
    check_secret(&r, secret_of(&headers, &q))?;
    Ok(Json(public_view(&st, &r)))
}

pub async fn public_qr(
    State(st): State<Shared>,
    Path(id): Path<String>,
    headers: axum::http::HeaderMap,
    Query(q): Query<SecretQuery>,
) -> Result<Response, ApiError> {
    let r = load(&st, None, &id)?;
    if r.kind != "campaign" {
        check_secret(&r, secret_of(&headers, &q))?;
    }
    qr_for(&st, &r)
}

pub async fn public_submit(State(st): State<Shared>, Path(id): Path<String>, Body(req, _): Body<SubmitReceipt>) -> Result<Json<Value>, ApiError> {
    let r = load(&st, None, &id)?;
    if r.kind != "campaign" {
        check_secret(&r, req.client_secret.as_deref())?;
    }
    let text = req.receipt.ok_or_else(|| ApiError::missing("receipt"))?;
    accept_receipt(&st, mode_of(&r), &r, &text).await?;
    let r = load(&st, None, &id)?;
    Ok(Json(public_view(&st, &r)))
}

/// Public campaign tally: aggregate-only (see the module docs for why).
pub async fn campaign_json(State(st): State<Shared>, Path(id): Path<String>) -> Result<Json<Value>, ApiError> {
    let r = load(&st, None, &id)?;
    if r.kind != "campaign" {
        return Err(ApiError::not_found("request_not_found", "not a campaign"));
    }
    let (snapshot, snapshot_at, k): (Option<String>, Option<i64>, i64) = {
        let c = st.db.0.lock().unwrap();
        c.query_row("SELECT snapshot, snapshot_at, public_k FROM requests WHERE id = ?1", [&id], |x| Ok((x.get(0)?, x.get(1)?, x.get(2)?)))?
    };
    let fresh = snapshot_at.is_some_and(|t| now() - t < st.config.campaign_snapshot_secs);
    let snap: Value = match (fresh, snapshot.as_deref().and_then(|s| serde_json::from_str(s).ok())) {
        (true, Some(s)) => s,
        _ => {
            let (count, total, mut notes): (i64, i64, Vec<String>) = {
                let c = st.db.0.lock().unwrap();
                let (count, total) = c.query_row("SELECT COUNT(*), COALESCE(SUM(zatoshis), 0) FROM request_payments WHERE request_id = ?1", [&id], |x| {
                    Ok((x.get(0)?, x.get(1)?))
                })?;
                let mut stmt = c.prepare("SELECT public_note FROM request_payments WHERE request_id = ?1 AND public_note IS NOT NULL")?;
                let notes = stmt.query_map([&id], |x| x.get::<_, String>(0))?.collect::<Result<Vec<_>, _>>()?;
                (count, total, notes)
            };
            // Shuffle so the order of notes doesn't reveal the order of contributions.
            for i in (1..notes.len()).rev() {
                let mut b = [0u8; 8];
                getrandom::fill(&mut b).expect("OS RNG");
                notes.swap(i, (u64::from_le_bytes(b) % (i as u64 + 1)) as usize);
            }
            let visible = count >= k;
            let s = json!({
                "visible": visible,
                "contributions": if visible { json!(count) } else { Value::Null },
                // Rounded down to 0.001 ZEC so a total can't be diffed back to one exact amount.
                "received_zatoshis_rounded": if visible { json!((total / 100_000) * 100_000) } else { Value::Null },
                "public_notes": if visible { json!(notes) } else { json!([]) },
                "as_of": now(),
            });
            let c = st.db.0.lock().unwrap();
            c.execute("UPDATE requests SET snapshot = ?1, snapshot_at = ?2 WHERE id = ?3", params![s.to_string(), now(), id])?;
            s
        }
    };
    let full = to_json(&st, &r);
    Ok(Json(json!({
        "id": r.id, "object": "campaign", "label": r.label, "payee": r.payee, "goal_zatoshis": r.amount,
        "min_contributions_to_publish": k,
        "refresh_secs": st.config.campaign_snapshot_secs,
        "tally": snap,
        "payment_uri": full["payment_uri"], "receipt_link": full["receipt_link"], "livemode": r.mode == "live",
    })))
}

pub async fn pay_page() -> Html<&'static str> {
    Html(include_str!("../../../docs/pay.html"))
}

pub async fn campaign_page() -> Html<&'static str> {
    Html(include_str!("../../../docs/campaign.html"))
}

/// Marks overdue open requests expired and emits `request.expired` once each.
pub async fn expiry_sweeper(st: Shared) {
    loop {
        let due: Option<Vec<(String, String)>> = {
            let c = st.db.0.lock().unwrap();
            let stmt = match c.prepare("SELECT id, mode FROM requests WHERE status = 'open' AND expires_at IS NOT NULL AND expires_at <= ?1 AND expired_notified = 0 AND test_clock IS NULL") {
                Ok(s) => Some(s),
                Err(_) => None,
            };
            stmt.map(|mut stmt| stmt.query_map([now()], |r| Ok((r.get(0)?, r.get(1)?))).map(|x| x.filter_map(Result::ok).collect()).unwrap_or_default())
        };
        // A failing query (a missing column, say) must not turn this loop into a spin.
        let Some(due) = due else {
            tokio::time::sleep(std::time::Duration::from_secs(5)).await;
            continue;
        };
        for (id, mode) in due {
            {
                let c = st.db.0.lock().unwrap();
                let _ = c.execute("UPDATE requests SET status = 'expired', expired_notified = 1 WHERE id = ?1 AND status = 'open'", [&id]);
            }
            let m = if mode == "live" { Mode::Live } else { Mode::Test };
            if let Ok(r) = load(&st, Some(m), &id) {
                let _ = emit(&st, m, "request.expired", to_json(&st, &r));
            }
        }
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    }
}
