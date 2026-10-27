//! Refunds with proof in both directions.
//!
//! A payer can sign `refund-to:<address>` into their receipt. Only whoever authorized the
//! payment can write that line, so the merchant learns an authenticated refund address
//! without asking. The merchant then creates a refund (a ZIP-321 link to that address with
//! its own challenge) and settles it with a receipt for the refund payment, so both sides
//! end up with proof: the payer that they paid, the merchant that they paid back.

use crate::{
    check_payee,
    db::{new_id, now},
    emit,
    error::ApiError,
    idempotent,
    requests::load,
    sandbox, urlenc, verify, zec, AppState, Auth, Body, Mode, Shared,
};
use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::Response,
    Json,
};
use rusqlite::{params, OptionalExtension};
use serde::Deserialize;
use serde_json::{json, Value};

/// The refund address a payer signed into their receipt, if any.
pub fn refund_address_of(message: &str) -> Option<String> {
    message.lines().find_map(|l| l.strip_prefix("refund-to:")).map(|s| s.trim().to_string()).filter(|s| !s.is_empty() && s.len() < 1000)
}

struct RefundRec {
    id: String,
    mode: String,
    request_id: String,
    payment_txid: String,
    address: String,
    amount: i64,
    reason: Option<String>,
    challenge: String,
    status: String,
    created: i64,
    refunded_at: Option<i64>,
    txid: Option<String>,
    created_height: Option<i64>,
}

const COLS: &str = "id, mode, request_id, payment_txid, address, amount_zatoshis, reason, challenge, status, created, refunded_at, txid, created_height";

fn from_row(r: &rusqlite::Row) -> rusqlite::Result<RefundRec> {
    Ok(RefundRec {
        id: r.get(0)?,
        mode: r.get(1)?,
        request_id: r.get(2)?,
        payment_txid: r.get(3)?,
        address: r.get(4)?,
        amount: r.get(5)?,
        reason: r.get(6)?,
        challenge: r.get(7)?,
        status: r.get(8)?,
        created: r.get(9)?,
        refunded_at: r.get(10)?,
        txid: r.get(11)?,
        created_height: r.get(12)?,
    })
}

fn to_json(r: &RefundRec) -> Value {
    let memo = format!("Refund {} for {}", r.id, r.request_id);
    let uri = format!(
        "zcash:{}?amount={}&memo={}&message={}",
        r.address,
        zec(r.amount as u64),
        base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, memo.as_bytes()),
        urlenc(&memo)
    );
    json!({
        "id": r.id,
        "object": "refund",
        "livemode": r.mode == "live",
        "request": r.request_id,
        "payment_txid": r.payment_txid,
        "address": r.address,
        "amount_zatoshis": r.amount,
        "reason": r.reason,
        "challenge": r.challenge,
        "status": r.status,
        "created": r.created,
        "payment_uri": uri,
        "cli_command": format!("zceipt create --seed-stdin --network <main|test> --birthday <wallet birthday> --txid <refund txid> --msg 'challenge:{}'", r.challenge),
        "refunded_at": r.refunded_at,
        "txid": r.txid,
    })
}

fn load_refund(st: &AppState, mode: Mode, id: &str) -> Result<RefundRec, ApiError> {
    let c = st.db.0.lock().unwrap();
    c.query_row(&format!("SELECT {COLS} FROM refunds WHERE id = ?1 AND mode = ?2"), params![id, mode.as_str()], from_row)
        .optional()?
        .ok_or_else(|| ApiError::not_found("refund_not_found", format!("no refund {id} for this key's mode")))
}

/// Refunds of a request, for the request object.
pub fn refunds_of(st: &AppState, request_id: &str) -> Vec<Value> {
    let c = st.db.0.lock().unwrap();
    let Ok(mut stmt) = c.prepare(&format!("SELECT {COLS} FROM refunds WHERE request_id = ?1 ORDER BY created, id")) else { return vec![] };
    stmt.query_map([request_id], from_row).map(|rows| rows.filter_map(Result::ok).map(|r| to_json(&r)).collect()).unwrap_or_default()
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateRefund {
    /// Which payment to refund (its txid). Default: the request's latest payment with a refund address.
    payment_txid: Option<String>,
    /// Default: what is left of that payment after earlier refunds.
    amount_zatoshis: Option<u64>,
    reason: Option<String>,
}

/// POST /v1/requests/{id}/refunds
pub async fn create(State(st): State<Shared>, auth: Auth, headers: HeaderMap, Path(id): Path<String>, Body(req, raw): Body<CreateRefund>) -> Response {
    let st2 = st.clone();
    let mode = auth.mode;
    let route = format!("POST /v1/requests/{id}/refunds");
    idempotent(&st, &auth, &headers, &route, &raw, || async move {
        let r = load(&st2, Some(mode), &id)?;
        if req.reason.as_ref().is_some_and(|x| x.len() > 200) {
            return Err(ApiError::invalid("parameter_invalid", "reason is longer than 200 characters").param("reason"));
        }
        let refund_id = new_id("rf_");
        let mut ch = [0u8; 8];
        getrandom::fill(&mut ch).expect("OS RNG");
        let challenge = hex::encode(ch);
        {
            let mut c = st2.db.0.lock().unwrap();
            let tx = c.transaction()?;
            let payment: Option<(String, i64, Option<String>)> = tx
                .query_row(
                    "SELECT txid, zatoshis, refund_address FROM request_payments WHERE request_id = ?1 AND (?2 IS NULL OR txid = ?2) ORDER BY (refund_address IS NULL), id DESC LIMIT 1",
                    params![r.id, req.payment_txid],
                    |x| Ok((x.get(0)?, x.get(1)?, x.get(2)?)),
                )
                .optional()?;
            let (txid, paid, address) = payment.ok_or_else(|| match &req.payment_txid {
                Some(_) => ApiError::not_found("payment_not_found", "no payment with that txid on this request").param("payment_txid"),
                None => ApiError::conflict("refund_not_possible", "this request has no payments yet"),
            })?;
            let address = address.ok_or_else(|| {
                ApiError::conflict("refund_address_missing", "the payer did not sign a refund address into their receipt (`zceipt create --refund-to <address>`)")
            })?;
            let already: i64 = tx.query_row(
                "SELECT COALESCE(SUM(amount_zatoshis), 0) FROM refunds WHERE request_id = ?1 AND payment_txid = ?2",
                params![r.id, txid],
                |x| x.get(0),
            )?;
            let left = paid - already;
            let amount = req.amount_zatoshis.map(|a| a as i64).unwrap_or(left);
            if amount <= 0 || amount > left {
                return Err(ApiError::invalid("refund_amount_invalid", format!("this payment has {left} zatoshis left to refund")).param("amount_zatoshis"));
            }
            tx.execute(
                "INSERT INTO refunds (id, mode, request_id, payment_txid, address, amount_zatoshis, reason, challenge, status, created) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,'pending',?9)",
                params![refund_id, mode.as_str(), r.id, txid, address, amount, req.reason, challenge, now()],
            )?;
            tx.commit()?;
        }
        // The tip now, fetched in the background (retried): the settling payment must be mined after it,
        // so an older payment to the same address cannot settle this refund.
        {
            let (st3, rid) = (st2.clone(), refund_id.clone());
            tokio::spawn(async move {
                let net = mode.net(&st3.config);
                let server = mode.server(&st3.config);
                for attempt in 0..4u64 {
                    if let Ok(Ok(tip)) = tokio::time::timeout(std::time::Duration::from_secs(20), zceipt_chain::chain::chain_tip(net, server.as_deref())).await {
                        let c = st3.db.0.lock().unwrap();
                        let _ = c.execute("UPDATE refunds SET created_height = ?1 WHERE id = ?2 AND created_height IS NULL", params![tip as i64, rid]);
                        break;
                    }
                    tokio::time::sleep(std::time::Duration::from_secs(5 * (attempt + 1))).await;
                }
            });
        }
        let obj = to_json(&load_refund(&st2, mode, &refund_id)?);
        emit(&st2, mode, "refund.created", obj.clone())?;
        Ok((StatusCode::CREATED, obj))
    })
    .await
}

/// GET /v1/refunds/{id}
pub async fn get(State(st): State<Shared>, auth: Auth, Path(id): Path<String>) -> Result<Json<Value>, ApiError> {
    Ok(Json(to_json(&load_refund(&st, auth.mode, &id)?)))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SubmitRefundReceipt {
    receipt: Option<String>,
}

/// POST /v1/refunds/{id}/receipts — settles a refund with a receipt for the refund payment.
pub async fn submit(State(st): State<Shared>, auth: Auth, headers: HeaderMap, Path(id): Path<String>, Body(req, raw): Body<SubmitRefundReceipt>) -> Response {
    let st2 = st.clone();
    let mode = auth.mode;
    let route = format!("POST /v1/refunds/{id}/receipts");
    idempotent(&st, &auth, &headers, &route, &raw, || async move {
        let text = req.receipt.ok_or_else(|| ApiError::missing("receipt"))?;
        let rf = load_refund(&st2, mode, &id)?;
        if rf.status == "succeeded" {
            return Err(ApiError::conflict("refund_already_succeeded", format!("{} was already settled", rf.id)));
        }
        let v = if sandbox::is_fixture(&text) {
            if mode != Mode::Test {
                return Err(ApiError::invalid("receipt_network_mismatch", "sandbox fixtures only work with rcpt_test_ keys").param("receipt"));
            }
            sandbox::resolve(&text, Some(&rf.address), Some(rf.amount as u64), Some(&rf.challenge))?
        } else {
            verify::verify_receipt(mode.net(&st2.config), mode.server(&st2.config).as_deref(), &text).await?
        };
        if v.challenge.as_deref() != Some(rf.challenge.as_str()) {
            return Err(ApiError::verification("challenge_mismatch", "the receipt does not sign this refund's challenge"));
        }
        if !sandbox::is_fixture(&text) {
            match rf.created_height {
                None => return Err(ApiError::conflict("refund_not_ready", "this refund's creation height isn't recorded yet (the chain server was slow); retry in a few seconds")),
                Some(h) if i64::from(v.mined_height) <= h => {
                    return Err(ApiError::verification(
                        "paid_before_refund",
                        format!("the payment was mined at block {}, before this refund was made (block {h})", v.mined_height),
                    ))
                }
                Some(_) => {}
            }
        }
        let want = zceipt_chain::chain::orchard_receiver_of(&rf.address).map_err(|e| ApiError::internal(e.to_string()))?;
        // Outputs disclosed with the memo withheld (format v5) prove the recipient and amount but
        // not that the recipient's wallet can decrypt and spend the note, so they don't settle.
        let outs: Vec<&verify::Output> = v.outputs.iter().filter(|o| o.recipient_raw == want && !o.memo_withheld).collect();
        let paid: u64 = outs.iter().map(|o| o.zatoshis).sum();
        if paid == 0 && v.outputs.iter().any(|o| o.recipient_raw == want && o.memo_withheld) {
            return Err(ApiError::verification(
                "delivery_unproven",
                "the output to the refund address was disclosed with its memo withheld, which doesn't show the note can be received; disclose it with its memo",
            ));
        }
        if paid == 0 {
            return Err(ApiError::verification("wrong_payee", "no disclosed output paid the refund address"));
        }
        if paid < rf.amount as u64 {
            return Err(ApiError::verification("insufficient_amount", format!("refunded {paid} zatoshis, the refund is for {}", rf.amount)));
        }
        {
            let mut c = st2.db.0.lock().unwrap();
            let tx = c.transaction()?;
            // Settled by a concurrent submission while this receipt was being verified?
            let status_now: String = tx.query_row("SELECT status FROM refunds WHERE id = ?1", [&rf.id], |x| x.get(0))?;
            if status_now != "pending" {
                return Err(ApiError::conflict("refund_already_succeeded", format!("{} was already settled", rf.id)));
            }
            for o in &outs {
                let used: Option<String> = tx
                    .query_row(
                        "SELECT request_id FROM payments_used WHERE mode = ?1 AND txid = ?2 AND action = ?3",
                        params![mode.as_str(), v.txid, o.action],
                        |x| x.get(0),
                    )
                    .optional()?;
                if used.is_some() {
                    return Err(ApiError::conflict("payment_already_used", "this payment was already used to settle something else").param("receipt"));
                }
                tx.execute(
                    "INSERT INTO payments_used (mode, txid, action, request_id, zatoshis, created) VALUES (?1,?2,?3,?4,?5,?6)",
                    params![mode.as_str(), v.txid, o.action, rf.id, o.zatoshis as i64, now()],
                )?;
            }
            tx.execute(
                "UPDATE refunds SET status = 'succeeded', refunded_at = ?1, txid = ?2, receipt = ?3, verification = ?4 WHERE id = ?5",
                params![now(), v.txid, text, serde_json::to_string(&v).unwrap(), rf.id],
            )?;
            tx.commit()?;
        }
        let obj = to_json(&load_refund(&st2, mode, &id)?);
        emit(&st2, mode, "refund.succeeded", obj.clone())?;
        Ok((StatusCode::OK, obj))
    })
    .await
}

/// Validates a signed refund address against the key's network; invalid ones are ignored.
pub fn checked_refund_address(st: &AppState, mode: Mode, message: &str) -> Option<String> {
    refund_address_of(message).filter(|a| check_payee(mode.net(&st.config), a).is_ok())
}
