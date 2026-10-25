//! Sandbox test clocks and payment finality.
//!
//! A test clock is a frozen time and block height that requests can run on. Advancing it fires
//! the same events real time would (`request.expired`, `request.final`), so an integration can
//! test expiry and the 10-confirmation finality path in seconds instead of hours.
//!
//! Real requests become final when the chain tip is FINALITY_CONFIRMATIONS past the payment;
//! `finality_sweeper` checks that and emits `request.final`.

use crate::{
    db::{new_id, now},
    emit,
    error::ApiError,
    requests::{load as load_request, to_json},
    AppState, Auth, Body, Mode, Shared,
};
use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};
use receipts_chain::chain::{self, FINALITY_CONFIRMATIONS};
use rusqlite::{params, OptionalExtension};
use serde::Deserialize;
use serde_json::{json, Value};

pub struct Clock {
    pub id: String,
    pub frozen_time: i64,
    pub height: i64,
    pub created: i64,
}

pub fn load(st: &AppState, id: &str) -> Result<Clock, ApiError> {
    let c = st.db.0.lock().unwrap();
    c.query_row("SELECT id, frozen_time, height, created FROM test_clocks WHERE id = ?1", [id], |r| {
        Ok(Clock { id: r.get(0)?, frozen_time: r.get(1)?, height: r.get(2)?, created: r.get(3)? })
    })
    .optional()?
    .ok_or_else(|| ApiError::not_found("test_clock_not_found", format!("no test clock {id}")).param("test_clock"))
}

fn clock_json(st: &AppState, k: &Clock) -> Value {
    let requests: Vec<String> = {
        let c = st.db.0.lock().unwrap();
        c.prepare("SELECT id FROM requests WHERE test_clock = ?1 ORDER BY created, id")
            .and_then(|mut s| s.query_map([&k.id], |r| r.get(0))?.collect())
            .unwrap_or_default()
    };
    json!({ "id": k.id, "object": "test_clock", "livemode": false, "frozen_time": k.frozen_time, "height": k.height, "created": k.created, "requests": requests })
}

fn test_only(auth: &Auth) -> Result<(), ApiError> {
    if auth.mode != Mode::Test {
        return Err(ApiError::invalid("livemode_not_allowed", "test clocks only exist in test mode; use an rcpt_test_ key"));
    }
    Ok(())
}

#[derive(Deserialize)]
pub struct CreateClock {
    frozen_time: Option<i64>,
    height: Option<i64>,
}

/// POST /v1/test_clocks
pub async fn create(State(st): State<Shared>, auth: Auth, Body(req, _): Body<CreateClock>) -> Result<(StatusCode, Json<Value>), ApiError> {
    test_only(&auth)?;
    let id = new_id("clock_");
    let t = req.frozen_time.unwrap_or_else(now);
    let h = req.height.unwrap_or(4_500_000);
    if !(1..=100_000_000).contains(&h) {
        return Err(ApiError::invalid("parameter_invalid", "height must be 1 to 100,000,000").param("height"));
    }
    if !(0..=32_503_680_000).contains(&t) {
        return Err(ApiError::invalid("parameter_invalid", "frozen_time must be a unix time between 1970 and 3000").param("frozen_time"));
    }
    st.db.0.lock().unwrap().execute("INSERT INTO test_clocks (id, frozen_time, height, created) VALUES (?1,?2,?3,?4)", params![id, t, h, now()])?;
    Ok((StatusCode::CREATED, Json(clock_json(&st, &load(&st, &id)?))))
}

/// GET /v1/test_clocks/{id}
pub async fn get(State(st): State<Shared>, auth: Auth, Path(id): Path<String>) -> Result<Json<Value>, ApiError> {
    test_only(&auth)?;
    Ok(Json(clock_json(&st, &load(&st, &id)?)))
}

#[derive(Deserialize)]
pub struct Advance {
    /// Seconds to move time forward.
    seconds: Option<i64>,
    /// Blocks to mine (each also moves time by 75 s, the target spacing, unless `seconds` is given).
    blocks: Option<i64>,
}

/// POST /v1/test_clocks/{id}/advance — moves the clock, then fires every event that became due.
pub async fn advance(State(st): State<Shared>, auth: Auth, Path(id): Path<String>, Body(req, _): Body<Advance>) -> Result<Json<Value>, ApiError> {
    test_only(&auth)?;
    let blocks = req.blocks.unwrap_or(0);
    if !(0..=1_000_000).contains(&blocks) {
        return Err(ApiError::invalid("parameter_invalid", "blocks must be 0 to 1,000,000").param("blocks"));
    }
    let seconds = req.seconds.unwrap_or(blocks * 75);
    if !(0..=10 * 366 * 86_400).contains(&seconds) || (seconds == 0 && blocks == 0) {
        return Err(ApiError::invalid("parameter_invalid", "advance by up to 10 years and/or 1,000,000 blocks, and by something"));
    }
    let k = load(&st, &id)?;
    let (t, h) = (k.frozen_time + seconds, k.height + blocks);
    st.db.0.lock().unwrap().execute("UPDATE test_clocks SET frozen_time = ?1, height = ?2 WHERE id = ?3", params![t, h, id])?;

    let mut fired = Vec::new();
    // Payments dropped by a simulated reorg are mined again in the next block.
    if blocks > 0 {
        st.db.0.lock().unwrap().execute(
            "UPDATE request_payments SET mined_height = ?1 WHERE mined_height IS NULL AND request_id IN (SELECT id FROM requests WHERE test_clock = ?2)",
            params![k.height + 1, id],
        )?;
    }
    // Expiry, by clock time.
    let expired: Vec<String> = {
        let c = st.db.0.lock().unwrap();
        let rows = c
            .prepare(
                "SELECT id FROM requests WHERE test_clock = ?1 AND status = 'open' AND expires_at IS NOT NULL AND expires_at <= ?2 AND expired_notified = 0",
            )?
            .query_map(params![id, t], |r| r.get(0))?
            .collect::<Result<Vec<String>, _>>()?;
        rows
    };
    for rid in expired {
        st.db.0.lock().unwrap().execute("UPDATE requests SET status = 'expired', expired_notified = 1 WHERE id = ?1 AND status = 'open'", [&rid])?;
        let ev = emit(&st, Mode::Test, "request.expired", to_json(&st, &load_request(&st, Some(Mode::Test), &rid)?))?;
        fired.push(json!({ "type": "request.expired", "request": rid, "event": ev["id"] }));
    }
    // Finality, by clock height.
    let due: Vec<String> = {
        let c = st.db.0.lock().unwrap();
        let rows = c
            .prepare(
                "SELECT r.id FROM requests r WHERE r.test_clock = ?1 AND r.status = 'fulfilled' AND r.final_at IS NULL
             AND NOT EXISTS (SELECT 1 FROM request_payments p WHERE p.request_id = r.id AND p.mined_height IS NULL)
             AND (SELECT MAX(mined_height) FROM request_payments p WHERE p.request_id = r.id) + ?2 - 1 <= ?3",
            )?
            .query_map(params![id, FINALITY_CONFIRMATIONS as i64, h], |r| r.get(0))?
            .collect::<Result<Vec<String>, _>>()?;
        rows
    };
    for rid in due {
        let ev = mark_final(&st, Mode::Test, &rid)?;
        fired.push(json!({ "type": "request.final", "request": rid, "event": ev.map(|e| e["id"].clone()) }));
    }
    let mut body = clock_json(&st, &load(&st, &id)?);
    body["fired"] = json!(fired);
    Ok(Json(body))
}

#[derive(Deserialize)]
pub struct Reorg {
    /// How many blocks to roll back (1..=100). Payments mined in them become unconfirmed.
    depth: Option<i64>,
}

/// POST /v1/test_clocks/{id}/reorg — rolls the clock's chain back `depth` blocks. Payments in
/// those blocks fire `request.payment_reorged` and lose their confirmations; the next `advance`
/// mines them again. A payment that was already final is never affected (that is what final means).
pub async fn reorg(State(st): State<Shared>, auth: Auth, Path(id): Path<String>, Body(req, _): Body<Reorg>) -> Result<Json<Value>, ApiError> {
    test_only(&auth)?;
    let depth = req.depth.unwrap_or(1);
    if !(1..=100).contains(&depth) {
        return Err(ApiError::invalid("parameter_invalid", "depth must be 1..=100").param("depth"));
    }
    let k = load(&st, &id)?;
    if depth >= k.height {
        return Err(ApiError::invalid("parameter_invalid", format!("depth must be less than the clock's height ({})", k.height)).param("depth"));
    }
    let new_tip = k.height - depth;
    st.db.0.lock().unwrap().execute("UPDATE test_clocks SET height = ?1 WHERE id = ?2", params![new_tip, id])?;
    let hit: Vec<String> = {
        let c = st.db.0.lock().unwrap();
        let rows = c
            .prepare(
                "SELECT DISTINCT r.id FROM requests r JOIN request_payments p ON p.request_id = r.id
                 WHERE r.test_clock = ?1 AND r.final_at IS NULL AND p.mined_height > ?2",
            )?
            .query_map(params![id, new_tip], |r| r.get(0))?
            .collect::<Result<Vec<String>, _>>()?;
        rows
    };
    let mut fired = Vec::new();
    for rid in hit {
        st.db
            .0
            .lock()
            .unwrap()
            .execute("UPDATE request_payments SET mined_height = NULL WHERE request_id = ?1 AND mined_height > ?2", params![rid, new_tip])?;
        let ev = emit(&st, Mode::Test, "request.payment_reorged", to_json(&st, &load_request(&st, Some(Mode::Test), &rid)?))?;
        fired.push(json!({ "type": "request.payment_reorged", "request": rid, "event": ev["id"] }));
    }
    let mut body = clock_json(&st, &load(&st, &id)?);
    body["fired"] = json!(fired);
    Ok(Json(body))
}

/// Marks a fulfilled request final and emits `request.final` (once).
pub fn mark_final(st: &AppState, mode: Mode, request_id: &str) -> Result<Option<Value>, ApiError> {
    // The stored verification was provisional; record that the payment is now final.
    let n = st.db.0.lock().unwrap().execute(
        "UPDATE requests SET final_at = ?1,
           verification = CASE WHEN verification IS NULL THEN NULL
             ELSE json_set(verification, '$.verdict', 'valid', '$.checks.finality', 'final') END
         WHERE id = ?2 AND final_at IS NULL",
        params![now(), request_id],
    )?;
    if n == 0 {
        return Ok(None);
    }
    let obj = to_json(st, &load_request(st, Some(mode), request_id)?);
    Ok(Some(emit(st, mode, "request.final", obj)?))
}

/// Emits `request.final` for real fulfilled requests once the chain tip is
/// FINALITY_CONFIRMATIONS past their latest payment. Checks every 60 s.
pub async fn finality_sweeper(st: Shared) {
    loop {
        tokio::time::sleep(std::time::Duration::from_secs(60)).await;
        for mode in [Mode::Test, Mode::Live] {
            let pending: Vec<(String, i64)> = {
                let c = st.db.0.lock().unwrap();
                c.prepare(
                    "SELECT r.id, (SELECT MAX(mined_height) FROM request_payments p WHERE p.request_id = r.id) FROM requests r
                     WHERE r.mode = ?1 AND r.status = 'fulfilled' AND r.final_at IS NULL AND r.test_clock IS NULL",
                )
                .and_then(|mut s| s.query_map([mode.as_str()], |r| Ok((r.get(0)?, r.get::<_, Option<i64>>(1)?.unwrap_or(0))))?.collect())
                .unwrap_or_default()
            };
            if pending.is_empty() {
                continue;
            }
            let (net, server) = (mode.net(&st.config), mode.server(&st.config));
            let Ok(tip) = chain::chain_tip(net, server.as_deref()).await else { continue };
            for (rid, _) in pending {
                // Re-check every payment: a reorg can drop a transaction or move it to another block.
                let txs: Vec<(i64, String, Option<i64>)> = {
                    let c = st.db.0.lock().unwrap();
                    c.prepare("SELECT id, txid, mined_height FROM request_payments WHERE request_id = ?1")
                        .and_then(|mut s| s.query_map([&rid], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?.collect())
                        .unwrap_or_default()
                };
                let mut lowest_conf = i64::MAX;
                let mut dropped = false;
                for (pid, txid, was) in txs {
                    if txid.starts_with("5a4db0c5") {
                        continue; // sandbox payment
                    }
                    let Ok(id) = crate::verify::parse_display_txid(&txid) else { continue };
                    // Known block: watch the block (the server learns the block, not the txid).
                    if let Some(h) = was {
                        match chain::tx_in_block(net, server.as_deref(), id, h as u32).await {
                            Ok(true) => {
                                lowest_conf = lowest_conf.min(tip as i64 - h + 1);
                                continue;
                            }
                            Ok(false) => {} // reorged out of that block: find it again below
                            Err(_) => {
                                dropped = true; // server trouble: decide next time
                                continue;
                            }
                        }
                    }
                    match chain::fetch_mined_tx(net, server.as_deref(), id).await {
                        Ok((_, h)) => {
                            if was != Some(h as i64) {
                                let _ = st.db.0.lock().unwrap().execute("UPDATE request_payments SET mined_height = ?1 WHERE id = ?2", params![h, pid]);
                            }
                            lowest_conf = lowest_conf.min(tip as i64 - h as i64 + 1);
                        }
                        Err(e) if e.to_string().contains("not mined") || e.to_string().to_lowercase().contains("not found") => {
                            if was.is_some() {
                                let _ = st.db.0.lock().unwrap().execute("UPDATE request_payments SET mined_height = NULL WHERE id = ?1", [pid]);
                                if let Ok(r) = load_request(&st, Some(mode), &rid) {
                                    let _ = emit(&st, mode, "request.payment_reorged", to_json(&st, &r));
                                }
                            }
                            dropped = true;
                        }
                        Err(_) => dropped = true, // server trouble: decide next time
                    }
                }
                if !dropped && lowest_conf != i64::MAX && lowest_conf >= FINALITY_CONFIRMATIONS as i64 {
                    let _ = mark_final(&st, mode, &rid);
                }
            }
        }
    }
}
