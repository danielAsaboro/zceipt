//! Sandbox test clocks and payment finality.
//!
//! A test clock is a frozen time and block height that requests can run on. Advancing it fires
//! the same events real time would (`request.expired`, `request.final`), so an integration can
//! test expiry and the 10-confirmation finality path in seconds instead of hours.
//!
//! Real requests become final when the chain tip is FINALITY_CONFIRMATIONS past the payment;
//! `finality_sweeper` checks that and emits `request.final`.

use crate::{db::{new_id, now}, emit, error::ApiError, requests::{load as load_request, to_json}, AppState, Auth, Body, Mode, Shared};
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
    if h < 1 {
        return Err(ApiError::invalid("parameter_invalid", "height must be positive").param("height"));
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
    let seconds = req.seconds.unwrap_or(blocks * 75);
    if seconds < 0 || blocks < 0 || (seconds == 0 && blocks == 0) {
        return Err(ApiError::invalid("parameter_invalid", "advance by a positive number of seconds and/or blocks"));
    }
    let k = load(&st, &id)?;
    let (t, h) = (k.frozen_time + seconds, k.height + blocks);
    st.db.0.lock().unwrap().execute("UPDATE test_clocks SET frozen_time = ?1, height = ?2 WHERE id = ?3", params![t, h, id])?;

    let mut fired = Vec::new();
    // Expiry, by clock time.
    let expired: Vec<String> = {
        let c = st.db.0.lock().unwrap();
        let rows = c.prepare("SELECT id FROM requests WHERE test_clock = ?1 AND status = 'open' AND expires_at IS NOT NULL AND expires_at <= ?2 AND expired_notified = 0")?
            .query_map(params![id, t], |r| r.get(0))?
            .collect::<Result<Vec<String>, _>>()?;
        rows
    };
    for rid in expired {
        st.db.0.lock().unwrap().execute("UPDATE requests SET status = 'expired', expired_notified = 1 WHERE id = ?1", [&rid])?;
        let ev = emit(&st, Mode::Test, "request.expired", to_json(&st, &load_request(&st, Some(Mode::Test), &rid)?))?;
        fired.push(json!({ "type": "request.expired", "request": rid, "event": ev["id"] }));
    }
    // Finality, by clock height.
    let due: Vec<String> = {
        let c = st.db.0.lock().unwrap();
        let rows = c.prepare(
            "SELECT r.id FROM requests r WHERE r.test_clock = ?1 AND r.status = 'fulfilled' AND r.final_at IS NULL
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

/// Marks a fulfilled request final and emits `request.final` (once).
pub fn mark_final(st: &AppState, mode: Mode, request_id: &str) -> Result<Option<Value>, ApiError> {
    let n = st.db.0.lock().unwrap().execute("UPDATE requests SET final_at = ?1 WHERE id = ?2 AND final_at IS NULL", params![now(), request_id])?;
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
            let Ok(tip) = chain::chain_tip(mode.net(&st.config), mode.server(&st.config).as_deref()).await else { continue };
            for (rid, h) in pending {
                if h > 0 && (tip as i64) - h + 1 >= FINALITY_CONFIRMATIONS as i64 {
                    let _ = mark_final(&st, mode, &rid);
                }
            }
        }
    }
}
