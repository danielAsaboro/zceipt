//! Webhook delivery: signed POSTs with retries and exponential backoff.
//!
//! Each delivery carries `Receipts-Signature: t=<unix seconds>,v1=<hex>`, where `v1` is
//! HMAC-SHA256 with the endpoint's `whsec_…` secret over `"<t>.<raw body>"`. Receivers should
//! check the signature, reject timestamps older than a few minutes, and deduplicate on the
//! event `id`, because a delivery may arrive more than once.

use crate::{db::now, Shared};
use hmac::{Hmac, Mac};
use rusqlite::params;
use sha2::Sha256;

pub const MAX_ATTEMPTS: i64 = 8;

/// `t=…,v1=…` signature header value for `body` at time `t`.
pub fn sign(secret: &str, t: i64, body: &str) -> String {
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).expect("any key length");
    mac.update(format!("{t}.{body}").as_bytes());
    format!("t={t},v1={}", hex::encode(mac.finalize().into_bytes()))
}

/// Checks a `Receipts-Signature` header against `body` (for receivers and tests).
pub fn verify_signature(secret: &str, header: &str, body: &str, tolerance_secs: i64) -> bool {
    let mut t = None;
    let mut sigs = Vec::new();
    for part in header.split(',') {
        match part.split_once('=') {
            Some(("t", v)) => t = v.parse::<i64>().ok(),
            Some(("v1", v)) => sigs.push(v.to_string()),
            _ => {}
        }
    }
    let Some(t) = t else { return false };
    if (now() - t).abs() > tolerance_secs {
        return false;
    }
    let expected = sign(secret, t, body);
    let expected = expected.split("v1=").nth(1).unwrap_or_default();
    sigs.iter().any(|s| s.len() == expected.len() && s.bytes().zip(expected.bytes()).fold(0u8, |a, (x, y)| a | (x ^ y)) == 0)
}

fn backoff(attempts: i64) -> i64 {
    // 10s, 20s, 40s … capped at one hour.
    (10i64 << attempts.min(9)).min(3600)
}

/// Delivers due webhooks forever, once a second.
pub async fn worker(st: Shared) {
    loop {
        if let Err(e) = tick(&st).await {
            tracing::warn!("webhook worker: {e}");
        }
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    }
}

async fn tick(st: &Shared) -> anyhow::Result<()> {
    let due: Vec<(i64, String, String, String, i64)> = {
        let c = st.db.0.lock().unwrap();
        let mut stmt = c.prepare(
            "SELECT d.id, e.body, w.url, w.secret, d.attempts FROM deliveries d
             JOIN events e ON e.id = d.event_id JOIN webhook_endpoints w ON w.id = d.endpoint_id
             WHERE d.status = 'pending' AND d.next_attempt_at <= ?1 AND w.disabled = 0 LIMIT 20",
        )?;
        let rows = stmt.query_map([now()], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)))?;
        rows.collect::<Result<_, _>>()?
    };
    for (id, body, url, secret, attempts) in due {
        let res = st
            .http
            .post(&url)
            .header("content-type", "application/json")
            .header("user-agent", "Receipts-Webhooks/1")
            .header("receipts-signature", sign(&secret, now(), &body))
            .body(body.clone())
            .send()
            .await;
        let (ok, status, err) = match res {
            Ok(r) => (r.status().is_success(), Some(r.status().as_u16() as i64), None),
            Err(e) => (false, None, Some(e.to_string())),
        };
        let c = st.db.0.lock().unwrap();
        if ok {
            c.execute("UPDATE deliveries SET status = 'delivered', attempts = attempts + 1, last_status = ?1, delivered_at = ?2 WHERE id = ?3", params![status, now(), id])?;
        } else {
            let attempts = attempts + 1;
            let status_text = if attempts >= MAX_ATTEMPTS { "failed" } else { "pending" };
            c.execute(
                "UPDATE deliveries SET status = ?1, attempts = ?2, last_status = ?3, last_error = ?4, next_attempt_at = ?5 WHERE id = ?6",
                params![status_text, attempts, status, err, now() + backoff(attempts), id],
            )?;
        }
    }
    Ok(())
}
