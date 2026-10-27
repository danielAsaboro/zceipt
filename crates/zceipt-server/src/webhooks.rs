//! Webhook delivery: signed POSTs with retries and exponential backoff.
//!
//! Each delivery carries `Zceipt-Signature: t=<unix seconds>,v1=<hex>`, where `v1` is
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

/// Checks a `Zceipt-Signature` header against `body` (for receivers and tests).
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
    sigs.iter().any(|s| crate::ct_eq(s.as_bytes(), expected.as_bytes()))
}

fn backoff(base: i64, attempts: i64) -> i64 {
    // base, 2×base, 4×base … capped at one hour (10 s, 20 s, 40 s … by default).
    (base << (attempts - 1).clamp(0, 9)).min(3600)
}

/// Most due deliveries taken per pass, and most sent at once.
const BATCH: usize = 200;
const IN_FLIGHT: usize = 32;

/// Delivers due webhooks forever: a pass every 250 ms, or straight away while there's a backlog.
/// Live and test deliveries run in separate loops, so a test endpoint that hangs for its full timeout
/// can never delay a live delivery.
pub async fn worker(st: Shared) {
    tokio::spawn(worker_for(st.clone(), "test"));
    worker_for(st, "live").await
}

async fn worker_for(st: Shared, mode: &'static str) {
    loop {
        match tick(&st, mode).await {
            Ok(n) if n == BATCH => continue,
            Ok(_) => {}
            Err(e) => tracing::warn!("webhook worker ({mode}): {e}"),
        }
        tokio::time::sleep(std::time::Duration::from_millis(250)).await;
    }
}

async fn tick(st: &Shared, mode: &str) -> anyhow::Result<usize> {
    let due: Vec<(i64, String, String, String, i64, String)> = {
        let c = st.db.0.lock().unwrap();
        let mut stmt = c.prepare(
            "SELECT d.id, e.body, w.url, w.secret, d.attempts, w.mode FROM deliveries d
             JOIN events e ON e.id = d.event_id JOIN webhook_endpoints w ON w.id = d.endpoint_id
             WHERE d.status = 'pending' AND d.next_attempt_at <= ?1 AND w.disabled = 0 AND w.mode = ?3
             ORDER BY d.next_attempt_at, d.id LIMIT ?2",
        )?;
        let rows = stmt.query_map(params![now(), BATCH as i64, mode], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?)))?;
        rows.collect::<Result<_, _>>()?
    };
    let n = due.len();
    // Send concurrently (a slow endpoint must not hold up the rest), at most IN_FLIGHT at once.
    let mut set = tokio::task::JoinSet::new();
    for d in due {
        while set.len() >= IN_FLIGHT {
            if let Some(r) = set.join_next().await {
                r??;
            }
        }
        set.spawn(deliver(st.clone(), d));
    }
    while let Some(r) = set.join_next().await {
        r??;
    }
    Ok(n)
}

async fn deliver(st: Shared, (id, body, url, secret, attempts, mode): (i64, String, String, String, i64, String)) -> anyhow::Result<()> {
    // Live deliveries: resolve the host now and connect only to a public address, pinned
    // so a DNS answer can't change between this check and the connection.
    let client = if mode == "live" {
        match pinned_public_client(&url).await {
            Ok(c) => c,
            Err(e) => {
                let c = st.db.0.lock().unwrap();
                // A failed DNS lookup is transient: retry on the usual schedule. A refused address or URL is final.
                let attempts = attempts + 1;
                if e.starts_with("DNS") && attempts < st.config.webhook_max_attempts {
                    c.execute(
                        "UPDATE deliveries SET status = 'pending', attempts = ?1, last_error = ?2, next_attempt_at = ?3 WHERE id = ?4",
                        params![attempts, e, now() + backoff(st.config.webhook_backoff_secs, attempts), id],
                    )?;
                } else {
                    c.execute("UPDATE deliveries SET status = 'failed', attempts = attempts + 1, last_error = ?1 WHERE id = ?2", params![e, id])?;
                }
                return Ok(());
            }
        }
    } else {
        // Test deliveries may reach localhost and private hosts, but not link-local or metadata addresses.
        match test_mode_client(&url).await {
            Ok(c) => c,
            Err(e) => {
                let c = st.db.0.lock().unwrap();
                let attempts = attempts + 1;
                if e.starts_with("DNS") && attempts < st.config.webhook_max_attempts {
                    c.execute(
                        "UPDATE deliveries SET status = 'pending', attempts = ?1, last_error = ?2, next_attempt_at = ?3 WHERE id = ?4",
                        params![attempts, e, now() + backoff(st.config.webhook_backoff_secs, attempts), id],
                    )?;
                } else {
                    c.execute("UPDATE deliveries SET status = 'failed', attempts = attempts + 1, last_error = ?1 WHERE id = ?2", params![e, id])?;
                }
                return Ok(());
            }
        }
    };
    let res = client
        .post(&url)
        .header("content-type", "application/json")
        .header("user-agent", "Zceipt-Webhooks/1")
        .header("zceipt-signature", sign(&secret, now(), &body))
        .body(body)
        .send()
        .await;
    let (ok, status, err) = match res {
        Ok(r) => (r.status().is_success(), Some(r.status().as_u16() as i64), None),
        Err(e) => (false, None, Some(e.to_string())),
    };
    let c = st.db.0.lock().unwrap();
    if ok {
        c.execute(
            "UPDATE deliveries SET status = 'delivered', attempts = attempts + 1, last_status = ?1, delivered_at = ?2 WHERE id = ?3",
            params![status, now(), id],
        )?;
    } else {
        let attempts = attempts + 1;
        let status_text = if attempts >= st.config.webhook_max_attempts { "failed" } else { "pending" };
        c.execute(
            "UPDATE deliveries SET status = ?1, attempts = ?2, last_status = ?3, last_error = ?4, next_attempt_at = ?5 WHERE id = ?6",
            params![status_text, attempts, status, err, now() + backoff(st.config.webhook_backoff_secs, attempts), id],
        )?;
    }
    Ok(())
}

/// Link-local, unspecified and cloud-metadata addresses, including IPv6 forms that embed one.
pub(crate) fn is_blocked_test_ip(ip: std::net::IpAddr) -> bool {
    use std::net::IpAddr;
    let v4 = |v: std::net::Ipv4Addr| v.is_link_local() || v.is_unspecified() || matches!(v.octets(), [100, 100, 100, 200] | [168, 63, 129, 16] | [192, 0, 0, 192]);
    match ip {
        IpAddr::V4(v) => v4(v),
        IpAddr::V6(v) => {
            let s = v.segments();
            let embedded = |a: u16, b: u16| std::net::Ipv4Addr::new((a >> 8) as u8, a as u8, (b >> 8) as u8, b as u8);
            v.is_unspecified()
                || (s[0] & 0xffc0) == 0xfe80
                || s[..3] == [0xfd00, 0x0ec2, 0]
                || v.to_ipv4_mapped().is_some_and(v4)
                || (s[..6] == [0, 0, 0, 0, 0, 0] && v4(embedded(s[6], s[7])))
                || (s[0] == 0x64 && s[1] == 0xff9b && v4(embedded(s[6], s[7])))
                || (s[0] == 0x2002 && v4(embedded(s[1], s[2])))
        }
    }
}

/// A client for a test-mode delivery: the host is resolved once, refused if any answer is a
/// link-local or metadata address, and the connection is pinned to what was checked, so a second
/// DNS answer can't differ (rebinding). Localhost and private networks stay allowed.
async fn test_mode_client(url: &str) -> Result<reqwest::Client, String> {
    crate::check_test_webhook_url(url).map_err(|e| e.message)?;
    let u = reqwest::Url::parse(url).map_err(|e| e.to_string())?;
    let host = u.host_str().ok_or("no host")?.to_string();
    let port = u.port_or_known_default().unwrap_or(80);
    let bare = host.trim_matches(|c| c == '[' || c == ']').to_string();
    let mut b = reqwest::Client::builder().timeout(std::time::Duration::from_secs(10)).redirect(reqwest::redirect::Policy::none());
    if bare.parse::<std::net::IpAddr>().is_err() {
        let addrs: Vec<std::net::SocketAddr> = tokio::net::lookup_host((bare.as_str(), port)).await.map_err(|e| format!("DNS: {e}"))?.collect();
        let addr = addrs.first().copied().ok_or("DNS: no address")?;
        if let Some(bad) = addrs.iter().find(|a| is_blocked_test_ip(a.ip())) {
            return Err(format!("refused: {host} resolves to a link-local or metadata address ({})", bad.ip()));
        }
        b = b.resolve(&host, addr);
    }
    b.build().map_err(|e| e.to_string())
}

async fn pinned_public_client(url: &str) -> Result<reqwest::Client, String> {
    crate::check_live_webhook_url(url).map_err(|e| e.message)?;
    let u = reqwest::Url::parse(url).map_err(|e| e.to_string())?;
    let host = u.host_str().ok_or("no host")?.to_string();
    let port = u.port_or_known_default().unwrap_or(443);
    let addrs: Vec<std::net::SocketAddr> =
        tokio::net::lookup_host((host.trim_matches(|c| c == '[' || c == ']'), port)).await.map_err(|e| format!("DNS: {e}"))?.collect();
    let addr = addrs.first().copied().ok_or("DNS: no address")?;
    if let Some(bad) = addrs.iter().find(|a| !crate::is_public_ip(a.ip())) {
        return Err(format!("refused: {host} resolves to a non-public address ({})", bad.ip()));
    }
    reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .redirect(reqwest::redirect::Policy::none())
        .resolve(&host, addr)
        .build()
        .map_err(|e| e.to_string())
}
