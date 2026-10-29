//! Business-fact attestations: a signed, minimal statement about a fulfilled request, such as
//! "at least 0.01 ZEC was paid to Kemi's Coffee on or before 2026-10-14", for an accountant,
//! an auditor or a grant committee who should not see the transaction itself.
//!
//! Format: an SD-JWT (IETF selective-disclosure JWT) signed with Ed25519. By default it states
//! only a lower bound on the amount, a day-granular "paid on or before" date, the network and
//! finality. The txid, the exact amount, the exact time, the request id and the label are
//! salted, hashed disclosures: the holder can reveal any of them later, one by one, and the
//! signature still checks. Public keys are at `/.well-known/jwks.json`.

use crate::{
    db::{new_id, now},
    error::ApiError,
    requests::load,
    AppState, Auth, Body, Shared,
};
use axum::{
    extract::{Path, State},
    Json,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64, Engine};
use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use rusqlite::{params, OptionalExtension};
use serde::Deserialize;
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

pub const VCT: &str = "urn:zceipt:payment-fact:1";
const DISCLOSABLE: &[&str] = &["txid", "amount_zatoshis", "paid_at", "request", "label"];

/// The server's attestation key (created on first use) and its key id.
fn key(st: &AppState) -> Result<(String, SigningKey), ApiError> {
    let c = st.db.0.lock().unwrap();
    if let Some((kid, sk)) = c
        .query_row("SELECT kid, secret FROM signing_keys ORDER BY created DESC LIMIT 1", [], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))
        .optional()?
    {
        let b: [u8; 32] = hex::decode(sk).ok().and_then(|v| v.try_into().ok()).ok_or_else(|| ApiError::internal("corrupt signing key"))?;
        return Ok((kid, SigningKey::from_bytes(&b)));
    }
    let mut b = [0u8; 32];
    getrandom::fill(&mut b).expect("OS RNG");
    let sk = SigningKey::from_bytes(&b);
    let kid = new_id("key_");
    c.execute("INSERT INTO signing_keys (kid, secret, created) VALUES (?1, ?2, ?3)", params![kid, hex::encode(b), now()])?;
    Ok((kid, sk))
}

fn public_keys(st: &AppState) -> Result<Vec<(String, VerifyingKey)>, ApiError> {
    key(st)?;
    let c = st.db.0.lock().unwrap();
    let mut stmt = c.prepare("SELECT kid, secret FROM signing_keys ORDER BY created DESC")?;
    let rows = stmt.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))?.collect::<Result<Vec<_>, _>>()?;
    Ok(rows
        .into_iter()
        .filter_map(|(kid, s)| {
            let b: [u8; 32] = hex::decode(s).ok()?.try_into().ok()?;
            Some((kid, SigningKey::from_bytes(&b).verifying_key()))
        })
        .collect())
}

/// GET /.well-known/jwks.json
pub async fn jwks(State(st): State<Shared>) -> Result<Json<Value>, ApiError> {
    let keys: Vec<Value> = public_keys(&st)?
        .into_iter()
        .map(|(kid, vk)| json!({ "kty": "OKP", "crv": "Ed25519", "alg": "EdDSA", "use": "sig", "kid": kid, "x": B64.encode(vk.as_bytes()) }))
        .collect();
    Ok(Json(json!({ "keys": keys })))
}

/// `YYYY-MM-DD` for a unix time (UTC), and the unix time at the start of that day.
pub fn utc_date(t: i64) -> (String, i64) {
    let days = t.div_euclid(86_400);
    // Howard Hinnant's civil_from_days.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    (format!("{y:04}-{m:02}-{d:02}"), days * 86_400)
}

fn parse_date(s: &str) -> Option<i64> {
    let p: Vec<i64> = s.split('-').map(|x| x.parse().ok()).collect::<Option<_>>()?;
    let [y, m, d] = p[..] else { return None };
    if !(1..=12).contains(&m) || !(1..=31).contains(&d) {
        return None;
    }
    // days_from_civil
    let y2 = if m <= 2 { y - 1 } else { y };
    let era = y2.div_euclid(400);
    let yoe = y2 - era * 400;
    let mp = if m > 2 { m - 3 } else { m + 9 };
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let t = (era * 146_097 + doe - 719_468) * 86_400;
    (utc_date(t).0 == s).then_some(t)
}

fn disclosure(name: &str, value: &Value) -> (String, String) {
    let mut salt = [0u8; 16];
    getrandom::fill(&mut salt).expect("OS RNG");
    let d = B64.encode(json!([B64.encode(salt), name, value]).to_string());
    let digest = B64.encode(Sha256::digest(d.as_bytes()));
    (d, digest)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateAttestation {
    /// The amount floor to state. Default: the requested amount, or what was paid rounded down to 0.001 ZEC.
    at_least_zatoshis: Option<u64>,
    /// `YYYY-MM-DD` the payment is stated to be on or before. Default: the day it was paid.
    before: Option<String>,
    /// Which hidden claims to reveal in `presentation` right away (`txid`, `amount_zatoshis`,
    /// `paid_at`, `request`, `label`). Default: none.
    disclose: Option<Vec<String>>,
    /// Who the attestation is for (becomes `aud`): a verifier that names its own audience refuses one made for another.
    audience: Option<String>,
    /// Days the attestation stays valid (becomes `exp`). Default: no expiry.
    valid_for_days: Option<u32>,
}

/// POST /v1/requests/{id}/attestations
pub async fn create(State(st): State<Shared>, auth: Auth, Path(id): Path<String>, Body(req, _): Body<CreateAttestation>) -> Result<Json<Value>, ApiError> {
    let r = load(&st, Some(auth.mode), &id)?;
    // Held and rejected deposits were paid but not accepted: nothing is attested for them.
    if !matches!(r.status.as_str(), "fulfilled" | "final") {
        return Err(ApiError::conflict("request_not_fulfilled", "only a fulfilled request can be attested"));
    }
    let (Some(paid_at), Some(paid)) = (r.fulfilled_at, r.paid) else {
        return Err(ApiError::conflict("request_not_fulfilled", "only a fulfilled request can be attested"));
    };
    // State what the payee kept: refunds already paid back are subtracted.
    let refunded: i64 = st.db.0.lock().unwrap().query_row(
        "SELECT COALESCE(SUM(amount_zatoshis), 0) FROM refunds WHERE request_id = ?1 AND status = 'succeeded'",
        [&r.id],
        |x| x.get(0),
    )?;
    let paid = (paid - refunded).max(0) as u64;
    // A payment a reorg dropped is not a payment yet.
    let (unconfirmed, sandbox): (i64, i64) = st.db.0.lock().unwrap().query_row(
        "SELECT COALESCE(SUM(mined_height IS NULL), 0), COALESCE(SUM(txid LIKE '5a4db0c5%'), 0) FROM request_payments WHERE request_id = ?1",
        [&r.id],
        |x| Ok((x.get(0)?, x.get(1)?)),
    )?;
    // Only test keys have sandbox payments; a real transaction whose id happens to start with the fixture prefix is not one.
    let sandbox = if auth.mode == crate::Mode::Test { sandbox } else { 0 };
    if unconfirmed > 0 {
        return Err(ApiError::conflict("payment_unconfirmed", "a payment on this request left the chain in a reorg; attest once it is mined again"));
    }
    // Default floor: rounded down (to 0.01 ZEC, or 0.001 below that), so the exact amount
    // stays hidden unless the holder reveals it.
    let step = if paid >= 1_000_000 { 1_000_000 } else { 100_000 };
    let floor = req.at_least_zatoshis.unwrap_or(paid / step * step);
    if floor > paid {
        return Err(ApiError::invalid("attestation_overclaims", format!("at_least_zatoshis is more than the {paid} zatoshis paid (net of refunds)"))
            .param("at_least_zatoshis"));
    }
    let (paid_day, paid_day_start) = utc_date(paid_at);
    let before = match &req.before {
        None => paid_day,
        Some(b) => {
            let t = parse_date(b).ok_or_else(|| ApiError::invalid("parameter_invalid", "before must be a date like 2026-10-14").param("before"))?;
            if t < paid_day_start {
                return Err(ApiError::invalid("attestation_overclaims", format!("the payment was on {paid_day}, after {b}")).param("before"));
            }
            b.clone()
        }
    };
    let mut disclose = req.disclose.unwrap_or_default();
    disclose.sort();
    disclose.dedup();
    if let Some(bad) = disclose.iter().find(|d| !DISCLOSABLE.contains(&d.as_str())) {
        return Err(ApiError::invalid("parameter_invalid", format!("cannot disclose {bad}; one of {DISCLOSABLE:?}")).param("disclose"));
    }

    let hidden: Vec<(&str, Value)> = vec![
        ("txid", json!(r.txid)),
        ("amount_zatoshis", json!(paid + refunded as u64)),
        ("paid_at", json!(paid_at)),
        ("request", json!(r.id)),
        ("label", json!(r.label)),
    ];
    let mut disclosures = Map::new();
    let mut digests = Vec::new();
    for (name, value) in &hidden {
        if value.is_null() {
            continue;
        }
        let (d, h) = disclosure(name, value);
        disclosures.insert(name.to_string(), d.into());
        digests.push(h);
    }
    // Pad with decoys so the number of digests doesn't reveal which claims exist (a label or not).
    while digests.len() < 8 {
        let mut b = [0u8; 32];
        getrandom::fill(&mut b).expect("OS RNG");
        digests.push(B64.encode(b));
    }
    digests.sort(); // order must not leak which claim is which
    let (kid, sk) = key(&st)?;
    if req.audience.as_ref().is_some_and(|a| a.is_empty() || a.len() > 200) || req.valid_for_days.is_some_and(|d| !(1..=3650).contains(&d)) {
        return Err(ApiError::invalid("parameter_invalid", "audience is 1 to 200 characters; valid_for_days is 1 to 3650"));
    }
    // A random 128-bit token id, so a verifier can keep a seen-list and refuse a replayed
    // presentation. `iat` and `exp` are both to the second: `exp` already was, so a day-granular
    // `iat` hid nothing. Neither claim says when the payment happened; that is `paid_at`, hidden.
    let mut jti = [0u8; 16];
    getrandom::fill(&mut jti).expect("OS RNG");
    let issued = now();
    let mut payload = json!({
        "iss": st.config.public_url,
        "iat": issued,
        "jti": hex::encode(jti),
        "vct": VCT,
        "network": auth.mode.net(&st.config).name(),
        "livemode": auth.mode == crate::Mode::Live,
        // Paid with a sandbox fixture, not a real transaction.
        "sandbox": sandbox > 0,
        "pool_proof": "zip311",
        "paid_at_least_zatoshis": floor,
        "paid_on_or_before": before,
        "final": r.final_at.is_some(),
        "net_of_refunds": true,
        "_sd": digests,
        "_sd_alg": "sha-256",
    });
    if let Some(a) = &req.audience {
        payload["aud"] = json!(a);
    }
    if let Some(d) = req.valid_for_days {
        payload["exp"] = json!(issued + i64::from(d) * 86_400);
    }
    let header = json!({ "alg": "EdDSA", "typ": "vc+sd-jwt", "kid": kid });
    let signing_input = format!("{}.{}", B64.encode(header.to_string()), B64.encode(payload.to_string()));
    let jwt = format!("{signing_input}.{}", B64.encode(sk.sign(signing_input.as_bytes()).to_bytes()));
    let presentation = disclose.iter().filter_map(|n| disclosures.get(n).and_then(Value::as_str)).fold(format!("{jwt}~"), |acc, d| format!("{acc}{d}~"));
    Ok(Json(json!({
        "object": "attestation",
        "livemode": auth.mode == crate::Mode::Live,
        "request": r.id,
        "claims": { "paid_at_least_zatoshis": floor, "paid_on_or_before": before, "final": r.final_at.is_some(), "network": payload["network"], "sandbox": sandbox > 0 },
        "presentation": presentation,
        "disclosures": disclosures,
        "jwks_url": format!("{}/.well-known/jwks.json", st.config.public_url.trim_end_matches('/')),
    })))
}

/// Checks an SD-JWT presentation against `keys`; returns the claims, with revealed ones merged.
pub fn verify_presentation(text: &str, keys: &[(String, VerifyingKey)]) -> Result<Value, String> {
    let mut parts = text.trim().split('~');
    let jwt = parts.next().ok_or("empty")?;
    let segs: Vec<&str> = jwt.split('.').collect();
    let [h, p, s] = segs[..] else { return Err("not a JWT".into()) };
    let header: Value = serde_json::from_slice(&B64.decode(h).map_err(|_| "bad header")?).map_err(|_| "bad header")?;
    if header["alg"] != "EdDSA" {
        return Err("unsupported alg".into());
    }
    let kid = header["kid"].as_str().ok_or("no kid")?;
    let vk = keys.iter().find(|(k, _)| k == kid).map(|(_, v)| v).ok_or("unknown key id")?;
    let sig: [u8; 64] = B64.decode(s).map_err(|_| "bad signature")?.try_into().map_err(|_| "bad signature")?;
    vk.verify(format!("{h}.{p}").as_bytes(), &ed25519_dalek::Signature::from_bytes(&sig)).map_err(|_| "signature does not verify")?;
    let mut claims: Value = serde_json::from_slice(&B64.decode(p).map_err(|_| "bad payload")?).map_err(|_| "bad payload")?;
    let sd: Vec<String> = claims["_sd"].as_array().map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect()).unwrap_or_default();
    let mut revealed = Map::new();
    for d in parts.filter(|d| !d.is_empty()) {
        let digest = B64.encode(Sha256::digest(d.as_bytes()));
        if !sd.contains(&digest) {
            return Err("a disclosure is not part of this attestation".into());
        }
        let arr: Value = serde_json::from_slice(&B64.decode(d).map_err(|_| "bad disclosure")?).map_err(|_| "bad disclosure")?;
        let name = arr[1].as_str().ok_or("bad disclosure")?.to_string();
        if !DISCLOSABLE.contains(&name.as_str()) || revealed.contains_key(&name) {
            return Err("bad disclosure".into());
        }
        revealed.insert(name, arr[2].clone());
    }
    let obj = claims.as_object_mut().unwrap();
    obj.remove("_sd");
    obj.remove("_sd_alg");
    obj.insert("revealed".into(), Value::Object(revealed));
    Ok(claims)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerifyAttestation {
    attestation: Option<String>,
    /// Who is checking. An attestation made for an audience is refused by anyone else, and one made
    /// for nobody is refused if you name yours.
    audience: Option<String>,
}

/// POST /v1/attestations/verify — checks an attestation this server issued.
pub async fn verify(State(st): State<Shared>, auth: Auth, Body(req, _): Body<VerifyAttestation>) -> Result<Json<Value>, ApiError> {
    let text = req.attestation.ok_or_else(|| ApiError::missing("attestation"))?;
    let claims = verify_presentation(&text, &public_keys(&st)?).map_err(|e| ApiError::verification("attestation_invalid", e).param("attestation"))?;
    // A live key only accepts live facts: test-mode and sandbox attestations are signed with the
    // same key, so the claims themselves say which they are.
    if auth.mode == crate::Mode::Live && (claims["livemode"] != true || claims["sandbox"] == true) {
        return Err(ApiError::verification(
            "attestation_invalid",
            "this attestation was issued in test mode (or paid with a sandbox fixture); a live key accepts only live ones",
        )
        .param("attestation"));
    }
    if claims["exp"].as_i64().is_some_and(|e| now() > e) {
        return Err(ApiError::verification("attestation_invalid", "this attestation has expired".to_string()).param("attestation"));
    }
    if claims["aud"].as_str() != req.audience.as_deref() && (req.audience.is_some() || claims["aud"].is_string()) {
        return Err(ApiError::verification("attestation_invalid", "this attestation was made for another audience (or none)".to_string()).param("attestation"));
    }
    Ok(Json(json!({ "object": "attestation_verification", "valid": true, "claims": claims })))
}

#[cfg(test)]
mod tests {
    #[test]
    fn dates() {
        assert_eq!(super::utc_date(1_792_014_283).0, "2026-10-14");
        assert_eq!(super::utc_date(0).0, "1970-01-01");
        let t = super::parse_date("2024-02-29").unwrap();
        assert_eq!(super::utc_date(t).0, "2024-02-29");
        assert!(super::parse_date("2023-02-29").is_none());
    }
}
