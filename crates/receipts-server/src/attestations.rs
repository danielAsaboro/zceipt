//! Business-fact attestations: a signed, minimal statement about a fulfilled request, such as
//! "at least 0.01 ZEC was paid to Kemi's Coffee on or before 2026-10-14", for an accountant,
//! an auditor or a grant committee who should not see the transaction itself.
//!
//! Format: an SD-JWT (IETF selective-disclosure JWT) signed with Ed25519. By default it states
//! only a lower bound on the amount, a day-granular "paid on or before" date, the network and
//! finality. The txid, the exact amount, the exact time, the request id and the label are
//! salted, hashed disclosures: the holder can reveal any of them later, one by one, and the
//! signature still checks. Public keys are at `/.well-known/jwks.json`.

use crate::{db::{new_id, now}, error::ApiError, requests::load, AppState, Auth, Body, Shared};
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

pub const VCT: &str = "urn:zcash-receipts:payment-fact:1";
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
pub struct CreateAttestation {
    /// The amount floor to state. Default: the requested amount, or what was paid rounded down to 0.001 ZEC.
    at_least_zatoshis: Option<u64>,
    /// `YYYY-MM-DD` the payment is stated to be on or before. Default: the day it was paid.
    before: Option<String>,
    /// Which hidden claims to reveal in `presentation` right away (`txid`, `amount_zatoshis`,
    /// `paid_at`, `request`, `label`). Default: none.
    disclose: Option<Vec<String>>,
}

/// POST /v1/requests/{id}/attestations
pub async fn create(State(st): State<Shared>, auth: Auth, Path(id): Path<String>, Body(req, _): Body<CreateAttestation>) -> Result<Json<Value>, ApiError> {
    let r = load(&st, Some(auth.mode), &id)?;
    let (Some(paid_at), Some(paid)) = (r.fulfilled_at, r.paid) else {
        return Err(ApiError::conflict("request_not_fulfilled", "only a fulfilled request can be attested"));
    };
    let paid = paid as u64;
    let floor = req.at_least_zatoshis.unwrap_or_else(|| r.amount.map(|a| a as u64).unwrap_or(paid / 100_000 * 100_000).min(paid));
    if floor > paid {
        return Err(ApiError::invalid("attestation_overclaims", format!("at_least_zatoshis is more than the {paid} zatoshis paid")).param("at_least_zatoshis"));
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
    let disclose = req.disclose.unwrap_or_default();
    if let Some(bad) = disclose.iter().find(|d| !DISCLOSABLE.contains(&d.as_str())) {
        return Err(ApiError::invalid("parameter_invalid", format!("cannot disclose {bad}; one of {DISCLOSABLE:?}")).param("disclose"));
    }

    let hidden: Vec<(&str, Value)> = vec![
        ("txid", json!(r.txid)),
        ("amount_zatoshis", json!(paid)),
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
    digests.sort(); // order must not leak which claim is which
    let (kid, sk) = key(&st)?;
    let (_, today) = utc_date(now());
    let payload = json!({
        "iss": st.config.public_url,
        "iat": today,
        "vct": VCT,
        "network": auth.mode.net(&st.config).name(),
        "pool_proof": "zip311",
        "paid_at_least_zatoshis": floor,
        "paid_on_or_before": before,
        "final": r.final_at.is_some(),
        "_sd": digests,
        "_sd_alg": "sha-256",
    });
    let header = json!({ "alg": "EdDSA", "typ": "vc+sd-jwt", "kid": kid });
    let signing_input = format!("{}.{}", B64.encode(header.to_string()), B64.encode(payload.to_string()));
    let jwt = format!("{signing_input}.{}", B64.encode(sk.sign(signing_input.as_bytes()).to_bytes()));
    let presentation = disclose.iter().filter_map(|n| disclosures.get(n).and_then(Value::as_str)).fold(format!("{jwt}~"), |acc, d| format!("{acc}{d}~"));
    Ok(Json(json!({
        "object": "attestation",
        "livemode": auth.mode == crate::Mode::Live,
        "request": r.id,
        "claims": { "paid_at_least_zatoshis": floor, "paid_on_or_before": before, "final": r.final_at.is_some(), "network": payload["network"] },
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
pub struct VerifyAttestation {
    attestation: Option<String>,
}

/// POST /v1/attestations/verify — checks an attestation this server issued.
pub async fn verify(State(st): State<Shared>, _auth: Auth, Body(req, _): Body<VerifyAttestation>) -> Result<Json<Value>, ApiError> {
    let text = req.attestation.ok_or_else(|| ApiError::missing("attestation"))?;
    let claims = verify_presentation(&text, &public_keys(&st)?).map_err(|e| ApiError::verification("attestation_invalid", e).param("attestation"))?;
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
