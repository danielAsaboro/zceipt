//! Sign in with Zcash: the API issues a single-use nonce bound to a domain, the wallet answers
//! with a `zsig1…` proof of control of a shielded address, and the API checks it once.

use crate::{db::{new_id, now}, error::ApiError, verify::extract, Auth, Body, Mode, Shared};
use axum::{extract::State, Json};
use receipts_chain::chain;
use receipts_core::{signin::SignIn, COIN_TYPE_MAINNET, COIN_TYPE_TESTNET};
use rusqlite::{params, OptionalExtension};
use serde::Deserialize;
use serde_json::{json, Value};
use std::sync::OnceLock;

/// How long a sign-in challenge stays valid.
pub const CHALLENGE_TTL_SECS: i64 = 300;

fn vk() -> &'static orchard::circuit::VerifyingKey {
    static VK: OnceLock<orchard::circuit::VerifyingKey> = OnceLock::new();
    VK.get_or_init(receipts_core::verifying_key)
}

fn coin_type(mode: Mode) -> u32 {
    if mode == Mode::Live { COIN_TYPE_MAINNET } else { COIN_TYPE_TESTNET }
}

#[derive(Deserialize)]
pub struct CreateChallenge {
    domain: Option<String>,
}

fn host_of(url: &str) -> String {
    let rest = url.split("://").nth(1).unwrap_or(url);
    rest.split(['/', '?', '#']).next().unwrap_or(rest).to_string()
}

fn challenge_json(id: &str, mode: &str, domain: &str, nonce: &str, created: i64, expires_at: i64, used_at: Option<i64>) -> Value {
    json!({
        "object": "sign_in_challenge",
        "id": id,
        "livemode": mode == "live",
        "coin_type": if mode == "live" { COIN_TYPE_MAINNET } else { COIN_TYPE_TESTNET },
        "domain": domain,
        "nonce": nonce,
        "created": created,
        "expires_at": expires_at,
        "status": if used_at.is_some() { "used" } else if now() >= expires_at { "expired" } else { "pending" },
        "wallet_command": format!("receipts sign-in -w <wallet> -i <key.age> --domain {domain} --nonce {nonce}"),
    })
}

/// POST /v1/sign_in/challenges
pub async fn create_challenge(State(st): State<Shared>, auth: Auth, Body(req, _): Body<CreateChallenge>) -> Result<Json<Value>, ApiError> {
    let domain = req.domain.unwrap_or_else(|| host_of(&st.config.public_url));
    if domain.is_empty() || domain.len() > 253 || !domain.chars().all(|c| c.is_ascii_alphanumeric() || ".-:".contains(c)) {
        return Err(ApiError::invalid("parameter_invalid", "domain must be a host name such as shop.example").param("domain"));
    }
    let id = new_id("sic_");
    let nonce = new_id("").chars().take(24).collect::<String>();
    let t = now();
    let mode = auth.mode.as_str();
    st.db.0.lock().unwrap().execute(
        "INSERT INTO sign_in_challenges (id, mode, domain, nonce, created, expires_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![id, mode, domain, nonce, t, t + CHALLENGE_TTL_SECS],
    )?;
    Ok(Json(challenge_json(&id, mode, &domain, &nonce, t, t + CHALLENGE_TTL_SECS, None)))
}

#[derive(Deserialize)]
pub struct VerifySignIn {
    sign_in: Option<String>,
}

/// POST /v1/sign_in/verify — checks a `zsig1…` once; the challenge is spent even on success only.
pub async fn verify(State(st): State<Shared>, auth: Auth, Body(req, _): Body<VerifySignIn>) -> Result<Json<Value>, ApiError> {
    let text = req.sign_in.ok_or_else(|| ApiError::missing("sign_in"))?;
    let body = extract(&text, "zsig1").ok_or_else(|| ApiError::invalid("sign_in_malformed", "no zsig1… sign-in found").param("sign_in"))?;
    let s = SignIn::from_text(&body).ok_or_else(|| ApiError::invalid("sign_in_malformed", "the sign-in could not be decoded").param("sign_in"))?;
    let mode = auth.mode.as_str();
    let row: Option<(String, String, i64, Option<i64>)> = st
        .db
        .0
        .lock()
        .unwrap()
        .query_row(
            "SELECT id, domain, expires_at, used_at FROM sign_in_challenges WHERE mode = ?1 AND nonce = ?2",
            params![mode, s.nonce],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
        )
        .optional()?;
    let (id, domain, expires_at, used_at) = row.ok_or_else(|| ApiError::not_found("sign_in_challenge_not_found", "no sign-in challenge with this nonce for this key's mode"))?;
    if used_at.is_some() {
        return Err(ApiError::conflict("sign_in_challenge_used", "this challenge was already used; ask for a new one"));
    }
    if now() >= expires_at {
        return Err(ApiError::conflict("sign_in_challenge_expired", "this challenge expired; ask for a new one"));
    }
    let coin = coin_type(auth.mode);
    let (s2, d2, n2) = (s.clone(), domain.clone(), s.nonce.clone());
    let address = tokio::task::spawn_blocking(move || receipts_core::signin::verify_sign_in(vk(), &s2, coin, &d2, &n2))
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?
        .map_err(|e| ApiError::verification("sign_in_invalid", format!("the sign-in does not check out for {domain}: {e}")).param("sign_in"))?;
    // Spend the challenge atomically: a second, concurrent verify loses.
    let n = st.db.0.lock().unwrap().execute(
        "UPDATE sign_in_challenges SET used_at = ?1 WHERE id = ?2 AND used_at IS NULL",
        params![now(), id],
    )?;
    if n == 0 {
        return Err(ApiError::conflict("sign_in_challenge_used", "this challenge was already used; ask for a new one"));
    }
    Ok(Json(json!({
        "object": "sign_in",
        "verified": true,
        "livemode": auth.mode == Mode::Live,
        "challenge": id,
        "domain": domain,
        "issued_at": s.issued_at,
        "address": chain::encode_orchard_receiver(auth.mode.net(&st.config), address),
    })))
}
