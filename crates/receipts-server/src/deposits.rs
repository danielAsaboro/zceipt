//! Deposit desks: shielded deposits an exchange can accept.
//!
//! Exchanges keep Zcash transparent because they can't see where shielded deposits come from
//! (docs/PAIN-POINTS.md, B1–B8). A request created with `source_of_funds` only accepts a receipt
//! that proves the source of every note it spent (`receipts create --prove-source`; `receipts pay`
//! adds it on its own). The desk then screens where the money entered the shielded pool in the
//! clear (the source transaction's transparent inputs) against its own list of blocked
//! addresses:
//!
//! - every source funded in the clear by addresses not on the list, every one of its transparent
//!   inputs resolved, and enough moved in from the clear to cover the spent note (whose value
//!   the payer reveals): `cleared`, the request is fulfilled (credited) as usual;
//! - a blocked address, or a source funded from shielded notes the payer didn't show: the request
//!   is `held_for_review` (`request.held_for_review` webhook) until the desk accepts or rejects
//!   it (`POST /v1/requests/{id}/review`); a rejected deposit can be refunded to the address the
//!   payer signed into the receipt.
//!
//! The desk learns that link and those funding addresses, as it would from a transparent
//! deposit, and nothing else about the customer's wallet.

use crate::{error::ApiError, requests, Auth, Body, Mode, Shared};
use axum::{
    extract::{Path, State},
    Json,
};
use receipts_chain::Net;
use rusqlite::params;
use serde::Deserialize;
use serde_json::{json, Value};

#[derive(Deserialize)]
pub struct SourcePolicy {
    /// Must be true (present for clarity and future options).
    pub required: bool,
    /// Transparent addresses whose funds the desk won't credit without review.
    #[serde(default)]
    pub blocked_addresses: Vec<String>,
}

/// Checks a policy and returns it as stored JSON.
pub fn validate(net: Net, p: &SourcePolicy) -> Result<String, ApiError> {
    if !p.required {
        return Err(ApiError::invalid("parameter_invalid", "source_of_funds.required must be true (omit source_of_funds otherwise)").param("source_of_funds"));
    }
    if p.blocked_addresses.len() > 10_000 {
        return Err(ApiError::invalid("parameter_invalid", "at most 10,000 blocked addresses per request").param("source_of_funds"));
    }
    let want = match net {
        Net::Main => zcash_protocol::consensus::NetworkType::Main,
        Net::Test => zcash_protocol::consensus::NetworkType::Test,
        // Regtest uses the testnet transparent prefixes.
        Net::Regtest(_) => zcash_protocol::consensus::NetworkType::Test,
    };
    for a in &p.blocked_addresses {
        let ok = zcash_address::ZcashAddress::try_from_encoded(a)
            .is_ok_and(|z| z.is_transparent_only() && z.can_receive_as(zcash_protocol::PoolType::Transparent))
            && net_of_taddr(a) == Some(want);
        if !ok {
            return Err(ApiError::invalid("parameter_invalid", format!("{a} is not a transparent address for this network")).param("source_of_funds"));
        }
    }
    Ok(json!({ "required": true, "blocked_addresses": p.blocked_addresses }).to_string())
}

fn net_of_taddr(a: &str) -> Option<zcash_protocol::consensus::NetworkType> {
    use zcash_protocol::consensus::NetworkType;
    if a.starts_with("t1") || a.starts_with("t3") {
        Some(NetworkType::Main)
    } else if a.starts_with("tm") || a.starts_with("t2") {
        // Testnet and regtest share transparent prefixes.
        Some(NetworkType::Test)
    } else {
        None
    }
}

/// What a request shows about its policy (never the blocked list itself).
pub fn policy_summary(p: Option<&str>) -> Value {
    match p.and_then(|p| serde_json::from_str::<Value>(p).ok()) {
        None => Value::Null,
        Some(p) => json!({ "required": true, "screened_addresses": p["blocked_addresses"].as_array().map(|a| a.len()).unwrap_or(0) }),
    }
}

/// Checks a verified receipt against the policy. Errors if a spend lacks a source proof (the
/// payer must resend); otherwise returns the provenance record, `cleared` or `review`.
/// Zatoshis each source transaction already funded in deposits this desk credited (other than
/// `except`): the clear funding of one source can't be counted for several deposits.
pub fn prior_claims(c: &rusqlite::Connection, except: &str) -> std::collections::BTreeMap<String, u64> {
    let mut out = std::collections::BTreeMap::new();
    let Ok(mut stmt) = c.prepare("SELECT provenance FROM requests WHERE provenance IS NOT NULL AND status = 'fulfilled' AND id != ?1") else { return out };
    let rows: Vec<String> = stmt.query_map([except], |r| r.get(0)).map(|it| it.flatten().collect()).unwrap_or_default();
    for p in rows {
        let Ok(p) = serde_json::from_str::<Value>(&p) else { continue };
        for s in p["sources"].as_array().into_iter().flatten() {
            if let (Some(t), Some(z)) = (s["source_txid"].as_str(), s["zatoshis"].as_u64()) {
                *out.entry(t.to_string()).or_default() += z;
            }
        }
    }
    out
}

pub fn evaluate(policy: &str, v: &crate::verify::Verification, paid: u64, prior: &std::collections::BTreeMap<String, u64>) -> Result<Value, ApiError> {
    let p: Value = serde_json::from_str(policy).unwrap_or(json!({}));
    let blocked: std::collections::BTreeSet<&str> =
        p["blocked_addresses"].as_array().map(|a| a.iter().filter_map(|x| x.as_str()).collect()).unwrap_or_default();
    let spends = v.checks["spend_authority"]["actions"].as_u64().unwrap_or(0) as usize;
    if v.sources.len() < spends.max(1) {
        return Err(ApiError::verification(
            "source_of_funds_required",
            "this deposit must prove where its money came from: create the receipt with --prove-source (receipts pay does this automatically)",
        ));
    }
    let mut reasons = Vec::new();
    let mut funding = Vec::new();
    for s in &v.sources {
        let (action, stx) = (&s["spend_action"], s["source_txid"].as_str().unwrap_or("?"));
        let inputs = s["transparent_inputs"].as_array().cloned().unwrap_or_default();
        let known: Vec<&Value> = inputs.iter().filter(|i| i["address"].is_string()).collect();
        if known.is_empty() {
            reasons.push(format!("the note spent by action {action} came from transaction {stx}, whose own funding isn't visible (shielded notes the payer didn't show, or newly mined coins)"));
        } else if known.len() < inputs.len() {
            // An input whose previous output couldn't be read (or past the lookup limit) could be
            // a blocked address: never clear around it.
            reasons.push(format!("{} of the {} transparent inputs of transaction {stx} couldn't be resolved", inputs.len() - known.len(), inputs.len()));
        }
        // Clean inputs alone don't explain the note: the clear funding must cover its value, or
        // the rest came from shielded notes the payer didn't show.
        if s["zatoshis"].as_u64().is_none() && !known.is_empty() {
            reasons.push(format!("the value of the note spent by action {action} is hidden, so the desk can't check its funding covers it (resend with --reveal-source-value; receipts pay does this for deposit desks)"));
        }
        for i in known {
            let a = i["address"].as_str().unwrap_or_default();
            if blocked.contains(a) {
                reasons.push(format!("funded by blocked address {a}"));
            }
            funding.push(json!({ "address": a, "zatoshis": i["zatoshis"], "source_txid": s["source_txid"] }));
        }
    }
    // Coverage: notes from one source transaction can't together claim more than it moved in
    // from the clear, and the screened notes must add up to what the deposit paid (a receipt can
    // disclose a small screened spend next to large spends it doesn't show).
    let mut per_source: std::collections::BTreeMap<String, (u64, i64)> = Default::default();
    let mut screened = 0u64;
    for s in &v.sources {
        let Some(value) = s["zatoshis"].as_u64() else { continue };
        let e = per_source.entry(s["source_txid"].as_str().unwrap_or("?").to_string()).or_insert((0, s["net_into_shielded_zatoshis"].as_i64().unwrap_or(0)));
        e.0 += value;
        screened += value;
    }
    for (stx, (claimed, moved_in)) in &per_source {
        let earlier = prior.get(stx).copied().unwrap_or(0);
        if (*claimed + earlier) as i64 > *moved_in {
            reasons.push(if earlier > 0 {
                format!("transaction {stx} moved {moved_in} zatoshis in from the clear; {earlier} of that already funded earlier deposits here, so it can't also cover the {claimed} zatoshis of notes in this one")
            } else {
                format!("transaction {stx} moved {moved_in} zatoshis in from the clear, less than the {claimed} zatoshis of notes it funded here: the rest came from shielded notes the payer didn't show")
            });
        }
    }
    if screened < paid && reasons.is_empty() {
        reasons.push(format!(
            "the screened notes hold {screened} zatoshis, less than the {paid} zatoshis deposited: the rest came from spends the receipt doesn't show"
        ));
    }
    reasons.dedup();
    Ok(json!({
        "status": if reasons.is_empty() { "cleared" } else { "review" },
        "reasons": reasons,
        "funding": funding,
        "sources": v.sources,
        "checked_at": crate::db::now(),
    }))
}

#[derive(Deserialize)]
pub struct Review {
    decision: Option<String>,
    note: Option<String>,
}

/// `POST /v1/requests/{id}/review`: the desk accepts (credit) or rejects a held deposit.
pub async fn review(State(st): State<Shared>, auth: Auth, Path(id): Path<String>, Body(req, _): Body<Review>) -> Result<Json<Value>, ApiError> {
    let decision = req.decision.ok_or_else(|| ApiError::missing("decision"))?;
    let new_status = match decision.as_str() {
        "accept" => "fulfilled",
        "reject" => "rejected",
        _ => return Err(ApiError::invalid("parameter_invalid", "decision must be accept or reject").param("decision")),
    };
    if req.note.as_ref().is_some_and(|n| n.len() > 500) {
        return Err(ApiError::invalid("parameter_invalid", "note is longer than 500 characters").param("note"));
    }
    let mode: Mode = auth.mode;
    {
        let c = st.db.0.lock().unwrap();
        let (status, prov): (String, Option<String>) = c
            .query_row("SELECT status, provenance FROM requests WHERE id = ?1 AND mode = ?2", params![id, mode.as_str()], |x| Ok((x.get(0)?, x.get(1)?)))
            .map_err(|_| ApiError::not_found("request_not_found", format!("no request {id}")).param("id"))?;
        if status != "held_for_review" {
            return Err(ApiError::conflict("not_held_for_review", format!("{id} is {status}, not held for review")));
        }
        let mut p: Value = prov.as_deref().and_then(|p| serde_json::from_str(p).ok()).unwrap_or(json!({}));
        p["review"] = json!({ "decision": decision, "note": req.note, "at": crate::db::now() });
        c.execute("UPDATE requests SET status = ?1, provenance = ?2 WHERE id = ?3", params![new_status, p.to_string(), id])?;
    }
    let obj = requests::to_json(&st, &requests::load(&st, Some(mode), &id)?);
    crate::emit(&st, mode, if new_status == "fulfilled" { "request.fulfilled" } else { "request.rejected" }, obj.clone())?;
    Ok(Json(obj))
}
