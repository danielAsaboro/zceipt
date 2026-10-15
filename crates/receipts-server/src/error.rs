//! API errors: one JSON shape, a stable machine-readable `code`, and a human message.
//!
//! ```json
//! { "error": { "type": "verification_error", "code": "challenge_mismatch",
//!              "message": "…", "param": "receipt", "doc_url": "/docs/ERRORS.md#challenge_mismatch" } }
//! ```

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;

#[derive(Debug, Clone)]
pub struct ApiError {
    pub status: StatusCode,
    pub kind: &'static str,
    pub code: &'static str,
    pub message: String,
    pub param: Option<&'static str>,
}

impl ApiError {
    fn new(status: StatusCode, kind: &'static str, code: &'static str, message: impl Into<String>) -> Self {
        Self { status, kind, code, message: message.into(), param: None }
    }
    pub fn param(mut self, p: &'static str) -> Self {
        self.param = Some(p);
        self
    }

    // 400 — the request itself is wrong.
    pub fn invalid(code: &'static str, message: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, "invalid_request_error", code, message)
    }
    pub fn missing(param: &'static str) -> Self {
        Self::invalid("parameter_missing", format!("`{param}` is required")).param(param)
    }
    // 401 — no or bad API key.
    pub fn auth(code: &'static str, message: impl Into<String>) -> Self {
        Self::new(StatusCode::UNAUTHORIZED, "authentication_error", code, message)
    }
    // 404
    pub fn not_found(code: &'static str, message: impl Into<String>) -> Self {
        Self::new(StatusCode::NOT_FOUND, "invalid_request_error", code, message)
    }
    // 409 — state conflicts (already fulfilled, idempotency key reused).
    pub fn conflict(code: &'static str, message: impl Into<String>) -> Self {
        Self::new(StatusCode::CONFLICT, "invalid_request_error", code, message)
    }
    // 422 — the receipt was read but does not prove what is required.
    pub fn verification(code: &'static str, message: impl Into<String>) -> Self {
        Self::new(StatusCode::UNPROCESSABLE_ENTITY, "verification_error", code, message).param("receipt")
    }
    // 502 — lightwalletd could not be reached.
    pub fn chain(message: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_GATEWAY, "api_error", "chain_unavailable", message)
    }
    pub fn new_rate_limited() -> Self {
        Self::new(StatusCode::TOO_MANY_REQUESTS, "rate_limit_error", "rate_limited", "too many requests for this key; wait for Retry-After seconds")
    }
    pub fn internal(message: impl Into<String>) -> Self {
        Self::new(StatusCode::INTERNAL_SERVER_ERROR, "api_error", "internal_error", message)
    }

    pub fn body(&self) -> serde_json::Value {
        json!({
            "error": {
                "type": self.kind,
                "code": self.code,
                "message": self.message,
                "param": self.param,
                "doc_url": format!("/docs/ERRORS.md#{}", self.code),
            }
        })
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.status, Json(self.body())).into_response()
    }
}

impl From<rusqlite::Error> for ApiError {
    fn from(e: rusqlite::Error) -> Self {
        ApiError::internal(format!("database: {e}"))
    }
}

/// Every error code the API can return, with its HTTP status and meaning. Served at
/// `GET /v1/errors` and used to generate the docs table.
pub const ERROR_CODES: &[(&str, u16, &str)] = &[
    ("missing_api_key", 401, "No API key. Send `Authorization: Bearer rcpt_test_…`."),
    ("invalid_api_key", 401, "The API key is unknown or revoked."),
    ("invalid_json", 400, "The body is not valid JSON for this endpoint."),
    ("parameter_missing", 400, "A required parameter is missing; see `param`."),
    ("parameter_invalid", 400, "A parameter has the wrong format; see `param`."),
    ("address_network_mismatch", 400, "The address belongs to a different network than the key's mode."),
    ("secret_detected", 400, "The request contained a viewing key, spending key or seed phrase. It was refused and not stored. Never share these; a receipt is all that's needed."),
    ("receipt_malformed", 400, "The receipt text could not be decoded."),
    ("receipt_network_mismatch", 400, "A test key was used with a mainnet receipt, or a live key with a testnet one."),
    ("transaction_not_found", 422, "lightwalletd does not know the receipt's transaction."),
    ("transaction_not_mined", 422, "The transaction exists but is not in a block yet. Retry later."),
    ("receipt_invalid", 422, "The proof, the signature or a disclosed output does not check out."),
    ("challenge_mismatch", 422, "The receipt does not sign this proof request's challenge."),
    ("wrong_payee", 422, "No disclosed output paid the request's payee."),
    ("insufficient_amount", 422, "The payee received less than the requested amount."),
    ("batch_invalid", 422, "A batch is incomplete, reordered or mixes batches."),
    ("request_not_found", 404, "No proof request with that id for this key's mode."),
    ("request_already_fulfilled", 409, "The proof request was already fulfilled."),
    ("payment_already_used", 409, "This payment (transaction output) already counted towards a request. One payment can settle only one request."),
    ("request_expired", 409, "The proof request expired before a valid receipt arrived."),
    ("request_not_fulfilled", 409, "Only a fulfilled request can be attested."),
    ("attestation_overclaims", 400, "The attestation would state more than was paid, or an earlier date than the payment."),
    ("payment_unconfirmed", 409, "A payment on the request left the chain in a reorg; wait until it is mined again."),
    ("attestation_invalid", 422, "The attestation's signature or one of its disclosures does not check out."),
    ("test_clock_not_found", 404, "No test clock with that id."),
    ("livemode_not_allowed", 400, "Test clocks exist only in test mode; use an rcpt_test_ key."),
    ("refund_not_found", 404, "No refund with that id for this key's mode."),
    ("payment_not_found", 404, "No payment with that txid on this request."),
    ("refund_not_possible", 409, "The request has no payments to refund."),
    ("refund_address_missing", 409, "The payer did not sign a refund address into their receipt (`receipts create --refund-to`)."),
    ("refund_amount_invalid", 400, "The refund amount is zero or more than what is left of the payment."),
    ("refund_already_succeeded", 409, "The refund was already settled with a receipt."),
    ("sign_in_malformed", 400, "The `sign_in` text could not be decoded as a zsig1… sign-in."),
    ("sign_in_challenge_not_found", 404, "No sign-in challenge with that nonce for this key's mode."),
    ("sign_in_challenge_used", 409, "The sign-in challenge was already used. Each nonce signs in once."),
    ("sign_in_challenge_expired", 409, "The sign-in challenge expired (they last 5 minutes)."),
    ("sign_in_invalid", 422, "The sign-in proof or signature does not check out for this domain and nonce."),
    ("webhook_url_not_allowed", 400, "Live webhooks must use https and a public host (no localhost or private addresses)."),
    ("webhook_endpoint_not_found", 404, "No webhook endpoint with that id."),
    ("event_not_found", 404, "No event with that id."),
    ("idempotency_key_reused", 409, "The Idempotency-Key was used with a different request body."),
    ("api_version_unsupported", 400, "The Receipts-Version header names a version this server doesn't speak."),
    ("rate_limited", 429, "Too many requests for this key this minute. Wait `Retry-After` seconds; SDKs do this automatically."),
    ("chain_unavailable", 502, "lightwalletd could not be reached. Safe to retry."),
    ("internal_error", 500, "Unexpected server error. Safe to retry."),
];
