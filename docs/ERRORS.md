# Errors

Every error has the same shape:

```json
{ "error": { "type": "verification_error", "code": "challenge_mismatch", "message": "…", "param": "receipt", "doc_url": "/docs/ERRORS.md#challenge_mismatch" } }
```

Branch on `code`, never on `message`. SDKs raise `AuthenticationError` (401), `InvalidRequestError` (400/404/409), `VerificationError` (422), `ApiError` (5xx) and `ConnectionError`. `GET /v1/errors` returns this table as JSON.

| code | HTTP | meaning |
|---|---|---|
| <a id="missing_api_key"></a>`missing_api_key` | 401 | No API key. Send `Authorization: Bearer rcpt_test_…`. |
| <a id="invalid_api_key"></a>`invalid_api_key` | 401 | The API key is unknown or revoked. |
| <a id="invalid_json"></a>`invalid_json` | 400 | The body is not valid JSON for this endpoint. |
| <a id="parameter_missing"></a>`parameter_missing` | 400 | A required parameter is missing; see `param`. |
| <a id="parameter_invalid"></a>`parameter_invalid` | 400 | A parameter has the wrong format; see `param`. |
| <a id="address_network_mismatch"></a>`address_network_mismatch` | 400 | The address belongs to a different network than the key's mode. |
| <a id="secret_detected"></a>`secret_detected` | 400 | The request contained a viewing key, spending key or seed phrase. It was refused and not stored. Never share these; a receipt is all that's needed. |
| <a id="receipt_malformed"></a>`receipt_malformed` | 400 | The receipt text could not be decoded. |
| <a id="receipt_network_mismatch"></a>`receipt_network_mismatch` | 400 | A test key was used with a mainnet receipt, or a live key with a testnet one. |
| <a id="transaction_not_found"></a>`transaction_not_found` | 422 | lightwalletd does not know the receipt's transaction. |
| <a id="transaction_not_mined"></a>`transaction_not_mined` | 422 | The transaction exists but is not in a block yet. Retry later. |
| <a id="receipt_invalid"></a>`receipt_invalid` | 422 | The proof, the signature or a disclosed output does not check out. |
| <a id="challenge_mismatch"></a>`challenge_mismatch` | 422 | The receipt does not sign this proof request's challenge. |
| <a id="wrong_payee"></a>`wrong_payee` | 422 | No disclosed output paid the request's payee. |
| <a id="insufficient_amount"></a>`insufficient_amount` | 422 | The payee received less than the requested amount. |
| <a id="batch_invalid"></a>`batch_invalid` | 422 | A batch is incomplete, reordered or mixes batches. |
| <a id="request_not_found"></a>`request_not_found` | 404 | No proof request with that id for this key's mode. |
| <a id="request_already_fulfilled"></a>`request_already_fulfilled` | 409 | The proof request was already fulfilled. |
| <a id="payment_already_used"></a>`payment_already_used` | 409 | This payment (transaction output) already counted towards a request. One payment can settle only one request. |
| <a id="request_expired"></a>`request_expired` | 409 | The proof request expired before a valid receipt arrived. |
| <a id="request_not_fulfilled"></a>`request_not_fulfilled` | 409 | Only a fulfilled request can be attested. |
| <a id="attestation_overclaims"></a>`attestation_overclaims` | 400 | The attestation would state more than was paid, or an earlier date than the payment. |
| <a id="attestation_invalid"></a>`attestation_invalid` | 422 | The attestation's signature or one of its disclosures does not check out. |
| <a id="test_clock_not_found"></a>`test_clock_not_found` | 404 | No test clock with that id. |
| <a id="livemode_not_allowed"></a>`livemode_not_allowed` | 400 | Test clocks exist only in test mode; use an rcpt_test_ key. |
| <a id="refund_not_found"></a>`refund_not_found` | 404 | No refund with that id for this key's mode. |
| <a id="payment_not_found"></a>`payment_not_found` | 404 | No payment with that txid on this request. |
| <a id="refund_not_possible"></a>`refund_not_possible` | 409 | The request has no payments to refund. |
| <a id="refund_address_missing"></a>`refund_address_missing` | 409 | The payer did not sign a refund address into their receipt (`receipts create --refund-to`). |
| <a id="refund_amount_invalid"></a>`refund_amount_invalid` | 400 | The refund amount is zero or more than what is left of the payment. |
| <a id="refund_already_succeeded"></a>`refund_already_succeeded` | 409 | The refund was already settled with a receipt. |
| <a id="sign_in_malformed"></a>`sign_in_malformed` | 400 | The `sign_in` text could not be decoded as a zsig1… sign-in. |
| <a id="sign_in_challenge_not_found"></a>`sign_in_challenge_not_found` | 404 | No sign-in challenge with that nonce for this key's mode. |
| <a id="sign_in_challenge_used"></a>`sign_in_challenge_used` | 409 | The sign-in challenge was already used. Each nonce signs in once. |
| <a id="sign_in_challenge_expired"></a>`sign_in_challenge_expired` | 409 | The sign-in challenge expired (they last 5 minutes). |
| <a id="sign_in_invalid"></a>`sign_in_invalid` | 422 | The sign-in proof or signature does not check out for this domain and nonce. |
| <a id="webhook_endpoint_not_found"></a>`webhook_endpoint_not_found` | 404 | No webhook endpoint with that id. |
| <a id="event_not_found"></a>`event_not_found` | 404 | No event with that id. |
| <a id="idempotency_key_reused"></a>`idempotency_key_reused` | 409 | The Idempotency-Key was used with a different request body. |
| <a id="api_version_unsupported"></a>`api_version_unsupported` | 400 | The Receipts-Version header names a version this server doesn't speak. |
| <a id="rate_limited"></a>`rate_limited` | 429 | Too many requests for this key this minute. Wait `Retry-After` seconds; SDKs do this automatically. |
| <a id="chain_unavailable"></a>`chain_unavailable` | 502 | lightwalletd could not be reached. Safe to retry. |
| <a id="internal_error"></a>`internal_error` | 500 | Unexpected server error. Safe to retry. |

Retry `transaction_not_mined`, `chain_unavailable` and `internal_error`. Retries with the same `Idempotency-Key` are safe; the SDKs set one automatically.
