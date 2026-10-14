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
| <a id="request_expired"></a>`request_expired` | 409 | The proof request expired before a valid receipt arrived. |
| <a id="webhook_endpoint_not_found"></a>`webhook_endpoint_not_found` | 404 | No webhook endpoint with that id. |
| <a id="event_not_found"></a>`event_not_found` | 404 | No event with that id. |
| <a id="idempotency_key_reused"></a>`idempotency_key_reused` | 409 | The Idempotency-Key was used with a different request body. |
| <a id="chain_unavailable"></a>`chain_unavailable` | 502 | lightwalletd could not be reached. Safe to retry. |
| <a id="internal_error"></a>`internal_error` | 500 | Unexpected server error. Safe to retry. |

Retry `transaction_not_mined`, `chain_unavailable` and `internal_error`. Retries with the same `Idempotency-Key` are safe; the SDKs set one automatically.
