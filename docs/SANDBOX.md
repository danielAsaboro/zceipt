# Sandbox fixtures

With an `rcpt_test_` key, these receipts give a fixed outcome with no wallet, faucet or chain,
like Stripe's test card numbers. They work in `POST /v1/verify` and
`POST /v1/requests/{id}/receipts`. Live keys reject them.

| receipt | outcome |
|---|---|
| `zrcpt_test_valid` | valid: pays the expected payee the expected amount, and signs the request's challenge |
| `zrcpt_test_wrong_payee` | 422 `wrong_payee` |
| `zrcpt_test_insufficient_amount` | 422 `insufficient_amount` |
| `zrcpt_test_challenge_mismatch` | 422 `challenge_mismatch` |
| `zrcpt_test_invalid` | 422 `receipt_invalid` |
| `zrcpt_test_not_mined` | 422 `transaction_not_mined` (retry later) |
| `zrcpt_test_not_found` | 422 `transaction_not_found` |
| `zrcpt_test_chain_unavailable` | 502 `chain_unavailable` (retryable) |

`GET /v1/sandbox/fixtures` lists them.

For end-to-end tests against real proofs, use the committed receipts in `examples/`:
- `examples/regtest`: verifies fully offline from the raw transaction.
- `examples/testnet`: verifies against the public testnet.
