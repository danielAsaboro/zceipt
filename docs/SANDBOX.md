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
| `zrcpt_test_partial` | valid; pays half of what's still owed (for `partial` requests and campaigns) |
| `zrcpt_test_public_note` | valid; the contributor opted in to a public campaign note |
| `zrcpt_test_refund_to` | valid; the payer signed a refund address, so `POST /v1/requests/{id}/refunds` works |
| `zrcpt_test_same_payment` | valid, but always the same transaction: submit it to two requests to see `payment_already_used` |

`wrong_payee`, `insufficient_amount` and `challenge_mismatch` describe a check that fails.
With `POST /v1/verify` they only fail if you ask for that check:

```bash
curl -s 127.0.0.1:8723/v1/verify -H "Authorization: Bearer $RECEIPTS_KEY" -H 'content-type: application/json' \
  -d '{"receipt":"zrcpt_test_wrong_payee","expect_address":"utest1…your address…"}'      # → 422 wrong_payee
```

Submitted to a proof request (`POST /v1/requests/{id}/receipts`), they always fail, because
the request supplies the payee, amount and challenge. `GET /v1/sandbox/fixtures` lists them.

For end-to-end tests against real proofs, use the committed receipts in `examples/`:
- `examples/regtest`: verifies fully offline from the raw transaction, e.g. `receipts verify @examples/regtest/receipt.txt --raw-tx examples/regtest/tx.hex --height 222 --regtest examples/regtest/heights.toml`.
- `examples/testnet`: verifies against the public testnet.
