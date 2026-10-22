# Refunds, with proof both ways

Shielded payments have no "return to sender": the merchant cannot see who paid. Asking the
customer for an address by email invites phishing ("send my refund here instead"). Receipts
fixes both:

1. **The payer signs a refund address into their receipt.**
   `receipts create … --request '<link>' --refund-to <your address>` adds `refund-to:<address>`
   to the signed message. Only whoever authorized the payment can write that line, so the
   address is authenticated. A payer who doesn't add it stays fully private.
2. **The merchant creates a refund.** `POST /v1/requests/{id}/refunds` with an optional
   `amount_zatoshis` (default: whatever is left of the payment) and `reason`. The response has
   a ZIP-321 `payment_uri` to the signed address and a fresh `challenge`. Partial refunds add up;
   refunding more than was paid is refused (`refund_amount_invalid`). Event: `refund.created`.
3. **The merchant proves the refund.** After paying, they create a receipt for the refund
   transaction that signs the refund's challenge (`--msg 'challenge:<challenge>'`) and submit
   it to `POST /v1/refunds/{id}/receipts`. The API checks the proof, the address and the amount,
   and that the payment wasn't used elsewhere. Event: `refund.succeeded`.

The customer has a receipt proving they paid; the merchant has one proving they paid it back.
Either can show it to the other, a support agent or an arbiter, without a viewing key.

```bash
curl -s -X POST localhost:8723/v1/requests/$ID/refunds \
  -H "authorization: Bearer $RECEIPTS_KEY" -d '{"amount_zatoshis":100000,"reason":"one coffee was cold"}'
```

SDKs: `receipts.refunds.create(id, {…})` and `receipts.refunds.submitReceipt(rf, { receipt })` (JS),
`client.refunds.create(id, …)` (Python), `create_refund` / `submit_refund_receipt` (Rust).
In the sandbox, pay with `zip311_test_refund_to`, then settle with `zip311_test_valid`.
