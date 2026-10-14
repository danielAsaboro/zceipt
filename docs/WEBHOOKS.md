# Webhooks

Register an endpoint:

```bash
curl -s 127.0.0.1:8723/v1/webhook_endpoints -H "Authorization: Bearer $RECEIPTS_KEY" \
  -H 'content-type: application/json' -d '{"url":"https://example.com/hooks/receipts","events":["request.fulfilled"]}'
# → { "id": "we_…", "secret": "whsec_…" }   (the secret is only shown once)
```

| event | when |
|---|---|
| `request.created` | a proof request was created |
| `request.fulfilled` | a valid receipt answered a request; `data.object` is the fulfilled request |
| `receipt.rejected` | a submitted receipt failed verification; `data.object.error.code` says why |

**Signature.** Each delivery carries
`Receipts-Signature: t=<unix>,v1=<hex HMAC-SHA256(secret, "<t>.<raw body>")>`. Verify it on the
**raw** body with the SDK helpers:

- JS: `webhooks.constructEvent(raw, header, secret)`
- Python: `construct_event(raw, header, secret)`
- Rust: `receipts_client::webhooks::construct_event(raw, header, secret, 300)`

They reject bad signatures and timestamps more than 5 minutes off.

**Delivery.**
- Return any 2xx to acknowledge.
- Failures are retried with exponential backoff (10 s, 20 s, 40 s …, capped at 1 h) for up to 8 attempts.
- Deliveries can repeat, so deduplicate on the event `id`.
- `POST /v1/events/{id}/resend` re-delivers an event.

**Local development.** `receipts listen --forward-to http://localhost:3000/…` registers a
temporary endpoint, prints every event and forwards it with its signature.
`receipts trigger request.fulfilled` fires a real test-mode event.
