# HTTP 402 for Zcash: gate a route behind a receipt

`zceipt/middleware` (Node) and `zceipt.web` (Python) turn any route into "pay,
prove, get in", without the server ever seeing the payer's wallet.

1. A request without proof gets **402 Payment Required** and JSON with a ZIP-321 `payment_uri`,
   a `receipt_link` and the request id.
2. The caller pays from any shielded wallet and answers the link with a receipt
   (`zceipt create … --request '<receipt_link>'`, or the hosted page).
3. The caller retries with `Receipt-Request: <id>` and gets through once the request is
   fulfilled (or final, with `requireFinal`).

What a paid request unlocks:

- **Who:** a fulfilled request id works like a bearer token, so pass `bindTo`: a server-side
  session or account id (never a header the client sets, such as `X-Forwarded-For`). The gate
  stores it in the request's metadata and only lets that caller through.
- **What:** `route` (default: the label) is stored too; a request paid for `/a` doesn't open `/b`.
- **For how long:** a day by default; set `maxAgeSeconds` (Python: `max_age_seconds`), or `null`
  / `None` for no expiry.
- **How much:** at least the price, net of refunds already paid back.

Abuse: a bound caller without a valid header gets the open request the gate already issued to it
for that route (not a new one; unbound callers each get their own, so one payment never opens
the route for everyone), and the gate creates at most `maxNewPerMinute` (default 30) new
requests a minute in all, answering 429 beyond that, so anonymous traffic can't exhaust your API
key's rate limit.

## Express

```js
import { receiptGate, webhookHandler } from "zceipt/middleware";
app.get("/report.pdf", receiptGate.express({ receipts, payee: SHOP_UA, amountZatoshis: 1_000_000, bindTo: (req) => req.session.id }), sendReport);
app.post("/webhooks/receipts", express.raw({ type: "application/json" }),
  webhookHandler.express({ secret: process.env.ZCEIPT_WHSEC, on: { "request.final": markPaid } }));
```

## Next.js route handlers (and Hono, Bun, Deno)

```js
export async function GET(request) {
  const blocked = await receiptGate.fetch(request, { receipts, payee: SHOP_UA, amountZatoshis: 1_000_000, bindTo: sessionId(request) });
  return blocked ?? Response.json(await report());
}
export const POST = (request) => webhookHandler.fetch(request, { secret: process.env.ZCEIPT_WHSEC, on: { "*": log } });
```

## FastAPI, Django, Flask

```python
from zceipt.web import check_gate, handle_webhook
gate = check_gate(receipts, payee=SHOP_UA, amount_zatoshis=1_000_000,
                  request_id=request.headers.get("receipt-request"), bind_to=session_id)
if not gate.allow:
    return JSONResponse(gate.body, status_code=402)
```

`handle_webhook(raw_body, signature_header, secret, {"request.fulfilled": mark_paid})` verifies the
signature and dispatches; it raises `WebhookSignatureError` (answer 400) on a forged call.

`examples/paid-api/server.mjs` is a runnable 40-line paid API using the fetch adapter.
