# Quickstart: verify a shielded payment in 5 minutes

Receipts lets the sender of a shielded Zcash payment prove that one payment happened
(recipient, amount, memo) without revealing anything else about their wallet. You can be
the one *asking* for proof (a shop, an exchange, a grant program) or the one *giving* it.

## 1. Start the API (testnet)

```bash
cargo install --path crates/receipts-cli      # installs `receipts`
receipts serve                                 # http://127.0.0.1:8723
#   test key  rcpt_test_…    (testnet)
#   live key  rcpt_live_…    (mainnet)
export RECEIPTS_KEY=rcpt_test_…
```

## 2. Try it with no wallet: sandbox fixtures

```bash
curl -s 127.0.0.1:8723/v1/verify -H "Authorization: Bearer $RECEIPTS_KEY" \
  -H 'content-type: application/json' -d '{"receipt":"zrcpt_test_valid"}'
```

Every error path has a fixture (`zrcpt_test_wrong_payee`, `zrcpt_test_not_mined`, …).
See [SANDBOX.md](SANDBOX.md).

## 3. Ask for proof of a payment

```js
import { Receipts } from "zcash-receipts/client";
const receipts = new Receipts(process.env.RECEIPTS_KEY);

const req = await receipts.requests.create({
  payee: "utest1…your address…",
  amount_zatoshis: 1_000_000,          // 0.01 ZEC
  label: "Order #42",
  metadata: { order_id: "42" },
});
req.payment_uri;   // zcash:utest1…?amount=0.01&memo=…  (render as a QR code)
req.receipt_link;  // send to the payer
```

## 4. The payer answers

```bash
receipts create -w <wallet> -i <key.age> --txid <their txid> --request '<receipt_link>'
```

The CLI refuses unless the transaction paid your address at least the requested amount. It
prints a link containing the receipt.

## 5. Submit it, or let the payer submit it

```js
const done = await receipts.requests.submitReceipt(req.id, { receipt: linkOrText });
done.status;                       // "fulfilled"
done.fulfillment.paid_zatoshis;    // 1000000
```

A failure throws `VerificationError` with a stable `code`, e.g. `challenge_mismatch`
(the receipt wasn't made for this request), `wrong_payee`, `insufficient_amount` or
`transaction_not_mined`.

## More request kinds

- `kind: "partial"`: the customer can pay in several transactions. Receipts add up until
  `amount_zatoshis` is reached, and `payment_uri` always asks for what's still owed.
- `kind: "campaign"`: fundraising. Every valid receipt counts and the request never closes.
  `public_url` (`/c/{id}`) shows the verified total and each payment's amount and memo, but
  never who paid.
- **Hosted pay page.** Send the payer `hosted_url` (`/pay/{id}?secret=…`). It shows the QR
  code and the command, and accepts the receipt with no API key and no frontend work on your
  side.
- **Double-spend protection.** A payment (transaction output) can settle only one request,
  ever. A second receipt for the same payment gets `payment_already_used`.

## 6. Get told when it happens

```bash
receipts listen --forward-to http://localhost:3000/webhooks/receipts   # local dev
receipts trigger request.fulfilled                                     # fire a test event
```

```js
import { webhooks } from "zcash-receipts/client";
app.post("/webhooks/receipts", express.raw({ type: "*/*" }), async (req, res) => {
  const event = await webhooks.constructEvent(req.body, req.headers["receipts-signature"], WHSEC);
  if (event.type === "request.fulfilled") markPaid(event.data.object.metadata.order_id);
  res.sendStatus(200);
});
```

Next: [WEBHOOKS.md](WEBHOOKS.md) · [ERRORS.md](ERRORS.md) · [SDKs](SDKS.md) · [guides](guides/) · [OpenAPI](openapi.yaml) · [how it works](SPEC.md)
