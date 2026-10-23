# Quickstart: verify a shielded payment in 5 minutes

Receipts lets the sender of a shielded Zcash payment prove that one payment happened
(recipient, amount, memo) without revealing anything else about their wallet. You can be
the one *asking* for proof (a shop, an exchange, a grant program) or the one *giving* it.

Just looking? `receipts demo --shop` runs the whole flow in the sandbox in about five seconds and
leaves the API, dashboard and verifier running.

Run `receipts doctor` first: it checks the lightwalletd servers, a running API and your
`RECEIPTS_KEY`, your clock, an optional wallet (`-w`), and how fast this machine builds proof keys,
and says what to fix.

## 1. Start the API (testnet)

`receipts serve` also serves the browser verifier at `/verify/`, and proof-request links point
there unless you pass `--verifier-url`.

Needs Rust 1.89 or newer; `rust-toolchain.toml` pins 1.95, which rustup installs automatically.

```bash
cargo install --locked --path crates/receipts-cli   # installs `receipts`
receipts serve                                       # http://127.0.0.1:8723, data in ./receipts.db
#   test key  rcpt_test_…    (testnet)
#   live key  rcpt_live_…    (mainnet; printed shortened, the full key is in receipts.db.keys)
export RECEIPTS_KEY=rcpt_test_…
```

## 2. Try it with no wallet: sandbox fixtures

```bash
curl -s 127.0.0.1:8723/v1/verify -H "Authorization: Bearer $RECEIPTS_KEY" \
  -H 'content-type: application/json' -d '{"receipt":"zip311_test_valid"}'
```

Every error path has a fixture (`zip311_test_wrong_payee`, `zip311_test_not_mined`, …).
See [SANDBOX.md](SANDBOX.md).

## 3. Ask for proof of a payment

The SDKs aren't on npm or PyPI yet. Install them from the repo:

```bash
npm install ./packages/zcash-receipts          # JS / TS / React
python3 -m venv .venv && .venv/bin/pip install ./packages/receipts-python   # Python (in a venv; Homebrew Python refuses global installs)
# Rust: receipts-client = { path = "crates/receipts-client" }
```

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
  `public_url` (`/c/{id}`) is aggregate-only: a total rounded to 0.001 ZEC and a contributor
  count. It appears only after `public_min_contributions` gifts (default 3) and refreshes in
  batches (every 10 min by default). It never shows individual amounts, txids, times or
  on-chain memos, so a gift can't be matched to a transaction. A contributor can opt in to a
  public note with `receipts create … --public-note "…"`, which is signed into their receipt.
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

## 7. Let AI agents use it (MCP)

```json
{ "mcpServers": { "receipts": { "command": "receipts", "args": ["mcp"],
    "env": { "RECEIPTS_KEY": "rcpt_test_…", "RECEIPTS_URL": "http://127.0.0.1:8723" } } } }
```

Tools: `verify_receipt`, `create_proof_request`, `get_proof_request`, `submit_receipt`, `refund_payment` and `check_payment_link`.

## 8. Run the SDK tests against your server

```bash
export RECEIPTS_URL=http://127.0.0.1:8723 RECEIPTS_KEY=rcpt_test_…
(cd packages/zcash-receipts && node --test test/*.test.js)
(cd packages/receipts-python && python3 -m unittest discover tests)
```

Without these variables, the tests that need the API are skipped.

Next: [WEBHOOKS.md](WEBHOOKS.md) · [ERRORS.md](ERRORS.md) · [SDKs](SDKS.md) · [checkout recipe](guides/merchant-checkout.md) · [OpenAPI](openapi.yaml) · [how it works](SPEC.md)
