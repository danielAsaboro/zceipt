# zceipt

`npm install ./packages/zceipt` (not on npm yet).

Verify Zcash payment receipts (ZIP 311 for Orchard and Ironwood) in the browser or in Node.
A receipt proves that one shielded payment happened (recipient, amount and memo) and that the
sender authorized it. It reveals nothing else about the sender's wallet.

```js
import { verifyReceipt } from "zceipt";

const r = await verifyReceipt("https://…#zip311r1…", {
  expectAddress: "u1…",        // fail unless this address was paid
  minZatoshis: 1_000_000,      // …at least this much
  challenge: "e1e14a5d182a",   // fail unless the receipt signs your challenge
});
// r.valid, r.txid, r.mined_height, r.outputs[0].zatoshis, r.outputs[0].memo, r.paidToExpected
```

Or drop the web component into any page:

```html
<script type="module" src="/zceipt/widget.js"></script>
<zcash-receipt receipt="zip311r1…" expect-address="u1…" min-zatoshis="1000000"></zcash-receipt>
```

It fires `receipt-verified` (with the result in `detail`) or `receipt-invalid`.

- Verification runs locally in WebAssembly, and in a Web Worker for the widget. The first check
  builds the Halo 2 verifying key, which takes a few seconds.
- The only network call fetches the public transaction from a lightwalletd grpc-web server.
  The defaults are ChainSafe mainnet and testnet. Pass `endpoint` to use your own, or
  `rawTx`/`height` to make no network call at all.
- Also exported: `inspectReceipt`, `extractReceipt`, `orchardReceiver`, `fetchTransaction`.

Tests (`npm test`): an offline regtest receipt, a tampered receipt that must fail, and a live
testnet receipt with a challenge.

## React

```jsx
import { useVerifyReceipt } from "zceipt/react";

function OrderStatus({ link }) {
  const { status, result, error } = useVerifyReceipt(link, { expectAddress: SHOP_UA, minZatoshis: 1_000_000 });
  if (status === "verifying") return <Spinner />;
  if (status === "invalid") return <p>Not paid: {error.message}</p>;
  return <p>Paid {result.outputs[0].zatoshis / 1e8} ZEC</p>;
}
```

## API client

```js
import { Zceipt, webhooks, VerificationError } from "zceipt/client";
```

See [docs/QUICKSTART.md](../../docs/QUICKSTART.md).

## Server middleware: HTTP 402 and webhooks

```js
import { receiptGate, webhookHandler } from "zceipt/middleware";
app.get("/report", receiptGate.express({ receipts, payee, amountZatoshis: 1_000_000, route: "/report", bindTo: (req) => req.session.id }), handler);
```

Callers get 402 with a payment link until they answer it with a receipt. See
[docs/guides/http-402.md](../../docs/guides/http-402.md).

## Attestations and sign-in

`verifyAttestation(token, { issuer })` checks a payment-fact attestation offline against the server
you trust; `verifySignIn(zsig, { domain, nonce })` checks a Sign in with Zcash proof.
`checkPaymentLink(uri)` lints a `zcash:` link.

## Tests

`ZCEIPT_URL=http://127.0.0.1:8723 ZCEIPT_KEY=rcpt_test_… ` then run the test command. Without them, the API tests are skipped and only the offline tests run.
