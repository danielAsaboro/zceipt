# zcash-receipts

`npm install ./packages/zcash-receipts` (not on npm yet).

Verify Zcash payment receipts (ZIP 311 for Orchard and Ironwood) in the browser or in Node.
A receipt proves that one shielded payment happened (recipient, amount and memo) and that the
sender authorized it. It reveals nothing else about the sender's wallet.

```js
import { verifyReceipt } from "zcash-receipts";

const r = await verifyReceipt("https://…#zrcpt1…", {
  expectAddress: "u1…",        // fail unless this address was paid
  minZatoshis: 1_000_000,      // …at least this much
  challenge: "e1e14a5d182a",   // fail unless the receipt signs your challenge
});
// r.valid, r.txid, r.mined_height, r.outputs[0].zatoshis, r.outputs[0].memo, r.paidToExpected
```

Or drop the web component into any page:

```html
<script type="module" src="/zcash-receipts/widget.js"></script>
<zcash-receipt receipt="zrcpt1…" expect-address="u1…" min-zatoshis="1000000"></zcash-receipt>
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
import { useVerifyReceipt } from "zcash-receipts/react";

function OrderStatus({ link }) {
  const { status, result, error } = useVerifyReceipt(link, { expectAddress: SHOP_UA, minZatoshis: 1_000_000 });
  if (status === "verifying") return <Spinner />;
  if (status === "invalid") return <p>Not paid: {error.message}</p>;
  return <p>Paid {result.outputs[0].zatoshis / 1e8} ZEC</p>;
}
```

## API client

```js
import { Receipts, webhooks, VerificationError } from "zcash-receipts/client";
```

See [docs/QUICKSTART.md](../../docs/QUICKSTART.md).

## Tests

`RECEIPTS_URL=http://127.0.0.1:8723 RECEIPTS_KEY=rcpt_test_… ` then run the test command. Without them, the API tests are skipped and only the offline tests run.
