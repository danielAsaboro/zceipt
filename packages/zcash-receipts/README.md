# zcash-receipts

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
