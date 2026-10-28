// Helpers the snap test runs in plain Node (ESM): make the proofs from a viewing key, and verify
// a signed receipt against the chain. `node live.mjs prove <ufvk> <birthday> <txid> <height>`
// prints the prepared receipt; `node live.mjs verify <receipt> <height>` prints the verdict.
import { readFileSync } from "node:fs";
const pkg = new URL("../../zceipt/", import.meta.url);
const wasm = await import(new URL("pkg/zceipt_wasm.js", pkg));
wasm.initSync({ module: readFileSync(new URL("pkg/zceipt_wasm_bg.wasm", pkg)) });
const [cmd, ...a] = process.argv.slice(2);
if (cmd === "prove") {
  const { prepareFromViewingKey } = await import(new URL("maker.js", pkg));
  const [ufvk, birthday, txid, height] = a;
  const r = await prepareFromViewingKey({ wasm, ufvk, birthday: Number(birthday), txid, height: Number(height), message: "Order 2001 (MetaMask)" });
  process.stdout.write(r.prepared);
} else if (cmd === "verify") {
  const { verifyReceipt } = await import(new URL("index.js", pkg));
  const v = await verifyReceipt(a[0], { height: Number(a[1]) });
  process.stdout.write(JSON.stringify({ txid: v.txid, outputs: v.outputs.map((o) => ({ zatoshis: o.zatoshis, memo: o.memo, recipient: o.recipient })), message: v.message }));
}
