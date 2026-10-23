// Makes the proofs off the main thread: scanning, the Merkle path and the proving key take tens
// of seconds. Only the prepared receipt (no key) comes back.
import init, * as wasm from "./zcash-receipts/pkg/receipts_wasm.js";
import { prepareFromViewingKey } from "./zcash-receipts/maker.js";

const ready = init();
self.onmessage = async ({ data }) => {
  try {
    await ready;
    const r = await prepareFromViewingKey({ wasm, ...data, onProgress: (p) => self.postMessage({ progress: p }) });
    self.postMessage({ result: r });
  } catch (e) {
    self.postMessage({ error: String(e && e.message ? e.message : e) });
  }
};
